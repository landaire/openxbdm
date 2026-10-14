//! Compare two recordings of the same command list.
//!
//! A variance file names reply fields that legitimately differ between
//! runs, one command per line: `<command line> | <fields> | <reason>`.
//! Blank lines and lines starting with `#` are skipped. Fields are
//! space-separated:
//!
//! - `head`: the head text after the status code.
//! - `head.<key>`: the value of `<key>=` in the head.
//! - `body`: every body line, including their number.
//! - `body.<key>`: the value of `<key>=` in each body line.
//! - `body-order`: the order of the body lines.
//! - `binary`: the payload contents (the length is still compared).
//! - `binary-length`: the payload length and contents.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use similar::DiffTag;

use super::record::Exchange;
use super::record::Recording;
use super::record::Reply;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field {
    Head,
    HeadKey(String),
    Body,
    BodyKey(String),
    BodyOrder,
    Binary,
    BinaryLength,
}

impl Field {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "head" => Self::Head,
            "body" => Self::Body,
            "body-order" => Self::BodyOrder,
            "binary" => Self::Binary,
            "binary-length" => Self::BinaryLength,
            _ => {
                let key = |prefix| text.strip_prefix(prefix).filter(|key| !key.is_empty());
                if let Some(key) = key("head.") {
                    Self::HeadKey(key.to_owned())
                } else {
                    Self::BodyKey(key("body.")?.to_owned())
                }
            }
        })
    }
}

/// Fields known to vary, by command line.
#[derive(Debug, Default)]
pub struct Variances {
    by_command: BTreeMap<String, Vec<Field>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct VarianceError {
    /// One-based line number in the variance file.
    pub line: usize,
    pub kind: VarianceErrorKind,
}

impl fmt::Display for VarianceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.kind)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VarianceErrorKind {
    #[error("expected `<command> | <fields> | <reason>`")]
    Shape,
    #[error("unknown field `{field}`")]
    UnknownField { field: String },
    #[error("no fields given")]
    NoFields,
    #[error("no reason given")]
    NoReason,
}

impl Variances {
    pub fn parse(text: &str) -> Result<Self, VarianceError> {
        let mut variances = Self::default();
        for (index, raw) in text.lines().enumerate() {
            let error = |kind| VarianceError {
                line: index + 1,
                kind,
            };
            if raw.trim().is_empty() || raw.starts_with('#') {
                continue;
            }
            // Split from the right: command lines may contain ` | `.
            let mut parts = raw.rsplitn(3, " | ");
            let (Some(reason), Some(fields), Some(command)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Err(error(VarianceErrorKind::Shape));
            };
            if reason.trim().is_empty() {
                return Err(error(VarianceErrorKind::NoReason));
            }
            let fields = fields
                .split_whitespace()
                .map(|field| {
                    Field::parse(field).ok_or_else(|| {
                        error(VarianceErrorKind::UnknownField {
                            field: field.to_owned(),
                        })
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if fields.is_empty() {
                return Err(error(VarianceErrorKind::NoFields));
            }
            let entry = variances.by_command.entry(command.to_owned()).or_default();
            entry.extend(fields);
            entry.sort();
            entry.dedup();
        }
        Ok(variances)
    }

    fn fields(&self, command: &str) -> &[Field] {
        self.by_command.get(command).map_or(&[], Vec::as_slice)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompareError {
    #[error("exchange {index} ran `{a}` in one recording and `{b}` in the other")]
    CommandMismatch { index: usize, a: String, b: String },
}

/// Result of comparing two recordings.
#[derive(Debug)]
pub struct Comparison {
    pub exchanges: usize,
    /// Exchanges equal only because of variance fields.
    pub masked: usize,
    pub banner: Option<BannerDifference>,
    pub differences: Vec<ExchangeDifference>,
    pub unmatched: Vec<Unmatched>,
    /// Variance entries whose command does not occur in the recordings.
    pub unused_variances: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

#[derive(Debug)]
pub struct BannerDifference {
    pub a: Option<String>,
    pub b: Option<String>,
}

/// An exchange present in only one recording.
#[derive(Debug)]
pub struct Unmatched {
    pub index: usize,
    pub command: String,
    pub present_in: Side,
}

#[derive(Debug)]
pub struct ExchangeDifference {
    pub index: usize,
    pub command: String,
    pub items: Vec<Difference>,
}

#[derive(Debug)]
pub enum Difference {
    /// Different reply shapes or heads; both replies are shown whole.
    Reply {
        a: Reply,
        b: Reply,
    },
    Head {
        a: String,
        b: String,
    },
    /// Body lines removed (`a` only) and added (`b` only), in order.
    Body {
        lines: Vec<(Side, String)>,
    },
    BinaryLength {
        a: u64,
        b: u64,
    },
    BinaryContents {
        a: String,
        b: String,
    },
    /// Difference inside the reply that followed an upload.
    AfterUpload(Box<Difference>),
}

impl Comparison {
    pub fn is_equal(&self) -> bool {
        self.banner.is_none() && self.differences.is_empty() && self.unmatched.is_empty()
    }
}

pub fn compare(
    a: &Recording,
    b: &Recording,
    variances: &Variances,
) -> Result<Comparison, CompareError> {
    let mut comparison = Comparison {
        exchanges: a.exchanges.len().max(b.exchanges.len()),
        masked: 0,
        banner: (a.banner != b.banner).then(|| BannerDifference {
            a: a.banner.clone(),
            b: b.banner.clone(),
        }),
        differences: Vec::new(),
        unmatched: Vec::new(),
        unused_variances: Vec::new(),
    };
    for (index, (x, y)) in a.exchanges.iter().zip(&b.exchanges).enumerate() {
        if x.command != y.command {
            return Err(CompareError::CommandMismatch {
                index,
                a: x.command.clone(),
                b: y.command.clone(),
            });
        }
        let fields = variances.fields(&x.command);
        let mut items = Vec::new();
        compare_replies(&x.reply, &y.reply, fields, &mut items);
        if !items.is_empty() {
            comparison.differences.push(ExchangeDifference {
                index,
                command: x.command.clone(),
                items,
            });
        } else if x.reply != y.reply {
            comparison.masked += 1;
        }
    }
    let (longer, present_in) = if a.exchanges.len() > b.exchanges.len() {
        (&a.exchanges, Side::A)
    } else {
        (&b.exchanges, Side::B)
    };
    let shorter = a.exchanges.len().min(b.exchanges.len());
    comparison.unmatched = longer
        .iter()
        .enumerate()
        .skip(shorter)
        .map(|(index, exchange)| Unmatched {
            index,
            command: exchange.command.clone(),
            present_in,
        })
        .collect();
    comparison.unused_variances = variances
        .by_command
        .keys()
        .filter(|command| {
            !a.exchanges
                .iter()
                .chain(&b.exchanges)
                .any(|Exchange { command: run, .. }| run == *command)
        })
        .cloned()
        .collect();
    Ok(comparison)
}

fn compare_replies(a: &Reply, b: &Reply, fields: &[Field], items: &mut Vec<Difference>) {
    let head_keys = keys(fields, |field| match field {
        Field::HeadKey(key) => Some(key),
        _ => None,
    });
    let whole_head = fields.contains(&Field::Head);
    let heads_equal = |x: &str, y: &str| {
        if whole_head {
            x.get(..3) == y.get(..3)
        } else {
            mask(x, &head_keys) == mask(y, &head_keys)
        }
    };
    match (a, b) {
        (Reply::Line { head: x }, Reply::Line { head: y })
        | (Reply::Channel { head: x }, Reply::Channel { head: y }) => {
            if !heads_equal(x, y) {
                items.push(head_difference(x, y));
            }
        }
        (Reply::Multiline { head: x, body: xb }, Reply::Multiline { head: y, body: yb }) => {
            if !heads_equal(x, y) {
                items.push(head_difference(x, y));
            }
            if !fields.contains(&Field::Body) {
                compare_bodies(xb, yb, fields, items);
            }
        }
        (
            Reply::Binary {
                head: x,
                length: xl,
                digest: xd,
                end: xe,
            },
            Reply::Binary {
                head: y,
                length: yl,
                digest: yd,
                end: ye,
            },
        ) => {
            if !heads_equal(x, y) || xe != ye {
                items.push(Difference::Reply {
                    a: a.clone(),
                    b: b.clone(),
                });
                return;
            }
            if fields.contains(&Field::BinaryLength) {
                return;
            }
            if xl != yl {
                items.push(Difference::BinaryLength { a: *xl, b: *yl });
            } else if xd != yd && !fields.contains(&Field::Binary) {
                items.push(Difference::BinaryContents {
                    a: xd.clone(),
                    b: yd.clone(),
                });
            }
        }
        (Reply::Upload { head: x, after: xa }, Reply::Upload { head: y, after: ya }) => {
            if !heads_equal(x, y) {
                items.push(head_difference(x, y));
            }
            match (xa, ya) {
                (Some(xa), Some(ya)) => {
                    let mut inner = Vec::new();
                    compare_replies(xa, ya, fields, &mut inner);
                    items.extend(
                        inner
                            .into_iter()
                            .map(|item| Difference::AfterUpload(Box::new(item))),
                    );
                }
                (None, None) => {}
                _ => items.push(Difference::Reply {
                    a: a.clone(),
                    b: b.clone(),
                }),
            }
        }
        _ => {
            if a != b {
                items.push(Difference::Reply {
                    a: a.clone(),
                    b: b.clone(),
                });
            }
        }
    }
}

fn head_difference(a: &str, b: &str) -> Difference {
    Difference::Head {
        a: a.to_owned(),
        b: b.to_owned(),
    }
}

fn keys<'a>(fields: &'a [Field], select: impl Fn(&'a Field) -> Option<&'a String>) -> Vec<&'a str> {
    fields
        .iter()
        .filter_map(select)
        .map(String::as_str)
        .collect()
}

fn compare_bodies(a: &[String], b: &[String], fields: &[Field], items: &mut Vec<Difference>) {
    let body_keys = keys(fields, |field| match field {
        Field::BodyKey(key) => Some(key),
        _ => None,
    });
    // Keep each masked line with its original for display.
    let prepare = |lines: &[String]| {
        let mut pairs: Vec<(String, String)> = lines
            .iter()
            .map(|line| (mask(line, &body_keys), line.clone()))
            .collect();
        if fields.contains(&Field::BodyOrder) {
            pairs.sort();
        }
        pairs
    };
    let a = prepare(a);
    let b = prepare(b);
    let masked_a: Vec<&str> = a.iter().map(|(masked, _)| masked.as_str()).collect();
    let masked_b: Vec<&str> = b.iter().map(|(masked, _)| masked.as_str()).collect();
    let diff = similar::TextDiff::from_slices(&masked_a, &masked_b);
    let mut lines = Vec::new();
    for op in diff.ops() {
        if op.tag() == DiffTag::Equal {
            continue;
        }
        lines.extend(
            a[op.old_range()]
                .iter()
                .map(|(_, line)| (Side::A, line.clone())),
        );
        lines.extend(
            b[op.new_range()]
                .iter()
                .map(|(_, line)| (Side::B, line.clone())),
        );
    }
    if !lines.is_empty() {
        items.push(Difference::Body { lines });
    }
}

/// Replace the value of each `key=` token named in `keys` with `*`. Tokens
/// are separated by spaces outside double quotes; spacing is preserved.
fn mask(line: &str, keys: &[&str]) -> String {
    if keys.is_empty() {
        return line.to_owned();
    }
    let mut masked = String::with_capacity(line.len());
    let mut rest = line;
    while !rest.is_empty() {
        let spaces = rest.len() - rest.trim_start_matches(' ').len();
        masked.push_str(&rest[..spaces]);
        rest = &rest[spaces..];
        let mut quoted = false;
        let end = rest
            .char_indices()
            .find(|&(_, c)| {
                if c == '"' {
                    quoted = !quoted;
                }
                c == ' ' && !quoted
            })
            .map_or(rest.len(), |(index, _)| index);
        let token = &rest[..end];
        match token.split_once('=') {
            Some((key, _)) if keys.contains(&key) => {
                masked.push_str(key);
                masked.push_str("=*");
            }
            _ => masked.push_str(token),
        }
        rest = &rest[end..];
    }
    masked
}

/// Render a comparison as text; `a` and `b` label the recordings.
pub fn render(comparison: &Comparison, a: &str, b: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "a: {a}");
    let _ = writeln!(out, "b: {b}");
    if let Some(banner) = &comparison.banner {
        let _ = writeln!(out, "banner");
        let _ = writeln!(out, "  a: {}", banner_text(banner.a.as_deref()));
        let _ = writeln!(out, "  b: {}", banner_text(banner.b.as_deref()));
    }
    for difference in &comparison.differences {
        let _ = writeln!(out, "[{}] {}", difference.index, difference.command);
        for item in &difference.items {
            render_difference(&mut out, item, "  ");
        }
    }
    for unmatched in &comparison.unmatched {
        let which = match unmatched.present_in {
            Side::A => "a",
            Side::B => "b",
        };
        let _ = writeln!(out, "[{}] {}", unmatched.index, unmatched.command);
        let _ = writeln!(out, "  only in {which}");
    }
    for command in &comparison.unused_variances {
        let _ = writeln!(out, "unused variance: {command}");
    }
    let differing = comparison.differences.len() + comparison.unmatched.len();
    let _ = writeln!(
        out,
        "{} exchanges: {} equal, {} equal outside varying fields, {} differ",
        comparison.exchanges,
        comparison.exchanges - differing - comparison.masked,
        comparison.masked,
        differing
    );
    out
}

fn banner_text(banner: Option<&str>) -> &str {
    banner.unwrap_or("(no connection)")
}

fn render_difference(out: &mut String, difference: &Difference, indent: &str) {
    match difference {
        Difference::Reply { a, b } => {
            let _ = writeln!(out, "{indent}reply");
            let _ = writeln!(out, "{indent}  a: {}", describe(a));
            let _ = writeln!(out, "{indent}  b: {}", describe(b));
        }
        Difference::Head { a, b } => {
            let _ = writeln!(out, "{indent}head");
            let _ = writeln!(out, "{indent}  a: {a}");
            let _ = writeln!(out, "{indent}  b: {b}");
        }
        Difference::Body { lines } => {
            let _ = writeln!(out, "{indent}body");
            for (side, line) in lines {
                let mark = match side {
                    Side::A => '-',
                    Side::B => '+',
                };
                let _ = writeln!(out, "{indent}  {mark} {line}");
            }
        }
        Difference::BinaryLength { a, b } => {
            let _ = writeln!(out, "{indent}binary length");
            let _ = writeln!(out, "{indent}  a: {a}");
            let _ = writeln!(out, "{indent}  b: {b}");
        }
        Difference::BinaryContents { a, b } => {
            let _ = writeln!(out, "{indent}binary digest");
            let _ = writeln!(out, "{indent}  a: {a}");
            let _ = writeln!(out, "{indent}  b: {b}");
        }
        Difference::AfterUpload(inner) => {
            let _ = writeln!(out, "{indent}after upload");
            render_difference(out, inner, &format!("{indent}  "));
        }
    }
}

pub(super) fn describe(reply: &Reply) -> String {
    match reply {
        Reply::Line { head } | Reply::Channel { head } => head.clone(),
        Reply::Multiline { head, body } => format!("{head} ({} lines)", body.len()),
        Reply::Binary {
            head, length, end, ..
        } => format!("{head} ({length} bytes, end {end:?})"),
        Reply::Upload { head, after } => match after {
            Some(after) => format!("{head}, then {}", describe(after)),
            None => format!("{head}, no upload"),
        },
        Reply::Closed { received } => format!("closed after `{received}`"),
        Reply::Timeout { received } => format!("timeout after `{received}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parity::record::BinaryEnd;

    fn exchange(command: &str, reply: Reply) -> Exchange {
        Exchange {
            command: command.to_owned(),
            reply,
        }
    }

    fn line(head: &str) -> Reply {
        Reply::Line {
            head: head.to_owned(),
        }
    }

    fn multiline(head: &str, body: &[&str]) -> Reply {
        Reply::Multiline {
            head: head.to_owned(),
            body: body.iter().map(|line| (*line).to_owned()).collect(),
        }
    }

    fn binary(length: u64, digest: &str) -> Reply {
        Reply::Binary {
            head: "203- binary response follows".to_owned(),
            length,
            digest: digest.to_owned(),
            end: BinaryEnd::Bye,
        }
    }

    fn recordings() -> (Recording, Recording) {
        let a = Recording {
            banner: Some("201- connected".to_owned()),
            exchanges: vec![
                exchange("dmversion", line("200- 2.0.21256.0")),
                exchange("getpid", line("200- pid=0x36060869")),
                exchange(
                    "getsockinfo",
                    multiline(
                        "202- multiline response follows",
                        &[
                            "handle=0x3343f000 flags=0x00808000 name=\"a b\"",
                            "handle=0x33441002 flags=0x00808800 name=\"c\"",
                        ],
                    ),
                ),
                exchange(
                    "pclist",
                    multiline(
                        "202- multiline response follows",
                        &["name=\"x\"", "name=\"y\""],
                    ),
                ),
                exchange(
                    "threads",
                    multiline("202- thread list follows", &["-1", "-2"]),
                ),
                exchange(
                    "getmemex addr=0x80040000 length=0x10",
                    binary(16, "00000000000000aa"),
                ),
                exchange("screenshot", binary(100, "00000000000000bb")),
                exchange(
                    "sendfile name=\"DEVKIT:\\\\oxtest\\\\a\" length=2",
                    Reply::Upload {
                        head: "204- send binary data".to_owned(),
                        after: Some(Box::new(line("200- OK"))),
                    },
                ),
                exchange("isstopped thread=0x1", line("405- no such thread")),
                exchange("bye", line("200- bye")),
            ],
        };
        let b = Recording {
            banner: Some("201- connected".to_owned()),
            exchanges: vec![
                exchange("dmversion", line("200- 2.0.21256.0")),
                exchange("getpid", line("200- pid=0x12345678")),
                exchange(
                    "getsockinfo",
                    multiline(
                        "202- multiline response follows",
                        &[
                            "handle=0x3cd59000 flags=0x00008000 name=\"a b\"",
                            "handle=0x3cd5d002 flags=0x00808800 name=\"c\"",
                        ],
                    ),
                ),
                exchange(
                    "pclist",
                    multiline(
                        "202- multiline response follows",
                        &["name=\"y\"", "name=\"x\""],
                    ),
                ),
                exchange(
                    "threads",
                    multiline("202- thread list follows", &["-1", "-3", "-4"]),
                ),
                exchange(
                    "getmemex addr=0x80040000 length=0x10",
                    binary(16, "00000000000000ac"),
                ),
                exchange("screenshot", binary(120, "00000000000000bc")),
                exchange(
                    "sendfile name=\"DEVKIT:\\\\oxtest\\\\a\" length=2",
                    Reply::Upload {
                        head: "204- send binary data".to_owned(),
                        after: Some(Box::new(line("400- "))),
                    },
                ),
                exchange(
                    "isstopped thread=0x1",
                    Reply::Closed {
                        received: String::new(),
                    },
                ),
                exchange("bye", line("200- bye")),
                exchange("dmversion", line("200- 2.0.21256.0")),
            ],
        };
        (a, b)
    }

    const VARIANCES: &str = "\
# process identifier of the running title
getpid | head.pid | assigned at title launch
getsockinfo | body.handle | socket handles are allocated per boot
pclist | body-order | hash table order
screenshot | binary-length | frame buffer contents
walkmem | body | not in the recording
";

    #[test]
    fn renders_differences_outside_varying_fields() {
        let (a, b) = recordings();
        let variances = Variances::parse(VARIANCES).unwrap();
        let comparison = compare(&a, &b, &variances).unwrap();
        insta::assert_snapshot!(render(&comparison, "stock.json", "openxbdm.json"));
    }

    #[test]
    fn equal_recordings_render_a_summary_only() {
        let (a, _) = recordings();
        let comparison = compare(&a, &a, &Variances::default()).unwrap();
        assert!(comparison.is_equal());
        insta::assert_snapshot!(render(&comparison, "stock.json", "stock.json"));
    }

    #[test]
    fn rejects_recordings_of_different_command_lists() {
        let (a, mut b) = recordings();
        b.exchanges[1].command = "getpid2".to_owned();
        let error = compare(&a, &b, &Variances::default()).unwrap_err();
        assert_eq!(
            error,
            CompareError::CommandMismatch {
                index: 1,
                a: "getpid".to_owned(),
                b: "getpid2".to_owned()
            }
        );
    }

    #[test]
    fn masks_values_and_preserves_spacing() {
        let masked = mask(
            "name=\"a b=c\"  handle=0x1 flags=0x2 dll handle",
            &["handle", "name"],
        );
        assert_eq!(masked, "name=*  handle=* flags=0x2 dll handle");
    }

    #[test]
    fn rejects_malformed_variance_lines() {
        let cases = [
            "getpid | head.pid",
            "getpid | head.pid | ",
            "getpid | pid | reason",
            "getpid | head. | reason",
            "getpid |  | reason",
        ];
        let errors: Vec<String> = cases
            .iter()
            .map(|case| Variances::parse(case).unwrap_err().to_string())
            .collect();
        insta::assert_debug_snapshot!(errors);
    }
}
