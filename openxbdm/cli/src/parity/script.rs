//! Command list files for `parity record`.
//!
//! One command line per line. Blank lines and lines starting with `#` are
//! skipped. Lines starting with `%` are directives:
//!
//! - `%send <text>`: send `<text>` verbatim (may be empty, or start with
//!   `#` or `%`).
//! - `%repeat <count> <text>`: send `<text>` repeated `<count>` times.
//! - `%upload <hex>`: bytes sent when the previous command replies `204`.
//! - `%reconnect`: close the connection and open a new one.

use super::error::ScriptError;
use super::error::ScriptErrorKind;

/// One step of a command list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Command(Command),
    Reconnect,
}

/// A command line and the data it uploads after a `204` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub line: String,
    pub upload: Option<Vec<u8>>,
}

/// Parse a command list.
pub fn parse(text: &str) -> Result<Vec<Step>, ScriptError> {
    let mut steps = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let error = |kind| ScriptError {
            line: index + 1,
            kind,
        };
        if raw.contains('\r') {
            return Err(error(ScriptErrorKind::CarriageReturn));
        }

        if raw.trim().is_empty() || raw.starts_with('#') {
            continue;
        }

        let Some(directive) = raw.strip_prefix('%') else {
            steps.push(command(raw.to_owned()));
            continue;
        };

        // A directive without a space has an empty argument.
        let (name, argument) = directive.split_once(' ').unwrap_or((directive, ""));
        match name {
            "send" => steps.push(command(argument.to_owned())),
            "repeat" => {
                let (count, text) = argument
                    .split_once(' ')
                    .ok_or(error(ScriptErrorKind::InvalidRepeat))?;
                let count: usize = count
                    .parse()
                    .map_err(|_| error(ScriptErrorKind::InvalidRepeat))?;
                steps.push(command(text.repeat(count)));
            }
            "upload" => {
                let data =
                    decode_hex(argument.trim()).ok_or(error(ScriptErrorKind::InvalidUpload))?;
                match steps.last_mut() {
                    Some(Step::Command(Command {
                        upload: Some(_), ..
                    })) => {
                        return Err(error(ScriptErrorKind::DuplicateUpload));
                    }
                    Some(Step::Command(previous)) => previous.upload = Some(data),
                    Some(Step::Reconnect) | None => {
                        return Err(error(ScriptErrorKind::UploadWithoutCommand));
                    }
                }
            }
            "reconnect" if argument.is_empty() => steps.push(Step::Reconnect),
            "reconnect" => return Err(error(ScriptErrorKind::ReconnectArgument)),
            _ => {
                return Err(error(ScriptErrorKind::UnknownDirective {
                    name: name.to_owned(),
                }));
            }
        }
    }

    Ok(steps)
}

fn command(line: String) -> Step {
    Step::Command(Command { line, upload: None })
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }

    pairs
        .iter()
        .map(|pair| {
            let digits = core::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_commands_and_directives() {
        let steps = parse(
            "# comment\n\
             dmversion\n\
             \n\
             %send\n\
             %send #literal\n\
             %repeat 3 ab\n\
             sendfile name=\"DEVKIT:\\oxtest\\a\" length=2\n\
             %upload 0aFF\n\
             %reconnect\n",
        );
        insta::assert_debug_snapshot!(steps);
    }

    #[test]
    fn rejects_malformed_directives() {
        let cases = [
            "%upload 00",
            "a\n%upload 0",
            "a\n%upload 00\n%upload 00",
            "%reconnect\n%upload 00",
            "%repeat x a",
            "%repeat 2",
            "%sleep 1",
            "%reconnect now",
            "a\rb",
        ];
        let errors: Vec<String> = cases
            .iter()
            .map(|case| parse(case).expect_err(case).to_string())
            .collect();
        insta::assert_debug_snapshot!(errors);
    }
}
