//! Shared winnow parser combinators for XBDM wire text.

use winnow::ascii::digit1;
use winnow::combinator::alt;
use winnow::combinator::opt;
use winnow::error::ContextError;
use winnow::error::ErrMode;
use winnow::prelude::*;
use winnow::token::rest;
use winnow::token::take_until;
use winnow::token::take_while;

use crate::error::FramingError;
use crate::error::ParseError;

pub type Input<'a> = &'a str;

pub fn three_digit_code(input: &mut Input<'_>) -> Result<u16, ErrMode<ContextError>> {
    digit1
        .verify(|s: &str| s.len() == 3)
        .try_map(|s: &str| s.parse::<u16>())
        .parse_next(input)
}

/// Parse a response head: `NNN<sep>rest` where `sep` is one of `- `, `-`,
/// ` `, or empty. The head text runs to end-of-input.
pub fn response_head<'a>(input: &mut Input<'a>) -> Result<(u16, &'a str), ErrMode<ContextError>> {
    let code = three_digit_code.parse_next(input)?;
    let _ = opt(alt(("- ", "-", " "))).parse_next(input)?;
    let tail = rest.parse_next(input)?;
    Ok((code, tail))
}

/// Parse a `0x`-prefixed unsigned hex integer.
#[allow(dead_code)]
pub fn hex_u64_prefixed(input: &mut Input<'_>) -> Result<u64, ErrMode<ContextError>> {
    alt(("0x", "0X")).parse_next(input)?;
    take_while(1..=16, |c: char| c.is_ascii_hexdigit())
        .try_map(|s: &str| u64::from_str_radix(s, 16))
        .parse_next(input)
}

/// Parse a quadword literal (`0q` + 16 hex digits).
#[allow(dead_code)]
pub fn qword_literal(input: &mut Input<'_>) -> Result<u64, ErrMode<ContextError>> {
    alt(("0q", "0Q")).parse_next(input)?;
    take_while(16..=16, |c: char| c.is_ascii_hexdigit())
        .try_map(|s: &str| u64::from_str_radix(s, 16))
        .parse_next(input)
}

/// Run a parser over a `&str` and translate any winnow error into a
/// typed [`FramingError`].
pub fn run_framing<'a, T, F>(
    parser: F,
    input: &'a str,
    on_fail: FramingError,
) -> Result<T, FramingError>
where
    F: FnOnce(&mut Input<'a>) -> Result<T, ErrMode<ContextError>>,
{
    let mut cursor = input;
    parser(&mut cursor).map_err(|_| on_fail)
}

/// Run a parser over a `&str` and translate any winnow error into a
/// typed [`ParseError`].
pub fn run_parse<'a, T, F>(parser: F, input: &'a str, on_fail: ParseError) -> Result<T, ParseError>
where
    F: FnOnce(&mut Input<'a>) -> Result<T, ErrMode<ContextError>>,
{
    let mut cursor = input;
    parser(&mut cursor).map_err(|_| on_fail)
}

/// Output of [`kv_tokens`]: the `KEY=VALUE` pairs and the bare flag tokens,
/// each preserved in source order within their respective lists.
#[derive(Debug, Default)]
pub struct KvTokens<'a> {
    pub pairs: Vec<(&'a str, KvValue<'a>)>,
    pub flags: Vec<&'a str>,
}

/// Consume whitespace-separated `KEY=VALUE` pairs and bare flag tokens.
pub fn kv_tokens<'a>(input: &mut Input<'a>) -> Result<KvTokens<'a>, ErrMode<ContextError>> {
    let mut out = KvTokens::default();
    loop {
        let _ = winnow::ascii::space0.parse_next(input)?;
        if input.is_empty() {
            break;
        }
        let key =
            take_while(1.., |c: char| c != '=' && !c.is_ascii_whitespace()).parse_next(input)?;
        match opt('=').parse_next(input)? {
            Some(_) => {
                let value = kv_value.parse_next(input)?;
                out.pairs.push((key, value));
            }
            None => out.flags.push(key),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
pub enum KvValue<'a> {
    Bare(&'a str),
    Quoted(&'a str),
}

impl<'a> KvValue<'a> {
    pub fn as_str(self) -> &'a str {
        match self {
            KvValue::Bare(s) | KvValue::Quoted(s) => s,
        }
    }
}

pub fn kv_value<'a>(input: &mut Input<'a>) -> Result<KvValue<'a>, ErrMode<ContextError>> {
    alt((quoted_value, bare_value)).parse_next(input)
}

fn bare_value<'a>(input: &mut Input<'a>) -> Result<KvValue<'a>, ErrMode<ContextError>> {
    take_while(0.., |c: char| !c.is_ascii_whitespace())
        .map(KvValue::Bare)
        .parse_next(input)
}

fn quoted_value<'a>(input: &mut Input<'a>) -> Result<KvValue<'a>, ErrMode<ContextError>> {
    '"'.parse_next(input)?;
    let inner = take_until(0.., '"').parse_next(input)?;
    '"'.parse_next(input)?;
    Ok(KvValue::Quoted(inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_digit_code_parses() {
        let mut input = "200";
        assert_eq!(three_digit_code.parse_next(&mut input).unwrap(), 200);
    }

    #[test]
    fn three_digit_code_rejects_two_digits() {
        let mut input = "20";
        assert!(three_digit_code.parse_next(&mut input).is_err());
    }

    #[test]
    fn response_head_parses_dash_space() {
        let mut input = "200- OK";
        let (code, rest) = response_head.parse_next(&mut input).unwrap();
        assert_eq!(code, 200);
        assert_eq!(rest, "OK");
    }

    #[test]
    fn response_head_parses_bare_dash() {
        let mut input = "201-connected";
        let (code, rest) = response_head.parse_next(&mut input).unwrap();
        assert_eq!(code, 201);
        assert_eq!(rest, "connected");
    }

    #[test]
    fn response_head_parses_space_only() {
        let mut input = "206 dedicated";
        let (code, rest) = response_head.parse_next(&mut input).unwrap();
        assert_eq!(code, 206);
        assert_eq!(rest, "dedicated");
    }

    #[test]
    fn kv_tokens_parses_mixed() {
        let mut input = r#"NAME="e:\foo" ADDR=0x80000000 RUNNING"#;
        let tokens = kv_tokens.parse_next(&mut input).unwrap();
        assert_eq!(tokens.pairs.len(), 2);
        assert_eq!(tokens.pairs[0].0, "NAME");
        assert_eq!(tokens.pairs[0].1.as_str(), r"e:\foo");
        assert_eq!(tokens.pairs[1].0, "ADDR");
        assert_eq!(tokens.pairs[1].1.as_str(), "0x80000000");
        assert_eq!(tokens.flags, vec!["RUNNING"]);
    }

    #[test]
    fn qword_literal_parses_16_digits() {
        let mut input = "0q0011223344556677";
        assert_eq!(
            qword_literal.parse_next(&mut input).unwrap(),
            0x0011_2233_4455_6677
        );
    }
}
