//! File name expressions of directory queries (MS-FSA 2.1.4.4): `*` and
//! `?`, and the DOS wildcards `<` (DOS_STAR), `>` (DOS_QM), and `"`
//! (DOS_DOT). Names compare without case.
//!
//! The expression runs as a nondeterministic automaton whose states are
//! expression positions, so matching takes no recursion and no allocation.

/// Longest expression in code units.
pub const EXPRESSION_CAPACITY: usize = 255;

const STAR: u16 = b'*' as u16;
const QUESTION: u16 = b'?' as u16;
const DOS_STAR: u16 = b'<' as u16;
const DOS_QM: u16 = b'>' as u16;
const DOS_DOT: u16 = b'"' as u16;
const DOT: u16 = b'.' as u16;

/// Expression positions `0..=EXPRESSION_CAPACITY`.
#[derive(Clone, Copy, PartialEq, Eq)]
struct States([u64; 4]);

impl States {
    const fn new() -> Self {
        Self([0; 4])
    }

    fn insert(&mut self, state: usize) {
        self.0[state / 64] |= 1 << (state % 64);
    }

    fn contains(&self, state: usize) -> bool {
        self.0[state / 64] & (1 << (state % 64)) != 0
    }

    fn is_empty(&self) -> bool {
        self.0 == [0; 4]
    }
}

/// Whether `name` matches `expression`. Expressions longer than
/// [`EXPRESSION_CAPACITY`] match nothing.
pub fn is_name_in_expression(expression: &[u16], name: &[u16]) -> bool {
    let end = expression.len();
    if end > EXPRESSION_CAPACITY {
        return false;
    }
    let last_dot = name.iter().rposition(|&unit| unit == DOT);
    let mut current = States::new();
    current.insert(0);
    for (index, &unit) in name.iter().enumerate() {
        close(&mut current, expression, Some(unit));
        let mut next = States::new();
        for (state, &token) in expression.iter().enumerate() {
            if !current.contains(state) {
                continue;
            }
            let advance = match token {
                STAR => {
                    next.insert(state);
                    false
                }
                DOS_STAR => {
                    // DOS_STAR stops before the final dot of the name.
                    if !(unit == DOT && last_dot == Some(index)) {
                        next.insert(state);
                    }
                    false
                }
                QUESTION => true,
                DOS_QM => unit != DOT,
                DOS_DOT => unit == DOT,
                literal => fold(literal) == fold(unit),
            };
            if advance {
                next.insert(state + 1);
            }
        }
        if next.is_empty() {
            return false;
        }
        current = next;
    }
    close(&mut current, expression, None);
    current.contains(end)
}

/// Add the positions reachable without consuming a character before
/// `next`, the following name character (`None` at the end of the name).
fn close(states: &mut States, expression: &[u16], next: Option<u16>) {
    for (state, &token) in expression.iter().enumerate() {
        if !states.contains(state) {
            continue;
        }
        let empty = match token {
            STAR | DOS_STAR => true,
            DOS_QM => matches!(next, None | Some(DOT)),
            DOS_DOT => next.is_none(),
            _ => false,
        };
        if empty {
            states.insert(state + 1);
        }
    }
}

/// Upper-case ASCII and Latin-1 letters.
pub const fn fold(unit: u16) -> u16 {
    match unit {
        0x61..=0x7a => unit - 0x20,
        0xe0..=0xfe if unit != 0xf7 => unit - 0x20,
        _ => unit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn units<const N: usize>(text: &[u8; N]) -> [u16; N] {
        text.map(u16::from)
    }

    fn matches(expression: &[u8], name: &[u8]) -> bool {
        let mut expression_units = [0; 64];
        let mut name_units = [0; 64];
        for (unit, &byte) in expression_units.iter_mut().zip(expression) {
            *unit = u16::from(byte);
        }
        for (unit, &byte) in name_units.iter_mut().zip(name) {
            *unit = u16::from(byte);
        }
        is_name_in_expression(
            &expression_units[..expression.len()],
            &name_units[..name.len()],
        )
    }

    #[test]
    fn star_and_question_mark() {
        assert!(matches(b"*", b"anything.txt"));
        assert!(matches(b"*", b""));
        assert!(matches(b"*.txt", b"notes.TXT"));
        assert!(!matches(b"*.txt", b"notes.txt.bak"));
        assert!(matches(b"a?c", b"abc"));
        assert!(!matches(b"a?c", b"ac"));
        assert!(matches(b"*a*b*", b"xxaxxbxx"));
        assert!(!matches(b"*a*b*", b"xxbxxaxx"));
        assert!(matches(b"default.xex", b"DEFAULT.XEX"));
    }

    #[test]
    fn dos_star_stops_at_the_final_dot() {
        // `<.txt` is how Win32 sends `*.txt`.
        assert!(matches(b"<.txt", b"a.b.txt"));
        assert!(!matches(b"<.txt", b"atxt"));
        // `<` alone takes every character when the name has no dot.
        assert!(matches(b"<", b"name"));
        assert!(!matches(b"<", b"name.ext"));
        assert!(matches(b"<.<", b"name.ext"));
    }

    #[test]
    fn dos_question_mark_and_dot() {
        // `>>>>>>>>.>>>` and `<"*` are the 8.3 forms of `????????.???`
        // and `*.*`.
        assert!(matches(b">>>>>>>>\">>>", b"abc.d"));
        assert!(matches(b">>>>>>>>\">>>", b"abc"));
        assert!(!matches(b">>>>>>>>\">>>", b"abcdefghi.txt"));
        assert!(matches(b"<\"*", b"file"));
        assert!(matches(b"<\"*", b"file.txt"));
        assert!(matches(b"a>", b"a"));
        assert!(matches(b"a>", b"ab"));
        assert!(!matches(b"a>", b"abc"));
    }

    #[test]
    fn latin1_letters_compare_without_case() {
        let expression = [0xc9];
        let name = [0xe9];
        assert!(is_name_in_expression(&expression, &name));
        let _ = units(b"x");
    }
}
