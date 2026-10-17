//! Validated paths relative to the root of a share.

mod error;

use crate::utf16::Utf16Le;

pub use self::error::PathError;

const SEPARATOR: u16 = b'\\' as u16;

/// A path relative to a share root: components separated by `\`, none of
/// them empty, `.` or `..`, and no characters that NT file names exclude.
/// The empty path names the share root.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SharePath<'a>(Utf16Le<'a>);

impl<'a> SharePath<'a> {
    pub const ROOT: SharePath<'static> = SharePath(Utf16Le::EMPTY);

    /// Validate a path from a request.
    pub fn parse(path: Utf16Le<'a>) -> Result<Self, PathError> {
        let path = strip_default_stream(path);

        if path.is_empty() {
            return Ok(Self(path));
        }

        if path.unit(0) == Some(SEPARATOR) {
            return Err(PathError::LeadingSeparator);
        }

        for component in split(path) {
            validate_component(component)?;
        }

        Ok(Self(path))
    }

    pub const fn as_utf16(self) -> Utf16Le<'a> {
        self.0
    }

    pub const fn is_root(self) -> bool {
        self.0.is_empty()
    }

    pub fn components(self) -> impl DoubleEndedIterator<Item = Utf16Le<'a>> + Clone {
        let path = self.0;
        let empty = path.is_empty();

        split(path).filter(move |_| !empty)
    }

    /// The last component, or `None` for the root.
    pub fn file_name(self) -> Option<Utf16Le<'a>> {
        self.components().next_back()
    }

    /// The path without its last component; the root for a one-component
    /// path, `None` for the root itself.
    pub fn parent(self) -> Option<Self> {
        if self.is_root() {
            return None;
        }

        // A path with one component has the root as its parent.
        let end = self
            .0
            .units()
            .rposition(|unit| unit == SEPARATOR)
            .unwrap_or(0);

        Some(Self(self.0.slice(0, end)))
    }
}

impl core::fmt::Debug for SharePath<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "SharePath({:?})", self.0)
    }
}

#[derive(Clone)]
struct Components<'a> {
    rest: Option<&'a [u8]>,
}

impl<'a> Iterator for Components<'a> {
    type Item = Utf16Le<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let rest = self.rest?;

        match find_separator(rest) {
            Some(index) => {
                self.rest = Some(&rest[index + 2..]);
                Utf16Le::new(&rest[..index])
            }
            None => {
                self.rest = None;
                Utf16Le::new(rest)
            }
        }
    }
}

impl DoubleEndedIterator for Components<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let rest = self.rest?;

        match rfind_separator(rest) {
            Some(index) => {
                self.rest = Some(&rest[..index]);
                Utf16Le::new(&rest[index + 2..])
            }
            None => {
                self.rest = None;
                Utf16Le::new(rest)
            }
        }
    }
}

/// Components of `path` split at separators.
fn split(path: Utf16Le<'_>) -> Components<'_> {
    Components {
        rest: Some(path.as_bytes()),
    }
}

fn find_separator(bytes: &[u8]) -> Option<usize> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .position(|pair| *pair == [b'\\', 0])
        .map(|index| index * 2)
}

fn rfind_separator(bytes: &[u8]) -> Option<usize> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .rposition(|pair| *pair == [b'\\', 0])
        .map(|index| index * 2)
}

fn strip_default_stream(path: Utf16Le<'_>) -> Utf16Le<'_> {
    // Suffix naming the default data stream, which the server accepts and
    // removes.
    const DEFAULT_STREAM: &[u8] = b"::$DATA";

    let suffix = DEFAULT_STREAM.len();

    if path.len() >= suffix
        && path
            .slice(path.len() - suffix, path.len())
            .eq_ignore_ascii_case(DEFAULT_STREAM)
    {
        path.slice(0, path.len() - suffix)
    } else {
        path
    }
}

fn validate_component(component: Utf16Le<'_>) -> Result<(), PathError> {
    if component.is_empty() {
        return Err(PathError::EmptyComponent);
    }

    if component.eq_ignore_ascii_case(b".") || component.eq_ignore_ascii_case(b"..") {
        return Err(PathError::RelativeComponent);
    }

    match component.units().find(|&unit| is_excluded(unit)) {
        Some(unit) => Err(PathError::ExcludedCharacter { unit }),
        None => Ok(()),
    }
}

/// Characters NT file names exclude (MS-FSCC 2.1.5.2), including the
/// wildcards and the stream separator.
pub(crate) const fn is_excluded(unit: u16) -> bool {
    unit < 0x20
        || matches!(
            unit,
            0x22 | 0x2a | 0x2f | 0x3a | 0x3c | 0x3e | 0x3f | 0x5c | 0x7c
        )
}
