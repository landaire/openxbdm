//! Backslash-separated object name helpers.

pub(super) fn parent(path: &[u8]) -> &[u8] {
    &path[..path.iter().rposition(|&byte| byte == b'\\').unwrap_or(0)]
}

pub(super) fn leaf(path: &[u8]) -> &[u8] {
    &path[path
        .iter()
        .rposition(|&byte| byte == b'\\')
        .map_or(0, |index| index + 1)..]
}

fn starts_with_ignore_case(text: &[u8], prefix: &[u8]) -> bool {
    text.len() >= prefix.len() && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Whether `path` names an object below `ancestor`.
pub(super) fn is_below(path: &[u8], ancestor: &[u8]) -> bool {
    path.len() > ancestor.len()
        && starts_with_ignore_case(path, ancestor)
        && path[ancestor.len()] == b'\\'
}

/// The rest of `path` after `prefix` when `prefix` names a whole
/// component.
pub(super) fn strip_component<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if !starts_with_ignore_case(path, prefix) {
        return None;
    }

    let rest = &path[prefix.len()..];
    (rest.is_empty() || rest[0] == b'\\').then_some(rest)
}
