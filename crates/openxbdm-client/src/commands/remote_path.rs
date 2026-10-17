//! Console path manipulation. Console paths separate components with `\`
//! and may start with a `DRIVE:` prefix.

/// `path` with a trailing `\`. Empty paths are returned unchanged.
pub fn normalize_dir_path(path: &str) -> String {
    if path.ends_with('\\') || path.is_empty() {
        return path.to_owned();
    }

    format!("{path}\\")
}

/// `child` appended to the directory `parent`.
pub fn join_path(parent: &str, child: &str) -> String {
    if parent.ends_with('\\') {
        return format!("{parent}{child}");
    }

    format!("{parent}\\{child}")
}

/// Last non-empty component of `path`. The drive prefix is never returned,
/// so the result is usable as a host file name.
pub fn basename(path: &str) -> Option<&str> {
    let after_drive = path.split_once(':').map_or(path, |(_, rest)| rest);

    after_drive
        .rsplit(['\\', '/'])
        .find(|component| !component.is_empty())
}
