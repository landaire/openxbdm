//! Console paths of PIX capture segment files.

/// A capture remote path split into the parts that name its segment files.
///
/// The PIX handler writes the capture as numbered segments
/// `<stem><N><extension>` next to the requested `<stem><extension>`, with
/// `N` counting from 0.
#[derive(Debug)]
pub struct CaptureRemotePath {
    /// DOS-form directory, always ending in `\` (e.g. `DEVKIT:\`).
    pub parent: String,
    /// Filename stem, without extension.
    pub stem: String,
    /// Extension with leading `.` (e.g. `.xbm`), or empty if no dot.
    pub extension: String,
}

impl CaptureRemotePath {
    /// Accepts both the NT device form
    /// (`\Device\Harddisk0\Partition1\DEVKIT\foo.xbm`) and the DOS form
    /// (`DEVKIT:\foo.xbm`), translating the former to the latter for use
    /// with xbdm's file commands. An NT-form path is assumed to be on
    /// partition 1; any other layout needs a DOS-form path.
    pub fn parse(remote: &str) -> Self {
        const NT_PREFIX: &str = r"\Device\Harddisk0\Partition1\";

        // The rest looks like `DEVKIT\foo.xbm`; the first `\` becomes `:\`.
        let dos_form = match remote.strip_prefix(NT_PREFIX) {
            Some(rest) => match rest.split_once('\\') {
                Some((drive, path)) => format!("{drive}:\\{path}"),
                None => format!("{rest}:\\"),
            },
            None => remote.to_owned(),
        };

        let last_separator = dos_form.rfind('\\').unwrap_or(0);
        let (parent, name) = dos_form.split_at(last_separator + 1);
        let (stem, extension) = match name.rfind('.') {
            Some(dot) => (&name[..dot], &name[dot..]),
            None => (name, ""),
        };

        Self {
            parent: parent.to_owned(),
            stem: stem.to_owned(),
            extension: extension.to_owned(),
        }
    }

    /// Segment number of `file_name` when it names a segment of this capture.
    pub fn segment_index(&self, file_name: &str) -> Option<u32> {
        let index = file_name
            .strip_prefix(self.stem.as_str())?
            .strip_suffix(self.extension.as_str())?;

        index.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_nt_device_path() {
        let CaptureRemotePath {
            parent,
            stem,
            extension,
        } = CaptureRemotePath::parse(r"\Device\Harddisk0\Partition1\DEVKIT\foo.xbm");
        assert_eq!(parent, r"DEVKIT:\");
        assert_eq!(stem, "foo");
        assert_eq!(extension, ".xbm");
    }

    #[test]
    fn splits_dos_path_unchanged() {
        let CaptureRemotePath {
            parent,
            stem,
            extension,
        } = CaptureRemotePath::parse(r"DEVKIT:\bar.xbm");
        assert_eq!(parent, r"DEVKIT:\");
        assert_eq!(stem, "bar");
        assert_eq!(extension, ".xbm");
    }

    #[test]
    fn splits_nt_nested() {
        let CaptureRemotePath {
            parent,
            stem,
            extension,
        } = CaptureRemotePath::parse(r"\Device\Harddisk0\Partition1\DEVKIT\sub\baz.xbm");
        assert_eq!(parent, r"DEVKIT:\sub\");
        assert_eq!(stem, "baz");
        assert_eq!(extension, ".xbm");
    }
}
