/// Why a XAM export could not be called. The failure is stored as the
/// calling thread's last error, as stock stores it.
#[derive(Debug)]
pub(super) enum Unresolved {
    /// xam.xex is not loaded.
    Module,
    /// The export is absent.
    Export,
}

impl core::fmt::Display for Unresolved {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Module => "xam.xex is not loaded",
            Self::Export => "the XAM export is absent",
        })
    }
}

impl core::error::Error for Unresolved {}
