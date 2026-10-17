/// Why the driver was not patched. Stock returns the status named in each
/// comment; the caller only reports the failure.
#[derive(Debug)]
pub(super) enum PatchError {
    /// `KernelError::NoSuchDevice`.
    NoDevice,
    /// The kernel is not a 2.0.x.0x8000 build: `KernelError::InvalidParameter`.
    UnsupportedKernel,
    /// `KernelError::ObjectNameNotFound`.
    ChannelNotFound,
    /// The channel does not belong to the device:
    /// `KernelError::AccessViolation`.
    InvalidChannel,
    /// `KernelError::InvalidHandle`.
    NoDriverObject,
    /// Stock does not check the allocations.
    NoIrp,
}

impl core::fmt::Display for PatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NoDevice => "no CD-ROM device",
            Self::UnsupportedKernel => "unsupported kernel",
            Self::ChannelNotFound => "CD-ROM channel not found",
            Self::InvalidChannel => "invalid CD-ROM channel",
            Self::NoDriverObject => "no CD-ROM driver object",
            Self::NoIrp => "request allocation failed",
        })
    }
}

impl core::error::Error for PatchError {}
