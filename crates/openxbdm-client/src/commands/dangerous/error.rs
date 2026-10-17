#[derive(Debug, thiserror::Error)]
pub enum PeError {
    #[error("DOS header does not start with MZ signature")]
    MissingDosSignature,
    #[error("PE signature not found at e_lfanew offset")]
    MissingPeSignature,
    #[error("unsupported PE machine type {0:#06x}; expected POWERPCBE (0x01F2)")]
    UnexpectedMachine(u16),
    #[error("PE claims {0} sections which is implausible for xbdm")]
    AbsurdSectionCount(u16),
}

#[derive(Debug, thiserror::Error)]
pub enum DrivemapError {
    #[error("could not find the xbdm module in the running kernel's module list")]
    XbdmModuleMissing,
    #[error("a required section ({0}) is missing from xbdm's PE header")]
    SectionMissing(&'static str),
    #[error(
        "could not locate the drivemap setup function: no code signature matched. \
         This xbdm build may reorganize the startup call chain."
    )]
    DrivemapFunctionNotFound,
    #[error(
        "found drivemap signature but the function prologue is wrong; refusing \
         to proceed rather than jump to a mid-function address"
    )]
    DrivemapPrologueMismatch,
    #[error(
        "could not locate the drivemap internal flag global by scanning ini-parser \
         call pattern"
    )]
    DrivemapFlagNotFound,
    #[error(
        "could not locate the altaddr command-table entry; looked for a .data pointer \
         to the \"altaddr\" string followed by a plausible handler pointer"
    )]
    AltaddrEntryNotFound,
    #[error(
        "altaddr handler pointer {got:#010x} is outside the xbdm .text range; refusing \
         to overwrite an entry that may not be what we think it is"
    )]
    AltaddrHandlerOutsideText { got: u32 },
    #[error(
        "after swapping, altaddr no longer returns a valid reply. patch has been \
         rolled back; console should still be reachable"
    )]
    InvocationFailed,
    #[error(
        "failed to restore altaddr handler after invocation. the console is in a \
         broken state -- probe {expected:#010x}, observed {observed:#010x}"
    )]
    RestoreMismatch { expected: u32, observed: u32 },
}
