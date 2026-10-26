use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;

use crate::commands::network::netsim::classifier::variant::VariantError;

/// Stock results of the compile errors, named here by the error they
/// report.
pub(crate) mod result {
    use openxbdm_core::status::Hresult;
    use openxbdm_core::status::xbdm_error;
    use xbox360_sys::status::Facility;

    pub const SYNTAX: Hresult = win32(0x545);
    pub const STACK_OVERFLOW: Hresult = win32(0x3e9);
    pub const OUT_OF_MEMORY: Hresult = Hresult::OUT_OF_MEMORY;
    pub const INVALID_CHARACTER: Hresult = win32(0xd);
    pub const UNTERMINATED_COMMENT: Hresult = win32(0x26);
    pub const TRUNCATED_NUMBER: Hresult = win32(0x44c);
    pub const NUMBER_OVERFLOW: Hresult = win32(0x216);
    pub const SUFFIX_OVERFLOW: Hresult = win32(0xea);
    pub const MISSING_OPERAND: Hresult = win32(0x10d2);
    pub const EMPTY_NAME: Hresult = win32(0x7b);
    pub const NAME_TOO_LONG: Hresult = win32(0x9a);
    pub const TOO_MANY_ITEMS: Hresult = win32(0x44);
    pub const NOT_SCALAR: Hresult = win32(0x99);
    pub const WRONG_ITEM_KIND: Hresult = win32(0x48a);
    pub const NEGATIVE_INDEX: Hresult = win32(0x83);
    pub const INDEX_OUT_OF_RANGE: Hresult = win32(0x585);
    pub const TOO_FEW_ARGUMENTS: Hresult = dispatch(0x4);
    pub const TOO_MANY_ARGUMENTS: Hresult = dispatch(0xe);
    /// Stock returns the monitor's facility 0x2da code 0x10 for a
    /// constant-false program, the value of status 416 "not debuggable".
    pub const ALWAYS_FALSE: Hresult = xbdm_error(0x10);

    const fn win32(code: u16) -> Hresult {
        Hresult::failure(Facility::WIN32, code)
    }

    const fn dispatch(code: u16) -> Hresult {
        Hresult::failure(Facility::new(2), code)
    }
}

/// Why classifier text did not compile. Titles receive the result value
/// through the simulator exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompileError {
    Syntax,
    StackOverflow,
    OutOfMemory,
    InvalidCharacter,
    UnterminatedComment,
    TruncatedNumber,
    NumberOverflow,
    SuffixOverflow,
    MissingOperand,
    EmptyName,
    NameTooLong,
    TooManyItems,
    NotScalar,
    WrongItemKind,
    NegativeIndex,
    IndexOutOfRange,
    TooFewArguments,
    TooManyArguments,
    /// The program is a constant false: it would match nothing.
    AlwaysFalse,
    /// A name that is not in the field table.
    UnknownField,
    /// Constant folding failed.
    Value(VariantError),
}

impl From<VariantError> for CompileError {
    fn from(error: VariantError) -> Self {
        Self::Value(error)
    }
}

impl From<CompileError> for Hresult {
    fn from(error: CompileError) -> Self {
        match error {
            CompileError::Syntax => result::SYNTAX,
            CompileError::StackOverflow => result::STACK_OVERFLOW,
            CompileError::OutOfMemory => result::OUT_OF_MEMORY,
            CompileError::InvalidCharacter => result::INVALID_CHARACTER,
            CompileError::UnterminatedComment => result::UNTERMINATED_COMMENT,
            CompileError::TruncatedNumber => result::TRUNCATED_NUMBER,
            CompileError::NumberOverflow => result::NUMBER_OVERFLOW,
            CompileError::SuffixOverflow => result::SUFFIX_OVERFLOW,
            CompileError::MissingOperand => result::MISSING_OPERAND,
            CompileError::EmptyName => result::EMPTY_NAME,
            CompileError::NameTooLong => result::NAME_TOO_LONG,
            CompileError::TooManyItems => result::TOO_MANY_ITEMS,
            CompileError::NotScalar => result::NOT_SCALAR,
            CompileError::WrongItemKind => result::WRONG_ITEM_KIND,
            CompileError::NegativeIndex => result::NEGATIVE_INDEX,
            CompileError::IndexOutOfRange => result::INDEX_OUT_OF_RANGE,
            CompileError::TooFewArguments => result::TOO_FEW_ARGUMENTS,
            CompileError::TooManyArguments => result::TOO_MANY_ARGUMENTS,
            CompileError::AlwaysFalse => result::ALWAYS_FALSE,
            CompileError::UnknownField => Hresult::NO_SUCH_FIELD,
            CompileError::Value(error) => error.into(),
        }
    }
}
