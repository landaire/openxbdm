use openxbdm_core::status::Hresult;

/// Why a value operation failed. Constant folding hands the result value
/// to titles through the simulator exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VariantError {
    /// The value has no type.
    NoValue,
    /// The operation does not accept the value's type.
    WrongType,
    /// The value is wider than the target integer.
    TooWide,
    /// Signed value to unsigned target or the reverse.
    SignMismatch,
    DivideByZero,
    /// Signed division of `i64::MIN` by -1.
    Overflow,
    NegativeShift,
    BadIndex,
    BadLength,
}

impl From<VariantError> for Hresult {
    fn from(error: VariantError) -> Self {
        Self(match error {
            VariantError::NoValue => 0x8007_0483,
            VariantError::WrongType => 0x8007_0545,
            VariantError::TooWide => 0x8007_00ea,
            VariantError::SignMismatch => 0x8007_00d1,
            VariantError::DivideByZero => 0x8002_0012,
            VariantError::Overflow => 0x8007_0216,
            VariantError::NegativeShift => 0x8007_0083,
            VariantError::BadIndex => 0x8007_0585,
            VariantError::BadLength => 0x8007_0018,
        })
    }
}
