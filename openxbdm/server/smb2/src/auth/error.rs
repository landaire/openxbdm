//! Failures of an authentication exchange.

use crate::status::NtStatus;

/// An NTLMSSP message the server receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtlmMessage {
    Negotiate,
    Authenticate,
}

impl core::fmt::Display for NtlmMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Negotiate => "NEGOTIATE",
            Self::Authenticate => "AUTHENTICATE",
        })
    }
}

/// Why [`Authenticator::step`](super::Authenticator::step) failed. The
/// exchange is over either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// A SPNEGO or NTLMSSP token does not parse.
    MalformedToken,
    /// A message the server keeps for MIC computation exceeds its buffer.
    MessageTooLarge { length: usize, capacity: usize },
    /// A well-formed NTLMSSP message of the wrong type for this stage.
    UnexpectedMessage { expected: NtlmMessage },
    /// The client's SPNEGO mechanism list does not include NTLMSSP.
    MechanismNotOffered,
    /// The NEGOTIATE does not request Unicode strings.
    NotUnicode,
    /// The AUTHENTICATE carries an NTLMv1 or LM response.
    NtlmV1Response,
    /// A null session while the backend refuses anonymous logons.
    AnonymousRefused,
    /// No such account while the backend refuses guest logons.
    UnknownAccount,
    /// The account exists and the response does not prove its password.
    WrongPassword,
    /// The AUTHENTICATE MIC does not match.
    MicMismatch,
    /// NTLMSSP was not the client's first mechanism and the final token
    /// has no mechListMIC.
    MechListMicMissing,
    /// The client's mechListMIC does not match.
    MechListMicMismatch,
    /// Signing is negotiated without extended session security, so the
    /// mechListMIC cannot be computed.
    MechListMicUnsupported,
    /// The client sent negState reject.
    ClientRejected,
    /// The reply does not fit the output buffer.
    OutputTooSmall,
    /// The backend reported a computer name longer than its buffer.
    InvalidComputerName { length: usize },
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedToken => formatter.write_str("malformed security token"),
            Self::MessageTooLarge { length, capacity } => write!(
                formatter,
                "message of {length} bytes exceeds the {capacity}-byte buffer"
            ),
            Self::UnexpectedMessage { expected } => {
                write!(formatter, "expected an NTLMSSP {expected} message")
            }
            Self::MechanismNotOffered => formatter.write_str("client does not offer NTLMSSP"),
            Self::NotUnicode => formatter.write_str("client does not support Unicode"),
            Self::NtlmV1Response => formatter.write_str("NTLMv1 responses are not accepted"),
            Self::AnonymousRefused => formatter.write_str("anonymous logon refused"),
            Self::UnknownAccount => formatter.write_str("unknown account"),
            Self::WrongPassword => formatter.write_str("wrong password"),
            Self::MicMismatch => formatter.write_str("AUTHENTICATE MIC mismatch"),
            Self::MechListMicMissing => formatter.write_str("required mechListMIC is absent"),
            Self::MechListMicMismatch => formatter.write_str("mechListMIC mismatch"),
            Self::MechListMicUnsupported => {
                formatter.write_str("mechListMIC requires extended session security")
            }
            Self::ClientRejected => formatter.write_str("client rejected the negotiation"),
            Self::OutputTooSmall => formatter.write_str("output buffer too small"),
            Self::InvalidComputerName { length } => {
                write!(formatter, "computer name length {length} exceeds capacity")
            }
        }
    }
}

impl core::error::Error for AuthError {}

impl From<AuthError> for NtStatus {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::MalformedToken
            | AuthError::MessageTooLarge { .. }
            | AuthError::UnexpectedMessage { .. } => Self::InvalidParameter,
            AuthError::MechanismNotOffered
            | AuthError::NotUnicode
            | AuthError::NtlmV1Response
            | AuthError::AnonymousRefused
            | AuthError::UnknownAccount
            | AuthError::WrongPassword
            | AuthError::MicMismatch
            | AuthError::MechListMicMissing
            | AuthError::MechListMicMismatch
            | AuthError::MechListMicUnsupported
            | AuthError::ClientRejected => Self::LogonFailure,
            AuthError::OutputTooSmall => Self::BufferTooSmall,
            AuthError::InvalidComputerName { .. } => Self::InternalError,
        }
    }
}
