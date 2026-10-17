//! Session errors.

use crate::EncodeError;
use crate::packet::PacketId;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("packet {outstanding:?} is not acknowledged yet")]
    Outstanding { outstanding: PacketId },
    #[error(transparent)]
    Encode(#[from] EncodeError),
}
