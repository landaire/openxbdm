//! XBDM name discovery (NAP) protocol.
//!
//! XBDM devkits listen on UDP port 730 for name-resolution packets. A host
//! either asks "is your name `foo`?" (lookup, opcode `0x01`) or "what is
//! your name?" (identify, opcode `0x03`). Consoles reply with an `0x02`
//! packet whose body echoes their own `dbgname`. The reply's source
//! address is the console's IP.
//!
//! This module exposes the wire format as a pure encoder/decoder so it can
//! be tested and fuzzed without any sockets. The I/O-bearing runner lives
//! in [`runner`] and is feature-gated behind `tokio`.

mod engine;
mod wire;

#[cfg(feature = "tokio")]
pub mod runner;

pub use engine::Discovery;
pub use engine::DiscoveryAction;
pub use engine::DiscoveryConfig;
pub use wire::DiscoveredConsole;
pub use wire::MAX_NAME_LEN;
pub use wire::NAP_PORT;
pub use wire::NapError;
pub use wire::NapRequest;
pub use wire::NapResponse;
pub use wire::RESPONSE_OPCODE;
pub use wire::RequestOpcode;
pub use wire::encode_request;
pub use wire::parse_response;

#[cfg(feature = "tokio")]
pub use runner::discover_all;
#[cfg(feature = "tokio")]
pub use runner::find_by_name;
