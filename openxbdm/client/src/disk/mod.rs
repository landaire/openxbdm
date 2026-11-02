//! Read-only access to the console's block devices over `gethddblk`.
//!
//! [`RemoteDisk`] presents a device as an [`fskit::AsyncReadAt`] source so
//! that sans-io parsers can read it in place, and [`Pull`] drives a
//! resumable copy of a whole device to an image file.

mod error;
mod known;
mod pull;
mod remote;
mod signature;

pub use error::DiskError;
pub use error::JournalError;
pub use known::DeviceKind;
pub use known::KNOWN_DEVICES;
pub use known::KnownDevice;
pub use known::known_device;
pub use pull::MAX_LINE_LEN;
pub use pull::Pull;
pub use pull::PullHeader;
pub use pull::PullStep;
pub use pull::SEGMENT_LEN;
pub use pull::SegmentRecord;
pub use remote::DeviceSize;
pub use remote::RemoteDisk;
pub use remote::SectorRun;
pub use remote::sector_runs;
pub use signature::Signature;
