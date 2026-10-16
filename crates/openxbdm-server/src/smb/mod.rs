//! SMB 2 file sharing of the console's drives ([`smb2_server`]).
//!
//! Shares: every name of the drive table and of the internal drive
//! mapping (`drivemap internal`) is a share whose device exists, whether
//! or not `drivelist` shows it. A drive pointing at `\Badpath` serves its
//! internal mapping target. The hidden SystemRoot row, other names that
//! are not valid share names, and title mappings longer than an object
//! name are skipped; a repeated name, compared without case, is listed
//! once. A share exists when the root of its target opens as a directory
//! or its device has no medium. Shares on optical drives and on volumes
//! that report themselves read-only are read-only. A tree connect binds
//! the share name to its target at that time; when the name is removed
//! or points elsewhere, the tree's requests fail with
//! `NETWORK_NAME_DELETED`.
//!
//! Paths: share paths become kernel object names below the share's
//! target, one byte per UTF-16 code unit; code units above 0xff are
//! invalid.
//!
//! Logons: while security is disabled, every user name is an account with
//! the empty password, and guest and anonymous logons are allowed. While
//! the console is locked, no logon succeeds, no share is listed or found,
//! and opens, renames, and deletes fail with `ACCESS_DENIED`, also in
//! sessions established before the lock; files already open may still be
//! read and written.

mod adapter;
mod limits;
mod service;
mod shares;

pub use service::BUFFER_SIZE;
pub use service::SmbService;
