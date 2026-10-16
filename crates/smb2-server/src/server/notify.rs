//! CHANGE_NOTIFY (MS-SMB2 3.3.5.19).
//!
//! Changes made through the server are reported with their names. Changes
//! made outside it are found by scanning watched directories every
//! [`ServerConfig::change_scan_interval`](crate::ServerConfig) and are
//! reported as STATUS_NOTIFY_ENUM_DIR, which tells the client to list the
//! directory again. Changes that happen while no CHANGE_NOTIFY is pending
//! are not kept; the next one reports STATUS_NOTIFY_ENUM_DIR.

use crate::backend::Backend;
use crate::fs::AccessMask;
use crate::server::Body;
use crate::server::Completion;
use crate::server::Connection;
use crate::server::Exchange;
use crate::server::Failure;
use crate::server::Handled;
use crate::server::RequestError;
use crate::server::Server;
use crate::server::pending::baseline;
use crate::server::shared::ChangeFilter;
use crate::server::tables::NotifyState;
use crate::server::tables::OpenKind;
use crate::server::tables::PendingKind;
use crate::server::wire;
use crate::server::wire::FileId;

const REQUEST_FIXED: usize = 32;

/// Flags of a CHANGE_NOTIFY request (MS-SMB2 2.2.35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotifyFlags(u16);

impl NotifyFlags {
    const WATCH_TREE: Self = Self(0x0001);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Filter bits a client may set (MS-SMB2 2.2.35).
const VALID_FILTER: ChangeFilter = ChangeFilter(0x0000_0fff);

impl Connection {
    pub(super) fn change_notify(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        let body = exchange.fixed_body(32, REQUEST_FIXED)?;
        let tree = NotifyFlags(wire::u16_at(body, 2)).contains(NotifyFlags::WATCH_TREE);
        let output_length = wire::u32_at(body, 4);
        // Undefined filter bits are ignored; a request with no defined
        // bits matches nothing and waits until it is cancelled or its open
        // closes.
        let filter = ChangeFilter(wire::u32_at(body, 24) & VALID_FILTER.0);
        let slot = self.find_open(exchange, FileId::read(body, 8))?;
        if output_length as usize > exchange.config.max_io() {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        let open = *self.open(slot);
        let OpenKind::File(file) = open.kind else {
            return Err(Failure::Error(RequestError::InvalidRequest));
        };
        if !file.directory {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        if !open.access.contains(AccessMask::READ_DATA) {
            return Err(Failure::Error(RequestError::AccessDenied));
        }
        let state = match file.notify {
            Some(state) => NotifyState {
                filter,
                tree,
                ..state
            },
            None => {
                let (digest, scanned) = match exchange.config.change_scan_interval {
                    Some(_) => {
                        let now = backend.system_time();
                        let (digest, scanned) = baseline(
                            backend,
                            server.files.share(file.file),
                            server.files.path(file.file),
                            tree,
                            now,
                        );
                        (Some(digest), scanned)
                    }
                    None => (None, crate::fs::FileTime(0)),
                };
                NotifyState {
                    filter,
                    tree,
                    overflowed: false,
                    digest,
                    scanned,
                }
            }
        };
        let overflowed = state.overflowed;
        if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
            file.notify = Some(NotifyState {
                overflowed: false,
                ..state
            });
        }
        // Changes that were not kept, or a request that cannot wait in a
        // compound chain, tell the client to list the directory again.
        if overflowed || !exchange.last {
            output[..8].fill(0);
            wire::put_u16(output, 0, 9);
            return Ok(Body {
                completion: Completion::NotifyEnumDirectory,
                length: 8,
            });
        }
        if self.pending.iter().flatten().any(|pending| {
            pending.open == slot
                && pending.ready.is_none()
                && matches!(pending.kind, PendingKind::Notify { .. })
        }) {
            // One notification waits per open at a time.
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        let session = exchange.session.ok_or(RequestError::SessionNotFound)?;
        let async_id = self.add_pending(
            &exchange.header,
            exchange.encrypted,
            session,
            slot,
            PendingKind::Notify { output_length },
        )?;
        Err(Failure::Pending { async_id })
    }
}
