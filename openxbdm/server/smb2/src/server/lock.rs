//! LOCK (MS-SMB2 3.3.5.14): byte-range locks held in the server's lock
//! table.

use crate::fs::AccessMask;
use crate::server::Connection;
use crate::server::Server;
use crate::server::error::LockRefusal;
use crate::server::error::RequestError;
use crate::server::request::Body;
use crate::server::request::Exchange;
use crate::server::request::Failure;
use crate::server::request::Handled;
use crate::server::request::empty_body;
use crate::server::shared::ByteRange;
use crate::server::shared::MAX_LOCKS;
use crate::server::tables::OpenKind;
use crate::server::tables::PendingKind;
use crate::server::wire;
use crate::server::wire::FileId;

const REQUEST_FIXED: usize = 24;
const ELEMENT: usize = 24;

/// Flags of a LOCK element (MS-SMB2 2.2.26.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LockFlags(u32);

impl LockFlags {
    const SHARED: Self = Self(0x01);
    const EXCLUSIVE: Self = Self(0x02);
    const UNLOCK: Self = Self(0x04);
    const FAIL_IMMEDIATELY: Self = Self(0x10);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// One element of a LOCK request.
#[derive(Debug, Clone, Copy)]
struct Element {
    range: ByteRange,
    flags: LockFlags,
}

impl Element {
    fn read(body: &[u8], index: usize) -> Self {
        let at = REQUEST_FIXED + index * ELEMENT;

        Self {
            range: ByteRange {
                offset: wire::u64_at(body, at),
                length: wire::u64_at(body, at + 8),
            },
            flags: LockFlags(wire::u32_at(body, at + 16)),
        }
    }
}

impl Connection {
    pub(super) fn lock(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        output: &mut [u8],
    ) -> Handled {
        let body = exchange.fixed_body(48, REQUEST_FIXED + ELEMENT)?;
        let count = usize::from(wire::u16_at(body, 2));
        if count == 0 || body.len() < REQUEST_FIXED + count * ELEMENT {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }

        let slot = self.find_open(exchange, FileId::read(body, 8))?;
        let open = *self.open(slot);
        let OpenKind::File(file) = open.kind else {
            return Err(Failure::Error(RequestError::WrongFileKind));
        };
        if file.directory {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }

        let owner = self.lock_owner(open.id);
        let first = Element::read(body, 0);
        if first.flags.contains(LockFlags::UNLOCK) {
            for index in 0..count {
                let element = Element::read(body, index);
                if element.flags != LockFlags::UNLOCK {
                    return Err(Failure::Error(RequestError::InvalidRequest));
                }
                if !server.locks.unlock(file.file, owner, element.range) {
                    return Err(Failure::Error(RequestError::RangeNotLocked));
                }
            }

            return Ok(Body::success(empty_body(output)));
        }

        if !open
            .access
            .intersects(AccessMask::READ_DATA.union(AccessMask::WRITE_DATA))
        {
            return Err(Failure::Error(RequestError::AccessDenied));
        }

        for index in 0..count {
            let element = Element::read(body, index);
            let mode = element.flags.without(LockFlags::FAIL_IMMEDIATELY);
            if (mode != LockFlags::SHARED && mode != LockFlags::EXCLUSIVE)
                || (count > 1 && !element.flags.contains(LockFlags::FAIL_IMMEDIATELY))
            {
                return Err(Failure::Error(RequestError::InvalidRequest));
            }
            if element.range.length != 0
                && element
                    .range
                    .offset
                    .checked_add(element.range.length - 1)
                    .is_none()
            {
                return Err(Failure::Error(RequestError::InvalidLockRange));
            }
        }

        // Each granted element holds a lock table entry, so a request takes
        // at most MAX_LOCKS of them.
        let mut taken = [None; MAX_LOCKS];
        let mut held = 0;
        for index in 0..count {
            let element = Element::read(body, index);
            let exclusive = element.flags.contains(LockFlags::EXCLUSIVE);
            let refusal = match server
                .locks
                .lock(file.file, owner, element.range, exclusive)
            {
                Ok(lock) => {
                    taken[held] = Some(lock);
                    held += 1;
                    continue;
                }
                Err(refusal) => refusal,
            };

            // The locks this request took are released before it fails.
            for lock in taken.into_iter().flatten() {
                server.locks.release(lock);
            }

            return match refusal {
                LockRefusal::Exhausted => Err(Failure::Error(RequestError::TableFull)),
                LockRefusal::Conflict
                    if element.flags.contains(LockFlags::FAIL_IMMEDIATELY) || !exchange.last =>
                {
                    Err(Failure::Error(RequestError::LockNotGranted))
                }
                LockRefusal::Conflict => {
                    let session = exchange.session.ok_or(RequestError::SessionNotFound)?;
                    let async_id = self.add_pending(
                        &exchange.header,
                        exchange.encrypted,
                        session,
                        slot,
                        PendingKind::Lock {
                            range: element.range,
                            exclusive,
                            epoch: server.locks.epoch(),
                        },
                    )?;

                    Err(Failure::Pending { async_id })
                }
            };
        }

        Ok(Body::success(empty_body(output)))
    }
}
