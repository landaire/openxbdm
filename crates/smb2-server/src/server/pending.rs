//! Requests answered after their interim reply (MS-SMB2 3.3.4.2): change
//! notifications and blocking byte-range locks, their cancellation, and
//! the scans that find changes made outside the server.

use crate::backend::Backend;
use crate::backend::ShareId;
use crate::pattern::fold;
use crate::server::Connection;
use crate::server::Server;
use crate::server::ServerConfig;
use crate::server::error::LockRefusal;
use crate::server::error::RequestError;
use crate::server::request::ERROR_BODY;
use crate::server::request::RequestHeader;
use crate::server::scan::scan;
use crate::server::security;
use crate::server::shared::Change;
use crate::server::shared::ChangeSequence;
use crate::server::shared::FileSlot;
use crate::server::tables::NotifyState;
use crate::server::tables::OpenKind;
use crate::server::tables::OpenSlot;
use crate::server::tables::Pending;
use crate::server::tables::PendingKind;
use crate::server::tables::PendingOutcome;
use crate::server::tables::SessionSlot;
use crate::server::wire;
use crate::server::wire::AsyncId;
use crate::server::wire::Command;
use crate::server::wire::HEADER_SIZE;
use crate::server::wire::HeaderFlags;
use crate::server::wire::header;
use crate::status::NtStatus;
use crate::transport;

/// Fixed part of a CHANGE_NOTIFY reply body.
const NOTIFY_REPLY_FIXED: usize = 8;

impl Connection {
    /// End the request a CANCEL names with STATUS_CANCELLED (MS-SMB2
    /// 3.3.5.16). `message` is the CANCEL; `encrypted` names the session
    /// whose key decrypted it. A CANCEL names requests of its own session
    /// only, and is ignored unless it passes that session's encryption and
    /// signing checks.
    pub(super) fn cancel(
        &mut self,
        request: &RequestHeader,
        message: &[u8],
        encrypted: Option<SessionSlot>,
    ) {
        let Some(slot) = self.find_session(request.session_id) else {
            return;
        };
        let Some(session) = self.sessions[usize::from(slot.0)] else {
            return;
        };

        let accepted = match encrypted {
            Some(decrypted) => decrypted == slot,
            None if session.encrypt_data => false,
            None if request.is_signed() => session
                .signing
                .is_some_and(|key| security::verify(message, &key)),
            None => !session.signing_required,
        };
        if !accepted {
            return;
        }

        for pending in self.pending.iter_mut().flatten() {
            if pending.session != slot {
                continue;
            }

            let named = if request.is_async() {
                pending.async_id == request.async_id
            } else {
                pending.message_id == request.message_id
            };
            if named && pending.ready.is_none() {
                pending.ready = Some(PendingOutcome::Cancelled);
            }
        }
    }

    /// Register a request that completes later; returns its async
    /// identifier.
    pub(super) fn add_pending(
        &mut self,
        request: &RequestHeader,
        encrypted: bool,
        session: SessionSlot,
        open: OpenSlot,
        kind: PendingKind,
    ) -> Result<AsyncId, RequestError> {
        let slot = self
            .pending
            .iter_mut()
            .find(|pending| pending.is_none())
            .ok_or(RequestError::TableFull)?;

        let async_id = self.next_async;
        self.next_async = async_id.next();
        *slot = Some(Pending {
            message_id: request.message_id,
            async_id,
            session,
            open,
            signed: request.is_signed(),
            encrypted,
            credit_charge: request.credit_charge,
            kind,
            ready: None,
        });

        Ok(async_id)
    }

    /// Retry blocked locks and scan watched directories that are due.
    pub(super) fn advance(
        &mut self,
        server: &mut Server,
        config: &ServerConfig,
        backend: &mut dyn Backend,
    ) {
        self.retry_locks(server);
        self.scan_due(server, config, backend);
    }

    /// Retry blocked lock requests when a lock was released since their
    /// last try.
    fn retry_locks(&mut self, server: &mut Server) {
        let epoch = server.locks.epoch();
        for index in 0..self.pending.len() {
            let Some(pending) = self.pending[index] else {
                continue;
            };
            let PendingKind::Lock {
                range,
                exclusive,
                epoch: tried,
            } = pending.kind
            else {
                continue;
            };
            if pending.ready.is_some() || tried == epoch {
                continue;
            }

            let Some(open) = self.opens[usize::from(pending.open.0)] else {
                continue;
            };
            let OpenKind::File(file) = open.kind else {
                continue;
            };

            let owner = self.lock_owner(open.id);
            let entry = self.pending[index].as_mut().expect("pending entry exists");
            match server.locks.lock(file.file, owner, range, exclusive) {
                Ok(_) => entry.ready = Some(PendingOutcome::Completed),
                Err(LockRefusal::Conflict) => {
                    entry.kind = PendingKind::Lock {
                        range,
                        exclusive,
                        epoch,
                    };
                }
                Err(LockRefusal::Exhausted) => {
                    entry.ready = Some(PendingOutcome::Failed(RequestError::TableFull));
                }
            }
        }
    }

    /// Scan the watched directory that is due, if any, for changes made
    /// outside the server.
    fn scan_due(&mut self, server: &mut Server, config: &ServerConfig, backend: &mut dyn Backend) {
        let Some(interval) = config.change_scan_interval else {
            return;
        };

        let interval = (interval.as_nanos() / 100) as u64;
        let now = backend.system_time();

        // One scan per call bounds the backend work of a poll; the watch
        // scanned longest ago goes first. A watch is scanned only while a
        // notification waits on it; its digest persists between
        // notifications, so a change in between is found by the next scan.
        let due = (0..self.opens.len())
            .filter_map(|slot| {
                let open = self.opens[slot]?;
                let OpenKind::File(file) = open.kind else {
                    return None;
                };
                let notify = file.notify?;
                let waiting = self.notify_waiting(OpenSlot(slot as u8));
                (waiting
                    && notify.filter.0 != 0
                    && now.0 >= notify.scanned.0.saturating_add(interval))
                .then_some((slot, file, notify))
            })
            .min_by_key(|(_, _, notify)| notify.scanned.0);
        let Some((slot, file, notify)) = due else {
            return;
        };

        let share = server.files.share(file.file);
        let digest = scan(backend, share, server.files.path(file.file), notify.tree);
        let changed = notify.digest.is_some_and(|previous| previous != digest);

        if let Some(OpenKind::File(file)) = self.opens[slot].as_mut().map(|open| &mut open.kind)
            && let Some(state) = file.notify.as_mut()
        {
            state.digest = Some(digest);
            state.scanned = now;
        }

        if changed {
            self.report_overflow(OpenSlot(slot as u8));
        }
    }

    /// Whether a CHANGE_NOTIFY on the open in `slot` waits for changes.
    fn notify_waiting(&self, slot: OpenSlot) -> bool {
        self.pending.iter().flatten().any(|pending| {
            pending.open == slot
                && pending.ready.is_none()
                && matches!(pending.kind, PendingKind::Notify { .. })
        })
    }

    /// Mark that changes of the open in `slot` were not kept: a pending
    /// CHANGE_NOTIFY ends with STATUS_NOTIFY_ENUM_DIR, otherwise the next
    /// one does.
    fn report_overflow(&mut self, slot: OpenSlot) {
        let watches_nothing = self.opens[usize::from(slot.0)].is_some_and(|open| {
            matches!(open.kind, OpenKind::File(file) if file.notify.is_some_and(|notify| notify.filter.0 == 0))
        });
        if watches_nothing {
            return;
        }

        if let Some(pending) = self.pending.iter_mut().flatten().find(|pending| {
            pending.open == slot
                && pending.ready.is_none()
                && matches!(pending.kind, PendingKind::Notify { .. })
        }) {
            pending.ready = Some(PendingOutcome::EnumerateDirectory);
        } else if let Some(OpenKind::File(file)) = self.opens[usize::from(slot.0)]
            .as_mut()
            .map(|open| &mut open.kind)
            && let Some(state) = file.notify.as_mut()
        {
            state.overflowed = true;
        }
    }

    /// Write the final replies that are ready, starting at `at`; returns
    /// the end of what was written. Change records the connection has not
    /// examined complete pending notifications first.
    pub(super) fn write_ready(
        &mut self,
        server: &mut Server,
        response: &mut [u8],
        mut at: usize,
    ) -> usize {
        self.examine_changes(server, response, &mut at);

        for index in 0..self.pending.len() {
            let Some(pending) = self.pending[index] else {
                continue;
            };
            let Some(outcome) = pending.ready else {
                continue;
            };

            let granted = outcome == PendingOutcome::Completed;
            let body_length = match pending.kind {
                PendingKind::Lock { .. } if granted => 4,
                PendingKind::Notify { .. } if outcome == PendingOutcome::EnumerateDirectory => {
                    NOTIFY_REPLY_FIXED
                }
                _ => ERROR_BODY,
            };
            let Some(end) =
                self.write_final(&pending, outcome, body_length, response, at, |body| {
                    body.fill(0);
                    match pending.kind {
                        PendingKind::Lock { .. } if granted => wire::put_u16(body, 0, 4),
                        _ => wire::put_u16(body, 0, 9),
                    }
                })
            else {
                // No room: the reply waits for the next call.
                break;
            };
            at = end;
            self.pending[index] = None;
        }

        at
    }

    /// Complete pending notifications with the change records written
    /// since the cursor, and mark watched opens with no pending request
    /// as overflowed.
    fn examine_changes(&mut self, server: &mut Server, response: &mut [u8], at: &mut usize) {
        let next = server.changes.next();
        if self.change_cursor == next {
            return;
        }

        let lost = server.changes.oldest().0.wrapping_sub(self.change_cursor.0) as i32 > 0;
        for slot in 0..self.opens.len() {
            let Some(open) = self.opens[slot] else {
                continue;
            };
            let OpenKind::File(file) = open.kind else {
                continue;
            };
            let Some(notify) = file.notify else {
                continue;
            };

            let slot = OpenSlot(slot as u8);
            if lost {
                self.report_overflow(slot);
                continue;
            }

            let share = server.files.share(file.file);
            let watched = server.files.path(file.file);
            let mut matched = false;
            let mut sequence = self.change_cursor;
            while sequence != next {
                if let Some(change) = server.changes.get(sequence)
                    && relative_name(&change, share, watched, &notify).is_some()
                {
                    matched = true;
                    break;
                }
                sequence = ChangeSequence(sequence.0.wrapping_add(1));
            }
            if !matched {
                continue;
            }

            let Some(index) = self.pending.iter().position(|pending| {
                pending.is_some_and(|pending| {
                    pending.open == slot
                        && pending.ready.is_none()
                        && matches!(pending.kind, PendingKind::Notify { .. })
                })
            }) else {
                self.report_overflow(slot);
                continue;
            };
            let pending = self.pending[index].expect("found pending entry");
            let PendingKind::Notify { output_length } = pending.kind else {
                continue;
            };

            let cursor = self.change_cursor;
            let written = self.write_final(
                &pending,
                PendingOutcome::Completed,
                NOTIFY_REPLY_FIXED + output_length as usize,
                response,
                *at,
                |body| {
                    body.fill(0);
                    wire::put_u16(body, 0, 9);
                    let records = write_records(
                        server,
                        cursor,
                        next,
                        share,
                        file.file,
                        &notify,
                        &mut body[NOTIFY_REPLY_FIXED..],
                    );
                    if let Some(length) = records
                        && length > 0
                    {
                        wire::put_u16(body, 2, (HEADER_SIZE + NOTIFY_REPLY_FIXED) as u16);
                        wire::put_u32(body, 4, length as u32);
                    }
                },
            );

            match written {
                Some(end) => {
                    *at = end;
                    self.pending[index] = None;
                }
                // The records are not kept past this call; a short reply
                // tells the client to list the directory, and write_ready
                // sends it when there is room.
                None => {
                    if let Some(pending) = self.pending[index].as_mut() {
                        pending.ready = Some(PendingOutcome::EnumerateDirectory);
                    }
                }
            }
        }

        self.change_cursor = next;
    }

    /// Write a final reply to `pending` at `at`: transport header, async
    /// SMB 2 header, and a body of `body_length` bytes that `fill` writes,
    /// encrypted when the request was. Returns the end, or `None` when it
    /// does not fit. A reply whose session ended is dropped (its end is
    /// `at`).
    fn write_final(
        &mut self,
        pending: &Pending,
        outcome: PendingOutcome,
        body_length: usize,
        response: &mut [u8],
        at: usize,
        fill: impl FnOnce(&mut [u8]),
    ) -> Option<usize> {
        let Some(session) = self.sessions[usize::from(pending.session.0)].as_mut() else {
            return Some(at);
        };

        let encryption = session.encryption.filter(|_| pending.encrypted);
        let transform = if encryption.is_some() {
            security::TRANSFORM_HEADER
        } else {
            0
        };
        let start = at + transport::HEADER_LENGTH + transform;
        let end = start + HEADER_SIZE + body_length;
        if end > response.len() {
            return None;
        }

        let message = &mut response[start..end];
        fill(&mut message[HEADER_SIZE..]);

        // A notification whose records did not fit reports
        // STATUS_NOTIFY_ENUM_DIR with an empty body.
        let notify = matches!(pending.kind, PendingKind::Notify { .. });
        let (outcome, length) = if notify
            && outcome == PendingOutcome::Completed
            && wire::u32_at(message, HEADER_SIZE + 4) == 0
        {
            (
                PendingOutcome::EnumerateDirectory,
                HEADER_SIZE + NOTIFY_REPLY_FIXED,
            )
        } else if notify && outcome == PendingOutcome::Completed {
            (
                outcome,
                HEADER_SIZE + NOTIFY_REPLY_FIXED + wire::u32_at(message, HEADER_SIZE + 4) as usize,
            )
        } else {
            (outcome, HEADER_SIZE + body_length)
        };

        let message = &mut response[start..start + length];
        message[..HEADER_SIZE].fill(0);
        message[..4].copy_from_slice(&wire::PROTOCOL_ID);
        wire::put_u16(message, header::STRUCTURE_SIZE, HEADER_SIZE as u16);
        wire::put_u16(message, header::CREDIT_CHARGE, pending.credit_charge.0);
        wire::put_u32(message, header::STATUS, NtStatus::from(outcome).raw());

        let command = match pending.kind {
            PendingKind::Notify { .. } => Command::CHANGE_NOTIFY,
            PendingKind::Lock { .. } => Command::LOCK,
        };
        wire::put_u16(message, header::COMMAND, command.0);

        let key = session
            .signing
            .filter(|_| encryption.is_none() && (session.signing_required || pending.signed));
        let mut flags = HeaderFlags::SERVER_TO_REDIR.union(HeaderFlags::ASYNC_COMMAND);
        if key.is_some() {
            flags = flags.union(HeaderFlags::SIGNED);
        }
        wire::put_u32(message, header::FLAGS, flags.0);
        wire::put_u64(message, header::MESSAGE_ID, pending.message_id.0);
        wire::put_u64(message, header::ASYNC_ID, pending.async_id.0);
        wire::put_u64(message, header::SESSION_ID, session.id.0);
        if let Some(key) = key {
            security::sign(message, &key);
        }

        let frame = start + length - (at + transport::HEADER_LENGTH);
        if let Some(keys) = encryption {
            let nonce = session.next_nonce;
            session.next_nonce = nonce.next();
            security::encrypt(
                &mut response[at + transport::HEADER_LENGTH..start + length],
                &keys,
                session.id,
                nonce,
            )?;
        }
        response[at..at + transport::HEADER_LENGTH].copy_from_slice(&transport::header(frame));

        Some(start + length)
    }
}

/// Write the FILE_NOTIFY_INFORMATION records (MS-FSCC 2.4.42) of the
/// changes `from..to` that the watch on `watched` reports; returns their
/// length, or `None` when they do not fit in `output`.
fn write_records(
    server: &Server,
    from: ChangeSequence,
    to: ChangeSequence,
    share: ShareId,
    watched: FileSlot,
    notify: &NotifyState,
    output: &mut [u8],
) -> Option<usize> {
    // Fixed part of a FILE_NOTIFY_INFORMATION record.
    const RECORD_FIXED: usize = 12;

    let path = server.files.path(watched);
    let mut written = 0usize;
    let mut previous: Option<usize> = None;
    let mut sequence = from;

    while sequence != to {
        if let Some(change) = server.changes.get(sequence)
            && let Some(name) = relative_name(&change, share, path, notify)
        {
            let start = (written + 3) & !3;
            let end = start + RECORD_FIXED + name.len() * 2;
            if end > output.len() {
                return None;
            }

            output[written..start].fill(0);
            if let Some(previous) = previous {
                wire::put_u32(output, previous, (start - previous) as u32);
            }
            wire::put_u32(output, start, 0);
            wire::put_u32(output, start + 4, change.action as u32);
            wire::put_u32(output, start + 8, (name.len() * 2) as u32);
            for (index, unit) in name.iter().enumerate() {
                wire::put_u16(output, start + RECORD_FIXED + index * 2, *unit);
            }
            previous = Some(start);
            written = end;
        }
        sequence = ChangeSequence(sequence.0.wrapping_add(1));
    }

    Some(written)
}

/// The name of a change relative to a watched directory, when the watch
/// reports it.
fn relative_name<'a>(
    change: &Change<'a>,
    share: ShareId,
    watched: &[u16],
    notify: &NotifyState,
) -> Option<&'a [u16]> {
    const SEPARATOR: u16 = b'\\' as u16;

    if change.share != share || change.filter.0 & notify.filter.0 == 0 {
        return None;
    }

    let path = change.path;
    let rest = if watched.is_empty() {
        path
    } else {
        if path.len() <= watched.len()
            || path[watched.len()] != SEPARATOR
            || !path[..watched.len()]
                .iter()
                .zip(watched)
                .all(|(&changed, &expected)| fold(changed) == fold(expected))
        {
            return None;
        }
        &path[watched.len() + 1..]
    };
    if rest.is_empty() || (!notify.tree && rest.contains(&SEPARATOR)) {
        return None;
    }

    Some(rest)
}
