//! READ (MS-SMB2 3.3.5.12), WRITE (3.3.5.13), and FLUSH (3.3.5.11).

use crate::backend::Backend;
use crate::fs::AccessMask;
use crate::rpc::PipeContext;
use crate::rpc::PipeRead;
use crate::server::Connection;
use crate::server::Server;
use crate::server::error::RequestError;
use crate::server::request::Body;
use crate::server::request::Completion;
use crate::server::request::Exchange;
use crate::server::request::Failure;
use crate::server::request::Handled;
use crate::server::request::empty_body;
use crate::server::shared::ByteRange;
use crate::server::shared::ChangeAction;
use crate::server::shared::ChangeFilter;
use crate::server::shared::record_change;
use crate::server::tables::OpenKind;
use crate::server::tables::OpenSlot;
use crate::server::tables::PipeIndex;
use crate::server::wire;
use crate::server::wire::FileId;
use crate::server::wire::HEADER_SIZE;

impl Connection {
    pub(super) fn read(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        const READ_REPLY_FIXED: usize = 16;

        let body = exchange.fixed_body(49, 48)?;
        let length = wire::u32_at(body, 4) as usize;
        let offset = wire::u64_at(body, 8);
        let minimum = wire::u32_at(body, 32) as usize;
        if length > exchange.config.max_io() {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }

        let slot = self.find_open(exchange, FileId::read(body, 16))?;
        let open = *self.open(slot);
        let room = output.len().saturating_sub(READ_REPLY_FIXED);
        let data = &mut output[READ_REPLY_FIXED..READ_REPLY_FIXED + length.min(room)];
        let (completion, count) = match open.kind {
            OpenKind::File(file) => {
                if file.directory {
                    return Err(Failure::Error(RequestError::WrongFileKind));
                }
                if !open
                    .access
                    .intersects(AccessMask::READ_DATA.union(AccessMask::EXECUTE))
                {
                    return Err(Failure::Error(RequestError::AccessDenied));
                }

                let range = ByteRange {
                    offset,
                    length: data.len() as u64,
                };
                if server
                    .locks
                    .check_access(file.file, self.lock_owner(open.id), range, false)
                    .is_err()
                {
                    return Err(Failure::Error(RequestError::LockConflict));
                }

                let count = backend.read(file.handle, offset, data)?;
                if (count == 0 && !data.is_empty()) || count < minimum {
                    return Err(Failure::Error(RequestError::EndOfFile));
                }

                if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
                    file.position = offset.saturating_add(count as u64);
                }

                (Completion::Success, count)
            }
            OpenKind::Pipe(pipe) => self.read_pipe(slot, pipe, backend, data)?,
        };

        output[..READ_REPLY_FIXED].fill(0);
        wire::put_u16(output, 0, 17);
        wire::put_u8(output, 2, (HEADER_SIZE + READ_REPLY_FIXED) as u8);
        wire::put_u32(output, 4, count as u32);

        Ok(Body {
            completion,
            length: READ_REPLY_FIXED + count,
        })
    }

    pub(super) fn write(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        const WRITE_REPLY: usize = 16;

        let body = exchange.fixed_body(49, 48)?;
        let length = wire::u32_at(body, 4) as usize;
        if length > exchange.config.max_io() {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }

        let data = wire::buffer(
            exchange.message,
            48,
            usize::from(wire::u16_at(body, 2)),
            length,
        )
        .ok_or(RequestError::InvalidRequest)?;
        let offset = wire::u64_at(body, 8);
        let slot = self.find_open(exchange, FileId::read(body, 16))?;
        let open = *self.open(slot);

        match open.kind {
            OpenKind::File(file) => {
                if file.directory {
                    return Err(Failure::Error(RequestError::WrongFileKind));
                }
                if !open
                    .access
                    .intersects(AccessMask::WRITE_DATA.union(AccessMask::APPEND_DATA))
                {
                    return Err(Failure::Error(RequestError::AccessDenied));
                }

                // An offset of all ones writes at the end of the file.
                let offset = if offset == u64::MAX {
                    backend.information(file.handle)?.end_of_file
                } else {
                    offset
                };
                let range = ByteRange {
                    offset,
                    length: data.len() as u64,
                };
                if server
                    .locks
                    .check_access(file.file, self.lock_owner(open.id), range, true)
                    .is_err()
                {
                    return Err(Failure::Error(RequestError::LockConflict));
                }

                backend.write(file.handle, offset, data)?;
                if !file.write_recorded {
                    record_change(
                        server,
                        file.file,
                        ChangeAction::Modified,
                        ChangeFilter::SIZE.union(ChangeFilter::LAST_WRITE),
                    );
                }
                if let OpenKind::File(file) = &mut self.open_mut(slot).kind {
                    file.position = offset.saturating_add(data.len() as u64);
                    file.write_recorded = true;
                }
            }
            OpenKind::Pipe(pipe) => self.pipes[usize::from(pipe.0)].pipe.write(data)?,
        }

        output[..WRITE_REPLY].fill(0);
        wire::put_u16(output, 0, 17);
        wire::put_u32(output, 4, data.len() as u32);

        Ok(Body::success(WRITE_REPLY))
    }

    pub(super) fn flush(
        &mut self,
        exchange: &Exchange<'_>,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        let body = exchange.fixed_body(24, 24)?;
        let slot = self.find_open(exchange, FileId::read(body, 8))?;
        let open = *self.open(slot);

        if let OpenKind::File(file) = open.kind {
            if !open
                .access
                .intersects(AccessMask::WRITE_DATA.union(AccessMask::APPEND_DATA))
            {
                return Err(Failure::Error(RequestError::AccessDenied));
            }
            backend.flush(file.handle)?;
        }

        Ok(Body::success(empty_body(output)))
    }

    /// Read a reply from the pipe in slot `pipe` into `data`.
    pub(super) fn read_pipe(
        &mut self,
        slot: OpenSlot,
        pipe: PipeIndex,
        backend: &mut dyn Backend,
        data: &mut [u8],
    ) -> Result<(Completion, usize), Failure> {
        let user = self.sessions[usize::from(self.open(slot).session.0)]
            .as_ref()
            .map(|session| session.kind)
            .ok_or(RequestError::SessionNotFound)?;

        let mut context = PipeContext { backend, user };
        match self.pipes[usize::from(pipe.0)]
            .pipe
            .read(data, &mut context)?
        {
            PipeRead::Complete { length } => Ok((Completion::Success, length)),
            PipeRead::Partial { length } => Ok((Completion::BufferOverflow, length)),
        }
    }
}
