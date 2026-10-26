//! IOCTL (MS-SMB2 3.3.5.15).

use crate::backend::Backend;
use crate::server::Connection;
use crate::server::error::RequestError;
use crate::server::negotiate::GlobalCapabilities;
use crate::server::negotiate::SecurityMode;
use crate::server::negotiate::capabilities;
use crate::server::negotiate::security_mode;
use crate::server::negotiate::select_dialect;
use crate::server::request::Body;
use crate::server::request::Exchange;
use crate::server::request::Failure;
use crate::server::request::Handled;
use crate::server::tables::OpenKind;
use crate::server::wire;
use crate::server::wire::Dialect;
use crate::server::wire::FileId;
use crate::server::wire::HEADER_SIZE;

const IOCTL_REQUEST_FIXED: usize = 56;
const IOCTL_REPLY_FIXED: usize = 48;

/// Flags of an IOCTL request (MS-SMB2 2.2.31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IoctlFlags(u32);

impl IoctlFlags {
    const IS_FSCTL: Self = Self(0x1);
}

/// A file system control code (MS-FSCC 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FsctlCode(u32);

impl FsctlCode {
    const DFS_GET_REFERRALS: Self = Self(0x0006_0194);
    const DFS_GET_REFERRALS_EX: Self = Self(0x0006_01b0);
    const PIPE_TRANSCEIVE: Self = Self(0x0011_c017);
    const GET_REPARSE_POINT: Self = Self(0x0009_00a8);
    const VALIDATE_NEGOTIATE_INFO: Self = Self(0x0014_0204);
}

impl Connection {
    pub(super) fn ioctl(
        &mut self,
        exchange: &Exchange<'_>,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        let body = exchange.fixed_body(57, IOCTL_REQUEST_FIXED)?;
        let code = FsctlCode(wire::u32_at(body, 4));
        let file_id = FileId::read(body, 8);
        let input = wire::buffer(
            exchange.message,
            IOCTL_REQUEST_FIXED,
            wire::u32_at(body, 24) as usize,
            wire::u32_at(body, 28) as usize,
        )
        .ok_or(RequestError::InvalidRequest)?;
        let max_output = wire::u32_at(body, 44) as usize;

        if IoctlFlags(wire::u32_at(body, 48)) != IoctlFlags::IS_FSCTL {
            return Err(Failure::Error(RequestError::Unsupported));
        }
        if input.len() > exchange.config.max_io() || max_output > exchange.config.max_io() {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }

        match code {
            FsctlCode::DFS_GET_REFERRALS | FsctlCode::DFS_GET_REFERRALS_EX => {
                return Err(Failure::Error(RequestError::NoDfs));
            }
            FsctlCode::VALIDATE_NEGOTIATE_INFO => {
                return self.validate_negotiate(exchange, file_id, input, max_output, output);
            }
            // Every other control code names an open.
            _ => {}
        }

        let slot = self.find_open(exchange, file_id)?;
        let open = *self.open(slot);
        let room = output.len().saturating_sub(IOCTL_REPLY_FIXED);
        let (completion, count) = match (code, open.kind) {
            (FsctlCode::PIPE_TRANSCEIVE, OpenKind::Pipe(pipe)) => {
                self.pipes[usize::from(pipe.0)].pipe.write(input)?;
                let data = &mut output[IOCTL_REPLY_FIXED..IOCTL_REPLY_FIXED + max_output.min(room)];
                self.read_pipe(slot, pipe, backend, data)?
            }
            (FsctlCode::PIPE_TRANSCEIVE, OpenKind::File(_)) => {
                return Err(Failure::Error(RequestError::WrongFileKind));
            }
            (FsctlCode::GET_REPARSE_POINT, OpenKind::File(_)) => {
                return Err(Failure::Error(RequestError::NotAReparsePoint));
            }
            _ => return Err(Failure::Error(RequestError::WrongFileKind)),
        };

        output[..IOCTL_REPLY_FIXED].fill(0);
        wire::put_u16(output, 0, 49);
        wire::put_u32(output, 4, code.0);
        open.id.write(output, 8);
        wire::put_u32(output, 24, (HEADER_SIZE + IOCTL_REPLY_FIXED) as u32);
        wire::put_u32(output, 32, (HEADER_SIZE + IOCTL_REPLY_FIXED) as u32);
        wire::put_u32(output, 36, count as u32);

        Ok(Body {
            completion,
            length: IOCTL_REPLY_FIXED + count,
        })
    }

    /// FSCTL_VALIDATE_NEGOTIATE_INFO (MS-SMB2 3.3.5.15.12): the client
    /// repeats its NEGOTIATE in a signed request, and the connection ends
    /// when it differs from what the server received.
    fn validate_negotiate(
        &self,
        exchange: &Exchange<'_>,
        file_id: FileId,
        input: &[u8],
        max_output: usize,
        output: &mut [u8],
    ) -> Handled {
        // Fixed part of a VALIDATE_NEGOTIATE_INFO request and the length of
        // its reply.
        const VALIDATE_REQUEST_FIXED: usize = 24;
        const VALIDATE_REPLY: usize = 24;

        let Some(negotiated) = self.negotiated else {
            return Err(Failure::Disconnect);
        };
        if !matches!(
            negotiated.dialect,
            Dialect::SMB_3_0 | Dialect::SMB_3_0_2 | Dialect::SMB_3_1_1
        ) {
            return Err(Failure::Error(RequestError::Unsupported));
        }
        if input.len() < VALIDATE_REQUEST_FIXED || max_output < VALIDATE_REPLY {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }

        let count = usize::from(wire::u16_at(input, 22));
        let dialects = input
            .get(VALIDATE_REQUEST_FIXED..VALIDATE_REQUEST_FIXED + count * 2)
            .ok_or(RequestError::InvalidRequest)?;
        if GlobalCapabilities(wire::u32_at(input, 0)) != self.client_capabilities
            || input[4..20] != self.client_guid.0
            || SecurityMode(wire::u16_at(input, 20)) != self.client_security_mode
            || select_dialect(dialects) != Some(negotiated.dialect)
        {
            return Err(Failure::Disconnect);
        }

        let reply = &mut output[IOCTL_REPLY_FIXED..IOCTL_REPLY_FIXED + VALIDATE_REPLY];
        wire::put_u32(reply, 0, capabilities(&negotiated).0);
        reply[4..20].copy_from_slice(&exchange.config.guid.0);
        wire::put_u16(reply, 20, security_mode(&exchange.config).0);
        wire::put_u16(reply, 22, negotiated.dialect.0);

        output[..IOCTL_REPLY_FIXED].fill(0);
        wire::put_u16(output, 0, 49);
        wire::put_u32(output, 4, FsctlCode::VALIDATE_NEGOTIATE_INFO.0);
        file_id.write(output, 8);
        wire::put_u32(output, 24, (HEADER_SIZE + IOCTL_REPLY_FIXED) as u32);
        wire::put_u32(output, 32, (HEADER_SIZE + IOCTL_REPLY_FIXED) as u32);
        wire::put_u32(output, 36, VALIDATE_REPLY as u32);

        Ok(Body::success(IOCTL_REPLY_FIXED + VALIDATE_REPLY))
    }
}
