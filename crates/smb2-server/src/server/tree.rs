//! TREE_CONNECT (MS-SMB2 3.3.5.7) and TREE_DISCONNECT (3.3.5.8).

use crate::backend::Backend;
use crate::fs::AccessMask;
use crate::server::Body;
use crate::server::Connection;
use crate::server::Exchange;
use crate::server::Failure;
use crate::server::Handled;
use crate::server::RequestError;
use crate::server::Server;
use crate::server::empty_body;
use crate::server::tables::Tree;
use crate::server::tables::TreeId;
use crate::server::tables::TreeKind;
use crate::server::wire;
use crate::utf16::Utf16Le;

/// ShareType of a TREE_CONNECT reply (MS-SMB2 2.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShareType {
    Disk = 0x1,
    Pipe = 0x2,
}

/// ShareFlags of a TREE_CONNECT reply (MS-SMB2 2.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShareFlags(u32);

impl ShareFlags {
    /// Clients must not cache files of the share for offline use.
    const NO_CACHING: Self = Self(0x30);
}

const REPLY_LENGTH: usize = 16;
/// Rights of a read-only share: read data, attributes and extended
/// attributes, execute, read control, synchronize.
const READ_ONLY_ACCESS: AccessMask = AccessMask(0x0012_00a9);
const SEPARATOR: u16 = b'\\' as u16;

impl Connection {
    pub(super) fn tree_connect(
        &mut self,
        exchange: &Exchange<'_>,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Result<(Body, TreeId), Failure> {
        let body = exchange.fixed_body(9, 8)?;
        let path = wire::buffer(
            exchange.message,
            8,
            usize::from(wire::u16_at(body, 4)),
            usize::from(wire::u16_at(body, 6)),
        )
        .and_then(Utf16Le::new)
        .ok_or(RequestError::InvalidRequest)?;
        let share = share_name(path).ok_or(RequestError::InvalidRequest)?;
        let session = exchange.session.ok_or(RequestError::SessionNotFound)?;
        let kind = self.sessions[usize::from(session.0)]
            .as_ref()
            .map(|session| session.kind)
            .ok_or(RequestError::SessionNotFound)?;
        let (tree, share_type, access) = if share.eq_ignore_ascii_case(b"IPC$") {
            (TreeKind::Pipe, ShareType::Pipe, AccessMask::FILE_ALL_ACCESS)
        } else {
            let found = backend
                .find_share(share, kind)
                .ok_or(RequestError::ShareNotFound)?;
            let access = if found.writable {
                AccessMask::FILE_ALL_ACCESS
            } else {
                READ_ONLY_ACCESS
            };
            (
                TreeKind::Disk {
                    share: found.id,
                    writable: found.writable,
                },
                ShareType::Disk,
                access,
            )
        };
        let index = self
            .trees
            .iter()
            .position(Option::is_none)
            .ok_or(RequestError::TableFull)?;
        let id = self.new_tree_id();
        self.trees[index] = Some(Tree {
            id,
            session,
            kind: tree,
        });
        output[..REPLY_LENGTH].fill(0);
        wire::put_u16(output, 0, REPLY_LENGTH as u16);
        wire::put_u8(output, 2, share_type as u8);
        wire::put_u32(output, 4, ShareFlags::NO_CACHING.0);
        wire::put_u32(output, 12, access.0);
        Ok((Body::success(REPLY_LENGTH), id))
    }

    pub(super) fn tree_disconnect(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        exchange.fixed_body(4, 4)?;
        if let Some(slot) = exchange.tree {
            self.close_opens_where(server, backend, |open| open.tree == slot);
            self.trees[usize::from(slot.0)] = None;
        }
        Ok(Body::success(empty_body(output)))
    }

    fn new_tree_id(&mut self) -> TreeId {
        loop {
            let id = self.next_tree_id;
            self.next_tree_id = TreeId(id.0.wrapping_add(1));
            if id.0 != 0
                && id.0 != u32::MAX
                && !self
                    .trees
                    .iter()
                    .any(|tree| tree.is_some_and(|tree| tree.id == id))
            {
                return id;
            }
        }
    }
}

/// The share of a `\\server\share` path.
fn share_name(path: Utf16Le<'_>) -> Option<Utf16Le<'_>> {
    if path.unit(0) != Some(SEPARATOR) || path.unit(1) != Some(SEPARATOR) {
        return None;
    }
    let server_end = 2 + path
        .slice(2, path.len())
        .units()
        .position(|unit| unit == SEPARATOR)?;
    let share = path.slice(server_end + 1, path.len());
    if share.is_empty() || share.units().any(|unit| unit == SEPARATOR) {
        return None;
    }
    Some(share)
}
