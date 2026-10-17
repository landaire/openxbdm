//! `fastpipe`: hand connections to a file-receive engine. A group of up to
//! six pipes carries `CC` (create) and `AA` (data) packets; the console
//! answers each `CC` with one 12-byte `BB` reply when the file is complete
//! or has failed.
//!
//! Packets are big-endian: +0 u16 magic, +2 u16 file id, +4 u32 packet
//! length, +8 u32 data offset (`AA`). A `CC` body has +0xc u32 header
//! size, +0x10 creation time, +0x18 last write time, +0x20 u64 file size,
//! +0x28 u32 attributes, and the NUL-terminated path at +0x2c, followed by
//! the file data when it fits. `AA` data starts at +0xc.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use crate::backend::Backend as AnyBackend;
use crate::commands::filesystem;
use crate::commands::filesystem::BasicInformation;
use crate::commands::filesystem::CreateDisposition;
use crate::commands::filesystem::CreateOptions;
use crate::commands::filesystem::CreateRequest;
use crate::commands::filesystem::FileAccess;
use crate::commands::filesystem::FileAttributes;
use crate::commands::filesystem::FileData;
use crate::commands::filesystem::FileHandle;
use crate::commands::filesystem::FileTime;
use crate::commands::filesystem::PoolBuffer;
use crate::commands::filesystem::PoolRange;
use crate::commands::filesystem::ShareAccess;
use crate::invocation::Invocation;
use crate::invocation::SessionRequest;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_all;
use crate::network::send_line;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;

xbox360_sys::value_enum! {
    /// First word of a pipe packet.
    pub enum PacketMagic: u16 {
        /// `AA`: file data.
        Data = 0x4141,
        /// `BB`: the result of a file.
        Reply = 0x4242,
        /// `CC`: create a file.
        Create = 0x4343,
    }
}

/// Pipes open at one time, all of one group.
pub const PIPE_SLOTS: usize = 6;
/// Largest packet.
const PACKET_CAPACITY: u32 = 0x1000c;
/// Every packet is read with a first receive of this many bytes; a shorter
/// packet is followed by padding up to it.
const FIRST_READ: u32 = 0x5b4;
/// Data bytes of one `AA` packet.
const BLOCK_SIZE: u32 = 0x10000;
/// File cache elements while a group is open.
const PIPE_CACHE_ELEMENTS: u32 = 0x400;
/// Files receiving data at one time; the monitor's wait list holds 62.
const MAX_FILES: usize = 62;
/// `AA` packets kept for files whose `CC` has not arrived.
const MAX_ORPHANS: usize = 16;
const PATH_OFFSET: usize = 0x2c;
const CREATE_FALLBACK: CommandError = CommandError::Status(ErrorCode::FileCannotBeCreated);
/// `BB` result word of a complete file.
const PIPE_SUCCESS: u32 = 0;
/// Access the monitor opens files with.
const PIPE_FILE_ACCESS: FileAccess = FileAccess::GENERIC_WRITE
    .union(FileAccess::DELETE)
    .union(FileAccess::SYNCHRONIZE);

/// Platform services of `fastpipe`.
pub trait FastPipeBackend {
    /// Element count of file system cache 2.
    fn file_cache_elements(&mut self) -> u32;
    fn set_file_cache_elements(&mut self, count: u32);
}

/// Identifier of a pipe group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeGroup(pub u32);

#[derive(Debug, Clone, Copy)]
struct Pipe {
    socket: SocketId,
    group: PipeGroup,
    /// Packet being received; taken when the packet goes to the orphan
    /// list.
    block: Option<PoolBuffer>,
    received: u32,
    expected: u32,
}

/// A file receiving `AA` packets.
#[derive(Debug, Clone, Copy)]
struct PipeFile {
    id: u16,
    /// Slot of the pipe the `CC` came from; the reply goes there.
    slot: u8,
    /// Length field of the `CC`, echoed in the reply.
    create_length: u32,
    /// Low word of the file size; only it is used for blocks and offsets.
    size: u32,
    blocks_remaining: u32,
    handle: FileHandle,
    creation_time: FileTime,
    last_write_time: FileTime,
    attributes: FileAttributes,
    /// `CC` arrival order.
    order: u32,
}

/// State of the pipe engine.
#[derive(Debug)]
pub struct FastPipes {
    slots: [Option<Pipe>; PIPE_SLOTS],
    /// Last automatically assigned group.
    group_counter: u32,
    /// Cache element count saved when the first pipe opened.
    saved_cache_elements: u32,
    files: [Option<PipeFile>; MAX_FILES],
    next_order: u32,
    /// `AA` packets in arrival order.
    orphans: [Option<PoolBuffer>; MAX_ORPHANS],
}

impl FastPipes {
    pub const fn new() -> Self {
        Self {
            slots: [None; PIPE_SLOTS],
            group_counter: 0,
            saved_cache_elements: 0,
            files: [None; MAX_FILES],
            next_order: 0,
            orphans: [None; MAX_ORPHANS],
        }
    }
}

impl FastPipes {
    /// Sockets owned by open pipes.
    pub fn sockets(&self) -> impl Iterator<Item = SocketId> + '_ {
        self.slots.iter().flatten().map(|pipe| pipe.socket)
    }

    pub fn owns(&self, socket: SocketId) -> bool {
        self.sockets().any(|owned| owned == socket)
    }
}

/// `fastpipe [group=<dword>]`: turn the connection into a pipe of `group`
/// (a new group when absent or 0). Success sends only
/// `209- result code <group>`.
pub(super) fn fast_pipe(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(socket) = invocation
        .session
        .as_deref()
        .map(|session| session.socket())
    else {
        return Err(CommandError::Fail);
    };
    // The engine requires the 1 GB memory configuration.
    if !invocation.backend.kit_features().one_gigabyte_ram {
        return Err(CommandError::Fail);
    }
    // An absent or malformed value requests a new group.
    let group = invocation.line.dword("group").unwrap_or(0);
    if !open_pipe(
        invocation.state,
        invocation.backend,
        invocation.network,
        socket,
        group,
    ) {
        invocation.text.set_bytes(b"fastpipe limit exceeded");
        return Err(CommandError::Fail);
    }
    if let Some(session) = invocation.session.as_deref_mut() {
        session.request(SessionRequest::ReleaseSocket);
    }
    Ok(Reply::Sent)
}

fn open_pipe(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    socket: SocketId,
    group: u32,
) -> bool {
    let pipes = &mut state.session.fast_pipes;
    let group = if group == 0 {
        pipes.group_counter = pipes.group_counter.wrapping_add(1);
        if pipes.group_counter == 0 {
            pipes.group_counter = 1;
        }
        PipeGroup(pipes.group_counter)
    } else {
        PipeGroup(group)
    };
    let mut open = 0;
    let mut free = None;
    for (index, slot) in pipes.slots.iter().enumerate() {
        match slot {
            Some(pipe) if pipe.group != group => return false,
            Some(_) => open += 1,
            None if free.is_none() => free = Some(index),
            None => {}
        }
    }
    let Some(free) = free else { return false };
    let Some(block) = backend.allocate_pool(PACKET_CAPACITY) else {
        return false;
    };
    let mut line = Text::<0x20>::new();
    let _ = core::fmt::Write::write_fmt(
        &mut line,
        format_args!("209- result code {}", group.0 as i32),
    );
    if send_line(network, socket, line.as_bytes()).is_err() {
        backend.free_pool(block);
        return false;
    }
    if open == 0 {
        pipes.saved_cache_elements = backend.file_cache_elements();
        backend.set_file_cache_elements(PIPE_CACHE_ELEMENTS);
    }
    pipes.slots[free] = Some(Pipe {
        socket,
        group,
        block: Some(block),
        received: 0,
        expected: FIRST_READ,
    });
    true
}

/// A pipe socket is readable.
pub fn on_readable(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    socket: SocketId,
) {
    let Some(slot) = state
        .session
        .fast_pipes
        .slots
        .iter()
        .position(|pipe| matches!(pipe, Some(p) if p.socket == socket))
    else {
        return;
    };
    let Some(mut pipe) = state.session.fast_pipes.slots[slot] else {
        return;
    };
    let Some(block) = pipe.block else {
        return close_pipe(state, backend, network, slot);
    };
    let range = pipe.received as usize..pipe.expected as usize;
    let received = match network.receive(socket, &mut backend.pool(block)[range]) {
        Ok(count @ 1..) => count as u32,
        _ => return close_pipe(state, backend, network, slot),
    };
    pipe.received += received;
    if pipe.received == FIRST_READ && pipe.expected == FIRST_READ {
        let header = &backend.pool(block)[..8];
        let magic = PacketMagic::from_raw(u16::from_be_bytes([header[0], header[1]]));
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        if !matches!(magic, Some(PacketMagic::Create | PacketMagic::Data))
            || length > PACKET_CAPACITY
        {
            return close_pipe(state, backend, network, slot);
        }
        pipe.expected = length;
    }
    if pipe.received < pipe.expected {
        state.session.fast_pipes.slots[slot] = Some(pipe);
        return;
    }
    // Bytes of a short packet beyond its length were padding.
    pipe.received = 0;
    pipe.expected = FIRST_READ;
    state.session.fast_pipes.slots[slot] = Some(pipe);
    let magic = {
        let header = backend.pool(block);
        u16::from_be_bytes([header[0], header[1]])
    };
    if magic == PacketMagic::Create.raw() {
        create(state, backend, network, slot as u8, block);
    } else if keeps_block(state, backend, network, block) {
        // The packet waits for its file; the pipe needs a new block.
        let replacement = backend.allocate_pool(PACKET_CAPACITY);
        if let Some(Some(pipe)) = state.session.fast_pipes.slots.get_mut(slot) {
            pipe.block = replacement;
        }
        if replacement.is_none() {
            close_pipe(state, backend, network, slot);
        }
    }
}

fn u32_at(block: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        block[offset],
        block[offset + 1],
        block[offset + 2],
        block[offset + 3],
    ])
}

fn u64_at(block: &[u8], offset: usize) -> u64 {
    u64::from(u32_at(block, offset)) << 32 | u64::from(u32_at(block, offset + 4))
}

/// A `CC` packet: open the file and write inline data, or wait for `AA`
/// packets.
fn create(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    slot: u8,
    block: PoolBuffer,
) {
    let packet = backend.pool(block);
    let id = u16::from_be_bytes([packet[2], packet[3]]);
    let create_length = u32_at(packet, 4);
    let header_size = u32_at(packet, 0xc);
    let creation_time = FileTime(u64_at(packet, 0x10));
    let last_write_time = FileTime(u64_at(packet, 0x18));
    let full_size = u64_at(packet, 0x20);
    let size = full_size as u32;
    let attributes = FileAttributes(u32_at(packet, 0x28));
    let path_length = packet[PATH_OFFSET..]
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(packet.len() - PATH_OFFSET);
    let mut path = [0u8; 0x200];
    let path_length = path_length.min(path.len());
    path[..path_length].copy_from_slice(&packet[PATH_OFFSET..PATH_OFFSET + path_length]);
    let data_offset = PATH_OFFSET + path_length + 1;

    let reply =
        |state: &mut ServerState, network: &mut dyn Network, result: Result<(), CommandError>| {
            send_reply(state, network, slot, id, create_length, result);
        };
    let pipes = &mut state.session.fast_pipes;
    let Some(free) = pipes.files.iter().position(Option::is_none) else {
        return reply(state, network, Err(CommandError::OutOfMemory));
    };
    let request = CreateRequest {
        access: PIPE_FILE_ACCESS,
        allocation_size: Some(full_size),
        attributes: FileAttributes::NONE,
        share: ShareAccess::NONE,
        disposition: CreateDisposition::OverwriteIf,
        options: CreateOptions::NONE,
    };
    let handle = match filesystem::open_path(state, backend, &path[..path_length], &request) {
        Ok(handle) => handle,
        Err(error) => {
            return reply(
                state,
                network,
                Err(CommandError::from_kernel(error, CREATE_FALLBACK)),
            );
        }
    };
    if size > BLOCK_SIZE
        && let Err(error) = backend.set_end_of_file(handle, full_size)
    {
        let _ = backend.set_delete_disposition(handle, true);
        backend.close_file(handle);
        return reply(
            state,
            network,
            Err(CommandError::from_kernel(error, CREATE_FALLBACK)),
        );
    }
    if BLOCK_SIZE.wrapping_sub(header_size) >= size {
        // The data follows the path; times and attributes are not applied.
        let mut result = Ok(());
        if size != 0 {
            let end = (data_offset + size as usize).min(PACKET_CAPACITY as usize);
            let range = PoolRange {
                buffer: block,
                offset: data_offset as u32,
                length: (end - data_offset.min(end)) as u32,
            };
            if let Err(error) = backend.write_file(handle, Some(0), FileData::Pool(range)) {
                let _ = backend.set_delete_disposition(handle, true);
                result = Err(CommandError::from_kernel(error, CREATE_FALLBACK));
            }
        }
        backend.close_file(handle);
        return reply(state, network, result);
    }
    let pipes = &mut state.session.fast_pipes;
    let order = pipes.next_order;
    pipes.next_order = pipes.next_order.wrapping_add(1);
    let blocks_remaining = (size >> 16) + u32::from(size & 0xffff != 0);
    pipes.files[free] = Some(PipeFile {
        id,
        slot,
        create_length,
        size,
        blocks_remaining,
        handle,
        creation_time,
        last_write_time,
        attributes,
        order,
    });
    for index in 0..MAX_ORPHANS {
        let Some(orphan) = state.session.fast_pipes.orphans[index] else {
            continue;
        };
        let packet = backend.pool(orphan);
        if u16::from_be_bytes([packet[2], packet[3]]) != id {
            continue;
        }
        state.session.fast_pipes.orphans[index] = None;
        if state.session.fast_pipes.files[free].is_some() {
            write_block(state, backend, network, free, orphan);
        }
        backend.free_pool(orphan);
    }
    compact_orphans(&mut state.session.fast_pipes);
}

/// An `AA` packet. Returns whether the block was kept for a later `CC`.
fn keeps_block(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    block: PoolBuffer,
) -> bool {
    let packet = backend.pool(block);
    let id = u16::from_be_bytes([packet[2], packet[3]]);
    let pipes = &mut state.session.fast_pipes;
    let file = pipes
        .files
        .iter()
        .enumerate()
        .filter_map(|(index, file)| file.filter(|f| f.id == id).map(|f| (index, f.order)))
        .min_by_key(|&(_, order)| order.wrapping_sub(pipes.next_order))
        .map(|(index, _)| index);
    match file {
        Some(index) => {
            write_block(state, backend, network, index, block);
            false
        }
        None => match pipes.orphans.iter().position(Option::is_none) {
            Some(free) => {
                pipes.orphans[free] = Some(block);
                true
            }
            // Without room the packet is dropped.
            None => false,
        },
    }
}

fn compact_orphans(pipes: &mut FastPipes) {
    let mut kept = 0;
    for index in 0..MAX_ORPHANS {
        if let Some(orphan) = pipes.orphans[index].take() {
            pipes.orphans[kept] = Some(orphan);
            kept += 1;
        }
    }
}

/// Write the data of an `AA` packet to file `index`.
fn write_block(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    index: usize,
    block: PoolBuffer,
) {
    let Some(mut file) = state.session.fast_pipes.files[index] else {
        return;
    };
    let offset = u32_at(backend.pool(block), 8);
    let length = if offset.wrapping_add(BLOCK_SIZE) > file.size {
        file.size & 0xffff
    } else {
        BLOCK_SIZE
    };
    let written = if offset >= file.size || offset & 0xffff != 0 {
        // The monitor's STATUS_INVALID_OFFSET has no reply mapping.
        Err(CommandError::Unexpected)
    } else {
        let range = PoolRange {
            buffer: block,
            offset: 0xc,
            length,
        };
        backend
            .write_file(file.handle, Some(u64::from(offset)), FileData::Pool(range))
            .map_err(|error| CommandError::from_kernel(error, CommandError::Unexpected))
    };
    let result = match written {
        Err(error) => {
            let _ = backend.set_delete_disposition(file.handle, true);
            Err(error)
        }
        Ok(()) => {
            file.blocks_remaining -= 1;
            if file.blocks_remaining != 0 {
                state.session.fast_pipes.files[index] = Some(file);
                return;
            }
            finalize(backend, &file)
        }
    };
    state.session.fast_pipes.files[index] = None;
    send_reply(
        state,
        network,
        file.slot,
        file.id,
        file.create_length,
        result,
    );
    backend.close_file(file.handle);
}

/// Apply the times and attributes of a complete file.
fn finalize(backend: &mut dyn AnyBackend, file: &PipeFile) -> Result<(), CommandError> {
    match backend.query_file_information(file.handle) {
        Ok(_) => {
            let information = BasicInformation {
                creation_time: file.creation_time,
                last_access_time: FileTime(0),
                last_write_time: file.last_write_time,
                change_time: FileTime(0),
                attributes: file.attributes,
            };
            let _ = backend.set_basic_information(file.handle, &information);
            Ok(())
        }
        Err(error) => {
            let _ = backend.set_delete_disposition(file.handle, true);
            Err(CommandError::from_kernel(error, CommandError::Unexpected))
        }
    }
}

/// Send `BB`, file id, the `CC` length, and the result on the pipe in
/// `slot`; a closed pipe drops it and send errors are ignored.
fn send_reply(
    state: &ServerState,
    network: &mut dyn Network,
    slot: u8,
    id: u16,
    create_length: u32,
    result: Result<(), CommandError>,
) {
    let Some(Some(pipe)) = state.session.fast_pipes.slots.get(slot as usize) else {
        return;
    };
    let mut reply = [0u8; 12];
    reply[..2].copy_from_slice(&PacketMagic::Reply.raw().to_be_bytes());
    reply[2..4].copy_from_slice(&id.to_be_bytes());
    reply[4..8].copy_from_slice(&create_length.to_be_bytes());
    let word = result.map_or_else(|error| Hresult::from(error).0, |()| PIPE_SUCCESS);
    reply[8..].copy_from_slice(&word.to_be_bytes());
    let _ = send_all(network, pipe.socket, &reply);
}

/// Close the pipe in `slot` and every pipe of its group. When no pipe
/// remains, unfinished files are closed without their replies, waiting
/// packets are discarded, and the cache size is restored.
fn close_pipe(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
    slot: usize,
) {
    let pipes = &mut state.session.fast_pipes;
    let Some(closing) = pipes.slots[slot] else {
        return;
    };
    for entry in &mut pipes.slots {
        if let Some(pipe) = entry
            && pipe.group == closing.group
        {
            network.close(pipe.socket);
            if let Some(block) = pipe.block {
                backend.free_pool(block);
            }
            *entry = None;
        }
    }
    if pipes.slots.iter().any(Option::is_some) {
        return;
    }
    for file in pipes.files.iter_mut().filter_map(Option::take) {
        backend.close_file(file.handle);
    }
    for orphan in pipes.orphans.iter_mut().filter_map(Option::take) {
        backend.free_pool(orphan);
    }
    backend.set_file_cache_elements(pipes.saved_cache_elements);
}
