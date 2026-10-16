//! Socket transport of the Xbox Studio session (stock object 0x91f83698).
//!
//! The XAM studio service drives the transport through a table of six
//! routines. Each message on the stream is a 4-byte big-endian length
//! followed by that many bytes. Sends and receives share four request
//! slots; a request completes into a slot that the caller frees by reading
//! its result. Socket calls never block: progress is made whenever the
//! caller queues a request or asks for a result.

use openxbdm_core::status::Hresult;

/// Request slots of one transport.
pub const REQUEST_SLOTS: usize = 4;

/// A failed transport routine or request, as the studio service receives
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StudioError {
    /// The request is still queued.
    Pending,
    /// The connection is closed.
    NotConnected,
    /// Removed by a cancel or a disconnect.
    Aborted,
    /// No request slot or memory is free.
    OutOfMemory,
    /// A message longer than the receive buffer, or an unknown request.
    InvalidArgument,
    NotImplemented,
    Fail,
}

impl From<StudioError> for Hresult {
    fn from(error: StudioError) -> Self {
        match error {
            StudioError::Pending => Hresult(0x8000_000a),
            StudioError::NotConnected => Hresult(0x8000_4002),
            StudioError::Aborted => Hresult(0x8000_4004),
            StudioError::OutOfMemory => Hresult::OUT_OF_MEMORY,
            StudioError::InvalidArgument => Hresult::INVALID_ARGUMENT,
            StudioError::NotImplemented => Hresult(0x8000_4001),
            StudioError::Fail => Hresult::FAIL,
        }
    }
}

/// The result word of a transport routine; success is 0.
pub fn routine_result(result: Result<(), StudioError>) -> Hresult {
    match result {
        Ok(()) => Hresult(0),
        Err(error) => error.into(),
    }
}

const LENGTH_SIZE: u32 = 4;
/// Largest receive used to drop the body of a rejected message.
const DISCARD_CHUNK: usize = 0x100;

/// A request slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot(u8);

impl Slot {
    pub fn index(self) -> usize {
        usize::from(self.0)
    }

    pub fn from_index(index: usize) -> Option<Self> {
        (index < REQUEST_SLOTS).then_some(Self(index as u8))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Send,
    Receive,
}

/// Memory of the caller, addressed in its address space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerBuffer {
    pub address: u32,
    pub length: u32,
}

/// Source of a socket send.
pub enum Outgoing<'a> {
    Local(&'a [u8]),
    Caller(CallerBuffer),
}

/// Destination of a socket receive.
pub enum Incoming<'a> {
    Local(&'a mut [u8]),
    Caller(CallerBuffer),
}

/// The socket and event of a transport.
pub trait Stream {
    /// Bytes sent; `None` is a socket error.
    fn send(&mut self, data: Outgoing<'_>) -> Option<u32>;
    /// Bytes received, 0 at the end of the stream; `None` is a socket error.
    fn receive(&mut self, into: Incoming<'_>) -> Option<u32>;
    /// The last socket error only reports that the call would block.
    fn would_block(&mut self) -> bool;
    /// The big-endian length at `address` in the caller's memory.
    fn read_length(&mut self, address: u32) -> u32;
    /// Signal the event the caller waits on for completions.
    fn signal(&mut self);
    /// Stock assertion trap for a receive buffer shorter than a length.
    fn short_buffer(&mut self);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Queue {
    Free,
    Send,
    Receive,
    Completed,
}

#[derive(Clone, Copy)]
struct Request {
    queue: Queue,
    /// The length prefix has been transferred.
    framed: bool,
    buffer: u32,
    length: u32,
    progress: u32,
    /// `None` while queued.
    status: Option<Result<(), StudioError>>,
}

/// State of one socket transport.
pub struct Transport {
    requests: [Request; REQUEST_SLOTS],
    /// All slots; each queue is ordered as its members appear here.
    order: [Slot; REQUEST_SLOTS],
    connected: bool,
    /// Bytes of a rejected message still to be dropped.
    discard: u32,
}

impl Default for Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport {
    pub const fn new() -> Self {
        const FREE: Request = Request {
            queue: Queue::Free,
            framed: false,
            buffer: 0,
            length: 0,
            progress: 0,
            status: Some(Ok(())),
        };
        Self {
            requests: [FREE; REQUEST_SLOTS],
            order: [Slot(0), Slot(1), Slot(2), Slot(3)],
            connected: true,
            discard: 0,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connected
    }

    fn head(&self, queue: Queue) -> Option<Slot> {
        self.order
            .iter()
            .copied()
            .find(|slot| self.requests[slot.index()].queue == queue)
    }

    /// Unlink `slot` and append it to `queue`.
    fn move_to(&mut self, slot: Slot, queue: Queue) {
        if let Some(position) = self.order.iter().position(|&member| member == slot) {
            self.order[position..].rotate_left(1);
        }
        self.requests[slot.index()].queue = queue;
    }

    fn finish(&mut self, slot: Slot, status: Result<(), StudioError>, stream: &mut impl Stream) {
        self.requests[slot.index()].status = Some(status);
        self.move_to(slot, Queue::Completed);
        stream.signal();
    }

    /// The slot the next request takes (stock checks of 0x91f840d8).
    pub fn reserve(&self) -> Result<Slot, StudioError> {
        if !self.connected {
            return Err(StudioError::NotConnected);
        }
        self.head(Queue::Free).ok_or(StudioError::OutOfMemory)
    }

    /// Queue a request in the slot from [`Self::reserve`] and make progress.
    pub fn submit(
        &mut self,
        slot: Slot,
        direction: Direction,
        buffer: CallerBuffer,
        stream: &mut impl Stream,
    ) {
        let request = &mut self.requests[slot.index()];
        request.framed = false;
        request.buffer = buffer.address;
        request.length = buffer.length;
        request.progress = 0;
        request.status = None;
        let queue = match direction {
            Direction::Send => Queue::Send,
            Direction::Receive => Queue::Receive,
        };
        self.move_to(slot, queue);
        self.pump(stream);
    }

    pub fn is_pending(&self, slot: Slot) -> bool {
        self.requests[slot.index()].status.is_none()
    }

    /// Free a finished slot, returning its status and the bytes moved.
    pub fn complete(&mut self, slot: Slot) -> Option<(Result<(), StudioError>, u32)> {
        let request = self.requests[slot.index()];
        let status = request.status?;
        self.move_to(slot, Queue::Free);
        Some((status, request.progress))
    }

    /// Abort every queued send, then every queued receive (0x91f84538).
    pub fn cancel(&mut self, stream: &mut impl Stream) {
        for queue in [Queue::Send, Queue::Receive] {
            while let Some(slot) = self.head(queue) {
                self.finish(slot, Err(StudioError::Aborted), stream);
            }
        }
    }

    /// A socket call failed (0x91f83980): anything but a blocked call ends
    /// the connection.
    pub fn socket_error(&mut self, stream: &mut impl Stream) {
        if !stream.would_block() {
            self.disconnect(stream);
        }
    }

    fn disconnect(&mut self, stream: &mut impl Stream) {
        self.cancel(stream);
        self.connected = false;
    }

    /// Move queued data while the socket accepts it (0x91f83fe8).
    pub fn pump(&mut self, stream: &mut impl Stream) {
        if self.connected {
            self.pump_sends(stream);
            self.pump_receives(stream);
        }
    }

    fn pump_sends(&mut self, stream: &mut impl Stream) {
        while let Some(slot) = self.head(Queue::Send) {
            let request = self.requests[slot.index()];
            let sent = if request.framed {
                let remaining = request.length.wrapping_sub(request.progress);
                stream.send(Outgoing::Caller(CallerBuffer {
                    address: request.buffer.wrapping_add(request.progress),
                    length: remaining,
                }))
            } else {
                let prefix = request.length.to_be_bytes();
                stream.send(Outgoing::Local(
                    &prefix[(request.progress as usize).min(prefix.len())..],
                ))
            };
            let Some(count) = sent else {
                self.socket_error(stream);
                return;
            };
            let request = &mut self.requests[slot.index()];
            request.progress = request.progress.wrapping_add(count);
            if !request.framed {
                if request.progress >= LENGTH_SIZE {
                    request.framed = true;
                    request.progress = 0;
                }
            } else if request.progress >= request.length {
                self.finish(slot, Ok(()), stream);
            }
        }
    }

    fn pump_receives(&mut self, stream: &mut impl Stream) {
        while let Some(slot) = self.head(Queue::Receive) {
            self.drop_discarded(stream);
            if self.discard > 0 {
                return;
            }
            let request = self.requests[slot.index()];
            if !request.framed && request.length < LENGTH_SIZE {
                stream.short_buffer();
            }
            let end = if request.framed {
                request.length
            } else {
                LENGTH_SIZE
            };
            let received = stream.receive(Incoming::Caller(CallerBuffer {
                address: request.buffer.wrapping_add(request.progress),
                length: end.wrapping_sub(request.progress),
            }));
            match received {
                None => {
                    self.socket_error(stream);
                    return;
                }
                // A zero-length body is read with a zero-length receive, so
                // its 0 result also ends the connection.
                Some(0) => {
                    self.disconnect(stream);
                    return;
                }
                Some(count) => {
                    let request = &mut self.requests[slot.index()];
                    request.progress = request.progress.wrapping_add(count);
                    if request.progress < end {
                        continue;
                    }
                    if request.framed {
                        self.finish(slot, Ok(()), stream);
                        continue;
                    }
                    let length = stream.read_length(request.buffer);
                    if length <= request.length {
                        request.framed = true;
                        request.length = length;
                        request.progress = 0;
                    } else {
                        // Stock drops the buffer capacity, not the message
                        // length, so the rest of the body is read as the next
                        // length prefix.
                        let capacity = request.length;
                        self.finish(slot, Err(StudioError::InvalidArgument), stream);
                        self.discard = self.discard.wrapping_add(capacity);
                    }
                }
            }
        }
    }

    /// Read and drop pending rejected bytes (0x91f83c00).
    fn drop_discarded(&mut self, stream: &mut impl Stream) {
        let mut scratch = [0u8; DISCARD_CHUNK];
        while self.discard > 0 {
            let count = (self.discard as usize).min(DISCARD_CHUNK);
            match stream.receive(Incoming::Local(&mut scratch[..count])) {
                None => {
                    self.socket_error(stream);
                    return;
                }
                Some(0) => {
                    self.disconnect(stream);
                    return;
                }
                Some(received) => self.discard = self.discard.wrapping_sub(received),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::collections::VecDeque;
    use std::vec::Vec;

    use super::*;

    /// Socket that accepts up to `send_limit` bytes per send and returns
    /// queued inbound chunks; caller memory is one flat array.
    struct FakeStream {
        memory: Vec<u8>,
        sent: Vec<u8>,
        send_limit: usize,
        inbound: VecDeque<Vec<u8>>,
        closed: bool,
        signals: u32,
        short_buffers: u32,
    }

    impl FakeStream {
        fn new() -> Self {
            Self {
                memory: std::vec![0; 0x100],
                sent: Vec::new(),
                send_limit: usize::MAX,
                inbound: VecDeque::new(),
                closed: false,
                signals: 0,
                short_buffers: 0,
            }
        }

        fn deliver(&mut self, bytes: &[u8]) {
            self.inbound.push_back(bytes.to_vec());
        }

        fn take_inbound(&mut self, limit: usize) -> Option<Vec<u8>> {
            let mut chunk = self.inbound.pop_front()?;
            if chunk.len() > limit {
                let rest = chunk.split_off(limit);
                self.inbound.push_front(rest);
            }
            Some(chunk)
        }
    }

    impl Stream for FakeStream {
        fn send(&mut self, data: Outgoing<'_>) -> Option<u32> {
            let bytes = match data {
                Outgoing::Local(bytes) => bytes.to_vec(),
                Outgoing::Caller(buffer) => self.memory
                    [buffer.address as usize..(buffer.address + buffer.length) as usize]
                    .to_vec(),
            };
            let count = bytes.len().min(self.send_limit);
            self.sent.extend_from_slice(&bytes[..count]);
            Some(count as u32)
        }

        fn receive(&mut self, into: Incoming<'_>) -> Option<u32> {
            let limit = match &into {
                Incoming::Local(bytes) => bytes.len(),
                Incoming::Caller(buffer) => buffer.length as usize,
            };
            let Some(chunk) = self.take_inbound(limit) else {
                return if self.closed { Some(0) } else { None };
            };
            match into {
                Incoming::Local(bytes) => bytes[..chunk.len()].copy_from_slice(&chunk),
                Incoming::Caller(buffer) => {
                    let start = buffer.address as usize;
                    self.memory[start..start + chunk.len()].copy_from_slice(&chunk);
                }
            }
            Some(chunk.len() as u32)
        }

        fn would_block(&mut self) -> bool {
            !self.closed
        }

        fn read_length(&mut self, address: u32) -> u32 {
            let start = address as usize;
            u32::from_be_bytes(self.memory[start..start + 4].try_into().unwrap())
        }

        fn signal(&mut self) {
            self.signals += 1;
        }

        fn short_buffer(&mut self) {
            self.short_buffers += 1;
        }
    }

    fn queue(
        transport: &mut Transport,
        direction: Direction,
        address: u32,
        length: u32,
        stream: &mut FakeStream,
    ) -> Slot {
        let slot = transport.reserve().unwrap();
        transport.submit(slot, direction, CallerBuffer { address, length }, stream);
        slot
    }

    #[test]
    fn send_writes_length_prefix_then_body() {
        let mut stream = FakeStream::new();
        stream.memory[0x10..0x13].copy_from_slice(b"abc");
        stream.send_limit = 2;
        let mut transport = Transport::new();
        let slot = queue(&mut transport, Direction::Send, 0x10, 3, &mut stream);
        assert_eq!(stream.sent, [0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(transport.complete(slot), Some((Ok(()), 3)));
        assert_eq!(stream.signals, 1);
    }

    #[test]
    fn receive_completes_across_partial_reads() {
        let mut stream = FakeStream::new();
        let mut transport = Transport::new();
        let slot = queue(&mut transport, Direction::Receive, 0x20, 8, &mut stream);
        assert!(transport.is_pending(slot));
        assert_eq!(transport.complete(slot), None);
        stream.deliver(&[0, 0]);
        transport.pump(&mut stream);
        stream.deliver(&[0, 5, b'h', b'e']);
        stream.deliver(b"llo");
        transport.pump(&mut stream);
        assert_eq!(transport.complete(slot), Some((Ok(()), 5)));
        assert_eq!(&stream.memory[0x20..0x25], b"hello");
    }

    #[test]
    fn oversized_message_drops_buffer_capacity_only() {
        let mut stream = FakeStream::new();
        let mut transport = Transport::new();
        let first = queue(&mut transport, Direction::Receive, 0x20, 4, &mut stream);
        let second = queue(&mut transport, Direction::Receive, 0x40, 8, &mut stream);
        stream.deliver(&[0, 0, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0, 2, b'o', b'k']);
        transport.pump(&mut stream);
        assert_eq!(
            transport.complete(first),
            Some((Err(StudioError::InvalidArgument), 4))
        );
        // Four of the six body bytes were dropped; the last two start the
        // next length prefix.
        assert_eq!(
            transport.complete(second),
            Some((Err(StudioError::InvalidArgument), 4))
        );
        assert!(transport.is_connected());
    }

    #[test]
    fn short_receive_buffer_raises_the_assertion() {
        let mut stream = FakeStream::new();
        let mut transport = Transport::new();
        queue(&mut transport, Direction::Receive, 0x20, 2, &mut stream);
        assert_eq!(stream.short_buffers, 1);
    }

    #[test]
    fn four_outstanding_requests_exhaust_the_slots() {
        let mut stream = FakeStream::new();
        let mut transport = Transport::new();
        let slots: Vec<Slot> = (0..REQUEST_SLOTS)
            .map(|_| queue(&mut transport, Direction::Receive, 0x20, 8, &mut stream))
            .collect();
        assert_eq!(transport.reserve(), Err(StudioError::OutOfMemory));
        transport.cancel(&mut stream);
        assert_eq!(stream.signals, 4);
        assert_eq!(
            transport.complete(slots[2]),
            Some((Err(StudioError::Aborted), 0))
        );
        assert_eq!(transport.reserve(), Ok(slots[2]));
    }

    #[test]
    fn freed_slots_are_reused_in_release_order() {
        let mut stream = FakeStream::new();
        let mut transport = Transport::new();
        let first = queue(&mut transport, Direction::Send, 0x10, 0, &mut stream);
        let second = queue(&mut transport, Direction::Send, 0x10, 0, &mut stream);
        assert_eq!(transport.complete(second), Some((Ok(()), 0)));
        assert_eq!(transport.complete(first), Some((Ok(()), 0)));
        let order: Vec<Slot> = (0..REQUEST_SLOTS)
            .map(|_| queue(&mut transport, Direction::Receive, 0x20, 8, &mut stream))
            .collect();
        assert_eq!(order, [Slot(2), Slot(3), second, first]);
    }

    #[test]
    fn blocked_socket_keeps_the_connection() {
        let mut stream = FakeStream::new();
        let mut transport = Transport::new();
        let slot = queue(&mut transport, Direction::Receive, 0x20, 8, &mut stream);
        assert!(transport.is_connected());
        assert!(transport.is_pending(slot));
        stream.closed = true;
        transport.pump(&mut stream);
        assert!(!transport.is_connected());
        assert_eq!(
            transport.complete(slot),
            Some((Err(StudioError::Aborted), 0))
        );
    }
}
