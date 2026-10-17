//! Simulated `rpc` call blocks and the title threads that run them.

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use openxbdm_server::commands::session::RpcBackend;
use openxbdm_server::commands::session::RpcCall;
use openxbdm_server::commands::session::RpcContext;
use openxbdm_server::commands::session::RpcCreateError;
use openxbdm_server::commands::session::RpcThread;

use super::Mock;
use crate::backend::MockBackend;
use crate::backend::POOL_LIMIT;

/// Drain requests of title threads (monitor control code 0xa8). Tests
/// send thread names without holding the host lock, as a title thread
/// runs beside the monitor; the simulation runs them before it checks a
/// call.
#[derive(Debug)]
pub struct RpcDrains {
    sender: mpsc::Sender<Vec<u8>>,
    receiver: mpsc::Receiver<Vec<u8>>,
}

impl Default for RpcDrains {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();

        Self { sender, receiver }
    }
}

impl RpcDrains {
    /// A sender for drain requests by thread name.
    pub fn sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.sender.clone()
    }
}

/// Arguments of a simulated call, as loaded into r3..r10 and f1..f8.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcArguments {
    pub integers: Vec<u64>,
    pub doubles: Vec<f64>,
}

/// Return registers of a simulated call.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RpcRegisters {
    pub r3: u64,
    pub f1: f64,
}

/// A console function callable through `rpc`.
pub type RpcFunction = Box<dyn FnMut(&RpcArguments) -> RpcRegisters + Send>;

/// Where a simulated call runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcRunner {
    OwnThread { context: RpcContext, processor: u32 },
    Named(Vec<u8>),
}

/// A call block.
#[derive(Debug)]
pub struct MockCall {
    pub runner: RpcRunner,
    pub buffer: Vec<u8>,
    pub started: bool,
    pub done: bool,
}

impl Mock {
    fn buffer_address(id: u32) -> u32 {
        /// Console address of the first call buffer; each call block gets
        /// its own 1 MB window.
        const RPC_BUFFER_BASE: u32 = 0x4a00_0068;
        const RPC_BLOCK_STRIDE: u32 = 0x10_0000;

        RPC_BUFFER_BASE + id * RPC_BLOCK_STRIDE
    }

    /// Run a call as its thread would. A call whose function address is not
    /// registered never finishes.
    fn execute(&mut self, id: u32) {
        const MODULE_NOT_FOUND: u64 = 0xffff_ffff_8007_007e;
        const PROCEDURE_NOT_FOUND: u64 = 0xffff_ffff_8007_007f;

        let Some(call) = self.rpc_calls.get(&id) else {
            return;
        };

        let buffer = &call.buffer;

        let requested = read_qword(buffer, 0x38) as u32;
        let module = read_qword(buffer, 0x30);
        let target = if module == 0 {
            requested
        } else {
            let start = (module as u32).wrapping_sub(Self::buffer_address(id)) as usize;
            let name = name_of(buffer, start);
            let resolved = match self.rpc_exports.get(&(name.clone(), requested)) {
                Some(&address) => Ok(address),
                None if self.rpc_exports.keys().any(|(module, _)| *module == name) => {
                    Err(PROCEDURE_NOT_FOUND)
                }
                None => Err(MODULE_NOT_FOUND),
            };

            match resolved {
                Ok(address) => address,
                Err(failure) => {
                    let call = self.rpc_calls.get_mut(&id).expect("call exists");
                    write_qword(&mut call.buffer, 0, failure);
                    call.done = true;

                    return;
                }
            }
        };

        let Some(function) = self.rpc_functions.get_mut(&target) else {
            return;
        };

        let flags = read_qword(buffer, 0x18);

        // Counts come from the client; arguments past the buffer are not simulated.
        let slots = buffer.len().saturating_sub(0x40) / 8;
        let integer_count = (read_qword(buffer, 0x20) as u32 as usize).min(slots);
        let double_count = (read_qword(buffer, 0x28) as u32 as usize).min(slots - integer_count);
        let integers = (0..integer_count)
            .map(|index| read_qword(buffer, 0x40 + 8 * index))
            .collect();
        let doubles = (0..double_count)
            .map(|index| f64::from_bits(read_qword(buffer, 0x40 + 8 * (integer_count + index))))
            .collect();

        let registers = function(&RpcArguments { integers, doubles });

        let last_error = self.rpc_last_error;
        let call = self.rpc_calls.get_mut(&id).expect("call exists");

        let value = if flags & 1 != 0 {
            registers.f1.to_bits()
        } else {
            registers.r3
        };

        write_qword(&mut call.buffer, 8, value);
        if read_qword(&call.buffer, 0x10) == 1 {
            write_qword(&mut call.buffer, 0x10, u64::from(last_error));
        }

        call.done = true;
        write_qword(&mut call.buffer, 0, 0);
    }
}

impl MockBackend {
    /// Run the queued calls of the title thread named `name`, newest
    /// first, as the thread does when it drains the queue.
    pub fn drain_rpc(&mut self, name: &[u8]) {
        while let Some(position) = self.session.rpc_queue.iter().rposition(|id| {
            self.session
                .rpc_calls
                .get(id)
                .is_some_and(|call| call.runner == RpcRunner::Named(name.to_vec()))
        }) {
            let id = self.session.rpc_queue.remove(position);
            self.session.execute(id);
        }
    }

    fn run_rpc_drains(&mut self) {
        while let Ok(name) = self.session.rpc_drains.receiver.try_recv() {
            self.drain_rpc(&name);
        }
    }
}

impl RpcBackend for MockBackend {
    fn rpc_create(
        &mut self,
        size: u32,
        context: RpcContext,
        thread: RpcThread<'_>,
    ) -> Result<RpcCall, RpcCreateError> {
        if self.session.rpc_exhausted || size > POOL_LIMIT {
            return Err(RpcCreateError::OutOfMemory);
        }

        let id = self.session.next_call;
        self.session.next_call += 1;

        let runner = match thread {
            RpcThread::Own { processor } => RpcRunner::OwnThread { context, processor },
            RpcThread::Named(name) => RpcRunner::Named(name.to_vec()),
        };
        self.session.rpc_calls.insert(
            id,
            MockCall {
                runner,
                buffer: vec![0; size as usize],
                started: false,
                done: false,
            },
        );

        // SAFETY: the id names the new call in `rpc_calls`, removed only by
        // `rpc_abort` and `rpc_release`, after which no copy is used (the
        // trait contract).
        Ok(unsafe { RpcCall::from_raw(id) })
    }

    fn rpc_buffer_address(&mut self, call: RpcCall) -> u32 {
        Mock::buffer_address(call.raw())
    }

    unsafe fn rpc_write(&mut self, call: RpcCall, offset: u32, data: &[u8]) {
        if let Some(call) = self.session.rpc_calls.get_mut(&call.raw()) {
            let start = offset as usize;
            call.buffer[start..start + data.len()].copy_from_slice(data);
        }
    }

    fn rpc_start(&mut self, call: RpcCall) {
        self.run_rpc_drains();

        let id = call.raw();
        let Some(entry) = self.session.rpc_calls.get_mut(&id) else {
            return;
        };

        entry.started = true;
        match entry.runner {
            RpcRunner::OwnThread { .. } => self.session.execute(id),
            RpcRunner::Named(_) => self.session.rpc_queue.push(id),
        }
    }

    unsafe fn rpc_abort(&mut self, call: RpcCall) {
        let id = call.raw();
        self.session.rpc_queue.retain(|&queued| queued != id);
        self.session.rpc_calls.remove(&id);
    }

    fn rpc_wait(&mut self, call: RpcCall) -> bool {
        /// The monitor waits this long for a call before sending a marker.
        const RPC_WAIT: Duration = Duration::from_millis(100);

        self.run_rpc_drains();

        let done = self
            .session
            .rpc_calls
            .get(&call.raw())
            .is_some_and(|call| call.done);
        if !done {
            thread::sleep(RPC_WAIT);
        }

        done
    }

    unsafe fn rpc_read(&mut self, call: RpcCall, offset: u32, output: &mut [u8]) {
        if let Some(call) = self.session.rpc_calls.get(&call.raw()) {
            let start = offset as usize;
            output.copy_from_slice(&call.buffer[start..start + output.len()]);
        }
    }

    unsafe fn rpc_release(&mut self, call: RpcCall) {
        let id = call.raw();
        self.session.rpc_queue.retain(|&queued| queued != id);
        self.session.rpc_calls.remove(&id);
    }
}

fn read_qword(buffer: &[u8], offset: usize) -> u64 {
    buffer.get(offset..offset + 8).map_or(0, |bytes| {
        u64::from_be_bytes(bytes.try_into().unwrap_or([0; 8]))
    })
}

fn write_qword(buffer: &mut [u8], offset: usize, value: u64) {
    if let Some(bytes) = buffer.get_mut(offset..offset + 8) {
        bytes.copy_from_slice(&value.to_be_bytes());
    }
}

fn name_of(buffer: &[u8], start: usize) -> Vec<u8> {
    buffer.get(start..).map_or_else(Vec::new, |tail| {
        tail.split(|&byte| byte == 0)
            .next()
            .unwrap_or(tail)
            .to_vec()
    })
}
