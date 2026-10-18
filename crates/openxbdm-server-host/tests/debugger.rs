//! Breakpoint, execution control, thread, and debug event commands over
//! TCP.

mod common;

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::net::TcpListener;
use std::net::TcpStream;
use std::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::commands::console::ConfigSetting;
use openxbdm_server::commands::debugger;
use openxbdm_server::commands::debugger::ContextFlags;
use openxbdm_server::commands::debugger::ExceptionRecord;
use openxbdm_server::commands::debugger::ExitStatus;
use openxbdm_server::commands::debugger::Msr;
use openxbdm_server::commands::debugger::ProcessKind;
use openxbdm_server::commands::debugger::TRAP_INSTRUCTION;
use openxbdm_server::commands::debugger::trap;
use openxbdm_server::commands::services::ThreadHandle;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server_host::Host;
use openxbdm_server_host::backend::debugger::MockThread;
use openxbdm_server_host::backend::memory::MEMORY_BASE;
use xbox360_sys::xboxkrnl::HardwareFlags;

use common::RawSession;
use common::TestServer;

const TITLE_THREAD: u32 = 0xfb00_0058;
const OTHER_THREAD: u32 = 0xfb00_0060;
const SYSTEM_THREAD: u32 = 0xf900_0010;
const CODE: u32 = MEMORY_BASE + 0x1000;

/// A notification channel registered directly in the server state.
struct Channel {
    reader: BufReader<TcpStream>,
}

impl Channel {
    fn attach(server: &TestServer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let (accepted, _) = listener.accept().unwrap();
        let mut host = server.host.lock();
        let socket = host.network.insert(accepted);
        host.server.state.notifications.add_socket(socket).unwrap();

        Self {
            reader: BufReader::new(client),
        }
    }

    fn line(&mut self) -> String {
        let mut line = String::new();
        self.reader.read_line(&mut line).unwrap();
        line.trim_end_matches(['\r', '\n']).to_owned()
    }

    fn lines(&mut self, count: usize) -> Vec<String> {
        (0..count).map(|_| self.line()).collect()
    }
}

fn poll(server: &TestServer) {
    let mut guard = server.host.lock();
    let Host {
        server,
        backend,
        network,
    } = &mut *guard;
    server.poll_debug_events(backend, network);
}

fn code_word(server: &TestServer, address: u32) -> u32 {
    let host = server.host.lock();
    let region = host
        .backend
        .memory
        .regions
        .iter()
        .find(|region| region.base == MEMORY_BASE)
        .unwrap();

    let offset = (address - MEMORY_BASE) as usize;
    u32::from_be_bytes(region.bytes[offset..offset + 4].try_into().unwrap())
}

fn write_memory(server: &TestServer, address: u32, bytes: &[u8]) {
    let mut host = server.host.lock();
    let region = host
        .backend
        .memory
        .regions
        .iter_mut()
        .find(|region| region.base == MEMORY_BASE)
        .unwrap();

    let offset = (address - MEMORY_BASE) as usize;
    region.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
}

#[test]
fn software_breakpoints_are_set_queried_and_cleared() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    assert_eq!(code_word(&server, CODE), TRAP_INSTRUCTION);
    assert_eq!(
        debugger::shadow_read(&mut server.host.lock().backend, CODE + 1),
        Some(original.to_be_bytes()[1])
    );
    assert_eq!(
        session.command(&format!("isbreak addr=0x{CODE:08x}")),
        "200- type=4"
    );
    assert_eq!(
        session.command(&format!("isbreak addr=0x{:08x}", CODE + 4)),
        "200- type=0"
    );

    // Re-arming an existing breakpoint keeps the saved instruction.
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    assert_eq!(
        session.command(&format!("break addr=0x{:08x}", CODE + 2)),
        "400- "
    );
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x} clear")),
        "200- OK"
    );
    assert_eq!(code_word(&server, CODE), original);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x} clear")),
        "400- "
    );
    assert_eq!(session.command("break"), "400- missing addr");

    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    assert_eq!(
        session.command(&format!("break addr=0x{:08x}", CODE + 8)),
        "200- OK"
    );
    assert_eq!(session.command("break clearall"), "200- OK");
    assert_eq!(code_word(&server, CODE), original);
    assert_eq!(
        session.command(&format!("isbreak addr=0x{:08x}", CODE + 8)),
        "200- type=0"
    );
}

#[test]
fn break_fails_only_when_pool_memory_runs_out() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();

    server.host.lock().backend.filesystem.pool_exhausted = true;
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "400- "
    );
    server.host.lock().backend.filesystem.pool_exhausted = false;

    // Ascending sets split each full 0x80-entry block in half: every block
    // but the last keeps 0x40 entries. This chain has 9 blocks, the last
    // holding 0x41 entries, and no spare.
    let chained = 9 * 0x40 + 1;

    // One write per command, sent at once, keeps the run from waiting for
    // delayed acknowledgments.
    session.stream.set_nodelay(true).unwrap();
    let set = |session: &mut RawSession, index: u32| {
        session
            .stream
            .write_all(format!("break addr=0x{:08x}\r\n", CODE + index * 8).as_bytes())
            .unwrap();
        assert_eq!(session.line(), "200- OK");
    };
    for index in 0..chained {
        set(&mut session, index);
    }

    // Without pool memory the last block still fills up.
    server.host.lock().backend.filesystem.pool_exhausted = true;
    let full = chained + 0x3f;
    for index in chained..full {
        set(&mut session, index);
    }
    assert_eq!(
        session.command(&format!("break addr=0x{:08x}", CODE + full * 8)),
        "400- "
    );
    assert_eq!(
        session.command(&format!("isbreak addr=0x{:08x}", CODE + full * 8)),
        "200- type=0"
    );

    // An address below the first entry goes to the full last block.
    assert_eq!(
        session.command(&format!("break addr=0x{:08x}", CODE - 4)),
        "400- "
    );

    // The first block has room.
    assert_eq!(
        session.command(&format!("break addr=0x{:08x}", CODE + 4)),
        "200- OK"
    );

    server.host.lock().backend.filesystem.pool_exhausted = false;
    assert_eq!(
        session.command(&format!("break addr=0x{:08x}", CODE + full * 8)),
        "200- OK"
    );
}

#[test]
fn getmem_hides_breakpoint_instructions() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    assert_eq!(
        session.command(&format!("getmem addr=0x{CODE:08x} length=4")),
        "202- memory data follows"
    );
    assert_eq!(session.multiline(), [format!("{original:08X}")]);
}

#[test]
fn data_breakpoint_follows_monitor_rules() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let address = MEMORY_BASE + 0x2004;
    assert_eq!(
        session.command(&format!("break read=0x{address:08x}")),
        "400- missing size"
    );
    assert_eq!(
        session.command(&format!("break write=0x{address:08x} size=8")),
        "400- bad parameter"
    );
    assert_eq!(
        session.command(&format!("break execute=0x{address:08x} size=4")),
        "400- bad parameter"
    );
    assert_eq!(
        session.command(&format!("break read=0x{address:08x} size=4")),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().backend.debugger.data_breakpoint_register,
        (address & !3) | 0x4 | 0x1
    );
    assert_eq!(
        session.command(&format!("isbreak addr=0x{address:08x}")),
        "200- type=5"
    );
    assert_eq!(
        session.command(&format!("break write=0x{:08x} size=4", address + 8)),
        "400- out of memory"
    );
    assert_eq!(
        session.command(&format!("break readwrite=0x{:08x} clear", address + 8)),
        "200- OK"
    );
    assert_eq!(
        session.command(&format!("isbreak addr=0x{address:08x}")),
        "200- type=5"
    );
    assert_eq!(
        session.command(&format!("break write=0x{address:08x} clear")),
        "200- OK"
    );
    assert_eq!(
        session.command(&format!("isbreak addr=0x{address:08x}")),
        "200- type=0"
    );
    assert_eq!(
        server.host.lock().backend.debugger.data_breakpoint_register,
        0
    );

    // The monitor stores address 0 as "no breakpoint": a breakpoint there is
    // reported but replaced by the next set.
    assert_eq!(session.command("break write=0x00000000 size=4"), "200- OK");
    assert_eq!(session.command("isbreak addr=0x00000000"), "200- type=1");
    assert_eq!(
        session.command(&format!("break readwrite=0x{address:08x} size=2")),
        "200- OK"
    );
    assert_eq!(
        session.command(&format!("isbreak addr=0x{address:08x}")),
        "200- type=2"
    );
}

#[test]
fn break_start_requires_pending_execution() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("break start"), "400- execution not pending");
    server.host.lock().backend.execution_state = ExecutionState::Pending;
    assert_eq!(session.command("break start"), "200- OK");
    assert!(
        server
            .host
            .lock()
            .server
            .state
            .debugger
            .break_at_title_entry
    );
}

#[test]
fn stop_and_go_change_execution_and_notify() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("go"), "408- not stopped");
    assert_eq!(session.command("stop"), "200- OK");
    assert_eq!(channel.line(), "execution stopped");
    assert_eq!(session.command("stop"), "426- already stopped");
    assert_eq!(
        session.command(&format!("threadinfo thread=0x{TITLE_THREAD:08x}")),
        "202- thread info follows"
    );
    let info = session.multiline();
    assert!(info[0].starts_with("suspend=0 priority=9 "), "{info:?}");
    assert_eq!(
        server.host.lock().backend.debugger.threads[0]
            .info
            .suspend_count,
        1
    );
    assert_eq!(session.command("go"), "200- OK");
    assert_eq!(channel.line(), "execution started");
    assert_eq!(
        server.host.lock().backend.debugger.threads[0]
            .info
            .suspend_count,
        0
    );
    assert_eq!(session.command("halt"), "400- ");
}

#[test]
fn breakpoint_hit_stops_and_continue_steps_over_it() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    server
        .host
        .lock()
        .backend
        .debugger
        .raise_breakpoint(TITLE_THREAD, CODE);
    poll(&server);
    assert_eq!(
        channel.lines(2),
        [
            "execution stopped".to_owned(),
            format!("break addr=0x{CODE:08x} thread=0x{TITLE_THREAD:08x} stop")
        ]
    );
    assert_eq!(
        session.command(&format!("isstopped thread=0x{TITLE_THREAD:08x}")),
        format!("200- break addr=0x{CODE:08x} thread=0x{TITLE_THREAD:08x}")
    );
    assert_eq!(
        session.command(&format!("isstopped thread=0x{OTHER_THREAD:08x}")),
        "408- not stopped"
    );
    assert_eq!(
        session.command("isstopped thread=0x1234"),
        "405- no such thread"
    );
    assert_eq!(
        session.command(&format!("continue thread=0x{OTHER_THREAD:08x}")),
        "408- not stopped"
    );

    assert_eq!(
        session.command(&format!("continue thread=0x{TITLE_THREAD:08x}")),
        "200- OK"
    );
    {
        let host = server.host.lock();
        let disposition = host.backend.debugger.disposition(TITLE_THREAD).unwrap();
        assert!(disposition.handled && !disposition.chain_kernel_debugger);

        // Continued while stopped: the thread stays suspended for the monitor.
        assert!(host.backend.debugger.threads[0].monitor_suspended);
    }

    // The breakpoint is lifted for the trace step over it.
    assert_eq!(code_word(&server, CODE), original);
    let mut context = server
        .host
        .lock()
        .backend
        .debugger
        .exception_context(TITLE_THREAD, CODE);
    context.msr |= Msr::SINGLE_STEP;
    server
        .host
        .lock()
        .backend
        .debugger
        .in_monitor
        .insert(TITLE_THREAD, context);
    server
        .host
        .lock()
        .backend
        .debugger
        .raise_single_step(TITLE_THREAD, CODE + 4);
    poll(&server);
    assert_eq!(code_word(&server, CODE), TRAP_INSTRUCTION);
    assert!(
        server
            .host
            .lock()
            .backend
            .debugger
            .disposition(TITLE_THREAD)
            .unwrap()
            .handled
    );

    assert_eq!(session.command("go"), "200- OK");
    assert_eq!(channel.line(), "execution started");
    assert!(!server.host.lock().backend.debugger.threads[0].monitor_suspended);
}

#[test]
fn first_chance_exception_is_reported_without_stopping() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let record = ExceptionRecord {
        code: NtStatus::ACCESS_VIOLATION,
        address: CODE,
        parameter_count: 2,
        parameters: [1, 0x1234_5678, 0, 0],
        record_address: 0x7006_e000,
        ..ExceptionRecord::default()
    };
    {
        let mut host = server.host.lock();
        let context = host.backend.debugger.exception_context(OTHER_THREAD, CODE);
        host.backend
            .debugger
            .raise_exception(OTHER_THREAD, record, context, false);
    }

    poll(&server);
    assert_eq!(
        channel.line(),
        format!(
            "exception code=0xc0000005 thread=0x{OTHER_THREAD:08x} address=0x{CODE:08x} write=0x12345678 first"
        )
    );
    let disposition = server
        .host
        .lock()
        .backend
        .debugger
        .disposition(OTHER_THREAD)
        .unwrap();
    assert!(!disposition.handled);
}

#[test]
fn stop_on_first_chance_exception_and_pass_it_on() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("stopon fce"), "200- OK");
    let record = ExceptionRecord {
        code: NtStatus(0xc000_001d),
        address: CODE,
        parameter_count: 0,
        record_address: 0x7006_e000,
        ..ExceptionRecord::default()
    };
    {
        let mut host = server.host.lock();
        let context = host.backend.debugger.exception_context(OTHER_THREAD, CODE);
        host.backend
            .debugger
            .raise_exception(OTHER_THREAD, record, context, false);
    }

    poll(&server);
    let line = format!(
        "exception code=0xc000001d thread=0x{OTHER_THREAD:08x} address=0x{CODE:08x} nparam=0 params=0x7006e014 first"
    );
    assert_eq!(
        channel.lines(2),
        ["execution stopped".to_owned(), format!("{line} stop")]
    );
    assert_eq!(
        session.command(&format!("isstopped thread=0x{OTHER_THREAD:08x}")),
        format!("200- {line}")
    );
    assert_eq!(
        session.command(&format!("continue thread=0x{OTHER_THREAD:08x} exception")),
        "200- OK"
    );
    assert!(
        !server
            .host
            .lock()
            .backend
            .debugger
            .disposition(OTHER_THREAD)
            .unwrap()
            .handled
    );
    assert_eq!(session.command("nostopon all"), "200- stop on none");
}

#[test]
fn debug_strings_are_split_into_lines() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let text_address = MEMORY_BASE + 0x3000;
    {
        let mut host = server.host.lock();
        let region = host
            .backend
            .memory
            .regions
            .iter_mut()
            .find(|region| region.base == MEMORY_BASE)
            .unwrap();
        region.bytes[0x3000..0x300a].copy_from_slice(b"one\ntwo\r\n3");
        let mut context = host.backend.debugger.exception_context(SYSTEM_THREAD, CODE);
        context.gpr[3] = u64::from(text_address);
        context.gpr[4] = 10;
        let record = ExceptionRecord {
            code: NtStatus::BREAKPOINT,
            address: CODE,
            parameter_count: 1,
            parameters: [u32::from(trap::DEBUG_STRING), 0, 0, 0],
            ..ExceptionRecord::default()
        };

        host.backend
            .debugger
            .raise_exception(SYSTEM_THREAD, record, context, false);
    }

    poll(&server);
    assert_eq!(
        channel.lines(4),
        [
            format!("debugstr thread=0x{SYSTEM_THREAD:08x} lf string=one"),
            format!("debugstr thread=0x{SYSTEM_THREAD:08x} cr string=two"),
            format!("debugstr thread=0x{SYSTEM_THREAD:08x} lf string="),
            format!("debugstr thread=0x{SYSTEM_THREAD:08x} string=3"),
        ]
    );
    let disposition = server
        .host
        .lock()
        .backend
        .debugger
        .disposition(SYSTEM_THREAD)
        .unwrap();

    // kd lite chaining is on by default: the kernel debugger finishes it.
    assert!(disposition.chain_kernel_debugger);
}

#[test]
fn thread_create_stops_when_requested() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("stopon createthread"), "200- OK");
    {
        let mut host = server.host.lock();
        let thread = MockThread::new(0xfb00_0070, ProcessKind::Title);
        host.backend.debugger.raise_thread_create(thread, false);
    }

    poll(&server);
    assert_eq!(
        channel.lines(2),
        [
            "execution stopped".to_owned(),
            "create thread=0xfb000070 start=0x82004000 stop".to_owned()
        ]
    );
    assert_eq!(
        session.command("isstopped thread=0xfb000070"),
        "200- stopped"
    );
    assert_eq!(session.command("continue thread=0xfb000070"), "200- OK");
    assert_eq!(session.command("go"), "200- OK");
    assert_eq!(channel.line(), "execution started");
}

#[test]
fn threads_lists_signed_identifiers_in_reverse_order() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("threads"), "202- thread list follows");
    assert_eq!(
        session.multiline(),
        [
            (SYSTEM_THREAD as i32).to_string(),
            (OTHER_THREAD as i32).to_string(),
            (TITLE_THREAD as i32).to_string()
        ]
    );
    server.host.lock().backend.execution_state = ExecutionState::Pending;
    assert_eq!(session.command("threads"), "202- thread list follows");
    assert!(session.multiline().is_empty());
}

#[test]
fn threadinfo_reports_scheduler_fields() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command(&format!("threadinfo thread=0x{TITLE_THREAD:08x}")),
        "202- thread info follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "suspend=0 priority=9 tlsbase=0x7006f800 start=0x82004000 base=0x70070000 limit=0x70060000 slack=0x00000540 \
          createhi=0x01d91234 createlo=0x56789abc nameaddr=0x00000000 namelen=0x00000000 proc=0x01 lasterr=0x00000000"
        ]
    );
    assert_eq!(
        session.command("threadinfo thread=0x1"),
        "405- no such thread"
    );
    assert_eq!(session.command("threadinfo"), "400- missing thread");
}

#[test]
fn context_of_a_running_thread_uses_switch_frame_values() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command(&format!(
            "getcontext thread=0x{TITLE_THREAD:08x} control fp"
        )),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        [
            "Msr=0xffffffff",
            "Iar=0x82000050",
            "Lr=0x82001000",
            "Ctr=0qffffffffffffffff"
        ]
    );
    assert_eq!(
        session.command(&format!("getcontext thread=0x{TITLE_THREAD:08x} int")),
        "202- multiline response follows"
    );
    let lines = session.multiline();
    assert_eq!(lines.len(), 34);
    assert_eq!(lines[0], "Gpr0=0qffffffffffffffff");
    assert_eq!(lines[1], "Gpr1=0q000000007006f000");
    assert_eq!(lines[14], "Gpr14=0q000000000000140e");
    assert_eq!(lines[33], "Xer=0xffffffff");
    assert_eq!(
        session.command(&format!(
            "setcontext thread=0x{TITLE_THREAD:08x} Iar=0x82000000"
        )),
        "408- not stopped"
    );
    assert_eq!(
        session.command("getcontext thread=0x1 control"),
        "405- no such thread"
    );
}

#[test]
fn context_of_a_stopped_thread_round_trips() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    server
        .host
        .lock()
        .backend
        .debugger
        .raise_breakpoint(TITLE_THREAD, CODE);
    poll(&server);
    channel.lines(2);
    assert_eq!(
        session.command(&format!(
            "setcontext thread=0x{TITLE_THREAD:08x} Lr=0x82001234 Gpr5=0q00000001deadbeef Fpr2=0q3ff0000000000000 Vr7=1,0x2,03,4 Bogus=1"
        )),
        "200- OK"
    );
    assert_eq!(
        session.command(&format!("getcontext thread=0x{TITLE_THREAD:08x} full")),
        "202- multiline response follows"
    );
    let lines = session.multiline();
    assert_eq!(lines.len(), 4 + 34 + 33 + 129);
    assert_eq!(lines[0], "Msr=0x00009032");
    assert_eq!(lines[1], format!("Iar=0x{CODE:08x}"));
    assert_eq!(lines[2], "Lr=0x82001234");
    assert_eq!(lines[4 + 5], "Gpr5=0q00000001deadbeef");
    assert_eq!(lines[38], "Fpscr=0q8000000000000000");
    assert_eq!(lines[38 + 3], "Fpr2=0q3ff0000000000000");
    assert_eq!(
        lines[71],
        "Vscr=0x00000000,0x00000000,0x00000000,0x00000000"
    );
    assert_eq!(
        lines[72 + 7],
        "Vr7=0x00000001,0x00000002,0x00000003,0x00000004"
    );
    let saved = server.host.lock().backend.debugger.in_monitor[&TITLE_THREAD].clone();
    assert_eq!(saved.flags, ContextFlags::FULL);
    assert_eq!(saved.lr, 0x8200_1234);
}

#[test]
fn getcontext_uses_pool_memory_while_another_transfer_holds_the_spare() {
    let server = TestServer::start();
    let mut holder = server.raw();
    holder.line();
    assert_eq!(holder.command("keyxchg"), "204- send binary data");
    let mut session = server.raw();
    session.line();
    server.host.lock().backend.filesystem.pool_exhausted = true;
    assert_eq!(
        session.command(&format!("getcontext thread=0x{TITLE_THREAD:08x} control")),
        "400- out of memory"
    );
    server.host.lock().backend.filesystem.pool_exhausted = false;
    assert_eq!(
        session.command(&format!("getcontext thread=0x{TITLE_THREAD:08x} control")),
        "202- multiline response follows"
    );
    assert_eq!(session.multiline().len(), 4);
    assert_eq!(server.host.lock().backend.filesystem.pool_blocks(), 0);
}

#[test]
fn getcontext_works_without_pool_memory() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    server.host.lock().backend.filesystem.pool_exhausted = true;
    for _ in 0..2 {
        assert_eq!(
            session.command(&format!("getcontext thread=0x{TITLE_THREAD:08x} control")),
            "202- multiline response follows"
        );
        assert_eq!(session.multiline().len(), 4);
    }
}

#[test]
fn stop_on_flags_and_replies() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command("stopon modload pogomodstart titleinit"),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().server.state.debugger.stop_on.bits(),
        0x50
    );
    assert_eq!(session.command("nostopon"), "200- OK");
    assert_eq!(
        server.host.lock().server.state.debugger.stop_on.bits(),
        0x50
    );
    assert_eq!(session.command("stopon all"), "200- stop on all");
    assert_eq!(
        server.host.lock().server.state.debugger.stop_on.bits(),
        u32::MAX
    );
    assert_eq!(session.command("nostopon debugstr"), "200- OK");
    assert_eq!(
        server.host.lock().server.state.debugger.stop_on.bits(),
        !0x4
    );
}

#[test]
fn suspend_and_resume_change_suspend_count() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command(&format!("suspend thread=0x{OTHER_THREAD:08x}")),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().backend.debugger.threads[1]
            .info
            .suspend_count,
        1
    );
    assert_eq!(
        session.command(&format!("resume thread=0x{OTHER_THREAD:08x}")),
        "200- OK"
    );
    assert_eq!(
        server.host.lock().backend.debugger.threads[1]
            .info
            .suspend_count,
        0
    );
    assert_eq!(session.command("suspend thread=0x1"), "405- no such thread");
    assert_eq!(session.command("resume"), "400- missing thread");
}

#[test]
fn debugger_identity_and_isdebugger() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("isdebugger"), "200- OK");
    assert_eq!(session.command("debugger"), "400- no command");
    assert_eq!(
        session.command("debugger connect addr=0.0.0.0 port=0 name=\"dev box\" user=me"),
        "200- OK"
    );
    assert_eq!(
        session.command("isdebugger"),
        "410- name=\"dev box\" user=me"
    );
    assert_eq!(session.command("debugger disconnect port=1"), "200- OK");
    assert_eq!(session.command("isdebugger"), "200- OK");
    assert_eq!(
        session.command("debugger connect addr=1.2.3.4 port=0x2da"),
        "200- OK"
    );
    assert_eq!(
        session.command("debugger disconnect port=0x2da addr=1.2.3.5"),
        "414- access denied"
    );
    assert_eq!(
        session.command("debugger disconnect port=0x2da addr=1.2.3.4"),
        "200- OK"
    );
}

#[test]
fn threadstat_reports_exit_code_or_error() {
    let server = TestServer::start();
    server
        .host
        .lock()
        .backend
        .debugger
        .thread_handles
        .insert(ThreadHandle(0x10), Ok(ExitStatus::STILL_ACTIVE));
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command("threadstat handle=0x10"),
        "200- Exit Code 0x103"
    );
    assert_eq!(
        session.command("threadstat handle 16"),
        "200- Exit Code 0x103"
    );
    assert_eq!(session.command("threadstat handle=0x20"), "200- Error 0x6");
    // The current-thread pseudo-handle names the server thread itself.
    assert_eq!(
        session.command("threadstat handle=0xfffffffe"),
        "200- Exit Code 0x103"
    );
    assert_eq!(session.command("threadstat"), "423- bad parameter");
}

#[test]
fn kd_commands_switch_routing() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("kd enable"), "200- kd enabled");
    assert_eq!(
        server.host.lock().server.state.debugger.kernel_debugger,
        Some(true)
    );
    assert_eq!(session.command("kd disable"), "200- kd disabled");
    assert_eq!(
        server.host.lock().server.state.debugger.kernel_debugger,
        Some(false)
    );
    assert_eq!(session.command("kd"), "400- improper command");
    assert_eq!(session.command("kdnet bogus"), "423- bad parameter");
    server.host.lock().backend.debugger.kernel_build = 11500;
    assert_eq!(
        session.command("kdnet show"),
        "407- kdnet is not supported on this flash version.\u{1e}"
    );
}

#[test]
fn kdnet_settings_are_set_shown_and_switched() {
    use openxbdm_server::commands::debugger::KDNET_RECORD_OFFSET;
    use openxbdm_server::commands::debugger::KDNET_RECORD_SIZE;

    let server = TestServer::start();
    server.host.lock().backend.console.xconfig.settings.insert(
        ConfigSetting::new(2, 1),
        vec![0x00, 0x22, 0x48, 0x01, 0x02, 0x10],
    );
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command("kdnet show"),
        "200- kdnet settings:\u{1e}\tEnable=0\u{1e}\tTarget IP: 0.0.0.0\u{1e}\tTarget MAC: 00-00-00-00-00-00\u{1e}\tHost IP: 0.0.0.0\u{1e}\tHost Port: 0\u{1e}\tEncrypted: 0\u{1e}"
    );
    assert_eq!(
        session.command("kdnet enable"),
        "407- kdnet: can't enable kdnet without setting the parameters."
    );
    assert_eq!(
        session.command("kdnet set Port=50000"),
        "423- kdnet set failed: error code 0x82da0017"
    );

    // Without a MAC the console's address less one is used.
    assert_eq!(
        session.command("kdnet set IP=10.0.0.2 Port=50000"),
        "200- kdnet set succeeded."
    );
    let record = {
        let host = server.host.lock();
        host.backend.memory.flash[KDNET_RECORD_OFFSET as usize..][..KDNET_RECORD_SIZE].to_vec()
    };

    assert_eq!(&record[..2], &[0xca, 0x4a]);
    assert_eq!(
        &record[8..0x14],
        &[0, 0, 0, 0x10, 0, 0, 0, 0x48, 0, 0, 0, 1]
    );
    assert_eq!(
        session.command("kdnet show"),
        "200- kdnet settings:\u{1e}\tEnable=1\u{1e}\tTarget IP: 0.0.0.0\u{1e}\tTarget MAC: 00-22-48-01-02-0F\u{1e}\tHost IP: 10.0.0.2\u{1e}\tHost Port: 50000\u{1e}\tEncrypted: 0\u{1e}"
    );
    assert_eq!(
        session.command("kdnet disable"),
        "200- kdnet disabled: 0x10000000"
    );
    assert!(session.command("kdnet show").contains("\tEnable=0\u{1e}"));
    assert_eq!(
        session.command("kdnet enable"),
        "200- kdnet enabled: 0x10000000"
    );
    assert_eq!(
        session.command("kdnet set Mac=00-11-22-33-44-zz"),
        "423- kdnet set failed: error code 0x82da0017"
    );
    assert_eq!(
        session.command("kdnet set Mac=00-11-22-33-44-55"),
        "200- kdnet set succeeded."
    );
    assert!(
        session
            .command("kdnet show")
            .contains("\tTarget MAC: 00-11-22-33-44-55\u{1e}")
    );

    server.host.lock().backend.memory.flash_write_failure = Some(KernelError::AccessDenied);
    assert_eq!(
        session.command("kdnet set Port=1"),
        "400- kdnet set failed: error code 0xd0000022"
    );
    assert_eq!(
        session.command("kdnet disable"),
        "200- kdnet disabled: 0xd0000022"
    );
    server.host.lock().backend.memory.flash_read_failure = Some(KernelError::Unsuccessful);
    assert_eq!(
        session.command("kdnet show"),
        "200- kdnet: failed to load current settings: 0xD0000001"
    );
    assert_eq!(
        session.command("kdnet enable"),
        "200- kdnet: unable to load current kdnet settings: 0xd0000001"
    );
}

#[test]
fn crashdump_replies_before_dumping() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("crashdump"), "200- OK");
    assert_eq!(session.command("getpid").get(..8), Some("200- pid"));
    assert_eq!(server.host.lock().backend.debugger.crash_dumps, 1);
}

#[test]
fn extension_loads_once_and_counts_references() {
    let server = TestServer::start();
    server.host.lock().backend.debugger.extension_images.insert(
        b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\DMEXT\\ext.xex".to_vec(),
        0x8e00_0000,
    );
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command("dbgextld name=missing.xex"),
        "402- file not found"
    );
    assert_eq!(
        session.command("dbgextld name=ext.xex"),
        "200- module=0x8e000000"
    );
    assert_eq!(
        session.command("dbgextld name=EXT.XEX"),
        "200- module=0x8e000000"
    );
    assert_eq!(session.command("dbgextld name=other.xex"), "443- ");
    assert_eq!(
        session.command("dbgextld unload module=0x1"),
        "423- bad parameter"
    );
    assert_eq!(session.command("dbgextld unload"), "423- missing module");
    assert_eq!(
        session.command("dbgextld unload module=0x8e000000"),
        "200- OK"
    );
    assert!(
        server
            .host
            .lock()
            .backend
            .debugger
            .unloaded_extensions
            .is_empty()
    );
    assert_eq!(
        session.command("dbgextld unload module=0x8e000000"),
        "200- OK"
    );
    assert_eq!(
        server
            .host
            .lock()
            .backend
            .debugger
            .unloaded_extensions
            .len(),
        1
    );
}

#[test]
fn break_now_ends_unresolved_on_the_command_thread() {
    use openxbdm_server::commands::console::DumpMode;
    use openxbdm_server_host::backend::debugger::BREAK_NOW_TRAP;

    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    poll(&server);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );

    // The other keys are not looked at.
    assert_eq!(session.command("break now clearall"), "200- OK");
    assert_eq!(
        session.command(&format!("isbreak addr=0x{CODE:08x}")),
        "200- type=4"
    );

    // The command thread's record is not debuggable, so it cannot stop: no
    // line, a crash dump, and the kd lite chain.
    let (outcome, context) = server
        .host
        .lock()
        .backend
        .debugger
        .break_now
        .take()
        .unwrap();
    assert!(outcome.notice.is_none());
    assert!(outcome.disposition.write_dump && outcome.disposition.chain_kernel_debugger);
    assert_eq!(context.iar, BREAK_NOW_TRAP);

    // Without kd lite and dumps the trap is stepped past.
    {
        let mut host = server.host.lock();
        host.server.state.debugger.kd_lite = false;
        host.server.state.console.dump_mode = DumpMode::Disabled;
    }
    poll(&server);
    assert_eq!(session.command("break now"), "200- OK");
    let (outcome, context) = server
        .host
        .lock()
        .backend
        .debugger
        .break_now
        .take()
        .unwrap();
    assert!(!outcome.disposition.write_dump && outcome.disposition.handled);
    assert_eq!((context.iar, context.gpr[3]), (BREAK_NOW_TRAP + 4, 0));

    // Nothing was queued for the notification channels.
    assert!(server.host.lock().backend.debugger.direct.is_empty());
}

#[test]
fn debug_string_above_passive_level_is_deferred_only_when_selected() {
    use openxbdm_server::commands::debugger::Delivery;

    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    write_memory(&server, MEMORY_BASE + 0x2000, b"hi\n");
    let record = ExceptionRecord {
        code: NtStatus::BREAKPOINT,
        parameter_count: 1,
        parameters: [u32::from(trap::DEBUG_STRING), 0, 0, 0],
        ..ExceptionRecord::default()
    };

    let raise = |server: &TestServer| {
        let mut host = server.host.lock();
        let mut context = host.backend.debugger.exception_context(SYSTEM_THREAD, CODE);
        context.gpr[3] = u64::from(MEMORY_BASE + 0x2000);
        context.gpr[4] = 3;
        let outcome = host.backend.raise_direct_exception(
            SYSTEM_THREAD,
            record,
            &mut context,
            Delivery::Deferred,
        );
        (outcome, context)
    };

    // No debugger attached: nothing is queued and the kernel debugger gets
    // the string (kd lite).
    poll(&server);
    let (outcome, _) = raise(&server);
    assert!(outcome.notice.is_none() && outcome.disposition.chain_kernel_debugger);
    assert_eq!(session.command("debugger connect"), "200- OK");
    poll(&server);
    let (outcome, _) = raise(&server);
    assert!(outcome.notice.is_some());
    poll(&server);
    assert_eq!(
        channel.line(),
        format!("debugstr thread=0x{SYSTEM_THREAD:08x} lf string=hi")
    );
    assert_eq!(session.command("eventdefer set break"), "200-  break");
    poll(&server);
    let (outcome, _) = raise(&server);
    assert!(outcome.notice.is_none());
}

#[test]
fn exceptions_after_a_stack_overflow_end_unresolved() {
    use openxbdm_server::commands::debugger::Delivery;

    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("debugger connect"), "200- OK");
    write_memory(&server, MEMORY_BASE + 0x2000, b"hi\n");
    {
        let mut host = server.host.lock();
        host.server.state.debugger.kd_lite = false;
        host.backend
            .debugger
            .threads
            .iter_mut()
            .find(|thread| thread.id.0 == SYSTEM_THREAD)
            .unwrap()
            .stack_overflowed = true;
    }
    poll(&server);

    let raise = |server: &TestServer| {
        let mut host = server.host.lock();
        let mut context = host.backend.debugger.exception_context(SYSTEM_THREAD, CODE);
        context.gpr[3] = u64::from(MEMORY_BASE + 0x2000);
        context.gpr[4] = 3;
        let record = ExceptionRecord {
            code: NtStatus::BREAKPOINT,
            parameter_count: 1,
            parameters: [u32::from(trap::DEBUG_STRING), 0, 0, 0],
            ..ExceptionRecord::default()
        };
        let outcome = host.backend.raise_direct_exception(
            SYSTEM_THREAD,
            record,
            &mut context,
            Delivery::Deferred,
        );
        (outcome, context)
    };

    // The debug string is not queued; the exception ends unresolved with a
    // crash dump and continues past the trap.
    let (outcome, context) = raise(&server);
    assert!(outcome.notice.is_none());
    assert!(outcome.disposition.write_dump && outcome.disposition.handled);
    assert!(!outcome.disposition.chain_kernel_debugger);
    assert_eq!((context.iar, context.gpr[3]), (CODE + 4, 0));

    // With kd lite the kernel debugger takes it instead of the advance.
    server.host.lock().server.state.debugger.kd_lite = true;
    poll(&server);
    let (outcome, context) = raise(&server);
    assert!(outcome.disposition.write_dump && outcome.disposition.chain_kernel_debugger);
    assert_eq!(context.iar, CODE);
}

fn breakpoint_record(address: u32) -> ExceptionRecord {
    ExceptionRecord {
        code: NtStatus::BREAKPOINT,
        address,
        parameter_count: 1,
        parameters: [u32::from(trap::BREAKPOINT), 0, 0, 0],
        ..ExceptionRecord::default()
    }
}

fn single_step_record(address: u32) -> ExceptionRecord {
    ExceptionRecord {
        code: NtStatus::SINGLE_STEP,
        address,
        parameter_count: 1,
        parameters: [1, 0, 0, 0],
        ..ExceptionRecord::default()
    }
}

/// Raise `record` at its address on `thread`, dispatched in place up to
/// dispatch level; `trace` sets the trace bit of the context.
fn raise_in_place(
    server: &TestServer,
    thread: u32,
    record: ExceptionRecord,
    trace: bool,
) -> (
    openxbdm_server::commands::debugger::DirectOutcome,
    openxbdm_server::commands::debugger::Context,
) {
    use openxbdm_server::commands::debugger::Delivery;

    let mut host = server.host.lock();
    let mut context = host
        .backend
        .debugger
        .exception_context(thread, record.address);
    if trace {
        context.msr.insert(Msr::SINGLE_STEP);
    } else {
        context.msr.remove(Msr::SINGLE_STEP);
    }
    let outcome =
        host.backend
            .raise_direct_exception(thread, record, &mut context, Delivery::Deferred);

    (outcome, context)
}

#[test]
fn breakpoints_in_place_follow_the_table() {
    use openxbdm_server::commands::debugger::DirectNotice;

    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    assert_eq!(session.command("debugger connect"), "200- OK");
    assert_eq!(session.command("eventdefer set break"), "200-  break");
    server.host.lock().server.state.debugger.kd_lite = false;
    poll(&server);

    // A table breakpoint is reported without a stop, lifted for a trace
    // step, and handled.
    let (outcome, context) = raise_in_place(&server, SYSTEM_THREAD, breakpoint_record(CODE), false);
    assert_eq!(outcome.notice, Some(DirectNotice::Break));
    assert!(outcome.disposition.handled && !outcome.disposition.write_dump);
    assert!(!outcome.disposition.chain_kernel_debugger);
    assert_eq!(context.iar, CODE);
    assert!(context.msr.contains(Msr::SINGLE_STEP));
    assert_eq!(code_word(&server, CODE), original);
    poll(&server);
    assert_eq!(
        channel.line(),
        format!("break addr=0x{CODE:08x} thread=0x{SYSTEM_THREAD:08x}")
    );

    // The trace step re-arms it and clears the trace bit it set.
    let (outcome, context) =
        raise_in_place(&server, SYSTEM_THREAD, single_step_record(CODE + 4), true);
    assert!(outcome.notice.is_none() && outcome.disposition.handled);
    assert!(!context.msr.contains(Msr::SINGLE_STEP));
    assert_eq!(code_word(&server, CODE), TRAP_INSTRUCTION);

    // Any other breakpoint ends unresolved: no line, a crash dump, and Iar
    // past the trap.
    let (outcome, context) =
        raise_in_place(&server, SYSTEM_THREAD, breakpoint_record(CODE + 8), false);
    assert!(outcome.notice.is_none());
    assert!(outcome.disposition.handled && outcome.disposition.write_dump);
    assert_eq!((context.iar, context.gpr[3]), (CODE + 12, 0));
}

#[test]
fn queued_single_step_steps_over_a_table_breakpoint() {
    use openxbdm_server::commands::debugger::DirectNotice;

    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    assert_eq!(session.command("debugger connect"), "200- OK");
    assert!(
        session
            .command("eventdefer set singlestep")
            .starts_with("200-")
    );
    poll(&server);

    let (outcome, context) = raise_in_place(&server, SYSTEM_THREAD, single_step_record(CODE), true);
    assert_eq!(outcome.notice, Some(DirectNotice::SingleStep));
    assert!(outcome.disposition.handled);
    assert_eq!(context.iar, CODE);
    assert!(context.msr.contains(Msr::SINGLE_STEP));
    assert_eq!(code_word(&server, CODE), original);

    // The step over the breakpoint ends at the next trace exception, which
    // re-arms it.
    let (outcome, context) =
        raise_in_place(&server, SYSTEM_THREAD, single_step_record(CODE + 4), true);
    assert!(outcome.notice.is_none() && outcome.disposition.handled);
    assert!(!context.msr.contains(Msr::SINGLE_STEP));
    assert_eq!(code_word(&server, CODE), TRAP_INSTRUCTION);
}

#[test]
fn nested_exception_disarms_a_table_breakpoint_or_ends_unresolved() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    server.host.lock().server.state.debugger.kd_lite = false;
    poll(&server);

    // The thread stops at a first breakpoint and waits in its slot.
    server
        .host
        .lock()
        .backend
        .debugger
        .raise_breakpoint(TITLE_THREAD, CODE + 0x20);
    poll(&server);
    assert_eq!(
        session.command(&format!("isstopped thread=0x{TITLE_THREAD:08x}")),
        format!(
            "200- break addr=0x{:08x} thread=0x{TITLE_THREAD:08x}",
            CODE + 0x20
        )
    );

    // A nested trap at a table breakpoint gets its instruction back; the
    // entry stays.
    let (outcome, context) = raise_in_place(&server, TITLE_THREAD, breakpoint_record(CODE), false);
    assert!(outcome.notice.is_none() && outcome.disposition.handled);
    assert!(!outcome.disposition.write_dump);
    assert_eq!(context.iar, CODE);
    assert_eq!(code_word(&server, CODE), original);
    assert_eq!(
        session.command(&format!("isbreak addr=0x{CODE:08x}")),
        "200- type=4"
    );

    // Any other nested exception ends unresolved.
    let (outcome, context) =
        raise_in_place(&server, TITLE_THREAD, breakpoint_record(CODE + 8), false);
    assert!(outcome.notice.is_none());
    assert!(outcome.disposition.handled && outcome.disposition.write_dump);
    assert_eq!(context.iar, CODE + 12);
}

#[test]
fn module_unload_in_place_removes_its_breakpoints_during_the_dispatch() {
    use openxbdm_server::commands::debugger::Delivery;
    use openxbdm_server::commands::debugger::ModuleEvent;

    const NAME_STRING: u32 = 0x7000_1000;
    const ENTRY: u32 = 0x7000_2000;

    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    poll(&server);

    let mut host = server.host.lock();
    host.backend.debugger.modules.insert(
        (NAME_STRING, ENTRY),
        ModuleEvent {
            base: CODE,
            size: 0x100,
            ..ModuleEvent::default()
        },
    );
    let mut context = host
        .backend
        .debugger
        .exception_context(SYSTEM_THREAD, CODE + 0x800);
    context.gpr[3] = u64::from(NAME_STRING);
    context.gpr[4] = u64::from(ENTRY);
    let record = ExceptionRecord {
        code: NtStatus::BREAKPOINT,
        address: CODE + 0x800,
        parameter_count: 1,
        parameters: [u32::from(trap::MODULE_UNLOAD), 0, 0, 0],
        ..ExceptionRecord::default()
    };
    host.backend
        .raise_direct_exception(SYSTEM_THREAD, record, &mut context, Delivery::Deferred);
    drop(host);

    // The instruction is back before the server takes any notice.
    assert_eq!(code_word(&server, CODE), original);
    assert_eq!(
        session.command(&format!("isbreak addr=0x{CODE:08x}")),
        "200- type=0"
    );
}

#[test]
fn posted_breakpoints_stop_only_threads_that_can_stop() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    let original = code_word(&server, CODE);
    assert_eq!(
        session.command(&format!("break addr=0x{CODE:08x}")),
        "200- OK"
    );
    {
        let mut host = server.host.lock();
        host.server.state.debugger.kd_lite = false;
        host.backend
            .debugger
            .threads
            .iter_mut()
            .find(|thread| thread.id.0 == OTHER_THREAD)
            .unwrap()
            .debuggable = false;
    }

    // Not debuggable: the table breakpoint is stepped over without a line.
    server
        .host
        .lock()
        .backend
        .debugger
        .raise_breakpoint(OTHER_THREAD, CODE);
    poll(&server);
    let disposition = server
        .host
        .lock()
        .backend
        .debugger
        .disposition(OTHER_THREAD)
        .unwrap();
    assert!(disposition.handled && !disposition.write_dump);
    assert_eq!(code_word(&server, CODE), original);

    // Debuggable with interrupts off: reported without a stop.
    let raise = |address: u32| {
        let mut host = server.host.lock();
        let mut context = host
            .backend
            .debugger
            .exception_context(TITLE_THREAD, address);
        context.msr.remove(Msr::EXTERNAL_INTERRUPT);
        host.backend.debugger.raise_exception(
            TITLE_THREAD,
            breakpoint_record(address),
            context,
            false,
        );
    };
    raise(CODE);
    poll(&server);
    assert_eq!(
        channel.line(),
        format!("break addr=0x{CODE:08x} thread=0x{TITLE_THREAD:08x}")
    );
    assert!(
        server
            .host
            .lock()
            .backend
            .debugger
            .disposition(TITLE_THREAD)
            .unwrap()
            .handled
    );

    // Not a table breakpoint: no line, unresolved with a crash dump.
    raise(CODE + 8);
    poll(&server);
    let disposition = server
        .host
        .lock()
        .backend
        .debugger
        .disposition(TITLE_THREAD)
        .unwrap();
    assert!(disposition.handled && disposition.write_dump);
    assert_eq!(
        session.command(&format!("isstopped thread=0x{TITLE_THREAD:08x}")),
        "408- not stopped"
    );
}

#[test]
fn data_breakpoint_overlap_uses_the_instruction_access_length() {
    let server = TestServer::start();
    let mut channel = Channel::attach(&server);
    let mut session = server.raw();
    session.line();
    let watched = MEMORY_BASE + 0x3004;
    assert_eq!(
        session.command(&format!("break write=0x{watched:08x} size=4")),
        "200- OK"
    );

    let raise = |server: &TestServer, instruction: u32, access: u32| {
        write_memory(server, CODE, &instruction.to_be_bytes());
        let record = ExceptionRecord {
            code: NtStatus::SINGLE_STEP,
            parameter_count: 2,
            parameters: [0, access, 0, 0],
            ..ExceptionRecord::default()
        };

        let context = server
            .host
            .lock()
            .backend
            .debugger
            .exception_context(TITLE_THREAD, CODE);
        server
            .host
            .lock()
            .backend
            .debugger
            .raise_exception(TITLE_THREAD, record, context, false);
        poll(server);
    };

    // lbz r3, 0(r4): one byte just below the watched word misses it; the
    // monitor steps over the data breakpoint without a notification.
    raise(&server, 0x8864_0000, watched - 1);
    assert!(
        server
            .host
            .lock()
            .backend
            .debugger
            .disposition(TITLE_THREAD)
            .unwrap()
            .handled
    );

    // stw r3, 0(r4): four bytes from two below the word reach it.
    raise(&server, 0x9064_0000, watched - 2);
    assert_eq!(
        channel.lines(2),
        [
            "execution stopped".to_owned(),
            format!(
                "data write=0x{watched:08x} addr=0x{CODE:08x} thread=0x{TITLE_THREAD:08x} stop"
            )
        ]
    );
}

#[test]
fn kdlite_needs_the_hardware_flag_and_persists() {
    let server = TestServer::start();

    // Setting (2,6) also holds the `hdd` and `builtinmu` bits.
    server.host.lock().backend.console.xconfig.settings.insert(
        ConfigSetting::new(2, 6),
        0x8000_0007u32.to_be_bytes().to_vec(),
    );
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("kdlite enable"), "400- improper command");
    server
        .host
        .lock()
        .backend
        .system
        .hardware_flags
        .insert(HardwareFlags::TEST_KIT);
    assert_eq!(session.command("kdlite"), "400- improper command");
    assert_eq!(session.command("kdlite disable"), "200- kd lite disabled");
    assert!(!server.host.lock().server.state.debugger.kd_lite);
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(2, 6),
        0x8000_0005
    );
    assert_eq!(session.command("kdlite enable"), "200- kd lite enabled");
    assert!(server.host.lock().server.state.debugger.kd_lite);
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(2, 6),
        0x8000_0007
    );

    server
        .host
        .lock()
        .backend
        .console
        .xconfig
        .failures
        .insert(ConfigSetting::new(2, 6), KernelError::Unsuccessful);
    assert_eq!(session.command("kdlite disable"), "400- improper command");
    assert!(server.host.lock().server.state.debugger.kd_lite);
}
