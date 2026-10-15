//! System control commands and the settings file over TCP.

mod common;

use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;

use common::TestServer;
use openxbdm_core::status::Hresult;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::system::BootFlags;
use openxbdm_server::commands::system::BootWait;
use openxbdm_server::commands::system::LaunchReason;
use openxbdm_server::commands::system::RebootKind;
use openxbdm_server::commands::system::SettingsCopy;
use openxbdm_server::commands::system::TitleFlags;
use openxbdm_server::commands::system::TitleRebootStop;
use openxbdm_server::commands::system::Win32Error;
use openxbdm_server::commands::system::copy_settings;
use openxbdm_server::commands::system::launch_from_paths;
use openxbdm_server::commands::system::launch_image_exists;
use openxbdm_server::commands::system::launch_override;
use openxbdm_server::commands::system::launch_without_connection;
use openxbdm_server::commands::system::prepare_reboot;
use openxbdm_server::commands::system::set_title_from_paths;
use openxbdm_server::commands::system::title_reboot_launch;
use openxbdm_server::commands::system::title_reboot_stop;
use openxbdm_server::commands::system::trace_title_reboot;
use openxbdm_server::commands::system::wipe_settings;
use openxbdm_server::notify::ExecutionState;
use openxbdm_server_host::Host;

const GAME: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\game.xex";

fn settings_lines(host: &Host) -> Vec<String> {
    let file = host
        .backend
        .system
        .settings
        .as_ref()
        .expect("settings file");
    let text = String::from_utf8(file.clone()).unwrap();
    assert!(text.ends_with("\r\n"));
    text.split_terminator("\r\n").map(str::to_owned).collect()
}

/// Debug output that starts with one of `prefixes`, from the point the
/// output was last cleared.
fn traced(host: &Host, prefixes: &[&str]) -> Vec<String> {
    host.backend
        .debug_output
        .iter()
        .map(|line| String::from_utf8_lossy(line).into_owned())
        .filter(|line| prefixes.iter().any(|prefix| line.starts_with(prefix)))
        .collect()
}

/// Settings-file traces (bit 4) other than the line executor's.
fn settings_traced(host: &Host) -> Vec<String> {
    let mut lines = traced(host, &["XBDM: "]);
    lines.retain(|line| !line.starts_with("XBDM: DoIniLine"));
    lines
}

fn echo(text: &str) -> String {
    format!("XBDM: WriteIniSzNoCRLF: '{text}'\n")
}

/// Set the trace mask as `verbose level=` does.
fn set_trace_mask(host: &mut Host, mask: u32) {
    let Host {
        server: core,
        backend,
        network,
    } = host;
    core.execute_settings_line(format!("verbose level={mask}").as_bytes(), backend, network);
    backend.debug_output.clear();
}

#[test]
fn reboot_replies_then_closes_every_connection() {
    let server = TestServer::start();
    let mut other = server.raw();
    other.line();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("reboot wait smcreset title=x"), "200- OK");
    let mut rest = Vec::new();
    session.reader.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    other.reader.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());

    let host = server.host.lock();
    assert_eq!(host.backend.system.reboots, [RebootKind::SmcReset]);
    assert_eq!(host.server.state.system.boot_wait, Some(BootWait::Wait));
}

#[test]
fn reboot_keeps_the_first_boot_wait_request() {
    let server = TestServer::start();
    for command in ["reboot stop", "reboot wait"] {
        let mut session = server.raw();
        session.line();
        assert_eq!(session.command(command), "200- OK");
    }
    let host = server.host.lock();
    assert_eq!(
        host.backend.system.reboots,
        [RebootKind::Normal, RebootKind::Normal]
    );
    assert_eq!(host.server.state.system.boot_wait, Some(BootWait::Stop));
}

#[test]
fn systime_fails_until_the_clock_is_set() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("systime"), "406- ");
    assert_eq!(session.command("setsystime clockhi=0x01da3411"), "406- ");
    assert_eq!(
        session.command("setsystime clockhi=0x01da3411 clocklo=0x9a2b8200"),
        "200- OK"
    );
    let reply = session.command("systime");
    let rest = reply
        .strip_prefix("200- high=0x1da3411 low=0x")
        .expect("stock format");
    let low = u32::from_str_radix(rest, 16).unwrap();
    assert!(low.wrapping_sub(0x9a2b_8200) < 10_000_000 * 60);
    assert_eq!(
        server.host.lock().backend.system.clock_sets,
        [0x01da_3411_9a2b_8200]
    );
}

#[test]
fn setsystime_with_tz_writes_the_default_zone_once() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command("setsystime clockhi=1 clocklo=2 tz=0"),
        "200- OK"
    );
    {
        let host = server.host.lock();
        let xconfig = &host.backend.console.xconfig;
        assert_eq!(xconfig.dword(3, 1), 0x1e0);
        assert_eq!(xconfig.value(3, 2), Some(&b"PST\0"[..]));
        assert_eq!(xconfig.value(3, 3), Some(&b"PDT\0"[..]));
        assert_eq!(xconfig.dword(3, 7), 0xffff_ffc4);
        assert_eq!(xconfig.value(3, 4), Some(&[0x0a, 0x05, 0, 0][..]));
        assert_eq!(xconfig.value(3, 5), Some(&[0x04, 0x01, 0, 0][..]));
        assert_eq!(xconfig.dword(3, 9), 1);
    }
    server.host.lock().backend.console.xconfig.settings.clear();
    server.host.lock().backend.console.xconfig.settings.insert(
        openxbdm_server::commands::console::ConfigSetting::new(3, 2),
        b"CET\0".to_vec(),
    );
    assert_eq!(
        session.command("setsystime clockhi=1 clocklo=2 tz=0"),
        "200- OK"
    );
    let host = server.host.lock();
    assert_eq!(host.backend.console.xconfig.value(3, 1), None);
    assert_eq!(host.backend.console.xconfig.dword(3, 9), 1);
}

#[test]
fn setreset_stores_and_reports_the_chord() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("setreset chord=ABCDEF"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.value(2, 5),
        Some(&b"ABCD\0"[..])
    );
    assert_eq!(session.command("setreset"), "200- ABCD");
    server.host.lock().backend.console.xconfig.failures.insert(
        openxbdm_server::commands::console::ConfigSetting::new(2, 5),
        openxbdm_core::status::NtStatus(0xc000_0001),
    );
    assert_eq!(
        session.command("setreset"),
        "400- Could not change reset key"
    );
}

#[test]
fn setdiscboot_selects_the_boot_device_bits() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("setdiscboot"), "400- missing enable");
    assert_eq!(session.command("setdiscboot enable=2"), "400- ");
    server.host.lock().backend.console.xconfig.settings.insert(
        openxbdm_server::commands::console::ConfigSetting::new(3, 0xc),
        0xffff_ffffu32.to_be_bytes().to_vec(),
    );
    assert_eq!(session.command("setdiscboot enable=1"), "200- OK");
    assert_eq!(
        server.host.lock().backend.console.xconfig.dword(3, 0xc),
        0xfffd_f77f
    );
    server.host.lock().backend.console.xconfig.modify_export = false;
    assert_eq!(
        session.command("setdiscboot enable=0"),
        "400- Modify failed: 0xc0000138"
    );
}

#[test]
fn title_checks_the_image_and_persists_both_lines() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("title dir=e:\\"), "400- missing name");
    assert_eq!(
        session.command("title name=game.xex dir=e:\\"),
        "402- file not found"
    );
    server.host.lock().backend.filesystem.write(GAME, b"xex");
    assert_eq!(
        session.command("title name=game.xex dir=e:\\ persist cmdline=a \"b\" c"),
        "200- OK"
    );
    let host = server.host.lock();
    let lines = settings_lines(&host);
    assert_eq!(lines[0], "[xbdm]");
    assert_eq!(
        lines[1],
        format!(
            "title persist name=\"{GAME}\" dir=\"\\Device\\Harddisk0\\Partition1\\DEVKIT\\\" cmdline=\"a \"b\" c\""
        )
    );
    assert_eq!(
        lines[2],
        format!(
            "title name=\"{GAME}\" dir=\"\\Device\\Harddisk0\\Partition1\\DEVKIT\\\" cmdline=a \"b\" c"
        )
    );
}

#[test]
fn settings_file_follows_the_stock_order_and_reloads() {
    let server = TestServer::start();
    server.host.lock().backend.filesystem.write(GAME, b"xex");
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("title name=game.xex dir=e:\\"), "200- OK");
    assert_eq!(session.command("reboot stop"), "200- OK");
    let (file, filesystem) = {
        let mut host = server.host.lock();
        let lines = settings_lines(&host);
        let order: Vec<&str> = lines
            .iter()
            .map(|line| line.split(' ').next().unwrap())
            .collect();
        let rank = |word: &str| {
            order
                .iter()
                .position(|&w| w == word)
                .unwrap_or_else(|| panic!("{word} line in {lines:?}"))
        };
        assert_eq!(&order[..3], ["[xbdm]", "wait", "title"]);
        assert_eq!(lines[1], "wait stop");
        assert!(rank("title") < rank("dbgname"));
        assert!(rank("dbgname") < rank("staticip"));
        assert!(rank("staticip") < rank("subnet") && rank("subnet") < rank("gateway"));
        assert!(rank("gateway") < rank("memtrack"));
        assert!(rank("memtrack") < rank("dumpsettings"));
        assert!(rank("dumpsettings") < rank("dumpmode"));
        let filesystem = std::mem::take(&mut host.backend.filesystem);
        (host.backend.system.settings.clone(), filesystem)
    };

    let mut host = Host::default();
    host.backend.system.settings = file;
    host.backend.filesystem = filesystem;
    let restarted = TestServer::with_host(host);
    let host = restarted.host.lock();
    assert_eq!(
        host.server.state.system.title.image.as_bytes(),
        GAME.as_bytes()
    );
    assert_eq!(
        host.server.state.system.title.drive.as_bytes(),
        b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\"
    );
    // A one-time boot-wait mode is consumed at startup and the file rewritten.
    assert_eq!(host.server.state.system.boot_wait, None);
    assert!(
        !settings_lines(&host)
            .iter()
            .any(|line| line.starts_with("wait"))
    );
}

#[test]
fn settings_loader_quirks() {
    let mut host = Host::default();
    host.backend.system.settings = Some(b"[xbdm]\nwait forever\r\ndbgname name=abcd".to_vec());
    let server = TestServer::with_host(host);
    let host = server.host.lock();
    assert_eq!(host.server.state.system.boot_wait, Some(BootWait::Forever));
    // The unterminated last line loses its final byte.
    assert_eq!(host.server.state.console.debug_name.as_bytes(), b"abc");

    let mut host = Host::default();
    host.backend.system.settings = Some(b"[xbdm]\r\n\0wait\r\n".to_vec());
    let server = TestServer::with_host(host);
    assert_eq!(server.host.lock().server.state.system.boot_wait, None);
}

#[test]
fn settings_are_skipped_when_the_read_buffer_cannot_be_allocated() {
    let mut host = Host::default();
    host.backend.system.settings = Some(b"[xbdm]\r\nwait forever\r\n".to_vec());
    host.backend.filesystem.pool_exhausted = true;
    let server = TestServer::with_host(host);
    let host = server.host.lock();
    assert_eq!(host.server.state.system.boot_wait, None);
    assert!(!host.server.state.system.settings_loaded);
}

#[test]
fn settings_are_not_written_before_load_completes_or_on_cd_boot() {
    let mut host = Host::default();
    host.backend.filesystem.write(GAME, b"xex");
    let saved = format!("[xbdm]\r\ntitle name=\"{GAME}\"\r\n").into_bytes();
    host.backend.system.settings = Some(saved.clone());
    host.backend.system.recint = Some(b"wait forever\r\n".to_vec());
    let server = TestServer::with_host(host);
    {
        let host = server.host.lock();
        assert_eq!(
            host.server.state.system.title.image.as_bytes(),
            GAME.as_bytes()
        );
        assert_eq!(host.backend.system.settings.as_deref(), Some(&saved[..]));
    }
    server.host.lock().backend.system.cd_boot = true;
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("title nopersist"), "200- OK");
    assert_eq!(
        server.host.lock().backend.system.settings.as_deref(),
        Some(&saved[..])
    );
}

#[test]
fn magicboot_relaunches_in_place_or_reboots() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command("magicboot title=q:\\missing.xex"),
        "402- file not found"
    );
    assert_eq!(
        session.command("magicboot title=nodrive"),
        "402- file not found"
    );
    assert_eq!(
        session.command("magicboot directory=nodrive"),
        "430- path not found"
    );
    {
        let mut host = server.host.lock();
        host.backend.filesystem.write(GAME, b"xex");
        host.backend.system.relaunch_routine = true;
    }
    assert_eq!(
        session.command("magicboot title=e:\\game.xex wait"),
        "200- OK"
    );
    {
        let host = server.host.lock();
        assert_eq!(host.backend.system.relaunches, 1);
        assert_eq!(host.backend.execution_state, ExecutionState::RebootTitle);
        assert_eq!(
            host.server.state.system.title.image.as_bytes(),
            GAME.as_bytes()
        );
    }
    assert_eq!(session.command("magicboot"), "200- OK");
    assert_eq!(server.host.lock().backend.system.relaunches, 1);

    // Revision 4 hardware without a readable SMC settings block takes a
    // cold boot.
    server.host.lock().backend.console.i2c_failure = true;
    assert_eq!(session.command("magicboot stop"), "200- OK");
    let mut rest = Vec::new();
    session.reader.read_to_end(&mut rest).unwrap();
    let host = server.host.lock();
    assert_eq!(host.backend.system.reboots, [RebootKind::Normal]);
    assert_eq!(host.server.state.system.boot_wait, Some(BootWait::Stop));
    assert!(settings_lines(&host).contains(&format!("title flags=0x00000008 name=\"{GAME}\"")));
}

#[test]
fn recovery_reboots_and_records_the_request() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("recovery"), "200- OK");
    let mut rest = Vec::new();
    session.reader.read_to_end(&mut rest).unwrap();
    let host = server.host.lock();
    assert_eq!(host.backend.system.reboots, [RebootKind::Normal]);
    assert_eq!(
        settings_lines(&host).last().map(String::as_str),
        Some("recovery")
    );
}

#[test]
fn deftitle_writes_and_deletes_the_default_title_file() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(session.command("deftitle"), "400- missing dir");
    assert_eq!(session.command("deftitle dir=e:\\"), "400- missing name");
    assert_eq!(session.command("deftitle launcher"), "402- file not found");
    server
        .host
        .lock()
        .backend
        .filesystem
        .write("\\SystemRoot\\xshell.xex", b"xex");
    assert_eq!(session.command("deftitle launcher"), "200- OK");
    let mut expected = b"\\SystemRoot;xshell.xex".to_vec();
    expected.resize(0x100, 0);
    assert_eq!(
        server
            .host
            .lock()
            .backend
            .filesystem
            .read("\\SystemRoot\\dashboard.xbx"),
        Some(&expected[..])
    );
    assert_eq!(session.command("deftitle none"), "200- OK");
    assert_eq!(
        server
            .host
            .lock()
            .backend
            .filesystem
            .read("\\SystemRoot\\dashboard.xbx"),
        None
    );
    assert_eq!(session.command("deftitle none"), "200- OK");
}

#[test]
fn flash_receives_the_image_for_this_hardware() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command("flash size_f=0x10"),
        "400- unsupported hardware type, requires t"
    );
    assert_eq!(
        session.command("flash size_t=0x5000 stockimage"),
        "204- send=t"
    );
    session.stream.write_all(&[0x5a; 0x5000]).unwrap();
    assert_eq!(session.line(), "200- Done, new image flashed");
    {
        let host = server.host.lock();
        let write = &host.backend.system.flash_writes[0];
        assert_eq!(write.image.len(), 0x8000);
        assert!(write.image[..0x5000].iter().all(|&byte| byte == 0x5a));
        assert!(write.image[0x5000..].iter().all(|&byte| byte == 0));
        assert!(write.options.stock_image && !write.options.ignore_version_checking);
    }
    server.host.lock().backend.system.flash_result =
        Err(Win32Error(std::num::NonZeroU32::new(0xb).unwrap()));
    assert_eq!(
        session.command("flash size_t=1 ignoreversionchecking=1"),
        "204- send=t"
    );
    session.stream.write_all(&[1]).unwrap();
    assert_eq!(session.line(), "400- Flash failed with HRESULT 0x8007000b");
    server.host.lock().backend.system.flash_memory = 0;
    assert_eq!(session.command("flash size_t=1"), "400- Not enough memory");
    server.host.lock().backend.system.hardware_flags = 0x7000_0003;
    assert_eq!(
        session.command("flash size_t=1"),
        "400- unsupported hardware type, requires (null)"
    );
}

#[test]
fn flash_with_a_wrapped_size_releases_the_connection() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    // The rounded size wraps to zero, as in the monitor.
    assert_eq!(session.command("flash size_t=0xffffffff"), "204- send=t");
    session.stream.write_all(&[0x5a; 0x100]).unwrap();
    drop(session);
    server.wait_until(|host| host.server.connections().next().is_none());
}

#[test]
fn settings_copies_append_sysset_and_recovery() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    server.host.lock().backend.filesystem.write(GAME, b"xex");
    assert_eq!(session.command("title name=e:\\game.xex"), "200- OK");
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        network,
    } = &mut *host;
    core.execute_settings_line(b"sysset videostd=5", backend, network);
    let saved = backend.system.settings.clone().unwrap();
    let mut expected = saved.clone();
    expected.extend_from_slice(b"sysset videostd=0x00000005\r\nrecovery\r\n");

    let memory = SettingsCopy::Memory {
        address: 0x4000_0000,
        capacity: 0x1000,
    };
    assert_eq!(
        copy_settings(&core.state, backend, memory),
        Some(expected.len() as u32)
    );
    // A memory copy that does not fit keeps its first bytes.
    let short = SettingsCopy::Memory {
        address: 0x4000_0000,
        capacity: 10,
    };
    assert_eq!(copy_settings(&core.state, backend, short), Some(10));
    let padded = SettingsCopy::File {
        handle: 7,
        pad: true,
    };
    assert_eq!(
        copy_settings(&core.state, backend, padded),
        Some(expected.len() as u32)
    );
    let copies = &backend.system.copies;
    assert_eq!(copies[0].bytes, expected);
    assert_eq!(copies[1].bytes, expected[..10]);
    assert_eq!(copies[2].bytes.len(), 0x1000);
    assert_eq!(copies[2].bytes[..expected.len()], expected[..]);
    assert!(
        copies[2].bytes[expected.len()..]
            .iter()
            .all(|&byte| byte == 0)
    );

    backend.system.copy_buffer_available = false;
    assert_eq!(copy_settings(&core.state, backend, padded), None);
    // Copies leave the saved file alone.
    assert_eq!(backend.system.settings.as_deref(), Some(&saved[..]));
}

#[test]
fn wipe_empties_the_settings_file_even_on_cd_boot() {
    let server = TestServer::start();
    let mut host = server.host.lock();
    host.backend.system.cd_boot = true;
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    wipe_settings(&core.state, backend);
    assert_eq!(host.backend.system.settings.as_deref(), Some(&b""[..]));
}

#[test]
fn prepare_reboot_announces_writes_and_closes_connections() {
    let server = TestServer::start();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut session = server.raw();
    session.line();
    assert_eq!(
        session.command(&format!("notifyat port={port} addr=1.0.0.127")),
        "200- OK"
    );
    let (target, _) = listener.accept().unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut target = BufReader::new(target);
    let mut line = String::new();
    target.read_line(&mut line).unwrap();
    assert_eq!(line, "execution started\r\n");
    {
        let mut host = server.host.lock();
        host.backend.system.settings = None;
        let Host {
            server: core,
            backend,
            network,
        } = &mut *host;
        prepare_reboot(core, backend, network);
        assert_eq!(core.state.debugger.kernel_debugger, Some(true));
    }
    line.clear();
    target.read_line(&mut line).unwrap();
    assert_eq!(line, "execution rebooting\r\n");
    let mut rest = Vec::new();
    session.reader.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
    assert!(
        settings_lines(&server.host.lock())
            .contains(&format!("notifyat addr=1.0.0.127 port={port}"))
    );
    let mut late = server.raw();
    assert_eq!(late.line(), "401- max number of connections exceeded");
}

#[test]
fn title_reboot_stops_by_reason_and_flags() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    let state = &mut core.state;
    state.system.boot_flags = BootFlags(BootFlags::WAIT.0 | BootFlags::STOP.0);
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(0)),
        TitleRebootStop::Run
    );
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(1)),
        TitleRebootStop::Run
    );
    // Reason 4 consumes `stop`, so its stop always times out.
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(4)),
        TitleRebootStop::Stop { forever: false }
    );
    assert_eq!(state.system.boot_flags, BootFlags::WAIT);
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(4)),
        TitleRebootStop::Stop { forever: false }
    );
    state.system.boot_flags = BootFlags::default();
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(4)),
        TitleRebootStop::Run
    );
    drop(host);

    assert_eq!(session.command("stopon all"), "200- stop on all");
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    let state = &mut core.state;
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(1)),
        TitleRebootStop::Stop { forever: false }
    );
    state.system.boot_flags = BootFlags::STOP;
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(1)),
        TitleRebootStop::Stop { forever: true }
    );
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(0)),
        TitleRebootStop::Run
    );
}

#[test]
fn title_reboot_uses_up_the_launch_title() {
    const DEFAULT: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\default.xex";
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    {
        let mut host = server.host.lock();
        host.backend.filesystem.write(GAME, b"xex");
        host.backend.filesystem.write(DEFAULT, b"xex");
    }
    assert_eq!(
        session.command("title name=e:\\default.xex persist"),
        "200- OK"
    );
    assert_eq!(session.command("title name=e:\\game.xex"), "200- OK");
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    let launch = launch_override(&core.state, LaunchReason(1)).unwrap();
    assert_eq!(launch.image.as_bytes(), GAME.as_bytes());
    assert_eq!(launch_override(&core.state, LaunchReason(1)), Some(launch));

    assert_eq!(
        title_reboot_launch(&mut core.state, backend, LaunchReason(1)),
        Some(launch)
    );
    assert!(core.state.system.title.image.is_empty());
    assert!(
        !settings_lines(&host)
            .iter()
            .any(|line| line.starts_with("title name="))
    );
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    // Only reasons 0 and 4 fall back to the persistent title.
    assert_eq!(
        title_reboot_launch(&mut core.state, backend, LaunchReason(1)),
        None
    );
    let persistent = title_reboot_launch(&mut core.state, backend, LaunchReason(4)).unwrap();
    assert_eq!(persistent.image.as_bytes(), DEFAULT.as_bytes());
    assert_eq!(core.state.system.persistent_title, persistent);

    assert!(launch_image_exists(&core.state, backend, GAME.as_bytes()));
    // After boot a disc image must open like any other.
    assert!(!launch_image_exists(
        &core.state,
        backend,
        b"\\Device\\Cdrom0\\default.xex"
    ));
}

#[test]
fn hard_reboot_keeps_the_launch_title_for_the_next_boot() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    server.host.lock().backend.filesystem.write(GAME, b"xex");
    assert_eq!(
        session.command("magicboot title=e:\\game.xex cold"),
        "200- OK"
    );
    let mut rest = Vec::new();
    session.reader.read_to_end(&mut rest).unwrap();
    let host = server.host.lock();
    assert!(host.server.state.system.hard_reboot_pending);
    assert_eq!(
        host.server.state.system.title.image.as_bytes(),
        GAME.as_bytes()
    );
    assert_eq!(launch_override(&host.server.state, LaunchReason(0)), None);
}

#[test]
fn set_title_export_sets_or_clears_titles() {
    let server = TestServer::start();
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    let state = &mut core.state;
    assert_eq!(
        set_title_from_paths(state, backend, None, None, None, TitleFlags::default()),
        Hresult::INVALID_ARGUMENT
    );
    assert_eq!(
        set_title_from_paths(
            state,
            backend,
            Some(b"e:\\"),
            Some(b"game.xex"),
            None,
            TitleFlags::default()
        ),
        Hresult(0x82da_0002)
    );
    backend.filesystem.write(GAME, b"xex");
    let flags = TitleFlags::PERSIST;
    assert_eq!(
        set_title_from_paths(
            state,
            backend,
            Some(b"e:\\"),
            Some(b"game.xex"),
            Some(b"-x"),
            flags
        ),
        Hresult::OK
    );
    assert_eq!(state.system.title.image.as_bytes(), GAME.as_bytes());
    assert_eq!(
        state.system.title.drive.as_bytes(),
        b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\"
    );
    assert_eq!(state.system.title.command_line.as_bytes(), b"-x");
    assert_eq!(state.system.persistent_title, state.system.title);
    assert_eq!(
        set_title_from_paths(
            state,
            backend,
            None,
            None,
            None,
            TitleFlags::CLEAR_PERSISTENT
        ),
        Hresult::OK
    );
    assert!(state.system.persistent_title.image.is_empty());
    assert_eq!(state.system.title.image.as_bytes(), GAME.as_bytes());
}

#[test]
fn launch_export_translates_relaunches_or_reboots() {
    let server = TestServer::start();
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        network,
    } = &mut *host;
    let none = BootFlags::default();
    assert_eq!(
        launch_from_paths(core, backend, network, none, None, Some(b"e:\\"), None),
        Hresult::INVALID_ARGUMENT
    );
    assert_eq!(
        launch_from_paths(core, backend, network, none, Some(b"nodrive"), None, None),
        Hresult(0x82da_0002)
    );
    assert_eq!(
        launch_from_paths(
            core,
            backend,
            network,
            none,
            Some(b"e:\\game.xex"),
            Some(b"nodrive"),
            None
        ),
        Hresult(0x82da_001e)
    );
    backend.filesystem.write(GAME, b"xex");
    backend.system.relaunch_routine = true;
    let object_paths = BootFlags::OBJECT_PATHS;
    assert_eq!(
        launch_from_paths(
            core,
            backend,
            network,
            object_paths,
            Some(GAME.as_bytes()),
            None,
            None
        ),
        Hresult::OK
    );
    assert_eq!(backend.system.relaunches, 1);
    assert_eq!(core.state.system.boot_flags, object_paths);

    backend.system.relaunch_routine = false;
    // Execution is at reboot_title now, so only a cold launch restarts.
    let cold_wait = BootFlags(BootFlags::WAIT.0 | BootFlags::COLD.0);
    assert_eq!(
        launch_without_connection(core, backend, network, cold_wait, None),
        Hresult::NO_REPLY
    );
    assert_eq!(backend.system.reboots, [RebootKind::Normal]);
    assert!(core.state.system.hard_reboot_pending);
    assert_eq!(core.state.system.boot_wait, Some(BootWait::Wait));
    drop(host);
    assert!(settings_lines(&server.host.lock()).contains(&"wait".to_owned()));
    let mut late = server.raw();
    assert_eq!(late.line(), "401- max number of connections exceeded");
}

#[test]
fn settings_load_and_write_traces() {
    let settings = format!("title name={GAME}\r\n");
    let mut host = Host::default();
    host.backend.filesystem.write(GAME, b"xex");
    host.backend.system.settings = Some(settings.clone().into_bytes());
    host.backend.system.recint = Some(b"wait\r\n".to_vec());
    // The mask is set before the saved settings run.
    host.server.state.console.trace_mask = TraceMask::SETTINGS;
    host.backend.console.published.trace_mask = TraceMask::SETTINGS.0;
    let server = TestServer::with_host(host);
    let lines = settings_traced(&server.host.lock());
    let head = [
        "XBDM: LoadIniFile\n".to_owned(),
        format!("XBDM: Handle: 0x00000000, File Size: {}\n", settings.len()),
        // The title line writes the settings file twice, each time too early.
        "XBDM: WriteIniFile - not finished loading\n".to_owned(),
        "XBDM: WriteIniFile - not finished loading\n".to_owned(),
        "XBDM: g_fFinishedLoadingIniFile = TRUE\n".to_owned(),
        "XBDM: Finished loading recint.ini\n".to_owned(),
        // The one-time `wait` is used up and the file rewritten.
        "XBDM: WriteIniFileImpl - entry\n".to_owned(),
        echo("[xbdm]"),
        echo("verbose level=4"),
        echo("title"),
        echo(" name=\""),
        echo(GAME),
        echo("\""),
        echo("(null)"),
    ];
    assert_eq!(lines[..head.len()], head);
    assert_eq!(
        lines.last().map(String::as_str),
        Some("XBDM: WriteIniFileImpl - Done writing ini file...\n")
    );
}

#[test]
fn settings_copy_wipe_and_gate_traces() {
    let server = TestServer::start();
    let mut host = server.host.lock();
    set_trace_mask(&mut host, 4);
    let Host {
        server: core,
        backend,
        network,
    } = &mut *host;
    core.execute_settings_line(b"sysset videostd=5", backend, network);
    backend.debug_output.clear();
    let memory = SettingsCopy::Memory {
        address: 0x4000_0000,
        capacity: 0x1000,
    };
    assert!(copy_settings(&core.state, backend, memory).is_some());
    let lines = settings_traced(&host);
    assert_eq!(
        lines[..2],
        ["XBDM: CaptureIniFile - start\n".to_owned(), echo("[xbdm]")]
    );
    assert_eq!(
        lines[lines.len() - 5..],
        [
            echo("sysset"),
            echo(" videostd=0x00000005"),
            echo("(null)"),
            echo("recovery"),
            "XBDM: CaptureIniFile - end\n".to_owned(),
        ]
    );

    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    backend.debug_output.clear();
    backend.system.copy_buffer_available = false;
    assert_eq!(
        copy_settings(
            &core.state,
            backend,
            SettingsCopy::File {
                handle: 7,
                pad: false
            }
        ),
        None
    );
    assert_eq!(settings_traced(&host), ["XBDM: WriteAltIniFile - start\n"]);

    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    backend.debug_output.clear();
    backend.system.title_process_caller = true;
    wipe_settings(&core.state, backend);
    assert_eq!(
        settings_traced(&host),
        [
            "XBDM: WipeIniFile - signaling system thread to wipe ini file.\n",
            "XBDM: WriteIniFileImpl - entry\n",
            "XBDM: WriteIniFileImpl - Done writing ini file...\n",
        ]
    );

    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    backend.debug_output.clear();
    let clear = TitleFlags::CLEAR_PERSISTENT;
    assert_eq!(
        set_title_from_paths(&mut core.state, backend, None, None, None, clear),
        Hresult::OK
    );
    let lines = settings_traced(&host);
    assert_eq!(
        lines[..3],
        [
            "XBDM: WriteIniFile - called from title process - signal server\n".to_owned(),
            "XBDM: WriteIniFileImpl - entry\n".to_owned(),
            echo("[xbdm]"),
        ]
    );

    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    backend.debug_output.clear();
    backend.system.cd_boot = true;
    assert_eq!(
        set_title_from_paths(&mut core.state, backend, None, None, None, clear),
        Hresult::OK
    );
    assert_eq!(
        settings_traced(&host),
        ["XBDM: Cannot write xbdm.ini: CD boot\n"]
    );

    // Every bit but 4.
    set_trace_mask(&mut host, 0x3b);
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    backend.system.cd_boot = false;
    backend.system.copy_buffer_available = true;
    wipe_settings(&core.state, backend);
    assert!(copy_settings(&core.state, backend, memory).is_some());
    assert_eq!(
        set_title_from_paths(&mut core.state, backend, None, None, None, clear),
        Hresult::OK
    );
    assert!(settings_traced(&host).is_empty());
}

#[test]
fn title_image_traces() {
    const PREFIXES: [&str; 2] = ["[xbdm] FGetImageAndDrive", "[xbdm] FTitleExists"];
    const DRIVE: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\";
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    server.host.lock().backend.filesystem.write(GAME, b"xex");
    assert_eq!(session.command("verbose level=8"), "200- OK");
    server.host.lock().backend.debug_output.clear();
    assert_eq!(session.command("title name=e:\\game.xex"), "200- OK");
    assert_eq!(
        traced(&server.host.lock(), &PREFIXES),
        [
            "[xbdm] FGetImageAndDrive(\n   szTitle='e:\\game.xex',\n   szDir='(null)',\n   ...)\n"
                .to_owned(),
            format!("[xbdm] FGetImageAndDrive succeeded:\n   oszImage='{GAME}'\n   oszDrive=''\n"),
            format!("[xbdm] FTitleExists(oszImage='{GAME}',fPostBoot=FALSE)\n"),
            "[xbdm] FTitleExists() returning TRUE\n".to_owned(),
        ]
    );

    // A name past the end of the image buffer is cut, and the cut image is
    // still checked.
    server.host.lock().backend.debug_output.clear();
    let long = "a".repeat(0xe0);
    assert_eq!(
        session.command(&format!("title dir=e:\\ name={long}")),
        "402- file not found"
    );
    let image = format!("{DRIVE}{}", &long[..0x100 - DRIVE.len()]);
    assert_eq!(
        traced(&server.host.lock(), &PREFIXES),
        [
            format!("[xbdm] FGetImageAndDrive(\n   szTitle='{long}',\n   szDir='e:\\',\n   ...)\n"),
            "[xbdm] FGetImageAndDrive buffer overflow appending title\n".to_owned(),
            format!(
                "[xbdm] FGetImageAndDrive succeeded:\n   oszImage='{image}'\n   oszDrive='{DRIVE}'\n"
            ),
            format!("[xbdm] FTitleExists(oszImage='{image}',fPostBoot=FALSE)\n"),
            "[xbdm] FTitleExists() returning FALSE\n".to_owned(),
        ]
    );

    server.host.lock().backend.debug_output.clear();
    assert_eq!(session.command("title name=nodrive"), "402- file not found");
    assert_eq!(
        traced(&server.host.lock(), &PREFIXES),
        [
            "[xbdm] FGetImageAndDrive(\n   szTitle='nodrive',\n   szDir='(null)',\n   ...)\n",
            "[xbdm] FGetImageAndDrive failed:\n",
        ]
    );

    // Before boot a disc image is taken without a check; after boot it is
    // opened.
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        network,
    } = &mut *host;
    backend.debug_output.clear();
    core.execute_settings_line(
        b"title name=\\Device\\Cdrom0\\default.xex",
        backend,
        network,
    );
    assert!(launch_image_exists(&core.state, backend, GAME.as_bytes()));
    assert_eq!(
        traced(&host, &PREFIXES),
        [
            "[xbdm] FTitleExists(oszImage='\\Device\\Cdrom0\\default.xex',fPostBoot=FALSE)\n"
                .to_owned(),
            format!("[xbdm] FTitleExists(oszImage='{GAME}',fPostBoot=TRUE)\n"),
            "[xbdm] FTitleExists() returning TRUE\n".to_owned(),
        ]
    );
    drop(host);

    assert_eq!(session.command("verbose level=0x37"), "200- OK");
    server.host.lock().backend.debug_output.clear();
    assert_eq!(session.command("title name=e:\\game.xex"), "200- OK");
    let mut host = server.host.lock();
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    assert!(launch_image_exists(&core.state, backend, GAME.as_bytes()));
    assert!(traced(&host, &PREFIXES).is_empty());
}

#[test]
fn title_reboot_traces() {
    let server = TestServer::start();
    let mut session = server.raw();
    session.line();
    server.host.lock().backend.filesystem.write(GAME, b"xex");
    assert_eq!(
        session.command("title name=e:\\game.xex persist cmdline=-x"),
        "200- OK"
    );
    let mut host = server.host.lock();
    set_trace_mask(&mut host, 0x10);
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    let state = &mut core.state;
    state.system.boot_flags = BootFlags(BootFlags::WAIT.0 | BootFlags::STOP.0);
    trace_title_reboot(state, backend, LaunchReason(4));
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(4)),
        TitleRebootStop::Stop { forever: false }
    );
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(0)),
        TitleRebootStop::Run
    );
    // Reasons other than 0 that do not stop say nothing.
    state.system.boot_flags = BootFlags::default();
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(4)),
        TitleRebootStop::Run
    );
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(1)),
        TitleRebootStop::Run
    );
    assert!(title_reboot_launch(state, backend, LaunchReason(4)).is_some());
    assert!(title_reboot_launch(state, backend, LaunchReason(4)).is_some());
    let fields = format!("  ImageName='{GAME}'\n   DDrive=''\n   CommandLine='-x'\n");
    assert_eq!(
        traced(&host, &["[xbdm] DmpTitleReboot"]),
        [
            "[xbdm] DmpTitleReboot: Reason=4, g_XamGlobals.Flags=0x00000009\n".to_owned(),
            "[xbdm] DmpTitleReboot: stopping\n".to_owned(),
            "[xbdm] DmpTitleReboot: not stopping\n".to_owned(),
            format!("[xbdm] DmpTitleReboot: updating launch info\n{fields}"),
            format!("[xbdm] DmpTitleReboot: updating [default] launch info\n{fields}"),
        ]
    );

    // Every bit but 0x10.
    set_trace_mask(&mut host, 0x2f);
    let Host {
        server: core,
        backend,
        ..
    } = &mut *host;
    let state = &mut core.state;
    state.system.boot_flags = BootFlags::WAIT;
    trace_title_reboot(state, backend, LaunchReason(4));
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(4)),
        TitleRebootStop::Stop { forever: false }
    );
    assert_eq!(
        title_reboot_stop(state, backend, LaunchReason(0)),
        TitleRebootStop::Run
    );
    assert!(title_reboot_launch(state, backend, LaunchReason(0)).is_some());
    assert!(traced(&host, &["[xbdm] DmpTitleReboot"]).is_empty());
}
