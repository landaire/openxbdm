//! `gdbserver`: serve one GDB or LLDB client over TCP.

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::client::KdClient;
use crate::connection::stop_target;
use crate::error::CliError;
use crate::gdb;
use crate::gdb::ConsoleText;
use crate::gdb::KdTarget;
use crate::gdb::Xenon32;
use crate::gdb::Xenon64;
use crate::gdb::XenonArch;
use crate::gdb::XenonIlp32;
use crate::link::Notification;
use crate::print::print_notification;
use crate::print::print_stop_report;
use crate::transport::UdpTransport;

/// Register width the debugger is told about.
#[derive(Debug, Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
pub enum RegisterWidth {
    /// The 64-bit registers of the processor (`powerpc:common64`).
    #[value(name = "64")]
    Bits64,
    /// The full registers with a 32-bit PowerPC architecture, for ELF32
    /// code compiled in 64-bit mode with 32-bit pointers.
    #[value(name = "ilp32")]
    Ilp32,
    /// Their low words (`powerpc:common`), for code compiled as 32-bit
    /// PowerPC: GDB accepts a 32-bit ELF as the symbol file only then.
    #[value(name = "32")]
    Bits32,
}

/// GDB process launched after the listener and target stop are ready.
#[derive(Debug)]
pub struct DebuggerCommand {
    pub program: PathBuf,
    pub commands: PathBuf,
}

/// Accepts one debugger on `listen`, serves it, then lets the console run.
/// Loads of the images in `stop_on_load` stop the console before their entry
/// points run. `stop_on_connect` keeps the attachment stop while waiting for
/// the debugger. `debugger` launches GDB after the listener and target are
/// ready.
pub fn gdb_server(
    mut client: KdClient<UdpTransport>,
    listen: SocketAddr,
    width: RegisterWidth,
    stop_on_load: Vec<String>,
    stop_on_connect: bool,
    debugger: Option<DebuggerCommand>,
) -> Result<(), Report<CliError>> {
    let (console, console_text) = mpsc::channel();
    client.set_notify(Box::new(move |notification| {
        if let Some(text) = console_line(&notification) {
            // The debugger may be gone; the line is printed below as well.
            let _ = console.send(text);
        }
        print_notification(notification);
    }));
    let listener = TcpListener::bind(listen)
        .map_err(CliError::from)
        .attach(format!("listen {listen}"))?;
    let listener_address = listener
        .local_addr()
        .map_err(CliError::from)
        .attach("reading debugger listener address")?;
    let debugger_address = match listener_address {
        SocketAddr::V4(address) if address.ip().is_unspecified() => {
            SocketAddr::from((Ipv4Addr::LOCALHOST, address.port()))
        }
        SocketAddr::V6(address) if address.ip().is_unspecified() => {
            SocketAddr::from((Ipv6Addr::LOCALHOST, address.port()))
        }
        address => address,
    };
    listener.set_nonblocking(true).map_err(CliError::from)?;

    client.set_hold_loads(stop_on_load);
    if stop_on_connect || debugger.is_some() {
        stop_target(&mut client)?;
        println!("the console is stopped; waiting for the debugger");
    } else {
        attach(&mut client)?;
    }
    println!("waiting for a GDB client on {listener_address}");

    let mut debugger = match debugger {
        Some(command) => match launch_debugger(&command, debugger_address, width) {
            Ok(child) => Some(child),
            Err(error) => {
                if client.stop().is_some() {
                    client
                        .continue_from_stop()
                        .map_err(CliError::from)
                        .attach("release target after GDB launch failure")?;
                }
                return Err(error);
            }
        },
        None => None,
    };

    let stream = match accept(&mut client, &listener, &console_text, debugger.as_mut()) {
        Ok(stream) => stream,
        Err(error) => {
            stop_debugger(&mut debugger);
            if client.stop().is_some() {
                client
                    .continue_from_stop()
                    .map_err(CliError::from)
                    .attach("release target after debugger listener failure")?;
            }
            return Err(error);
        }
    };
    if let Err(error) = stream.set_nonblocking(false) {
        stop_debugger(&mut debugger);
        if client.stop().is_some() {
            client
                .continue_from_stop()
                .map_err(CliError::from)
                .attach("release target after debugger socket failure")?;
        }
        return Err(Report::new(CliError::from(error)));
    }

    if let Err(error) = stop_target(&mut client) {
        stop_debugger(&mut debugger);
        return Err(error);
    }
    if let Some(stop) = client.stop() {
        print_stop_report(stop);
    }

    // Text sent before the debugger attached is printed only.
    while console_text.try_recv().is_ok() {}

    let served = match width {
        RegisterWidth::Bits64 => serve::<Xenon64>(client, stream, console_text),
        RegisterWidth::Ilp32 => serve::<XenonIlp32>(client, stream, console_text),
        RegisterWidth::Bits32 => serve::<Xenon32>(client, stream, console_text),
    };
    let debugger_status = debugger
        .as_mut()
        .map(Child::wait)
        .transpose()
        .map_err(CliError::from)
        .attach("waiting for GDB")?;

    served?;
    if let Some(status) = debugger_status
        && !status.success()
    {
        return Err(Report::new(CliError::GdbExit { status }));
    }

    Ok(())
}

fn launch_debugger(
    debugger: &DebuggerCommand,
    listen: SocketAddr,
    width: RegisterWidth,
) -> Result<Child, Report<CliError>> {
    let architecture = match width {
        RegisterWidth::Bits64 => "powerpc:common64",
        RegisterWidth::Ilp32 | RegisterWidth::Bits32 => "powerpc:common",
    };

    Command::new(&debugger.program)
        .args(["-q", "-nx", "-batch"])
        .args(["-ex", "set pagination off"])
        .args(["-ex", "set confirm off"])
        .args(["-ex", &format!("set architecture {architecture}")])
        .args(["-ex", "set endian big"])
        .args(["-ex", &format!("target remote {listen}")])
        .arg("-x")
        .arg(&debugger.commands)
        .spawn()
        .map_err(CliError::from)
        .attach(format!("launching {}", debugger.program.display()))
}

fn stop_debugger(debugger: &mut Option<Child>) {
    if let Some(debugger) = debugger {
        let _ = debugger.kill();
        let _ = debugger.wait();
    }
}

/// Makes the kernel treat the host as present, so that it reports module
/// loads and debug output: an acknowledged exchange sets the flag, and a
/// report that goes unanswered clears it. A stop the kernel already waits
/// in is kept for the debugger.
fn attach(client: &mut KdClient<UdpTransport>) -> Result<(), Report<CliError>> {
    // Longer than the kernel retransmission interval (0.5 s).
    const PENDING_STOP_WAIT: Duration = Duration::from_millis(1200);

    if client
        .wait_for_stop(PENDING_STOP_WAIT)
        .map_err(CliError::from)?
    {
        println!("the console waits in a stop; it is kept for the debugger");
        return Ok(());
    }

    stop_target(client)?;
    client.continue_from_stop().map_err(CliError::from)?;

    Ok(())
}

/// Keeps servicing the kernel until a debugger connects. Stops are
/// continued, except a held image load and a stop that was pending at
/// startup, which wait for the debugger. A launched debugger that exits
/// before connecting ends the wait.
fn accept(
    client: &mut KdClient<UdpTransport>,
    listener: &TcpListener,
    console_text: &mpsc::Receiver<ConsoleText>,
    mut debugger: Option<&mut Child>,
) -> Result<TcpStream, Report<CliError>> {
    let stream = loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("debugger connected from {peer}");
                break stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // Text without a debugger is printed only.
                while console_text.try_recv().is_ok() {}

                if let Some(debugger) = debugger.as_deref_mut()
                    && let Some(status) = debugger.try_wait().map_err(CliError::from)?
                {
                    return Err(Report::new(CliError::GdbExit { status }));
                }

                if client.stop().is_some() {
                    client
                        .service(Duration::from_millis(200))
                        .map_err(CliError::from)?;
                } else if client
                    .wait_for_stop(Duration::from_millis(200))
                    .map_err(CliError::from)?
                {
                    if let Some(image) = client.stop().and_then(|stop| stop.image.as_ref()) {
                        println!(
                            "stopped at the load of {}; waiting for the debugger",
                            String::from_utf8_lossy(&image.name)
                        );
                    } else {
                        client.continue_from_stop().map_err(CliError::from)?;
                    }
                }
            }
            Err(error) => return Err(Report::new(CliError::from(error))),
        }
    };
    Ok(stream)
}

fn serve<A>(
    client: KdClient<UdpTransport>,
    stream: TcpStream,
    console_text: mpsc::Receiver<ConsoleText>,
) -> Result<(), Report<CliError>>
where
    A: XenonArch,
{
    let mut target = KdTarget::<_, A>::new(client, console_text).map_err(CliError::from)?;
    let outcome = gdb::serve(&mut target, stream);
    let released = target.release();

    let reason = match outcome {
        Ok(reason) => reason,
        Err(error) => {
            released.map_err(CliError::from)?;
            return Err(Report::new(CliError::Gdb {
                message: error.to_string(),
            }));
        }
    };
    println!("debugger session ended: {reason:?}");

    released.map_err(CliError::from)?;
    println!("console resumed");

    Ok(())
}

/// Console text for a debug print or a module load.
fn console_line(notification: &Notification<'_>) -> Option<ConsoleText> {
    match notification {
        Notification::Print(text) => Some(text.to_vec()),
        Notification::LoadSymbols {
            path,
            base,
            size,
            unload,
        } => Some(
            format!(
                "{} {} at {base:#x} size {size:#x}\n",
                if *unload { "unload" } else { "load" },
                String::from_utf8_lossy(path)
            )
            .into_bytes(),
        ),
        Notification::Prompt(_)
        | Notification::FileOpen { .. }
        | Notification::FileClosed { .. }
        | Notification::Beacon(_) => None,
    }
}
