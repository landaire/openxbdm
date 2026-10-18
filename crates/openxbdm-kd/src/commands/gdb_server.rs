//! `gdbserver`: serve one GDB or LLDB client over TCP.

use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
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
    /// Their low words (`powerpc:common`), for code compiled as 32-bit
    /// PowerPC: GDB accepts a 32-bit ELF as the symbol file only then.
    #[value(name = "32")]
    Bits32,
}

/// Accepts one debugger on `listen`, serves it, then lets the console run.
/// Loads of the images in `stop_on_load` stop the console, before their
/// entry points run, with or without a debugger attached.
pub fn gdb_server(
    mut client: KdClient<UdpTransport>,
    listen: SocketAddr,
    width: RegisterWidth,
    stop_on_load: Vec<String>,
) -> Result<(), Report<CliError>> {
    let (console, console_text) = mpsc::channel();
    client.set_notify(Box::new(move |notification| {
        if let Some(text) = console_line(&notification) {
            // The debugger may be gone; the line is printed below as well.
            let _ = console.send(text);
        }
        print_notification(notification);
    }));

    attach(&mut client)?;
    client.set_hold_loads(stop_on_load);

    let listener = TcpListener::bind(listen)
        .map_err(CliError::from)
        .attach(format!("listen {listen}"))?;
    println!("waiting for a GDB client on {listen}");

    let stream = accept(&mut client, &listener, &console_text)?;

    stop_target(&mut client)?;
    if let Some(stop) = client.stop() {
        print_stop_report(stop);
    }

    // Text sent before the debugger attached is printed only.
    while console_text.try_recv().is_ok() {}

    match width {
        RegisterWidth::Bits64 => serve::<Xenon64>(client, stream, console_text),
        RegisterWidth::Bits32 => serve::<Xenon32>(client, stream, console_text),
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
/// startup, which wait for the debugger.
fn accept(
    client: &mut KdClient<UdpTransport>,
    listener: &TcpListener,
    console_text: &mpsc::Receiver<ConsoleText>,
) -> Result<TcpStream, Report<CliError>> {
    listener.set_nonblocking(true).map_err(CliError::from)?;

    let stream = loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                println!("debugger connected from {peer}");
                break stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // Text without a debugger is printed only.
                while console_text.try_recv().is_ok() {}

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

    stream.set_nonblocking(false).map_err(CliError::from)?;

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
