//! Standard output reports of notifications, stops, registers and memory.

use openxbdm_kd_core::context::Context;
use openxbdm_kd_core::context::Gpr;
use rootcause::Report;

use crate::client::KdClient;
use crate::error::CliError;
use crate::error::KdError;
use crate::link::FileOpenAnswer;
use crate::link::Notification;
use crate::stop::StopReport;
use crate::transport::UdpTransport;

pub fn print_notification(notification: Notification<'_>) {
    match notification {
        Notification::Print(text) => print!("{}", String::from_utf8_lossy(text)),
        Notification::Prompt(text) => {
            println!("prompt (answered empty): {}", String::from_utf8_lossy(text))
        }
        Notification::LoadSymbols {
            path,
            base,
            size,
            unload,
        } => println!(
            "{} {} at {base:#x} size {size:#x}",
            if unload { "unload" } else { "load" },
            String::from_utf8_lossy(path)
        ),
        Notification::FileOpen { path, answer } => match answer {
            FileOpenAnswer::Served { local_path, size } => {
                println!(
                    "file open {path}: served from {} ({size} bytes)",
                    local_path.display()
                )
            }
            FileOpenAnswer::NotMapped => {
                println!("file open {path}: not mapped, answered not found")
            }
            FileOpenAnswer::Failed { local_path } => {
                println!(
                    "file open {path}: {} cannot be opened, answered not found",
                    local_path.display()
                )
            }
        },
        Notification::FileClosed {
            console_path,
            bytes_served,
        } => {
            println!("file close {console_path}: {bytes_served} bytes served")
        }
        // Beacons only confirm the kernel is alive.
        Notification::Beacon(_) => {}
    }
}

/// Prints the current stop, the kernel version, the registers of the
/// stopped processor and `stack_words` words from its stack pointer.
pub fn print_stop(
    client: &mut KdClient<UdpTransport>,
    stack_words: usize,
) -> Result<(), Report<CliError>> {
    let Some(stop) = client.stop().cloned() else {
        return Err(Report::new(CliError::Kd(KdError::NotStopped)));
    };

    print_stop_report(&stop);

    let version = client.version().map_err(CliError::from)?;
    println!(
        "kernel build {} protocol {} base {:#x}",
        version.minor, version.protocol_version, version.kernel_base
    );

    let context = client
        .read_context(stop.processor)
        .map_err(CliError::from)?;
    print_registers(&context);

    let Some(sp_register) = Gpr::new(1) else {
        unreachable!("r1 is a valid register")
    };
    let sp = context.gpr(sp_register) as u32;
    let mut stack = vec![0u8; stack_words * 4];
    let read = client
        .read_memory(u64::from(sp), &mut stack)
        .map_err(CliError::from)?;

    println!("stack at {sp:#010x}:");
    for (idx, word) in stack[..read].as_chunks::<4>().0.iter().enumerate() {
        let value = u32::from_be_bytes(*word);

        if idx.is_multiple_of(4) {
            print!("  {:08x}:", sp as usize + idx * 4);
        }

        print!(" {value:08x}");

        if idx % 4 == 3 {
            println!();
        }
    }

    if !(read / 4).is_multiple_of(4) {
        println!();
    }

    Ok(())
}

pub fn print_stop_report(stop: &StopReport) {
    println!(
        "stopped: processor {} of {}, thread {:#x}, pc {:#010x}",
        stop.processor.0,
        stop.number_processors,
        stop.thread,
        stop.pc()
    );

    if let Some(exception) = stop.exception {
        println!(
            "exception {} at {:#x}, {} chance, parameters {:x?}",
            exception.record.code,
            exception.record.address,
            if exception.first_chance {
                "first"
            } else {
                "second"
            },
            &exception.record.information[..(exception.record.number_parameters as usize).min(15)]
        );
    }

    let stream = &stop.control_report.instruction_stream;
    println!(
        "instructions at pc: {}",
        stream
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| format!("{:08x}", u32::from_be_bytes(*word)))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

fn print_registers(context: &Context) {
    for row in 0..8u8 {
        let mut line = String::new();

        for column in 0..4u8 {
            let idx = row + column * 8;
            let Some(register) = Gpr::new(idx) else {
                unreachable!("index below 32")
            };
            line.push_str(&format!("r{idx:<2} {:016x}  ", context.gpr(register)));
        }

        println!("{}", line.trim_end());
    }

    println!(
        "pc  {:08x}  msr {:08x}  lr  {:08x}  ctr {:016x}  cr {:08x}  xer {:08x}",
        context.iar(),
        context.msr(),
        context.lr(),
        context.ctr(),
        context.cr(),
        context.xer()
    );
}

/// Sixteen bytes per line: address, hex bytes and printable ASCII.
pub fn hexdump(address: u64, bytes: &[u8]) {
    for (idx, line) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = line.iter().map(|byte| format!("{byte:02x}")).collect();
        let text: String = line
            .iter()
            .map(|&byte| {
                if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect();

        println!(
            "{:08x}  {:<47}  {text}",
            address + (idx * 16) as u64,
            hex.join(" ")
        );
    }
}
