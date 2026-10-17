//! One-line descriptions of datagrams for logging.

use std::fmt::Write;

use openxbdm_kd_core::debug_io::DebugIo;
use openxbdm_kd_core::file_io::FileIoReply;
use openxbdm_kd_core::file_io::FileIoRequest;
use openxbdm_kd_core::manipulate::Reply;
use openxbdm_kd_core::manipulate::ReplyBody;
use openxbdm_kd_core::message::Message;
use openxbdm_kd_core::packet::Datagram;
use openxbdm_kd_core::packet::PacketType;
use openxbdm_kd_core::state_change::StateBody;
use openxbdm_kd_core::state_change::StateChange;

use crate::client::Direction;

/// Describes a datagram. Host and kernel messages of one packet type differ
/// for host file I/O, so the direction selects the decoder.
pub fn describe(datagram: &[u8], direction: Direction) -> String {
    let packet = match Datagram::decode(datagram) {
        Ok(Datagram::Data(packet)) => packet,
        Ok(Datagram::Control(control)) => {
            return format!("control {:?} {:?}", control.kind, control.id);
        }
        Ok(Datagram::Beacon(beacon)) => {
            return format!(
                "beacon host {} word {:#x}",
                beacon.host_address, beacon.unidentified
            );
        }
        Ok(Datagram::BreakIn) => return "break-in request".to_owned(),
        Err(error) => return format!("undecodable ({error})"),
    };

    let mut line = format!(
        "data {:?} {:?} {} bytes",
        packet.packet_type(),
        packet.id(),
        packet.payload().len()
    );

    if let Err(error) = packet.verify() {
        let _ = write!(line, " ({error})");
        return line;
    }

    if direction == Direction::Sent && packet.packet_type() == PacketType::FILE_IO {
        let _ = match FileIoReply::decode(packet.payload()) {
            Ok((reply, data)) => write!(line, ": file reply {reply:?} data {:#x}", data.len()),
            Err(error) => write!(line, " ({error})"),
        };
        return line;
    }

    let message = match Message::decode(&packet) {
        Ok(message) => message,
        Err(error) => {
            let _ = write!(line, " ({error})");
            return line;
        }
    };

    let _ = match message {
        Message::StateChange(change) => write!(line, ": {}", describe_state_change(&change)),
        Message::Manipulate(reply) => write!(line, ": {}", describe_manipulate(&reply)),
        Message::DebugIo(DebugIo::Print { text, .. }) => {
            write!(
                line,
                ": print {:?}",
                String::from_utf8_lossy(text).trim_end()
            )
        }
        Message::DebugIo(DebugIo::Prompt { text, .. }) => {
            write!(
                line,
                ": prompt {:?}",
                String::from_utf8_lossy(text).trim_end()
            )
        }
        Message::DebugIo(DebugIo::Other { api, .. }) => write!(line, ": debug I/O {api:#x}"),
        Message::FileIo(FileIoRequest::Open(open)) => write!(line, ": file open {:?}", open.path),
        Message::FileIo(FileIoRequest::Read(read)) => {
            write!(
                line,
                ": file read handle {} offset {:#x} length {:#x}",
                read.handle.0, read.offset, read.length
            )
        }
        Message::FileIo(FileIoRequest::Close(close)) => {
            write!(line, ": file close handle {}", close.handle.0)
        }
        Message::FileIo(FileIoRequest::Other { api, .. }) => write!(line, ": file {api:?}"),
        Message::Other { .. } => Ok(()),
    };

    line
}

fn describe_state_change(change: &StateChange<'_>) -> String {
    let mut line = format!(
        "{:?} processor {}/{} thread {:#x} pc {:#x}",
        change.new_state,
        change.processor.0,
        change.number_processors,
        change.thread,
        change.program_counter
    );

    let _ = match change.body {
        StateBody::Exception {
            record,
            first_chance,
        } => write!(
            line,
            " code {} address {:#x} parameters {} first chance {first_chance}",
            record.code, record.address, record.number_parameters
        ),
        StateBody::LoadSymbols(symbols) => write!(
            line,
            " {:?} base {:#x} size {:#x}{}",
            String::from_utf8_lossy(change.path),
            symbols.base,
            symbols.size_of_image,
            if symbols.unload { " unload" } else { "" }
        ),
        StateBody::Other => Ok(()),
    };

    line
}

fn describe_manipulate(reply: &Reply<'_>) -> String {
    let mut line = format!("{:?} status {}", reply.api, reply.status);

    let _ = match reply.body {
        ReplyBody::ReadMemory {
            address, actual, ..
        } => {
            write!(line, " address {address:#x} read {actual:#x}")
        }
        ReplyBody::WriteMemory { address, actual } => {
            write!(line, " address {address:#x} written {actual:#x}")
        }
        ReplyBody::ReadContextRange { offset, actual, .. } => {
            write!(line, " offset {offset:#x} read {actual:#x}")
        }
        ReplyBody::WriteContextRange { offset, actual, .. } => {
            write!(line, " offset {offset:#x} written {actual:#x}")
        }
        ReplyBody::WriteBreakpoint { address, handle } => {
            write!(line, " address {address:#x} handle {handle:?}")
        }
        ReplyBody::RestoreBreakpoint { handle } => write!(line, " handle {handle}"),
        ReplyBody::Version(version) => write!(
            line,
            " build {} protocol {} kernel base {:#x}",
            version.minor, version.protocol_version, version.kernel_base
        ),
        ReplyBody::Other { .. } => Ok(()),
    };

    line
}
