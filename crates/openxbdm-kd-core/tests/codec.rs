//! Decoding of captured kdnet datagrams and the host session state machine.

use std::fmt::Write;
use std::num::NonZeroU64;
use std::path::PathBuf;

use openxbdm_kd_core::file_io;
use openxbdm_kd_core::file_io::FileIoReply;
use openxbdm_kd_core::file_io::FileIoRequest;
use openxbdm_kd_core::file_io::HostFileError;
use openxbdm_kd_core::file_io::HostFileHandle;
use openxbdm_kd_core::file_io::HostFileSystem;
use openxbdm_kd_core::file_io::MAX_READ_LEN;
use openxbdm_kd_core::file_io::OpenRequest;
use openxbdm_kd_core::file_io::OpenedFile;
use openxbdm_kd_core::manipulate::ContinueDisposition;
use openxbdm_kd_core::manipulate::Processor;
use openxbdm_kd_core::manipulate::Request;
use openxbdm_kd_core::message::Message;
use openxbdm_kd_core::packet::Datagram;
use openxbdm_kd_core::packet::PacketId;
use openxbdm_kd_core::packet::PacketType;
use openxbdm_kd_core::session::Event;
use openxbdm_kd_core::session::Session;

const FILE_SIZE: u64 = 258_048;
const HANDLE: HostFileHandle = HostFileHandle(NonZeroU64::MIN);

/// A 258048-byte file served for `host:\Device\Flash\xbdm.xex`.
struct OneFile;

impl HostFileSystem for OneFile {
    fn open(&mut self, request: &OpenRequest<'_>) -> Result<OpenedFile, HostFileError> {
        if request
            .path
            .to_string()
            .eq_ignore_ascii_case(r"host:\Device\Flash\xbdm.xex")
        {
            Ok(OpenedFile {
                handle: HANDLE,
                size: FILE_SIZE,
            })
        } else {
            Err(HostFileError::NotMapped)
        }
    }

    fn read(
        &mut self,
        handle: HostFileHandle,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, HostFileError> {
        if handle != HANDLE {
            return Err(HostFileError::UnknownHandle);
        }

        let count = (FILE_SIZE.saturating_sub(offset) as usize).min(buffer.len());
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = (offset as usize + index) as u8;
        }

        Ok(count)
    }

    fn close(&mut self, handle: HostFileHandle) -> Result<(), HostFileError> {
        if handle == HANDLE {
            Ok(())
        } else {
            Err(HostFileError::UnknownHandle)
        }
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// Buck2 sets CARGO_MANIFEST_DIR at run time relative to the project root,
/// where its tests run; the compile-time value does not serve.
fn fixture_path(name: &str) -> PathBuf {
    let manifest_dir =
        std::env::var_os("CARGO_MANIFEST_DIR").expect("the test runner sets CARGO_MANIFEST_DIR");

    PathBuf::from(manifest_dir)
        .join("tests/fixtures")
        .join(name)
}

/// Datagrams of a fixture log (`time peer length hex` lines).
fn fixture_datagrams(name: &str) -> Vec<Vec<u8>> {
    std::fs::read_to_string(fixture_path(name))
        .unwrap()
        .lines()
        .map(|line| hex(line.split_whitespace().nth(3).unwrap()))
        .collect()
}

/// Datagrams from `tests/fixtures/kd.log`.
fn captured() -> Vec<Vec<u8>> {
    fixture_datagrams("kd.log")
}

/// Host file requests captured while the kernel loaded `xbdm.xex` from the
/// host: two opens, three reads (first, a short one ending at a 0x800
/// boundary, last) and the close.
fn captured_file_io() -> Vec<Vec<u8>> {
    fixture_datagrams("file_io.log")
}

#[test]
fn captured_datagrams() {
    let mut out = String::new();

    for datagram in captured() {
        match Datagram::decode(&datagram).unwrap() {
            Datagram::Data(packet) => {
                let packet = packet.verify().unwrap();
                writeln!(out, "{:#?}", packet.header()).unwrap();
                writeln!(out, "{:#?}", Message::decode(&packet).unwrap()).unwrap();
            }
            other => writeln!(out, "{other:#?}").unwrap(),
        }
    }

    insta::assert_snapshot!(out);
}

#[test]
fn checksum_mismatch_is_reported() {
    let mut datagram = captured()
        .into_iter()
        .find(|datagram| datagram.len() > 16)
        .unwrap();
    datagram[20] ^= 1;

    let Datagram::Data(packet) = Datagram::decode(&datagram).unwrap() else {
        panic!("data packet")
    };

    insta::assert_debug_snapshot!(packet.verify().unwrap_err());
}

#[test]
fn request_encodings() {
    let requests = [
        Request::ReadVirtualMemory {
            address: 0x8004_0000,
            length: 0x40,
        },
        Request::ReadContextRange {
            offset: 0x548,
            length: 0x4f8,
        },
        Request::WriteContextRange {
            offset: 0,
            length: 0x548,
        },
        Request::WriteBreakpoint {
            address: 0x801b_4990,
        },
        Request::Continue {
            disposition: ContinueDisposition::Handled,
        },
        Request::GetVersion,
        // The header names the target processor, not the sender.
        Request::SwitchProcessor {
            processor: Processor(3),
        },
    ];

    let mut out = String::new();
    for request in requests {
        let encoded = request.encode(Processor(0));
        let text: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
        writeln!(out, "{:?} {text}", request.api()).unwrap();
    }

    insta::assert_snapshot!(out);
}

#[test]
fn session_exchange() {
    let captured = captured();
    let state_change = &captured[2];
    let mut session = Session::new();
    let mut out = String::new();

    let received = session.receive(state_change).unwrap();
    writeln!(out, "state change: reply {:02x?}", received.reply.unwrap()).unwrap();
    assert!(matches!(received.event, Event::Data(_)));

    let received = session.receive(state_change).unwrap();
    writeln!(out, "repeat: {:?}", received.event).unwrap();

    let reset = session.reset();
    writeln!(out, "reset: {reset:02x?}").unwrap();

    let header = Request::GetVersion.encode(Processor(0));
    let datagram = session
        .send(PacketType::MANIPULATE, &[&header])
        .unwrap()
        .to_vec();
    writeln!(out, "request: {:02x?}", &datagram[..16]).unwrap();
    writeln!(
        out,
        "second send: {:?}",
        session
            .send(PacketType::MANIPULATE, &[&header])
            .unwrap_err()
    )
    .unwrap();

    // The kernel repeats its stop before it reads the request; that does
    // not retire the request.
    let resend = hex("6969696905000000000000000000000000");
    let received = session.receive(&resend[..16]).unwrap();
    writeln!(
        out,
        "resend: {:?} retransmit {}",
        received.event,
        session.retransmission().is_some()
    )
    .unwrap();

    let acknowledge = hex("69696969040000000000008000000000");
    let received = session.receive(&acknowledge).unwrap();
    writeln!(
        out,
        "acknowledge: {:?} outstanding {:?}",
        received.event,
        session.outstanding()
    )
    .unwrap();

    let version = &captured[3];
    let received = session.receive(version).unwrap();
    let Event::Data(packet) = received.event else {
        panic!("data")
    };
    writeln!(out, "reply id {:?}", packet.id()).unwrap();
    assert_eq!(packet.id(), PacketId(2));

    insta::assert_snapshot!(out);
}

#[test]
fn file_io_exchange() {
    let mut requests: Vec<Vec<u8>> = captured_file_io()
        .iter()
        .map(|datagram| {
            let Datagram::Data(packet) = Datagram::decode(datagram).unwrap() else {
                panic!("data packet")
            };
            packet.verify().unwrap().payload().to_vec()
        })
        .collect();

    // A read at the end of the file, which the kernel does not send for a
    // file of known size.
    let mut past_end = requests[4].clone();
    past_end[0x10..0x18].copy_from_slice(&FILE_SIZE.to_le_bytes());
    requests.push(past_end);

    let mut session = Session::new();
    let mut data = [0u8; MAX_READ_LEN];
    let mut out = String::new();

    for payload in &requests {
        let request = FileIoRequest::decode(payload).unwrap();
        writeln!(out, "{request:?}").unwrap();

        let (reply, length) = file_io::respond(&request, &mut OneFile, &mut data);
        let header = reply.encode();
        let datagram = session
            .send(PacketType::FILE_IO, &[&header, &data[..length]])
            .unwrap()
            .to_vec();
        session.abandon();

        let text: String = header.iter().map(|byte| format!("{byte:02x}")).collect();
        writeln!(out, "  {reply:?} data {length:#x}\n  header {text}").unwrap();
        writeln!(out, "  packet {:02x?}", &datagram[..16]).unwrap();

        assert_eq!(
            FileIoReply::decode(&datagram[16..]).unwrap(),
            (reply, &data[..length])
        );
    }

    insta::assert_snapshot!(out);
}
