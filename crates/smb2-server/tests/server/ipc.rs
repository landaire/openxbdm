//! The srvsvc named pipe on IPC$.

use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::client::Client;
use crate::client::PIPE_ACCESS;
use crate::client::disposition;
use crate::client::hex;
use crate::client::u16_at;
use crate::client::u32_at;

const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_c017;

/// Bind (C706 12.6.4.3) for srvsvc 4b324fc8-1670-01d3-1278-5a47bf6ee188
/// version 3.0 over NDR 2.0, call_id 2, one presentation context.
#[rustfmt::skip]
const BIND: [u8; 72] = [
    0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    // max_xmit_frag 4280, max_recv_frag 4280, assoc_group_id 0, one context.
    0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00,
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    0x03, 0x00, 0x00, 0x00,
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00,
];

/// NetrShareEnum (MS-SRVS 3.1.4.8) at level 1, call_id 3: ServerName
/// `\\XBOX`, an empty SHARE_INFO_1_CONTAINER, MAX_PREFERRED_LENGTH, and a
/// zero ResumeHandle.
#[rustfmt::skip]
const SHARE_ENUM: [u8; 88] = [
    0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    // alloc_hint 64, p_cont_id 0, opnum 15.
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x5c, 0x00, 0x5c, 0x00, 0x58, 0x00, 0x42, 0x00, 0x4f, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn bound_pipe(client: &mut Client) -> FileId {
    let pipe = client
        .create("srvsvc", PIPE_ACCESS, disposition::OPEN, 0)
        .file_id();
    client
        .ioctl(pipe, FSCTL_PIPE_TRANSCEIVE, &BIND, 4280)
        .expect(NtStatus::Success);

    pipe
}

#[test]
fn share_enumeration_over_srvsvc() {
    const BIND_ACK: u8 = 0x0c;
    const RESPONSE: u8 = 0x02;

    let mut client = Client::connected("IPC$");
    let pipe = client
        .create("srvsvc", PIPE_ACCESS, disposition::OPEN, 0)
        .file_id();

    let reply = client.ioctl(pipe, FSCTL_PIPE_TRANSCEIVE, &BIND, 4280);
    reply.expect(NtStatus::Success);
    let ack = reply.ioctl_output();
    assert_eq!(ack[2], BIND_ACK);
    assert_eq!(usize::from(u16_at(ack, 8)), ack.len());
    assert_eq!(u32_at(ack, 12), 2);

    let reply = client.write(pipe, 0, &SHARE_ENUM);
    reply.expect(NtStatus::Success);
    assert_eq!(u32_at(reply.body(), 4), SHARE_ENUM.len() as u32);

    let reply = client.read(pipe, 0, 4280);
    reply.expect(NtStatus::Success);
    let pdu = reply.data();
    assert_eq!(pdu[2], RESPONSE);
    assert_eq!(u32_at(pdu, 12), 3);
    assert_eq!(usize::from(u16_at(pdu, 8)), pdu.len());

    // Level 1 with EntriesRead 3: Data, Public, and IPC$.
    insta::assert_snapshot!(hex(&pdu[24..]));
}

#[test]
fn small_transceive_output_continues_with_reads() {
    let mut client = Client::connected("IPC$");
    let pipe = bound_pipe(&mut client);

    let whole = client.ioctl(pipe, FSCTL_PIPE_TRANSCEIVE, &SHARE_ENUM, 4280);
    whole.expect(NtStatus::Success);
    let whole = whole.ioctl_output().to_vec();
    assert!(whole.len() > 128);

    let first = client.ioctl(pipe, FSCTL_PIPE_TRANSCEIVE, &SHARE_ENUM, 64);
    first.expect(NtStatus::BufferOverflow);
    let mut pieces = first.ioctl_output().to_vec();
    assert_eq!(pieces.len(), 64);

    loop {
        let reply = client.read(pipe, 0, 64);
        pieces.extend_from_slice(reply.data());
        if reply.status() == NtStatus::Success {
            break;
        }

        reply.expect(NtStatus::BufferOverflow);
        assert_eq!(reply.data().len(), 64);
    }

    assert_eq!(pieces, whole);
}

#[test]
fn third_pipe_open_exceeds_pipe_slots() {
    let mut client = Client::connected("IPC$");
    let first = client
        .create("srvsvc", PIPE_ACCESS, disposition::OPEN, 0)
        .file_id();
    let second = bound_pipe(&mut client);

    client
        .create("srvsvc", PIPE_ACCESS, disposition::OPEN, 0)
        .expect(NtStatus::InsufficientResources);
    client.close(first, 0).expect(NtStatus::Success);
    let third = bound_pipe(&mut client);

    // Each open keeps its own pipe state.
    client
        .write(second, 0, &SHARE_ENUM)
        .expect(NtStatus::Success);
    client
        .write(third, 0, &SHARE_ENUM)
        .expect(NtStatus::Success);

    let second_reply = client.read(second, 0, 4280).data().to_vec();
    assert_eq!(client.read(third, 0, 4280).data(), second_reply);
}

#[test]
fn unknown_pipe_is_not_found() {
    let mut client = Client::connected("IPC$");
    client
        .create("nopipe", PIPE_ACCESS, disposition::OPEN, 0)
        .expect(NtStatus::ObjectNameNotFound);
}

#[test]
fn transceive_on_disk_file_is_invalid() {
    let mut client = Client::connected("Data");
    let file = client.open("a.txt", disposition::CREATE);

    client
        .ioctl(file, FSCTL_PIPE_TRANSCEIVE, &BIND, 4280)
        .expect(NtStatus::InvalidDeviceRequest);
}
