extern crate std;

use std::string::String;
use std::vec::Vec;

use super::CallId;
use super::DataFormat;
use super::PacketType;
use super::PduError;
use super::Pipe;
use super::PipeContext;
use super::PipeError;
use super::PipeRead;
use super::RpcVersion;
use super::pipe_supported;
use crate::backend::Accounts;
use crate::backend::COMPUTER_NAME_CAPACITY;
use crate::backend::FileHandle;
use crate::backend::FileSystem;
use crate::backend::NtOwf;
use crate::backend::OpenRequest;
use crate::backend::Opened;
use crate::backend::Platform;
use crate::backend::SHARE_NAME_CAPACITY;
use crate::backend::Share;
use crate::backend::ShareId;
use crate::backend::ShareIndex;
use crate::backend::Shares;
use crate::backend::UserKind;
use crate::fs::BasicInformation;
use crate::fs::DirectoryEntry;
use crate::fs::FileInformation;
use crate::fs::FileTime;
use crate::fs::FsError;
use crate::fs::NAME_CAPACITY;
use crate::fs::VolumeInformation;
use crate::path::SharePath;
use crate::utf16::Utf16Le;

/// Disk shares from a list, and the computer name XBOX360.
struct TestBackend {
    shares: &'static [&'static str],
}

const SHARES: TestBackend = TestBackend {
    shares: &["Devkit", "Hdd"],
};

impl Platform for TestBackend {
    fn system_time(&mut self) -> FileTime {
        FileTime(0)
    }

    fn random_bytes(&mut self, output: &mut [u8]) {
        output.fill(0);
    }

    fn computer_name(&mut self, output: &mut [u8; COMPUTER_NAME_CAPACITY]) -> usize {
        output[..7].copy_from_slice(b"XBOX360");
        7
    }
}

impl Accounts for TestBackend {
    fn password(&mut self, _: Utf16Le<'_>, _: Utf16Le<'_>) -> Option<NtOwf> {
        None
    }

    fn allow_guest(&mut self) -> bool {
        true
    }

    fn allow_anonymous(&mut self) -> bool {
        true
    }
}

impl Shares for TestBackend {
    fn find_share(&mut self, _: Utf16Le<'_>, _: UserKind) -> Option<Share> {
        unreachable!()
    }

    fn share_name(
        &mut self,
        index: ShareIndex,
        _: UserKind,
        name: &mut [u16; SHARE_NAME_CAPACITY],
    ) -> Option<usize> {
        let share = self.shares.get(index.0 as usize)?;
        for (unit, byte) in name.iter_mut().zip(share.bytes()) {
            *unit = u16::from(byte);
        }
        Some(share.len())
    }
}

impl FileSystem for TestBackend {
    fn open(&mut self, _: ShareId, _: SharePath<'_>, _: &OpenRequest) -> Result<Opened, FsError> {
        unreachable!()
    }

    fn close(&mut self, _: FileHandle) {
        unreachable!()
    }

    fn read(&mut self, _: FileHandle, _: u64, _: &mut [u8]) -> Result<usize, FsError> {
        unreachable!()
    }

    fn write(&mut self, _: FileHandle, _: u64, _: &[u8]) -> Result<(), FsError> {
        unreachable!()
    }

    fn flush(&mut self, _: FileHandle) -> Result<(), FsError> {
        unreachable!()
    }

    fn information(&mut self, _: FileHandle) -> Result<FileInformation, FsError> {
        unreachable!()
    }

    fn set_basic_information(
        &mut self,
        _: FileHandle,
        _: &BasicInformation,
    ) -> Result<(), FsError> {
        unreachable!()
    }

    fn set_end_of_file(&mut self, _: FileHandle, _: u64) -> Result<(), FsError> {
        unreachable!()
    }

    fn set_delete_pending(&mut self, _: FileHandle, _: bool) -> Result<(), FsError> {
        unreachable!()
    }

    fn rename(&mut self, _: FileHandle, _: SharePath<'_>, _: bool) -> Result<(), FsError> {
        unreachable!()
    }

    fn read_directory(
        &mut self,
        _: FileHandle,
        _: bool,
        _: &mut [u16; NAME_CAPACITY],
    ) -> Result<Option<DirectoryEntry>, FsError> {
        unreachable!()
    }

    fn volume_information(&mut self, _: FileHandle) -> Result<VolumeInformation, FsError> {
        unreachable!()
    }
}

/// Bind as a Windows client sends it for srvsvc (C706 12.6.4.3, MS-RPCE
/// 2.2.2.13 and 3.3.1.5.3): three presentation contexts for the srvsvc
/// interface, offering NDR 2.0, NDR64, and bind time feature negotiation
/// with features 0x03.
#[rustfmt::skip]
const BIND: [u8; 160] = [
    // Version 5.0, bind, first and last fragment, little-endian, frag_length
    // 160, auth_length 0, call_id 2.
    0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    // max_xmit_frag 4280, max_recv_frag 4280, assoc_group_id 0.
    0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
    // n_context_elem 3.
    0x03, 0x00, 0x00, 0x00,
    // Context 0, one transfer syntax: srvsvc 4b324fc8-1670-01d3-1278-5a47bf6ee188
    // version 3.0 over NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 version 2.
    0x00, 0x00, 0x01, 0x00,
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    0x03, 0x00, 0x00, 0x00,
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00,
    // Context 1: NDR64 71710533-beba-4937-8319-b5dbef9ccc36 version 1.
    0x01, 0x00, 0x01, 0x00,
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    0x03, 0x00, 0x00, 0x00,
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
    0x01, 0x00, 0x00, 0x00,
    // Context 2: bind time feature negotiation 6cb71c2c-9812-4540-0300-000000000000
    // version 1.
    0x02, 0x00, 0x01, 0x00,
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    0x03, 0x00, 0x00, 0x00,
    0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
];

/// Bind as smbclient sends it with NTLMSSP sealing (C706 12.6.4.3 and
/// 13.2.6.1 sec_trailer, MS-NLMP 2.2.1.1 NEGOTIATE_MESSAGE): one NDR
/// context and an auth verifier.
#[rustfmt::skip]
const BIND_WITH_AUTH: [u8; 112] = [
    // Bind, frag_length 112, auth_length 32, call_id 1.
    0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x70, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00,
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    0x03, 0x00, 0x00, 0x00,
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00,
    // sec_trailer: RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, no
    // padding, context 0.
    0x0a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // NTLMSSP NEGOTIATE_MESSAGE without domain or workstation.
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82, 0x08, 0xa2,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// NetrShareEnum (MS-SRVS 3.1.4.8) level 1 as Windows sends it for
/// `\\XBOX`: request header (C706 12.6.4.9), then ServerName as a unique
/// conformant varying string, SHARE_ENUM_STRUCT with an empty
/// SHARE_INFO_1_CONTAINER, MAX_PREFERRED_LENGTH, and a zero ResumeHandle.
#[rustfmt::skip]
const SHARE_ENUM: [u8; 88] = [
    // Request, first and last fragment, frag_length 88, call_id 3.
    0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    // alloc_hint 64, p_cont_id 0, opnum 15.
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00,
    // ServerName: referent, max_count 7, offset 0, actual_count 7.
    0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    // "\\XBOX" with terminator, padding.
    0x5c, 0x00, 0x5c, 0x00, 0x58, 0x00, 0x42, 0x00, 0x4f, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Level 1, union discriminant 1, container referent.
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00,
    // EntriesRead 0, Buffer null.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // PreferedMaximumLength, ResumeHandle referent, ResumeHandle 0.
    0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// NetrShareGetInfo (MS-SRVS 3.1.4.10) for share "devkit" at level 1005,
/// as Windows Explorer queries a share's caching flags: ServerName, NetName
/// as a reference conformant varying string, Level.
#[rustfmt::skip]
const SHARE_GET_INFO_1005: [u8; 88] = [
    // Request, frag_length 88, call_id 4.
    0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    // alloc_hint 64, p_cont_id 0, opnum 16.
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    // ServerName "\\XBOX".
    0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x5c, 0x00, 0x5c, 0x00, 0x58, 0x00, 0x42, 0x00, 0x4f, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00,
    // NetName: max_count 7, offset 0, actual_count 7, "devkit", padding.
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x64, 0x00, 0x65, 0x00, 0x76, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Level 1005.
    0xed, 0x03, 0x00, 0x00,
];

/// NetrShareGetInfo for "IPC$" at level 1, laid out as
/// [`SHARE_GET_INFO_1005`].
#[rustfmt::skip]
const SHARE_GET_INFO_1: [u8; 84] = [
    // Request, frag_length 84, call_id 5.
    0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    // alloc_hint 60, p_cont_id 0, opnum 16.
    0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x5c, 0x00, 0x5c, 0x00, 0x58, 0x00, 0x42, 0x00, 0x4f, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00,
    // NetName "IPC$" with terminator, padding.
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x49, 0x00, 0x50, 0x00, 0x43, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Level 1.
    0x01, 0x00, 0x00, 0x00,
];

/// NetrServerGetInfo (MS-SRVS 3.1.4.17) level 101 as `net view` sends it:
/// ServerName, Level.
#[rustfmt::skip]
const SERVER_GET_INFO_101: [u8; 60] = [
    // Request, frag_length 60, call_id 6.
    0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    // alloc_hint 36, p_cont_id 0, opnum 21.
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x5c, 0x00, 0x5c, 0x00, 0x58, 0x00, 0x42, 0x00, 0x4f, 0x00, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Level 101.
    0x65, 0x00, 0x00, 0x00,
];

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut text = String::new();
    for (index, line) in bytes.chunks(16).enumerate() {
        write!(text, "{:04x}:", index * 16).unwrap();
        for byte in line {
            write!(text, " {byte:02x}").unwrap();
        }
        text.push('\n');
    }
    text
}

/// One read of the pending reply with `backend`.
fn read_with(
    pipe: &mut Pipe,
    output: &mut [u8],
    mut backend: TestBackend,
) -> Result<PipeRead, PipeError> {
    let mut context = PipeContext {
        backend: &mut backend,
        user: UserKind::Authenticated,
    };
    pipe.read(output, &mut context)
}

/// Write `request` and read every reply fragment with `chunk`-byte reads.
fn exchange(pipe: &mut Pipe, request: &[u8], chunk: usize) -> Vec<Vec<u8>> {
    pipe.write(request).unwrap();
    let mut fragments = Vec::new();
    let mut fragment = Vec::new();
    let mut output = std::vec![0; chunk];
    loop {
        match read_with(pipe, &mut output, SHARES) {
            Ok(PipeRead::Partial { length }) => {
                assert_eq!(length, chunk);
                fragment.extend_from_slice(&output[..length]);
            }
            Ok(PipeRead::Complete { length }) => {
                fragment.extend_from_slice(&output[..length]);
                fragments.push(core::mem::take(&mut fragment));
            }
            Err(error) => {
                assert_eq!(error, PipeError::Empty);
                assert!(fragment.is_empty());
                return fragments;
            }
        }
    }
}

/// The single reply PDU to `request`.
fn reply(pipe: &mut Pipe, request: &[u8]) -> Vec<u8> {
    let mut fragments = exchange(pipe, request, 8192);
    assert_eq!(fragments.len(), 1);
    fragments.remove(0)
}

fn bound_pipe() -> Pipe {
    let mut pipe = Pipe::new();
    reply(&mut pipe, &BIND);
    pipe
}

#[test]
fn bind_ack() {
    let mut pipe = Pipe::new();
    insta::assert_snapshot!(hex(&reply(&mut pipe, &BIND)));
}

#[test]
fn bind_with_auth_is_rejected() {
    let mut pipe = Pipe::new();
    insta::assert_snapshot!(hex(&reply(&mut pipe, &BIND_WITH_AUTH)));
}

#[test]
fn share_enum_level_1() {
    let mut pipe = bound_pipe();
    insta::assert_snapshot!(hex(&reply(&mut pipe, &SHARE_ENUM)));
}

#[test]
fn share_get_info_1005() {
    let mut pipe = bound_pipe();
    insta::assert_snapshot!(hex(&reply(&mut pipe, &SHARE_GET_INFO_1005)));
}

#[test]
fn share_get_info_1() {
    let mut pipe = bound_pipe();
    insta::assert_snapshot!(hex(&reply(&mut pipe, &SHARE_GET_INFO_1)));
}

#[test]
fn share_get_info_unknown_share() {
    let mut request = SHARE_GET_INFO_1005;
    // "devkit" becomes "devkiz".
    request[78] = b'z';
    let mut pipe = bound_pipe();
    let response = reply(&mut pipe, &request);
    // Discriminant 1005, null pointer, NERR_NetNameNotFound.
    assert_eq!(
        response[24..],
        [0xed, 0x03, 0, 0, 0, 0, 0, 0, 0x06, 0x09, 0, 0]
    );
}

#[test]
fn server_get_info_101() {
    let mut pipe = bound_pipe();
    insta::assert_snapshot!(hex(&reply(&mut pipe, &SERVER_GET_INFO_101)));
}

#[test]
fn unknown_opnum_faults() {
    let mut request = SERVER_GET_INFO_101;
    // Opnum 58, one past the last MS-SRVS operation.
    request[22] = 58;
    let mut pipe = bound_pipe();
    insta::assert_snapshot!(hex(&reply(&mut pipe, &request)));
}

#[test]
fn small_reads_match_one_read() {
    let mut pipe = bound_pipe();
    let whole = exchange(&mut pipe, &SHARE_ENUM, 8192);
    let pieces = exchange(&mut pipe, &SHARE_ENUM, 7);
    assert_eq!(pieces, whole);
}

/// FSCTL_PIPE_TRANSCEIVE as Windows issues it: the write, then a read
/// limited to the ioctl's maximum output, then reads for the rest.
#[test]
fn transceive_then_reads_match_one_read() {
    let mut pipe = bound_pipe();
    let whole = reply(&mut pipe, &SHARE_ENUM);

    pipe.write(&SHARE_ENUM).unwrap();
    assert_eq!(
        read_with(&mut pipe, &mut [], SHARES),
        Err(PipeError::OutputEmpty)
    );
    let mut joined = std::vec![0; 64];
    assert_eq!(
        read_with(&mut pipe, &mut joined, SHARES),
        Ok(PipeRead::Partial { length: 64 })
    );
    let mut output = [0; 1024];
    let Ok(PipeRead::Complete { length }) = read_with(&mut pipe, &mut output, SHARES) else {
        panic!("reply not completed");
    };
    joined.extend_from_slice(&output[..length]);
    assert_eq!(joined, whole);
    assert_eq!(
        read_with(&mut pipe, &mut output, SHARES),
        Err(PipeError::Empty)
    );
}

/// A share list that changes while a reply is read fails the read with
/// PipeError::ReplyChanged, discards the reply, and leaves the pipe bound.
#[test]
fn share_list_change_breaks_reply() {
    const ONE_SHARE: TestBackend = TestBackend {
        shares: &["Devkit"],
    };
    const RENAMED: TestBackend = TestBackend {
        shares: &["Devkit", "Usb"],
    };
    let mut small_frag_bind = BIND;
    small_frag_bind[18..20].copy_from_slice(&64u16.to_le_bytes());
    // Bind, first read size and its result, backend for the second read.
    let cases = [
        (&BIND, 7, PipeRead::Partial { length: 7 }, ONE_SHARE),
        (
            &small_frag_bind,
            1024,
            PipeRead::Complete { length: 64 },
            ONE_SHARE,
        ),
        (&BIND, 7, PipeRead::Partial { length: 7 }, RENAMED),
    ];
    for (bind, first, first_result, changed) in cases {
        let mut pipe = Pipe::new();
        reply(&mut pipe, bind);
        pipe.write(&SHARE_ENUM).unwrap();
        let mut output = [0; 1024];
        assert_eq!(
            read_with(&mut pipe, &mut output[..first], SHARES),
            Ok(first_result)
        );
        assert_eq!(
            read_with(&mut pipe, &mut output, changed),
            Err(PipeError::ReplyChanged)
        );
        assert_eq!(
            read_with(&mut pipe, &mut output, SHARES),
            Err(PipeError::Empty)
        );
        let fragments = exchange(&mut pipe, &SHARE_ENUM, 8192);
        // Response PDUs, not faults.
        assert!(fragments.iter().all(|fragment| fragment[2] == 2));
    }
}

#[test]
fn response_fragments_at_max_recv_frag() {
    const MAX_RECV_FRAG: usize = 64;
    let mut whole_pipe = bound_pipe();
    let whole = reply(&mut whole_pipe, &SHARE_ENUM);
    let stub = &whole[24..];

    let mut bind = BIND;
    bind[18..20].copy_from_slice(&(MAX_RECV_FRAG as u16).to_le_bytes());
    let mut pipe = Pipe::new();
    let ack = reply(&mut pipe, &bind);
    assert_eq!(ack[16..18], (MAX_RECV_FRAG as u16).to_le_bytes());

    let fragments = exchange(&mut pipe, &SHARE_ENUM, 8192);
    assert!(fragments.len() > 1);
    let mut joined = Vec::new();
    for (index, fragment) in fragments.iter().enumerate() {
        assert!(fragment.len() <= MAX_RECV_FRAG);
        // Header identical to the unfragmented one except flags, length,
        // and allocation hint.
        assert_eq!(fragment[..3], whole[..3]);
        let first = index == 0;
        let last = index == fragments.len() - 1;
        assert_eq!(fragment[3], u8::from(first) | u8::from(last) << 1);
        assert_eq!(fragment[4..8], whole[4..8]);
        assert_eq!(
            usize::from(u16::from_le_bytes([fragment[8], fragment[9]])),
            fragment.len()
        );
        assert_eq!(fragment[10..16], whole[10..16]);
        let hint = u32::from_le_bytes([fragment[16], fragment[17], fragment[18], fragment[19]]);
        assert_eq!(hint as usize, stub.len() - joined.len());
        assert_eq!(fragment[20..24], whole[20..24]);
        if !last {
            assert_eq!((fragment.len() - 24) % 8, 0);
        }
        joined.extend_from_slice(&fragment[24..]);
    }
    assert_eq!(joined, stub);
}

/// A request split into two fragments (C706 12.6.3.4 fragmentation) and
/// written one byte at a time.
#[test]
fn fragmented_request() {
    let mut whole_pipe = bound_pipe();
    let whole = reply(&mut whole_pipe, &SHARE_GET_INFO_1005);

    let stub = &SHARE_GET_INFO_1005[24..];
    let (head, tail) = stub.split_at(32);
    let mut stream = Vec::new();
    for (part, flags, hint) in [(head, 0x01, stub.len()), (tail, 0x02, tail.len())] {
        let mut header = SHARE_GET_INFO_1005[..24].to_vec();
        header[3] = flags;
        header[8..10].copy_from_slice(&((24 + part.len()) as u16).to_le_bytes());
        header[16..20].copy_from_slice(&(hint as u32).to_le_bytes());
        stream.extend_from_slice(&header);
        stream.extend_from_slice(part);
    }
    let mut pipe = bound_pipe();
    let (last, rest) = stream.split_last().unwrap();
    for byte in rest {
        pipe.write(core::slice::from_ref(byte)).unwrap();
    }
    assert_eq!(reply(&mut pipe, core::slice::from_ref(last)), whole);
}

#[test]
fn request_without_bind_faults() {
    let mut pipe = Pipe::new();
    let response = reply(&mut pipe, &SHARE_ENUM);
    // Fault PDU with nca_s_unk_if.
    assert_eq!(response[2], 3);
    assert_eq!(response[24..28], 0x1c01_0003u32.to_le_bytes());
}

#[test]
fn read_without_reply_is_empty() {
    let mut pipe = bound_pipe();
    assert_eq!(
        read_with(&mut pipe, &mut [0; 16], SHARES),
        Err(PipeError::Empty)
    );
}

#[test]
fn write_before_reply_is_read() {
    let mut pipe = bound_pipe();
    pipe.write(&SHARE_ENUM).unwrap();
    assert_eq!(pipe.write(&SHARE_ENUM), Err(PipeError::Busy));
}

/// Each malformed header fails the write with its cause, and the pipe
/// accepts a valid PDU afterwards.
#[test]
fn malformed_pdus() {
    let edit = |index: usize, value: u8| {
        let mut request = SHARE_ENUM;
        request[index] = value;
        request
    };
    let mut continuation = SHARE_ENUM;
    continuation[3] = 0x02;
    let cases = [
        (
            edit(0, 4),
            PduError::UnsupportedVersion {
                version: RpcVersion { major: 4, minor: 0 },
            },
        ),
        (
            edit(4, 0x00),
            PduError::UnsupportedDataRepresentation {
                format: DataFormat(0x00),
            },
        ),
        // A bind_ack, which only a server sends.
        (
            edit(2, 12),
            PduError::UnexpectedType {
                packet_type: PacketType(12),
            },
        ),
        (
            edit(8, 20),
            PduError::FragmentTooShort {
                packet_type: PacketType(0),
                length: 20,
                minimum: 24,
            },
        ),
        (
            continuation,
            PduError::UnexpectedContinuation { call_id: CallId(3) },
        ),
    ];
    for (request, expected) in cases {
        let mut pipe = bound_pipe();
        assert_eq!(pipe.write(&request), Err(PipeError::MalformedPdu(expected)));
        let fragments = exchange(&mut pipe, &SHARE_ENUM, 8192);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0][2], 2);
    }
}

#[test]
fn pipe_names() {
    let name = |text: &str| {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        pipe_supported(Utf16Le::new(&bytes).unwrap())
    };
    assert!(name("srvsvc"));
    assert!(name("SRVSVC"));
    assert!(!name("\\srvsvc"));
    assert!(!name("lsarpc"));
}
