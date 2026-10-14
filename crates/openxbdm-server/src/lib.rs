#![no_std]

use core::fmt;
use core::fmt::Write as _;

const RESPONSE_CAPACITY: usize = 512;
const MEMORY_CHUNK_SIZE: usize = 64;
const MAX_MEMORY_TRANSFER: u32 = 0x1_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address(u32);

impl Address {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLength(u32);

impl MemoryLength {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferCount(usize);

impl TransferCount {
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    pub const fn get(self) -> usize {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadableMask(u64);

impl ReadableMask {
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn is_readable(self, index: usize) -> bool {
        index < u64::BITS as usize && self.0 & (1u64 << index) != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessId(u32);

impl ProcessId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    MemoryNotMapped,
    NotFound,
    AccessDenied,
    InvalidArgument,
    Unavailable,
}

pub trait ConsoleBackend {
    fn debug_name(&self) -> &str;
    fn set_debug_name(&mut self, name: &str) -> Result<(), BackendError>;
    fn dm_version(&self) -> &str;
    fn console_type(&self) -> &str;
    fn console_features(&self) -> &[&str];
}

pub trait FileSystemBackend {
    fn drives(&self) -> &[&str];
    fn delete_file(&mut self, path: &str) -> Result<(), BackendError>;
}

pub trait MemoryBackend {
    fn read_memory(&self, address: Address, output: &mut [u8]) -> Result<ReadableMask, BackendError>;
    fn write_memory(&mut self, address: Address, data: &[u8]) -> Result<TransferCount, BackendError>;
}

pub trait ProcessBackend {
    fn process_id(&self) -> ProcessId;
}

pub trait Backend: ConsoleBackend + FileSystemBackend + MemoryBackend + ProcessBackend {}

impl<T> Backend for T where T: ConsoleBackend + FileSystemBackend + MemoryBackend + ProcessBackend {}

pub trait ResponseSink {
    type Error;

    fn single(&mut self, code: u16, message: &str) -> Result<(), Self::Error>;
    fn multiline_start(&mut self, message: &str) -> Result<(), Self::Error>;
    fn multiline_line(&mut self, line: &str) -> Result<(), Self::Error>;
    fn multiline_end(&mut self) -> Result<(), Self::Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionControl {
    Continue,
    Disconnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchError<E> {
    Response(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Request<'a> {
    Bye,
    DebugName { name: Option<&'a str> },
    DmVersion,
    ConsoleType,
    ConsoleFeatures,
    DriveList,
    Delete { path: &'a str },
    GetPid,
    GetMem { address: Address, length: MemoryLength },
    SetMem { address: Address, data: &'a str },
    Unknown,
}

pub struct Service<B> {
    backend: B,
}

impl<B> Service<B> {
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn into_backend(self) -> B {
        self.backend
    }
}

impl<B: Backend> Service<B> {
    pub fn dispatch<S: ResponseSink>(
        &mut self,
        line: &str,
        sink: &mut S,
    ) -> Result<SessionControl, DispatchError<S::Error>> {
        let request = match parse_request(line) {
            Ok(request) => request,
            Err(()) => {
                sink.single(400, "invalid command syntax").map_err(DispatchError::Response)?;
                return Ok(SessionControl::Continue);
            }
        };

        match request {
            Request::Bye => {
                sink.single(205, "connection closing").map_err(DispatchError::Response)?;
                Ok(SessionControl::Disconnect)
            }
            Request::DebugName { name: None } => {
                sink.single(200, self.backend.debug_name()).map_err(DispatchError::Response)?;
                Ok(SessionControl::Continue)
            }
            Request::DebugName { name: Some(name) } => {
                let result = self.backend.set_debug_name(name);
                emit_backend_result(result, sink, "name set")?;
                Ok(SessionControl::Continue)
            }
            Request::DmVersion => {
                sink.single(200, self.backend.dm_version()).map_err(DispatchError::Response)?;
                Ok(SessionControl::Continue)
            }
            Request::ConsoleType => {
                sink.single(200, self.backend.console_type()).map_err(DispatchError::Response)?;
                Ok(SessionControl::Continue)
            }
            Request::ConsoleFeatures => {
                let mut response = StackString::<RESPONSE_CAPACITY>::new();
                for (index, feature) in self.backend.console_features().iter().enumerate() {
                    let result = if index == 0 { response.write_str(feature) } else { write!(response, " {feature}") };
                    if result.is_err() {
                        sink.single(400, "response exceeds protocol limit").map_err(DispatchError::Response)?;
                        return Ok(SessionControl::Continue);
                    }
                }
                sink.single(200, response.as_str()).map_err(DispatchError::Response)?;
                Ok(SessionControl::Continue)
            }
            Request::DriveList => {
                sink.multiline_start("multiline response follows").map_err(DispatchError::Response)?;
                for drive in self.backend.drives() {
                    let mut response = StackString::<RESPONSE_CAPACITY>::new();
                    write!(response, "drivename=\"{drive}\"").expect("backend drive name fits fixed response buffer");
                    sink.multiline_line(response.as_str()).map_err(DispatchError::Response)?;
                }
                sink.multiline_end().map_err(DispatchError::Response)?;
                Ok(SessionControl::Continue)
            }
            Request::Delete { path } => {
                let result = self.backend.delete_file(path);
                emit_backend_result(result, sink, "file deleted")?;
                Ok(SessionControl::Continue)
            }
            Request::GetPid => {
                let mut response = StackString::<32>::new();
                write!(response, "pid=0x{:08x}", self.backend.process_id().get())
                    .expect("PID response fits fixed buffer");
                sink.single(200, response.as_str()).map_err(DispatchError::Response)?;
                Ok(SessionControl::Continue)
            }
            Request::GetMem { address, length } => {
                self.dispatch_get_memory(address, length, sink)?;
                Ok(SessionControl::Continue)
            }
            Request::SetMem { address, data } => {
                self.dispatch_set_memory(address, data, sink)?;
                Ok(SessionControl::Continue)
            }
            Request::Unknown => {
                sink.single(407, "unknown command").map_err(DispatchError::Response)?;
                Ok(SessionControl::Continue)
            }
        }
    }

    fn dispatch_get_memory<S: ResponseSink>(
        &self,
        address: Address,
        length: MemoryLength,
        sink: &mut S,
    ) -> Result<(), DispatchError<S::Error>> {
        let length = length.get();
        if length == 0 || length > MAX_MEMORY_TRANSFER || address.get().checked_add(length - 1).is_none() {
            sink.single(400, "invalid memory range").map_err(DispatchError::Response)?;
            return Ok(());
        }
        sink.multiline_start("multiline response follows").map_err(DispatchError::Response)?;

        let length = length as usize;
        let mut offset = 0usize;
        let mut bytes = [0u8; MEMORY_CHUNK_SIZE];
        while offset < length {
            let count = core::cmp::min(MEMORY_CHUNK_SIZE, length - offset);
            let chunk_address =
                Address::new(address.get().checked_add(offset as u32).expect("memory range was validated"));
            let readable = self
                .backend
                .read_memory(chunk_address, &mut bytes[..count])
                .unwrap_or_else(|_| ReadableMask::from_bits(0));
            let mut line = StackString::<{ MEMORY_CHUNK_SIZE * 2 }>::new();
            for (index, byte) in bytes[..count].iter().enumerate() {
                if readable.is_readable(index) {
                    write!(line, "{byte:02X}").expect("hex memory line fits fixed buffer");
                } else {
                    line.write_str("??").expect("unreadable memory line fits fixed buffer");
                }
            }
            sink.multiline_line(line.as_str()).map_err(DispatchError::Response)?;
            offset += count;
        }

        sink.multiline_end().map_err(DispatchError::Response)
    }

    fn dispatch_set_memory<S: ResponseSink>(
        &mut self,
        address: Address,
        data: &str,
        sink: &mut S,
    ) -> Result<(), DispatchError<S::Error>> {
        if !data.len().is_multiple_of(2) {
            sink.single(400, "hex data has odd length").map_err(DispatchError::Response)?;
            return Ok(());
        }

        let decoded_length = data.len() / 2;
        let Some(decoded_length_u32) = u32::try_from(decoded_length).ok() else {
            sink.single(400, "invalid memory range").map_err(DispatchError::Response)?;
            return Ok(());
        };
        if decoded_length_u32 == 0
            || decoded_length_u32 > MAX_MEMORY_TRANSFER
            || address.get().checked_add(decoded_length_u32 - 1).is_none()
        {
            sink.single(400, "invalid memory range").map_err(DispatchError::Response)?;
            return Ok(());
        }
        if data.as_bytes().iter().any(|byte| hex_digit(*byte).is_none()) {
            sink.single(400, "invalid hex data").map_err(DispatchError::Response)?;
            return Ok(());
        }

        let mut bytes = [0u8; MEMORY_CHUNK_SIZE];
        let mut written = 0usize;
        for chunk in data.as_bytes().chunks(MEMORY_CHUNK_SIZE * 2) {
            let count = chunk.len() / 2;
            for index in 0..count {
                let high = hex_digit(chunk[index * 2]).expect("hex data was validated");
                let low = hex_digit(chunk[index * 2 + 1]).expect("hex data was validated");
                bytes[index] = high << 4 | low;
            }

            let chunk_address =
                Address::new(address.get().checked_add(written as u32).expect("memory range was validated"));
            match self.backend.write_memory(chunk_address, &bytes[..count]) {
                Ok(chunk_written) => {
                    let chunk_written = core::cmp::min(chunk_written.get(), count);
                    written += chunk_written;
                    if chunk_written != count {
                        break;
                    }
                }
                Err(error) if written == 0 => {
                    let (code, message) = backend_error_response(error);
                    sink.single(code, message).map_err(DispatchError::Response)?;
                    return Ok(());
                }
                Err(_) => break,
            }
        }

        let mut response = StackString::<48>::new();
        write!(response, "set {written} bytes").expect("setmem response fits fixed buffer");
        sink.single(200, response.as_str()).map_err(DispatchError::Response)
    }
}

fn emit_backend_result<S: ResponseSink>(
    result: Result<(), BackendError>,
    sink: &mut S,
    success: &str,
) -> Result<(), DispatchError<S::Error>> {
    match result {
        Ok(()) => sink.single(200, success).map_err(DispatchError::Response),
        Err(error) => {
            let (code, message) = backend_error_response(error);
            sink.single(code, message).map_err(DispatchError::Response)
        }
    }
}

fn backend_error_response(error: BackendError) -> (u16, &'static str) {
    match error {
        BackendError::NotFound => (402, "file not found"),
        BackendError::MemoryNotMapped => (404, "memory not mapped"),
        BackendError::AccessDenied => (415, "access denied"),
        BackendError::InvalidArgument => (400, "invalid argument"),
        BackendError::Unavailable => (419, "data not available"),
    }
}

fn parse_request(line: &str) -> Result<Request<'_>, ()> {
    let line = line.trim_matches(['\r', '\n']);
    let mut fields = line.split_ascii_whitespace();
    let command = fields.next().ok_or(())?;

    if command.eq_ignore_ascii_case("bye") {
        return Ok(Request::Bye);
    }
    if command.eq_ignore_ascii_case("dbgname") {
        let arguments = line[command.len()..].trim_start();
        if arguments.is_empty() {
            return Ok(Request::DebugName { name: None });
        }
        let (key, value) = arguments.split_once('=').ok_or(())?;
        if !key.trim().eq_ignore_ascii_case("name") {
            return Err(());
        }
        return Ok(Request::DebugName { name: Some(value.trim_matches('"')) });
    }
    if command.eq_ignore_ascii_case("dmversion") {
        return Ok(Request::DmVersion);
    }
    if command.eq_ignore_ascii_case("consoletype") {
        return Ok(Request::ConsoleType);
    }
    if command.eq_ignore_ascii_case("consolefeatures") {
        return Ok(Request::ConsoleFeatures);
    }
    if command.eq_ignore_ascii_case("drivelist") {
        return Ok(Request::DriveList);
    }
    if command.eq_ignore_ascii_case("delete") {
        let path = find_argument(line.split_ascii_whitespace().skip(1), "name").ok_or(())?;
        if path.is_empty() {
            return Err(());
        }
        return Ok(Request::Delete { path });
    }
    if command.eq_ignore_ascii_case("getpid") {
        return Ok(Request::GetPid);
    }
    if command.eq_ignore_ascii_case("getmem") {
        let address = find_argument(line.split_ascii_whitespace().skip(1), "addr").and_then(parse_u32).ok_or(())?;
        let length = find_argument(line.split_ascii_whitespace().skip(1), "length").and_then(parse_u32).ok_or(())?;
        return Ok(Request::GetMem { address: Address::new(address), length: MemoryLength::new(length) });
    }
    if command.eq_ignore_ascii_case("setmem") {
        let address = find_argument(line.split_ascii_whitespace().skip(1), "addr").and_then(parse_u32).ok_or(())?;
        let data = find_argument(line.split_ascii_whitespace().skip(1), "data").ok_or(())?;
        return Ok(Request::SetMem { address: Address::new(address), data });
    }

    Ok(Request::Unknown)
}

fn find_argument<'a>(fields: impl Iterator<Item = &'a str>, name: &str) -> Option<&'a str> {
    fields
        .filter_map(|field| field.split_once('='))
        .find_map(|(key, value)| if key.eq_ignore_ascii_case(name) { Some(value.trim_matches('"')) } else { None })
}

fn parse_u32(value: &str) -> Option<u32> {
    let digits = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    u32::from_str_radix(digits, 16).ok()
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

struct StackString<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> StackString<N> {
    const fn new() -> Self {
        Self { bytes: [0; N], len: 0 }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("fmt::Write accepts UTF-8 strings")
    }
}

impl<const N: usize> fmt::Write for StackString<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        if end > N {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    struct TestBackend {
        name: String,
        memory: [u8; 8],
        deleted: bool,
    }

    impl ConsoleBackend for TestBackend {
        fn debug_name(&self) -> &str {
            &self.name
        }
        fn set_debug_name(&mut self, name: &str) -> Result<(), BackendError> {
            self.name.clear();
            self.name.push_str(name);
            Ok(())
        }
        fn dm_version(&self) -> &str {
            "2.0.21256.0"
        }
        fn console_type(&self) -> &str {
            "DevKit"
        }
        fn console_features(&self) -> &[&str] {
            &["DEBUGGING", "1GB_RAM"]
        }
    }

    impl FileSystemBackend for TestBackend {
        fn drives(&self) -> &[&str] {
            &["DEVKIT", "FLASH"]
        }

        fn delete_file(&mut self, path: &str) -> Result<(), BackendError> {
            if path.eq_ignore_ascii_case(r"DEVKIT:\FlashEx\xbdm.xex") {
                self.deleted = true;
                Ok(())
            } else {
                Err(BackendError::NotFound)
            }
        }
    }

    impl MemoryBackend for TestBackend {
        fn read_memory(&self, address: Address, output: &mut [u8]) -> Result<ReadableMask, BackendError> {
            let mut bits = 0u64;
            for (index, byte) in output.iter_mut().enumerate() {
                let current = address.get() as u64 + index as u64;
                let Some(source) = current.checked_sub(0x1000).and_then(|offset| self.memory.get(offset as usize))
                else {
                    continue;
                };
                *byte = *source;
                bits |= 1u64 << index;
            }
            if bits == 0 {
                return Err(BackendError::MemoryNotMapped);
            }
            Ok(ReadableMask::from_bits(bits))
        }

        fn write_memory(&mut self, address: Address, data: &[u8]) -> Result<TransferCount, BackendError> {
            let start = address.get().checked_sub(0x1000).ok_or(BackendError::MemoryNotMapped)? as usize;
            let available = self.memory.len().checked_sub(start).ok_or(BackendError::MemoryNotMapped)?;
            let count = core::cmp::min(data.len(), available);
            if count == 0 {
                return Err(BackendError::MemoryNotMapped);
            }
            self.memory[start..start + count].copy_from_slice(&data[..count]);
            Ok(TransferCount::new(count))
        }
    }

    impl ProcessBackend for TestBackend {
        fn process_id(&self) -> ProcessId {
            ProcessId::new(2)
        }
    }

    #[derive(Default)]
    struct Sink(Vec<(u16, String)>);

    impl ResponseSink for Sink {
        type Error = ();
        fn single(&mut self, code: u16, message: &str) -> Result<(), Self::Error> {
            self.0.push((code, message.into()));
            Ok(())
        }
        fn multiline_start(&mut self, message: &str) -> Result<(), Self::Error> {
            self.0.push((202, message.into()));
            Ok(())
        }
        fn multiline_line(&mut self, line: &str) -> Result<(), Self::Error> {
            self.0.push((0, line.into()));
            Ok(())
        }
        fn multiline_end(&mut self) -> Result<(), Self::Error> {
            self.0.push((0, ".".into()));
            Ok(())
        }
    }

    fn service() -> Service<TestBackend> {
        Service::new(TestBackend { name: "mockkit".into(), memory: [0, 1, 2, 3, 4, 5, 6, 7], deleted: false })
    }

    #[test]
    fn memory_round_trip_uses_xbdm_hex_format() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("setmem addr=0x1002 data=AABBCC", &mut sink).unwrap();
        assert_eq!(sink.0, vec![(200, "set 3 bytes".into())]);

        sink.0.clear();
        service.dispatch("getmem addr=0x1000 length=8", &mut sink).unwrap();
        assert_eq!(
            sink.0,
            vec![(202, "multiline response follows".into()), (0, "0001AABBCC050607".into()), (0, ".".into()),]
        );
    }

    #[test]
    fn invalid_setmem_does_not_write_valid_prefix() {
        let mut service = service();
        let mut sink = Sink::default();
        let mut data = "00".repeat(MEMORY_CHUNK_SIZE);
        data.push_str("GG");
        let command = std::format!("setmem addr=0x1000 data={data}");
        service.dispatch(&command, &mut sink).unwrap();
        assert_eq!(sink.0, vec![(400, "invalid hex data".into())]);
        assert_eq!(service.backend().memory, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn setmem_reports_short_write() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("setmem addr=0x1006 data=AABBCC", &mut sink).unwrap();
        assert_eq!(sink.0, vec![(200, "set 2 bytes".into())]);
        assert_eq!(service.backend().memory, [0, 1, 2, 3, 4, 5, 0xAA, 0xBB]);
    }

    #[test]
    fn getmem_preserves_readable_bytes_at_mapping_boundaries() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("getmem addr=0x1007 length=2", &mut sink).unwrap();
        assert_eq!(sink.0[1], (0, "07??".into()));

        sink.0.clear();
        service.dispatch("getmem addr=0x0fff length=2", &mut sink).unwrap();
        assert_eq!(sink.0[1], (0, "??00".into()));
    }

    #[test]
    fn getmem_rejects_unbounded_transfer() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("getmem addr=0x1000 length=0x10001", &mut sink).unwrap();
        assert_eq!(sink.0, vec![(400, "invalid memory range".into())]);
    }

    #[test]
    fn debug_name_setter_preserves_spaces() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("dbgname name=Development Kit", &mut sink).unwrap();
        assert_eq!(service.backend().debug_name(), "Development Kit");
    }

    #[test]
    fn drive_list_uses_named_records() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("drivelist", &mut sink).unwrap();
        assert_eq!(
            sink.0,
            vec![
                (202, "multiline response follows".into()),
                (0, "drivename=\"DEVKIT\"".into()),
                (0, "drivename=\"FLASH\"".into()),
                (0, ".".into()),
            ]
        );
    }

    #[test]
    fn delete_dispatches_to_filesystem_backend() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch(r#"delete NAME="DEVKIT:\FlashEx\xbdm.xex""#, &mut sink).unwrap();
        assert_eq!(sink.0, vec![(200, "file deleted".into())]);
        assert!(service.backend().deleted);
    }

    #[test]
    fn unmapped_memory_is_reported_per_byte() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("getmem addr=0x2000 length=3", &mut sink).unwrap();
        assert_eq!(sink.0[1], (0, "??????".into()));
    }

    #[test]
    fn unknown_command_uses_observed_status_code() {
        let mut service = service();
        let mut sink = Sink::default();
        service.dispatch("not-a-command", &mut sink).unwrap();
        assert_eq!(sink.0, vec![(407, "unknown command".into())]);
    }
}
