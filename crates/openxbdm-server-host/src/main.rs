use std::fmt;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process::ExitCode;
use std::thread;

use openxbdm_server::Address;
use openxbdm_server::BackendError;
use openxbdm_server::ConsoleBackend;
use openxbdm_server::FileSystemBackend;
use openxbdm_server::MemoryBackend;
use openxbdm_server::ProcessBackend;
use openxbdm_server::ProcessId;
use openxbdm_server::ReadableMask;
use openxbdm_server::ResponseSink;
use openxbdm_server::Service;
use openxbdm_server::SessionControl;
use openxbdm_server::TransferCount;

const DEFAULT_LISTEN: &str = "127.0.0.1:1730";
const MOCK_MEMORY_BASE: u32 = 0x8000_0000;
const MOCK_MEMORY_SIZE: usize = 1024 * 1024;
const FEATURES: &[&str] = &["DEBUGGING", "1GB_RAM"];
const DRIVES: &[&str] = &["DEVKIT", "FLASH"];
const MAX_COMMAND_LENGTH: usize = 16 * 1024;

#[derive(Debug)]
enum ServerError {
    InvalidArgument { argument: String },
    InvalidListenAddress { value: String, source: std::net::AddrParseError },
    Bind { address: SocketAddr, source: io::Error },
    LocalAddress(io::Error),
    Accept(io::Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument { argument } => write!(formatter, "invalid argument: {argument}"),
            Self::InvalidListenAddress { value, source } => {
                write!(formatter, "invalid listen address {value:?}: {source}")
            }
            Self::Bind { address, source } => {
                write!(formatter, "cannot bind {address}: {source}")
            }
            Self::LocalAddress(source) => write!(formatter, "cannot read listen address: {source}"),
            Self::Accept(source) => write!(formatter, "cannot accept connection: {source}"),
        }
    }
}

impl std::error::Error for ServerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidListenAddress { source, .. } => Some(source),
            Self::Bind { source, .. } => Some(source),
            Self::LocalAddress(source) | Self::Accept(source) => Some(source),
            Self::InvalidArgument { .. } => None,
        }
    }
}

#[derive(Debug)]
enum ConnectionError {
    Clone(io::Error),
    Read(io::Error),
    Write(io::Error),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clone(source) => write!(formatter, "cannot clone client socket: {source}"),
            Self::Read(source) => write!(formatter, "cannot read client command: {source}"),
            Self::Write(source) => write!(formatter, "cannot write client response: {source}"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clone(source) | Self::Read(source) | Self::Write(source) => Some(source),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandRead {
    Eof,
    Line,
    TooLong,
}

#[derive(Debug)]
struct MockBackend {
    debug_name: String,
    memory: Vec<u8>,
}

impl Default for MockBackend {
    fn default() -> Self {
        let mut memory = vec![0; MOCK_MEMORY_SIZE];
        for (index, byte) in memory.iter_mut().enumerate() {
            *byte = index as u8;
        }
        Self { debug_name: "openxbdm-mock".to_owned(), memory }
    }
}

impl ConsoleBackend for MockBackend {
    fn debug_name(&self) -> &str {
        &self.debug_name
    }

    fn set_debug_name(&mut self, name: &str) -> Result<(), BackendError> {
        if name.is_empty() || name.len() > 255 {
            return Err(BackendError::InvalidArgument);
        }
        self.debug_name.clear();
        self.debug_name.push_str(name);
        Ok(())
    }

    fn dm_version(&self) -> &str {
        "2.0.21256.0"
    }

    fn console_type(&self) -> &str {
        "DevKit"
    }

    fn console_features(&self) -> &[&str] {
        FEATURES
    }
}

impl FileSystemBackend for MockBackend {
    fn drives(&self) -> &[&str] {
        DRIVES
    }

    fn delete_file(&mut self, _path: &str) -> Result<(), BackendError> {
        Err(BackendError::Unavailable)
    }
}

impl MemoryBackend for MockBackend {
    fn read_memory(&self, address: Address, output: &mut [u8]) -> Result<ReadableMask, BackendError> {
        let mut bits = 0u64;
        for (index, byte) in output.iter_mut().enumerate() {
            let current = address.get() as u64 + index as u64;
            let Some(source) =
                current.checked_sub(MOCK_MEMORY_BASE as u64).and_then(|offset| self.memory.get(offset as usize))
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
        let range = memory_window(address, data.len(), self.memory.len())?;
        let count = range.len();
        self.memory[range].copy_from_slice(&data[..count]);
        Ok(TransferCount::new(count))
    }
}

impl ProcessBackend for MockBackend {
    fn process_id(&self) -> ProcessId {
        ProcessId::new(2)
    }
}

fn memory_window(
    address: Address,
    requested: usize,
    memory_len: usize,
) -> Result<std::ops::Range<usize>, BackendError> {
    let start = address.get().checked_sub(MOCK_MEMORY_BASE).ok_or(BackendError::MemoryNotMapped)? as usize;
    let available = memory_len.checked_sub(start).ok_or(BackendError::MemoryNotMapped)?;
    let count = core::cmp::min(requested, available);
    if count == 0 {
        return Err(BackendError::MemoryNotMapped);
    }
    Ok(start..start + count)
}

struct SocketSink<'a> {
    writer: BufWriter<&'a mut TcpStream>,
}

impl<'a> SocketSink<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self { writer: BufWriter::new(stream) }
    }

    fn write_status(&mut self, code: u16, message: &str) -> io::Result<()> {
        write!(self.writer, "{code:03}- {message}\r\n")?;
        self.writer.flush()
    }
}

impl ResponseSink for SocketSink<'_> {
    type Error = io::Error;

    fn single(&mut self, code: u16, message: &str) -> Result<(), Self::Error> {
        self.write_status(code, message)
    }

    fn multiline_start(&mut self, message: &str) -> Result<(), Self::Error> {
        self.write_status(202, message)
    }

    fn multiline_line(&mut self, line: &str) -> Result<(), Self::Error> {
        write!(self.writer, "{line}\r\n")?;
        self.writer.flush()
    }

    fn multiline_end(&mut self) -> Result<(), Self::Error> {
        self.multiline_line(".")
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openxbdm-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), ServerError> {
    let address = parse_args()?;
    let listener = TcpListener::bind(address).map_err(|source| ServerError::Bind { address, source })?;
    let local_address = listener.local_addr().map_err(ServerError::LocalAddress)?;
    println!("listening on {local_address}");

    loop {
        let (stream, peer) = listener.accept().map_err(ServerError::Accept)?;
        thread::spawn(move || {
            if let Err(error) = serve_connection(stream) {
                eprintln!("client {peer}: {error}");
            }
        });
    }
}

fn parse_args() -> Result<SocketAddr, ServerError> {
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => {
                listen = arguments.next().ok_or_else(|| ServerError::InvalidArgument {
                    argument: "--listen requires an address".to_owned(),
                })?;
            }
            "-h" | "--help" => {
                println!("usage: openxbdm-server [--listen HOST:PORT]");
                std::process::exit(0);
            }
            _ => return Err(ServerError::InvalidArgument { argument }),
        }
    }
    listen.parse().map_err(|source| ServerError::InvalidListenAddress { value: listen, source })
}

fn serve_connection(mut stream: TcpStream) -> Result<(), ConnectionError> {
    let reader_stream = stream.try_clone().map_err(ConnectionError::Clone)?;
    let mut reader = BufReader::new(reader_stream);
    let mut sink = SocketSink::new(&mut stream);
    sink.single(201, "connected").map_err(ConnectionError::Write)?;

    let mut service = Service::new(MockBackend::default());
    let mut line = String::new();
    loop {
        match read_command(&mut reader, &mut line).map_err(ConnectionError::Read)? {
            CommandRead::Eof => return Ok(()),
            CommandRead::TooLong => {
                sink.single(400, "command exceeds protocol limit").map_err(ConnectionError::Write)?;
                continue;
            }
            CommandRead::Line => {}
        }
        let control = service.dispatch(&line, &mut sink).map_err(|error| match error {
            openxbdm_server::DispatchError::Response(source) => ConnectionError::Write(source),
        })?;
        if control == SessionControl::Disconnect {
            return Ok(());
        }
    }
}

fn read_command<R: BufRead>(reader: &mut R, line: &mut String) -> io::Result<CommandRead> {
    line.clear();
    let count = reader.by_ref().take((MAX_COMMAND_LENGTH + 1) as u64).read_line(line)?;
    if count == 0 {
        return Ok(CommandRead::Eof);
    }
    if count <= MAX_COMMAND_LENGTH
        && (line.ends_with('\n') || count < MAX_COMMAND_LENGTH || reader.fill_buf()?.is_empty())
    {
        return Ok(CommandRead::Line);
    }

    if !line.ends_with('\n') {
        loop {
            let buffered = reader.fill_buf()?;
            if buffered.is_empty() {
                break;
            }
            let newline = buffered.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(buffered.len(), |position| position + 1);
            reader.consume(consumed);
            if newline.is_some() {
                break;
            }
        }
    }
    line.clear();
    Ok(CommandRead::TooLong)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_window_returns_mapped_prefix() {
        let address = Address::new(MOCK_MEMORY_BASE + MOCK_MEMORY_SIZE as u32 - 1);
        assert_eq!(memory_window(address, 2, MOCK_MEMORY_SIZE), Ok(MOCK_MEMORY_SIZE - 1..MOCK_MEMORY_SIZE));
    }

    #[test]
    fn command_reader_discards_oversized_line() {
        let mut input = vec![b'x'; MAX_COMMAND_LENGTH];
        input.extend_from_slice(b"\nbye\r\n");
        let mut reader = io::Cursor::new(input);
        let mut line = String::new();

        assert_eq!(read_command(&mut reader, &mut line).unwrap(), CommandRead::TooLong);
        assert_eq!(read_command(&mut reader, &mut line).unwrap(), CommandRead::Line);
        assert_eq!(line, "bye\r\n");
    }

    #[test]
    fn openxbdm_client_exercises_stateful_mock_over_tcp() {
        use openxbdm_client::Client;
        use openxbdm_client::commands::DbgName;
        use openxbdm_client::commands::DmVersion;
        use openxbdm_client::commands::DriveList;
        use openxbdm_client::commands::GetMem;
        use openxbdm_client::commands::GetPid;
        use openxbdm_client::commands::SetMem;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(stream).unwrap();
        });

        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let transport = openxbdm_client::transport::tokio::connect(address).await.unwrap();
            let mut client = Client::new(transport).read_banner().await.unwrap();

            assert_eq!(client.run(DmVersion).await.unwrap(), "2.0.21256.0");
            assert_eq!(client.run(DriveList).await.unwrap(), vec!["DEVKIT".to_owned(), "FLASH".to_owned()]);
            assert_eq!(client.run(GetPid).await.unwrap(), 2);

            assert_eq!(client.run(DbgName::Set("Development Kit".to_owned())).await.unwrap(), "name set");
            assert_eq!(client.run(DbgName::Get).await.unwrap(), "Development Kit");

            let written =
                client.run(SetMem { address: MOCK_MEMORY_BASE + 2, data: vec![0xAA, 0xBB, 0xCC] }).await.unwrap();
            assert_eq!(written.requested, 3);
            assert_eq!(written.written, 3);
            let snapshot = client.run(GetMem { address: MOCK_MEMORY_BASE, length: 8 }).await.unwrap();
            assert_eq!(snapshot.data, [0, 1, 0xAA, 0xBB, 0xCC, 5, 6, 7]);
            assert!(snapshot.unmapped_offsets.is_empty());
            client.run(SetMem { address: MOCK_MEMORY_BASE, data: vec![0xAB] }).await.unwrap();

            let written = client
                .run(SetMem { address: MOCK_MEMORY_BASE + MOCK_MEMORY_SIZE as u32 - 1, data: vec![0xFE, 0xFD] })
                .await
                .unwrap();
            assert_eq!(written.requested, 2);
            assert_eq!(written.written, 1);
            let snapshot = client.run(GetMem { address: MOCK_MEMORY_BASE - 1, length: 2 }).await.unwrap();
            assert_eq!(snapshot.data, [0, 0xAB]);
            assert_eq!(snapshot.unmapped_offsets, [0]);

            client.bye().await.unwrap();
        });
        server.join().unwrap();
    }
}
