//! Network inspection and simulation commands.

pub mod ipproxy;
pub mod netcap;
pub mod netsim;
pub mod xhttpproxy;

use core::fmt::Write as _;
use core::num::NonZeroI32;

use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::Win32Error;

use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::system;
use crate::commands::system::SettingsFile;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::ConnectionIndex;
use crate::invocation::Invocation;
use crate::network::Ipv4Address;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;

pub(crate) use netsim::ini_netsim;
pub(crate) use xhttpproxy::ini_xhttpproxy;
pub(crate) use xhttpproxy::settings_lines as xhttpproxy_settings_lines;

/// First system version with the key, QoS lookup, and security association
/// tables.
const XN_TABLES_VERSION: SystemVersion = SystemVersion(0x200a_9a00);
/// Visible characters of one table line: the line buffer is 0x100 bytes and
/// its last byte is always the terminator.
const TABLE_LINE_LIMIT: usize = 0xff;

const fn entry(
    name: &'static str,
    any_of: Access,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry::new(name, any_of, Access::NONE, DispatchFlags::NONE, handler)
}

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry("getsockinfo", Access::READ, socket_info),
    entry("getxnkeyinfo", Access::READ, key_info),
    entry("getxnqoslookupinfo", Access::READ, qos_lookup_info),
    entry("getxnsecassocinfo", Access::READ, security_association_info),
    entry("ipproxy", Access::CONTROL, ipproxy::ipproxy),
    entry("linkstate", Access::CONTROL, link_state),
    entry("netcap", Access::CONTROL, netcap::netcap),
    entry("netsim", Access::CONTROL, netsim::netsim),
    entry("nicstats", Access::READ, nic_stats),
    entry("xhttpproxy", Access::CONTROL, xhttpproxy::xhttpproxy),
];

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    pub netcap: netcap::State,
    pub netsim: netsim::State,
    pub ipproxy: ipproxy::State,
}

impl State {
    pub const fn new() -> Self {
        Self {
            netcap: netcap::State::new(),
            netsim: netsim::State::new(),
            ipproxy: ipproxy::State::new(),
        }
    }
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// Lines of a table snapshot held by the backend for this connection.
    Table { table: Table, next: u32, count: u32 },
    /// Certificate upload of a pending `xhttpproxy` entry.
    ProxyCertificate {
        id: xhttpproxy::ProxyId,
        received: u32,
        size: u32,
    },
}

/// Static address configuration (`staticip`, `subnet`, `gateway` settings
/// lines; debug-monitor control codes 0x0b..0x13 read and change it from
/// other threads, so the platform holds it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSettings {
    /// `use=` value of `staticip`.
    pub use_static: u32,
    pub address: Ipv4Address,
    pub subnet: Ipv4Address,
    pub gateway: Ipv4Address,
}

/// One value of [`AddressSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressField {
    UseStatic,
    Address,
    Subnet,
    Gateway,
}

impl Default for AddressSettings {
    /// The monitor's zero-initialized globals.
    fn default() -> Self {
        Self {
            use_static: 0,
            address: Ipv4Address::UNSPECIFIED,
            subnet: Ipv4Address::UNSPECIFIED,
            gateway: Ipv4Address::UNSPECIFIED,
        }
    }
}

/// Version of the system software (`XamGetSystemVersion`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemVersion(pub u32);

/// A Winsock error code. Calls that report a Winsock error can also return
/// a negative result value, which passes through unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WsaError(NonZeroI32);

impl WsaError {
    /// `WSAEINVAL`.
    pub const INVALID_ARGUMENT: Self = Self::known(10022);
    /// `WSAEALREADY`.
    pub const ALREADY: Self = Self::known(10037);
    /// `WSAENOBUFS`.
    pub const NO_BUFFERS: Self = Self::known(10055);

    /// `None` for no error.
    pub const fn new(code: i32) -> Option<Self> {
        match NonZeroI32::new(code) {
            Some(code) => Some(Self(code)),
            None => None,
        }
    }

    const fn known(code: i32) -> Self {
        match Self::new(code) {
            Some(error) => error,
            None => panic!("zero is not an error"),
        }
    }

    pub const fn code(self) -> i32 {
        self.0.get()
    }
}

/// Positive codes move to the Win32 facility; others are result values.
impl From<WsaError> for Win32Error {
    fn from(error: WsaError) -> Self {
        let Some(error) = Win32Error::new(error.code() as u32) else {
            unreachable!("a Winsock error is nonzero");
        };
        error
    }
}

/// `linkstate setflags` without both masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissingLinkMask;

impl From<MissingLinkMask> for CommandError {
    fn from(_: MissingLinkMask) -> Self {
        ErrorCode::BadParameter.into()
    }
}

/// A failed network command as its status reports it. A result of the
/// monitor facility keeps its value; any other reads as 0x82da0000, the
/// common exit of the stock handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkError {
    Netsim(netsim::NetsimError),
    CaptureStart(netcap::StartError),
    /// `ipproxy stop` without a running proxy (426, no default text).
    ProxyNotStarted,
    /// `netcap stop` without a capture (435, no default text).
    NotCapturing,
    /// Frames were lost to a full capture write buffer.
    FramesLost,
    /// A certificate upload was cut short by the connection.
    UploadAborted,
}

impl From<NetworkError> for Hresult {
    #[inline(never)]
    fn from(error: NetworkError) -> Self {
        let result = match error {
            NetworkError::Netsim(error) => error.into(),
            NetworkError::CaptureStart(error) => error.into(),
            NetworkError::ProxyNotStarted => Hresult::error(0x1a),
            NetworkError::NotCapturing => Hresult::error(0x23),
            NetworkError::FramesLost => Hresult::error(0x26),
            NetworkError::UploadAborted => Hresult::error(0x101),
        };
        if result.0 & 0x1fff_0000 == Hresult::OK.0 & 0x1fff_0000 {
            result
        } else {
            Hresult::from_error_code(ErrorCode::Undefined)
        }
    }
}

impl From<NetworkError> for CommandError {
    fn from(error: NetworkError) -> Self {
        Self::Network(error)
    }
}

/// Ethernet link status bits (`XNetGetEthernetLinkStatus`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus(pub u32);

/// Masks applied to the link state: `new = (state & and) | or`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFlags {
    pub and: u32,
    pub or: u32,
}

impl LinkFlags {
    /// `linkstate restore`.
    pub const RESTORE: Self = Self {
        and: u32::MAX,
        or: 0,
    };
    /// `linkstate disconnect`.
    pub const DISCONNECT: Self = Self {
        and: 0,
        or: 0x0001_0000,
    };
}

/// A table of the network stack that the `get*info` commands list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    Sockets,
    Keys,
    SecurityAssociations,
    QosLookups,
}

/// Why a table snapshot failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableError {
    /// The network stack does not provide the table or refused the query.
    Unavailable,
    /// No memory for the snapshot.
    OutOfMemory,
}

/// A key exchange identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Xnkid(pub [u8; 8]);

/// A secure network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XnAddr(pub [u8; 0x24]);

impl Default for XnAddr {
    fn default() -> Self {
        Self([0; 0x24])
    }
}

/// An open socket of the network stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SocketRecord {
    pub handle: u32,
    pub owner_type: i32,
    pub flags: u32,
    pub address_family: i32,
    pub socket_type: i32,
    pub protocol: i32,
    pub local_address: u32,
    pub remote_address: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub tcp_state: u8,
}

/// A registered key exchange key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyRecord {
    pub xnkid: Xnkid,
    pub owner_type: i32,
    pub flags: u32,
    pub qos_data_size: u32,
    pub qos_bits_per_second: u32,
}

/// A security association with a remote console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityAssociationRecord {
    pub secure_address: u32,
    pub owner_type: i32,
    pub flags: u32,
    pub xnkid: Xnkid,
    pub xnaddr: XnAddr,
    pub service_id: i32,
    pub remote_address: u32,
    pub remote_port: u16,
    pub state: u8,
    pub nat_address: u32,
    pub nat_port: u16,
}

/// A pending quality-of-service lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QosLookupRecord {
    pub owner_type: i32,
    pub flags: u32,
    pub target_address: u32,
    pub target_port: u16,
    pub state: u8,
    pub retry: u8,
    pub secure_address: u32,
    pub probes_requested: u32,
    pub probes_sent: u32,
    pub probes_received: u32,
    pub data_received: u32,
    pub bits_per_second: u32,
    pub xnkid: Xnkid,
    pub xnaddr: XnAddr,
}

/// One entry of a table snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    Socket(SocketRecord),
    Key(KeyRecord),
    SecurityAssociation(SecurityAssociationRecord),
    QosLookup(QosLookupRecord),
}

/// Network adapter counters (`NicGetStats`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NicStats {
    pub transmitted_bytes: u64,
    pub received_unicast_bytes: u64,
    pub received_unicast1_bytes: u64,
    pub received_unicast2_bytes: u64,
    pub received_multicast_bytes: u64,
    pub received_broadcast_bytes: u64,
    pub transmitted_frames: u32,
    pub received_unicast_frames: u32,
    pub received_unicast1_frames: u32,
    pub received_unicast2_frames: u32,
    pub received_multicast_frames: u32,
    pub received_broadcast_frames: u32,
    pub transmit_underrun_errors: u32,
    pub transmit_other_errors: u32,
    pub receive_frame_errors: u32,
    pub receive_crc_errors: u32,
    pub receive_other_errors: u32,
}

/// Platform services this domain needs.
pub trait Backend:
    netcap::Backend + netsim::Backend + ipproxy::Backend + xhttpproxy::Backend
{
    fn system_version(&mut self) -> SystemVersion;
    /// Copy `table` for `connection`, replacing that connection's previous
    /// snapshot, and return the number of records.
    fn open_table(&mut self, connection: ConnectionIndex, table: Table) -> Result<u32, TableError>;
    /// Record `index` of the connection's snapshot.
    fn table_record(&mut self, connection: ConnectionIndex, index: u32) -> Option<Record>;
    /// Release the connection's snapshot.
    fn close_table(&mut self, connection: ConnectionIndex);
    fn link_status(&mut self) -> LinkStatus;
    fn set_link_flags(&mut self, flags: LinkFlags) -> Result<(), WsaError>;
    /// Adapter counters. `device_flags` selects the adapters.
    fn nic_stats(&mut self, device_flags: u32) -> NicStats;
    fn address_settings(&mut self) -> AddressSettings;
    /// Store one address setting; other threads may change the others.
    fn set_address_field(&mut self, field: AddressField, value: u32);
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
    match continuation {
        Continuation::Table {
            table: _,
            next,
            count,
        } => table_line(next, *count, cx),
        Continuation::ProxyCertificate { id, received, size } => {
            xhttpproxy::receive_certificate(*id, received, *size, cx)
        }
    }
}

fn socket_info(invocation: &mut Invocation<'_>) -> CommandResult {
    open_table(invocation, Table::Sockets)
}

fn key_info(invocation: &mut Invocation<'_>) -> CommandResult {
    open_xn_table(invocation, Table::Keys)
}

fn qos_lookup_info(invocation: &mut Invocation<'_>) -> CommandResult {
    open_xn_table(invocation, Table::QosLookups)
}

fn security_association_info(invocation: &mut Invocation<'_>) -> CommandResult {
    open_xn_table(invocation, Table::SecurityAssociations)
}

fn open_xn_table(invocation: &mut Invocation<'_>, table: Table) -> CommandResult {
    if invocation.backend.system_version() < XN_TABLES_VERSION {
        return Err(ErrorCode::UnknownCommand.into());
    }
    open_table(invocation, table)
}

/// Snapshot the table and stream one line per record. Settings-file lines
/// have no connection to stream to.
fn open_table(invocation: &mut Invocation<'_>, table: Table) -> CommandResult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };
    let count = match invocation.backend.open_table(session.index(), table) {
        Ok(count) => count,
        Err(TableError::Unavailable) => return Err(ErrorCode::AccessDenied.into()),
        Err(TableError::OutOfMemory) => return Err(ErrorCode::OutOfMemory.into()),
    };
    session.receive_remaining = None;
    session.continuation = AnyContinuation::Network(Continuation::Table {
        table,
        next: 0,
        count,
    });
    Ok(Reply::Multiline)
}

fn table_line(next: &mut u32, count: u32, cx: &mut ContinuationContext<'_>) -> CommandResult {
    let connection = cx.session.index();
    if *next >= count {
        cx.backend.close_table(connection);
        return Err(CommandError::EndOfData);
    }
    let record = cx.backend.table_record(connection, *next);
    *next += 1;
    let mut line = Text::<TABLE_LINE_LIMIT>::new();
    if let Some(record) = record {
        // Overflow truncates the line as the monitor's buffer does.
        let _ = write_record(&mut line, &record);
    }
    cx.line.set_bytes(line.as_bytes());
    Ok(Reply::Ok)
}

fn write_record(line: &mut Text<TABLE_LINE_LIMIT>, record: &Record) -> core::fmt::Result {
    match record {
        Record::Socket(socket) => write!(
            line,
            "handle=0x{:08x} ownertype={} flags=0x{:08x} addrfamily={} socktype={} protocol={} localaddr=0x{:08x} \
             remoteaddr=0x{:08x} localport=0x{:04x} remoteport=0x{:04x} tcpstate={}",
            socket.handle,
            socket.owner_type,
            socket.flags,
            socket.address_family,
            socket.socket_type,
            socket.protocol,
            socket.local_address,
            socket.remote_address,
            socket.local_port,
            socket.remote_port,
            socket.tcp_state,
        ),
        Record::Key(key) => {
            line.push_bytes(b"xnkid=\"")?;
            line.push_hex_upper(&key.xnkid.0)?;
            write!(
                line,
                "\" ownertype={} flags=0x{:08x} qosdatasize={} qosbps={}",
                key.owner_type, key.flags, key.qos_data_size, key.qos_bits_per_second,
            )
        }
        Record::SecurityAssociation(association) => {
            write!(
                line,
                "secaddr=0x{:08x} ownertype={} flags=0x{:08x} xnkid=\"",
                association.secure_address, association.owner_type, association.flags,
            )?;
            line.push_hex_upper(&association.xnkid.0)?;
            line.push_bytes(b"\" xnaddr=\"")?;
            line.push_hex_upper(&association.xnaddr.0)?;
            write!(
                line,
                "\" serviceid={} remoteaddr=0x{:08x} remoteport=0x{:04x} state={} nataddr=0x{:08x} natport=0x{:04x}",
                association.service_id,
                association.remote_address,
                association.remote_port,
                association.state,
                association.nat_address,
                association.nat_port,
            )
        }
        Record::QosLookup(lookup) => {
            write!(
                line,
                "ownertype={} flags=0x{:08x} preq={} ptx={} prx={} datarx={} bps={} targetaddr=0x{:08x} \
                 targetport=0x{:04x} state={} retry={} secaddr=0x{:08x} xnkid=\"",
                lookup.owner_type,
                lookup.flags,
                lookup.probes_requested,
                lookup.probes_sent,
                lookup.probes_received,
                lookup.data_received,
                lookup.bits_per_second,
                lookup.target_address,
                lookup.target_port,
                lookup.state,
                lookup.retry,
                lookup.secure_address,
            )?;
            line.push_hex_upper(&lookup.xnkid.0)?;
            line.push_bytes(b"\" xnaddr=\"")?;
            line.push_hex_upper(&lookup.xnaddr.0)?;
            line.push_bytes(b"\"")
        }
    }
}

/// `linkstate [restore | disconnect | setflags and=<dword> or=<dword>]`:
/// report the Ethernet link state or force it through masks. The link
/// state is always read first and reported as the old state.
pub(crate) fn link_state(invocation: &mut Invocation<'_>) -> CommandResult {
    let flags = parse_link_state(invocation.line);
    execute_link_state(invocation, flags)
}

/// The forced flags of a `linkstate` line, if any.
pub(crate) fn parse_link_state(
    line: CommandLine<'_>,
) -> Result<Option<LinkFlags>, MissingLinkMask> {
    Ok(if line.has("restore") {
        Some(LinkFlags::RESTORE)
    } else if line.has("disconnect") {
        Some(LinkFlags::DISCONNECT)
    } else if line.has("setflags") {
        let and = line.dword("and");
        let or = line.dword("or");
        let (Some(and), Some(or)) = (and, or) else {
            return Err(MissingLinkMask);
        };
        Some(LinkFlags { and, or })
    } else {
        None
    })
}

pub(crate) fn execute_link_state(
    invocation: &mut Invocation<'_>,
    flags: Result<Option<LinkFlags>, MissingLinkMask>,
) -> CommandResult {
    let flags = flags?;
    let LinkStatus(old) = invocation.backend.link_status();
    let Some(flags) = flags else {
        invocation.set_text(format_args!("state=0x{old:08x}"));
        return Ok(Reply::Ok);
    };
    match invocation.backend.set_link_flags(flags) {
        Ok(()) => {
            invocation.set_text(format_args!(
                "set, andflags=0x{:08x} orflags=0x{:08x} oldstate=0x{old:08x}",
                flags.and, flags.or
            ));
            Ok(Reply::Ok)
        }
        Err(error) => {
            invocation.set_text(format_args!("err={}", error.code()));
            Err(link_error(error))
        }
    }
}

/// Result of a refused link state change (0x91f35990): 10022 reads as an
/// unknown command, anything else as a generic failure.
pub fn link_error(error: WsaError) -> CommandError {
    if error == WsaError::INVALID_ARGUMENT {
        ErrorCode::UnknownCommand.into()
    } else {
        ErrorCode::Undefined.into()
    }
}

/// `nicstats [deviceflags=<dword>]`: adapter counters; all adapters by
/// default.
fn nic_stats(invocation: &mut Invocation<'_>) -> CommandResult {
    let device_flags = invocation.line.dword("deviceflags").unwrap_or(u32::MAX);
    let stats = invocation.backend.nic_stats(device_flags);
    invocation.set_text(format_args!(
        "tb=0q{:x} rub=0q{:x} ru1b=0q{:x} ru2b=0q{:x} rmb=0q{:x} rbb=0q{:x} tf={} ruf={} ru1f={} ru2f={} rmf={} \
         rbf={} tue={} toe={} rfe={} rce={} roe={}",
        stats.transmitted_bytes,
        stats.received_unicast_bytes,
        stats.received_unicast1_bytes,
        stats.received_unicast2_bytes,
        stats.received_multicast_bytes,
        stats.received_broadcast_bytes,
        stats.transmitted_frames,
        stats.received_unicast_frames,
        stats.received_unicast1_frames,
        stats.received_unicast2_frames,
        stats.received_multicast_frames,
        stats.received_broadcast_frames,
        stats.transmit_underrun_errors,
        stats.transmit_other_errors,
        stats.receive_frame_errors,
        stats.receive_crc_errors,
        stats.receive_other_errors,
    ));
    Ok(Reply::Ok)
}

/// Decode the hex text of a `cert=` or `cfg=` value (stock 0x91f364f0):
/// digit pairs of either case up to a space, quote, or the end of the line.
/// Returns the byte count, or `None` (0x82da0007) for a bad digit, an odd
/// digit count, or more bytes than `output` holds.
pub fn decode_hex(text: &[u8], output: &mut [u8]) -> Option<usize> {
    let at = |index: usize| match text.get(index) {
        // The monitor's line buffer ends at the CR.
        Some(b'\r') | None => 0,
        Some(&byte) => byte,
    };
    let digit = |byte: u8| char::from(byte).to_digit(16).map(|value| value as u8);
    let mut count = 0;
    let mut position = 0;
    loop {
        let high = at(position);
        if matches!(high, 0 | b' ' | b'"') {
            return Some(count);
        }
        let slot = output.get_mut(count)?;
        *slot = (digit(high)? << 4) | digit(at(position + 1))?;
        count += 1;
        position += 2;
    }
}

/// The title process ended (stock 0x91f38480).
pub fn title_exited(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    backend.proxy_title_exited();
    netcap::title_exited(&mut state.network.netcap, backend);
}

/// Settings lines of the address configuration, always written.
pub(crate) fn address_settings_lines(
    _state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let address = backend.address_settings();
    let dword = |address: Ipv4Address| u32::from_be_bytes(address.octets());
    system::write_line(
        backend,
        file,
        format_args!(
            "staticip use={}, addr=0x{:08x}",
            address.use_static as i32,
            dword(address.address)
        ),
    );
    system::write_line(
        backend,
        file,
        format_args!("subnet addr=0x{:08x}", dword(address.subnet)),
    );
    system::write_line(
        backend,
        file,
        format_args!("gateway addr=0x{:08x}", dword(address.gateway)),
    );
}

/// Store a settings dword as the monitor's getter does: a present value
/// stores its numeric prefix (so `use=1,` reads as 1); an absent one leaves
/// the setting unchanged.
fn ini_dword(invocation: &mut Invocation<'_>, name: &str, field: AddressField) {
    if let Some(value) = invocation.line.param(name) {
        invocation
            .backend
            .set_address_field(field, value.dword_prefix());
    }
}

/// Settings-file `staticip addr=<dword> use=<dword>`.
pub(crate) fn ini_staticip(invocation: &mut Invocation<'_>) {
    ini_dword(invocation, "addr", AddressField::Address);
    ini_dword(invocation, "use", AddressField::UseStatic);
}

/// Settings-file `subnet addr=<dword>`.
pub(crate) fn ini_subnet(invocation: &mut Invocation<'_>) {
    ini_dword(invocation, "addr", AddressField::Subnet);
}

/// Settings-file `gateway addr=<dword>`.
pub(crate) fn ini_gateway(invocation: &mut Invocation<'_>) {
    ini_dword(invocation, "addr", AddressField::Gateway);
}

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn hex_decoding_follows_the_monitor() {
        let mut output = [0u8; 4];
        assert_eq!(decode_hex(b"0aFf rest", &mut output), Some(2));
        assert_eq!(output[..2], [0x0a, 0xff]);
        assert_eq!(decode_hex(b"12\"", &mut output), Some(1));
        assert_eq!(decode_hex(b"", &mut output), Some(0));
        assert_eq!(decode_hex(b"123", &mut output), None);
        assert_eq!(decode_hex(b"1g", &mut output), None);
        assert_eq!(decode_hex(b"1 2", &mut output), None);
        assert_eq!(decode_hex(b"0102030405", &mut output), None);
    }
}
