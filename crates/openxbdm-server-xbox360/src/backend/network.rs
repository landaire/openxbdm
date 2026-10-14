//! Network stack inspection and control.

mod exports;
pub mod ipproxy;
pub mod netcap;
pub mod netsim;
pub mod xhttpproxy;

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::ConnectionIndex;
use openxbdm_server::commands::network;
use openxbdm_server::commands::network::AddressField;
use openxbdm_server::commands::network::AddressSettings;
use openxbdm_server::commands::network::KeyRecord;
use openxbdm_server::commands::network::LinkFlags;
use openxbdm_server::commands::network::LinkStatus;
use openxbdm_server::commands::network::NicStats;
use openxbdm_server::commands::network::QosLookupRecord;
use openxbdm_server::commands::network::Record;
use openxbdm_server::commands::network::SecurityAssociationRecord;
use openxbdm_server::commands::network::SocketRecord;
use openxbdm_server::commands::network::SystemVersion;
use openxbdm_server::commands::network::Table;
use openxbdm_server::commands::network::TableError;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::XnAddr;
use openxbdm_server::commands::network::Xnkid;
use openxbdm_server::network::Ipv4Address;
use openxbdm_server::server::MAX_CONNECTIONS;

use super::Console;
use crate::kernel;
use crate::kernel::LIB_KERNEL;
use crate::kernel::LIB_XAM;
use crate::kernel::import_thunk;

/// Caller identifier the monitor passes to XNet configuration functions.
pub(crate) const XNCALLER_SYSAPP: u32 = 2;
/// Caller identifier the monitor passes to the table queries.
const XNCALLER_XBDM: u32 = 3;
/// `XNetSetOpt` option that forces Ethernet link state bits.
const XNET_OPT_LINK_FLAGS: u32 = 0x1395;
/// Pool tag of monitor allocations (`mdbx`).
pub(crate) const POOL_TAG: u32 = 0x7862_646d;
/// QoS lookup query result for a too-small buffer (`WSAEMSGSIZE`).
const WSAEMSGSIZE: u32 = 0x2747;
/// Bytes of the adapter counter block: stock passes an 8-aligned 0x60-byte
/// stack slot (u64 counters, then eleven u32 counters and padding).
const NIC_STATS_SIZE: usize = 0x60;

#[repr(C, align(8))]
struct NicStatsBlock([u8; NIC_STATS_SIZE]);

import_thunk!(
    pub(crate) NetDll_XNetSetOpt(caller: u32, option: u32, value: *const u8, length: u32) -> i32,
    lib = LIB_XAM,
    ordinal = 0x4f
);
import_thunk!(pub(crate) NetDll_XNetGetEthernetLinkStatus(caller: u32) -> u32, lib = LIB_XAM, ordinal = 0x4b);
import_thunk!(
    pub(crate) NetDll_XnpEthernetInterceptSetCallbacks(caller: u32, transmit: usize, receive: usize, context: usize, flags: u32) -> i32,
    lib = LIB_XAM,
    ordinal = 0x6d
);
import_thunk!(
    NetDll_XnpGetActiveSocketList(caller: u32, buffer: *mut u8, count: *mut u32) -> u32,
    lib = LIB_XAM,
    ordinal = 0x7a
);
import_thunk!(
    NicGetStats(device_flags: u32, stats: *mut u8) -> u32,
    lib = LIB_KERNEL,
    ordinal = 0x209
);
import_thunk!(
    NetDll_XnpConfig(caller: u32, config: *const u8, flags: u32) -> i32,
    lib = LIB_XAM,
    ordinal = 0x68
);
import_thunk!(
    NetDll_XnpGetConfigStatus(caller: u32, status: *mut u8) -> i32,
    lib = LIB_XAM,
    ordinal = 0x69
);

/// Static address configuration (stock 0x91faddbc use, 0x91faddb8 address,
/// 0x91faddb4 subnet, 0x91faddb0 gateway). Debug-monitor control codes
/// read and change it from other threads.
static STATIC_IP_USE: AtomicU32 = AtomicU32::new(0);
static STATIC_IP_ADDRESS: AtomicU32 = AtomicU32::new(0);
static STATIC_IP_SUBNET: AtomicU32 = AtomicU32::new(0);
static STATIC_IP_GATEWAY: AtomicU32 = AtomicU32::new(0);

/// Bytes of the network stack configuration status (stock 0x91fadc20).
const CONFIG_STATUS_SIZE: usize = 0x3a;
/// Bytes of the configuration record passed to `XnpConfig`.
const CONFIG_SIZE: usize = 0x1ec;
/// Configuration flags: static address, subnet, and gateway present.
const CONFIG_STATIC_ADDRESS: u16 = 0xc;

fn address(value: u32) -> Ipv4Address {
    Ipv4Address(value.to_be_bytes())
}

fn current_address_settings() -> AddressSettings {
    AddressSettings {
        use_static: STATIC_IP_USE.load(Ordering::SeqCst),
        address: address(STATIC_IP_ADDRESS.load(Ordering::SeqCst)),
        subnet: address(STATIC_IP_SUBNET.load(Ordering::SeqCst)),
        gateway: address(STATIC_IP_GATEWAY.load(Ordering::SeqCst)),
    }
}

/// Store a control-code value, request the settings write, and return the
/// stored value (stock cases 0x0c, 0x0e, 0x10, 0x12).
fn set_and_save(target: &AtomicU32, value: u32) -> u32 {
    target.store(value, Ordering::SeqCst);
    crate::backend::dispatcher::request_settings_write();
    target.load(Ordering::SeqCst)
}

/// Control code 0x0b (stock 0x91f3b2c8): configure the network stack with
/// the static address (when enabled) and the debug name as host name. The
/// address values come through the dispatcher, so extensions see codes
/// 0x0d, 0x0f, 0x11, and 0x13.
pub(crate) fn service_apply_xnet_config(_argument: u32) -> u32 {
    use crate::backend::dispatcher::dispatch;
    // SAFETY: plain buffer; only this function and the status queries
    // use it, as in stock.
    unsafe { CONFIG_STATUS = [0; CONFIG_STATUS_SIZE] };
    let mut config = [0u8; CONFIG_SIZE];
    if dispatch(0x0d, 0) != 0 {
        config[0x4c..0x4e].copy_from_slice(&CONFIG_STATIC_ADDRESS.to_be_bytes());
        config[0x54..0x58].copy_from_slice(&dispatch(0x0f, 0).to_be_bytes());
        config[0x58..0x5c].copy_from_slice(&dispatch(0x11, 0).to_be_bytes());
        config[0x5c..0x60].copy_from_slice(&dispatch(0x13, 0).to_be_bytes());
    }
    let name = crate::backend::console::debug_name();
    let name = name.as_bytes();
    config[0x68..0x68 + name.len()].copy_from_slice(name);
    // The dispatcher case discards the result (0x91f3bb10).
    NetDll_XnpConfig(XNCALLER_XBDM, config.as_ptr(), 0);
    0
}

pub(crate) fn service_set_static_ip_enable(argument: u32) -> u32 {
    set_and_save(&STATIC_IP_USE, argument)
}

pub(crate) fn service_get_static_ip_enable(_argument: u32) -> u32 {
    STATIC_IP_USE.load(Ordering::SeqCst)
}

pub(crate) fn service_set_static_ip_address(argument: u32) -> u32 {
    set_and_save(&STATIC_IP_ADDRESS, argument)
}

pub(crate) fn service_get_static_ip_address(_argument: u32) -> u32 {
    STATIC_IP_ADDRESS.load(Ordering::SeqCst)
}

pub(crate) fn service_set_subnet(argument: u32) -> u32 {
    set_and_save(&STATIC_IP_SUBNET, argument)
}

pub(crate) fn service_get_subnet(_argument: u32) -> u32 {
    STATIC_IP_SUBNET.load(Ordering::SeqCst)
}

pub(crate) fn service_set_gateway(argument: u32) -> u32 {
    set_and_save(&STATIC_IP_GATEWAY, argument)
}

pub(crate) fn service_get_gateway(_argument: u32) -> u32 {
    STATIC_IP_GATEWAY.load(Ordering::SeqCst)
}

static mut CONFIG_STATUS: [u8; CONFIG_STATUS_SIZE] = [0; CONFIG_STATUS_SIZE];

/// Query the configuration status and return the dword at `offset`
/// (stock cases 0x14..0x16).
fn config_status_dword(offset: usize) -> u32 {
    // SAFETY: as in stock, concurrent queries share the status buffer.
    unsafe {
        let status = &raw mut CONFIG_STATUS;
        NetDll_XnpGetConfigStatus(XNCALLER_XBDM, status.cast());
        dword(&*status, offset)
    }
}

pub(crate) fn service_config_status_1(_argument: u32) -> u32 {
    config_status_dword(4)
}

pub(crate) fn service_config_status_2(_argument: u32) -> u32 {
    config_status_dword(8)
}

pub(crate) fn service_config_status_3(_argument: u32) -> u32 {
    config_status_dword(0xc)
}

/// Ethernet frame callback of the network stack intercept; returns nonzero
/// when the frame is consumed.
pub(crate) type FrameCallback = extern "C" fn(context: usize, frame: *mut u8, length: u32) -> u32;

/// Transmit and receive callbacks with their context.
#[derive(Clone, Copy)]
pub(crate) struct FrameHook {
    pub transmit: FrameCallback,
    pub receive: FrameCallback,
    pub context: usize,
}

/// Address of a `xam.xex` export (stock 0x91f31010 handle and
/// `XexGetProcedureAddress`; any success status counts).
pub(crate) fn xam_procedure(ordinal: u32) -> Option<u32> {
    let module = kernel::module_handle(c"xam.xex").ok()?;
    let mut address = 0u32;
    ((kernel::XexGetProcedureAddress(module, ordinal, &mut address) as i32) >= 0).then_some(address)
}

/// A pool allocation holding raw table records.
#[derive(Clone, Copy)]
struct Snapshot {
    table: Table,
    buffer: u32,
    count: u32,
}

impl Snapshot {
    fn record_size(table: Table) -> u32 {
        match table {
            Table::Sockets | Table::Keys => 0x28,
            Table::SecurityAssociations => 0x78,
            Table::QosLookups => 0x88,
        }
    }

    fn record(&self, index: u32) -> Option<Record> {
        if index >= self.count {
            return None;
        }
        let size = Self::record_size(self.table);
        let address = self.buffer + index * size;
        // SAFETY: the buffer holds `count` records of `size` bytes, written
        // by the network stack.
        let bytes =
            unsafe { core::slice::from_raw_parts(address as usize as *const u8, size as usize) };
        Some(decode(self.table, bytes))
    }
}

fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn xnkid(bytes: &[u8], offset: usize) -> Xnkid {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    Xnkid(value)
}

fn xnaddr(bytes: &[u8], offset: usize) -> XnAddr {
    let mut value = [0u8; 0x24];
    value.copy_from_slice(&bytes[offset..offset + 0x24]);
    XnAddr(value)
}

/// Record layouts of the stock table queries (see `getsockinfo`,
/// `getxnkeyinfo`, `getxnsecassocinfo`, `getxnqoslookupinfo` specs).
fn decode(table: Table, bytes: &[u8]) -> Record {
    match table {
        Table::Sockets => Record::Socket(SocketRecord {
            handle: dword(bytes, 0x00),
            owner_type: dword(bytes, 0x04) as i32,
            flags: dword(bytes, 0x08),
            address_family: dword(bytes, 0x0c) as i32,
            socket_type: dword(bytes, 0x10) as i32,
            protocol: dword(bytes, 0x14) as i32,
            local_address: dword(bytes, 0x18),
            remote_address: dword(bytes, 0x1c),
            local_port: word(bytes, 0x20),
            remote_port: word(bytes, 0x22),
            tcp_state: bytes[0x24],
        }),
        Table::Keys => Record::Key(KeyRecord {
            xnkid: xnkid(bytes, 0x00),
            owner_type: dword(bytes, 0x08) as i32,
            flags: dword(bytes, 0x0c),
            qos_data_size: dword(bytes, 0x10),
            qos_bits_per_second: dword(bytes, 0x14),
        }),
        Table::SecurityAssociations => Record::SecurityAssociation(SecurityAssociationRecord {
            secure_address: dword(bytes, 0x00),
            owner_type: dword(bytes, 0x04) as i32,
            flags: dword(bytes, 0x08),
            xnkid: xnkid(bytes, 0x10),
            xnaddr: xnaddr(bytes, 0x18),
            service_id: dword(bytes, 0x3c) as i32,
            remote_address: dword(bytes, 0x40),
            remote_port: word(bytes, 0x44),
            state: bytes[0x46],
            nat_address: dword(bytes, 0x48),
            nat_port: word(bytes, 0x4c),
        }),
        Table::QosLookups => Record::QosLookup(QosLookupRecord {
            owner_type: dword(bytes, 0x04) as i32,
            flags: dword(bytes, 0x08),
            target_address: dword(bytes, 0x0c),
            target_port: word(bytes, 0x10),
            state: bytes[0x12],
            retry: bytes[0x13],
            secure_address: dword(bytes, 0x14),
            probes_requested: dword(bytes, 0x18),
            probes_sent: dword(bytes, 0x1c),
            probes_received: dword(bytes, 0x20),
            data_received: dword(bytes, 0x24),
            bits_per_second: dword(bytes, 0x28),
            xnkid: xnkid(bytes, 0x2c),
            xnaddr: xnaddr(bytes, 0x34),
        }),
    }
}

/// XAM ordinal of a table query `fn(caller, buffer, &count) -> u32`.
fn table_ordinal(table: Table) -> Option<u32> {
    match table {
        Table::Sockets => None,
        Table::SecurityAssociations => Some(0x81),
        Table::Keys => Some(0x82),
        Table::QosLookups => Some(0x83),
    }
}

fn query(function: Option<u32>, buffer: u32, count: &mut u32) -> u32 {
    match function {
        // SAFETY: XAM table queries take (caller, buffer, count pointer).
        Some(function) => unsafe {
            kernel::call_export(
                function,
                XNCALLER_XBDM,
                buffer,
                count as *mut u32 as usize as u32,
                0,
            )
        },
        None => NetDll_XnpGetActiveSocketList(XNCALLER_XBDM, buffer as usize as *mut u8, count),
    }
}

/// Copy a table into a new pool buffer, following the stock capacities:
/// 0x800 sockets, 0x400 keys or associations, and the reported number of
/// QoS lookups plus one.
fn take_snapshot(table: Table) -> Result<Snapshot, TableError> {
    let function = match table_ordinal(table) {
        Some(ordinal) => Some(xam_procedure(ordinal).ok_or(TableError::Unavailable)?),
        None => None,
    };
    let mut count = match table {
        Table::Sockets => 0x800,
        Table::Keys | Table::SecurityAssociations => 0x400,
        Table::QosLookups => {
            let mut count = 0u32;
            let result = query(function, 0, &mut count);
            if result != 0 && result != WSAEMSGSIZE {
                return Err(TableError::Unavailable);
            }
            count.wrapping_add(1)
        }
    };
    let buffer =
        kernel::ExAllocatePoolWithTag(count.wrapping_mul(Snapshot::record_size(table)), POOL_TAG);
    if buffer == 0 {
        return Err(TableError::OutOfMemory);
    }
    if query(function, buffer, &mut count) != 0 {
        kernel::ExFreePool(buffer);
        return Err(TableError::Unavailable);
    }
    Ok(Snapshot {
        table,
        buffer,
        count,
    })
}

/// Platform state of this domain.
pub struct Data {
    snapshots: [Option<Snapshot>; MAX_CONNECTIONS],
    pub netcap: netcap::Data,
    pub ipproxy: ipproxy::Data,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            snapshots: [None; MAX_CONNECTIONS],
            netcap: netcap::Data::new(),
            ipproxy: ipproxy::Data::new(),
        }
    }

    fn release(&mut self, connection: ConnectionIndex) {
        if let Some(snapshot) = self
            .snapshots
            .get_mut(usize::from(connection.0))
            .and_then(Option::take)
        {
            kernel::ExFreePool(snapshot.buffer);
        }
    }
}

/// Ethernet link state (`XNetGetEthernetLinkStatus`); any thread.
pub(crate) fn link_status() -> LinkStatus {
    LinkStatus(NetDll_XNetGetEthernetLinkStatus(XNCALLER_SYSAPP))
}

/// Force link state bits through `XNetSetOpt`; any thread.
pub(crate) fn set_link_flags(flags: LinkFlags) -> Result<(), WsaError> {
    let mut value = [0u8; 8];
    value[..4].copy_from_slice(&flags.and.to_be_bytes());
    value[4..].copy_from_slice(&flags.or.to_be_bytes());
    match NetDll_XNetSetOpt(
        XNCALLER_SYSAPP,
        XNET_OPT_LINK_FLAGS,
        value.as_ptr(),
        value.len() as u32,
    ) {
        0 => Ok(()),
        error => Err(WsaError(error)),
    }
}

impl network::Backend for Console {
    fn system_version(&mut self) -> SystemVersion {
        SystemVersion(kernel::XamGetSystemVersion())
    }

    fn open_table(&mut self, connection: ConnectionIndex, table: Table) -> Result<u32, TableError> {
        self.network.release(connection);
        let snapshot = take_snapshot(table)?;
        match self.network.snapshots.get_mut(usize::from(connection.0)) {
            Some(slot) => {
                *slot = Some(snapshot);
                Ok(snapshot.count)
            }
            None => {
                kernel::ExFreePool(snapshot.buffer);
                Err(TableError::OutOfMemory)
            }
        }
    }

    fn table_record(&mut self, connection: ConnectionIndex, index: u32) -> Option<Record> {
        self.network
            .snapshots
            .get(usize::from(connection.0))
            .copied()
            .flatten()?
            .record(index)
    }

    fn close_table(&mut self, connection: ConnectionIndex) {
        self.network.release(connection);
    }

    fn link_status(&mut self) -> LinkStatus {
        link_status()
    }

    fn set_link_flags(&mut self, flags: LinkFlags) -> Result<(), WsaError> {
        set_link_flags(flags)
    }

    /// The kernel result is ignored, as in stock; a failed query reports
    /// zeros where stock reports stale stack contents.
    fn nic_stats(&mut self, device_flags: u32) -> NicStats {
        let mut block = NicStatsBlock([0; NIC_STATS_SIZE]);
        NicGetStats(device_flags, block.0.as_mut_ptr());
        let raw = block.0;
        let qword = |offset: usize| {
            (u64::from(dword(&raw, offset)) << 32) | u64::from(dword(&raw, offset + 4))
        };
        NicStats {
            transmitted_bytes: qword(0x00),
            received_unicast_bytes: qword(0x08),
            received_unicast1_bytes: qword(0x10),
            received_unicast2_bytes: qword(0x18),
            received_multicast_bytes: qword(0x20),
            received_broadcast_bytes: qword(0x28),
            transmitted_frames: dword(&raw, 0x30),
            received_unicast_frames: dword(&raw, 0x34),
            received_unicast1_frames: dword(&raw, 0x38),
            received_unicast2_frames: dword(&raw, 0x3c),
            received_multicast_frames: dword(&raw, 0x40),
            received_broadcast_frames: dword(&raw, 0x44),
            transmit_underrun_errors: dword(&raw, 0x48),
            transmit_other_errors: dword(&raw, 0x4c),
            receive_frame_errors: dword(&raw, 0x50),
            receive_crc_errors: dword(&raw, 0x54),
            receive_other_errors: dword(&raw, 0x58),
        }
    }

    fn address_settings(&mut self) -> AddressSettings {
        current_address_settings()
    }

    fn set_address_field(&mut self, field: AddressField, value: u32) {
        let target = match field {
            AddressField::UseStatic => &STATIC_IP_USE,
            AddressField::Address => &STATIC_IP_ADDRESS,
            AddressField::Subnet => &STATIC_IP_SUBNET,
            AddressField::Gateway => &STATIC_IP_GATEWAY,
        };
        target.store(value, Ordering::SeqCst);
    }
}
