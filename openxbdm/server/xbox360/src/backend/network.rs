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
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::status::Win32Error;
use xbox360_sys::xam;
use xbox360_sys::xam::EthernetInterceptFlags;
use xbox360_sys::xam::NetDll_XNetGetEthernetLinkStatus;
use xbox360_sys::xam::NetDll_XNetSetOpt;
use xbox360_sys::xam::NetDll_XnpGetActiveSocketList;
use xbox360_sys::xam::NetDll_XnpGetConfigStatus;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xam::XnetConfigFlags;
use xbox360_sys::xam::XnetConfigParams;
use xbox360_sys::xam::XnetOption;
use xbox360_sys::xam::ordinal;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::NicStatistics;

use super::Console;
use super::dispatcher;
use super::dispatcher::ControlCode;
use crate::kernel;
use crate::kernel::pool_tag;

/// Static address configuration (stock 0x91faddbc use, 0x91faddb8 address,
/// 0x91faddb4 subnet, 0x91faddb0 gateway). Debug-monitor control codes
/// read and change it from other threads.
static STATIC_IP_USE: AtomicU32 = AtomicU32::new(0);
static STATIC_IP_ADDRESS: AtomicU32 = AtomicU32::new(0);
static STATIC_IP_SUBNET: AtomicU32 = AtomicU32::new(0);
static STATIC_IP_GATEWAY: AtomicU32 = AtomicU32::new(0);

/// Words that hold the 0x3a bytes of the network stack configuration
/// status.
const CONFIG_STATUS_WORDS: usize = 0x3a_usize.div_ceil(4);

/// Network stack configuration status (stock 0x91fadc20), which each query
/// refills. Concurrent queries share it, as in stock.
static CONFIG_STATUS: [AtomicU32; CONFIG_STATUS_WORDS] =
    [const { AtomicU32::new(0) }; CONFIG_STATUS_WORDS];

/// Intercept flags of the simulator registration and its removal; a
/// capture registers with none.
pub(crate) const SIMULATOR_INTERCEPT: EthernetInterceptFlags =
    EthernetInterceptFlags::from_bits_retain(0x2);

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

/// A pool allocation holding raw table records. It owns the allocation,
/// which [`Snapshot::free`] releases; it has no `Drop` so that storing one
/// in a slot known to be empty emits no drop code.
#[must_use]
struct Snapshot {
    table: Table,
    buffer: u32,
    count: u32,
}

impl Snapshot {
    fn free(self) {
        // SAFETY: the snapshot owns its pool buffer, which nothing else
        // uses; `self` is consumed.
        unsafe { xboxkrnl::ExFreePool(self.buffer) };
    }

    fn record_size(table: Table) -> u32 {
        (match table {
            Table::Sockets => size_of::<SocketEntry>(),
            Table::Keys => size_of::<KeyEntry>(),
            Table::SecurityAssociations => size_of::<SecurityAssociationEntry>(),
            Table::QosLookups => size_of::<QosLookupEntry>(),
        }) as u32
    }

    fn record(&self, index: u32) -> Option<Record> {
        if index >= self.count {
            return None;
        }

        let address = self.buffer + index * Self::record_size(self.table);
        // SAFETY: the pool buffer (8-aligned) holds `count` records of
        // `record_size` bytes, a multiple of 8, written by the network stack.
        Some(unsafe { decode(self.table, address as usize as *const u8) })
    }
}

/// Socket record of `XnpGetActiveSocketList` (see `getsockinfo`).
#[repr(C)]
struct SocketEntry {
    handle: u32,
    owner_type: i32,
    flags: u32,
    address_family: i32,
    socket_type: i32,
    protocol: i32,
    local_address: u32,
    remote_address: u32,
    local_port: u16,
    remote_port: u16,
    tcp_state: u8,
    _reserved: [u8; 3],
}

/// Key record of XAM 0x82 (see `getxnkeyinfo`).
#[repr(C)]
struct KeyEntry {
    xnkid: [u8; 8],
    owner_type: i32,
    flags: u32,
    qos_data_size: u32,
    qos_bits_per_second: u32,
    _reserved: [u8; 0x10],
}

/// Security association record of XAM 0x81 (see `getxnsecassocinfo`).
#[repr(C)]
struct SecurityAssociationEntry {
    secure_address: u32,
    owner_type: i32,
    flags: u32,
    _reserved0: u32,
    xnkid: [u8; 8],
    xnaddr: [u8; 0x24],
    service_id: i32,
    remote_address: u32,
    remote_port: u16,
    state: u8,
    _reserved1: u8,
    nat_address: u32,
    nat_port: u16,
    _reserved2: [u8; 0x2a],
}

/// QoS lookup record of XAM 0x83 (see `getxnqoslookupinfo`).
#[repr(C)]
struct QosLookupEntry {
    _reserved0: u32,
    owner_type: i32,
    flags: u32,
    target_address: u32,
    target_port: u16,
    state: u8,
    retry: u8,
    secure_address: u32,
    probes_requested: u32,
    probes_sent: u32,
    probes_received: u32,
    data_received: u32,
    bits_per_second: u32,
    xnkid: [u8; 8],
    xnaddr: [u8; 0x24],
    _reserved1: [u8; 0x30],
}

const _: () = {
    assert!(core::mem::offset_of!(SocketEntry, tcp_state) == 0x24);
    assert!(size_of::<SocketEntry>() == 0x28);
    assert!(core::mem::offset_of!(KeyEntry, qos_bits_per_second) == 0x14);
    assert!(size_of::<KeyEntry>() == 0x28);
    assert!(core::mem::offset_of!(SecurityAssociationEntry, xnkid) == 0x10);
    assert!(core::mem::offset_of!(SecurityAssociationEntry, service_id) == 0x3c);
    assert!(core::mem::offset_of!(SecurityAssociationEntry, state) == 0x46);
    assert!(core::mem::offset_of!(SecurityAssociationEntry, nat_port) == 0x4c);
    assert!(size_of::<SecurityAssociationEntry>() == 0x78);
    assert!(core::mem::offset_of!(QosLookupEntry, retry) == 0x13);
    assert!(core::mem::offset_of!(QosLookupEntry, bits_per_second) == 0x28);
    assert!(core::mem::offset_of!(QosLookupEntry, xnkid) == 0x2c);
    assert!(core::mem::offset_of!(QosLookupEntry, xnaddr) == 0x34);
    assert!(size_of::<QosLookupEntry>() == 0x88);
};

/// Platform state of this domain.
pub struct Data {
    snapshots: [Option<Snapshot>; MAX_CONNECTIONS],
    pub netcap: netcap::Data,
    pub ipproxy: ipproxy::Data,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            snapshots: [const { None }; MAX_CONNECTIONS],
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
            snapshot.free();
        }
    }
}

impl network::Backend for Console {
    fn system_version(&mut self) -> SystemVersion {
        SystemVersion(xam::XamGetSystemVersion())
    }

    fn open_table(&mut self, connection: ConnectionIndex, table: Table) -> Result<u32, TableError> {
        self.network.release(connection);

        let snapshot = take_snapshot(table)?;

        match self.network.snapshots.get_mut(usize::from(connection.0)) {
            // The slot was emptied by `release`.
            Some(slot) => Ok(slot.insert(snapshot).count),
            None => {
                snapshot.free();
                Err(TableError::OutOfMemory)
            }
        }
    }

    fn table_record(&mut self, connection: ConnectionIndex, index: u32) -> Option<Record> {
        self.network
            .snapshots
            .get(usize::from(connection.0))?
            .as_ref()?
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
        let mut block = NicStatistics::default();
        // SAFETY: the device flags are the caller's, as stock passes them.
        unsafe { xboxkrnl::nic_get_stats(device_flags, &mut block) };

        NicStats {
            transmitted_bytes: block.transmitted_bytes,
            received_unicast_bytes: block.received_unicast_bytes,
            received_unicast1_bytes: block.received_unicast1_bytes,
            received_unicast2_bytes: block.received_unicast2_bytes,
            received_multicast_bytes: block.received_multicast_bytes,
            received_broadcast_bytes: block.received_broadcast_bytes,
            transmitted_frames: block.transmitted_frames,
            received_unicast_frames: block.received_unicast_frames,
            received_unicast1_frames: block.received_unicast1_frames,
            received_unicast2_frames: block.received_unicast2_frames,
            received_multicast_frames: block.received_multicast_frames,
            received_broadcast_frames: block.received_broadcast_frames,
            transmit_underrun_errors: block.transmit_underrun_errors,
            transmit_other_errors: block.transmit_other_errors,
            receive_frame_errors: block.receive_frame_errors,
            receive_crc_errors: block.receive_crc_errors,
            receive_other_errors: block.receive_other_errors,
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

    dispatcher::request_settings_write();

    target.load(Ordering::SeqCst)
}

/// Control code 0x0b (stock 0x91f3b2c8): configure the network stack with
/// the static address (when enabled) and the debug name as host name. The
/// address configuration is read through the dispatcher, so extensions see
/// the queries.
pub(crate) fn service_apply_xnet_config(_argument: u32) -> u32 {
    /// `XnpConfig` flags of a static address, subnet, and gateway; stock sets
    /// both bits together.
    const STATIC_ADDRESS: XnetConfigFlags = XnetConfigFlags::from_bits_retain(0xc);

    // SAFETY: the address queries take no argument.
    let query = |code: ControlCode| unsafe { dispatcher::dispatch(code, 0) };

    for word in &CONFIG_STATUS {
        word.store(0, Ordering::Relaxed);
    }

    let mut config = XnetConfigParams::new();
    if query(ControlCode::GET_STATIC_IP_ENABLE) != 0 {
        config.flags = STATIC_ADDRESS;
        config.address = query(ControlCode::GET_STATIC_IP_ADDRESS);
        config.subnet = query(ControlCode::GET_SUBNET);
        config.gateway = query(ControlCode::GET_GATEWAY);
    }

    let name = crate::backend::console::debug_name();
    let name = name.as_bytes();
    config.host_name[..name.len()].copy_from_slice(name);

    // The dispatcher case discards the result (0x91f3bb10).
    // SAFETY: the debug monitor caller with flags 0, as stock passes them.
    unsafe { xam::xnp_config(crate::net::CALLER, &config, 0) };

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

/// Query the configuration status and return its word `index` (stock
/// cases 0x14..0x16).
fn config_status_word(index: usize) -> u32 {
    // SAFETY: the status words are static storage of at least the 0x3a
    // bytes the network stack writes; atomics allow the shared writes.
    unsafe {
        NetDll_XnpGetConfigStatus(
            crate::net::CALLER,
            CONFIG_STATUS.as_ptr().cast::<u8>().cast_mut(),
        )
    };

    CONFIG_STATUS[index].load(Ordering::Relaxed)
}

pub(crate) fn service_config_status_1(_argument: u32) -> u32 {
    config_status_word(1)
}

pub(crate) fn service_config_status_2(_argument: u32) -> u32 {
    config_status_word(2)
}

pub(crate) fn service_config_status_3(_argument: u32) -> u32 {
    config_status_word(3)
}

/// Address of a `xam.xex` export (stock 0x91f31010 handle and
/// `XexGetProcedureAddress`; any success status counts).
pub(crate) fn xam_procedure(ordinal: Ordinal) -> Option<u32> {
    let module = SystemModule::Xam.handle().ok()?;

    let mut address = 0u32;
    // SAFETY: `module` is the loaded xam.xex handle and `address` is a live u32.
    let status = unsafe {
        xboxkrnl::XexGetProcedureAddress(module.raw(), u32::from(ordinal.get()), &mut address)
    };

    status.is_success().then_some(address)
}

/// Decode one table record.
///
/// # Safety
/// `record` points at a whole, 4-aligned record of `table`.
unsafe fn decode(table: Table, record: *const u8) -> Record {
    match table {
        Table::Sockets => {
            // SAFETY: guaranteed by the caller.
            let entry = unsafe { &*record.cast::<SocketEntry>() };
            Record::Socket(SocketRecord {
                handle: entry.handle,
                owner_type: entry.owner_type,
                flags: entry.flags,
                address_family: entry.address_family,
                socket_type: entry.socket_type,
                protocol: entry.protocol,
                local_address: entry.local_address,
                remote_address: entry.remote_address,
                local_port: entry.local_port,
                remote_port: entry.remote_port,
                tcp_state: entry.tcp_state,
            })
        }
        Table::Keys => {
            // SAFETY: guaranteed by the caller.
            let entry = unsafe { &*record.cast::<KeyEntry>() };
            Record::Key(KeyRecord {
                xnkid: Xnkid(entry.xnkid),
                owner_type: entry.owner_type,
                flags: entry.flags,
                qos_data_size: entry.qos_data_size,
                qos_bits_per_second: entry.qos_bits_per_second,
            })
        }
        Table::SecurityAssociations => {
            // SAFETY: guaranteed by the caller.
            let entry = unsafe { &*record.cast::<SecurityAssociationEntry>() };
            Record::SecurityAssociation(SecurityAssociationRecord {
                secure_address: entry.secure_address,
                owner_type: entry.owner_type,
                flags: entry.flags,
                xnkid: Xnkid(entry.xnkid),
                xnaddr: XnAddr(entry.xnaddr),
                service_id: entry.service_id,
                remote_address: entry.remote_address,
                remote_port: entry.remote_port,
                state: entry.state,
                nat_address: entry.nat_address,
                nat_port: entry.nat_port,
            })
        }
        Table::QosLookups => {
            // SAFETY: guaranteed by the caller.
            let entry = unsafe { &*record.cast::<QosLookupEntry>() };
            Record::QosLookup(QosLookupRecord {
                owner_type: entry.owner_type,
                flags: entry.flags,
                target_address: entry.target_address,
                target_port: entry.target_port,
                state: entry.state,
                retry: entry.retry,
                secure_address: entry.secure_address,
                probes_requested: entry.probes_requested,
                probes_sent: entry.probes_sent,
                probes_received: entry.probes_received,
                data_received: entry.data_received,
                bits_per_second: entry.bits_per_second,
                xnkid: Xnkid(entry.xnkid),
                xnaddr: XnAddr(entry.xnaddr),
            })
        }
    }
}

/// XAM ordinal of a table query `fn(caller, buffer, &count) -> u32`.
fn table_ordinal(table: Table) -> Option<Ordinal> {
    match table {
        Table::Sockets => None,
        Table::SecurityAssociations => Some(ordinal::XNP_GET_SEC_ASSOC_LIST),
        Table::Keys => Some(ordinal::XNP_GET_KEY_LIST),
        Table::QosLookups => Some(ordinal::XNP_GET_QOS_LOOKUP_LIST),
    }
}

/// Run a table query; the result is a Winsock error code.
fn query(function: Option<u32>, buffer: u32, count: &mut u32) -> Result<(), Win32Error> {
    let code = match function {
        // SAFETY: XAM table queries take (caller, buffer, count pointer).
        Some(function) => unsafe {
            kernel::call_export(
                function,
                crate::net::CALLER.raw(),
                buffer,
                count as *mut u32 as usize as u32,
                0,
            )
        },
        // SAFETY: `buffer` holds `count` socket records; `count` is a live u32.
        None => unsafe {
            NetDll_XnpGetActiveSocketList(crate::net::CALLER, buffer as usize as *mut u8, count)
        },
    };

    Win32Error::result(code)
}

/// Copy a table into a new pool buffer, following the stock capacities.
fn take_snapshot(table: Table) -> Result<Snapshot, TableError> {
    const SOCKET_CAPACITY: u32 = 0x800;
    /// Capacity for keys or security associations.
    const ENTRY_CAPACITY: u32 = 0x400;

    let function = match table_ordinal(table) {
        Some(ordinal) => Some(xam_procedure(ordinal).ok_or(TableError::Unavailable)?),
        None => None,
    };

    let mut count = match table {
        Table::Sockets => SOCKET_CAPACITY,
        Table::Keys | Table::SecurityAssociations => ENTRY_CAPACITY,
        // The reported number of lookups plus one; an empty buffer reports
        // `WSAENOBUFS`.
        Table::QosLookups => {
            let mut count = 0u32;
            match query(function, 0, &mut count) {
                Ok(()) | Err(Win32Error::NO_BUFFER_SPACE) => {}
                Err(_) => return Err(TableError::Unavailable),
            }

            count.wrapping_add(1)
        }
    };

    // SAFETY: pool allocation of a computed size; the result is checked below.
    let buffer = unsafe {
        xboxkrnl::ExAllocatePoolWithTag(
            count.wrapping_mul(Snapshot::record_size(table)),
            pool_tag::MONITOR,
        )
    };

    if buffer == 0 {
        return Err(TableError::OutOfMemory);
    }

    if query(function, buffer, &mut count).is_err() {
        // SAFETY: `buffer` was allocated above and is not used afterwards.
        unsafe { xboxkrnl::ExFreePool(buffer) };
        return Err(TableError::Unavailable);
    }

    Ok(Snapshot {
        table,
        buffer,
        count,
    })
}

/// Ethernet link state (`XNetGetEthernetLinkStatus`); any thread.
pub(crate) fn link_status() -> LinkStatus {
    LinkStatus(NetDll_XNetGetEthernetLinkStatus(XnCaller::SystemApp).bits())
}

/// Force link state bits through `XNetSetOpt`; any thread.
pub(crate) fn set_link_flags(flags: LinkFlags) -> Result<(), WsaError> {
    let mut value = [0u8; 8];
    value[..4].copy_from_slice(&flags.and.to_be_bytes());
    value[4..].copy_from_slice(&flags.or.to_be_bytes());

    // SAFETY: `value` is a live 8-byte option buffer of the stated length.
    let error = unsafe {
        NetDll_XNetSetOpt(
            XnCaller::SystemApp,
            XnetOption::LINK_FLAGS,
            value.as_ptr(),
            value.len() as u32,
        )
    };

    WsaError::new(error).map_or(Ok(()), Err)
}
