//! Simulated network stack.

pub mod ipproxy;
pub mod netcap;
pub mod netsim;
pub mod xhttpproxy;

use std::collections::HashMap;

use openxbdm_server::ConnectionIndex;
use openxbdm_server::commands::network;
use openxbdm_server::commands::network::AddressField;
use openxbdm_server::commands::network::AddressSettings;
use openxbdm_server::commands::network::LinkFlags;
use openxbdm_server::commands::network::LinkStatus;
use openxbdm_server::commands::network::NicStats;
use openxbdm_server::commands::network::Record;
use openxbdm_server::commands::network::SystemVersion;
use openxbdm_server::commands::network::Table;
use openxbdm_server::commands::network::TableError;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::network::Ipv4Address;

use super::MockBackend;

/// Simulated state of this domain.
#[derive(Debug)]
pub struct Mock {
    pub system_version: SystemVersion,

    pub sockets: Vec<network::SocketRecord>,
    pub keys: Vec<network::KeyRecord>,
    pub security_associations: Vec<network::SecurityAssociationRecord>,
    pub qos_lookups: Vec<network::QosLookupRecord>,
    /// Tables the network stack does not provide.
    pub unavailable: Vec<Table>,
    /// Tables whose snapshot fails for lack of memory.
    pub exhausted: Vec<Table>,
    /// Snapshots held for connections.
    pub snapshots: HashMap<u8, Vec<Record>>,

    /// Link status bits before the forcing masks.
    pub link_status: u32,
    /// Forcing masks in effect.
    pub link_flags: LinkFlags,
    /// Result of the next `set_link_flags` call.
    pub link_error: Option<WsaError>,
    pub nic_stats: NicStats,
    /// `device_flags` of each `nic_stats` call.
    pub nic_queries: Vec<u32>,
    pub address: AddressSettings,

    pub netcap: netcap::Mock,
    pub netsim: netsim::Mock,
    pub ipproxy: ipproxy::Mock,
    pub xhttpproxy: xhttpproxy::Mock,
}

impl Default for Mock {
    fn default() -> Self {
        /// System version of the simulated console: the newest gate in this
        /// domain (`netsim`, 0x20278700) passes.
        const SYSTEM_VERSION: SystemVersion = SystemVersion(0x2047_4800);
        /// Link status of the simulated adapter: link up.
        const LINK_STATUS: u32 = 0x0000_0001;

        Self {
            system_version: SYSTEM_VERSION,
            sockets: Vec::new(),
            keys: Vec::new(),
            security_associations: Vec::new(),
            qos_lookups: Vec::new(),
            unavailable: Vec::new(),
            exhausted: Vec::new(),
            snapshots: HashMap::new(),
            link_status: LINK_STATUS,
            link_flags: LinkFlags::RESTORE,
            link_error: None,
            nic_stats: NicStats::default(),
            nic_queries: Vec::new(),
            address: AddressSettings::default(),
            netcap: netcap::Mock::default(),
            netsim: netsim::Mock::default(),
            ipproxy: ipproxy::Mock::default(),
            xhttpproxy: xhttpproxy::Mock::default(),
        }
    }
}

impl Mock {
    fn records(&self, table: Table) -> Vec<Record> {
        match table {
            Table::Sockets => self.sockets.iter().copied().map(Record::Socket).collect(),
            Table::Keys => self.keys.iter().copied().map(Record::Key).collect(),
            Table::SecurityAssociations => self
                .security_associations
                .iter()
                .copied()
                .map(Record::SecurityAssociation)
                .collect(),
            Table::QosLookups => self
                .qos_lookups
                .iter()
                .copied()
                .map(Record::QosLookup)
                .collect(),
        }
    }
}

impl network::Backend for MockBackend {
    fn system_version(&mut self) -> SystemVersion {
        self.network.system_version
    }

    fn open_table(&mut self, connection: ConnectionIndex, table: Table) -> Result<u32, TableError> {
        let mock = &mut self.network;
        if mock.unavailable.contains(&table) {
            return Err(TableError::Unavailable);
        }
        if mock.exhausted.contains(&table) {
            return Err(TableError::OutOfMemory);
        }

        let records = mock.records(table);
        let count = records.len() as u32;
        mock.snapshots.insert(connection.0, records);

        Ok(count)
    }

    fn table_record(&mut self, connection: ConnectionIndex, index: u32) -> Option<Record> {
        self.network
            .snapshots
            .get(&connection.0)?
            .get(index as usize)
            .copied()
    }

    fn close_table(&mut self, connection: ConnectionIndex) {
        self.network.snapshots.remove(&connection.0);
    }

    fn link_status(&mut self) -> LinkStatus {
        let LinkFlags { and, or } = self.network.link_flags;
        LinkStatus((self.network.link_status & and) | or)
    }

    fn set_link_flags(&mut self, flags: LinkFlags) -> Result<(), WsaError> {
        if let Some(error) = self.network.link_error.take() {
            return Err(error);
        }

        self.network.link_flags = flags;

        Ok(())
    }

    fn nic_stats(&mut self, device_flags: u32) -> NicStats {
        self.network.nic_queries.push(device_flags);

        self.network.nic_stats
    }

    fn address_settings(&mut self) -> AddressSettings {
        self.network.address
    }

    fn set_address_field(&mut self, field: AddressField, value: u32) {
        let address = &mut self.network.address;
        match field {
            AddressField::UseStatic => address.use_static = value,
            AddressField::Address => address.address = Ipv4Address(value.to_be_bytes()),
            AddressField::Subnet => address.subnet = Ipv4Address(value.to_be_bytes()),
            AddressField::Gateway => address.gateway = Ipv4Address(value.to_be_bytes()),
        }
    }
}
