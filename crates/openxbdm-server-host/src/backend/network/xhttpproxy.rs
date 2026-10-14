//! Simulated proxy list.

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;
use openxbdm_server::commands::network::decode_hex;
use openxbdm_server::commands::network::xhttpproxy;
use openxbdm_server::commands::network::xhttpproxy::Certificate;
use openxbdm_server::commands::network::xhttpproxy::Inserted;
use openxbdm_server::commands::network::xhttpproxy::NAME_CAPACITY;
use openxbdm_server::commands::network::xhttpproxy::NewProxy;
use openxbdm_server::commands::network::xhttpproxy::ProxyEntry;
use openxbdm_server::commands::network::xhttpproxy::ProxyFlags;
use openxbdm_server::commands::network::xhttpproxy::ProxyId;
use openxbdm_server::commands::network::xhttpproxy::ProxyOutcome;

use crate::backend::MockBackend;
use crate::backend::POOL_LIMIT;

/// One proxy entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: ProxyId,
    pub flags: ProxyFlags,
    pub references: u32,
    pub name: Option<Vec<u8>>,
    pub port: u32,
    pub certificate: Vec<u8>,
}

/// Simulated state of `xhttpproxy`.
#[derive(Debug, Default)]
pub struct Mock {
    /// Entries, oldest first; the newest entry is the list head.
    pub entries: Vec<Entry>,
    /// Fail the next entry allocation.
    pub fail_allocation: bool,
    next_id: u32,
}

impl Mock {
    fn position(&self, id: ProxyId) -> Option<usize> {
        self.entries.iter().position(|entry| entry.id == id)
    }

    /// Title consumers do not exist on the host, so references alone keep
    /// an entry.
    fn release_if_unused(&mut self, position: usize) {
        if self.entries[position].references == 0 {
            self.entries.remove(position);
        }
    }

    /// Stock 0x91f37800 for the command: the newest active entry whose
    /// system bit equals `sys`.
    fn active(&self, sys: bool) -> Option<usize> {
        self.entries.iter().rposition(|entry| {
            entry.flags.contains(ProxyFlags::ACTIVE) && entry.flags.contains(ProxyFlags::SYS) == sys
        })
    }
}

impl xhttpproxy::Backend for MockBackend {
    fn proxy_update(&mut self, sys: bool, new: Option<&NewProxy<'_>>) -> ProxyOutcome {
        let mock = &mut self.network.xhttpproxy;
        let cleared = mock.active(sys).map(|position| {
            let entry = &mut mock.entries[position];
            let flags = entry.flags;
            entry.flags.0 &= !ProxyFlags::ACTIVE;
            entry.references -= 1;
            mock.release_if_unused(position);
            flags
        });
        let Some(new) = new else {
            return ProxyOutcome {
                cleared,
                inserted: None,
            };
        };
        let certificate_size = match new.certificate {
            Certificate::None => 0,
            Certificate::Hex { size, .. } | Certificate::Upload { size } => size,
        };
        if std::mem::take(&mut mock.fail_allocation) || certificate_size > POOL_LIMIT {
            let error = Hresult::from_error_code(ErrorCode::OUT_OF_MEMORY);
            return ProxyOutcome {
                cleared,
                inserted: Some(Err(error)),
            };
        }
        mock.next_id += 1;
        let id = ProxyId(mock.next_id);
        let mut entry = Entry {
            id,
            flags: new.flags,
            references: 1,
            name: new.name.map(<[u8]>::to_vec),
            port: new.port,
            certificate: Vec::new(),
        };
        let inserted = match new.certificate {
            Certificate::None => Ok(Inserted::Applied),
            Certificate::Hex { text, size } => {
                let mut certificate = vec![0u8; size as usize];
                match decode_hex(text, &mut certificate) {
                    Some(count) if count == size as usize => {
                        entry.certificate = certificate;
                        Ok(Inserted::Applied)
                    }
                    _ => Err(Hresult::from_error_code(ErrorCode::UNKNOWN_COMMAND)),
                }
            }
            Certificate::Upload { size } => {
                entry.certificate = vec![0u8; size as usize];
                entry.flags.0 |= ProxyFlags::CERTIFICATE_PENDING;
                entry.references += 1;
                Ok(Inserted::Pending(id))
            }
        };
        if inserted.is_ok() {
            mock.entries.push(entry);
        }
        ProxyOutcome {
            cleared,
            inserted: Some(inserted),
        }
    }

    fn proxy_write_certificate(&mut self, id: ProxyId, offset: u32, bytes: &[u8]) {
        let mock = &mut self.network.xhttpproxy;
        if let Some(position) = mock.position(id) {
            let offset = offset as usize;
            mock.entries[position].certificate[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
    }

    fn proxy_upload_complete(&mut self, id: ProxyId) -> Option<ProxyFlags> {
        let mock = &mut self.network.xhttpproxy;
        let position = mock.position(id)?;
        let entry = &mut mock.entries[position];
        entry.flags.0 &= !ProxyFlags::CERTIFICATE_PENDING;
        entry.references -= 1;
        let flags = entry.flags;
        mock.release_if_unused(position);
        Some(flags)
    }

    /// The host engine is single-threaded.
    fn proxy_lock(&mut self) {}

    fn proxy_unlock(&mut self) {}

    fn proxy_upload_aborted(&mut self, id: ProxyId) {
        let mock = &mut self.network.xhttpproxy;
        let Some(position) = mock.position(id) else {
            return;
        };
        let entry = &mut mock.entries[position];
        entry.references -= 1;
        if entry.flags.contains(ProxyFlags::ACTIVE) {
            entry.flags.0 &= !ProxyFlags::ACTIVE;
            entry.references -= 1;
        }
        mock.release_if_unused(position);
    }

    fn proxy_entry(&mut self, position: usize) -> Option<ProxyEntry> {
        let entry = self.network.xhttpproxy.entries.get(position)?;
        let mut name = [0u8; NAME_CAPACITY];
        let name_len = entry.name.as_ref().map(|stored| {
            name[..stored.len()].copy_from_slice(stored);
            stored.len()
        });
        Some(ProxyEntry {
            id: entry.id,
            flags: entry.flags,
            name_len,
            name,
            port: entry.port,
            certificate_size: entry.certificate.len() as u32,
        })
    }

    fn proxy_read_certificate(&mut self, id: ProxyId, offset: u32, output: &mut [u8]) {
        let mock = &self.network.xhttpproxy;
        if let Some(position) = mock.position(id) {
            let offset = offset as usize;
            output.copy_from_slice(
                &mock.entries[position].certificate[offset..offset + output.len()],
            );
        }
    }

    fn proxy_title_exited(&mut self) {
        let mock = &mut self.network.xhttpproxy;
        for entry in &mut mock.entries {
            let flags = entry.flags;
            if !flags.contains(ProxyFlags::SYS)
                && flags.contains(ProxyFlags::ACTIVE)
                && flags.contains(ProxyFlags::TEMP)
            {
                entry.flags.0 &= !ProxyFlags::ACTIVE;
                entry.references -= 1;
            }
        }
        mock.entries.retain(|entry| entry.references != 0);
    }
}
