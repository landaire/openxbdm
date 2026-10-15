//! `xhttpproxy`: HTTP proxy settings for the title and system scopes.
//!
//! The entries live in platform memory because title code receives
//! pointers into them; the list keeps stock order (new entries at the head,
//! settings written from the tail).

use core::fmt::Write as _;

use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use crate::backend::Backend as AnyBackend;
use crate::commands::network::Continuation;
use crate::commands::system;
use crate::commands::system::SettingsFile;
use crate::continuation::Continuation as AnyContinuation;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::state::ServerState;
use crate::text::HEX_UPPER;

/// Bytes copied from `name=`, including the terminator.
pub const NAME_CAPACITY: usize = 0x100;
/// Certificate bytes per hex chunk of a settings line.
const SETTINGS_CHUNK: u32 = 0x1ff;
/// Result of a certificate upload cut short by the connection.
const UPLOAD_ABORTED: Hresult = Hresult(0x82da_0101);

/// Flag bits of a proxy entry, as stored by the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyFlags(pub u32);

impl ProxyFlags {
    /// Entry of the system scope.
    pub const SYS: u32 = 0x8000_0000;
    /// System entry hidden from title queries.
    pub const SYS_ONLY: u32 = 0x4000_0000;
    pub const ACTIVE: u32 = 0x2000_0000;
    /// Not written to the settings file.
    pub const TEMP: u32 = 0x1000_0000;
    pub const FORCE: u32 = 0x0800_0000;
    /// The certificate upload has not finished.
    pub const CERTIFICATE_PENDING: u32 = 0x0400_0000;

    pub const fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }
}

/// Platform handle of a proxy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyId(pub u32);

/// Certificate of a new entry.
#[derive(Debug, Clone, Copy)]
pub enum Certificate<'a> {
    None,
    /// Hex text of the `cert=` value, decoded into `size` bytes.
    Hex {
        text: &'a [u8],
        size: u32,
    },
    /// `size` bytes follow as a 204 upload.
    Upload {
        size: u32,
    },
}

/// A new entry.
#[derive(Debug, Clone, Copy)]
pub struct NewProxy<'a> {
    pub flags: ProxyFlags,
    /// Host name without terminator; `None` stores no name.
    pub name: Option<&'a [u8]>,
    pub port: u32,
    pub certificate: Certificate<'a>,
}

/// Outcome of a new entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inserted {
    /// The entry is active and complete.
    Applied,
    /// The entry is active and holds an extra reference until the upload
    /// completes.
    Pending(ProxyId),
}

/// Result of [`Backend::proxy_update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyOutcome {
    /// Flags of the entry that was deactivated, if any.
    pub cleared: Option<ProxyFlags>,
    /// `None` when no entry was requested.
    pub inserted: Option<Result<Inserted, Hresult>>,
}

/// One entry as the settings writer reads it.
#[derive(Debug, Clone, Copy)]
pub struct ProxyEntry {
    pub id: ProxyId,
    pub flags: ProxyFlags,
    /// Name length without terminator; `None` when the entry has no name.
    pub name_len: Option<usize>,
    pub name: [u8; NAME_CAPACITY],
    pub port: u32,
    pub certificate_size: u32,
}

/// Platform services `xhttpproxy` needs. Each call is atomic with respect
/// to title code reading the list.
pub trait Backend {
    /// Deactivate the active entry whose system bit equals `sys` (dropping
    /// its active reference, freeing it when unreferenced), then insert
    /// `new` at the head as active with one reference. Certificate hex is
    /// decoded with [`super::decode_hex`]; a bad certificate unlinks and frees the
    /// new entry and yields 0x82da0007; no memory yields 0x82da001c.
    fn proxy_update(&mut self, sys: bool, new: Option<&NewProxy<'_>>) -> ProxyOutcome;
    /// Copy uploaded certificate bytes at `offset`.
    fn proxy_write_certificate(&mut self, id: ProxyId, offset: u32, bytes: &[u8]);
    /// The upload finished: clear the pending bit and drop the upload
    /// reference. Returns the entry's flags; `None` when title code
    /// released the entry during the upload.
    fn proxy_upload_complete(&mut self, id: ProxyId) -> Option<ProxyFlags>;
    /// The upload was cut short: drop the upload reference and, when the
    /// entry is still active, deactivate it.
    fn proxy_upload_aborted(&mut self, id: ProxyId);
    /// Hold the list lock across several calls (recursive), as the settings
    /// writer does for its whole walk.
    fn proxy_lock(&mut self);
    fn proxy_unlock(&mut self);
    /// Entry `position` counted from the tail (oldest first).
    fn proxy_entry(&mut self, position: usize) -> Option<ProxyEntry>;
    /// Copy certificate bytes from `offset` into `output`.
    fn proxy_read_certificate(&mut self, id: ProxyId, offset: u32, output: &mut [u8]);
    /// The title process ended: reset consumer counts and deactivate
    /// temporary title entries (stock 0x91f37860).
    fn proxy_title_exited(&mut self);
}

/// `xhttpproxy [name=<str> [port=<dword>] [certsize=<dword>] [cert=<hex>]]
/// [sys | sysonly] [force] [temp]`: replace the proxy of a scope.
pub(super) fn xhttpproxy(invocation: &mut Invocation<'_>) -> Hresult {
    let line = invocation.line;
    let mut name_buffer = [0u8; NAME_CAPACITY];
    let (name, certificate_size) = match line.param("name") {
        None => (None, 0),
        Some(value) => {
            let name = value.copy_into(&mut name_buffer);
            let port = line.dword("port").unwrap_or(0);
            let valid = if name.is_empty() {
                port == 0
            } else {
                (1..=0xffff).contains(&port)
            };
            if !valid {
                return Hresult::from_error_code(ErrorCode::BAD_PARAMETER);
            }
            let certificate_size = line.dword("certsize").unwrap_or(0);
            // An empty name stores no name, as a missing one does.
            ((!name.is_empty()).then_some((name, port)), certificate_size)
        }
    };
    let sys_only = line.has("sysonly");
    let sys = sys_only || line.has("sys");
    let force = line.has("force");
    let temp = line.has("temp");

    let mut flags = ProxyFlags::ACTIVE;
    for (set, bit) in [
        (sys, ProxyFlags::SYS),
        (sys_only, ProxyFlags::SYS_ONLY),
        (temp, ProxyFlags::TEMP),
        (force, ProxyFlags::FORCE),
    ] {
        if set {
            flags |= bit;
        }
    }
    let new = (name.is_some() || force).then(|| {
        let certificate = if certificate_size == 0 {
            Certificate::None
        } else {
            match line.param("cert") {
                Some(value) => {
                    let text = value.raw();
                    let text = text.strip_prefix(b"\"").unwrap_or(text);
                    Certificate::Hex {
                        text,
                        size: certificate_size,
                    }
                }
                None => Certificate::Upload {
                    size: certificate_size,
                },
            }
        };
        NewProxy {
            flags: ProxyFlags(flags),
            name: name.map(|(name, _)| name),
            port: name.map_or(0, |(_, port)| port),
            certificate,
        }
    });

    let outcome = invocation.backend.proxy_update(sys, new.as_ref());
    let mut settings_changed = outcome
        .cleared
        .is_some_and(|cleared| !cleared.contains(ProxyFlags::TEMP));
    let (result, applied) = match outcome.inserted {
        None => (Hresult::OK, ""),
        Some(Err(error)) => (error, ""),
        Some(Ok(Inserted::Applied)) => {
            settings_changed |= !temp;
            (Hresult::OK, " applied")
        }
        Some(Ok(Inserted::Pending(id))) => match invocation.session.as_deref_mut() {
            Some(session) => {
                session.receive_remaining = Some(certificate_size);
                session.continuation = AnyContinuation::Network(Continuation::ProxyCertificate {
                    id,
                    received: 0,
                    size: certificate_size,
                });
                (Hresult::SEND_BINARY, " applying")
            }
            // Stock stores the upload state through the missing context;
            // without a connection the entry cannot receive its certificate.
            None => {
                invocation.backend.proxy_upload_aborted(id);
                (Hresult::FAIL, "")
            }
        },
    };
    if settings_changed && invocation.session.is_some() {
        invocation.state.settings_dirty = true;
    }
    let cleared = if outcome.cleared.is_some() {
        "cleared"
    } else {
        ""
    };
    if result.is_failure() {
        invocation.set_text(format_args!("err=0x{:08x} {cleared}{applied}", result.0));
    } else {
        invocation.set_text(format_args!("{cleared}{applied}"));
    }
    result
}

/// Receive the certificate of a pending entry.
pub(super) fn receive_certificate(
    id: ProxyId,
    received: &mut u32,
    size: u32,
    cx: &mut ContinuationContext<'_>,
) -> Hresult {
    if cx.received.is_empty() {
        cx.backend.proxy_upload_aborted(id);
        cx.session.receive_remaining = Some(0);
        return UPLOAD_ABORTED;
    }
    let count = (cx.received.len() as u32).min(size - *received);
    cx.backend
        .proxy_write_certificate(id, *received, &cx.received[..count as usize]);
    *received += count;
    let remaining = size - *received;
    cx.session.receive_remaining = Some(remaining);
    if remaining != 0 {
        return Hresult::OK;
    }
    if cx
        .backend
        .proxy_upload_complete(id)
        .is_some_and(|flags| !flags.contains(ProxyFlags::TEMP))
    {
        cx.state.settings_dirty = true;
    }
    Hresult::OK
}

/// Settings lines of active, persistent, complete entries (stock
/// 0x91f37f18), oldest first.
pub(crate) fn settings_lines(
    _state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    backend.proxy_lock();
    write_entries(backend, file);
    backend.proxy_unlock();
}

fn write_entries(backend: &mut dyn AnyBackend, file: SettingsFile) {
    let mut position = 0;
    while let Some(entry) = backend.proxy_entry(position) {
        position += 1;
        let flags = entry.flags;
        if !flags.contains(ProxyFlags::ACTIVE)
            || flags.contains(ProxyFlags::TEMP)
            || flags.contains(ProxyFlags::CERTIFICATE_PENDING)
        {
            continue;
        }
        let scope = if !flags.contains(ProxyFlags::SYS) {
            ""
        } else if flags.contains(ProxyFlags::SYS_ONLY) {
            " sysonly"
        } else {
            " sys"
        };
        let force = if flags.contains(ProxyFlags::FORCE) {
            " force"
        } else {
            ""
        };
        let Some(name_len) = entry.name_len else {
            system::write_line(backend, file, format_args!("xhttpproxy{scope}{force}"));
            continue;
        };
        // Stock formats the line up to the certificate into one 0x400-byte
        // buffer, so the settings trace echoes it once.
        let mut line = crate::text::Text::<0x3ff>::new();
        let _ = write!(line, "xhttpproxy{scope} name=\"");
        let _ = line.push_bytes(&entry.name[..name_len]);
        let _ = write!(line, "\" port={}{force}", entry.port);
        if entry.certificate_size == 0 {
            system::write_bytes(backend, file, line.as_bytes());
            system::end_line(backend, file);
            continue;
        }
        let _ = write!(line, " certsize={} cert=", entry.certificate_size);
        system::write_bytes(backend, file, line.as_bytes());
        let mut offset = 0;
        while offset < entry.certificate_size {
            let count = (entry.certificate_size - offset).min(SETTINGS_CHUNK);
            let mut bytes = [0u8; SETTINGS_CHUNK as usize];
            let bytes = &mut bytes[..count as usize];
            backend.proxy_read_certificate(entry.id, offset, bytes);
            let mut hex = [0u8; 2 * SETTINGS_CHUNK as usize];
            for (index, &byte) in bytes.iter().enumerate() {
                hex[2 * index] = HEX_UPPER[usize::from(byte >> 4)];
                hex[2 * index + 1] = HEX_UPPER[usize::from(byte & 0xf)];
            }
            system::write_bytes(backend, file, &hex[..2 * count as usize]);
            offset += count;
        }
        system::end_line(backend, file);
    }
}

/// Settings-file `xhttpproxy` line.
pub(crate) fn ini_xhttpproxy(invocation: &mut Invocation<'_>) {
    let _ = xhttpproxy(invocation);
}
