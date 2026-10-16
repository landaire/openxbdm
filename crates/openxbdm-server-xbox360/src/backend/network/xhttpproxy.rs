//! Proxy list in pool memory with the stock entry layout, guarded by a
//! critical section so title threads can read it.

use core::ptr::addr_of_mut;
use core::ptr::null_mut;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::network::decode_hex;
use openxbdm_server::commands::network::xhttpproxy;
use openxbdm_server::commands::network::xhttpproxy::Certificate;
use openxbdm_server::commands::network::xhttpproxy::Inserted;
use openxbdm_server::commands::network::xhttpproxy::NAME_CAPACITY;
use openxbdm_server::commands::network::xhttpproxy::NewProxy;
use openxbdm_server::commands::network::xhttpproxy::ProxyEntry;
use openxbdm_server::commands::network::xhttpproxy::ProxyError;
use openxbdm_server::commands::network::xhttpproxy::ProxyFlags;
use openxbdm_server::commands::network::xhttpproxy::ProxyId;
use openxbdm_server::commands::network::xhttpproxy::ProxyOutcome;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::PoolTag;

use crate::backend::Console;
use crate::kernel::CriticalSection;

/// Pool tag of proxy entries (`HPXY`).
const PROXY_TAG: PoolTag = PoolTag::new(*b"HPXY");

/// Entry header; name and certificate storage follow it.
#[repr(C)]
struct Entry {
    flink: *mut Entry,
    blink: *mut Entry,
    flags: u32,
    references: u32,
    consumers: u32,
    name: *mut u8,
    port: u32,
    certificate: *mut u8,
    certificate_size: u32,
}

/// List sentinel; only the links are used.
static mut HEAD: Entry = Entry {
    flink: null_mut(),
    blink: null_mut(),
    flags: 0,
    references: 0,
    consumers: 0,
    name: null_mut(),
    port: 0,
    certificate: null_mut(),
    certificate_size: 0,
};
static LOCK: CriticalSection = CriticalSection::new();
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Holds the list lock inside a critical region.
struct Guard;

/// Set up the list and its lock before any thread can reach them (stock
/// initializes both during monitor startup).
pub(crate) fn initialize() {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }
    let head = addr_of_mut!(HEAD);
    // SAFETY: runs once at module load, before the control codes and the
    // server thread exist.
    unsafe {
        (*head).flink = head;
        (*head).blink = head;
    }
    LOCK.initialize();
}

impl Guard {
    fn acquire() -> Self {
        LOCK.enter();
        Self
    }

    fn head(&self) -> *mut Entry {
        addr_of_mut!(HEAD)
    }

    /// Entries from the head (newest first).
    fn iter(&self) -> impl Iterator<Item = *mut Entry> + '_ {
        let head = self.head();
        // SAFETY: the list is consistent while the lock is held.
        let mut current = unsafe { (*head).flink };
        core::iter::from_fn(move || {
            if current == head {
                return None;
            }
            let entry = current;
            // SAFETY: as above.
            current = unsafe { (*entry).flink };
            Some(entry)
        })
    }

    /// Stock 0x91f37800 for the command: same system bit, active.
    fn active(&self, sys: bool) -> Option<*mut Entry> {
        // SAFETY: entries are valid while the lock is held.
        self.iter().find(|&entry| unsafe {
            let flags = ProxyFlags((*entry).flags);
            flags.contains(ProxyFlags::ACTIVE) && flags.contains(ProxyFlags::SYS) == sys
        })
    }

    fn find(&self, id: ProxyId) -> Option<*mut Entry> {
        self.iter().find(|&entry| entry as usize as u32 == id.0)
    }

    /// SAFETY: `entry` is linked and the lock is held.
    unsafe fn unlink(&self, entry: *mut Entry) {
        unsafe {
            (*(*entry).blink).flink = (*entry).flink;
            (*(*entry).flink).blink = (*entry).blink;
        }
    }

    /// SAFETY: `entry` is linked and the lock is held.
    unsafe fn release_if_unused(&self, entry: *mut Entry) {
        unsafe {
            if (*entry).references == 0 && (*entry).consumers == 0 {
                self.unlink(entry);
                xboxkrnl::ExFreePool(entry as usize as u32);
            }
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        LOCK.leave();
    }
}

impl xhttpproxy::Backend for Console {
    fn proxy_update(&mut self, sys: bool, new: Option<&NewProxy<'_>>) -> ProxyOutcome {
        let guard = Guard::acquire();
        let cleared = guard.active(sys).map(|entry| {
            // SAFETY: the entry is linked and the lock is held.
            unsafe {
                let flags = ProxyFlags((*entry).flags);
                (*entry).flags &= !ProxyFlags::ACTIVE;
                (*entry).references -= 1;
                guard.release_if_unused(entry);
                flags
            }
        });
        let Some(new) = new else {
            return ProxyOutcome {
                cleared,
                inserted: None,
            };
        };
        // The stored name keeps its terminator.
        let name_size = new.name.map_or(0, |name| name.len() as u32 + 1);
        let certificate_size = match new.certificate {
            Certificate::None => 0,
            Certificate::Hex { size, .. } | Certificate::Upload { size } => size,
        };
        let size = certificate_size
            .wrapping_add(name_size)
            .wrapping_add(size_of::<Entry>() as u32);
        // SAFETY: pool allocation of the computed size; the result is checked below.
        let entry =
            unsafe { xboxkrnl::ExAllocatePoolWithTag(size, PROXY_TAG) } as usize as *mut Entry;
        if entry.is_null() {
            return ProxyOutcome {
                cleared,
                inserted: Some(Err(ProxyError::OutOfMemory)),
            };
        }
        // SAFETY: the allocation holds the header, the name, and the
        // certificate; the lock is held while linking.
        let inserted = unsafe {
            let data = entry.add(1).cast::<u8>();
            let name = match new.name {
                Some(name) => {
                    core::ptr::copy_nonoverlapping(name.as_ptr(), data, name.len());
                    *data.add(name.len()) = 0;
                    data
                }
                None => null_mut(),
            };
            let certificate = if certificate_size == 0 {
                null_mut()
            } else {
                data.add(name_size as usize)
            };
            entry.write(Entry {
                flink: (*guard.head()).flink,
                blink: guard.head(),
                flags: new.flags.0,
                references: 1,
                consumers: 0,
                name,
                port: new.port,
                certificate,
                certificate_size,
            });
            (*(*guard.head()).flink).blink = entry;
            (*guard.head()).flink = entry;
            match new.certificate {
                Certificate::None => Ok(Inserted::Applied),
                Certificate::Hex { text, size } => {
                    let output = core::slice::from_raw_parts_mut(certificate, size as usize);
                    match decode_hex(text, output) {
                        Some(count) if count == size as usize => Ok(Inserted::Applied),
                        _ => {
                            guard.unlink(entry);
                            xboxkrnl::ExFreePool(entry as usize as u32);
                            Err(ProxyError::BadCertificate)
                        }
                    }
                }
                Certificate::Upload { .. } => {
                    (*entry).flags |= ProxyFlags::CERTIFICATE_PENDING;
                    (*entry).references += 1;
                    Ok(Inserted::Pending(ProxyId(entry as usize as u32)))
                }
            }
        };
        ProxyOutcome {
            cleared,
            inserted: Some(inserted),
        }
    }

    fn proxy_write_certificate(&mut self, id: ProxyId, offset: u32, bytes: &[u8]) {
        let guard = Guard::acquire();
        if let Some(entry) = guard.find(id) {
            // SAFETY: the caller stays within the certificate size.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (*entry).certificate.add(offset as usize),
                    bytes.len(),
                )
            };
        }
    }

    fn proxy_upload_complete(&mut self, id: ProxyId) -> Option<ProxyFlags> {
        let guard = Guard::acquire();
        let entry = guard.find(id)?;
        // SAFETY: the entry is linked and the lock is held.
        unsafe {
            (*entry).flags &= !ProxyFlags::CERTIFICATE_PENDING;
            (*entry).references -= 1;
            let flags = ProxyFlags((*entry).flags);
            guard.release_if_unused(entry);
            Some(flags)
        }
    }

    /// The critical section is recursive, so calls made while the walk
    /// holds it nest.
    fn proxy_lock(&mut self) {
        LOCK.enter();
    }

    fn proxy_unlock(&mut self) {
        LOCK.leave();
    }

    fn proxy_upload_aborted(&mut self, id: ProxyId) {
        let guard = Guard::acquire();
        let Some(entry) = guard.find(id) else { return };
        // SAFETY: the entry is linked and the lock is held.
        unsafe {
            (*entry).references -= 1;
            if ProxyFlags((*entry).flags).contains(ProxyFlags::ACTIVE) {
                (*entry).flags &= !ProxyFlags::ACTIVE;
                (*entry).references -= 1;
            }
            guard.release_if_unused(entry);
        }
    }

    fn proxy_entry(&mut self, position: usize) -> Option<ProxyEntry> {
        let guard = Guard::acquire();
        let head = guard.head();
        // SAFETY: the list is consistent while the lock is held; walking
        // the back links visits the oldest entry first.
        unsafe {
            let mut entry = (*head).blink;
            for _ in 0..position {
                if entry == head {
                    return None;
                }
                entry = (*entry).blink;
            }
            if entry == head {
                return None;
            }
            let mut name = [0u8; NAME_CAPACITY];
            let name_len = (!(*entry).name.is_null()).then(|| {
                let stored = core::ffi::CStr::from_ptr((*entry).name.cast()).to_bytes();
                let length = stored.len().min(NAME_CAPACITY - 1);
                name[..length].copy_from_slice(&stored[..length]);
                length
            });
            Some(ProxyEntry {
                id: ProxyId(entry as usize as u32),
                flags: ProxyFlags((*entry).flags),
                name_len,
                name,
                port: (*entry).port,
                certificate_size: (*entry).certificate_size,
            })
        }
    }

    fn proxy_read_certificate(&mut self, id: ProxyId, offset: u32, output: &mut [u8]) {
        let guard = Guard::acquire();
        if let Some(entry) = guard.find(id) {
            // SAFETY: the caller stays within the certificate size.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (*entry).certificate.add(offset as usize),
                    output.as_mut_ptr(),
                    output.len(),
                )
            };
        }
    }

    fn proxy_title_exited(&mut self) {
        let guard = Guard::acquire();
        for entry in guard.iter() {
            // SAFETY: the iterator already holds the next link, so the entry
            // may be freed.
            unsafe {
                (*entry).consumers = 0;
                let flags = ProxyFlags((*entry).flags);
                if !flags.contains(ProxyFlags::SYS)
                    && flags.contains(ProxyFlags::ACTIVE)
                    && flags.contains(ProxyFlags::TEMP)
                {
                    (*entry).flags &= !ProxyFlags::ACTIVE;
                    (*entry).references -= 1;
                }
                if (*entry).references == 0 {
                    guard.unlink(entry);
                    xboxkrnl::ExFreePool(entry as usize as u32);
                }
            }
        }
    }
}

/// Request record of the proxy control codes; dword fields.
fn request(argument: u32) -> *mut u32 {
    argument as usize as *mut u32
}

const NOT_FOUND: u32 = 0x82da_0002;
const NOT_FORCED: u32 = 0x82da_000a;
const BAD_REQUEST: u32 = 0x82da_0017;
const SUCCESS: u32 = 0x02da_0000;

/// Control code 0xa5 (stock 0x91f380f8): look up the proxy of a scope for
/// title code. Mode 1 is the title scope and counts a consumer reference;
/// mode 2 is the system scope and counts a reference (only when the entry
/// has a name). With the caller's force-only byte set, an entry without
/// the force bit is refused.
pub(crate) fn service_http_proxy_acquire(argument: u32) -> u32 {
    let request = request(argument);
    // SAFETY: the caller passes a request record.
    let mode = unsafe { request.read() };
    let (sys, references, consumers) = match mode {
        1 => (false, 0, 1),
        2 => (true, 1, 0),
        _ => return NOT_FOUND,
    };
    let guard = Guard::acquire();
    // Stock 0x91f37800 with the title rule: a title-scope query also takes
    // a system entry that is not system-only.
    let found = guard.iter().find(|&entry| {
        // SAFETY: entries are valid while the lock is held.
        let flags = ProxyFlags(unsafe { (*entry).flags });
        let scope = if flags.contains(ProxyFlags::SYS) {
            sys || !flags.contains(ProxyFlags::SYS_ONLY)
        } else {
            !sys
        };
        scope && flags.contains(ProxyFlags::ACTIVE)
    });
    let Some(entry) = found else { return NOT_FOUND };
    // SAFETY: the entry is linked, the lock is held, and the request record
    // has the fields of this code.
    unsafe {
        let force_only = request.cast::<u8>().add(0x10);
        let forced = ProxyFlags((*entry).flags).contains(ProxyFlags::FORCE);
        if force_only.read() != 0 && !forced {
            return NOT_FORCED;
        }
        if !(*entry).name.is_null() {
            (*entry).references += references;
            (*entry).consumers += consumers;
        }
        request.add(2).write((*entry).name as usize as u32);
        request.add(3).write((*entry).port);
        force_only.write(u8::from(forced));
    }
    SUCCESS
}

/// Find an entry by the name pointer and port a title received.
fn find_by_name(guard: &Guard, name: u32, port: u32) -> Option<*mut Entry> {
    // SAFETY: entries are valid while the lock is held.
    guard
        .iter()
        .find(|&entry| unsafe { (*entry).name as usize as u32 == name && (*entry).port == port })
}

/// Control code 0xa6 (stock 0x91f381f8): release a reference taken by
/// code 0xa5.
pub(crate) fn service_http_proxy_release(argument: u32) -> u32 {
    let request = request(argument);
    // SAFETY: the caller passes a request record.
    let (mode, name, port) =
        unsafe { (request.read(), request.add(2).read(), request.add(3).read()) };
    let (references, consumers) = match mode {
        1 => (0, 1),
        2 => (1, 0),
        _ => return BAD_REQUEST,
    };
    if name == 0 || port == 0 {
        return BAD_REQUEST;
    }
    let guard = Guard::acquire();
    let Some(entry) = find_by_name(&guard, name, port) else {
        return NOT_FOUND;
    };
    // SAFETY: the entry is linked and the lock is held.
    unsafe {
        (*entry).references = (*entry).references.wrapping_sub(references);
        (*entry).consumers = (*entry).consumers.wrapping_sub(consumers);
        guard.release_if_unused(entry);
    }
    SUCCESS
}

/// Control code 0xa7 (stock 0x91f38320): pass the certificate of an entry
/// to a caller-supplied function.
pub(crate) fn service_http_proxy_certificate(argument: u32) -> u32 {
    let request = request(argument);
    // SAFETY: the caller passes a request record of nine dwords.
    let field = |index: usize| unsafe { request.add(index).read() };
    let mode = field(0);
    if !(1..=2).contains(&mode) || [2, 3, 5, 6, 8].iter().any(|&index| field(index) == 0) {
        return BAD_REQUEST;
    }
    let guard = Guard::acquire();
    let Some(entry) = find_by_name(&guard, field(2), field(3)) else {
        return NOT_FOUND;
    };
    // SAFETY: the entry is linked and the lock is held.
    let (flags, certificate, size) = unsafe {
        (
            (*entry).flags,
            (*entry).certificate,
            (*entry).certificate_size,
        )
    };
    if size == 0 {
        return NOT_FOUND;
    }
    if ProxyFlags(flags).contains(ProxyFlags::CERTIFICATE_PENDING) {
        return 0x82da_0150;
    }
    // SAFETY: the callback is the caller's; it takes (context, value 5,
    // value 6, certificate, size).
    let result = unsafe {
        call_callback(
            field(8),
            field(7),
            field(5),
            field(6),
            certificate as usize as u32,
            size,
        )
    };
    drop(guard);
    if (result as i32) < 0 {
        0x82da_0003
    } else {
        SUCCESS
    }
}

/// Call a console function with five arguments, allocating the callee home
/// area as `kernel::call_export` does.
#[unsafe(naked)]
unsafe extern "C" fn call_callback(
    function: u32,
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
    a4: u32,
) -> u32 {
    core::arch::naked_asm!(
        "stwu 1, -0x50(1)",
        "mflr 0",
        "stw 0, 0x54(1)",
        "mtctr 3",
        "mr 3, 4",
        "mr 4, 5",
        "mr 5, 6",
        "mr 6, 7",
        "mr 7, 8",
        "bctrl",
        "lwz 0, 0x54(1)",
        "mtlr 0",
        "addi 1, 1, 0x50",
        "blr",
    )
}
