//! Proxy list in pool memory with the stock entry layout, guarded by a
//! critical section so title threads can read it.

mod error;

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
use xbox360::status::Hresult;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::PoolTag;

use self::error::ControlError;
use crate::backend::Console;
use crate::exports::export_result;
use crate::kernel::CriticalSection;

/// Pool tag of proxy entries (`HPXY`).
const PROXY_TAG: PoolTag = PoolTag::new(*b"HPXY");

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

const _: () = {
    assert!(core::mem::offset_of!(Entry, flags) == 0x8);
    assert!(core::mem::offset_of!(Entry, name) == 0x14);
    assert!(core::mem::offset_of!(Entry, port) == 0x18);
    assert!(core::mem::offset_of!(Entry, certificate) == 0x1c);
    assert!(size_of::<Entry>() == 0x24);
};

/// Holds the list lock inside a critical region.
struct Guard;

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
            let flags = ProxyFlags::from_bits_retain((*entry).flags);
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
                let flags = ProxyFlags::from_bits_retain((*entry).flags);
                (*entry).flags &= !ProxyFlags::ACTIVE.bits();
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

        // Stock adds with wrapping, so a large `certsize` yields a small
        // block that the certificate then overruns. A size past 4 GiB is
        // refused as the failed allocation it would be without the wrap.
        let size = certificate_size
            .checked_add(name_size)
            .and_then(|size| size.checked_add(size_of::<Entry>() as u32));

        let entry = match size {
            // SAFETY: pool allocation of the computed size; the result is
            // checked below.
            Some(size) => unsafe { xboxkrnl::ExAllocatePoolWithTag(size, PROXY_TAG) },
            None => 0,
        } as usize as *mut Entry;

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
                flags: new.flags.bits(),
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
                    (*entry).flags |= ProxyFlags::CERTIFICATE_PENDING.bits();
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
        let Some(entry) = guard.find(id) else {
            return;
        };

        // The entry may be a new one at the address of a released
        // pending entry, so the copy stops at its own certificate size.
        // SAFETY: the guard keeps the listed entry allocated.
        let size = unsafe { (*entry).certificate_size };
        let count = bytes.len().min(size.saturating_sub(offset) as usize);

        // SAFETY: the `count` bytes at `offset` lie in the entry's
        // certificate storage.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (*entry).certificate.add(offset as usize),
                count,
            )
        };
    }

    fn proxy_upload_complete(&mut self, id: ProxyId) -> Option<ProxyFlags> {
        let guard = Guard::acquire();

        let entry = guard.find(id)?;

        // SAFETY: the entry is linked and the lock is held.
        unsafe {
            (*entry).flags &= !ProxyFlags::CERTIFICATE_PENDING.bits();
            (*entry).references -= 1;

            let flags = ProxyFlags::from_bits_retain((*entry).flags);
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

        let Some(entry) = guard.find(id) else {
            return;
        };

        // SAFETY: the entry is linked and the lock is held.
        unsafe {
            (*entry).references -= 1;

            if ProxyFlags::from_bits_retain((*entry).flags).contains(ProxyFlags::ACTIVE) {
                (*entry).flags &= !ProxyFlags::ACTIVE.bits();
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
                flags: ProxyFlags::from_bits_retain((*entry).flags),
                name_len,
                name,
                port: (*entry).port,
                certificate_size: (*entry).certificate_size,
            })
        }
    }

    fn proxy_read_certificate(&mut self, id: ProxyId, offset: u32, output: &mut [u8]) {
        let guard = Guard::acquire();
        let Some(entry) = guard.find(id) else {
            return;
        };

        // SAFETY: the guard keeps the listed entry allocated.
        let size = unsafe { (*entry).certificate_size };
        let count = output.len().min(size.saturating_sub(offset) as usize);

        // SAFETY: the `count` bytes at `offset` lie in the entry's
        // certificate storage.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (*entry).certificate.add(offset as usize),
                output.as_mut_ptr(),
                count,
            )
        };
    }

    fn proxy_title_exited(&mut self) {
        let guard = Guard::acquire();

        for entry in guard.iter() {
            // SAFETY: the iterator already holds the next link, so the entry
            // may be freed.
            unsafe {
                (*entry).consumers = 0;

                let flags = ProxyFlags::from_bits_retain((*entry).flags);

                if !flags.contains(ProxyFlags::SYS)
                    && flags.contains(ProxyFlags::ACTIVE)
                    && flags.contains(ProxyFlags::TEMP)
                {
                    (*entry).flags &= !ProxyFlags::ACTIVE.bits();
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

/// Scope of a proxy control code request, from its mode field.
#[derive(Clone, Copy)]
enum Scope {
    Title,
    System,
}

impl Scope {
    const fn from_mode(mode: u32) -> Option<Self> {
        match mode {
            1 => Some(Self::Title),
            2 => Some(Self::System),
            _ => None,
        }
    }

    /// What a lookup of the scope counts: the title scope counts a
    /// consumer, the system scope a reference.
    const fn counts(self) -> Counts {
        match self {
            Self::Title => Counts {
                references: 0,
                consumers: 1,
            },
            Self::System => Counts {
                references: 1,
                consumers: 0,
            },
        }
    }
}

/// Counts an entry holds for a lookup.
#[derive(Clone, Copy)]
struct Counts {
    references: u32,
    consumers: u32,
}

/// Leading fields of the proxy control code records.
#[repr(C)]
struct ProxyRecord {
    mode: u32,
    _reserved: u32,
    /// Name pointer of the entry, as code 0xa5 returns it.
    name: u32,
    port: u32,
}

/// Record of code 0xa7: the callback takes (context, argument, argument,
/// certificate, size).
#[repr(C)]
struct CertificateRequest {
    proxy: ProxyRecord,
    _reserved: u32,
    arguments: [u32; 2],
    context: u32,
    callback: u32,
}

const _: () = {
    assert!(size_of::<ProxyRecord>() == 0x10);
    assert!(core::mem::offset_of!(CertificateRequest, arguments) == 0x14);
    assert!(core::mem::offset_of!(CertificateRequest, callback) == 0x20);
    assert!(size_of::<CertificateRequest>() == 0x24);
};

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

/// Control code 0xa5 (stock 0x91f380f8): look up the proxy of a scope for
/// title code and count the lookup (only when the entry has a name). With
/// the caller's force-only byte set, an entry without the force bit is
/// refused.
///
/// # Safety
///
/// `argument` must be the 4-aligned address of a writable 0x11-byte code
/// 0xa5 record that no other thread uses for the call.
pub(crate) unsafe fn service_http_proxy_acquire(argument: u32) -> u32 {
    /// Record of code 0xa5: a [`ProxyRecord`] and the force byte at +0x10,
    /// 0x11 bytes with no tail padding. The force byte in: refuse an entry
    /// without the force bit; out: the force bit.
    const ACQUIRE_FORCE_OFFSET: u32 = size_of::<ProxyRecord>() as u32;

    // SAFETY: the caller's contract; the proxy fields and the force byte
    // are disjoint parts of the record.
    let (proxy, force_only) = unsafe {
        (
            crate::kernel::object_at_mut::<ProxyRecord>(argument),
            crate::kernel::object_at_mut::<u8>(argument.wrapping_add(ACQUIRE_FORCE_OFFSET)),
        )
    };

    export_result(acquire(proxy, force_only)).0
}

fn acquire(request: &mut ProxyRecord, force_only: &mut u8) -> Result<(), ControlError> {
    let scope = Scope::from_mode(request.mode).ok_or(ControlError::NotFound)?;
    let sys = matches!(scope, Scope::System);
    let guard = Guard::acquire();

    // Stock 0x91f37800 with the title rule: a title-scope query also takes
    // a system entry that is not system-only.
    let found = guard.iter().find(|&entry| {
        // SAFETY: entries are valid while the lock is held.
        let flags = ProxyFlags::from_bits_retain(unsafe { (*entry).flags });
        let in_scope = if flags.contains(ProxyFlags::SYS) {
            sys || !flags.contains(ProxyFlags::SYS_ONLY)
        } else {
            !sys
        };

        in_scope && flags.contains(ProxyFlags::ACTIVE)
    });

    let entry = found.ok_or(ControlError::NotFound)?;

    // SAFETY: the entry is linked and the lock is held.
    unsafe {
        let forced = ProxyFlags::from_bits_retain((*entry).flags).contains(ProxyFlags::FORCE);
        if *force_only != 0 && !forced {
            return Err(ControlError::NotForced);
        }

        if !(*entry).name.is_null() {
            let counts = scope.counts();
            (*entry).references += counts.references;
            (*entry).consumers += counts.consumers;
        }

        request.name = (*entry).name as usize as u32;
        request.port = (*entry).port;
        *force_only = u8::from(forced);
    }

    Ok(())
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
///
/// # Safety
///
/// `argument` must be the address of a [`ProxyRecord`] unchanged for the
/// call.
pub(crate) unsafe fn service_http_proxy_release(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    let request = unsafe { crate::kernel::object_at::<ProxyRecord>(argument) };

    export_result(release(request)).0
}

fn release(request: &ProxyRecord) -> Result<(), ControlError> {
    let scope = Scope::from_mode(request.mode).ok_or(ControlError::BadRequest)?;
    if request.name == 0 || request.port == 0 {
        return Err(ControlError::BadRequest);
    }

    let guard = Guard::acquire();
    let entry = find_by_name(&guard, request.name, request.port).ok_or(ControlError::NotFound)?;
    let counts = scope.counts();

    // SAFETY: the entry is linked and the lock is held.
    unsafe {
        (*entry).references = (*entry).references.wrapping_sub(counts.references);
        (*entry).consumers = (*entry).consumers.wrapping_sub(counts.consumers);
        guard.release_if_unused(entry);
    }

    Ok(())
}

/// Control code 0xa7 (stock 0x91f38320): pass the certificate of an entry
/// to a caller-supplied function.
///
/// # Safety
///
/// As for `pass_certificate`, with `argument` the address of the record.
pub(crate) unsafe fn service_http_proxy_certificate(argument: u32) -> u32 {
    // SAFETY: the caller's contract.
    export_result(unsafe {
        pass_certificate(core::ptr::with_exposed_provenance(argument as usize))
    })
    .0
}

/// # Safety
///
/// `request` points at a readable record. Fields are read through the
/// pointer, not a reference, because the caller's callback may change the
/// record.
unsafe fn pass_certificate(request: *const CertificateRequest) -> Result<(), ControlError> {
    // SAFETY: guaranteed by the caller.
    let (mode, name, port, [first, second], callback) = unsafe {
        (
            (*request).proxy.mode,
            (*request).proxy.name,
            (*request).proxy.port,
            (*request).arguments,
            (*request).callback,
        )
    };

    if Scope::from_mode(mode).is_none() || [name, port, first, second, callback].contains(&0) {
        return Err(ControlError::BadRequest);
    }

    let result = {
        let guard = Guard::acquire();
        let entry = find_by_name(&guard, name, port).ok_or(ControlError::NotFound)?;

        // SAFETY: the entry is linked and the lock is held.
        let (flags, certificate, size) = unsafe {
            (
                (*entry).flags,
                (*entry).certificate,
                (*entry).certificate_size,
            )
        };

        if size == 0 {
            return Err(ControlError::NotFound);
        }

        if ProxyFlags::from_bits_retain(flags).contains(ProxyFlags::CERTIFICATE_PENDING) {
            return Err(ControlError::UploadPending);
        }

        // SAFETY: the callback is the caller's; it takes (context, argument,
        // argument, certificate, size). The record is readable per the contract.
        unsafe {
            call_callback(
                callback,
                (*request).context,
                first,
                second,
                certificate as usize as u32,
                size,
            )
        }
    };

    if Hresult(result).is_failure() {
        Err(ControlError::CallbackFailed)
    } else {
        Ok(())
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
