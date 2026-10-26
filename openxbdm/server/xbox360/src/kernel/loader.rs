//! Walks of the kernel loader module lists under the loader lock.

use core::marker::PhantomData;
use core::num::NonZeroU32;
use core::sync::atomic::Ordering;

use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::KfAcquireSpinLock;
use xbox360_sys::xboxkrnl::KfReleaseSpinLock;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::LdrDataTableEntry;
use xbox360_sys::xboxkrnl::ListEntry;

use super::address::object_at;
use super::monitor::debug_monitor_data;

/// A loader module list of the debug monitor data.
#[derive(Clone, Copy)]
pub enum ModuleList {
    Loaded,
    Usermode,
}

impl ModuleList {
    /// The list head, if the kernel has the list.
    fn head(self) -> Option<NonZeroU32> {
        let data = debug_monitor_data();
        let head = match self {
            Self::Loaded => &data.loaded_module_list,
            Self::Usermode => &data.loaded_usermode_module_list,
        };

        NonZeroU32::new(head.load(Ordering::Relaxed))
    }
}

/// Holds the kernel loader spin lock, which guards both module lists, for
/// its lifetime.
pub struct LoaderLock {
    lock: *mut KspinLock,
    irql: Irql,
}

impl LoaderLock {
    /// Inlined: two loads and the import call cost less than a call.
    #[inline(always)]
    pub fn acquire() -> Self {
        let lock = core::ptr::with_exposed_provenance_mut::<KspinLock>(
            debug_monitor_data()
                .loaded_module_list_lock
                .load(Ordering::Relaxed) as usize,
        );
        // SAFETY: the debug monitor data holds the address of the kernel
        // loader spin lock; Drop releases it at the returned IRQL.
        let irql = unsafe { KfAcquireSpinLock(lock) };

        Self { lock, irql }
    }

    /// Entries of `list` in load order.
    pub fn entries(&self, list: ModuleList) -> LoaderEntries<'_> {
        LoaderEntries {
            heads: [list.head(), None],
            list: 0,
            link: None,
            _lock: PhantomData,
        }
    }

    /// Entries of the loaded list, then of the user-mode list, in the
    /// order the monitor walks them. One iterator for both lists keeps
    /// the walks from being instantiated once per list.
    pub fn all_entries(&self) -> LoaderEntries<'_> {
        LoaderEntries {
            heads: [ModuleList::Loaded.head(), ModuleList::Usermode.head()],
            list: 0,
            link: None,
            _lock: PhantomData,
        }
    }
}

impl Drop for LoaderLock {
    #[inline(always)]
    fn drop(&mut self) {
        // SAFETY: `acquire` took this lock at `self.irql`.
        unsafe { KfReleaseSpinLock(self.lock, self.irql) };
    }
}

/// Loader data table entries of up to two lists, one after the other;
/// built only by [`LoaderLock`], whose borrow keeps the entries linked.
pub struct LoaderEntries<'a> {
    /// Heads of the lists; none for a list the kernel does not have.
    heads: [Option<NonZeroU32>; 2],
    list: usize,
    /// The head or the last entry returned of the current list; none
    /// before its first entry.
    link: Option<NonZeroU32>,

    _lock: PhantomData<&'a LoaderLock>,
}

impl<'a> Iterator for LoaderEntries<'a> {
    type Item = &'a LdrDataTableEntry;

    fn next(&mut self) -> Option<&'a LdrDataTableEntry> {
        loop {
            if let Some(head) = *self.heads.get(self.list)? {
                let link = *self.link.get_or_insert(head);
                // SAFETY: `link` is the kernel's list head, which lives as
                // long as the system, or an entry linked into its list; the
                // loader lock borrowed for `'a` keeps the links unchanged and
                // the entries mapped.
                let entry = unsafe { object_at::<ListEntry>(link.get()) }
                    .flink
                    .load(Ordering::Relaxed);
                if entry != head.get() {
                    // SAFETY: the link of a circular kernel list holds the
                    // address of a mapped link, which is not 0.
                    self.link = Some(unsafe { NonZeroU32::new_unchecked(entry) });
                    // SAFETY: `entry` is linked into the list, as above; a
                    // loader entry starts with its load order link.
                    return Some(unsafe { object_at(entry) });
                }
            }

            // The current list is absent or exhausted.
            self.list += 1;
            self.link = None;
        }
    }
}
