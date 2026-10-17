//! `netsim` services: the network simulator on the Ethernet intercept.

mod engine;
mod filter;
mod frame;
mod pipeline;

use core::ptr::NonNull;
use core::ptr::null_mut;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::netsim;
use openxbdm_server::commands::network::netsim::Direction;
use openxbdm_server::commands::network::netsim::KeyStatus;
use openxbdm_server::commands::network::netsim::NetsimError;
use openxbdm_server::commands::network::netsim::Program;
use openxbdm_server::commands::network::netsim::QueueConfig;
use openxbdm_server::commands::network::netsim::QueueIndex;
use openxbdm_server::commands::network::netsim::QueueKind;
use openxbdm_server::commands::network::netsim::QueueSnapshot;
use openxbdm_server::commands::network::netsim::QueueStats;
use openxbdm_server::commands::network::netsim::RedirectConfig;
use openxbdm_server::commands::network::netsim::RedirectIndex;
use openxbdm_server::commands::network::netsim::RedirectSnapshot;
use xbox360_sys::xam::EthernetInterceptFlags;
use xbox360_sys::xam::NetDll_XnpEthernetInterceptSetCallbacks;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xboxkrnl::XeKeysGetStatus;

use self::engine::Instance;
use super::FrameHook;
use super::SIMULATOR_INTERCEPT;
use crate::backend::Console;

/// Pool blocks of the library (stock allocator 0x91f36460: tag `DMNS`,
/// pool type 2).
mod memory {
    use core::ptr::NonNull;

    use xbox360_sys::xboxkrnl;
    use xbox360_sys::xboxkrnl::PoolTag;
    use xbox360_sys::xboxkrnl::PoolType;

    const TAG: PoolTag = PoolTag::new(*b"DMNS");

    pub(super) fn allocate(size: usize) -> Option<NonNull<u8>> {
        // SAFETY: pool allocation of the requested size; the result is checked below.
        let address = unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(u32::try_from(size).ok()?, TAG, PoolType::System)
        };
        NonNull::new(address as usize as *mut u8)
    }

    /// # Safety
    /// `block` came from [`allocate`], is freed once, and is not used after.
    pub(super) unsafe fn free(block: *mut u8) {
        // SAFETY: guaranteed by the caller.
        unsafe { xboxkrnl::ExFreePool(block as usize as u32) };
    }
}

/// An intercept registration failure. Only the simulator's own
/// registration turns `WSAEALREADY` into its busy error.
fn registration_error(error: WsaError, own_registration: bool) -> NetsimError {
    if own_registration && error == WsaError::ALREADY {
        NetsimError::InterceptBusy
    } else {
        NetsimError::Intercept(error)
    }
}

/// The instance (0x91f9fc84). Only `destroy_simulator`, on the server
/// thread, unpublishes and frees it. The query exports read it on caller
/// threads, unsynchronized with that, as stock does (see [`instance`]).
static INSTANCE: AtomicPtr<Instance> = AtomicPtr::new(null_mut());

/// The published instance, without access to it.
fn published() -> Option<NonNull<Instance>> {
    NonNull::new(INSTANCE.load(Ordering::Acquire))
}

/// The published instance.
///
/// # Safety
/// `destroy_simulator` does not run while the reference lives. Code that
/// holds the console uses [`held_instance`] instead. The query exports
/// (221, 222, 223, 226) call this on caller threads, where stock does not
/// exclude a destruction during the query; there the stock race remains.
unsafe fn instance<'a>() -> Result<&'a Instance, NetsimError> {
    // SAFETY: a published instance stays allocated until `destroy_simulator`,
    // which the contract excludes.
    published()
        .map(|instance| unsafe { &*instance.as_ptr() })
        .ok_or(NetsimError::NoInstance)
}

/// The published instance, for the holder of the console.
#[inline(always)]
fn held_instance(_console: &mut Console) -> Result<&Instance, NetsimError> {
    // SAFETY: `destroy_simulator` needs the console mutably, so the borrow
    // excludes it while the reference lives.
    unsafe { instance() }
}

/// Whether the instance exists.
pub(crate) fn simulator_exists() -> bool {
    published().is_some()
}

/// Forward frames to a capture's callbacks, or stop forwarding; `false`
/// when there is no instance to chain into (0x91f8d428).
pub(crate) fn chain_capture(console: &mut Console, hook: Option<FrameHook>) -> bool {
    let Ok(instance) = held_instance(console) else {
        return false;
    };
    instance.chain(hook, false);
    true
}

/// Let frames bypass the simulation while the IP proxy runs (0x91f8d3d8).
pub(crate) fn set_proxy_bypass(console: &mut Console, active: bool) {
    if let Ok(instance) = held_instance(console) {
        instance.set_bypass(active);
    }
}

/// Queue counts of the instance, zero without one (0x91f37028 through
/// 0x91f8d4f8).
///
/// # Safety
/// As for [`instance`].
pub(crate) unsafe fn queue_counts() -> (u32, u32) {
    // SAFETY: guaranteed by the caller.
    unsafe { instance() }.map_or((0, 0), |instance| {
        (
            instance.queue_count(Direction::Inbound),
            instance.queue_count(Direction::Outbound),
        )
    })
}

/// Redirect count of the instance, zero without one (0x91f8da78).
///
/// # Safety
/// As for [`instance`].
pub(crate) unsafe fn redirect_count() -> u32 {
    // SAFETY: guaranteed by the caller.
    unsafe { instance() }.map_or(0, Instance::redirect_count)
}

/// Counters of a queue (0x91f8d558).
///
/// # Safety
/// As for [`instance`].
pub(crate) unsafe fn queue_stats(
    direction: Direction,
    index: QueueIndex,
) -> Result<QueueStats, NetsimError> {
    // SAFETY: guaranteed by the caller.
    unsafe { instance() }?.queue_stats(direction, index)
}

/// Type and stored settings of a queue (0x91f8d620).
///
/// # Safety
/// As for [`instance`].
pub(crate) unsafe fn queue(
    direction: Direction,
    index: QueueIndex,
) -> Result<QueueSnapshot, NetsimError> {
    // SAFETY: guaranteed by the caller.
    unsafe { instance() }?.queue(direction, index)
}

impl netsim::Backend for Console {
    fn simulator_exists(&mut self) -> bool {
        simulator_exists()
    }

    /// 0x91f365e8. A running capture moves from its own intercept into the
    /// instance; a failed registration leaves it detached, as stock does.
    fn create_simulator(&mut self) -> Result<(), NetsimError> {
        if simulator_exists() {
            return Err(NetsimError::InstanceExists);
        }
        let pointer = Instance::create()?;
        // SAFETY: just created and owned here.
        let instance = unsafe { pointer.as_ref() };
        if self.network.ipproxy.is_started() {
            instance.set_bypass(true);
        }
        if let Some(hook) = self.network.netcap.hook() {
            instance.chain(Some(hook), false);
            // SAFETY: clearing the callbacks passes no pointers.
            let error = unsafe {
                NetDll_XnpEthernetInterceptSetCallbacks(
                    XnCaller::SystemApp,
                    0,
                    0,
                    0,
                    EthernetInterceptFlags::empty().bits(),
                )
            };
            if let Some(error) = WsaError::new(error) {
                // SAFETY: created here and never published.
                unsafe { Instance::destroy(pointer) };
                return Err(registration_error(error, false));
            }
        }
        // SAFETY: the entries take the instance context, which stays allocated
        // until `destroy_simulator` removes the callbacks.
        let error = unsafe {
            NetDll_XnpEthernetInterceptSetCallbacks(
                XnCaller::SystemApp,
                engine::transmit_entry as *const () as usize,
                engine::receive_entry as *const () as usize,
                instance.context(),
                SIMULATOR_INTERCEPT.bits(),
            )
        };
        if let Some(error) = WsaError::new(error) {
            // SAFETY: the failed registration installed no callbacks; the
            // instance was never published.
            unsafe { Instance::destroy(pointer) };
            return Err(registration_error(error, true));
        }
        INSTANCE.store(pointer.as_ptr(), Ordering::Release);
        Ok(())
    }

    /// 0x91f36750.
    fn destroy_simulator(&mut self) -> Result<(), NetsimError> {
        let pointer = NonNull::new(INSTANCE.swap(null_mut(), Ordering::AcqRel))
            .ok_or(NetsimError::InstanceChanged)?;
        // SAFETY: removing the simulator callbacks passes no pointers. The
        // capture entries take its context, which stays allocated until
        // `close_capture`, after `detach_capture` removes the hook.
        unsafe {
            NetDll_XnpEthernetInterceptSetCallbacks(
                XnCaller::SystemApp,
                0,
                0,
                0,
                SIMULATOR_INTERCEPT.bits(),
            );
            if let Some(hook) = self.network.netcap.hook() {
                NetDll_XnpEthernetInterceptSetCallbacks(
                    XnCaller::SystemApp,
                    super::netcap::transmit_entry as *const () as usize,
                    super::netcap::receive_entry as *const () as usize,
                    hook.context,
                    EthernetInterceptFlags::empty().bits(),
                );
            }
        }
        // SAFETY: the instance came from `Instance::create`, left `INSTANCE`
        // above, and no intercept callback is installed for it. The console
        // borrow excludes every `held_instance` reference. Stock does not
        // exclude a query export that loaded it before the swap, nor a
        // release DPC or intercept callback already running on another
        // processor; those races remain (see `Instance::destroy`).
        unsafe { Instance::destroy(pointer) };
        Ok(())
    }

    fn queue_count(&mut self, direction: Direction) -> u32 {
        held_instance(self).map_or(0, |instance| instance.queue_count(direction))
    }

    fn redirect_count(&mut self) -> u32 {
        // SAFETY: the console borrow excludes `destroy_simulator` for the
        // call.
        unsafe { redirect_count() }
    }

    fn insert_queue(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
        kind: QueueKind,
        update: &QueueConfig,
        program: Option<&Program>,
    ) -> Result<QueueIndex, NetsimError> {
        held_instance(self)?.insert_queue(direction, position, kind, update, program)
    }

    fn modify_queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
        update: &QueueConfig,
    ) -> Result<(), NetsimError> {
        held_instance(self)?.modify_queue(direction, index, update)
    }

    fn remove_queues(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
    ) -> Result<u32, NetsimError> {
        held_instance(self)?.remove_queues(direction, position)
    }

    fn queue_stats(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueStats, NetsimError> {
        // SAFETY: the console borrow excludes `destroy_simulator` for the
        // call.
        unsafe { queue_stats(direction, index) }
    }

    fn queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueSnapshot, NetsimError> {
        // SAFETY: the console borrow excludes `destroy_simulator` for the
        // call.
        unsafe { queue(direction, index) }
    }

    fn insert_redirect(
        &mut self,
        position: Option<RedirectIndex>,
        redirect: &RedirectConfig,
        program: Option<&Program>,
    ) -> Result<RedirectIndex, NetsimError> {
        held_instance(self)?.insert_redirect(position, redirect, program)
    }

    fn remove_redirects(&mut self, position: Option<RedirectIndex>) -> Result<u32, NetsimError> {
        held_instance(self)?.remove_redirects(position)
    }

    fn redirect(&mut self, index: RedirectIndex) -> Option<RedirectSnapshot> {
        held_instance(self).ok()?.redirect(index)
    }

    fn key_status(&mut self) -> KeyStatus {
        let mut value = 0u32;
        // SAFETY: `value` is a live u32.
        unsafe { XeKeysGetStatus(&mut value) };
        KeyStatus::from_bits_retain(value)
    }
}
