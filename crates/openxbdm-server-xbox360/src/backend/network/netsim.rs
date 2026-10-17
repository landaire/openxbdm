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
use xbox360_sys::xam::NetDll_XnpEthernetInterceptSetCallbacks;
use xbox360_sys::xboxkrnl::XeKeysGetStatus;

use self::engine::Instance;
use super::FrameHook;
use super::XNCALLER_SYSAPP;
use crate::backend::Console;

/// Intercept flags of the simulator registration; a capture registers with
/// none.
const INTERCEPT_FLAGS: u32 = 2;

/// Pool blocks of the library (stock allocator 0x91f36460: tag `DMNS`,
/// pool type 2).
mod memory {
    use xbox360_sys::xboxkrnl;
    use xbox360_sys::xboxkrnl::PoolTag;
    use xbox360_sys::xboxkrnl::PoolType;

    const TAG: PoolTag = PoolTag::new(*b"DMNS");

    pub(super) fn allocate(size: usize) -> Option<*mut u8> {
        // SAFETY: pool allocation of the requested size; the result is checked below.
        let address = unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(u32::try_from(size).ok()?, TAG, PoolType::System)
        };
        (address != 0).then_some(address as usize as *mut u8)
    }

    pub(super) fn free(block: *mut u8) {
        // SAFETY: callers pass a block from `allocate` that they no longer use.
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

/// The instance (0x91f9fc84). The exports read it on caller threads,
/// unsynchronized with its creation and destruction, as stock does.
static INSTANCE: AtomicPtr<Instance> = AtomicPtr::new(null_mut());

fn instance() -> Result<&'static Instance, NetsimError> {
    // SAFETY: the instance stays allocated until `destroy_simulator`.
    NonNull::new(INSTANCE.load(Ordering::Acquire))
        .map(|instance| unsafe { &*instance.as_ptr() })
        .ok_or(NetsimError::NoInstance)
}

/// Whether the instance exists.
pub(crate) fn simulator_exists() -> bool {
    instance().is_ok()
}

/// Forward frames to a capture's callbacks, or stop forwarding; `false`
/// when there is no instance to chain into (0x91f8d428).
pub(crate) fn chain_capture(hook: Option<FrameHook>) -> bool {
    let Ok(instance) = instance() else {
        return false;
    };
    instance.chain(hook, false);
    true
}

/// Let frames bypass the simulation while the IP proxy runs (0x91f8d3d8).
pub(crate) fn set_proxy_bypass(active: bool) {
    if let Ok(instance) = instance() {
        instance.set_bypass(active);
    }
}

/// Queue counts of the instance, zero without one (0x91f37028 through
/// 0x91f8d4f8).
pub(crate) fn queue_counts() -> (u32, u32) {
    instance().map_or((0, 0), |instance| {
        (
            instance.queue_count(Direction::Inbound),
            instance.queue_count(Direction::Outbound),
        )
    })
}

/// Redirect count of the instance, zero without one (0x91f8da78).
pub(crate) fn redirect_count() -> u32 {
    instance().map_or(0, Instance::redirect_count)
}

/// Counters of a queue (0x91f8d558).
pub(crate) fn queue_stats(
    direction: Direction,
    index: QueueIndex,
) -> Result<QueueStats, NetsimError> {
    instance()?.queue_stats(direction, index)
}

/// Type and stored settings of a queue (0x91f8d620).
pub(crate) fn queue(direction: Direction, index: QueueIndex) -> Result<QueueSnapshot, NetsimError> {
    instance()?.queue(direction, index)
}

impl netsim::Backend for Console {
    fn simulator_exists(&mut self) -> bool {
        instance().is_ok()
    }

    /// 0x91f365e8. A running capture moves from its own intercept into the
    /// instance; a failed registration leaves it detached, as stock does.
    fn create_simulator(&mut self) -> Result<(), NetsimError> {
        if instance().is_ok() {
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
            let error =
                unsafe { NetDll_XnpEthernetInterceptSetCallbacks(XNCALLER_SYSAPP, 0, 0, 0, 0) };
            if let Some(error) = WsaError::new(error) {
                Instance::destroy(pointer.as_ptr());
                return Err(registration_error(error, false));
            }
        }
        // SAFETY: the entries take the instance context, which stays allocated
        // until `destroy_simulator` removes the callbacks.
        let error = unsafe {
            NetDll_XnpEthernetInterceptSetCallbacks(
                XNCALLER_SYSAPP,
                engine::transmit_entry as *const () as usize,
                engine::receive_entry as *const () as usize,
                instance.context(),
                INTERCEPT_FLAGS,
            )
        };
        if let Some(error) = WsaError::new(error) {
            Instance::destroy(pointer.as_ptr());
            return Err(registration_error(error, true));
        }
        INSTANCE.store(pointer.as_ptr(), Ordering::Release);
        Ok(())
    }

    /// 0x91f36750.
    fn destroy_simulator(&mut self) -> Result<(), NetsimError> {
        let pointer = NonNull::new(INSTANCE.swap(null_mut(), Ordering::AcqRel))
            .ok_or(NetsimError::InstanceChanged)?;
        // SAFETY: the capture entries take its context, which stays allocated
        // until `close_capture`, after `detach_capture` removes the hook.
        unsafe {
            NetDll_XnpEthernetInterceptSetCallbacks(XNCALLER_SYSAPP, 0, 0, 0, INTERCEPT_FLAGS);
            if let Some(hook) = self.network.netcap.hook() {
                NetDll_XnpEthernetInterceptSetCallbacks(
                    XNCALLER_SYSAPP,
                    super::netcap::transmit_entry as *const () as usize,
                    super::netcap::receive_entry as *const () as usize,
                    hook.context,
                    0,
                );
            }
        }
        Instance::destroy(pointer.as_ptr());
        Ok(())
    }

    fn queue_count(&mut self, direction: Direction) -> u32 {
        instance().map_or(0, |instance| instance.queue_count(direction))
    }

    fn redirect_count(&mut self) -> u32 {
        redirect_count()
    }

    fn insert_queue(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
        kind: QueueKind,
        update: &QueueConfig,
        program: Option<&Program>,
    ) -> Result<QueueIndex, NetsimError> {
        instance()?.insert_queue(direction, position, kind, update, program)
    }

    fn modify_queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
        update: &QueueConfig,
    ) -> Result<(), NetsimError> {
        instance()?.modify_queue(direction, index, update)
    }

    fn remove_queues(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
    ) -> Result<u32, NetsimError> {
        instance()?.remove_queues(direction, position)
    }

    fn queue_stats(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueStats, NetsimError> {
        queue_stats(direction, index)
    }

    fn queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueSnapshot, NetsimError> {
        queue(direction, index)
    }

    fn insert_redirect(
        &mut self,
        position: Option<RedirectIndex>,
        redirect: &RedirectConfig,
        program: Option<&Program>,
    ) -> Result<RedirectIndex, NetsimError> {
        instance()?.insert_redirect(position, redirect, program)
    }

    fn remove_redirects(&mut self, position: Option<RedirectIndex>) -> Result<u32, NetsimError> {
        instance()?.remove_redirects(position)
    }

    fn redirect(&mut self, index: RedirectIndex) -> Option<RedirectSnapshot> {
        instance().ok()?.redirect(index)
    }

    fn key_status(&mut self) -> KeyStatus {
        let mut value = 0u32;
        // SAFETY: `value` is a live u32.
        unsafe { XeKeysGetStatus(&mut value) };
        KeyStatus::from_bits_retain(value)
    }
}
