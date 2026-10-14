//! Simulated `netsim` library: queue and redirect lists of the instance.

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::network::netsim;
use openxbdm_server::commands::network::netsim::Direction;
use openxbdm_server::commands::network::netsim::KeyStatus;
use openxbdm_server::commands::network::netsim::Program;
use openxbdm_server::commands::network::netsim::QueueConfig;
use openxbdm_server::commands::network::netsim::QueueIndex;
use openxbdm_server::commands::network::netsim::QueueKind;
use openxbdm_server::commands::network::netsim::QueueSnapshot;
use openxbdm_server::commands::network::netsim::QueueStats;
use openxbdm_server::commands::network::netsim::RedirectConfig;
use openxbdm_server::commands::network::netsim::RedirectIndex;
use openxbdm_server::commands::network::netsim::RedirectSnapshot;
use openxbdm_server::commands::network::netsim::status;

use crate::backend::MockBackend;
use crate::backend::network::netcap::Attachment;

/// A queue of the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queue {
    pub kind: QueueKind,
    pub config: QueueConfig,
    /// Counters; tests set them to stand in for simulated traffic.
    pub stats: QueueStats,
    pub program: Option<Program>,
}

/// The simulator instance.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Instance {
    pub inbound: Vec<Queue>,
    pub outbound: Vec<Queue>,
    pub redirects: Vec<RedirectSnapshot>,
}

impl Instance {
    fn queues(&mut self, direction: Direction) -> &mut Vec<Queue> {
        match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        }
    }
}

/// Simulated state of `netsim`.
#[derive(Debug, Default)]
pub struct Mock {
    pub instance: Option<Instance>,
    /// Result of the next instance creation, standing in for intercept
    /// registration failures.
    pub create_error: Option<Hresult>,
    /// Instances created so far.
    pub created: u32,
    /// Instances destroyed so far.
    pub destroyed: u32,
    /// `XeKeysGetStatus` result.
    pub key_status: u32,
}

impl Mock {
    /// Whether the simulator instance exists; a starting capture chains
    /// into it instead of registering its own intercept.
    pub fn has_instance(&self) -> bool {
        self.instance.is_some()
    }

    fn instance(&mut self) -> Result<&mut Instance, Hresult> {
        self.instance.as_mut().ok_or(status::NO_INSTANCE)
    }
}

/// Insert before `position` or append; a position at or past the end is
/// rejected.
fn insert_at<T>(list: &mut Vec<T>, position: Option<u32>, item: T) -> Result<u32, Hresult> {
    match position {
        None => {
            list.push(item);
            Ok(list.len() as u32 - 1)
        }
        Some(index) if (index as usize) < list.len() => {
            list.insert(index as usize, item);
            Ok(index)
        }
        Some(_) => Err(status::INVALID),
    }
}

fn remove_at<T>(list: &mut Vec<T>, position: Option<u32>) -> Result<u32, Hresult> {
    match position {
        None => {
            let count = list.len() as u32;
            list.clear();
            Ok(count)
        }
        Some(index) if (index as usize) < list.len() => {
            list.remove(index as usize);
            Ok(1)
        }
        Some(_) => Err(status::INVALID),
    }
}

impl netsim::Backend for MockBackend {
    fn simulator_exists(&mut self) -> bool {
        self.network.netsim.has_instance()
    }

    /// A running capture moves from its own intercept into the instance;
    /// a failed registration leaves it unrouted (0x91f365e8).
    fn create_simulator(&mut self) -> Result<(), Hresult> {
        let mock = &mut self.network.netsim;
        if mock.instance.is_some() {
            return Err(status::INSTANCE_EXISTS);
        }
        let attachment = &mut self.network.netcap.attachment;
        if let Some(error) = mock.create_error.take() {
            if attachment.is_some() {
                *attachment = Some(Attachment::Unrouted);
            }
            return Err(error);
        }
        if attachment.is_some() {
            *attachment = Some(Attachment::Simulator);
        }
        mock.instance = Some(Instance::default());
        mock.created += 1;
        Ok(())
    }

    /// A chained capture returns to its own intercept (0x91f36750).
    fn destroy_simulator(&mut self) -> Result<(), Hresult> {
        let mock = &mut self.network.netsim;
        mock.instance.take().ok_or(status::INSTANCE_CHANGED)?;
        mock.destroyed += 1;
        let attachment = &mut self.network.netcap.attachment;
        if attachment.is_some() {
            *attachment = Some(Attachment::Intercept);
        }
        Ok(())
    }

    fn queue_count(&mut self, direction: Direction) -> u32 {
        self.network
            .netsim
            .instance()
            .map_or(0, |instance| instance.queues(direction).len() as u32)
    }

    fn redirect_count(&mut self) -> u32 {
        self.network
            .netsim
            .instance()
            .map_or(0, |instance| instance.redirects.len() as u32)
    }

    fn insert_queue(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
        kind: QueueKind,
        update: &QueueConfig,
        program: Option<&Program>,
    ) -> Result<QueueIndex, Hresult> {
        let instance = self.network.netsim.instance()?;
        let mut config = QueueConfig::default();
        config.merge(kind, update)?;
        let queue = Queue {
            kind,
            config,
            stats: QueueStats::default(),
            program: program.cloned(),
        };
        insert_at(
            instance.queues(direction),
            position.map(|QueueIndex(index)| index),
            queue,
        )
        .map(QueueIndex)
    }

    fn modify_queue(
        &mut self,
        direction: Direction,
        index: QueueIndex,
        update: &QueueConfig,
    ) -> Result<(), Hresult> {
        let instance = self.network.netsim.instance()?;
        let queue = instance
            .queues(direction)
            .get_mut(index.0 as usize)
            .ok_or(status::INVALID)?;
        queue.config.merge(queue.kind, update)?;
        Ok(())
    }

    fn remove_queues(
        &mut self,
        direction: Direction,
        position: Option<QueueIndex>,
    ) -> Result<u32, Hresult> {
        let instance = self.network.netsim.instance()?;
        remove_at(
            instance.queues(direction),
            position.map(|QueueIndex(index)| index),
        )
    }

    fn queue_stats(
        &mut self,
        direction: Direction,
        index: QueueIndex,
    ) -> Result<QueueStats, Hresult> {
        let instance = self.network.netsim.instance()?;
        instance
            .queues(direction)
            .get(index.0 as usize)
            .map(|queue| queue.stats)
            .ok_or(status::INVALID)
    }

    fn queue(&mut self, direction: Direction, index: QueueIndex) -> Result<QueueSnapshot, Hresult> {
        let instance = self.network.netsim.instance()?;
        instance
            .queues(direction)
            .get(index.0 as usize)
            .map(|queue| QueueSnapshot {
                kind: queue.kind,
                config: queue.config,
                program: queue.program.clone(),
            })
            .ok_or(status::INVALID)
    }

    fn insert_redirect(
        &mut self,
        position: Option<RedirectIndex>,
        redirect: &RedirectConfig,
        program: Option<&Program>,
    ) -> Result<RedirectIndex, Hresult> {
        let instance = self.network.netsim.instance()?;
        let redirect = RedirectSnapshot {
            config: *redirect,
            program: program.cloned(),
        };
        insert_at(
            &mut instance.redirects,
            position.map(|RedirectIndex(index)| index),
            redirect,
        )
        .map(RedirectIndex)
    }

    fn remove_redirects(&mut self, position: Option<RedirectIndex>) -> Result<u32, Hresult> {
        let instance = self.network.netsim.instance()?;
        remove_at(
            &mut instance.redirects,
            position.map(|RedirectIndex(index)| index),
        )
    }

    fn redirect(&mut self, index: RedirectIndex) -> Option<RedirectSnapshot> {
        self.network
            .netsim
            .instance
            .as_ref()?
            .redirects
            .get(index.0 as usize)
            .cloned()
    }

    fn key_status(&mut self) -> KeyStatus {
        KeyStatus(self.network.netsim.key_status)
    }
}
