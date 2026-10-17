//! Non-bridge implementation layer. Owns the tokio runtime and the
//! connected `openxbdm_client::Client`, and exposes synchronous helpers the
//! diplomat bridge calls into. Nothing in here is visible to C/C++.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;

use openxbdm_client::Client;
use openxbdm_client::Command;
use openxbdm_client::Connected;
use openxbdm_client::Notifications;
use openxbdm_client::commands::ExecutionState;
use openxbdm_client::commands::Notify;
use openxbdm_client::commands::screenshot::Screenshot;
use openxbdm_client::discovery;
use openxbdm_client::discovery::DiscoveredConsole;
use openxbdm_client::discovery::DiscoveryConfig;
use openxbdm_client::discovery::NAP_PORT;
use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::runtime::Runtime;
use tokio_util::compat::Compat;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::error::ClientError;

type Transport = Compat<TcpStream>;

/// Internal state of the FFI `OpenxbdmClient`. Owns a single-threaded tokio
/// runtime and the connected client. The mutex keeps things sound when a
/// host language shares one handle across threads.
pub struct BlockingClient {
    runtime: Runtime,
    client: Mutex<Client<Transport, Connected>>,
}

impl BlockingClient {
    pub fn connect(address: &str, timeout_secs: u32) -> Result<Self, ClientError> {
        let runtime = new_runtime()?;
        let client = runtime.block_on(connect_client(address, timeout_secs))?;

        Ok(Self {
            runtime,
            client: Mutex::new(client),
        })
    }

    /// Execute a typed [`openxbdm_client::Command`] and return its parsed output.
    pub fn run<C>(&self, cmd: C) -> Result<C::Output, ClientError>
    where
        C: Command,
    {
        let mut client = self.lock_client()?;

        Ok(self.runtime.block_on(client.run(cmd))?)
    }

    /// Capture a screenshot. Uses the bespoke method on `Client` (not a
    /// `Command` impl, since the response mixes a text metadata line with
    /// a binary framebuffer blob).
    pub fn screenshot(&self) -> Result<Screenshot, ClientError> {
        let mut client = self.lock_client()?;

        Ok(self.runtime.block_on(client.screenshot())?)
    }

    fn lock_client(&self) -> Result<MutexGuard<'_, Client<Transport, Connected>>, ClientError> {
        self.client
            .lock()
            .map_err(|_| ClientError::Poisoned { resource: "client" })
    }
}

/// A connection turned into a notification channel.
pub struct BlockingNotificationChannel {
    runtime: Runtime,
    channel: Mutex<Client<Transport, Notifications>>,
    execution: ExecutionState,
}

impl BlockingNotificationChannel {
    pub fn open(address: &str, timeout_secs: u32, request: Notify) -> Result<Self, ClientError> {
        let runtime = new_runtime()?;
        let (channel, execution) = runtime.block_on(async {
            let client = connect_client(address, timeout_secs).await?;

            Ok::<_, ClientError>(client.into_notification_channel(request).await?)
        })?;

        Ok(Self {
            runtime,
            channel: Mutex::new(channel),
            execution,
        })
    }

    pub fn execution_state(&self) -> &'static str {
        self.execution.name()
    }

    pub fn next_line(&self) -> Result<String, ClientError> {
        let mut channel = self.channel.lock().map_err(|_| ClientError::Poisoned {
            resource: "channel",
        })?;

        Ok(self.runtime.block_on(channel.next_notification())?)
    }
}

pub fn discover_all(timeout_ms: u32) -> Result<Vec<DiscoveredConsole>, ClientError> {
    run_discovery(discovery::discover_all(broadcast_config(timeout_ms)))
}

pub fn find_by_name(name: &str, timeout_ms: u32) -> Result<Option<DiscoveredConsole>, ClientError> {
    run_discovery(discovery::find_by_name(name, broadcast_config(timeout_ms)))
}

fn new_runtime() -> Result<Runtime, ClientError> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ClientError::Runtime)
}

async fn connect_client(
    address: &str,
    timeout_secs: u32,
) -> Result<Client<Transport, Connected>, ClientError> {
    let timeout = Duration::from_secs(timeout_secs.max(1) as u64);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| ClientError::ConnectTimeout {
            address: address.to_owned(),
        })?
        .map_err(|source| ClientError::Connect {
            address: address.to_owned(),
            source,
        })?;

    Ok(Client::new(stream.compat()).read_banner().await?)
}

fn broadcast_config(timeout_ms: u32) -> DiscoveryConfig {
    DiscoveryConfig {
        destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), NAP_PORT),
        listen_for: Duration::from_millis(timeout_ms.max(1) as u64),
        retransmits: 3,
        retransmit_interval: Duration::from_millis(400),
        broadcast: true,
    }
}

fn run_discovery<F, T>(discovery: F) -> Result<T, ClientError>
where
    F: Future<Output = Result<T, rootcause::Report<openxbdm_client::Error>>>,
{
    let runtime = new_runtime()?;

    Ok(runtime.block_on(discovery)?)
}
