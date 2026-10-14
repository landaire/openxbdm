//! Non-bridge implementation layer. Owns the tokio runtime and the
//! connected `openxbdm_client::Client`, and exposes synchronous helpers the
//! diplomat bridge calls into. Nothing in here is visible to C/C++.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::runtime::Builder;
use tokio::runtime::Runtime;
use tokio_util::compat::Compat;
use tokio_util::compat::TokioAsyncReadCompatExt;

use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::Notifications;
use openxbdm_client::commands::ExecutionState;
use openxbdm_client::commands::Notify;
use openxbdm_client::discovery::DiscoveredConsole;
use openxbdm_client::discovery::DiscoveryConfig;
use openxbdm_client::discovery::NAP_PORT;
use openxbdm_client::discovery::discover_all;
use openxbdm_client::discovery::find_by_name;

type Transport = Compat<TcpStream>;

/// Internal state of the FFI `OpenxbdmClient`. Owns a single-threaded tokio
/// runtime and the connected client. The mutex keeps things sound when a
/// host language shares one handle across threads.
pub struct Inner {
    runtime: Runtime,
    client: Mutex<Client<Transport, Connected>>,
}

impl Inner {
    pub fn connect(address: &str, timeout_secs: u32) -> Result<Self, String> {
        let runtime = new_runtime()?;
        let client = runtime.block_on(connect_client(address, timeout_secs))?;
        Ok(Self {
            runtime,
            client: Mutex::new(client),
        })
    }

    /// Execute a typed [`openxbdm_client::Command`] and return its parsed output.
    pub fn run<C>(&self, cmd: C) -> Result<C::Output, String>
    where
        C: openxbdm_client::Command,
    {
        let mut client = self
            .client
            .lock()
            .map_err(|_| "client mutex poisoned".to_string())?;
        self.runtime
            .block_on(client.run(cmd))
            .map_err(|e| format!("{}", e.current_context()))
    }

    /// Capture a screenshot. Uses the bespoke method on `Client` (not a
    /// `Command` impl, since the response mixes a text metadata line with
    /// a binary framebuffer blob).
    pub fn screenshot(&self) -> Result<openxbdm_client::commands::screenshot::Screenshot, String> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| "client mutex poisoned".to_string())?;
        self.runtime
            .block_on(client.screenshot())
            .map_err(|e| format!("{}", e.current_context()))
    }
}

/// A connection turned into a notification channel.
pub struct NotificationInner {
    runtime: Runtime,
    channel: Mutex<Client<Transport, Notifications>>,
    execution: ExecutionState,
}

impl NotificationInner {
    pub fn open(address: &str, timeout_secs: u32, request: Notify) -> Result<Self, String> {
        let runtime = new_runtime()?;
        let (channel, execution) = runtime.block_on(async {
            let client = connect_client(address, timeout_secs).await?;
            client
                .into_notification_channel(request)
                .await
                .map_err(|e| format!("{}", e.current_context()))
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

    pub fn next_line(&self) -> Result<String, String> {
        let mut channel = self
            .channel
            .lock()
            .map_err(|_| "channel mutex poisoned".to_string())?;
        self.runtime
            .block_on(channel.next_notification())
            .map_err(|e| format!("{}", e.current_context()))
    }
}

fn new_runtime() -> Result<Runtime, String> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("creating tokio runtime: {e}"))
}

async fn connect_client(
    address: &str,
    timeout_secs: u32,
) -> Result<Client<Transport, Connected>, String> {
    let timeout = Duration::from_secs(timeout_secs.max(1) as u64);
    let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
        .await
        .map_err(|_| format!("connect to {address} timed out"))?
        .map_err(|e| format!("connecting to {address}: {e}"))?;
    Client::new(stream.compat())
        .read_banner()
        .await
        .map_err(|e| format!("{}", e.current_context()))
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

fn run_discovery<F, T>(f: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, rootcause::Report<openxbdm_client::Error>>>,
{
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("creating tokio runtime: {e}"))?;
    runtime
        .block_on(f)
        .map_err(|e| format!("{}", e.current_context()))
}

pub fn discover_all_blocking(timeout_ms: u32) -> Result<Vec<DiscoveredConsole>, String> {
    run_discovery(discover_all(broadcast_config(timeout_ms)))
}

pub fn find_by_name_blocking(
    name: &str,
    timeout_ms: u32,
) -> Result<Option<DiscoveredConsole>, String> {
    run_discovery(find_by_name(name, broadcast_config(timeout_ms)))
}
