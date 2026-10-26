use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::watch;
use std::thread::JoinHandle;
use std::time::Duration;

use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::XBDM_PORT;
use openxbdm_client::commands::BindController;
use openxbdm_client::commands::ControllerQueueLength;
use openxbdm_client::commands::Gamepad;
use openxbdm_client::commands::QueryControllerQueue;
use openxbdm_client::commands::UnbindController;
use openxbdm_client::commands::UserSlot;
use openxbdm_client::transport::tokio::Target;
use openxbdm_client::transport::tokio::TokioTransport;
use openxbdm_client::transport::tokio::connect_target_timeout;

use crate::error::RelayError;
use crate::gamepad::ControllerIdentity;
use crate::gamepad::OpenController;
use crate::script::ControllerScript;

#[derive(Debug, Clone)]
pub enum RelaySource {
    Hardware(ControllerIdentity),
    Script(PathBuf),
}

#[derive(Debug, Clone)]
pub struct RelayRequest {
    pub target: String,
    pub source: RelaySource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPhase {
    Preparing,
    Connecting,
    Relaying,
    PlayingScript,
    Stopping,
    Stopped,
    Completed,
    Failed(String),
}

impl RelayPhase {
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Preparing
                | Self::Connecting
                | Self::Relaying
                | Self::PlayingScript
                | Self::Stopping
        )
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Preparing => "Preparing input source",
            Self::Connecting => "Connecting",
            Self::Relaying => "Relaying controller input",
            Self::PlayingScript => "Playing controller script",
            Self::Stopping => "Stopping",
            Self::Stopped => "Stopped",
            Self::Completed => "Completed",
            Self::Failed(_) => "Failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelaySnapshot {
    pub phase: RelayPhase,
    pub target: String,
    pub console_banner: Option<String>,
    pub packets_sent: u64,
    pub last_gamepad: Option<Gamepad>,
    pub script_frames: Option<u32>,
    pub script_frames_remaining: Option<u32>,
}

impl RelaySnapshot {
    fn new(target: String) -> Self {
        Self {
            phase: RelayPhase::Preparing,
            target,
            console_banner: None,
            packets_sent: 0,
            last_gamepad: None,
            script_frames: None,
            script_frames_remaining: None,
        }
    }
}

#[derive(Debug)]
pub struct RelayWorker {
    snapshot: Arc<Mutex<RelaySnapshot>>,
    stop: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl RelayWorker {
    pub fn start(request: RelayRequest) -> Result<Self, std::io::Error> {
        let snapshot = Arc::new(Mutex::new(RelaySnapshot::new(request.target.clone())));
        let (stop, worker_stop) = watch::channel(false);
        let worker_snapshot = Arc::clone(&snapshot);
        let thread = std::thread::Builder::new()
            .name("xeedee-controller-relay".to_owned())
            .spawn(move || relay_thread(request, worker_snapshot, worker_stop))?;

        Ok(Self {
            snapshot,
            stop,
            thread: Some(thread),
        })
    }

    pub fn snapshot(&self) -> Option<RelaySnapshot> {
        self.snapshot.lock().ok().map(|snapshot| snapshot.clone())
    }

    pub fn stop(&self) {
        self.stop.send_replace(true);
        update_snapshot(&self.snapshot, |snapshot| {
            if snapshot.phase.is_active() {
                snapshot.phase = RelayPhase::Stopping;
            }
        });
    }

    pub fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }

    pub fn join(&mut self) -> Result<(), RelayError> {
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };

        thread.join().map_err(|_| RelayError::WorkerPanicked)
    }
}

impl Drop for RelayWorker {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[derive(Debug)]
enum PreparedSource {
    Hardware(OpenController),
    Script(ControllerScript),
}

fn relay_thread(
    request: RelayRequest,
    snapshot: Arc<Mutex<RelaySnapshot>>,
    mut stop: watch::Receiver<bool>,
) {
    let result = prepare_source(request.source).and_then(|source| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(RelayError::Runtime)?;

        runtime.block_on(run_relay(
            request.target,
            source,
            Arc::clone(&snapshot),
            &mut stop,
        ))
    });

    update_snapshot(&snapshot, |snapshot| match result {
        Ok(()) if *stop.borrow() => snapshot.phase = RelayPhase::Stopped,
        Ok(()) => snapshot.phase = RelayPhase::Completed,
        Err(RelayError::Cancelled) => snapshot.phase = RelayPhase::Stopped,
        Err(error) => snapshot.phase = RelayPhase::Failed(error.to_string()),
    });
}

fn prepare_source(source: RelaySource) -> Result<PreparedSource, RelayError> {
    match source {
        RelaySource::Hardware(identity) => OpenController::open(identity)
            .map(PreparedSource::Hardware)
            .map_err(Into::into),
        RelaySource::Script(path) => ControllerScript::load(&path)
            .map(PreparedSource::Script)
            .map_err(Into::into),
    }
}

async fn run_relay(
    target: String,
    source: PreparedSource,
    snapshot: Arc<Mutex<RelaySnapshot>>,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), RelayError> {
    update_snapshot(&snapshot, |snapshot| {
        snapshot.phase = RelayPhase::Connecting;
    });
    let target = Target::parse(&target, XBDM_PORT);
    let transport = interruptible(
        stop,
        "connecting to the console",
        connect_target_timeout(&target, Duration::from_secs(5)),
    )
    .await?;
    let mut client = interruptible(
        stop,
        "reading the console banner",
        Client::new(transport).read_banner(),
    )
    .await?;
    let banner = client.banner().to_owned();
    update_snapshot(&snapshot, |snapshot| {
        snapshot.console_banner = Some(banner);
    });

    let user = UserSlot::new(0).expect("user zero is a valid controller slot");
    let queue_length = match &source {
        PreparedSource::Hardware(_) => ControllerQueueLength::FIXED_STATE,
        PreparedSource::Script(script) => script.queue_length(),
    };
    interruptible(
        stop,
        "binding the virtual controller",
        client.run(BindController { user, queue_length }),
    )
    .await?;

    let operation = match source {
        PreparedSource::Hardware(controller) => {
            relay_hardware(&mut client, user, controller, &snapshot, stop).await
        }
        PreparedSource::Script(script) => {
            play_script(&mut client, user, script, &snapshot, stop).await
        }
    };
    if matches!(
        &operation,
        Err(RelayError::Cancelled | RelayError::Timeout { .. })
    ) {
        return operation;
    }

    let cleanup = cleanup(&mut client, user).await;
    let close = timed_console_operation("closing the console session", client.bye()).await;

    operation.and(cleanup).and(close)
}

async fn relay_hardware(
    client: &mut Client<TokioTransport, Connected>,
    user: UserSlot,
    mut controller: OpenController,
    snapshot: &Arc<Mutex<RelaySnapshot>>,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), RelayError> {
    let mut last = controller.state()?;
    interruptible(
        stop,
        "sending a controller packet",
        client.set_gamepad(user, last),
    )
    .await?;
    record_packet(snapshot, last);
    update_snapshot(snapshot, |snapshot| {
        snapshot.phase = RelayPhase::Relaying;
    });

    while !*stop.borrow() {
        if let Some(packet) = controller.update()?
            && packet != last
        {
            interruptible(
                stop,
                "sending a controller packet",
                client.set_gamepad(user, packet),
            )
            .await?;
            last = packet;
            record_packet(snapshot, packet);
        }

        wait_or_stop(stop, Duration::from_millis(4)).await;
    }

    Ok(())
}

async fn play_script(
    client: &mut Client<TokioTransport, Connected>,
    user: UserSlot,
    script: ControllerScript,
    snapshot: &Arc<Mutex<RelaySnapshot>>,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), RelayError> {
    let requested = script.frame_count();
    let accepted = interruptible(
        stop,
        "uploading the controller script",
        client.queue_gamepads(user, script.frames()),
    )
    .await?
    .0;
    if accepted != requested {
        return Err(RelayError::PartialScript {
            accepted,
            requested,
        });
    }

    update_snapshot(snapshot, |snapshot| {
        snapshot.phase = RelayPhase::PlayingScript;
        snapshot.packets_sent = u64::from(accepted);
        snapshot.last_gamepad = script.frames().first().map(|frame| frame.packet);
        snapshot.script_frames = Some(requested);
        snapshot.script_frames_remaining = Some(accepted);
    });

    while !*stop.borrow() {
        let status = interruptible(
            stop,
            "querying controller script progress",
            client.run(QueryControllerQueue { user }),
        )
        .await?;
        let completed = requested.saturating_sub(status.queued);
        let packet = usize::try_from(completed)
            .ok()
            .and_then(|index| script.frames().get(index))
            .or_else(|| script.frames().last())
            .map(|frame| frame.packet);
        update_snapshot(snapshot, |snapshot| {
            snapshot.last_gamepad = packet;
            snapshot.script_frames_remaining = Some(status.queued);
        });
        if status.queued == 0 && status.remaining_ms == 0 && status.remaining_polls == 0 {
            return Ok(());
        }

        wait_or_stop(stop, Duration::from_millis(25)).await;
    }

    Ok(())
}

async fn cleanup(
    client: &mut Client<TokioTransport, Connected>,
    user: UserSlot,
) -> Result<(), RelayError> {
    let neutral = timed_console_operation(
        "resetting the virtual controller",
        client.set_gamepad(user, Gamepad::default()),
    )
    .await;
    let unbind = timed_console_operation(
        "unbinding the virtual controller",
        client.run(UnbindController { user }),
    )
    .await;

    neutral.and(unbind)
}

async fn interruptible<T>(
    stop: &mut watch::Receiver<bool>,
    operation: &'static str,
    future: impl Future<Output = Result<T, rootcause::Report<openxbdm_client::Error>>>,
) -> Result<T, RelayError> {
    if *stop.borrow() {
        return Err(RelayError::Cancelled);
    }

    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(10), future) => {
            result
                .map_err(|_| RelayError::Timeout { operation })?
                .map_err(console_error)
        }
        _ = stop.changed() => Err(RelayError::Cancelled),
    }
}

async fn timed_console_operation<T>(
    operation: &'static str,
    future: impl Future<Output = Result<T, rootcause::Report<openxbdm_client::Error>>>,
) -> Result<T, RelayError> {
    tokio::time::timeout(Duration::from_secs(10), future)
        .await
        .map_err(|_| RelayError::Timeout { operation })?
        .map_err(console_error)
}

async fn wait_or_stop(stop: &mut watch::Receiver<bool>, duration: Duration) {
    if *stop.borrow() {
        return;
    }

    _ = tokio::time::timeout(duration, stop.changed()).await;
}

fn record_packet(snapshot: &Arc<Mutex<RelaySnapshot>>, packet: Gamepad) {
    update_snapshot(snapshot, |snapshot| {
        snapshot.packets_sent = snapshot.packets_sent.saturating_add(1);
        snapshot.last_gamepad = Some(packet);
    });
}

fn update_snapshot(snapshot: &Arc<Mutex<RelaySnapshot>>, update: impl FnOnce(&mut RelaySnapshot)) {
    let Ok(mut snapshot) = snapshot.lock() else {
        return;
    };

    update(&mut snapshot);
}

fn console_error(report: rootcause::Report<openxbdm_client::Error>) -> RelayError {
    RelayError::Console { report }
}
