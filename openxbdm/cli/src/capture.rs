//! `capture`: record an xbmovie-style PIX! movie capture, download its
//! segments, and convert them to MP4.

use std::time::Duration;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::ParseError;
use openxbdm_client::commands::Delete;
use openxbdm_client::commands::DirList;
use openxbdm_client::commands::GetFileRange;
use openxbdm_client::commands::Hresult;
use openxbdm_client::commands::Notify;
use openxbdm_client::commands::pix::CaptureRemotePath;
use openxbdm_client::commands::pix::CaptureSession;
use openxbdm_client::commands::pix::ConnectOutcome;
use openxbdm_client::commands::pix::Notification;
use openxbdm_client::commands::pix::PixError;
use openxbdm_client::error::Error;
use openxbdm_client::transport::tokio::Target;
use openxbdm_client::transport::tokio::connect_target_timeout;
use rootcause::Report;
use rootcause::prelude::ResultExt;
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use crate::progress::ProgressWrite;
use crate::ui::UiOptions;
use crate::ui::ok_tag;
use crate::ui::warn_tag;
use crate::xbm;

type NotificationReceiver = mpsc::UnboundedReceiver<Result<Notification, ParseError>>;

pub struct CaptureOptions {
    /// Device-side capture path, sent verbatim to the PIX handler.
    pub remote: String,
    pub size_limit_mb: u32,
    /// Capture length; `None` captures until Enter is pressed.
    pub duration: Option<Duration>,
    pub output_dir: String,
    pub no_conversion: bool,
}

pub async fn capture(
    target: &Target,
    conn_timeout: Duration,
    options: CaptureOptions,
    ui: UiOptions,
) -> Result<(), Report<Error>> {
    std::fs::create_dir_all(&options.output_dir)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating local output dir {}", options.output_dir))?;

    // The handler signals capture file creation and capture end only on the
    // notification channel. Subscribe first so no event is missed.
    let (notify_task, mut notifications) = subscribe(target, conn_timeout).await?;

    let command_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut client = Client::new(command_transport).read_banner().await?;
    record(&mut client, &mut notifications, &options).await?;
    notify_task.abort();

    // xbdm rejects file commands on the dedicated PIX command connection
    // ("dedicated connection required"), so segments are downloaded over a
    // new connection.
    drop(client);
    let files_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut client = Client::new(files_transport).read_banner().await?;
    eprintln!("{} capture finalised, downloading segments", ok_tag("done"));

    let downloaded =
        download_segments(&mut client, &options.remote, &options.output_dir, ui).await?;
    if options.no_conversion || downloaded.is_empty() {
        return Ok(());
    }

    convert_segments(&downloaded);

    Ok(())
}

/// Open a notification channel and forward its PIX notifications.
async fn subscribe(
    target: &Target,
    conn_timeout: Duration,
) -> Result<(JoinHandle<()>, NotificationReceiver), Report<Error>> {
    let transport = connect_target_timeout(target, conn_timeout).await?;
    let client = Client::new(transport).read_banner().await?;
    let request = Notify {
        reverse: true,
        ..Default::default()
    };
    let (mut channel, _) = client.into_notification_channel(request).await?;

    let (sender, receiver) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok(line) = channel.next_notification().await {
            let notification = match Notification::parse(&line) {
                Ok(Some(notification)) => Ok(notification),
                Ok(None) => {
                    tracing::debug!(target: "openxbdm_client::pix", line = %line, "non-pix notify line");
                    continue;
                }
                Err(e) => Err(e),
            };
            if sender.send(notification).is_err() {
                break;
            }
        }
    });

    Ok((task, receiver))
}

/// Run the capture session on the command connection, from connecting to
/// the PIX handler until it has flushed every segment.
async fn record<T>(
    client: &mut Client<T, Connected>,
    notifications: &mut NotificationReceiver,
    options: &CaptureOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let ConnectOutcome {
        mut session,
        handler_detected,
    } = CaptureSession::connect(client).await?;
    if handler_detected {
        eprintln!(
            "{} PIX handler responded to {{Connect}}",
            ok_tag("connected")
        );
    } else {
        eprintln!(
            "{} no title has registered as the PIX handler (got plain `OK`). \
             Continuing anyway, but subsequent commands will likely no-op.",
            warn_tag("warning:")
        );
    }

    session.limit_capture_size_mb(options.size_limit_mb).await?;
    session.begin_capture_file_creation(&options.remote).await?;
    eprintln!(
        "{} requested capture file -> {}, waiting for \
         {{CaptureFileCreationEnded}} on notify channel",
        ok_tag("prepared"),
        options.remote,
    );

    let result = wait_for_capture_file(notifications).await?;
    if result.is_failure() {
        return Err(Report::new(Error::from(
            PixError::CaptureFileCreationFailed { result },
        )));
    }
    eprintln!("{} capture file ready", ok_tag("ready"));

    session.begin_capture().await?;
    eprintln!(
        "{} capturing; {}",
        ok_tag("recording"),
        match options.duration {
            Some(duration) => format!("stopping in {}s", duration.as_secs()),
            None => "press Enter to stop".to_owned(),
        }
    );

    match options.duration {
        Some(duration) => tokio::time::sleep(duration).await,
        None => {
            let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            let _ = lines.next_line().await;
        }
    }

    session.end_capture().await?;
    session.end_capture_file_creation().await?;
    eprintln!(
        "{} capture closed, waiting for {{CaptureEnded}}",
        ok_tag("stopping")
    );

    // `{CaptureEnded}` means every segment is on disk. Without it, the
    // download still collects whatever segments exist.
    let _ = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(notification) = notifications.recv().await {
            if matches!(notification, Ok(Notification::CaptureEnded)) {
                break;
            }
        }
    })
    .await;

    session.disconnect().await?;

    Ok(())
}

/// Wait for `{CaptureFileCreationEnded}` and return its result. The
/// handler acknowledges `{BeginCaptureFileCreation}` before the file
/// exists, so readiness is only known from this notification.
async fn wait_for_capture_file(
    notifications: &mut NotificationReceiver,
) -> Result<Hresult, Report<Error>> {
    const FILE_READY_TIMEOUT: Duration = Duration::from_secs(30);

    let wait = async {
        loop {
            match notifications.recv().await {
                Some(Ok(Notification::CaptureFileCreationEnded { result })) => return Ok(result),
                Some(Ok(other)) => {
                    tracing::debug!(
                        target: "openxbdm_client::pix",
                        ?other,
                        "notify while waiting for CaptureFileCreationEnded",
                    );
                }
                Some(Err(e)) => return Err(Report::new(Error::from(e))),
                None => {
                    return Err(Report::new(Error::from(
                        PixError::NotificationChannelClosed,
                    )));
                }
            }
        }
    };

    tokio::time::timeout(FILE_READY_TIMEOUT, wait)
        .await
        .map_err(|_| {
            Report::new(Error::from(PixError::CaptureFileCreationTimedOut {
                timeout: FILE_READY_TIMEOUT,
            }))
            .attach("is a title actually rendering D3D frames?")
        })?
}

/// Download every segment of the capture at `remote` into `output_dir`,
/// deleting each from the console. Returns the local paths written.
async fn download_segments<T>(
    client: &mut Client<T, Connected>,
    remote: &str,
    output_dir: &str,
    ui: UiOptions,
) -> Result<Vec<String>, Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // The parent directory is listed in DOS form rather than stat'ing
    // segment paths, because NT device paths do not always resolve back.
    let capture_path = CaptureRemotePath::parse(remote);
    let CaptureRemotePath {
        parent,
        stem,
        extension,
    } = &capture_path;
    eprintln!(
        "{} scanning {parent} for segments (stem={stem:?}, ext={extension:?})",
        ok_tag("looking"),
    );

    // A failed listing is reported and handled as an empty directory.
    let entries = match client
        .run(DirList {
            path: parent.clone(),
        })
        .await
    {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!(
                "{} dirlist failed on {parent}: {:?}",
                warn_tag("warn:"),
                e.current_context()
            );
            vec![]
        }
    };
    tracing::debug!(target: "openxbdm_client::pix", entry_count = entries.len(), "dirlist returned");

    let mut segments: Vec<(u32, String)> = entries
        .into_iter()
        .filter(|entry| !entry.is_directory)
        .filter_map(|entry| {
            let index = capture_path.segment_index(&entry.name)?;
            Some((index, entry.name))
        })
        .collect();
    segments.sort_by_key(|(index, _)| *index);
    if segments.is_empty() {
        eprintln!(
            "{} no files matching {stem}<N>{extension} in {parent}. \
             Either the handler produced no output this run, or the \
             previous segments have already been deleted.",
            warn_tag("warn:"),
        );
    }

    // Each segment is deleted from the console once handled; a failed
    // delete is ignored.
    let total_segments = segments.len();
    let mut bytes_downloaded = 0u64;
    let mut downloaded = Vec::new();
    for (index, name) in segments {
        let remote_path = format!("{parent}{name}");
        let local_path = format!("{output_dir}/{name}");

        let download = client
            .get_file(&remote_path, GetFileRange::WholeFile)
            .await?;
        let total = download.total();
        if total == 0 {
            // Release the streaming borrow before reusing `client`.
            drop(download);
            eprintln!("{} segment {index}: empty, skipping", warn_tag("skip:"));
            let _ = client
                .run(Delete {
                    path: remote_path,
                    is_directory: false,
                })
                .await;
            continue;
        }

        let bar = ui.progress(total, &format!("segment {index}"));
        let file = tokio::fs::File::create(&local_path)
            .await
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("creating {local_path}"))?;
        let mut tracked = ProgressWrite::new(file.compat_write(), bar.clone());
        let copied = download.copy_into(&mut tracked).await?;
        bar.finish_and_clear();
        eprintln!(
            "{} segment {index}: {copied} bytes -> {local_path}",
            ok_tag("saved")
        );

        let _ = client
            .run(Delete {
                path: remote_path,
                is_directory: false,
            })
            .await;
        bytes_downloaded += copied;
        downloaded.push(local_path);
    }

    eprintln!(
        "{} downloaded {}/{total_segments} segment{s} ({})",
        ok_tag("finished"),
        downloaded.len(),
        ui.format_bytes(bytes_downloaded),
        s = if total_segments == 1 { "" } else { "s" },
    );

    Ok(downloaded)
}

/// Encode each downloaded `.xbm` to an `.mp4` beside it, deleting the
/// `.xbm` on success. Failures are reported and leave the `.xbm` in place.
fn convert_segments(xbm_paths: &[String]) {
    if let Err(e) = xbm::require_ffmpeg() {
        eprintln!(
            "{} skipping conversion: {}. Pass --no-conversion to silence.",
            warn_tag("warn:"),
            e.current_context()
        );
        return;
    }

    for xbm_path in xbm_paths {
        let mp4_path = match xbm_path.strip_suffix(".xbm") {
            Some(stem) => format!("{stem}.mp4"),
            None => format!("{xbm_path}.mp4"),
        };
        eprintln!("{} encoding {xbm_path} -> {mp4_path}", ok_tag("converting"));

        if let Err(e) = xbm::encode_to_mp4(xbm_path, &mp4_path, "frame", None, 20, &[]) {
            eprintln!(
                "{} conversion of {xbm_path} failed: {:?}; raw file retained",
                warn_tag("warn:"),
                e.current_context()
            );
            continue;
        }

        match std::fs::remove_file(xbm_path) {
            Ok(()) => eprintln!("{} removed {xbm_path}", ok_tag("cleaned")),
            Err(e) => eprintln!(
                "{} could not delete {xbm_path} after encode: {e}",
                warn_tag("warn:")
            ),
        }
    }
}
