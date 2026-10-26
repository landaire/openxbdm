//! PIX profiler probes: `pixcmd-probe` and `pix-notify`.

use std::fs::File;
use std::io::Write as _;
use std::time::Duration;
use std::time::Instant;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::Notify;
use openxbdm_client::commands::pix::Notification;
use openxbdm_client::commands::pix::PixCmd;
use openxbdm_client::error::Error;
use openxbdm_client::transport::tokio::Target;
use openxbdm_client::transport::tokio::connect_target_timeout;
use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::ui::ok_tag;
use crate::ui::warn_tag;

pub async fn pixcmd_probe<T>(
    client: &mut Client<T, Connected>,
    subcommand: &str,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = PixCmd::new(client);
    let response = session.raw(subcommand).await?;
    println!("{response:#?}");

    Ok(())
}

/// Print every notification line, tagged with its classification, for
/// `duration_secs` seconds. 0 listens until interrupted.
pub async fn pix_notify(
    target: &Target,
    conn_timeout: Duration,
    duration_secs: u64,
    log_path: Option<&str>,
) -> Result<(), Report<Error>> {
    let duration = (duration_secs != 0).then(|| Duration::from_secs(duration_secs));

    let transport = connect_target_timeout(target, conn_timeout).await?;
    let client = Client::new(transport).read_banner().await?;

    // xbdm answers `notify` with the 205 line and the current execution
    // state, then sends events at its own discretion.
    let (mut channel, execution) = client.into_notification_channel(Notify::default()).await?;
    eprintln!(
        "{} execution {}; {}",
        ok_tag("subscribed"),
        execution.name(),
        match duration {
            Some(_) => format!("stopping in {duration_secs}s"),
            None => "Ctrl-C to stop".to_owned(),
        }
    );

    let mut log_file = match log_path {
        Some(path) => Some(
            File::create(path)
                .map_err(Error::from)
                .into_report()
                .attach_with(|| format!("creating notify log {path}"))?,
        ),
        None => None,
    };

    let start = Instant::now();
    loop {
        let result = match duration {
            Some(duration) => {
                let remaining = duration.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    break;
                }
                let Ok(result) = tokio::time::timeout(remaining, channel.next_notification()).await
                else {
                    break;
                };
                result
            }
            None => channel.next_notification().await,
        };

        let line = match result {
            Ok(line) => line,
            Err(report) if matches!(report.current_context(), Error::ConnectionClosed) => {
                eprintln!("{} notification channel closed", warn_tag("eof:"));
                break;
            }
            Err(report) => return Err(report),
        };
        if line.is_empty() {
            continue;
        }

        let elapsed_ms = start.elapsed().as_millis();
        let rendered = format!("{elapsed_ms:>6}ms [{}] {line}", notification_tag(&line));
        eprintln!("{rendered}");

        // The log is a convenience copy; a failed write does not stop the
        // monitor.
        if let Some(file) = log_file.as_mut() {
            let _ = writeln!(file, "{rendered}");
        }
    }

    Ok(())
}

fn notification_tag(line: &str) -> &'static str {
    match Notification::parse(line) {
        Ok(Some(Notification::CaptureFileCreationEnded { .. })) => "cap-seg",
        Ok(Some(Notification::CaptureEnded)) => "cap-end",
        Ok(Some(Notification::MovieData(_))) => "movie",
        Ok(Some(Notification::Resource(_))) => "rsrc",
        Ok(Some(Notification::VideoOp { error: true, .. })) => "verr",
        Ok(Some(Notification::VideoOp { error: false, .. })) => "vop",
        Ok(Some(Notification::Status(_))) => "stat",
        Ok(Some(Notification::Other(_))) => "pix?",
        Ok(None) => "line",
        // Shown verbatim: the monitor displays every line.
        Err(_) => "malformed",
    }
}
