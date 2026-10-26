//! `dangerous`: subcommands that write into xbdm's memory image.

use std::path::PathBuf;
use std::time::Duration;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::DriveList;
use openxbdm_client::commands::GetFileRange;
use openxbdm_client::commands::dangerous::drivemap;
use openxbdm_client::commands::dangerous::drivemap::DrivemapEnableReport;
use openxbdm_client::error::ArgumentError;
use openxbdm_client::error::Error;
use openxbdm_client::transport::tokio::Target;
use openxbdm_client::transport::tokio::connect_target_timeout;
use rootcause::Report;

use crate::args::DangerousCommand;
use crate::file::DownloadResult;
use crate::file::download_file;
use crate::ui::UiOptions;
use crate::ui::ok_tag;
use crate::ui::warn_tag;

pub async fn run<T>(
    client: &mut Client<T, Connected>,
    command: DangerousCommand,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match command {
        DangerousCommand::DrivemapStatus => {
            let status = drivemap::status(client).await?;
            println!(
                "xbdm @ {:#010x}, drivemap_fn @ {:#010x}, flag @ {:#010x} = {:#010x}, altaddr entry @ {:#010x}",
                status.layout.module.base,
                status.layout.drivemap_fn,
                status.layout.flag_global,
                status.flag_value,
                status.layout.altaddr_entry.name_ptr_addr
            );
            println!("visible drives: {:?}", status.visible_drives);
        }
        DangerousCommand::DrivemapPersist => {
            let report = drivemap::persist(client).await?;
            eprintln!(
                "{} wrote {} bytes to {}",
                ok_tag("persisted"),
                report.bytes_written,
                report.path
            );
        }
        DangerousCommand::DrivemapEnable => {
            unreachable!("DrivemapEnable is handled by drivemap_enable before drive_connected")
        }
        DangerousCommand::NandDump { .. } => {
            unreachable!("NandDump is handled by nand_dump before drive_connected")
        }
    }

    Ok(())
}

pub async fn drivemap_enable(target: &Target, conn_timeout: Duration) -> Result<(), Report<Error>> {
    let report = enable(target, conn_timeout).await?;

    if report.already_enabled {
        let drive_count = report.drives_after.len();
        eprintln!(
            "{} drivemap flag already set; skipped hijack. {drive_count} drive{} visible.",
            ok_tag("no-op"),
            if drive_count == 1 { "" } else { "s" }
        );
    } else {
        eprintln!(
            "{} drivemap internal enabled. drives went from {} -> {} entries.",
            ok_tag("done"),
            report.drives_before.len(),
            report.drives_after.len()
        );
    }

    for drive in &report.drives_after {
        println!("{drive}");
    }

    Ok(())
}

pub async fn nand_dump(
    target: &Target,
    conn_timeout: Duration,
    output: Option<&str>,
    ui: UiOptions,
) -> Result<(), Report<Error>> {
    let output_path = PathBuf::from(output.unwrap_or("nand.bin"));

    // A FLASH drive in the drive list makes the enable flow, and its
    // readback of xbdm's sections, unnecessary. A failed probe counts as
    // not mounted.
    let probe_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut probe = Client::new(probe_transport).read_banner().await?;
    let drives = probe.run(DriveList).await.unwrap_or_default();
    let flash_visible = has_flash(&drives);
    let _ = probe.bye().await;

    if !flash_visible {
        eprintln!(
            "{} FLASH: not mounted; running drivemap-enable first",
            warn_tag("note:")
        );
        let report = enable(target, conn_timeout).await?;
        if !has_flash(&report.drives_after) {
            return Err(Report::new(Error::from(ArgumentError::EmptyFilename))
                .attach("drivemap-enable completed but FLASH: is still not mounted"));
        }
    }

    let download_transport = connect_target_timeout(target, conn_timeout).await?;
    let mut client = Client::new(download_transport).read_banner().await?;
    // `getfile` on `FLASH:\` returns the raw NAND image even though `stat`
    // reports a directory, so the directory check of `file get` is skipped.
    let DownloadResult { copied, total } = download_file(
        &mut client,
        "FLASH:\\",
        &output_path,
        GetFileRange::WholeFile,
        ui,
    )
    .await?;
    eprintln!(
        "{} NAND dump: {copied} bytes ({total} declared) to {}",
        ok_tag("done"),
        output_path.display()
    );
    let _ = client.bye().await;

    Ok(())
}

/// Run the drivemap enable flow. The hijacked connection is abandoned with
/// a hung read, so the flow reconnects for its follow-up commands.
async fn enable(
    target: &Target,
    conn_timeout: Duration,
) -> Result<DrivemapEnableReport, Report<Error>> {
    const INVOKE_TIMEOUT: Duration = Duration::from_secs(3);

    let hijack_transport = connect_target_timeout(target, conn_timeout).await?;
    let hijack = Client::new(hijack_transport).read_banner().await?;

    let reconnect_target = target.clone();
    let reconnect = move || {
        let target = reconnect_target.clone();
        async move {
            let transport = connect_target_timeout(&target, conn_timeout).await?;
            let client = Client::new(transport).read_banner().await?;
            Ok::<_, Report<Error>>(client)
        }
    };

    drivemap::enable(hijack, reconnect, INVOKE_TIMEOUT).await
}

fn has_flash(drives: &[String]) -> bool {
    drives
        .iter()
        .any(|drive| drive.eq_ignore_ascii_case("flash"))
}
