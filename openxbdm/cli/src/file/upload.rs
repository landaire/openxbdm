//! `file put` and `file writeto`: send a local file to the console.

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::FileUploadKind;
use openxbdm_client::error::Error;
use rootcause::Report;
use rootcause::prelude::ResultExt;
use tokio::fs::File;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::progress::ProgressRead;
use crate::ui::UiOptions;
use crate::ui::ok_tag;

pub async fn put<T>(
    client: &mut Client<T, Connected>,
    local: &str,
    remote: &str,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let metadata = std::fs::metadata(local)
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("stat local file {local:?}"))?;
    let size = u32::try_from(metadata.len())
        .map_err(|_| {
            Error::from(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "sendfile lengths are 32-bit",
            ))
        })
        .into_report()
        .attach_with(|| format!("local file {local:?} is {} bytes", metadata.len()))?;

    let mut file = open_local(local).await?;
    send(
        client,
        &mut file,
        remote,
        FileUploadKind::Create { size },
        size,
        "upload",
        ui,
    )
    .await?;
    eprintln!("{} {size} bytes to {remote}", ok_tag("uploaded"));

    Ok(())
}

pub async fn write_to<T>(
    client: &mut Client<T, Connected>,
    local: &str,
    remote: &str,
    offset: u32,
    length: u32,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut file = open_local(local).await?;
    send(
        client,
        &mut file,
        remote,
        FileUploadKind::WriteAt {
            offset,
            size: length,
        },
        length,
        "write",
        ui,
    )
    .await?;
    eprintln!(
        "{} {length} bytes at offset {offset} in {remote}",
        ok_tag("wrote")
    );

    Ok(())
}

async fn open_local(local: &str) -> Result<File, Report<Error>> {
    File::open(local)
        .await
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("opening local file {local:?}"))
}

/// Stream `length` bytes of `file` to `remote` behind a progress bar.
async fn send<T>(
    client: &mut Client<T, Connected>,
    file: &mut File,
    remote: &str,
    kind: FileUploadKind,
    length: u32,
    label: &str,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let upload = client.send_file(remote, kind).await?;
    let bar = ui.progress(u64::from(length), label);

    let mut tracked = ProgressRead::new(file.compat(), bar.clone());
    upload.copy_from(&mut tracked).await?;
    bar.finish_and_clear();

    Ok(())
}
