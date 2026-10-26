//! `file get`: download a file or a directory tree.

use std::num::NonZeroU32;
use std::path::Path;
use std::path::PathBuf;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::DirEntry;
use openxbdm_client::commands::DirList;
use openxbdm_client::commands::GetFileAttributes;
use openxbdm_client::commands::GetFileRange;
use openxbdm_client::commands::remote_path;
use openxbdm_client::error::ArgumentError;
use openxbdm_client::error::Error;
use rootcause::Report;
use rootcause::prelude::ResultExt;
use tokio_util::compat::TokioAsyncWriteCompatExt;

use crate::progress::ProgressWrite;
use crate::ui::UiOptions;
use crate::ui::ok_tag;

pub struct DownloadResult {
    /// Bytes actually streamed onto disk.
    pub copied: u64,
    /// Total length declared by the remote in the `getfile` prefix header.
    pub total: u64,
}

#[derive(Default)]
struct TreeDownloadStats {
    files: u64,
    bytes: u64,
}

/// A directory of a tree download whose entries are being processed.
struct PendingDir {
    remote: String,
    local: PathBuf,
    entries: std::vec::IntoIter<DirEntry>,
}

pub async fn get<T>(
    client: &mut Client<T, Connected>,
    remote: &str,
    output: Option<&str>,
    recursive: bool,
    offset: Option<u32>,
    size: Option<NonZeroU32>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // A path that cannot be stat'd is downloaded as a file so that
    // `getfile` reports the error.
    let attributes = client
        .run(GetFileAttributes {
            path: remote.to_owned(),
        })
        .await;
    let is_directory = matches!(attributes, Ok(attributes) if attributes.is_directory);

    if !is_directory {
        let range = match offset {
            Some(offset) => GetFileRange::Range { offset, size },
            None => GetFileRange::WholeFile,
        };
        let Some(basename) = remote_path::basename(remote) else {
            return Err(Report::new(Error::from(ArgumentError::EmptyFilename))
                .attach(format!("cannot derive local filename from {remote:?}")));
        };
        let output_path = local_path(output, basename);

        let DownloadResult { copied, total } =
            download_file(client, remote, &output_path, range, ui).await?;
        eprintln!(
            "{} {copied} bytes ({total} declared) to {}",
            ok_tag("downloaded"),
            output_path.display()
        );

        return Ok(());
    }

    if !recursive {
        return Err(
            Report::new(Error::from(ArgumentError::EmptyFilename)).attach(format!(
                "{remote:?} is a directory; pass -r for recursive download"
            )),
        );
    }

    if offset.is_some() || size.is_some() {
        return Err(Report::new(Error::from(ArgumentError::EmptyFilename))
            .attach("--offset / --size are file-mode only, not valid with -r"));
    }

    // A drive root has no name of its own to mirror.
    let basename = remote_path::basename(remote).unwrap_or("download");
    let root = local_path(output, basename);
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating local directory {}", root.display()))?;

    let stats = download_tree(client, remote, &root, ui).await?;
    eprintln!(
        "{} {} file{} ({} total) under {}",
        ok_tag("downloaded"),
        stats.files,
        if stats.files == 1 { "" } else { "s" },
        ui.format_bytes(stats.bytes),
        root.display()
    );

    Ok(())
}

pub async fn download_file<T>(
    client: &mut Client<T, Connected>,
    remote: &str,
    output_path: &Path,
    range: GetFileRange,
    ui: UiOptions,
) -> Result<DownloadResult, Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let download = client.get_file(remote, range).await?;
    let total = download.total();
    let bar = ui.progress(total, "download");

    let file = tokio::fs::File::create(output_path)
        .await
        .map_err(Error::from)
        .into_report()
        .attach_with(|| format!("creating local file {}", output_path.display()))?;
    let mut tracked = ProgressWrite::new(file.compat_write(), bar.clone());
    let copied = download.copy_into(&mut tracked).await?;
    bar.finish_and_clear();

    Ok(DownloadResult { copied, total })
}

/// Mirror the tree under `remote_dir` into `local_root`, depth first in
/// listing order.
async fn download_tree<T>(
    client: &mut Client<T, Connected>,
    remote_dir: &str,
    local_root: &Path,
    ui: UiOptions,
) -> Result<TreeDownloadStats, Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut stats = TreeDownloadStats::default();

    let remote = remote_path::normalize_dir_path(remote_dir);
    let entries = client
        .run(DirList {
            path: remote.clone(),
        })
        .await?;
    let mut pending = vec![PendingDir {
        remote,
        local: local_root.to_owned(),
        entries: entries.into_iter(),
    }];

    while let Some(dir) = pending.last_mut() {
        let Some(entry) = dir.entries.next() else {
            pending.pop();
            continue;
        };

        let child_remote = remote_path::join_path(&dir.remote, &entry.name);
        let child_local = dir.local.join(&entry.name);

        if !entry.is_directory {
            let DownloadResult { copied, .. } = download_file(
                client,
                &child_remote,
                &child_local,
                GetFileRange::WholeFile,
                ui,
            )
            .await?;
            stats.files += 1;
            stats.bytes += copied;
            continue;
        }

        tokio::fs::create_dir_all(&child_local)
            .await
            .map_err(Error::from)
            .into_report()
            .attach_with(|| format!("creating local directory {}", child_local.display()))?;

        let remote = remote_path::normalize_dir_path(&child_remote);
        let entries = client
            .run(DirList {
                path: remote.clone(),
            })
            .await?;
        pending.push(PendingDir {
            remote,
            local: child_local,
            entries: entries.into_iter(),
        });
    }

    Ok(stats)
}

/// `output` as given, or `basename` inside it when it names an existing
/// directory. Without `output`, `basename` in the current directory.
fn local_path(output: Option<&str>, basename: &str) -> PathBuf {
    let Some(explicit) = output else {
        return PathBuf::from(basename);
    };

    let path = PathBuf::from(explicit);
    if path.is_dir() {
        return path.join(basename);
    }

    path
}
