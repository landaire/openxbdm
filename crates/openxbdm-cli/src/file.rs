//! File-system subcommands: `drivelist`, `df`, and `file`.

mod download;
mod tree;
mod upload;

use std::cmp::Ordering;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::Delete;
use openxbdm_client::commands::DirEntry;
use openxbdm_client::commands::DirList;
use openxbdm_client::commands::DriveFreeSpace;
use openxbdm_client::commands::DriveList;
use openxbdm_client::commands::EofDisposition;
use openxbdm_client::commands::FileEof;
use openxbdm_client::commands::GetFileAttributes;
use openxbdm_client::commands::MakeDirectory;
use openxbdm_client::commands::Rename;
use openxbdm_client::error::Error;
use rootcause::Report;
use tabled::Tabled;

use crate::args::FileCommand;
use crate::args::LsSortBy;
use crate::args::SortOrder;
use crate::ui::UiOptions;
use crate::ui::print_table;

pub use download::DownloadResult;
pub use download::download_file;

pub async fn drive_list<T>(
    client: &mut Client<T, Connected>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let drives = client.run(DriveList).await?;

    if !ui.is_pretty() {
        for drive in drives {
            println!("{drive}");
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row<'a> {
        #[tabled(rename = "drive")]
        name: &'a str,
    }

    let rows: Vec<Row<'_>> = drives.iter().map(|drive| Row { name: drive }).collect();
    print_table(&ui.heading("drives"), rows);

    Ok(())
}

pub async fn drive_free_space<T>(
    client: &mut Client<T, Connected>,
    drive: String,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let space = client
        .run(DriveFreeSpace {
            drive: drive.clone(),
        })
        .await?;

    if !ui.is_pretty() {
        println!(
            "free_to_caller={} total={} total_free={}",
            ui.format_bytes(space.free_to_caller_bytes),
            ui.format_bytes(space.total_bytes),
            ui.format_bytes(space.total_free_bytes)
        );
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        #[tabled(rename = "metric")]
        key: String,
        size: String,
    }

    let rows = vec![
        Row {
            key: "free_to_caller".into(),
            size: ui.format_bytes(space.free_to_caller_bytes),
        },
        Row {
            key: "total".into(),
            size: ui.format_bytes(space.total_bytes),
        },
        Row {
            key: "total_free".into(),
            size: ui.format_bytes(space.total_free_bytes),
        },
    ];
    print_table(&ui.heading(&format!("df {drive}")), rows);

    Ok(())
}

pub async fn run<T>(
    client: &mut Client<T, Connected>,
    command: FileCommand,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match command {
        FileCommand::Tree {
            path,
            max_depth,
            dirs_only,
        } => tree::tree(client, path, max_depth, !dirs_only, ui).await?,
        FileCommand::Ls {
            path,
            sort_by,
            sort_order,
        } => list(client, path, sort_by, sort_order, ui).await?,
        FileCommand::Stat { path } => stat(client, path, ui).await?,
        FileCommand::Mkdir { path } => {
            client.run(MakeDirectory { path }).await?;
        }
        FileCommand::Rm { path, dir } => {
            client
                .run(Delete {
                    path,
                    is_directory: dir,
                })
                .await?;
        }
        FileCommand::Mv { from, to } => {
            client.run(Rename { from, to }).await?;
        }
        FileCommand::Get {
            remote,
            output,
            recursive,
            offset,
            size,
        } => {
            download::get(
                client,
                &remote,
                output.as_deref(),
                recursive,
                offset,
                size,
                ui,
            )
            .await?
        }
        FileCommand::Put { local, remote } => upload::put(client, &local, &remote, ui).await?,
        FileCommand::Writeto {
            local,
            remote,
            offset,
            length,
        } => upload::write_to(client, &local, &remote, offset, length, ui).await?,
        FileCommand::Fileeof {
            path,
            size,
            mustcreate,
            cancreate,
        } => {
            let disposition = if mustcreate {
                EofDisposition::CreateNew
            } else if cancreate {
                EofDisposition::CreateOrTruncate
            } else {
                EofDisposition::OpenExisting
            };
            client
                .run(FileEof {
                    path,
                    size,
                    disposition,
                })
                .await?;
        }
    }

    Ok(())
}

async fn list<T>(
    client: &mut Client<T, Connected>,
    path: String,
    sort_by: LsSortBy,
    order: SortOrder,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut entries = client.run(DirList { path: path.clone() }).await?;
    sort_dir_entries(&mut entries, sort_by, order);

    if !ui.is_pretty() {
        for entry in entries {
            println!(
                "{}\t{}\t{}\t{}",
                entry.name,
                size_column(&entry, ui),
                if entry.is_directory { "DIR" } else { "FILE" },
                ui.format_time(entry.change_time),
            );
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        name: String,
        size: String,
        kind: String,
        #[tabled(rename = "changed")]
        changed: String,
    }

    let rows: Vec<Row> = entries
        .iter()
        .map(|entry| Row {
            name: entry.name.clone(),
            size: size_column(entry, ui),
            kind: if entry.is_directory {
                "DIR".into()
            } else {
                "FILE".into()
            },
            changed: ui.format_time(entry.change_time),
        })
        .collect();
    print_table(&ui.heading(&format!("ls {path}")), rows);

    Ok(())
}

async fn stat<T>(
    client: &mut Client<T, Connected>,
    path: String,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let attributes = client.run(GetFileAttributes { path }).await?;

    let size = if attributes.is_directory {
        "-".into()
    } else {
        ui.format_bytes(attributes.size)
    };
    println!(
        "size={size} created={} changed={} is_directory={}",
        ui.format_time(attributes.create_time),
        ui.format_time(attributes.change_time),
        attributes.is_directory,
    );

    Ok(())
}

/// Size of a file, or `-` for a directory.
fn size_column(entry: &DirEntry, ui: UiOptions) -> String {
    if entry.is_directory {
        return "-".into();
    }

    ui.format_bytes(entry.size)
}

fn sort_dir_entries(entries: &mut [DirEntry], sort_by: LsSortBy, order: SortOrder) {
    entries.sort_by(|a, b| {
        let primary = match sort_by {
            LsSortBy::Name => cmp_ignore_ascii_case(&a.name, &b.name),
            LsSortBy::Size => a.size.cmp(&b.size),
            LsSortBy::Kind => a.is_directory.cmp(&b.is_directory),
            LsSortBy::Modified => a.change_time.as_raw().cmp(&b.change_time.as_raw()),
            LsSortBy::Created => a.create_time.as_raw().cmp(&b.create_time.as_raw()),
        };
        let ordered = match order {
            SortOrder::Asc => primary,
            SortOrder::Desc => primary.reverse(),
        };

        // Ties fall back to name ascending so equal keys stay readable.
        ordered.then_with(|| cmp_ignore_ascii_case(&a.name, &b.name))
    });
}

fn cmp_ignore_ascii_case(a: &str, b: &str) -> Ordering {
    let a = a.bytes().map(|byte| byte.to_ascii_lowercase());
    let b = b.bytes().map(|byte| byte.to_ascii_lowercase());

    a.cmp(b)
}
