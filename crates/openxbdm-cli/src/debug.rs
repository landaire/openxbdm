//! Thread and breakpoint subcommands.

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::Breakpoint;
use openxbdm_client::commands::DataBreakpoint;
use openxbdm_client::commands::IsStopped;
use openxbdm_client::commands::ThreadInfo;
use openxbdm_client::commands::Threads;
use openxbdm_client::error::Error;
use rootcause::Report;
use tabled::Tabled;

use crate::args::DataBreakKindArg;
use crate::args::parse_thread_id;
use crate::args::parse_u32;
use crate::ui::UiOptions;
use crate::ui::print_table;

pub async fn threads<T>(
    client: &mut Client<T, Connected>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let thread_ids = client.run(Threads).await?;

    if !ui.is_pretty() {
        for thread_id in thread_ids {
            println!("{thread_id}");
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        #[tabled(rename = "thread id")]
        id: String,
    }

    let rows: Vec<Row> = thread_ids
        .iter()
        .map(|thread_id| Row {
            id: format!("{thread_id}"),
        })
        .collect();
    print_table(&ui.heading("threads"), rows);

    Ok(())
}

pub async fn thread_info<T>(
    client: &mut Client<T, Connected>,
    thread: &str,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let thread = parse_thread_id(thread)?;

    let info = client.run(ThreadInfo { thread }).await?;
    println!("{info:#?}");

    Ok(())
}

pub async fn is_stopped<T>(
    client: &mut Client<T, Connected>,
    thread: &str,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let thread = parse_thread_id(thread)?;

    let state = client.run(IsStopped { thread }).await?;
    println!("{state:?}");

    Ok(())
}

pub async fn breakpoint<T>(
    client: &mut Client<T, Connected>,
    address: &str,
    clear: bool,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let address = parse_u32(address).map_err(Report::new)?;

    client.run(Breakpoint { address, clear }).await?;

    Ok(())
}

pub async fn data_breakpoint<T>(
    client: &mut Client<T, Connected>,
    address: &str,
    size: u32,
    kind: DataBreakKindArg,
    clear: bool,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let address = parse_u32(address).map_err(Report::new)?;

    client
        .run(DataBreakpoint {
            address,
            size,
            kind: kind.into(),
            clear,
        })
        .await?;

    Ok(())
}
