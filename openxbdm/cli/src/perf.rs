//! Performance counter subcommands.

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::PerfCounterList;
use openxbdm_client::commands::QueryPerfCounter;
use openxbdm_client::error::Error;
use rootcause::Report;
use tabled::Tabled;

use crate::ui::UiOptions;
use crate::ui::print_table;

pub async fn pc_list<T>(
    client: &mut Client<T, Connected>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let counters = client.run(PerfCounterList).await?;

    if !ui.is_pretty() {
        for counter in counters {
            println!("{:#010x}\t{}", counter.kind, counter.name);
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        #[tabled(rename = "type")]
        kind: String,
        name: String,
    }

    let rows: Vec<Row> = counters
        .iter()
        .map(|counter| Row {
            kind: format!("{:#010x}", counter.kind),
            name: counter.name.clone(),
        })
        .collect();
    print_table(&ui.heading("pclist"), rows);

    Ok(())
}

pub async fn query_pc<T>(
    client: &mut Client<T, Connected>,
    name: String,
    kind: u32,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let sample = client.run(QueryPerfCounter { name, kind }).await?;
    println!(
        "type={:#010x} value={} rate={}",
        sample.kind, sample.value, sample.rate
    );

    Ok(())
}
