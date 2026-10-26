//! Virtual memory subcommands.

use std::collections::HashSet;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::GetMem;
use openxbdm_client::commands::SetMem;
use openxbdm_client::commands::WalkMem;
use openxbdm_client::error::Error;
use rootcause::Report;
use rootcause::prelude::ResultExt;
use tabled::Tabled;

use crate::args::decode_hex;
use crate::args::parse_u32;
use crate::ui::UiOptions;
use crate::ui::print_table;

pub async fn walk_mem<T>(
    client: &mut Client<T, Connected>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let regions = client.run(WalkMem).await?;

    if !ui.is_pretty() {
        for region in regions {
            println!(
                "base={:#010x} size={:#010x} protect={:#010x}",
                region.base, region.size, region.protect
            );
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        base: String,
        size: String,
        protect: String,
    }

    let rows: Vec<Row> = regions
        .iter()
        .map(|region| Row {
            base: format!("{:#010x}", region.base),
            size: format!("{:#010x}", region.size),
            protect: format!("{:#010x}", region.protect),
        })
        .collect();
    print_table(&ui.heading("walkmem"), rows);

    Ok(())
}

pub async fn get_mem<T>(
    client: &mut Client<T, Connected>,
    address: &str,
    length: &str,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let address = parse_u32(address).map_err(|e| Report::new(e).attach("--address"))?;
    let length = parse_u32(length).map_err(|e| Report::new(e).attach("--length"))?;

    let snapshot = client.run(GetMem { address, length }).await?;
    print_hex_dump(snapshot.address, &snapshot.data, &snapshot.unmapped_offsets);

    Ok(())
}

pub async fn set_mem<T>(
    client: &mut Client<T, Connected>,
    address: &str,
    hex: &str,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let address = parse_u32(address).map_err(Report::new)?;
    let data = decode_hex(hex)
        .map_err(Report::new)
        .attach_with(|| format!("decoding --data {hex:?}"))?;

    let result = client.run(SetMem { address, data }).await?;
    println!("requested={} written={}", result.requested, result.written);

    Ok(())
}

/// Print 16 bytes per row with an ASCII column. Bytes at the offsets in
/// `unmapped` are shown as `??`.
fn print_hex_dump(base: u32, data: &[u8], unmapped: &[u32]) {
    let unmapped: HashSet<u32> = unmapped.iter().copied().collect();

    for (row_index, row) in data.chunks(16).enumerate() {
        let row_offset = row_index * 16;
        let address = base.wrapping_add(row_offset as u32);
        print!("{address:#010x}  ");

        for (column, byte) in row.iter().enumerate() {
            let offset = (row_offset + column) as u32;
            if unmapped.contains(&offset) {
                print!("?? ");
            } else {
                print!("{byte:02x} ");
            }
            if column == 7 {
                print!(" ");
            }
        }

        for _ in row.len()..16 {
            print!("   ");
        }

        print!(" |");
        for (column, byte) in row.iter().enumerate() {
            let offset = (row_offset + column) as u32;
            if unmapped.contains(&offset) || !(0x20..0x7f).contains(byte) {
                print!(".");
            } else {
                print!("{}", char::from(*byte));
            }
        }
        println!("|");
    }
}
