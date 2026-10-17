//! Network address and socket subcommands.

use std::fmt::Write as _;

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::AltAddr;
use openxbdm_client::commands::GetNetAddrs;
use openxbdm_client::commands::GetSocketInfo;
use openxbdm_client::error::Error;
use rootcause::Report;
use tabled::Tabled;

use crate::ui::UiOptions;
use crate::ui::print_table;

pub async fn alt_addr<T>(client: &mut Client<T, Connected>) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let address = client.run(AltAddr).await?;
    println!("{address}");

    Ok(())
}

pub async fn net_addrs<T>(client: &mut Client<T, Connected>) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let addresses = client.run(GetNetAddrs).await?;
    println!("name={}", addresses.name);
    println!("debug={}", hex_string(&addresses.debug));
    println!("title={}", hex_string(&addresses.title));

    Ok(())
}

pub async fn sockets<T>(
    client: &mut Client<T, Connected>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let sockets = client.run(GetSocketInfo).await?;

    if !ui.is_pretty() {
        for socket in sockets {
            println!(
                "handle={:#010x} af={} type={} proto={} local={:#010x}:{:#06x} remote={:#010x}:{:#06x} tcpstate={} flags={:#010x}",
                socket.handle,
                socket.addr_family,
                socket.socket_type,
                socket.protocol,
                socket.local_addr,
                socket.local_port,
                socket.remote_addr,
                socket.remote_port,
                socket.tcp_state,
                socket.flags
            );
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        handle: String,
        af: i32,
        #[tabled(rename = "type")]
        sock_type: i32,
        proto: i32,
        local: String,
        remote: String,
        tcpstate: u8,
        flags: String,
    }

    let rows: Vec<Row> = sockets
        .iter()
        .map(|socket| Row {
            handle: format!("{:#010x}", socket.handle),
            af: socket.addr_family,
            sock_type: socket.socket_type,
            proto: socket.protocol,
            local: format!("{:#010x}:{:#06x}", socket.local_addr, socket.local_port),
            remote: format!("{:#010x}:{:#06x}", socket.remote_addr, socket.remote_port),
            tcpstate: socket.tcp_state,
            flags: format!("{:#010x}", socket.flags),
        })
        .collect();
    print_table(&ui.heading("sockets"), rows);

    Ok(())
}

/// Lowercase hex digits of `bytes`, without separators.
fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }

    text
}
