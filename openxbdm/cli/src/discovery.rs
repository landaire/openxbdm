//! `discover` and `resolve`: NAP console discovery.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Duration;

use openxbdm_client::discovery::DiscoveryConfig;
use openxbdm_client::discovery::NAP_PORT;
use openxbdm_client::discovery::discover_all;
use openxbdm_client::discovery::find_by_name;
use openxbdm_client::error::ArgumentError;
use openxbdm_client::error::Error;
use openxbdm_client::error::TransportError;
use openxbdm_client::transport::tokio::Target;
use rootcause::Report;
use tabled::Tabled;

use crate::ui::UiOptions;
use crate::ui::print_table;
use crate::ui::warn_tag;

pub async fn discover(
    listen_ms: u64,
    broadcast: Option<&str>,
    ui: UiOptions,
) -> Result<(), Report<Error>> {
    let mut config = DiscoveryConfig::broadcast();
    config.listen_for = Duration::from_millis(listen_ms);
    if let Some(raw) = broadcast {
        config.destination = raw
            .parse()
            .or_else(|_| format!("{raw}:{NAP_PORT}").parse::<SocketAddr>())
            .map_err(|_| {
                Report::new(Error::from(ArgumentError::QuotedContainsCrlf))
                    .attach(format!("invalid --broadcast value {raw:?}"))
            })?;
    }

    tracing::info!(destination = %config.destination, "broadcasting nap identify");
    let consoles = discover_all(config).await?;
    if consoles.is_empty() {
        eprintln!("{} no consoles responded", warn_tag("warning:"));
        return Ok(());
    }

    if !ui.is_pretty() {
        for console in consoles {
            println!("{}\t{}", console.name, console.addr);
        }
        return Ok(());
    }

    #[derive(Tabled)]
    struct Row {
        name: String,
        address: String,
    }

    let rows: Vec<Row> = consoles
        .iter()
        .map(|console| Row {
            name: console.name.clone(),
            address: console.addr.to_string(),
        })
        .collect();
    print_table(&ui.heading("discover"), rows);

    Ok(())
}

pub async fn resolve(name: &str, listen_ms: u64) -> Result<(), Report<Error>> {
    let mut config = DiscoveryConfig::broadcast();
    config.listen_for = Duration::from_millis(listen_ms);
    config.destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), NAP_PORT);

    let Some(console) = find_by_name(name, config).await? else {
        return Err(Report::new(Error::from(TransportError::ConnectTimeout))
            .attach(format!("no reply from console named {name:?}")));
    };

    println!("{}\t{}", console.name, console.addr);

    Ok(())
}

/// Resolves a host name that DNS does not know as a console name with the
/// name lookup protocol, which is how consoles are named on a network.
pub async fn resolve_target(target: Target) -> Result<Target, Report<Error>> {
    let Target::HostPort { host, port } = &target else {
        return Ok(target);
    };

    let known = tokio::net::lookup_host((host.as_str(), *port))
        .await
        .is_ok_and(|mut addresses| addresses.next().is_some());
    if known {
        return Ok(target);
    }

    let mut config = DiscoveryConfig::broadcast();
    config.destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), NAP_PORT);
    tracing::info!(name = %host, "DNS does not know the host; looking it up as a console name");

    match find_by_name(host, config).await? {
        Some(console) => Ok(Target::Addr(SocketAddr::new(console.addr.ip(), *port))),
        None => Err(Report::new(Error::from(TransportError::UnknownHost {
            name: host.clone(),
        }))),
    }
}
