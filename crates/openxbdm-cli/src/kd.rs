//! Kernel debugger subcommands: `kd`, `kdlite`, `kdnet`.

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::Hresult;
use openxbdm_client::commands::Kd;
use openxbdm_client::commands::KdLite;
use openxbdm_client::commands::KdNetDisable;
use openxbdm_client::commands::KdNetEnable;
use openxbdm_client::commands::KdNetMac;
use openxbdm_client::commands::KdNetQuery;
use openxbdm_client::commands::KdNetSet;
use openxbdm_client::commands::KdNetShow;
use openxbdm_client::commands::KdNetUpdate;
use openxbdm_client::error::Error;
use rootcause::Report;

use crate::args::KdCommand;
use crate::args::KdLiteCommand;
use crate::args::KdNetCommand;
use crate::ui::ok_tag;

pub async fn kd<T>(
    client: &mut Client<T, Connected>,
    command: KdCommand,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let request = match command {
        KdCommand::Enable => Kd::Enable,
        KdCommand::Disable => Kd::Disable,
        KdCommand::Except => Kd::Except,
        KdCommand::Exceptif => Kd::ExceptIf,
    };

    client.run(request).await?;

    Ok(())
}

pub async fn kd_lite<T>(
    client: &mut Client<T, Connected>,
    command: KdLiteCommand,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let request = match command {
        KdLiteCommand::Enable => KdLite::Enable,
        KdLiteCommand::Disable => KdLite::Disable,
    };

    client.run(request).await?;

    Ok(())
}

pub async fn kd_net<T>(
    client: &mut Client<T, Connected>,
    command: KdNetCommand,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match command {
        KdNetCommand::Show => {
            let settings = match client.run(KdNetShow).await? {
                KdNetQuery::Settings(settings) => settings,
                KdNetQuery::LoadFailed(hresult) => {
                    return Err(console_failure("kdnet settings load", hresult));
                }
            };

            println!("enable     {}", settings.enable);
            println!("target ip  {}", settings.target_ip);
            println!("target mac {}", settings.target_mac);
            println!("host ip    {}", settings.host_ip);
            println!("host port  {}", settings.host_port);
            println!("encrypted  {}", settings.encrypted);
        }
        KdNetCommand::Enable => {
            let update = client.run(KdNetEnable).await?;
            check_kdnet_update("kdnet enable", update)?;
            eprintln!("{} kdnet enabled", ok_tag("saved"));
        }
        KdNetCommand::Disable => {
            let update = client.run(KdNetDisable).await?;
            check_kdnet_update("kdnet disable", update)?;
            eprintln!("{} kdnet disabled", ok_tag("saved"));
        }
        KdNetCommand::Set { ip, port, mac } => {
            client
                .run(KdNetSet {
                    host_ip: Some(ip),
                    host_port: Some(port),
                    target_mac: mac.map(KdNetMac::Address),
                })
                .await?;
            eprintln!("{} kdnet set", ok_tag("saved"));
        }
    }

    Ok(())
}

fn check_kdnet_update(operation: &'static str, update: KdNetUpdate) -> Result<(), Report<Error>> {
    match update {
        KdNetUpdate::Saved(hresult) if !hresult.is_failure() => Ok(()),
        KdNetUpdate::Saved(hresult) => Err(console_failure(operation, hresult)),
        KdNetUpdate::LoadFailed(hresult) => Err(console_failure("kdnet settings load", hresult)),
    }
}

fn console_failure(operation: &'static str, hresult: Hresult) -> Report<Error> {
    Report::new(Error::ConsoleOperationFailed { operation, hresult })
}
