//! Console identity, title, and power subcommands.

use futures_io::AsyncRead;
use futures_io::AsyncWrite;
use openxbdm_client::Client;
use openxbdm_client::Connected;
use openxbdm_client::commands::DbgName;
use openxbdm_client::commands::DmVersion;
use openxbdm_client::commands::GetConsoleFeatures;
use openxbdm_client::commands::GetConsoleMem;
use openxbdm_client::commands::GetConsoleType;
use openxbdm_client::commands::GetPid;
use openxbdm_client::commands::MagicBoot;
use openxbdm_client::commands::Reboot;
use openxbdm_client::commands::SysTime;
use openxbdm_client::commands::Title;
use openxbdm_client::commands::XbeInfo;
use openxbdm_client::error::Error;
use rootcause::Report;

use crate::ui::UiOptions;

pub async fn dbg_name<T>(
    client: &mut Client<T, Connected>,
    set: Option<String>,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let request = match set {
        Some(value) => DbgName::Set(value),
        None => DbgName::Get,
    };

    let name = client.run(request).await?;
    println!("{name}");

    Ok(())
}

pub async fn sys_time<T>(
    client: &mut Client<T, Connected>,
    ui: UiOptions,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let result = client.run(SysTime).await?;
    println!("{}", ui.format_time(result.file_time));

    Ok(())
}

pub async fn dm_version<T>(client: &mut Client<T, Connected>) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let version = client.run(DmVersion).await?;
    println!("{version}");

    Ok(())
}

pub async fn console_type<T>(client: &mut Client<T, Connected>) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let kind = client.run(GetConsoleType).await?;
    println!("{kind:?}");

    Ok(())
}

pub async fn console_features<T>(client: &mut Client<T, Connected>) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let features = client.run(GetConsoleFeatures).await?;
    for flag in features.flags {
        println!("{flag}");
    }

    Ok(())
}

pub async fn console_mem<T>(client: &mut Client<T, Connected>) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let memory = client.run(GetConsoleMem).await?;
    println!("{memory:?}");

    Ok(())
}

pub async fn get_pid<T>(client: &mut Client<T, Connected>) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let pid = client.run(GetPid).await?;
    println!("{pid:#010x}");

    Ok(())
}

pub async fn xbe_info<T>(
    client: &mut Client<T, Connected>,
    name: Option<String>,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let request = match name {
        Some(path) => XbeInfo::Named(path),
        None => XbeInfo::Running,
    };

    let info = client.run(request).await?;
    println!("name={}", info.name);
    println!("timestamp={:#010x}", info.timestamp);
    println!("checksum={:#010x}", info.checksum);

    Ok(())
}

pub async fn reboot<T>(
    client: &mut Client<T, Connected>,
    request: Reboot,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    client.run(request).await?;
    println!("reboot issued");

    Ok(())
}

pub async fn magic_boot<T>(
    client: &mut Client<T, Connected>,
    request: MagicBoot,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    client.run(request).await?;
    println!("launch issued");

    Ok(())
}

pub async fn set_title<T>(
    client: &mut Client<T, Connected>,
    nopersist: bool,
    name: Option<String>,
) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    // clap rejects a name together with `--nopersist`. With neither, the
    // command is sent with `name=""`.
    let request = if nopersist {
        Title::NoPersist
    } else {
        Title::Set {
            name: name.unwrap_or_default(),
        }
    };

    client.run(request).await?;

    Ok(())
}

pub async fn raw<T>(client: &mut Client<T, Connected>, line: &str) -> Result<(), Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let response = client.send_raw(line).await?;
    println!("{response:#?}");

    Ok(())
}
