use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::UdpSocket;
use std::process::ExitCode;
use std::thread;

use openxbdm_server_host::Host;
use openxbdm_server_host::SharedHost;

#[cfg(feature = "smb")]
const USAGE: &str = "usage: openxbdm-server [--listen HOST:PORT] [--smb-listen HOST:PORT]";
#[cfg(not(feature = "smb"))]
const USAGE: &str = "usage: openxbdm-server [--listen HOST:PORT]";

/// A listener on `address` and its local address.
fn bind(address: &str) -> Result<(TcpListener, SocketAddr), String> {
    let parsed: SocketAddr = address
        .parse()
        .map_err(|error| format!("invalid listen address {address:?}: {error}"))?;

    let listener =
        TcpListener::bind(parsed).map_err(|error| format!("cannot bind {parsed}: {error}"))?;

    let local = listener
        .local_addr()
        .map_err(|error| format!("cannot read listen address: {error}"))?;

    Ok((listener, local))
}

fn fail(message: &str) -> ExitCode {
    eprintln!("openxbdm-server: {message}\n{USAGE}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    const DEFAULT_LISTEN: &str = "127.0.0.1:1730";
    /// Port 445 needs privileges on most hosts.
    #[cfg(feature = "smb")]
    const DEFAULT_SMB_LISTEN: &str = "127.0.0.1:1445";

    let mut listen = DEFAULT_LISTEN.to_owned();
    #[cfg(feature = "smb")]
    let mut smb_listen = DEFAULT_SMB_LISTEN.to_owned();
    let mut arguments = std::env::args().skip(1);

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => match arguments.next() {
                Some(value) => listen = value,
                None => return fail("--listen requires an address"),
            },
            #[cfg(feature = "smb")]
            "--smb-listen" => match arguments.next() {
                Some(value) => smb_listen = value,
                None => return fail("--smb-listen requires an address"),
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => return fail(&format!("invalid argument {argument:?}")),
        }
    }

    let (listener, local) = match bind(&listen) {
        Ok(bound) => bound,
        Err(message) => return fail(&message),
    };
    println!("listening on {local}");

    #[cfg(feature = "smb")]
    let (smb_listener, smb_local) = match bind(&smb_listen) {
        Ok(bound) => bound,
        Err(message) => return fail(&message),
    };
    #[cfg(feature = "smb")]
    println!("SMB listening on {smb_local}");

    let host = SharedHost::new(Host::default());

    // Name discovery uses the UDP port with the listener's number.
    match UdpSocket::bind(local) {
        Ok(discovery) => {
            let responder = host.clone();
            thread::spawn(move || responder.serve_discovery(&discovery));
        }
        Err(error) => return fail(&format!("cannot bind discovery {local}: {error}")),
    }

    #[cfg(feature = "smb")]
    {
        let smb = host.clone();
        thread::spawn(move || smb.serve_smb(&smb_listener));
    }

    match host.serve(&listener) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("cannot accept connection: {error}")),
    }
}
