use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::UdpSocket;
use std::process::ExitCode;
use std::thread;

use openxbdm_server_host::Host;
use openxbdm_server_host::SharedHost;

const DEFAULT_LISTEN: &str = "127.0.0.1:1730";
const USAGE: &str = "usage: openxbdm-server [--listen HOST:PORT]";

fn main() -> ExitCode {
    let mut listen = DEFAULT_LISTEN.to_owned();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--listen" => match arguments.next() {
                Some(value) => listen = value,
                None => return fail("--listen requires an address"),
            },
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            _ => return fail(&format!("invalid argument {argument:?}")),
        }
    }
    let address: SocketAddr = match listen.parse() {
        Ok(address) => address,
        Err(error) => return fail(&format!("invalid listen address {listen:?}: {error}")),
    };
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => return fail(&format!("cannot bind {address}: {error}")),
    };
    let local = match listener.local_addr() {
        Ok(local) => local,
        Err(error) => return fail(&format!("cannot read listen address: {error}")),
    };
    println!("listening on {local}");
    let host = SharedHost::new(Host::default());
    // Name discovery uses the UDP port with the listener's number.
    match UdpSocket::bind(local) {
        Ok(discovery) => {
            let responder = host.clone();
            thread::spawn(move || responder.serve_discovery(&discovery));
        }
        Err(error) => return fail(&format!("cannot bind discovery {local}: {error}")),
    }
    match host.serve(&listener) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(&format!("cannot accept connection: {error}")),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("openxbdm-server: {message}\n{USAGE}");
    ExitCode::FAILURE
}
