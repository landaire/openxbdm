//! Tokio-backed transport helpers.
//!
//! [`connect`] and [`connect_timeout`] accept anything `tokio::net` can
//! resolve (hostnames, IPv4/IPv6 literals, pre-parsed `SocketAddr`s) and
//! wrap the resulting [`tokio::net::TcpStream`] in
//! [`tokio_util::compat::Compat`] so it exposes the `futures_io` traits
//! the rest of the crate is written against.
//!
//! [`Target`] is a small enum for the common `(host, port)` / `host:port`
//! inputs a CLI or config file will parse.

use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use rootcause::Report;
use rootcause::prelude::ResultExt;
use tokio::net::TcpStream;
use tokio::net::ToSocketAddrs;
use tokio_util::compat::Compat;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::error::Error;
use crate::error::TransportError;

pub type TokioTransport = Compat<TcpStream>;

/// Parsed connection target. A [`Target::Addr`] skips DNS entirely; a
/// [`Target::HostPort`] triggers `tokio`'s built-in resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Numeric address with port; no name lookup.
    Addr(SocketAddr),
    /// Hostname or IPv4/IPv6 literal with separate port; resolved at
    /// connect time.
    HostPort { host: String, port: u16 },
}

impl Target {
    /// Build a target from a bare host (or IP literal) and a port.
    pub fn from_host_port(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        let Ok(ip) = IpAddr::from_str(&host) else {
            return Self::HostPort { host, port };
        };

        Self::Addr(SocketAddr::new(ip, port))
    }

    /// Build a target from a free-form `input` string, defaulting to
    /// `default_port` when the input has no explicit port.
    ///
    /// Accepted shapes:
    ///
    /// - bare IP: `192.168.1.26`, `fe80::1`
    /// - IP with port: `192.168.1.26:730`, `[fe80::1]:730`
    /// - hostname: `deanxbox`, `deanxbox.local`
    /// - hostname with port: `deanxbox:730`
    pub fn parse(input: &str, default_port: u16) -> Self {
        if let Ok(addr) = SocketAddr::from_str(input) {
            return Self::Addr(addr);
        }

        if let Ok(ip) = IpAddr::from_str(input) {
            return Self::Addr(SocketAddr::new(ip, default_port));
        }

        if let Some(rest) = input.strip_prefix('[')
            && let Some((ip_str, tail)) = rest.split_once(']')
            && let Ok(ip) = IpAddr::from_str(ip_str)
        {
            if let Some(port_str) = tail.strip_prefix(':')
                && let Ok(port) = port_str.parse::<u16>()
            {
                return Self::Addr(SocketAddr::new(ip, port));
            }
            return Self::Addr(SocketAddr::new(ip, default_port));
        }

        if let Some((host, port_str)) = input.rsplit_once(':')
            && !host.contains(':')
            && let Ok(port) = port_str.parse::<u16>()
        {
            return Self::from_host_port(host, port);
        }

        Self::from_host_port(input, default_port)
    }
}

impl core::fmt::Display for Target {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Addr(addr) => write!(f, "{addr}"),
            Self::HostPort { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Connect to an XBDM host. Accepts anything `tokio::net::ToSocketAddrs`
/// will resolve (string `"host:port"`, numeric `SocketAddr`, `(host, port)`
/// tuples, and more). Use [`Target`] for the most ergonomic path from CLI
/// input.
pub async fn connect<A>(addr: A) -> Result<TokioTransport, Report<Error>>
where
    A: ToSocketAddrs,
{
    let stream = TcpStream::connect(addr)
        .await
        .map_err(Error::from)
        .into_report()
        .attach("opening TCP connection to XBDM host")?;

    stream
        .set_nodelay(true)
        .map_err(Error::from)
        .into_report()
        .attach("configuring TCP_NODELAY on XBDM socket")?;

    Ok(stream.compat())
}

/// Connect to a [`Target`]. Prefers the pre-parsed numeric path when
/// available, otherwise delegates to DNS via tokio's resolver.
pub async fn connect_target(target: &Target) -> Result<TokioTransport, Report<Error>> {
    match target {
        Target::Addr(addr) => connect(*addr).await,
        Target::HostPort { host, port } => connect((host.as_str(), *port)).await,
    }
}

/// Connect with a hard timeout so hung consoles don't wedge the caller.
pub async fn connect_timeout<A>(addr: A, timeout: Duration) -> Result<TokioTransport, Report<Error>>
where
    A: ToSocketAddrs,
{
    match tokio::time::timeout(timeout, connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(Report::new(Error::from(TransportError::ConnectTimeout))),
    }
}

/// [`connect_target`] with a hard timeout.
pub async fn connect_target_timeout(
    target: &Target,
    timeout: Duration,
) -> Result<TokioTransport, Report<Error>> {
    match tokio::time::timeout(timeout, connect_target(target)).await {
        Ok(result) => result,
        Err(_) => Err(Report::new(Error::from(TransportError::ConnectTimeout))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_with_port() {
        let target = Target::parse("192.168.1.26:730", 9999);
        assert_eq!(target, Target::Addr("192.168.1.26:730".parse().unwrap()));
    }

    #[test]
    fn parses_bare_ipv4() {
        let target = Target::parse("192.168.1.26", 730);
        assert_eq!(target, Target::Addr("192.168.1.26:730".parse().unwrap()));
    }

    #[test]
    fn parses_bare_hostname() {
        let target = Target::parse("deanxbox", 730);
        assert_eq!(
            target,
            Target::HostPort {
                host: "deanxbox".to_owned(),
                port: 730
            }
        );
    }

    #[test]
    fn parses_hostname_with_port() {
        let target = Target::parse("deanxbox:42", 730);
        assert_eq!(
            target,
            Target::HostPort {
                host: "deanxbox".to_owned(),
                port: 42
            }
        );
    }

    #[test]
    fn parses_ipv6_bracketed() {
        let target = Target::parse("[::1]:730", 9999);
        assert_eq!(target, Target::Addr("[::1]:730".parse().unwrap()));
    }

    #[test]
    fn parses_bare_ipv6() {
        let target = Target::parse("::1", 730);
        assert_eq!(
            target,
            Target::Addr(SocketAddr::new("::1".parse().unwrap(), 730))
        );
    }

    #[test]
    fn from_host_port_detects_ip_literal() {
        let target = Target::from_host_port("192.168.1.26", 730);
        assert!(matches!(target, Target::Addr(_)));
        let target = Target::from_host_port("deanxbox", 730);
        assert!(matches!(target, Target::HostPort { .. }));
    }
}
