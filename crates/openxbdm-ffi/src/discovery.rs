#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;
    use std::net::SocketAddr;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::discovery::DiscoveredConsole;

    use crate::blocking;
    use crate::error::ffi::OpenxbdmError;

    /// NAP-discovery helpers. These are free functions that open a fresh
    /// UDP socket per call; no persistent client is involved.
    #[diplomat::opaque]
    pub struct OpenxbdmDiscovery;

    impl OpenxbdmDiscovery {
        /// Broadcast a `whatisyourname` request and collect replies for
        /// up to `timeout_ms` milliseconds.
        pub fn discover_all(
            timeout_ms: u32,
        ) -> Result<Box<OpenxbdmDiscoveredConsoles>, Box<OpenxbdmError>> {
            let consoles = blocking::discover_all(timeout_ms)?;

            Ok(Box::new(OpenxbdmDiscoveredConsoles::from_vec(consoles)))
        }

        /// Broadcast a targeted `lookup name` request; returns the first
        /// matching reply or an error if none arrive within `timeout_ms`.
        pub fn find_by_name(
            name: &str,
            timeout_ms: u32,
        ) -> Result<Box<OpenxbdmDiscoveredConsole>, Box<OpenxbdmError>> {
            let Some(console) = blocking::find_by_name(name, timeout_ms)? else {
                return Err(OpenxbdmError::new(format!(
                    "no reply from {name:?} within {timeout_ms}ms"
                )));
            };

            Ok(Box::new(OpenxbdmDiscoveredConsole::from(console)))
        }
    }

    /// One console reply from NAP discovery.
    #[diplomat::opaque]
    pub struct OpenxbdmDiscoveredConsole {
        name: String,
        ip_octets: [u8; 16],
        is_ipv6: bool,
        port: u16,
    }

    impl From<DiscoveredConsole> for OpenxbdmDiscoveredConsole {
        fn from(console: DiscoveredConsole) -> Self {
            let mut ip_octets = [0u8; 16];
            let is_ipv6 = match console.addr {
                SocketAddr::V4(v4) => {
                    ip_octets[..4].copy_from_slice(&v4.ip().octets());
                    false
                }
                SocketAddr::V6(v6) => {
                    ip_octets.copy_from_slice(&v6.ip().octets());
                    true
                }
            };

            Self {
                name: console.name,
                ip_octets,
                is_ipv6,
                port: console.addr.port(),
            }
        }
    }

    impl OpenxbdmDiscoveredConsole {
        pub fn name(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.name);
        }

        pub fn is_ipv6(&self) -> bool {
            self.is_ipv6
        }

        pub fn port(&self) -> u16 {
            self.port
        }

        /// Copy the socket address octets: first 4 bytes are valid when
        /// `is_ipv6()` is false; all 16 are valid when it is true.
        /// Returns the number of meaningful bytes (4 or 16).
        pub fn copy_ip(&self, dst: &mut [u8]) -> usize {
            let len = self.ip_len().min(dst.len());
            dst[..len].copy_from_slice(&self.ip_octets[..len]);

            len
        }
    }

    impl OpenxbdmDiscoveredConsole {
        fn ip_len(&self) -> usize {
            if self.is_ipv6 { 16 } else { 4 }
        }
    }

    /// Collection of discovery replies.
    #[diplomat::opaque]
    pub struct OpenxbdmDiscoveredConsoles(Vec<OpenxbdmDiscoveredConsole>);

    impl OpenxbdmDiscoveredConsoles {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn name(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let console = self.console(idx)?;
            let _ = write!(out, "{}", console.name);

            Ok(())
        }

        pub fn port(&self, idx: usize) -> Result<u16, Box<OpenxbdmError>> {
            Ok(self.console(idx)?.port)
        }

        pub fn is_ipv6(&self, idx: usize) -> Result<bool, Box<OpenxbdmError>> {
            Ok(self.console(idx)?.is_ipv6)
        }

        pub fn copy_ip(&self, idx: usize, dst: &mut [u8]) -> Result<usize, Box<OpenxbdmError>> {
            Ok(self.console(idx)?.copy_ip(dst))
        }
    }

    impl OpenxbdmDiscoveredConsoles {
        fn from_vec(consoles: Vec<DiscoveredConsole>) -> Self {
            Self(
                consoles
                    .into_iter()
                    .map(OpenxbdmDiscoveredConsole::from)
                    .collect(),
            )
        }

        fn console(&self, idx: usize) -> Result<&OpenxbdmDiscoveredConsole, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }
}
