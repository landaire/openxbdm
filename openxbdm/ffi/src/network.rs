#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::commands::NetAddrs;
    use openxbdm_client::commands::SocketEntry;

    use crate::error::ffi::OpenxbdmError;

    /// `getnetaddrs` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmNetAddrs {
        name: String,
        debug: Vec<u8>,
        title: Vec<u8>,
    }

    impl From<NetAddrs> for OpenxbdmNetAddrs {
        fn from(addrs: NetAddrs) -> Self {
            Self {
                name: addrs.name,
                debug: addrs.debug,
                title: addrs.title,
            }
        }
    }

    impl OpenxbdmNetAddrs {
        pub fn name(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.name);
        }

        pub fn debug_len(&self) -> usize {
            self.debug.len()
        }

        pub fn copy_debug(&self, dst: &mut [u8]) -> usize {
            let len = self.debug.len().min(dst.len());
            dst[..len].copy_from_slice(&self.debug[..len]);

            len
        }

        pub fn title_len(&self) -> usize {
            self.title.len()
        }

        pub fn copy_title(&self, dst: &mut [u8]) -> usize {
            let len = self.title.len().min(dst.len());
            dst[..len].copy_from_slice(&self.title[..len]);

            len
        }
    }

    /// `getsockinfo` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmSockets(pub(crate) Vec<SocketEntry>);

    impl OpenxbdmSockets {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn handle(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.handle)
        }

        pub fn owner_type(&self, idx: usize) -> Result<i32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.owner_type)
        }

        pub fn flags(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.flags)
        }

        pub fn addr_family(&self, idx: usize) -> Result<i32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.addr_family)
        }

        pub fn socket_type(&self, idx: usize) -> Result<i32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.socket_type)
        }

        pub fn protocol(&self, idx: usize) -> Result<i32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.protocol)
        }

        pub fn local_addr(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.local_addr)
        }

        pub fn remote_addr(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.remote_addr)
        }

        pub fn local_port(&self, idx: usize) -> Result<u16, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.local_port)
        }

        pub fn remote_port(&self, idx: usize) -> Result<u16, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.remote_port)
        }

        pub fn tcp_state(&self, idx: usize) -> Result<u8, Box<OpenxbdmError>> {
            Ok(self.socket(idx)?.tcp_state)
        }
    }

    impl OpenxbdmSockets {
        fn socket(&self, idx: usize) -> Result<&SocketEntry, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }
}
