#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::commands::Notify;

    use crate::blocking::BlockingNotificationChannel;
    use crate::error::ffi::OpenxbdmError;

    /// A connection turned into a notification channel with `notify`.
    #[diplomat::opaque]
    pub struct OpenxbdmNotificationChannel(BlockingNotificationChannel);

    impl OpenxbdmNotificationChannel {
        /// Connect to `address` and send `notify`. With `has_reconnect_port`
        /// the console also records a target at this host and
        /// `reconnect_port`.
        #[diplomat::attr(auto, named_constructor = "open")]
        pub fn open(
            address: &str,
            timeout_secs: u32,
            has_reconnect_port: bool,
            reconnect_port: u16,
            debug: bool,
            reverse: bool,
        ) -> Result<Box<OpenxbdmNotificationChannel>, Box<OpenxbdmError>> {
            let request = Notify {
                reconnect_port: has_reconnect_port.then_some(reconnect_port),
                debug,
                reverse,
            };
            let channel = BlockingNotificationChannel::open(address, timeout_secs, request)?;

            Ok(Box::new(OpenxbdmNotificationChannel(channel)))
        }

        /// Execution state announced when the channel opened, as its
        /// notification name (`started`, `stopped`, ...).
        pub fn execution_state(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.0.execution_state());
        }

        /// Wait for the next notification line.
        pub fn next_line(&self, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let line = self.0.next_line()?;
            let _ = write!(out, "{line}");

            Ok(())
        }
    }
}
