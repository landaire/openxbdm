#[diplomat::bridge]
pub mod ffi {
    use std::cell::RefCell;
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;
    use openxbdm_client::ArgBuilder;
    use openxbdm_client::Qword;
    use openxbdm_client::protocol::ResponseHead;
    use openxbdm_client::protocol::parse_response_head;

    use crate::buffers::ffi::OpenxbdmBytes;
    use crate::error::ffi::OpenxbdmError;

    /// Builder for an XBDM command line. Wraps [`openxbdm_client::ArgBuilder`].
    ///
    /// `ArgBuilder` consumes `self` on every append; we hold it in a
    /// `RefCell<Option<_>>` so diplomat's `&self` methods can take/replace.
    #[diplomat::opaque]
    pub struct OpenxbdmCommand(RefCell<Option<ArgBuilder>>);

    impl OpenxbdmCommand {
        #[diplomat::attr(auto, constructor)]
        pub fn new(mnemonic: &str) -> Box<OpenxbdmCommand> {
            Box::new(OpenxbdmCommand(RefCell::new(Some(ArgBuilder::new(
                mnemonic,
            )))))
        }

        pub fn flag(&self, token: &str) {
            self.mutate(|builder| builder.flag(token));
        }

        pub fn dec(&self, key: &str, value: u64) {
            self.mutate(|builder| builder.dec(key, value));
        }

        pub fn int(&self, key: &str, value: i64) {
            self.mutate(|builder| builder.int(key, value));
        }

        pub fn hex32(&self, key: &str, value: u32) {
            self.mutate(|builder| builder.hex32(key, value));
        }

        pub fn hex(&self, key: &str, value: u64) {
            self.mutate(|builder| builder.hex(key, value));
        }

        pub fn qword(&self, key: &str, value: u64) {
            self.mutate(|builder| builder.qword(key, Qword(value)));
        }

        pub fn quoted(&self, key: &str, value: &str) -> Result<(), Box<OpenxbdmError>> {
            let mut slot = self.0.borrow_mut();
            let builder = slot.take().ok_or_else(consumed)?;

            let next = builder
                .quoted(key, value)
                .map_err(|e| OpenxbdmError::new(e.to_string()))?;
            *slot = Some(next);

            Ok(())
        }

        pub fn finish(&self) -> Result<Box<OpenxbdmBytes>, Box<OpenxbdmError>> {
            let mut slot = self.0.borrow_mut();
            let builder = slot.take().ok_or_else(consumed)?;

            Ok(Box::new(OpenxbdmBytes(builder.finish().into_bytes())))
        }
    }

    impl OpenxbdmCommand {
        /// Appends are no-ops once `finish` or a failed `quoted` consumed the builder.
        fn mutate(&self, append: impl FnOnce(ArgBuilder) -> ArgBuilder) {
            let mut slot = self.0.borrow_mut();
            if let Some(builder) = slot.take() {
                *slot = Some(append(builder));
            }
        }
    }

    #[diplomat::opaque]
    pub struct OpenxbdmResponseHead(ResponseHead);

    impl OpenxbdmResponseHead {
        #[diplomat::attr(auto, named_constructor = "parse")]
        pub fn parse(line: &str) -> Result<Box<OpenxbdmResponseHead>, Box<OpenxbdmError>> {
            parse_response_head(line)
                .map(|head| Box::new(OpenxbdmResponseHead(head)))
                .map_err(|e| OpenxbdmError::new(e.to_string()))
        }

        pub fn status_code(&self) -> u16 {
            self.0.code.raw()
        }

        pub fn is_success(&self) -> bool {
            self.0.code.is_success()
        }

        pub fn is_error(&self) -> bool {
            self.0.code.is_error()
        }

        pub fn rest(&self, out: &mut DiplomatWrite) {
            let _ = write!(out, "{}", self.0.rest);
        }
    }

    fn consumed() -> Box<OpenxbdmError> {
        OpenxbdmError::new("command already consumed".into())
    }
}
