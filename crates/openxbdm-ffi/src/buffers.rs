#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWrite;

    use crate::error::ffi::OpenxbdmError;

    /// Owned byte buffer. Size via `.len()` then `.copy_into(dst)`.
    #[diplomat::opaque]
    pub struct OpenxbdmBytes(pub(crate) Vec<u8>);

    impl OpenxbdmBytes {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn copy_into(&self, dst: &mut [u8]) -> usize {
            let len = self.0.len().min(dst.len());
            dst[..len].copy_from_slice(&self.0[..len]);

            len
        }
    }

    /// Owned list of strings. `get(idx, out)` writes one entry, errors on OOB.
    #[diplomat::opaque]
    pub struct OpenxbdmStringList(pub(crate) Vec<String>);

    impl OpenxbdmStringList {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn get(&self, idx: usize, out: &mut DiplomatWrite) -> Result<(), Box<OpenxbdmError>> {
            let entry = self
                .0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))?;
            let _ = write!(out, "{entry}");

            Ok(())
        }
    }
}
