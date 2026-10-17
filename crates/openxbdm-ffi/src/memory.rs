#[diplomat::bridge]
pub mod ffi {
    use openxbdm_client::commands::MemorySnapshot;
    use openxbdm_client::commands::VirtualRegion;

    use crate::error::ffi::OpenxbdmError;

    /// `getmem` reply: raw bytes plus the offsets the kernel flagged as
    /// unmapped (`??`).
    #[diplomat::opaque]
    pub struct OpenxbdmMemorySnapshot {
        address: u32,
        data: Vec<u8>,
        unmapped: Vec<u32>,
    }

    impl From<MemorySnapshot> for OpenxbdmMemorySnapshot {
        fn from(snapshot: MemorySnapshot) -> Self {
            Self {
                address: snapshot.address,
                data: snapshot.data,
                unmapped: snapshot.unmapped_offsets,
            }
        }
    }

    impl OpenxbdmMemorySnapshot {
        pub fn address(&self) -> u32 {
            self.address
        }

        pub fn data_len(&self) -> usize {
            self.data.len()
        }

        pub fn copy_data(&self, dst: &mut [u8]) -> usize {
            let len = self.data.len().min(dst.len());
            dst[..len].copy_from_slice(&self.data[..len]);

            len
        }

        pub fn unmapped_len(&self) -> usize {
            self.unmapped.len()
        }

        pub fn unmapped_at(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            self.unmapped
                .get(idx)
                .copied()
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }

    /// `walkmem` reply.
    #[diplomat::opaque]
    pub struct OpenxbdmVirtualRegions(pub(crate) Vec<VirtualRegion>);

    impl OpenxbdmVirtualRegions {
        pub fn len(&self) -> usize {
            self.0.len()
        }

        pub fn base(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.region(idx)?.base)
        }

        pub fn size(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.region(idx)?.size)
        }

        pub fn protect(&self, idx: usize) -> Result<u32, Box<OpenxbdmError>> {
            Ok(self.region(idx)?.protect)
        }
    }

    impl OpenxbdmVirtualRegions {
        fn region(&self, idx: usize) -> Result<&VirtualRegion, Box<OpenxbdmError>> {
            self.0
                .get(idx)
                .ok_or_else(|| OpenxbdmError::index_out_of_range(idx))
        }
    }
}
