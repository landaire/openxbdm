#[diplomat::bridge]
pub mod ffi {
    use std::time::UNIX_EPOCH;

    use openxbdm_client::FileTime;

    #[diplomat::opaque]
    pub struct OpenxbdmFileTime(pub(crate) FileTime);

    impl OpenxbdmFileTime {
        #[diplomat::attr(auto, named_constructor = "from_raw")]
        pub fn from_raw(ticks: u64) -> Box<OpenxbdmFileTime> {
            Box::new(OpenxbdmFileTime(FileTime::from_raw(ticks)))
        }

        #[diplomat::attr(auto, named_constructor = "from_halves")]
        pub fn from_halves(high: u32, low: u32) -> Box<OpenxbdmFileTime> {
            Box::new(OpenxbdmFileTime(FileTime::from_halves(high, low)))
        }

        pub fn as_raw(&self) -> u64 {
            self.0.as_raw()
        }

        pub fn high(&self) -> u32 {
            self.0.high()
        }

        pub fn low(&self) -> u32 {
            self.0.low()
        }

        pub fn unix_seconds(&self) -> u64 {
            self.0
                .into_system_time()
                .duration_since(UNIX_EPOCH)
                .map(|since_epoch| since_epoch.as_secs())
                .unwrap_or(0)
        }

        pub fn unix_nanos(&self) -> u32 {
            self.0
                .into_system_time()
                .duration_since(UNIX_EPOCH)
                .map(|since_epoch| since_epoch.subsec_nanos())
                .unwrap_or(0)
        }
    }
}
