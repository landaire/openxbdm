#![cfg_attr(target_arch = "powerpc", no_std)]
#![cfg_attr(target_arch = "powerpc", no_main)]

#[cfg(target_arch = "powerpc")]
mod backend;
#[cfg(target_arch = "powerpc")]
mod entry;
#[cfg(target_arch = "powerpc")]
mod exports;
#[cfg(target_arch = "powerpc")]
mod kernel;
#[cfg(target_arch = "powerpc")]
mod lockfree;
#[cfg(target_arch = "powerpc")]
mod net;
#[cfg(target_arch = "powerpc")]
mod override_module;
#[cfg(target_arch = "powerpc")]
mod panic;
#[cfg(target_arch = "powerpc")]
mod serve;
#[cfg(all(target_arch = "powerpc", feature = "smb"))]
mod smb;
#[cfg(target_arch = "powerpc")]
mod thread;

#[cfg(not(target_arch = "powerpc"))]
fn main() {
    println!("openxbdm-server-xbox360 must be built for powerpc-unknown-xbox360");
}
