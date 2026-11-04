#![cfg_attr(target_os = "xbox360", no_std)]
#![cfg_attr(target_os = "xbox360", no_main)]

#[cfg(all(feature = "boot-guard", feature = "retail-dashlaunch"))]
compile_error!("boot-guard and retail-dashlaunch cannot be enabled together");

#[cfg(target_os = "xbox360")]
mod backend;
#[cfg(all(target_os = "xbox360", feature = "retail-dashlaunch"))]
mod dashlaunch;
#[cfg(target_os = "xbox360")]
mod entry;
#[cfg(target_os = "xbox360")]
mod exports;
#[cfg(target_os = "xbox360")]
mod kernel;
#[cfg(target_os = "xbox360")]
mod lockfree;
#[cfg(target_os = "xbox360")]
mod net;
#[cfg(all(target_os = "xbox360", not(feature = "retail-dashlaunch")))]
mod override_module;
#[cfg(target_os = "xbox360")]
mod panic;
#[cfg(target_os = "xbox360")]
mod serve;
#[cfg(all(target_os = "xbox360", feature = "smb"))]
mod smb;
#[cfg(target_os = "xbox360")]
mod thread;

#[cfg(not(target_os = "xbox360"))]
fn main() {
    println!("openxbdm-server-xbox360 must be built for an Xbox 360 target");
}
