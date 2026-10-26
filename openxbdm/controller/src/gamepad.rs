#[cfg(not(target_os = "macos"))]
mod gilrs;
#[cfg(target_os = "macos")]
mod macos;

pub fn initialize() {
    #[cfg(target_os = "macos")]
    macos::initialize();
}

#[cfg(not(target_os = "macos"))]
pub use gilrs::ControllerIdentity;
#[cfg(not(target_os = "macos"))]
pub use gilrs::HardwareController;
#[cfg(not(target_os = "macos"))]
pub use gilrs::OpenController;
#[cfg(not(target_os = "macos"))]
pub use gilrs::scan_controllers;
#[cfg(target_os = "macos")]
pub use macos::ControllerIdentity;
#[cfg(target_os = "macos")]
pub use macos::HardwareController;
#[cfg(target_os = "macos")]
pub use macos::OpenController;
#[cfg(target_os = "macos")]
pub use macos::scan_controllers;
