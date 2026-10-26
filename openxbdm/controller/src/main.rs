#![deny(unsafe_code)]

mod app;
mod error;
mod gamepad;
mod relay;
mod script;

fn main() {
    app::run();
}
