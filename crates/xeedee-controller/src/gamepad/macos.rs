#![allow(unsafe_code)]

use std::time::Duration;
use std::time::Instant;

use objc2::rc::Retained;
use objc2::rc::autoreleasepool;
use objc2_game_controller::GCController;
use objc2_game_controller::GCControllerAxisInput;
use objc2_game_controller::GCControllerButtonInput;
use objc2_game_controller::GCDevice as _;
use objc2_game_controller::GCExtendedGamepad;
use openxbdm_client::commands::Gamepad;
use openxbdm_client::commands::GamepadButtons;

use crate::error::ControllerError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerIdentity {
    address: usize,
}

#[derive(Debug, Clone)]
pub struct HardwareController {
    pub identity: ControllerIdentity,
    pub name: String,
    _controller: Retained<GCController>,
}

impl HardwareController {
    pub fn identifier(&self) -> String {
        format!("{:016x}", self.identity.address)
    }
}

pub fn initialize() {
    // SAFETY: This class property accepts any Boolean value and the application
    // invokes it while its macOS main run loop is active.
    unsafe {
        GCController::setShouldMonitorBackgroundEvents(true);
        _ = GCController::controllers();
    }
}

pub fn scan_controllers() -> Result<Vec<HardwareController>, ControllerError> {
    // SAFETY: The class method returns a retained snapshot of live controllers.
    let controllers = unsafe { GCController::controllers() };
    let mut result = Vec::with_capacity(controllers.len());

    for controller in controllers.iter() {
        // SAFETY: The retained controller remains live for this property read.
        if unsafe { controller.extendedGamepad() }.is_none() {
            continue;
        }

        result.push(HardwareController {
            identity: identity(&controller),
            name: controller_name(&controller),
            _controller: controller,
        });
    }

    Ok(result)
}

pub struct OpenController {
    controller: Retained<GCController>,
    last_state: Gamepad,
    last_connection_check: Instant,
}

impl core::fmt::Debug for OpenController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenController")
            .field("identity", &identity(&self.controller))
            .finish()
    }
}

impl OpenController {
    pub fn open(selector: ControllerIdentity) -> Result<Self, ControllerError> {
        // SAFETY: The class method returns a retained snapshot of live controllers.
        let controllers = unsafe { GCController::controllers() };
        let controller = controllers
            .iter()
            .find(|controller| identity(controller) == selector)
            .ok_or(ControllerError::NotConnected)?;
        let last_state = controller_state(&controller)?;

        Ok(Self {
            controller,
            last_state,
            last_connection_check: Instant::now(),
        })
    }

    pub fn update(&mut self) -> Result<Option<Gamepad>, ControllerError> {
        const CONNECTION_CHECK_INTERVAL: Duration = Duration::from_millis(100);

        let now = Instant::now();
        if now.duration_since(self.last_connection_check) >= CONNECTION_CHECK_INTERVAL {
            self.last_connection_check = now;
            if !is_connected(&self.controller) {
                return Err(ControllerError::NotConnected);
            }
        }

        let state = controller_state(&self.controller)?;
        if state == self.last_state {
            return Ok(None);
        }

        self.last_state = state;

        Ok(Some(state))
    }

    pub fn state(&self) -> Result<Gamepad, ControllerError> {
        controller_state(&self.controller)
    }
}

fn identity(controller: &Retained<GCController>) -> ControllerIdentity {
    ControllerIdentity {
        address: Retained::as_ptr(controller) as usize,
    }
}

fn is_connected(controller: &Retained<GCController>) -> bool {
    autoreleasepool(|_| {
        // SAFETY: The class method returns a retained snapshot of live controllers.
        let controllers = unsafe { GCController::controllers() };

        controllers
            .iter()
            .any(|candidate| identity(&candidate) == identity(controller))
    })
}

fn controller_name(controller: &GCController) -> String {
    // SAFETY: The retained controller remains live for this property read.
    unsafe { controller.vendorName() }
        .map(|name| name.to_string())
        .unwrap_or_else(|| "Game Controller".to_owned())
}

fn controller_state(controller: &GCController) -> Result<Gamepad, ControllerError> {
    autoreleasepool(|_| {
        // SAFETY: The retained controller remains live for this property read.
        let Some(gamepad) = (unsafe { controller.extendedGamepad() }) else {
            return Err(ControllerError::NotConnected);
        };

        Ok(to_xinput(&gamepad))
    })
}

fn to_xinput(gamepad: &GCExtendedGamepad) -> Gamepad {
    // SAFETY: Each accessor reads an element retained by the live input profile.
    unsafe {
        let dpad = gamepad.dpad();
        let mut buttons = GamepadButtons::default();
        for (pressed, mask) in [
            (dpad.up().isPressed(), GamepadButtons::DPAD_UP),
            (dpad.down().isPressed(), GamepadButtons::DPAD_DOWN),
            (dpad.left().isPressed(), GamepadButtons::DPAD_LEFT),
            (dpad.right().isPressed(), GamepadButtons::DPAD_RIGHT),
            (gamepad.buttonMenu().isPressed(), GamepadButtons::START),
            (
                gamepad
                    .buttonOptions()
                    .is_some_and(|button| button.isPressed()),
                GamepadButtons::BACK,
            ),
            (
                gamepad
                    .leftThumbstickButton()
                    .is_some_and(|button| button.isPressed()),
                GamepadButtons::LEFT_THUMB,
            ),
            (
                gamepad
                    .rightThumbstickButton()
                    .is_some_and(|button| button.isPressed()),
                GamepadButtons::RIGHT_THUMB,
            ),
            (
                gamepad.leftShoulder().isPressed(),
                GamepadButtons::LEFT_SHOULDER,
            ),
            (
                gamepad.rightShoulder().isPressed(),
                GamepadButtons::RIGHT_SHOULDER,
            ),
            (
                gamepad
                    .buttonHome()
                    .is_some_and(|button| button.isPressed()),
                GamepadButtons::GUIDE,
            ),
            (gamepad.buttonA().isPressed(), GamepadButtons::A),
            (gamepad.buttonB().isPressed(), GamepadButtons::B),
            (gamepad.buttonX().isPressed(), GamepadButtons::X),
            (gamepad.buttonY().isPressed(), GamepadButtons::Y),
        ] {
            if pressed {
                buttons |= mask;
            }
        }

        let left_thumbstick = gamepad.leftThumbstick();
        let right_thumbstick = gamepad.rightThumbstick();

        Gamepad {
            buttons,
            left_trigger: analog_button(&gamepad.leftTrigger()),
            right_trigger: analog_button(&gamepad.rightTrigger()),
            left_thumb_x: axis_value(&left_thumbstick.xAxis()),
            left_thumb_y: axis_value(&left_thumbstick.yAxis()),
            right_thumb_x: axis_value(&right_thumbstick.xAxis()),
            right_thumb_y: axis_value(&right_thumbstick.yAxis()),
        }
    }
}

fn analog_button(button: &GCControllerButtonInput) -> u8 {
    // SAFETY: The button belongs to a retained live input profile.
    let value = unsafe { button.value() };

    scale_trigger(value)
}

fn axis_value(axis: &GCControllerAxisInput) -> i16 {
    // SAFETY: The axis belongs to a retained live input profile.
    let value = unsafe { axis.value() };

    scale_axis(value)
}

fn scale_trigger(value: f32) -> u8 {
    if !value.is_finite() {
        return 0;
    }

    (value.clamp(0.0, 1.0) * f32::from(u8::MAX)).round() as u8
}

fn scale_axis(value: f32) -> i16 {
    if !value.is_finite() {
        return 0;
    }

    let value = value.clamp(-1.0, 1.0);
    let scaled = if value < 0.0 {
        value * 32768.0
    } else {
        value * 32767.0
    };

    scaled.round() as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_axis_uses_full_signed_range() {
        assert_eq!(scale_axis(-1.0), i16::MIN);
        assert_eq!(scale_axis(0.0), 0);
        assert_eq!(scale_axis(1.0), i16::MAX);
    }

    #[test]
    fn scale_trigger_uses_full_unsigned_range() {
        assert_eq!(scale_trigger(0.0), 0);
        assert_eq!(scale_trigger(1.0), u8::MAX);
    }
    #[test]
    fn extended_gamepad_maps_to_xinput() {
        // SAFETY: Snapshot controllers are writable test values owned by this scope.
        let controller = unsafe { GCController::controllerWithExtendedGamepad() };
        let gamepad =
            unsafe { controller.extendedGamepad() }.expect("snapshot has an extended profile");
        unsafe {
            gamepad.buttonA().setValue(1.0);
            gamepad.leftShoulder().setValue(1.0);
            gamepad.leftTrigger().setValue(0.5);
            gamepad.dpad().setValueForXAxis_yAxis(1.0, 0.0);
            gamepad.leftThumbstick().setValueForXAxis_yAxis(-0.5, 0.5);
        }

        let packet = to_xinput(&gamepad);

        assert_eq!(
            packet.buttons,
            GamepadButtons::A | GamepadButtons::LEFT_SHOULDER | GamepadButtons::DPAD_RIGHT
        );
        assert_eq!(packet.left_trigger, 128);
        assert_eq!(packet.right_trigger, 0);
        assert_eq!(packet.left_thumb_x, -16_384);
        assert_eq!(packet.left_thumb_y, 16_384);
        assert_eq!(packet.right_thumb_x, 0);
        assert_eq!(packet.right_thumb_y, 0);
    }
}
