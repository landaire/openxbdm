use core::fmt::Write as _;

use gilrs::Axis;
use gilrs::Button;
use gilrs::Gamepad as GilrsGamepad;
use gilrs::GamepadId;
use gilrs::Gilrs;
use openxbdm_client::commands::Gamepad;
use openxbdm_client::commands::GamepadButtons;

use crate::error::ControllerError;

/// Stable selector for one connected controller within a scan result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerIdentity {
    uuid: [u8; 16],
    occurrence: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareController {
    pub identity: ControllerIdentity,
    pub name: String,
}

impl HardwareController {
    pub fn identifier(&self) -> String {
        let mut identifier = String::with_capacity(36);
        for byte in self.identity.uuid {
            let _ = write!(identifier, "{byte:02x}");
        }
        let _ = write!(identifier, "-{}", self.identity.occurrence + 1);

        identifier
    }
}

pub fn scan_controllers() -> Result<Vec<HardwareController>, ControllerError> {
    let gilrs = Gilrs::new().map_err(ControllerError::Initialize)?;
    let mut controllers = Vec::new();
    let mut seen_uuids = Vec::<[u8; 16]>::new();

    for (_, gamepad) in gilrs
        .gamepads()
        .filter(|(_, gamepad)| gamepad.is_connected())
    {
        let uuid = gamepad.uuid();
        let occurrence = seen_uuids.iter().filter(|seen| **seen == uuid).count();
        seen_uuids.push(uuid);
        controllers.push(HardwareController {
            identity: ControllerIdentity { uuid, occurrence },
            name: gamepad.name().to_owned(),
        });
    }

    Ok(controllers)
}

pub struct OpenController {
    gilrs: Gilrs,
    id: GamepadId,
}

impl core::fmt::Debug for OpenController {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OpenController")
            .field("id", &self.id)
            .finish()
    }
}

impl OpenController {
    pub fn open(identity: ControllerIdentity) -> Result<Self, ControllerError> {
        let gilrs = Gilrs::new().map_err(ControllerError::Initialize)?;
        let mut occurrence = 0;
        let mut selected = None;

        for (id, gamepad) in gilrs
            .gamepads()
            .filter(|(_, gamepad)| gamepad.is_connected())
        {
            if gamepad.uuid() != identity.uuid {
                continue;
            }
            if occurrence == identity.occurrence {
                selected = Some(id);
                break;
            }

            occurrence += 1;
        }

        let Some(id) = selected else {
            return Err(ControllerError::NotConnected);
        };

        Ok(Self { gilrs, id })
    }

    pub fn update(&mut self) -> Result<Option<Gamepad>, ControllerError> {
        let mut changed = false;
        while let Some(event) = self.gilrs.next_event() {
            if event.id == self.id {
                changed = true;
            }
        }

        let Some(gamepad) = self.gilrs.connected_gamepad(self.id) else {
            return Err(ControllerError::NotConnected);
        };
        if !changed {
            return Ok(None);
        }

        Ok(Some(to_xinput(gamepad)))
    }

    pub fn state(&self) -> Result<Gamepad, ControllerError> {
        let Some(gamepad) = self.gilrs.connected_gamepad(self.id) else {
            return Err(ControllerError::NotConnected);
        };

        Ok(to_xinput(gamepad))
    }
}

fn to_xinput(gamepad: GilrsGamepad<'_>) -> Gamepad {
    let mut buttons = GamepadButtons::default();
    for (button, mask) in [
        (Button::DPadUp, GamepadButtons::DPAD_UP),
        (Button::DPadDown, GamepadButtons::DPAD_DOWN),
        (Button::DPadLeft, GamepadButtons::DPAD_LEFT),
        (Button::DPadRight, GamepadButtons::DPAD_RIGHT),
        (Button::Start, GamepadButtons::START),
        (Button::Select, GamepadButtons::BACK),
        (Button::LeftThumb, GamepadButtons::LEFT_THUMB),
        (Button::RightThumb, GamepadButtons::RIGHT_THUMB),
        (Button::LeftTrigger, GamepadButtons::LEFT_SHOULDER),
        (Button::RightTrigger, GamepadButtons::RIGHT_SHOULDER),
        (Button::Mode, GamepadButtons::GUIDE),
        (Button::South, GamepadButtons::A),
        (Button::East, GamepadButtons::B),
        (Button::West, GamepadButtons::X),
        (Button::North, GamepadButtons::Y),
    ] {
        if gamepad.is_pressed(button) {
            buttons |= mask;
        }
    }

    Gamepad {
        buttons,
        left_trigger: analog_button(gamepad, Button::LeftTrigger2),
        right_trigger: analog_button(gamepad, Button::RightTrigger2),
        left_thumb_x: axis(gamepad.value(Axis::LeftStickX)),
        left_thumb_y: axis(gamepad.value(Axis::LeftStickY)),
        right_thumb_x: axis(gamepad.value(Axis::RightStickX)),
        right_thumb_y: axis(gamepad.value(Axis::RightStickY)),
    }
}

fn analog_button(gamepad: GilrsGamepad<'_>, button: Button) -> u8 {
    let value = gamepad
        .button_data(button)
        .map(|data| data.value())
        .filter(|value| value.is_finite())
        .map(|value| value.clamp(0.0, 1.0));
    let Some(value) = value else {
        return 0;
    };

    (value * f32::from(u8::MAX)).round() as u8
}

fn axis(value: f32) -> i16 {
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
    fn axis_uses_full_signed_range() {
        assert_eq!(axis(-1.0), i16::MIN);
        assert_eq!(axis(0.0), 0);
        assert_eq!(axis(1.0), i16::MAX);
    }
}
