use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use openxbdm_client::commands::ControllerQueueLength;
use openxbdm_client::commands::Gamepad;
use openxbdm_client::commands::GamepadButtons;
use openxbdm_client::commands::GamepadDurationMillis;
use openxbdm_client::commands::TimedGamepad;
use serde::Deserialize;

use crate::error::ScriptError;

#[derive(Debug)]
pub struct ControllerScript {
    frames: Vec<TimedGamepad>,
    queue_length: ControllerQueueLength,
}

impl ControllerScript {
    pub fn load(path: &Path) -> Result<Self, ScriptError> {
        let file = File::open(path).map_err(|source| ScriptError::Open {
            path: path.to_owned(),
            source,
        })?;
        let reader = BufReader::new(file);
        let source: ScriptFile =
            serde_json::from_reader(reader).map_err(|source| ScriptError::Parse {
                path: path.to_owned(),
                source,
            })?;

        Self::from_file(source)
    }

    pub fn frames(&self) -> &[TimedGamepad] {
        &self.frames
    }

    pub fn frame_count(&self) -> u32 {
        self.queue_length.get()
    }

    pub fn queue_length(&self) -> ControllerQueueLength {
        self.queue_length
    }

    fn from_file(source: ScriptFile) -> Result<Self, ScriptError> {
        if source.frames.is_empty() {
            return Err(ScriptError::Empty);
        }
        let frame_count =
            u32::try_from(source.frames.len()).map_err(|_| ScriptError::TooManyFrames {
                count: source.frames.len(),
                maximum: ControllerQueueLength::MAX,
            })?;
        let queue_length =
            ControllerQueueLength::new(frame_count).map_err(|_| ScriptError::TooManyFrames {
                count: source.frames.len(),
                maximum: ControllerQueueLength::MAX,
            })?;

        let mut frames = Vec::with_capacity(source.frames.len());
        for (index, frame) in source.frames.into_iter().enumerate() {
            frames.push(frame.into_timed_gamepad(index)?);
        }

        Ok(Self {
            frames,
            queue_length,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptFile {
    frames: Vec<ScriptFrame>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptFrame {
    duration_ms: u32,
    #[serde(default)]
    buttons: Vec<ScriptButton>,
    #[serde(default)]
    left_trigger: f32,
    #[serde(default)]
    right_trigger: f32,
    #[serde(default)]
    left_stick: Stick,
    #[serde(default)]
    right_stick: Stick,
}

impl ScriptFrame {
    fn into_timed_gamepad(self, index: usize) -> Result<TimedGamepad, ScriptError> {
        let duration = GamepadDurationMillis::new(self.duration_ms).map_err(|_| {
            if self.duration_ms == 0 {
                ScriptError::ZeroDuration { index }
            } else {
                ScriptError::DurationOutOfRange {
                    index,
                    duration_ms: self.duration_ms,
                    maximum_ms: GamepadDurationMillis::MAX,
                }
            }
        })?;

        let mut buttons = GamepadButtons::default();
        for button in self.buttons {
            buttons |= button.mask();
        }

        Ok(TimedGamepad {
            packet: Gamepad {
                buttons,
                left_trigger: trigger(self.left_trigger, index, "left_trigger")?,
                right_trigger: trigger(self.right_trigger, index, "right_trigger")?,
                left_thumb_x: axis(self.left_stick.x, index, "left_stick.x")?,
                left_thumb_y: axis(self.left_stick.y, index, "left_stick.y")?,
                right_thumb_x: axis(self.right_stick.x, index, "right_stick.x")?,
                right_thumb_y: axis(self.right_stick.y, index, "right_stick.y")?,
            },
            duration,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stick {
    #[serde(default)]
    x: f32,
    #[serde(default)]
    y: f32,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScriptButton {
    DpadUp,
    DpadDown,
    DpadLeft,
    DpadRight,
    Start,
    Back,
    LeftThumb,
    RightThumb,
    LeftShoulder,
    RightShoulder,
    Guide,
    A,
    B,
    X,
    Y,
}

impl ScriptButton {
    const fn mask(self) -> GamepadButtons {
        match self {
            Self::DpadUp => GamepadButtons::DPAD_UP,
            Self::DpadDown => GamepadButtons::DPAD_DOWN,
            Self::DpadLeft => GamepadButtons::DPAD_LEFT,
            Self::DpadRight => GamepadButtons::DPAD_RIGHT,
            Self::Start => GamepadButtons::START,
            Self::Back => GamepadButtons::BACK,
            Self::LeftThumb => GamepadButtons::LEFT_THUMB,
            Self::RightThumb => GamepadButtons::RIGHT_THUMB,
            Self::LeftShoulder => GamepadButtons::LEFT_SHOULDER,
            Self::RightShoulder => GamepadButtons::RIGHT_SHOULDER,
            Self::Guide => GamepadButtons::GUIDE,
            Self::A => GamepadButtons::A,
            Self::B => GamepadButtons::B,
            Self::X => GamepadButtons::X,
            Self::Y => GamepadButtons::Y,
        }
    }
}

fn trigger(value: f32, index: usize, field: &'static str) -> Result<u8, ScriptError> {
    validate_range(value, index, field, 0.0, 1.0)?;

    Ok((value * f32::from(u8::MAX)).round() as u8)
}

fn axis(value: f32, index: usize, field: &'static str) -> Result<i16, ScriptError> {
    validate_range(value, index, field, -1.0, 1.0)?;

    let scaled = if value < 0.0 {
        value * 32768.0
    } else {
        value * 32767.0
    };

    Ok(scaled.round() as i16)
}

fn validate_range(
    value: f32,
    index: usize,
    field: &'static str,
    minimum: f32,
    maximum: f32,
) -> Result<(), ScriptError> {
    if value.is_finite() && value >= minimum && value <= maximum {
        return Ok(());
    }

    Err(ScriptError::ValueOutOfRange {
        index,
        field,
        value,
        minimum,
        maximum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> Result<ControllerScript, ScriptError> {
        let file: ScriptFile = serde_json::from_str(source).unwrap();

        ControllerScript::from_file(file)
    }

    #[test]
    fn parses_normalized_controller_frames() {
        let script = parse(
            r#"{
                "frames": [{
                    "duration_ms": 125,
                    "buttons": ["a", "dpad_up"],
                    "left_trigger": 0.5,
                    "left_stick": { "x": -1.0, "y": 1.0 }
                }]
            }"#,
        )
        .unwrap();

        assert_eq!(
            script.frames(),
            &[TimedGamepad {
                packet: Gamepad {
                    buttons: GamepadButtons::A | GamepadButtons::DPAD_UP,
                    left_trigger: 128,
                    left_thumb_x: i16::MIN,
                    left_thumb_y: i16::MAX,
                    ..Gamepad::default()
                },
                duration: GamepadDurationMillis::new(125).unwrap(),
            }]
        );
    }

    #[test]
    fn rejects_zero_duration() {
        let error = parse(r#"{ "frames": [{ "duration_ms": 0 }] }"#).unwrap_err();

        assert!(matches!(error, ScriptError::ZeroDuration { index: 0 }));
    }

    #[test]
    fn rejects_duration_outside_timer_range() {
        let error = parse(r#"{ "frames": [{ "duration_ms": 2147483648 }] }"#).unwrap_err();

        assert!(matches!(
            error,
            ScriptError::DurationOutOfRange {
                index: 0,
                duration_ms: 2_147_483_648,
                maximum_ms: 2_147_483_647,
            }
        ));
    }

    #[test]
    fn rejects_axes_outside_normalized_range() {
        let error = parse(
            r#"{
                "frames": [{
                    "duration_ms": 1,
                    "right_stick": { "x": 1.1, "y": 0.0 }
                }]
            }"#,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ScriptError::ValueOutOfRange {
                index: 0,
                field: "right_stick.x",
                ..
            }
        ));
    }
}
