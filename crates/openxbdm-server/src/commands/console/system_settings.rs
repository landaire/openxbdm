//! Settings block of control codes 0x1e and 0x1f (`sysset`).

use crate::backend::Backend as AnyBackend;
use crate::commands::system::SettingsFile;
use crate::commands::system::end_line;
use crate::commands::system::write_text;
use crate::invocation::Invocation;
use crate::state::ServerState;

/// Bytes of the settings block of control codes 0x1e and 0x1f.
pub const SYSTEM_SETTINGS_SIZE: usize = 0xc;

/// [`SystemSettings`] flag: the video standard is set.
const SYSTEM_SETTINGS_VIDEO_STANDARD: u32 = 1;

/// Settings block of control codes 0x1e and 0x1f (stock 0x91fade20),
/// big-endian: +0 size given by the last writer, +4 flags, +8 video
/// standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SystemSettings(pub [u8; SYSTEM_SETTINGS_SIZE]);

impl SystemSettings {
    fn word(&self, offset: usize) -> u32 {
        let bytes = &self.0;

        u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    /// The video standard, when its flag is set.
    pub fn video_standard(&self) -> Option<u32> {
        (self.word(4) & SYSTEM_SETTINGS_VIDEO_STANDARD != 0).then(|| self.word(8))
    }

    /// Settings-file `sysset videostd=`; the other flags are kept.
    pub fn set_video_standard(&mut self, value: u32) {
        let flags = self.word(4) | SYSTEM_SETTINGS_VIDEO_STANDARD;
        self.0[4..8].copy_from_slice(&flags.to_be_bytes());
        self.0[8..12].copy_from_slice(&value.to_be_bytes());
    }

    /// Stock export 92 (code 0x1e): `block` is the caller's block cut to
    /// its size field and [`SYSTEM_SETTINGS_SIZE`]. Only the video standard
    /// flag is kept.
    pub fn store(&mut self, block: &[u8]) {
        let length = block.len().min(SYSTEM_SETTINGS_SIZE);
        self.0[..length].copy_from_slice(&block[..length]);
        let flags = self.word(4) & SYSTEM_SETTINGS_VIDEO_STANDARD;
        self.0[4..8].copy_from_slice(&flags.to_be_bytes());
    }
}

/// Settings-file `sysset videostd=<dword>` (stock DoIniLine 0x91f311b8).
pub(crate) fn ini_sysset(invocation: &mut Invocation<'_>) {
    if let Some(value) = invocation.line.dword("videostd") {
        let mut settings = invocation.backend.system_settings();
        settings.set_video_standard(value);
        invocation.backend.set_system_settings(settings);
    }
}

/// `sysset[ videostd=0x%08x]` of the alternate settings writer (stock
/// 0x91f31fb0).
pub(crate) fn sysset_settings_lines(
    _state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    write_text(backend, file, format_args!("sysset"));
    if let Some(standard) = backend.system_settings().video_standard() {
        write_text(backend, file, format_args!(" videostd=0x{standard:08x}"));
    }

    end_line(backend, file);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_settings_store_keeps_only_the_video_standard_flag() {
        let mut settings = SystemSettings::default();
        settings.store(&[0, 0, 0, 0x10, 0, 0, 0, 3, 0, 0, 0, 5, 0xee]);
        assert_eq!(settings.0, [0, 0, 0, 0x10, 0, 0, 0, 1, 0, 0, 0, 5]);
        assert_eq!(settings.video_standard(), Some(5));
        settings.store(&[0, 0, 0, 8, 0, 0, 0, 2]);
        assert_eq!(settings.video_standard(), None);
        assert_eq!(settings.0[8..], [0, 0, 0, 5]);
        settings.set_video_standard(7);
        assert_eq!(settings.video_standard(), Some(7));
    }
}
