//! Simulated XAM feature switch: XAM ordinal 515 (0x81748138 in the
//! console's xam.xex). It edits the feature mask in console configuration
//! category 11, setting 2, which XAM loads at the next cold boot.

use openxbdm_core::status::Hresult;
use openxbdm_core::status::KernelError;
use openxbdm_server::commands::console::ConfigSetting;

use super::XConfig;

/// Stored feature mask: word 0 holds mask bits 32..63, word 1 the cleared
/// bits among the console features (bits 0..6), and 8 bytes of zeros.
const MASK_SETTING: ConfigSetting = ConfigSetting::new(11, 2);
const MASK_SETTING_SIZE: usize = 16;
/// Mask of a console without a stored setting: every console feature.
const CONSOLE_FEATURES: u64 = 0x7f;
/// Image budget of the console features.
const CONSOLE_BUDGET: u32 = 0x51_8000;
/// Budget a 1 GB development kit adds for development kit features.
const LARGE_KIT_BUDGET: u32 = 0x380_0000;
/// `XboxHardwareInfo.BldrFlags` bit of a 1 GB development kit.
const LARGE_KIT_LOADER_FLAG: u16 = 0x80;
/// Separator line of the XAM feature texts.
const RULE: &str = "----------------------------------------------------------------------------------------------------------\n";

/// XAM state of the feature switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XamFeatures {
    /// Mask in effect since boot (0x81d3fee0); the list reports it.
    pub running: u64,
    /// `XboxHardwareInfo.BldrFlags`; bit 0x80 enlarges the development kit
    /// feature budget.
    pub loader_flags: u16,
}

impl Default for XamFeatures {
    fn default() -> Self {
        Self {
            running: CONSOLE_FEATURES,
            // Value on the reference development kit.
            loader_flags: 0x9e,
        }
    }
}

/// One entry of the XAM feature table (0x815f9490, 13 entries of 0x20
/// bytes).
struct Feature {
    id: u32,
    name: &'static str,
    devkit: bool,
    heap: u32,
    image: u32,
    pool: u32,
    stack: u32,
    total: u32,
}

impl Feature {
    const fn bit(&self) -> u64 {
        1 << (self.id - 1)
    }
}

const FEATURES: [Feature; 13] = [
    feature(1, "PRELOADED_HUD", false, [0, 0x6_0000, 0, 0, 0x6_0000]),
    feature(2, "MESSENGER", false, [0, 0, 0, 0, 0]),
    feature(3, "XMP", false, [0x20_0000, 0, 0, 0, 0x20_0000]),
    feature(4, "COMMUNITY", false, [0x4_0000, 0xc_0000, 0, 0, 0x10_0000]),
    feature(5, "XIME", false, [0, 0x4_0000, 0, 0, 0x4_0000]),
    feature(6, "XSTUDIO", false, [0, 0xa_0000, 0, 0x1_0000, 0xb_0000]),
    feature(
        7,
        "WIRELESS_WAVEA",
        false,
        [0, 0x8_0000, 0x4_0000, 0x8000, 0xc_8000],
    ),
    feature(0x21, "DEVKIT_HEAP", true, [0x6_0000, 0, 0, 0, 0x6_0000]),
    feature(
        0x22,
        "PIX_STREAM",
        true,
        [0x6_0000, 0, 0x1_3000, 0, 0x7_3000],
    ),
    feature(0x23, "ETX_BOOST", true, [0, 0, 0x1_0000, 0, 0x1_0000]),
    feature(0x24, "XS_LOGS", true, [0, 0, 0x1_4000, 0, 0x1_4000]),
    feature(0x26, "TESTXEX", true, [0, 0x2_0000, 0, 0, 0x2_0000]),
    feature(
        0x27,
        "XAMUIAUTOMATION",
        true,
        [0, 0x3_0000, 0, 0x8000, 0x3_8000],
    ),
];

const fn feature(id: u32, name: &'static str, devkit: bool, sizes: [u32; 5]) -> Feature {
    let [heap, image, pool, stack, total] = sizes;
    Feature {
        id,
        name,
        devkit,
        heap,
        image,
        pool,
        stack,
        total,
    }
}

/// Bits of the features in the table.
fn known_features() -> u64 {
    FEATURES
        .iter()
        .fold(0, |mask, feature| mask | feature.bit())
}

/// XAM ordinal 515 `(enable, feature)`: its result and the texts it prints.
pub(super) fn switch(
    features: &XamFeatures,
    xconfig: &mut XConfig,
    enable: u32,
    feature: u32,
    print: &mut dyn FnMut(String),
) -> Hresult {
    if feature == 0 {
        print_list(features, print);
        return Hresult::SUCCESS;
    }
    if feature > 64 {
        return Hresult::INVALID_ARGUMENT;
    }
    let Some(entry) = FEATURES.iter().find(|entry| entry.id == feature) else {
        print(format!("Unknown XAM feature {feature}\n"));
        return Hresult::FAIL;
    };

    let mut mask = match read_mask(xconfig) {
        Ok(mask) => mask,
        Err(error) => {
            print(format!(
                "Reading feature mask returned 0x{:08X}\n",
                error.status().0
            ));
            return Hresult::FAIL;
        }
    };
    exclude_unknown(&mut mask, print);

    print(RULE.to_owned());
    print("XAM FEATURE SELECTION\n".to_owned());
    print(RULE.to_owned());
    if enable != 0 {
        print(format!("Enabling {}\n", entry.name));
        mask |= entry.bit();
    } else {
        print(format!("Disabling {}\n", entry.name));
        mask &= !entry.bit();
    }

    exclude_unknown(&mut mask, print);
    let mut stored = [0u8; MASK_SETTING_SIZE];
    stored[..4].copy_from_slice(&((mask >> 32) as u32).to_be_bytes());
    stored[4..8].copy_from_slice(&((!mask & CONSOLE_FEATURES) as u32).to_be_bytes());
    if let Err(error) = xconfig.check(MASK_SETTING) {
        print(format!(
            "Failed to write feature mask to flash (err: 0x{:08X})\n",
            error.status().0
        ));
        return Hresult::FAIL;
    }
    xconfig.settings.insert(MASK_SETTING, stored.to_vec());

    print("Printing pending settings for next cold reboot...\n".to_owned());
    print_budget(features, mask, print);

    Hresult::SUCCESS
}

/// 0x81747e58: the stored mask, or every console feature without one.
fn read_mask(xconfig: &XConfig) -> Result<u64, KernelError> {
    xconfig.check(MASK_SETTING)?;

    let mut stored = [0u8; MASK_SETTING_SIZE];
    if let Some(value) = xconfig.settings.get(&MASK_SETTING) {
        let length = value.len().min(MASK_SETTING_SIZE);
        stored[..length].copy_from_slice(&value[..length]);
    }

    let word =
        |index: usize| u32::from_be_bytes(stored[index * 4..index * 4 + 4].try_into().unwrap());

    Ok((CONSOLE_FEATURES & !u64::from(word(1))) | (u64::from(word(0)) << 32))
}

/// 0x81747d00: clear bits outside the table.
fn exclude_unknown(mask: &mut u64, print: &mut dyn FnMut(String)) {
    let unknown = *mask & !known_features();
    if unknown == 0 {
        return;
    }

    // Without the `I64` prefix the kernel formatter reads the low word of
    // the argument slot (0x8014e594); `I64` after the conversion is text.
    print(format!(
        "Excluding unknown features in mask: 0x{:016X}I64\n",
        unknown as u32
    ));
    *mask &= !unknown;
}

/// 0x81747d80: the feature table with the running mask.
fn print_list(features: &XamFeatures, print: &mut dyn FnMut(String)) {
    let answer = |set: bool| if set { "Yes" } else { "No " };

    print(RULE.to_owned());
    print("XAM FEATURE LIST\n".to_owned());
    print(RULE.to_owned());
    print("Id             Name\tEnabled\tDevkit\tHeap Size\tImage Size\tPool Size\tStack Size\tTotal Size\n".to_owned());
    for entry in &FEATURES {
        print(format!(
            "{:2} {:>16}\t{}\t\t{}\t\t0x{:08X}\t0x{:08X}\t0x{:08X}\t0x{:08X}\t0x{:08X}\n",
            entry.id,
            entry.name,
            answer(features.running & entry.bit() != 0),
            answer(entry.devkit),
            entry.heap,
            entry.image,
            entry.pool,
            entry.stack,
            entry.total,
        ));
    }
    print(RULE.to_owned());
}

/// 0x81747818: the image budget of `mask`. Development kit features that
/// do not fit are reported and left out of the budget.
fn print_budget(features: &XamFeatures, mask: u64, print: &mut dyn FnMut(String)) {
    print(RULE.to_owned());
    print("XAM FEATURE BUDGET\n".to_owned());
    print(RULE.to_owned());

    let mut extra = 0u32;
    if features.loader_flags & LARGE_KIT_LOADER_FLAG != 0 {
        print(format!(
            "1GB devkit - budgeting additional 0{LARGE_KIT_BUDGET:08X} bytes\n"
        ));
        extra = LARGE_KIT_BUDGET;
    }

    let mut console_disabled = 0u32;
    for entry in FEATURES.iter().filter(|entry| !entry.devkit) {
        if mask & entry.bit() == 0 {
            print(format!(
                " - (Console){:>16}\t0x{:08X} bytes\n",
                entry.name, entry.total
            ));
            console_disabled += entry.total;
        }
    }

    let mut available = extra + console_disabled;
    let mut requested = 0u32;
    let mut enabled = 0u32;
    for entry in FEATURES.iter().filter(|entry| entry.devkit) {
        if mask & entry.bit() == 0 {
            continue;
        }

        requested += entry.total;
        if entry.total <= available {
            print(format!(
                " + (Devkit) {:>16}\t0x{:08X} bytes\n",
                entry.name, entry.total
            ));
            available -= entry.total;
            enabled += entry.total;
        } else {
            print(format!(
                " - (Devkit) {:>16}\t0x{:08X} bytes (only 0x{available:08X} available)\n",
                entry.name, entry.total
            ));
        }
    }

    print(RULE.to_owned());
    print(format!(
        "Console features enabled:\t0x{:08X} bytes\n",
        CONSOLE_BUDGET - console_disabled
    ));
    print(format!(
        "Console features disabled:\t0x{console_disabled:08X} bytes\n"
    ));
    print(format!(
        "Devkit features requested:\t0x{requested:08X} bytes\n"
    ));
    print(format!("Devkit features enabled:\t0x{enabled:08X} bytes\n"));
    print(RULE.to_owned());
}
