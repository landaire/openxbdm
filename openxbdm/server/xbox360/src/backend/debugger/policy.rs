//! Direct dispatch policy published by the server thread.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::console::DumpMode;
use openxbdm_server::commands::console::EventDeferMask;
use openxbdm_server::commands::debugger::DataBreakpoint;
use openxbdm_server::commands::debugger::DataKind;
use openxbdm_server::commands::debugger::DirectPolicy;
use openxbdm_server::commands::debugger::StopOn;

/// Two copies of the published policy; `POLICY_SEQUENCE` selects the
/// current one. The server thread writes the other copy before switching,
/// so a reader at raised level never waits on the writer.
static POLICY: [[AtomicU32; policy_word::COUNT]; 2] =
    [const { [const { AtomicU32::new(0) }; policy_word::COUNT] }; 2];
static POLICY_SEQUENCE: AtomicU32 = AtomicU32::new(0);

xbox360_sys::flags! {
    /// Flags word of a published policy copy.
    pub struct PolicyFlags(u32) {
        KD_LITE = 0x1,
        KERNEL_DEBUGGER = 0x2,
        TRAP_PASSTHROUGH = 0x4,
        DUMP_IN_PROGRESS = 0x8,
        ATTACHED = 0x10,
        DATA_BREAKPOINT = 0x20,
        QUIET_STEP_TITLE = 0x40,
        QUIET_STEP_SYSTEM = 0x80,
    }
}

/// Words of a published policy copy.
mod policy_word {
    /// [`super::PolicyFlags`].
    pub(super) const FLAGS: usize = 0;
    pub(super) const DUMP_MODE: usize = 1;
    pub(super) const DEFER_MASK: usize = 2;
    pub(super) const STOP_ON: usize = 3;
    pub(super) const DATA_ADDRESS: usize = 4;
    pub(super) const DATA_SIZE: usize = 5;
    pub(super) const DATA_KIND: usize = 6;
    pub(super) const COUNT: usize = 7;
}

fn encode_policy(policy: &DirectPolicy) -> [u32; policy_word::COUNT] {
    let bit = |set: bool, bit: PolicyFlags| if set { bit } else { PolicyFlags::empty() };
    let flags = bit(policy.kd_lite, PolicyFlags::KD_LITE)
        | bit(policy.kernel_debugger, PolicyFlags::KERNEL_DEBUGGER)
        | bit(policy.trap_passthrough, PolicyFlags::TRAP_PASSTHROUGH)
        | bit(policy.dump_in_progress, PolicyFlags::DUMP_IN_PROGRESS)
        | bit(policy.attached, PolicyFlags::ATTACHED)
        | bit(
            policy.data_breakpoint.is_some(),
            PolicyFlags::DATA_BREAKPOINT,
        )
        | bit(policy.quiet_step[0], PolicyFlags::QUIET_STEP_TITLE)
        | bit(policy.quiet_step[1], PolicyFlags::QUIET_STEP_SYSTEM);
    let data = policy.data_breakpoint;
    let mut words = [0; policy_word::COUNT];
    words[policy_word::FLAGS] = flags.bits();
    words[policy_word::DUMP_MODE] = policy.dump_mode.raw();
    words[policy_word::DEFER_MASK] = policy.defer_mask.bits();
    words[policy_word::STOP_ON] = policy.stop_on.bits();
    words[policy_word::DATA_ADDRESS] = data.map_or(0, |data| data.address);
    words[policy_word::DATA_SIZE] = data.map_or(0, |data| data.size);
    words[policy_word::DATA_KIND] = data.map_or(0, |data| data.kind as u32);

    words
}

fn decode_policy(words: [u32; policy_word::COUNT]) -> DirectPolicy {
    let flags = PolicyFlags::from_bits_retain(words[policy_word::FLAGS]);
    const WRITE: u32 = DataKind::Write as u32;
    const READ_WRITE: u32 = DataKind::ReadWrite as u32;

    let kind = match words[policy_word::DATA_KIND] {
        WRITE => DataKind::Write,
        READ_WRITE => DataKind::ReadWrite,
        _ => DataKind::Read,
    };
    DirectPolicy {
        stop_on: StopOn::from_bits_retain(words[policy_word::STOP_ON]),
        kd_lite: flags.contains(PolicyFlags::KD_LITE),
        kernel_debugger: flags.contains(PolicyFlags::KERNEL_DEBUGGER),
        trap_passthrough: flags.contains(PolicyFlags::TRAP_PASSTHROUGH),
        dump_mode: DumpMode::from_raw(words[policy_word::DUMP_MODE]),
        dump_in_progress: flags.contains(PolicyFlags::DUMP_IN_PROGRESS),
        attached: flags.contains(PolicyFlags::ATTACHED),
        defer_mask: EventDeferMask::from_bits_retain(words[policy_word::DEFER_MASK]),
        data_breakpoint: flags
            .contains(PolicyFlags::DATA_BREAKPOINT)
            .then_some(DataBreakpoint {
                address: words[policy_word::DATA_ADDRESS],
                size: words[policy_word::DATA_SIZE],
                kind,
            }),
        quiet_step: [
            flags.contains(PolicyFlags::QUIET_STEP_TITLE),
            flags.contains(PolicyFlags::QUIET_STEP_SYSTEM),
        ],
    }
}

/// The policy the server last published.
pub(super) fn load_policy() -> DirectPolicy {
    loop {
        let sequence = POLICY_SEQUENCE.load(Ordering::Acquire);
        let copy = &POLICY[(sequence & 1) as usize];
        let words = core::array::from_fn(|index| copy[index].load(Ordering::Relaxed));
        if POLICY_SEQUENCE.load(Ordering::Acquire) == sequence {
            return decode_policy(words);
        }
    }
}

pub(super) fn store_policy(policy: &DirectPolicy) {
    let words = encode_policy(policy);
    let sequence = POLICY_SEQUENCE.load(Ordering::Relaxed);
    let current = &POLICY[(sequence & 1) as usize];
    if words
        .iter()
        .zip(current)
        .all(|(word, slot)| *word == slot.load(Ordering::Relaxed))
    {
        return;
    }

    for (slot, word) in POLICY[((sequence + 1) & 1) as usize].iter().zip(words) {
        slot.store(word, Ordering::Relaxed);
    }

    POLICY_SEQUENCE.store(sequence.wrapping_add(1), Ordering::Release);
}
