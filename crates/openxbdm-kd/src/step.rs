//! Successor addresses for software single-step.
//!
//! The kernel offers no trace mode: setting MSR[SE] in the context makes
//! the next trace interrupt bug check with code 0x2b (0x8009c7fc). A
//! single step is therefore a continue with breakpoints at every address
//! the instruction can transfer control to.

/// Effects of the instruction at the program counter.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StepPlan {
    /// Unconditional trap (`tw`/`twi` with TO = 31). Running it would only
    /// stop again; the step advances the program counter instead.
    SkipTrap { next: u32 },
    /// Run with breakpoints at these addresses (one or two distinct).
    Run { successors: [u32; 2], count: usize },
}

impl StepPlan {
    pub fn successors(&self) -> &[u32] {
        match self {
            Self::SkipTrap { .. } => &[],
            Self::Run { successors, count } => &successors[..*count],
        }
    }
}

/// True for a trap instruction that always traps.
pub fn is_unconditional_trap(instruction: u32) -> bool {
    const OPCODE_TWI: u32 = 3;
    const OPCODE_X: u32 = 31;
    const X_TW: u32 = 4;
    const TO_ALWAYS: u32 = 31;

    let opcode = instruction >> 26;
    let to = (instruction >> 21) & 0x1f;
    let extended = (instruction >> 1) & 0x3ff;

    to == TO_ALWAYS && (opcode == OPCODE_TWI || (opcode == OPCODE_X && extended == X_TW))
}

pub fn plan(pc: u32, instruction: u32, lr: u32, ctr: u32) -> StepPlan {
    const OPCODE_BC: u32 = 16;
    const OPCODE_B: u32 = 18;
    const OPCODE_XL: u32 = 19;
    const XL_BCLR: u32 = 16;
    const XL_BCCTR: u32 = 528;

    if is_unconditional_trap(instruction) {
        return StepPlan::SkipTrap {
            next: pc.wrapping_add(4),
        };
    }

    let fallthrough = pc.wrapping_add(4);
    let absolute = instruction & 2 != 0;
    let bo = (instruction >> 21) & 0x1f;

    let (target, conditional) = match instruction >> 26 {
        OPCODE_B => {
            let displacement = sign_extend(instruction & 0x03ff_fffc, 26);
            let target = if absolute {
                displacement
            } else {
                pc.wrapping_add(displacement)
            };
            (Some(target), false)
        }
        OPCODE_BC => {
            let displacement = sign_extend(instruction & 0xfffc, 16);
            let target = if absolute {
                displacement
            } else {
                pc.wrapping_add(displacement)
            };
            (Some(target), !branch_always(bo))
        }
        OPCODE_XL => match (instruction >> 1) & 0x3ff {
            XL_BCLR => (Some(lr & !3), !branch_always(bo)),
            XL_BCCTR => (Some(ctr & !3), !branch_always(bo)),
            _ => (None, false),
        },
        _ => (None, false),
    };

    match target {
        None => StepPlan::Run {
            successors: [fallthrough, 0],
            count: 1,
        },
        Some(target) if !conditional || target == fallthrough => StepPlan::Run {
            successors: [target, 0],
            count: 1,
        },
        Some(target) => StepPlan::Run {
            successors: [fallthrough, target],
            count: 2,
        },
    }
}

fn sign_extend(value: u32, bits: u32) -> u32 {
    let shift = 32 - bits;

    (((value << shift) as i32) >> shift) as u32
}

/// BO bits that make a conditional branch unconditional: the condition
/// is ignored (BO[0] in IBM numbering, value 0x10) and CTR is not
/// decremented (BO[2], value 0x04).
fn branch_always(bo: u32) -> bool {
    bo & 0x14 == 0x14
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_successors() {
        // b +0x10
        assert_eq!(
            plan(0x8000_0000, 0x4800_0010, 0, 0).successors(),
            &[0x8000_0010]
        );
        // bl -4
        assert_eq!(
            plan(0x8000_0010, 0x4bff_fffd, 0, 0).successors(),
            &[0x8000_000c]
        );
        // beq cr6, +8
        assert_eq!(
            plan(0x8000_0000, 0x419a_0008, 0, 0).successors(),
            &[0x8000_0004, 0x8000_0008]
        );
        // blr
        assert_eq!(
            plan(0x8000_0000, 0x4e80_0020, 0x8009_ce8c, 0).successors(),
            &[0x8009_ce8c]
        );
        // bctrl
        assert_eq!(
            plan(0x8000_0000, 0x4e80_0421, 0, 0x8001_0000).successors(),
            &[0x8001_0000]
        );
        // bnelr
        assert_eq!(
            plan(0x8000_0000, 0x4c82_0020, 0x8000_1000, 0).successors(),
            &[0x8000_0004, 0x8000_1000]
        );
        // mflr r12
        assert_eq!(
            plan(0x8000_0000, 0x7d88_02a6, 0, 0).successors(),
            &[0x8000_0004]
        );
        // twi 31, r0, 22
        assert_eq!(
            plan(0x800a_f588, 0x0fe0_0016, 0, 0),
            StepPlan::SkipTrap { next: 0x800a_f58c }
        );
    }
}
