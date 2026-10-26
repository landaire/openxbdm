//! Optical drive commands: `dvdeject` and `dvdperf`.

use core::fmt::Write as _;

use super::Continuation;
use super::DvdTrace;
use super::begin;
use super::optional_dword;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;

/// `dvdperf report`: one line per valid trace record.
#[derive(Debug)]
pub struct DvdReport {
    trace: DvdTrace,
    cursor: u32,
    base: u64,
}

impl DvdReport {
    pub(super) fn resume(&mut self, cx: &mut ContinuationContext<'_>) -> CommandResult {
        /// Bytes per trace record.
        const DVD_TRACE_RECORD: u32 = 16;

        while self.cursor + DVD_TRACE_RECORD <= self.trace.length {
            let start = self.cursor as usize;
            let mut record = [0u8; DVD_TRACE_RECORD as usize];
            record.copy_from_slice(
                &cx.backend.pool(self.trace.buffer)[start..start + DVD_TRACE_RECORD as usize],
            );
            self.cursor += DVD_TRACE_RECORD;

            let mut time = [0u8; 8];
            time.copy_from_slice(&record[..8]);
            let word = u32::from_be_bytes([record[8], record[9], record[10], record[11]]);
            let elapsed = u32::from_be_bytes([record[12], record[13], record[14], record[15]]);
            if word & 1 == 0 {
                continue;
            }

            let timestamp = u64::from_be_bytes(time).wrapping_sub(self.base) / 1000;
            let _ = write!(
                cx.line,
                "timestamp={} time={} lba={} cblk={}",
                timestamp as u32,
                elapsed as i32,
                (word >> 1) & 0xff_ffff,
                word >> 25,
            );

            return Ok(Reply::Ok);
        }

        // SAFETY: the transfer ends with this result, so the server drops the
        // continuation, the only other holder.
        unsafe { cx.backend.free_pool(self.trace.buffer) };

        Err(CommandError::EndOfData)
    }
}

/// `dvdeject [eject=<dword>]`.
pub(super) fn dvd_eject(invocation: &mut Invocation<'_>) -> CommandResult {
    let value = optional_dword(invocation, "eject", 1);
    invocation.backend.open_close_tray(value);

    Ok(Reply::Ok)
}

/// `dvdperf start` | `dvdperf stop [report]`.
pub(super) fn dvd_performance(invocation: &mut Invocation<'_>) -> CommandResult {
    if !invocation.line.has("stop") {
        if !invocation.line.has("start") {
            return Err(CommandError::Fail);
        }

        invocation.backend.start_dvd_trace();
        return Ok(Reply::Ok);
    }

    if invocation.session.is_none() {
        return Err(CommandError::Fail);
    }

    let trace = invocation.backend.stop_dvd_trace();
    if !invocation.line.has("report") {
        if let Some(trace) = trace {
            // SAFETY: the trace was taken from the backend here and is not
            // kept.
            unsafe { invocation.backend.free_pool(trace.buffer) };
        }

        return Ok(Reply::Ok);
    }

    let Some(trace) = trace else {
        invocation.set_text(format_args!("nothing to report"));
        return Err(CommandError::Fail);
    };

    let pool = invocation.backend.pool(trace.buffer);
    let mut base = [0u8; 8];
    base.copy_from_slice(&pool[..8]);
    let report = DvdReport {
        trace,
        cursor: 0,
        base: u64::from_be_bytes(base),
    };

    begin(invocation, Continuation::DvdReport(report), None);

    Ok(Reply::Multiline)
}

/// `dvdperf start` while a trace buffer is allocated, so tracing resumes
/// after a reboot.
pub(crate) fn dvdperf_settings_lines(
    _state: &ServerState,
    backend: &mut dyn crate::backend::Backend,
    file: crate::commands::system::SettingsFile,
) {
    if backend.dvd_trace_active() {
        crate::commands::system::write_line(backend, file, format_args!("dvdperf start"));
    }
}
