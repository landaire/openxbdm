//! `function-trace`: record mapped function entries.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use openxbdm_kd_core::NtStatus;
use openxbdm_kd_core::manipulate::BreakpointHandle;
use openxbdm_kd_core::manipulate::ContinueDisposition;
use openxbdm_kd_core::manipulate::Processor;
use rootcause::Report;
use rootcause::prelude::ResultExt;

use crate::client::KdClient;
use crate::connection::stop_target;
use crate::error::CliError;
use crate::step;
use crate::transport::UdpTransport;

const TRACE_INSTRUCTION: [u8; 4] = 0x0fe0_0016_u32.to_be_bytes();

#[derive(Debug)]
struct TracePoint {
    address: u32,
    names: Vec<String>,
    original: [u8; 4],
    armed: bool,
}

#[derive(Debug)]
struct StepBreakpoint {
    address: u32,
    handle: Option<BreakpointHandle>,
}

#[derive(Debug)]
struct PendingRearm {
    point: usize,
    processor: Processor,
    successors: [u32; 2],
    successor_count: usize,
    uncertain_breakpoint: Option<u32>,
    breakpoints: Vec<StepBreakpoint>,
}

impl PendingRearm {
    fn successors(&self) -> &[u32] {
        &self.successors[..self.successor_count]
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TraceEnd {
    ImageLoaded,
    Interrupted,
}

struct TraceSettings<'a> {
    output_path: &'a Path,
    until_load: &'a str,
    interrupted: &'a AtomicBool,
    once: bool,
}

/// Records mapped function entries in execution order and restores every
/// trace point when `until_load` loads or Ctrl-C is received. With `once`,
/// each point is removed after its first execution.
pub fn function_trace(
    client: &mut KdClient<UdpTransport>,
    points_path: PathBuf,
    output_path: PathBuf,
    until_load: String,
    once: bool,
) -> Result<(), Report<CliError>> {
    let mut points = read_points(&points_path)?;
    let output = File::create(&output_path)
        .map_err(CliError::from)
        .attach(format!("creating trace output {}", output_path.display()))?;
    let mut output = BufWriter::new(output);
    writeln!(output, "sequence\taddress\tprocessor\tthread\tname")
        .and_then(|()| output.flush())
        .map_err(CliError::from)
        .attach(format!("writing trace output {}", output_path.display()))?;

    let interrupted = Arc::new(AtomicBool::new(false));
    let interrupt_flag = Arc::clone(&interrupted);
    ctrlc::set_handler(move || interrupt_flag.store(true, Ordering::Release))
        .map_err(CliError::from)?;

    client.set_hold_loads(vec![until_load.clone()]);
    stop_target(client)?;

    let mut pending = Vec::new();
    let settings = TraceSettings {
        output_path: &output_path,
        until_load: &until_load,
        interrupted: &interrupted,
        once,
    };
    let trace_result = run_trace(client, &mut points, &mut pending, &mut output, &settings);

    let stopped_for_cleanup = client.stop().is_none();
    if stopped_for_cleanup {
        stop_target(client).attach("stopping target for function trace cleanup")?;
        let pc = client.stop().map(|stop| stop.pc());
        note_reported_breakpoints(&mut pending, pc);
    }

    let pending_result = cleanup_pending_rearms(client, &mut pending).map_err(CliError::from);
    // Never resume a target that may still contain a trace instruction.
    let restore_result = restore_points(client, &mut points).map_err(CliError::from);
    let flush_result = output
        .flush()
        .map_err(CliError::from)
        .attach(format!("writing trace output {}", output_path.display()));

    if let Err(error) = pending_result {
        return Err(Report::new(error));
    }
    if let Err(error) = restore_result {
        return Err(Report::new(error));
    }
    flush_result?;
    client.continue_from_stop().map_err(CliError::from)?;

    let end = trace_result?;

    match end {
        TraceEnd::ImageLoaded => println!("trace complete at load of {until_load}"),
        TraceEnd::Interrupted => println!("trace interrupted"),
    }

    Ok(())
}

fn run_trace(
    client: &mut KdClient<UdpTransport>,
    points: &mut [TracePoint],
    pending: &mut Vec<PendingRearm>,
    output: &mut BufWriter<File>,
    settings: &TraceSettings<'_>,
) -> Result<TraceEnd, Report<CliError>> {
    arm_points(client, points, settings.interrupted)?;
    if settings.interrupted.load(Ordering::Acquire) {
        return Ok(TraceEnd::Interrupted);
    }

    println!(
        "armed {} function entries",
        points.iter().filter(|point| point.armed).count()
    );
    client.continue_from_stop().map_err(CliError::from)?;

    let mut sequence = 0_u64;
    loop {
        if settings.interrupted.load(Ordering::Acquire) {
            stop_target(client)?;
            let pc = client.stop().map(|stop| stop.pc());
            note_reported_breakpoints(pending, pc);
            cleanup_pending_rearms(client, pending).map_err(CliError::from)?;
            return Ok(TraceEnd::Interrupted);
        }

        if !client
            .wait_for_stop(Duration::from_secs(1))
            .map_err(CliError::from)?
        {
            continue;
        }

        let stop = client
            .stop()
            .cloned()
            .ok_or(CliError::TraceCleanupTargetRunning)?;
        let pc = stop.pc();
        note_reported_breakpoints(pending, Some(pc));
        if stop.image.as_ref().is_some_and(|image| {
            image
                .name
                .eq_ignore_ascii_case(settings.until_load.as_bytes())
        }) {
            return Ok(TraceEnd::ImageLoaded);
        }

        let status = stop.exception.map(|exception| exception.record.code);
        complete_pending_rearm(client, points, pending, stop.processor, pc, status)
            .map_err(CliError::from)?;
        reinstall_step_breakpoints(client, pending).map_err(CliError::from)?;
        let position = points
            .binary_search_by_key(&pc, |point| point.address)
            .ok()
            .filter(|position| points[*position].armed);

        if status == Some(NtStatus::BREAKPOINT)
            && let Some(position) = position
        {
            let point = &mut points[position];
            client
                .write_memory(u64::from(point.address), &point.original)
                .map_err(CliError::from)?;
            point.armed = false;
            sequence += 1;

            for name in &point.names {
                writeln!(
                    output,
                    "{sequence}\t{:#010x}\t{}\t{:#018x}\t{name}",
                    point.address, stop.processor.0, stop.thread
                )
                .and_then(|()| output.flush())
                .map_err(CliError::from)
                .attach(format!(
                    "writing trace output {}",
                    settings.output_path.display()
                ))?;
            }

            if settings.once {
                client
                    .resume(ContinueDisposition::Handled)
                    .map_err(CliError::from)?;
            } else {
                begin_rearm_step(client, points, position, stop.processor, pending)?;
            }
            continue;
        }

        match status {
            Some(NtStatus::BREAKPOINT) | Some(NtStatus::SINGLE_STEP) | None => {
                tracing::debug!(address = pc, ?status, "continuing non-trace stop");
                client.continue_from_stop().map_err(CliError::from)?;
            }
            Some(status) => {
                return Err(Report::new(CliError::TraceException {
                    address: pc,
                    status,
                }));
            }
        }
    }
}

fn begin_rearm_step(
    client: &mut KdClient<UdpTransport>,
    points: &[TracePoint],
    position: usize,
    processor: Processor,
    active: &mut Vec<PendingRearm>,
) -> Result<(), Report<CliError>> {
    let point = &points[position];
    let instruction = u32::from_be_bytes(point.original);
    let context = client.read_context(processor).map_err(CliError::from)?;
    let plan = step::plan(
        point.address,
        instruction,
        context.lr(),
        context.ctr() as u32,
    );
    let step::StepPlan::Run { .. } = plan else {
        return Err(Report::new(CliError::TraceOriginalTrap {
            address: point.address,
        }));
    };

    let mut successors = [0; 2];
    successors[..plan.successors().len()].copy_from_slice(plan.successors());
    let mut pending = PendingRearm {
        point: position,
        processor,
        successors,
        successor_count: plan.successors().len(),
        uncertain_breakpoint: None,
        breakpoints: Vec::with_capacity(plan.successors().len()),
    };
    for &address in plan.successors() {
        let traced = points
            .binary_search_by_key(&address, |point| point.address)
            .ok()
            .is_some_and(|position| points[position].armed);
        if traced {
            continue;
        }

        match client.add_breakpoint(u64::from(address)) {
            Ok(handle) => pending.breakpoints.push(StepBreakpoint {
                address,
                handle: Some(handle),
            }),
            Err(error) => {
                if breakpoint_request_may_have_applied(&error) {
                    pending.uncertain_breakpoint = Some(address);
                }
                active.push(pending);
                return Err(Report::new(CliError::from(error)));
            }
        }
    }

    active.push(pending);
    client
        .resume(ContinueDisposition::Handled)
        .map_err(CliError::from)?;

    Ok(())
}

fn note_reported_breakpoints(pending: &mut [PendingRearm], stopped_pc: Option<u32>) {
    let Some(stopped_pc) = stopped_pc else {
        return;
    };

    for rearm in pending {
        for breakpoint in &mut rearm.breakpoints {
            if breakpoint.address.wrapping_sub(stopped_pc) < 16 {
                breakpoint.handle = None;
            }
        }
    }
}

fn complete_pending_rearm(
    client: &mut KdClient<UdpTransport>,
    points: &mut [TracePoint],
    active: &mut Vec<PendingRearm>,
    processor: Processor,
    pc: u32,
    status: Option<NtStatus>,
) -> Result<(), crate::error::KdError> {
    if status != Some(NtStatus::BREAKPOINT) {
        return Ok(());
    }
    let Some(position) = active
        .iter()
        .position(|pending| pending.processor == processor && pending.successors().contains(&pc))
    else {
        return Ok(());
    };

    let mut pending = active.remove(position);
    if let Err(error) = remove_step_breakpoints(client, &mut pending.breakpoints) {
        active.insert(position, pending);
        return Err(error);
    }

    let point = &mut points[pending.point];
    point.armed = true;
    client.write_memory(u64::from(point.address), &TRACE_INSTRUCTION)
}

fn reinstall_step_breakpoints(
    client: &mut KdClient<UdpTransport>,
    pending: &mut [PendingRearm],
) -> Result<(), crate::error::KdError> {
    for rearm in pending {
        for breakpoint in &mut rearm.breakpoints {
            if breakpoint.handle.is_none() {
                match client.add_breakpoint(u64::from(breakpoint.address)) {
                    Ok(handle) => breakpoint.handle = Some(handle),
                    Err(error) => {
                        if breakpoint_request_may_have_applied(&error) {
                            rearm.uncertain_breakpoint = Some(breakpoint.address);
                        }
                        return Err(error);
                    }
                }
            }
        }
    }

    Ok(())
}

fn cleanup_pending_rearms(
    client: &mut KdClient<UdpTransport>,
    pending: &mut Vec<PendingRearm>,
) -> Result<(), crate::error::KdError> {
    let mut first_error = None;
    for rearm in pending.iter_mut() {
        if let Err(error) = remove_step_breakpoints(client, &mut rearm.breakpoints)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        if let Some(address) = rearm.uncertain_breakpoint
            && first_error.is_none()
        {
            first_error = Some(crate::error::KdError::UntrackedBreakpoint {
                address: u64::from(address),
            });
        }
    }
    pending.retain(|rearm| !rearm.breakpoints.is_empty() || rearm.uncertain_breakpoint.is_some());

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn breakpoint_request_may_have_applied(error: &crate::error::KdError) -> bool {
    !matches!(
        error,
        crate::error::KdError::Status { .. }
            | crate::error::KdError::UnalignedBreakpoint { .. }
            | crate::error::KdError::BreakpointRejected { .. }
    )
}

fn remove_step_breakpoints(
    client: &mut KdClient<UdpTransport>,
    breakpoints: &mut Vec<StepBreakpoint>,
) -> Result<(), crate::error::KdError> {
    let mut first_error = None;
    breakpoints.retain_mut(|breakpoint| {
        let Some(handle) = breakpoint.handle else {
            return false;
        };
        match client.remove_breakpoint(handle) {
            Ok(()) => false,
            Err(error) => {
                tracing::error!(
                    %error,
                    address = breakpoint.address,
                    "step breakpoint removal failed"
                );
                if first_error.is_none() {
                    first_error = Some(error);
                }
                true
            }
        }
    });

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn arm_points(
    client: &mut KdClient<UdpTransport>,
    points: &mut [TracePoint],
    interrupted: &AtomicBool,
) -> Result<(), Report<CliError>> {
    for point in points.iter_mut() {
        let read = client
            .read_memory(u64::from(point.address), &mut point.original)
            .map_err(CliError::from)?;
        if read != point.original.len() {
            return Err(Report::new(CliError::UnreadableTracePoint {
                address: point.address,
                actual: read,
            }));
        }
    }

    for point in points {
        if interrupted.load(Ordering::Acquire) {
            break;
        }
        if step::is_unconditional_trap(u32::from_be_bytes(point.original)) {
            tracing::warn!(address = point.address, names = ?point.names, "natural trap entry skipped");
            continue;
        }

        point.armed = true;
        client
            .write_memory(u64::from(point.address), &TRACE_INSTRUCTION)
            .map_err(CliError::from)?;
    }

    Ok(())
}

fn restore_points(
    client: &mut KdClient<UdpTransport>,
    points: &mut [TracePoint],
) -> Result<(), crate::error::KdError> {
    let mut first_error = None;
    for point in points.iter_mut().filter(|point| point.armed) {
        match client.write_memory(u64::from(point.address), &point.original) {
            Ok(()) => point.armed = false,
            Err(error) => {
                tracing::error!(%error, address = point.address, "trace point restoration failed");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn read_points(path: &Path) -> Result<Vec<TracePoint>, Report<CliError>> {
    let file = File::open(path)
        .map_err(CliError::from)
        .attach(format!("opening trace points {}", path.display()))?;
    parse_points(BufReader::new(file), path)
}

fn parse_points(input: impl BufRead, path: &Path) -> Result<Vec<TracePoint>, Report<CliError>> {
    let mut by_address: BTreeMap<u32, Vec<String>> = BTreeMap::new();

    for (index, line) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = line
            .map_err(CliError::from)
            .attach(format!("reading trace points {}", path.display()))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let split = line
            .find(char::is_whitespace)
            .ok_or_else(|| CliError::TracePointSyntax {
                path: path.to_owned(),
                line: line_number,
            })?;
        let (address, name) = line.split_at(split);
        let name = name.trim();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(Report::new(CliError::TracePointName {
                path: path.to_owned(),
                line: line_number,
            }));
        }

        let parsed = match address
            .strip_prefix("0x")
            .or_else(|| address.strip_prefix("0X"))
        {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => address.parse(),
        }
        .map_err(|error| CliError::TracePointAddress {
            path: path.to_owned(),
            line: line_number,
            text: address.to_owned(),
            error,
        })?;
        let address = u32::try_from(parsed).map_err(|_| CliError::TracePointRange {
            path: path.to_owned(),
            line: line_number,
            address: parsed,
        })?;
        if !address.is_multiple_of(4) {
            return Err(Report::new(CliError::TracePointUnaligned {
                path: path.to_owned(),
                line: line_number,
                address,
            }));
        }

        let names = by_address.entry(address).or_default();
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_owned());
        }
    }

    if by_address.is_empty() {
        return Err(Report::new(CliError::NoTracePoints {
            path: path.to_owned(),
        }));
    }

    Ok(by_address
        .into_iter()
        .map(|(address, names)| TracePoint {
            address,
            names,
            original: [0; 4],
            armed: false,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn parses_sorted_points_and_merges_aliases() {
        let points = parse_points(
            Cursor::new(b"# address name\n0x80001004 second\n2147487744 first\n0x80001000 alias\n"),
            Path::new("points.txt"),
        )
        .unwrap();

        assert_eq!(points.len(), 2);
        assert_eq!(points[0].address, 0x8000_1000);
        assert_eq!(points[0].names, ["first", "alias"]);
        assert_eq!(points[1].address, 0x8000_1004);
        assert_eq!(points[1].names, ["second"]);
    }

    #[test]
    fn rejects_unaligned_points() {
        let error =
            parse_points(Cursor::new(b"0x80001002 bad\n"), Path::new("points.txt")).unwrap_err();

        assert!(error.to_string().contains("is not 4-byte aligned"));
    }

    #[test]
    fn rejects_empty_point_files() {
        let error = parse_points(Cursor::new(b"# none\n\n"), Path::new("points.txt")).unwrap_err();

        assert!(error.to_string().contains("contains no trace points"));
    }
}
