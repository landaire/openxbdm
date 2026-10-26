//! Frame replay through the title's frame record routines.

use core::sync::atomic::Ordering::Relaxed;

use xbox360::time::TickCount;
use xbox360_sys::xam;

use super::super::super::session::EngineFlags;
use super::super::super::session::FrameRecordFlags;
use super::super::buffers;
use super::super::error::VideoError;
use super::super::gpu::fence_header;
use super::super::sign24;
use super::super::wrap;
use super::AUDIO_LEAD;
use super::ClientState;
use super::Operation;
use super::POSITION_LIMIT;
use super::ReadState;
use super::RequestKind;
use super::VideoContext;
use super::VideoContextFlags;
use super::VideoRequest;
use super::audio_record;
use super::frame_header;
use super::gpu_record;
use super::read::count;
use super::read::fill_requests;
use super::read::finish;
use super::read::next_audio;
use super::read::next_request;
use super::read::note_request;
use super::read::seek;
use super::read::wait_requests;
use crate::kernel;

/// Entries of a command list; stock overruns it for more than 0xc8
/// command buffers.
pub(super) const COMMAND_LIST_ENTRIES: usize = 0xca;
/// Words the title's submit routine may store.
const SUBMIT_EXTRA_WORDS: usize = 0x40;

type CommandList = [u32; COMMAND_LIST_ENTRIES];

/// Part of a command list a request uses: first entry, entries, and the
/// byte offset in the first.
pub(super) struct Commands {
    pub(super) start: usize,
    pub(super) count: usize,
    pub(super) offset: u32,
}

/// The title's check routine (stock 0x91f5a420); 0 lets it run once
/// more at the end.
fn check(operation: Operation<'_>) -> u32 {
    let routine = operation.session().frame_record.check_routine.load(Relaxed);
    // SAFETY: the title's frame record routine takes one argument.
    let result = unsafe { kernel::call_export(routine, operation.routine_argument(), 0, 0, 0) };
    if result == 0 {
        operation
            .video
            .set_flags(operation.video.flags() | VideoContextFlags::COMPLETION);
    }

    result
}

/// Buffers of GPU request `first` up to request `next` into `list` (part
/// of stock 0x91f5a4e0 and 0x91f5bc78). An offset at the end of the first
/// buffer starts at the next one.
pub(super) fn command_list(
    operation: Operation<'_>,
    first: &VideoRequest,
    next: &VideoRequest,
    list: &mut CommandList,
) -> Commands {
    const MAX_COMMAND_BUFFERS: u32 = 0xc8;

    let [offset, units] = first.command_halves();
    let buffer_count = u32::from(units.load(Relaxed)).min(MAX_COMMAND_BUFFERS);

    let mut index = first.unit() as u32;
    for slot in list.iter_mut().take(buffer_count as usize) {
        *slot = operation.buffer(index as usize);
        index = wrap(index + 1, operation.video.buffer_count.load(Relaxed));
    }

    list[buffer_count as usize] = operation.buffer(next.unit());

    let offset = u32::from(offset.load(Relaxed));
    if offset == buffers::BUFFER_BYTES {
        Commands {
            start: 1,
            count: buffer_count as usize,
            offset: 0,
        }
    } else {
        Commands {
            start: 0,
            count: buffer_count as usize + 1,
            offset,
        }
    }
}

/// Submit one captured frame to the title (stock 0x91f5a4e0).
fn replay_frame(
    operation: Operation<'_>,
    first: &VideoRequest,
    next: &VideoRequest,
    extra: &mut [u32; SUBMIT_EXTRA_WORDS],
) -> Result<(), VideoError> {
    /// Last argument of the title's submit routine.
    const SUBMIT_MODE: u32 = 0x618;

    let mut list = [0u32; COMMAND_LIST_ENTRIES];
    let commands = command_list(operation, first, next, &mut list);

    // SAFETY: the title's submit routine takes seven arguments `(argument,
    // 0, buffers, count, offset, extra, mode)`.
    let result = unsafe {
        kernel::call_console(
            operation
                .session()
                .frame_record
                .submit_routine
                .load(Relaxed),
            operation.routine_argument(),
            0,
            list[commands.start..].as_ptr() as usize as u32,
            commands.count as u32,
            commands.offset,
            extra.as_mut_ptr() as usize as u32,
            SUBMIT_MODE,
        )
    };
    if result != 0 {
        return Err(VideoError::Submit { result });
    }

    count(&operation.video.statistics.frames);

    Ok(())
}

/// Tell the title the replay ended (submit routine with 1).
fn end_submissions(operation: Operation<'_>) {
    // SAFETY: as in `replay_frame`.
    unsafe {
        kernel::call_console(
            operation
                .session()
                .frame_record
                .submit_routine
                .load(Relaxed),
            operation.routine_argument(),
            1,
            0,
            0,
            0,
            0,
            0,
        )
    };
}

/// Statistics debug print (stock 0x91f5a5d8).
fn report(operation: Operation<'_>, start: u32) {
    let video = operation.video;
    let statistics = &video.statistics;

    if video.flags().contains(VideoContextFlags::GPU) {
        let frames = statistics.frames.load(Relaxed);
        let elapsed = TickCount::now()
            .milliseconds()
            .wrapping_sub(start)
            .wrapping_add(1);
        let range = (video.report_end.load(Relaxed) >> 8)
            .wrapping_sub(video.report_start.load(Relaxed) >> 8);
        // Stock traps on an empty range.
        let percent = (frames.wrapping_mul(100)).checked_div(range).unwrap_or(0);
        let rate = (frames as f32 * 1000.0) / elapsed as f32;

        let values = [
            u64::from(frames),
            u64::from(percent),
            f64::from(rate).to_bits(),
            u64::from(statistics.dropped.load(Relaxed)),
            u64::from(statistics.restarts.load(Relaxed)),
            u64::from(statistics.misses.load(Relaxed)),
            u64::from(statistics.overruns.load(Relaxed)),
        ];
        // SAFETY: the format consumes the seven arguments.
        unsafe {
            super::super::super::super::pmc::debug_print(
                c"Video: %i (%i%%) frames, %.2f fps, %i record-time drops, %i restarts, %i misses, %i index overruns\n".as_ptr().cast(),
                &values,
            )
        };
    }

    if video.flags().contains(VideoContextFlags::AUDIO) {
        let values = [
            u64::from(statistics.audio_frames.load(Relaxed)),
            u64::from(statistics.audio_dropped.load(Relaxed)),
            u64::from(statistics.audio_restarts.load(Relaxed)),
            u64::from(statistics.audio_misses.load(Relaxed)),
            u64::from(statistics.overruns.load(Relaxed)),
            0,
            0,
        ];
        // SAFETY: the format consumes five arguments.
        unsafe {
            super::super::super::super::pmc::debug_print(
                c"Audio: %i frames, %i record-time drops, %i restarts, %i misses, %i index overruns\n".as_ptr().cast(),
                &values,
            )
        };
    }

    kernel::debug_print(c"\n");
}

/// Wait until the title's vertical position routine reaches `target`
/// (stock 0x91f5a6e0).
fn wait_position(operation: Operation<'_>, target: u32) {
    let routine = operation
        .session()
        .frame_record
        .position_routine
        .load(Relaxed);
    // SAFETY: the title's routine takes one argument and returns a signed
    // position.
    let position = |argument| unsafe { kernel::call_export(routine, argument, 0, 0, 0) } as i32;

    let target = target as i32;
    let mut previous = position(operation.routine_argument());
    let passed = i32::from(target < previous);
    let mut wraps = 0;
    let mut current = position(operation.routine_argument());

    while current <= POSITION_LIMIT {
        if wraps == passed && current >= target {
            break;
        }
        if wraps > passed {
            break;
        }

        if current < previous {
            wraps += 1;
        }
        previous = current;
        current = position(operation.routine_argument());
    }
}

/// Elapsed replay time against a record time (stock 0x91f5b018): true
/// when the frame is due; a frame far behind is recorded as a miss.
fn frame_due(operation: Operation<'_>, request: &VideoRequest) -> bool {
    let video = operation.video;
    if operation
        .session()
        .engine_flags()
        .contains(EngineFlags::PAUSED)
    {
        return true;
    }

    let target = request
        .record_word(gpu_record::TIME)
        .wrapping_sub(video.clock_record.load(Relaxed)) as i32;
    let elapsed =
        (performance_counter() as i32).wrapping_sub(video.clock_start.load(Relaxed) as i32);

    if !video.flags().contains(VideoContextFlags::AUDIO)
        && target > elapsed.wrapping_add(POSITION_LIMIT)
    {
        video.restart.store(
            fence_header::frame(request.record_word(gpu_record::HEADER)),
            Relaxed,
        );
        count(&video.statistics.restarts);
    }

    target < elapsed
}

/// Audio counterpart of [`frame_due`] (stock 0x91f5b0c0).
pub(super) fn audio_due(operation: Operation<'_>, request: &VideoRequest) -> bool {
    let video = operation.video;
    let target = request
        .record_word(audio_record::TIME)
        .wrapping_sub(video.clock_record.load(Relaxed)) as i32;
    let mut elapsed =
        (performance_counter() as i32).wrapping_sub(video.clock_start.load(Relaxed) as i32);
    if video.flags().contains(VideoContextFlags::GPU) {
        elapsed = elapsed.wrapping_add(AUDIO_LEAD);
    }

    target < elapsed
}

pub(super) fn performance_counter() -> u32 {
    let mut counter = 0u64;
    // SAFETY: `counter` is a live local.
    unsafe { xam::QueryPerformanceCounter(&mut counter) };

    (counter as i64 >> 10) as u32
}

/// Start an operation at the context's frame (stock 0x91f5b420): reset
/// the queues, find the frame record, and decide the parts.
pub(super) fn begin(operation: Operation<'_>, audio: bool, no_gpu: bool) -> Result<(), VideoError> {
    let video = operation.video;
    let session = operation.session();

    video.read_slot.store(0, Relaxed);
    video.fill_slot.store(0, Relaxed);
    video.buffer_position.store(0, Relaxed);
    video.gpu_buffer.store(0, Relaxed);
    video.audio_buffer.store(0, Relaxed);
    video.ring_tail.store(0, Relaxed);
    video.audio_index.store(0, Relaxed);
    video.gpu_index.store(0, Relaxed);
    video.pending_units.store(0, Relaxed);
    video.pending_position.store(0, Relaxed);
    video.pending_spare.store(0, Relaxed);
    video.read_state.store(0, Relaxed);
    video.record_cursor.store(0, Relaxed);
    video.record_end.store(0, Relaxed);
    video
        .read_state
        .store(video.flags().bits() << 7 & ReadState::FRAME_MASK, Relaxed);

    let record = seek(operation, video.flags().frame()).ok_or(VideoError::NothingToReplay)?;
    video.restart.store(VideoContext::NO_RESTART, Relaxed);

    let word = record[0].load(Relaxed);
    let streams = (word << VideoContextFlags::GPU_STREAM_SHIFT
        & frame_header::GPU_STREAM << VideoContextFlags::GPU_STREAM_SHIFT)
        | (word << VideoContextFlags::AUDIO_STREAM_SHIFT
            & frame_header::AUDIO_STREAM << VideoContextFlags::AUDIO_STREAM_SHIFT);
    let mut flags = VideoContextFlags::from_bits_retain(
        (video.flags().bits() & !VideoContextFlags::STREAMS) | streams,
    );
    flags.remove(VideoContextFlags::GPU | VideoContextFlags::AUDIO);
    if word & frame_header::GPU_STREAM == 0 {
        flags.insert(VideoContextFlags::GPU);
    }
    if word & frame_header::AUDIO_STREAM == 0 {
        flags.insert(VideoContextFlags::AUDIO);
    }
    if no_gpu {
        flags.remove(VideoContextFlags::GPU);
    }
    if !audio {
        flags.remove(VideoContextFlags::AUDIO);
    }

    let full_record = FrameRecordFlags::from_bits_retain(session.frame_record.flags.load(Relaxed))
        .contains(FrameRecordFlags::FULL);
    if !full_record {
        flags.remove(VideoContextFlags::GPU);
    }
    if session.kernel_routine.load(Relaxed) == 0 {
        flags.remove(VideoContextFlags::AUDIO);
    }

    video.set_flags(flags);
    if !flags.intersects(VideoContextFlags::GPU | VideoContextFlags::AUDIO) {
        return Err(VideoError::NothingToReplay);
    }

    if flags.contains(VideoContextFlags::GPU) && !flags.contains(VideoContextFlags::COMPLETION) {
        let result = check(operation);
        if result != 0 {
            return Err(VideoError::Check { result });
        }
    }

    fill_requests(operation);
    wait_requests(operation);

    Ok(())
}

/// `VideoOp` status with the operation's argument and the frames left
/// (stock 0x91f5b5d8 and 0x91f56438).
fn status(operation: Operation<'_>, done: bool) {
    let video = operation.video;
    let start = video.report_start.load(Relaxed) >> 8;
    let end = video.report_end.load(Relaxed) >> 8;

    let mut frame = video.frame.load(Relaxed);
    if sign24(frame.wrapping_sub(start)) < 0 {
        frame = start;
    }
    if sign24(frame.wrapping_sub(end)) >= 0 {
        frame = end.wrapping_sub(1);
    }

    let back = sign24(operation.session().frame_index().wrapping_sub(frame));
    let current = super::super::super::frame::frame_number().wrapping_sub(back as u32) as i32;

    let mut text: openxbdm_server::text::Text<0x80> = openxbdm_server::text::Text::new();
    let argument = video.argument.load(Relaxed) as i32;
    let label = if done { "Done" } else { "Update" };
    let _ = core::fmt::Write::write_fmt(&mut text, format_args!("{argument} {label} {current}\0"));

    // SAFETY: the three fields and the NUL fit in `text`, which outlives
    // the call.
    unsafe {
        super::super::super::status::post(
            super::super::super::status::Status::VideoOp,
            text.as_bytes().as_ptr() as usize as u32,
        )
    };
}

/// Replay one frame (stock 0x91f5b630).
pub(super) fn single(operation: Operation<'_>) -> Result<(), VideoError> {
    begin(operation, false, false)?;

    let result = if operation.video.flags().contains(VideoContextFlags::GPU) {
        let first = VideoRequest::new();
        let next = VideoRequest::new();
        let mut extra = [0u32; SUBMIT_EXTRA_WORDS];
        next_request(operation, false, &first);

        let result = if first.kind() == Some(RequestKind::NoData) {
            let status = first.record_word(gpu_record::HEADER) >> fence_header::STATUS_SHIFT;
            if status != 0 {
                Err(VideoError::Refused { status })
            } else {
                Ok(())
            }
        } else {
            loop {
                next_request(operation, true, &next);
                if next.kind() != Some(RequestKind::NoData) {
                    break;
                }
            }

            replay_frame(operation, &first, &next, &mut extra)
        };

        if result.is_err() {
            end_submissions(operation);
        }

        result
    } else {
        Ok(())
    };

    status(operation, true);

    result
}

/// Align the replay clock with the first frame (stock 0x91f5b748).
fn start_clock(operation: Operation<'_>, out: &VideoRequest) {
    let video = operation.video;
    let current = &operation.session().render_client.current;
    if !video.flags().contains(VideoContextFlags::GPU) {
        next_audio(operation, current);
        video.clock_start.store(performance_counter(), Relaxed);
        video
            .clock_record
            .store(current.record_word(audio_record::TIME), Relaxed);
        return;
    }

    next_request(operation, false, out);
    while out.kind() == Some(RequestKind::Empty) {
        fill_requests(operation);
        next_audio(operation, current);
        next_request(operation, false, out);
        wait_requests(operation);
    }

    wait_position(
        operation,
        out.record_word(gpu_record::TIME)
            .wrapping_sub(out.record_word(gpu_record::POSITION)),
    );
    video.clock_start.store(performance_counter(), Relaxed);
    video
        .clock_record
        .store(out.record_word(gpu_record::TIME), Relaxed);

    if video.flags().contains(VideoContextFlags::AUDIO) {
        loop {
            next_audio(operation, current);
            if current.kind() != Some(RequestKind::Audio)
                || (video
                    .clock_record
                    .load(Relaxed)
                    .wrapping_sub(current.record_word(audio_record::TIME))
                    as i32)
                    <= AUDIO_LEAD
            {
                break;
            }
        }
    }
}

/// Replay a frame range in real time (stock 0x91f5b878) until its end, a
/// queued message, or a thread write; misses restart at the missed frame.
pub(super) fn multiple(operation: Operation<'_>) -> Result<(), VideoError> {
    /// Milliseconds between `Update` statuses.
    const STATUS_INTERVAL_MS: u32 = 100;

    let session = operation.session();
    let video = operation.video;
    let client = &session.render_client;
    let first = VideoRequest::new();
    let next = VideoRequest::new();
    let mut extra = [0u32; SUBMIT_EXTRA_WORDS];
    let mut last_status = TickCount::now().milliseconds();
    let start = TickCount::now().milliseconds();
    let mut interrupted = false;

    begin(operation, true, false)?;

    let mut result = Ok(());

    'restart: loop {
        start_clock(operation, &first);
        if video.flags().contains(VideoContextFlags::AUDIO) {
            client.publish_state(ClientState::Starting);
        }

        'frames: loop {
            let flags = video.flags();
            if flags.contains(VideoContextFlags::AUDIO)
                && client.state.load(Relaxed) == ClientState::Idle.raw()
            {
                break 'frames;
            }

            if flags.contains(VideoContextFlags::GPU) {
                let ready = if first.kind() == Some(RequestKind::Gpu) {
                    true
                } else {
                    next_request(operation, false, &first);
                    let kind = first.kind();
                    if kind == Some(RequestKind::End)
                        && !video.flags().contains(VideoContextFlags::AUDIO)
                    {
                        break 'frames;
                    }

                    kind == Some(RequestKind::Gpu)
                };

                if ready && frame_due(operation, &first) {
                    next_request(operation, true, &next);
                    match next.kind() {
                        Some(RequestKind::End) => break 'frames,
                        Some(RequestKind::Gpu) => {
                            result = replay_frame(operation, &first, &next, &mut extra);
                            if result.is_err() {
                                if video.statistics.frames.load(Relaxed) == 0 {
                                    end_submissions(operation);
                                }
                                break 'frames;
                            }

                            note_request(operation, &next);
                            if next.record_word(gpu_record::HEADER) & fence_header::LAST != 0 {
                                first.set_kind(RequestKind::Empty);
                            } else {
                                first.copy_from(&next);
                            }
                            next.set_kind(RequestKind::Empty);
                        }
                        Some(RequestKind::Empty) => {
                            note_request(operation, &first);
                            count(&video.statistics.misses);
                            next.set_kind(RequestKind::Empty);
                            first.set_kind(RequestKind::Empty);
                        }
                        // Other kinds leave both requests.
                        _ => {}
                    }
                }
            }

            if video.restart().is_some() {
                break 'frames;
            }

            fill_requests(operation);
            if TickCount::now().milliseconds().wrapping_sub(last_status) > STATUS_INTERVAL_MS {
                last_status = TickCount::now().milliseconds();
                status(operation, false);
            }

            session.leave_lock();
            session.enter_lock();
            if session.queue_count.load(Relaxed) > 0
                && !session.engine_flags().contains(EngineFlags::PAUSED)
            {
                interrupted = true;
                break 'frames;
            }

            if video.flags().contains(VideoContextFlags::AUDIO)
                && video.writes_at_pause.load(Relaxed) != session.thread_writes.load(Relaxed)
            {
                break 'frames;
            }
        }

        if let Some(restart) = video.restart()
            && restart < video.end.load(Relaxed) >> 8
        {
            finish(operation);
            video.flags.store(
                (video.flags().bits() & !VideoContextFlags::FRAME_MASK)
                    | (restart << 1 & VideoContextFlags::FRAME_MASK),
                Relaxed,
            );
            begin(operation, true, false)?;
            result = Ok(());
            continue 'restart;
        }

        break 'restart;
    }

    if video.flags().contains(VideoContextFlags::AUDIO) {
        if video.writes_at_pause.load(Relaxed) == session.thread_writes.load(Relaxed) {
            client.publish_state(ClientState::StopRequested);
            while client.state.load(Relaxed) != ClientState::Idle.raw() {}
        } else {
            client.publish_state(ClientState::Idle);
        }
    }

    status(operation, !interrupted);
    report(operation, start);

    result
}
