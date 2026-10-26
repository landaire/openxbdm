//! XAudio render client that plays captured audio.

use core::sync::atomic::AtomicU16;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use xbox360_sys::xboxkrnl::XAudioSubmitRenderDriverFrame;

use super::super::super::session::PixSession;
use super::super::buffers;
use super::super::cached;
use super::AUDIO_GAP_LIMIT;
use super::BLOCK_SAMPLES;
use super::BUFFER_SAMPLES;
use super::ClientState;
use super::Operation;
use super::RenderClient;
use super::RequestKind;
use super::VideoContext;
use super::VideoRequest;
use super::audio_record;
use super::read::count;
use super::read::next_audio;
use super::replay::audio_due;
use super::replay::performance_counter;

/// Convert the 16-bit samples at `source` to floats in `output` (stock
/// 0x91f5a860).
///
/// # Safety
///
/// `source` must address `output.len()` samples of a capture buffer.
unsafe fn to_float(output: &[AtomicU32], source: u32) {
    /// 2^-15.
    const SCALE: f32 = 1.0 / 32768.0;

    let start = cached(source);
    // SAFETY: guaranteed by the caller; `start` is the cached view of the
    // same memory.
    let samples: &[AtomicU16] = unsafe {
        core::slice::from_raw_parts(
            core::ptr::with_exposed_provenance(start as usize),
            output.len(),
        )
    };

    for (target, sample) in output.iter().zip(samples) {
        target.store(
            (f32::from(sample.load(Relaxed) as i16) * SCALE).to_bits(),
            Relaxed,
        );
    }

    buffers::flush(start, start + output.len() as u32 * 2);
}

crate::exports::bridged!(render_entry, render);

/// Address of the audio client routine handed to XAudio.
pub(in super::super) fn render_entry_address() -> u32 {
    render_entry as *const () as usize as u32
}

/// XAudio render client routine (stock 0x91f5b140): plays the captured
/// audio of the operation, [`BLOCK_SAMPLES`] samples per call.
extern "C" fn render(context: u32) {
    // SAFETY: XAudio passes the address of the word that holds the context
    // of the registration `pause_engine` made, the address of the session's
    // render client; the client's session and video words hold the
    // addresses of the session block that contains it and of the block's
    // video context. The block outlives the registration.
    let (client, session, video): (&RenderClient, &PixSession, &VideoContext) = unsafe {
        let client: &RenderClient =
            crate::kernel::object_at(crate::kernel::object_at::<AtomicU32>(context).load(Relaxed));
        (
            client,
            crate::kernel::object_at(client.session.load(Relaxed)),
            crate::kernel::object_at(client.video.load(Relaxed)),
        )
    };

    let current = &client.current;
    let state = ClientState::from_raw(client.state.load(Relaxed));

    match state {
        Some(ClientState::StopRequested) => {
            client.publish_state(ClientState::Idle);
            return;
        }
        // The client plays in these states.
        Some(ClientState::Starting | ClientState::Playing) => {}
        _ => return,
    }

    // Only `multiple` sets the starting state, after `initialize`; it sets
    // the client idle or stopped before `release`, so the ring and buffer
    // words hold the operation's. `multiple` only waits for the client to
    // stop on the stop request; when it sets the client idle after a thread
    // write it does not wait, as stock, so a call that passed the state
    // check above can still use the ring after `release` frees it (a race
    // of stock).
    let operation = Operation { video };

    if state == Some(ClientState::Starting) {
        if current.kind() == Some(RequestKind::Empty) {
            next_audio(operation, current);
            if current.kind() == Some(RequestKind::Empty) {
                return;
            }
        }

        if current.kind() == Some(RequestKind::End) {
            client.set_state(ClientState::Idle);
            return;
        }

        if !audio_due(operation, current) {
            return;
        }

        client.position.store(
            audio_record::position(current.record_word(audio_record::HEADER)),
            Relaxed,
        );
        client.data.store(operation.buffer(current.unit()), Relaxed);

        client.publish_state(ClientState::Playing);
    }

    let output_address = client.output.as_ptr().addr() as u32;
    let position = client.position.load(Relaxed);

    if position <= BUFFER_SAMPLES - BLOCK_SAMPLES {
        // SAFETY: the block lies in the audio buffer of `BUFFER_SAMPLES`
        // samples at `data`.
        unsafe { to_float(&client.output, client.data.load(Relaxed) + position * 2) };
        client.position.store(position + BLOCK_SAMPLES, Relaxed);
        // SAFETY: the client registered by `pause_engine`; `output` is its
        // sample buffer.
        unsafe {
            XAudioSubmitRenderDriverFrame(session.audio_client.load(Relaxed), output_address)
        };
        count(&video.statistics.audio_frames);
        return;
    }

    let repeat = current.record_word(audio_record::HEADER);
    let dropped = repeat >> audio_record::DROPPED_SHIFT;

    if dropped != 0 {
        current.record[audio_record::HEADER].store(
            (repeat & ((1 << audio_record::DROPPED_SHIFT) - 1))
                | (dropped - 1) << audio_record::DROPPED_SHIFT,
            Relaxed,
        );
        count(&video.statistics.audio_dropped);
        return;
    }

    let first = BUFFER_SAMPLES - position;
    let rest = BLOCK_SAMPLES - first;
    let (head, tail) = client.output.split_at(first as usize);

    // SAFETY: the samples from `position` to the end of the audio buffer at
    // `data`.
    unsafe { to_float(head, client.data.load(Relaxed) + position * 2) };

    let next = VideoRequest::new();
    next_audio(operation, &next);

    let underrun = match next.kind() {
        Some(RequestKind::End) => {
            client.publish_state(ClientState::Idle);
            return;
        }
        Some(RequestKind::Empty) => true,
        _ => {
            let lead = (video.clock_start.load(Relaxed) as i32)
                .wrapping_sub(performance_counter() as i32)
                .wrapping_add(
                    current
                        .record_word(audio_record::TIME)
                        .wrapping_sub(video.clock_record.load(Relaxed)) as i32,
                );
            lead > AUDIO_GAP_LIMIT
                || (audio_record::position(next.record_word(audio_record::HEADER))
                    .wrapping_sub(rest))
                    % BLOCK_SAMPLES
                    != 0
        }
    };

    if underrun {
        video.restart.store(current.frame() + 1, Relaxed);
        count(&video.statistics.audio_restarts);
        client.publish_state(ClientState::Underrun);
        return;
    }

    let data = operation.buffer(next.unit());
    client.position.store(rest, Relaxed);
    client.data.store(data, Relaxed);

    // SAFETY: the first `rest` samples of the next audio buffer.
    unsafe { to_float(tail, data) };

    // SAFETY: as above.
    unsafe { XAudioSubmitRenderDriverFrame(session.audio_client.load(Relaxed), output_address) };
    count(&video.statistics.audio_frames);

    current.copy_from(&next);
}
