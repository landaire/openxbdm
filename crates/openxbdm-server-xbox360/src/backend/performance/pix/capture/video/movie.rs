//! Movie data output.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use openxbdm_server::commands::memory::PAGE_SIZE;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::IoStatusBlock;

use super::super::super::files::RecordType;
use super::super::buffers;
use super::super::buffers::UNIT_SHIFT;
use super::super::cached;
use super::super::error::VideoError;
use super::super::gpu::fence_header;
use super::AUDIO_GAP_LIMIT;
use super::BLOCK_SAMPLES;
use super::BUFFER_SAMPLES;
use super::Operation;
use super::RequestKind;
use super::VideoContextFlags;
use super::VideoRequest;
use super::audio_record;
use super::gpu_record;
use super::read::current_request;
use super::read::fill_requests;
use super::read::finish;
use super::read::note_request;
use super::replay::COMMAND_LIST_ENTRIES;
use super::replay::Commands;
use super::replay::begin;
use super::replay::command_list;

/// Movie data record identifiers.
#[derive(Clone, Copy)]
#[repr(u32)]
enum MovieRecord {
    Start = 0x69,
    Frame = 0x6b,
    Audio = 0x6c,
    /// The audio stream has a gap; the movie restarts after it.
    Discontinuity = 0x6d,
    End = 0x18,
}

/// Header of the `PixV` image the title stores in a frame's command data.
#[repr(C)]
struct ImageHeader {
    magic: AtomicU32,
    /// 0.
    version: AtomicU32,
    /// At most [`ImageHeader::MAX_KIND`].
    kind: AtomicU32,
    _reserved_0c: AtomicU32,
    /// Copied into the movie frame record.
    frame_info: [AtomicU32; 2],
    _reserved_18: [AtomicU32; 2],
    /// Copied into the movie frame record.
    frame_format: AtomicU32,
}

impl ImageHeader {
    const MAGIC: u32 = u32::from_be_bytes(*b"PixV");
    const MAX_KIND: u32 = 2;
    /// Bytes from the header to the image data.
    const BYTES: u32 = PAGE_SIZE;
}

const _: () = assert!(core::mem::offset_of!(ImageHeader, frame_format) == 0x20);

/// Write movie data to the operation's file (stock 0x91f5a790).
///
/// # Safety
///
/// `bytes` bytes at `data` must be readable for the call.
unsafe fn emit(operation: Operation<'_>, data: *const u8, bytes: u32) {
    let mut io_status = IoStatusBlock::default();

    // SAFETY: the operation's open file; guaranteed by the caller; the
    // write is synchronous.
    let status = unsafe {
        xboxkrnl::NtWriteFile(
            Handle::from_raw(operation.video.file.load(Relaxed)),
            Handle::NULL,
            0,
            0,
            &mut io_status,
            data,
            bytes,
            core::ptr::null(),
        )
    };

    if !status.is_success() {
        operation.video.write_failed.store(1, Relaxed);
    }
}

fn emit_words(operation: Operation<'_>, words: &[u32]) {
    // SAFETY: `words` is live for the call.
    unsafe { emit(operation, words.as_ptr().cast(), (words.len() * 4) as u32) };
}

/// Write capture buffer memory as movie data.
///
/// # Safety
///
/// `[data, data + bytes)` must lie in a capture buffer.
unsafe fn emit_buffer(operation: Operation<'_>, data: u32, bytes: u32) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        emit(
            operation,
            core::ptr::with_exposed_provenance(data as usize),
            bytes,
        )
    };
}

/// Movie data record header (stock 0x91f5bc08).
fn movie_record(operation: Operation<'_>, id: MovieRecord, bytes: u32) {
    /// Records of fewer dwords have a one-word movie data header.
    const SHORT_RECORD_DWORDS: u32 = 0x7f;

    let id = id as u32;
    let dwords = bytes >> 2;

    if dwords < SHORT_RECORD_DWORDS {
        emit_words(operation, &[((dwords + 1) << 24 & 0x7fff_ffff) | id]);
    } else {
        emit_words(operation, &[RecordType::new(id).raw(), dwords + 2]);
    }
}

/// Movie frame: the `PixV` image the title stored in the frame's command
/// data (stock 0x91f5bc78).
fn movie_frame(
    operation: Operation<'_>,
    first: &VideoRequest,
    next: &VideoRequest,
) -> Result<(), VideoError> {
    let mut list = [0u32; COMMAND_LIST_ENTRIES];
    let Commands {
        start: mut index,
        mut count,
        offset,
    } = command_list(operation, first, next, &mut list);

    // SAFETY: the title stores the image header at the start of the
    // frame's command data, in a capture buffer.
    let image: &ImageHeader = unsafe { crate::kernel::object_at(cached(list[index] + offset)) };
    if image.magic.load(Relaxed) != ImageHeader::MAGIC
        || image.version.load(Relaxed) != 0
        || image.kind.load(Relaxed) > ImageHeader::MAX_KIND
    {
        return Err(VideoError::NoImage);
    }

    let mut position = offset + ImageHeader::BYTES;
    if position >= buffers::BUFFER_BYTES {
        if position != buffers::BUFFER_BYTES {
            return Err(VideoError::NoImage);
        }
        position = 0;
        index += 1;
        count -= 1;
    }

    let header = [
        first.record_word(gpu_record::TIME),
        image.frame_info[0].load(Relaxed),
        image.frame_info[1].load(Relaxed),
        image.frame_format.load(Relaxed),
    ];

    movie_record(
        operation,
        MovieRecord::Frame,
        ((count as u32) << UNIT_SHIFT).wrapping_sub(position) + 0x10,
    );
    emit_words(operation, &header);

    for &buffer in &list[index..index + count] {
        let data = buffer + position;
        let bytes = buffers::BUFFER_BYTES - position;
        // SAFETY: `data` and `bytes` lie in a capture buffer.
        unsafe {
            emit_buffer(operation, data, bytes);
            xboxkrnl::KeFlushCacheRange(data, bytes);
        }
        position = 0;
    }

    Ok(())
}

/// Movie audio between two audio requests (stock 0x91f5be10).
fn movie_audio(operation: Operation<'_>, previous: &VideoRequest, current: &VideoRequest) {
    let previous_header = previous.record_word(audio_record::HEADER);
    let start = audio_record::position(previous_header);
    let end = audio_record::position(current.record_word(audio_record::HEADER));
    let header = [
        previous.record_word(audio_record::TIME),
        (previous_header >> audio_record::DROPPED_SHIFT) * BLOCK_SAMPLES,
        end + (BUFFER_SAMPLES - start),
    ];

    let first_bytes = (BUFFER_SAMPLES - start) * 2;
    let second_bytes = end * 2;
    let first = cached(operation.buffer(previous.unit())) + start * 2;
    let second = cached(operation.buffer(current.unit()));

    movie_record(
        operation,
        MovieRecord::Audio,
        second_bytes + first_bytes + 0xc,
    );
    emit_words(operation, &header);

    // SAFETY: both ranges lie in the audio capture buffers of the requests.
    unsafe {
        emit_buffer(operation, first, first_bytes);
        emit_buffer(operation, second, second_bytes);
        xboxkrnl::KeFlushCacheRange(first, first_bytes);
        xboxkrnl::KeFlushCacheRange(second, second_bytes);
    }
}

/// Write the frame range as movie data (stock 0x91f5bf10).
pub(super) fn movie(operation: Operation<'_>, no_gpu: bool) -> Result<(), VideoError> {
    let video = operation.video;

    movie_record(operation, MovieRecord::Start, 0);

    // Stock starts from uninitialized previous requests.
    let audio = VideoRequest::new();
    let frame = VideoRequest::new();
    let current = VideoRequest::new();

    'restart: loop {
        begin(operation, true, no_gpu)?;

        loop {
            fill_requests(operation);
            current_request(operation, &current);

            match current.kind() {
                Some(RequestKind::End) => {
                    movie_record(operation, MovieRecord::End, 0);
                    return Ok(());
                }
                Some(RequestKind::Gpu) => {
                    if frame.kind() == Some(RequestKind::Gpu) {
                        if let Err(error) = movie_frame(operation, &frame, &current) {
                            movie_record(operation, MovieRecord::End, 0);
                            return Err(error);
                        }
                        note_request(operation, &current);
                    }

                    if current.record_word(gpu_record::HEADER) & fence_header::LAST != 0 {
                        frame.set_kind(RequestKind::Empty);
                    } else {
                        frame.copy_from(&current);
                    }
                }
                Some(RequestKind::Audio) => {
                    if audio.kind() == Some(RequestKind::Audio) {
                        let discontinuous = (current
                            .record_word(audio_record::TIME)
                            .wrapping_sub(audio.record_word(audio_record::TIME))
                            as i32)
                            > AUDIO_GAP_LIMIT
                            || (audio_record::position(current.record_word(audio_record::HEADER))
                                .wrapping_sub(audio_record::position(
                                    audio.record_word(audio_record::HEADER),
                                ))
                                .wrapping_add(BUFFER_SAMPLES))
                                % BLOCK_SAMPLES
                                != 0;

                        if discontinuous {
                            movie_record(operation, MovieRecord::Discontinuity, 0);
                            finish(operation);

                            let mask = VideoContextFlags::FRAME_MASK;
                            let restart =
                                ((current.header.load(Relaxed) >> 7) & mask).wrapping_add(2);
                            let flags = (restart & mask) | (video.flags().bits() & !mask);
                            video.flags.store(flags, Relaxed);

                            if flags & mask < (video.end.load(Relaxed) >> 7) & mask {
                                audio.set_kind(RequestKind::Empty);
                                frame.set_kind(RequestKind::Empty);
                                continue 'restart;
                            }
                        }

                        movie_audio(operation, &audio, &current);
                        video.audio_buffer.store(current.unit() as u32, Relaxed);
                    }
                    audio.copy_from(&current);
                }
                // Other kinds carry no movie data.
                _ => {}
            }
        }
    }
}
