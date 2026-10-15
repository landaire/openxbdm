//! Performance counters, display capture, video encoder access, and the
//! profiling engines. The engines live in submodules; `service` routes the
//! performance and PIX control codes of the monitor dispatcher to them.

mod capture;
mod counters;
pub(crate) mod module_snapshot;
pub(crate) mod pix;
mod pmc;
mod profiler;
pub(crate) mod studio;
pub(crate) mod xtrace;

pub(crate) use counters::memory_statistics;

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::filesystem::DriveTable;
use openxbdm_server::commands::performance;
use openxbdm_server::commands::performance::COUNTER_NAME_CAPACITY;
use openxbdm_server::commands::performance::CaptureValue;
use openxbdm_server::commands::performance::CounterEntry;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::DisplayCapture;
use openxbdm_server::commands::performance::DisplayInformation;
use openxbdm_server::commands::performance::EDID_BLOCK_SIZE;
use openxbdm_server::commands::performance::EdidRead;
use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::commands::performance::TILE_SIZE;
use openxbdm_server::commands::performance::capture::CaptureFlags;

use super::Console;
use crate::kernel;
use crate::kernel::import_thunk;

import_thunk!(
    VdGetCurrentDisplayInformation(information: *mut u32) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0x1ba
);
import_thunk!(
    VdReadDVERegisterUlong(register: u32) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0x1cb
);
import_thunk!(
    VdWriteDVERegisterUlong(register: u32, value: u32) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 0x1e0
);

/// GPU register block.
const GPU_REGISTERS: usize = 0x7fc8_0000;
/// GPU status register; bit 31 is set while a flip is pending.
const GPU_FLIP_PENDING: usize = 0x7fc8_1740;
/// Display controller gamma control; bits 8 to 10.
const DISPLAY_GAMMA: usize = 0x7fc8_6104;
/// Display controller front buffer address.
const DISPLAY_FRONT_BUFFER: usize = 0x7fc8_6110;
/// Longest wait for a pending flip.
const FLIP_WAIT_MS: u32 = 500;
/// Video encoder identification register; 0x10000 and up have the
/// extended banks.
const ENCODER_ID_REGISTER: u32 = 0xfe;
const ENCODER_EXTENDED_ID: u32 = 0x1_0000;
/// Kernel export that reads an EDID block.
const EDID_EXPORT: u32 = 623;
/// SMC message that carries an I2C transfer.
const SMC_I2C: u8 = 0x11;
/// Extended registers whose writes are bracketed by bus requests.
const BRACKETED_REGISTERS: core::ops::RangeInclusive<u32> = 0x1d0..=0x1f5;

/// Platform state of this domain.
pub struct Data {
    encoder_extended: Option<bool>,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            encoder_extended: None,
        }
    }
}

/// Start the engines during module initialization, after the control
/// dispatcher is published (stock order in 0x91f32628).
pub(crate) fn initialize() {
    counters::initialize();
    capture::initialize();
    pix::initialize();
    // SAFETY: written once, before the kernel uses the registration.
    unsafe {
        *TITLE_ENDED.0.get() = [
            title_ended_entry as *const () as usize as u32,
            TITLE_ENDED_PRIORITY,
            0,
            0,
        ]
    };
    kernel::ExRegisterTitleTerminateNotification(TITLE_ENDED.0.get().cast(), 1);
}

/// Stop every timer, DPC, thread, and hook that calls into this image;
/// runs before the image unloads.
pub(crate) fn shut_down() {
    kernel::ExRegisterTitleTerminateNotification(TITLE_ENDED.0.get().cast(), 0);
    counters::shut_down();
    capture::shut_down();
    profiler::shut_down();
    pix::shut_down();
    studio::shut_down();
    xtrace::shut_down();
}

/// Performance part of the title terminate notification (stock 0x91f32398).
pub(crate) fn title_terminated() {
    capture::title_terminated();
    profiler::title_terminated();
    counters::title_terminated();
    pmc::title_terminated();
    pix::title_terminated();
}

/// Title terminate registration `{routine, priority, 0, 0}` of stock
/// 0x91f97444, which runs after the main one (0x91f32398).
struct Registration(core::cell::UnsafeCell<[u32; 4]>);

// SAFETY: written once during initialization, then read by the kernel.
unsafe impl Sync for Registration {}

static TITLE_ENDED: Registration = Registration(core::cell::UnsafeCell::new([0; 4]));
const TITLE_ENDED_PRIORITY: u32 = 0x6d80_0000;

/// Second title terminate routine (stock 0x91f32418): the title's handles
/// are gone with its process.
extern "C" fn title_ended() {
    counters::title_ended();
    pix::title_ended();
    super::hardware::nuicam::title_ended();
}
crate::exports::bridged!(title_ended_entry, title_ended);

/// Monitor control codes of this domain; `None` for other codes.
pub(crate) fn service(code: u32, argument: u32) -> Option<u32> {
    match code {
        0x99 => Some(studio::service_set_device_status(argument)),
        0x1b => Some(pix::service_post_text(argument)),
        0x27 => Some(pix::service_write_dword(argument)),
        0x41 => Some(pix::service_unregister_consumer(argument)),
        0x42 => Some(pix::service_register_consumer(argument)),
        0x43 => Some(pix::service_write_block(argument)),
        0x45 => Some(pix::service_filter_control(argument)),
        0x58 => Some(pix::service_register_persistent_consumer(argument)),
        0x5e => Some(pix::service_write_block_list(argument)),
        0x7f => Some(pix::service_disk_start(argument)),
        0x80 => Some(pix::service_disk_complete(argument)),
        0x2e => Some(pix::service_frame(argument)),
        0x2f => Some(pix::service_register_callback(argument)),
        0x30 => Some(pix::service_unregister_callback(argument)),
        0x3c => Some(pix::service_thread_slot(argument)),
        0x3f => Some(pix::service_set_discard_output(argument)),
        0x44 => Some(pix::service_state_flags(argument)),
        0x52 => Some(pix::service_frame_record(argument)),
        0x53 => Some(pix::service_open_for_capture(argument)),
        0x54 => Some(pix::service_open_for_start(argument)),
        0x55 => Some(pix::service_write_capture_record(argument)),
        0x57 => Some(pix::service_queue_message(argument)),
        0x59 => Some(pix::service_acquire_owner(argument)),
        0x5a => Some(pix::service_release_owner(argument)),
        0x83 => Some(pix::service_resource_begin(argument)),
        0x84 => Some(pix::service_resource_record(argument)),
        0x85 => Some(pix::service_resource_end(argument)),
        0x87 => Some(pix::service_resource_information(argument)),
        0x50 => Some(pix::service_timing_request(argument)),
        0x51 => Some(pix::service_frame_buffer(argument)),
        0x56 => Some(pix::service_configure(argument)),
        0x5b => Some(pix::service_samples(argument)),
        0x5c => Some(pix::service_command_buffers(argument)),
        0x5d => Some(pix::service_fence(argument)),
        0x8d => Some(pix::service_nuicam_begin(argument)),
        0x8e => Some(pix::service_end(argument)),
        0x9f => Some(studio::service_set_test_mode(argument)),
        0x38 => Some(xtrace::service_start(argument)),
        0x39 => Some(xtrace::service_stop(argument)),
        0x3a => Some(xtrace::service_instruction_count(argument)),
        0x3b => Some(xtrace::service_request_stop(argument)),
        _ => None,
    }
}

fn read_register(address: usize) -> u32 {
    // SAFETY: GPU and display controller registers are mapped in every
    // process.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// Bytes of the NUL-terminated string at `address`, at most `limit`.
#[inline(never)]
fn c_string<'a>(address: u32, limit: usize) -> &'a [u8] {
    let mut length = 0;
    // SAFETY: callers pass a NUL-terminated string or one of at least
    // `limit` readable bytes.
    while length < limit
        && unsafe { core::ptr::read_volatile((address as usize + length) as *const u8) } != 0
    {
        length += 1;
    }
    // SAFETY: the bytes were just read.
    unsafe { core::slice::from_raw_parts(address as usize as *const u8, length) }
}

impl Console {
    fn encoder_extended(&mut self) -> bool {
        *self.performance.encoder_extended.get_or_insert_with(|| {
            VdReadDVERegisterUlong(ENCODER_ID_REGISTER) >= ENCODER_EXTENDED_ID
        })
    }
}

/// Send one SMC I2C message carrying `flags` in byte 1.
fn send_i2c_request(flags: u8) {
    let mut message = [0u8; 16];
    let mut reply = [0u8; 16];
    message[0] = SMC_I2C;
    message[1] = flags;
    kernel::HalSendSMCMessage(message.as_ptr(), reply.as_mut_ptr());
}

impl performance::Backend for Console {
    fn performance_frequency(&mut self) -> u64 {
        kernel::performance_frequency()
    }

    fn next_counter(
        &mut self,
        context: &mut u32,
        name: &mut [u8; COUNTER_NAME_CAPACITY],
    ) -> Result<CounterEntry, Hresult> {
        counters::next(context, name).map(|(name_len, counter_type)| CounterEntry {
            name_len,
            counter_type,
        })
    }

    fn query_counter(&mut self, name: &[u8], query: u32, out: &mut CounterSample) -> Hresult {
        let handle = match counters::open(name) {
            Ok(handle) => handle,
            Err(result) => return result,
        };
        let result = match counters::reference(handle) {
            Ok(mut counter) => {
                let result = counters::query(&mut counter, query, out);
                counter.release();
                result
            }
            Err(status) => {
                Hresult::from_nt_status(openxbdm_core::status::NtStatus(status), Hresult::FAIL)
            }
        };
        kernel::NtClose(handle);
        result
    }

    fn capture_display(&mut self) -> DisplayCapture {
        if read_register(GPU_FLIP_PENDING) & 0x8000_0000 != 0 {
            let start = kernel::tick_count();
            while kernel::tick_count().wrapping_sub(start) <= FLIP_WAIT_MS
                && read_register(GPU_FLIP_PENDING) & 0x8000_0000 != 0
            {}
        }
        let front_buffer = read_register(DISPLAY_FRONT_BUFFER);
        let mut information = [0u32; 0x18];
        VdGetCurrentDisplayInformation(information.as_mut_ptr());
        let gamma = (read_register(DISPLAY_GAMMA) >> 8) & 7 != 0;
        DisplayCapture {
            display: DisplayInformation {
                surface_width: (information[0] >> 16) as u16,
                colorspace: (information[1] >> 24) as u8,
                left: information[2],
                top: information[3],
                right: information[4],
                bottom: information[5],
                scaled_width: information[6],
                scaled_height: information[7],
            },
            front_buffer,
            gamma,
        }
    }

    fn read_framebuffer_page(&mut self, address: u32, page: &mut [u8]) {
        kernel::KeFlushCacheRange(address, TILE_SIZE);
        // SAFETY: the page lies in the front buffer the display controller
        // scans out.
        let source = unsafe {
            core::slice::from_raw_parts(address as usize as *const u8, TILE_SIZE as usize)
        };
        page.copy_from_slice(source);
        kernel::KeFlushCacheRange(address, TILE_SIZE);
    }

    fn read_video_encoder(&mut self, register: u32) -> u32 {
        VdReadDVERegisterUlong(register)
    }

    fn write_video_encoder(&mut self, register: u32, value: u32) {
        VdWriteDVERegisterUlong(register, value);
    }

    fn video_encoder_extended(&mut self) -> bool {
        self.encoder_extended()
    }

    /// One-byte I2C write to device 0x39 (0x100..0x1ff) or 0x3d
    /// (0x200..0x2ff), as stock 0x91f23f00.
    fn write_video_encoder_extended(&mut self, register: u32, value: u8) {
        let mut message = [0u8; 16];
        let mut reply = [0u8; 16];
        message[0] = SMC_I2C;
        message[1] = 2 << 4;
        message[3] = 0x80 | if register > 0x1ff { 0x3d } else { 0x39 };
        message[6] = register as u8;
        message[7] = value;
        let bracketed = BRACKETED_REGISTERS.contains(&register);
        let bus_requests = kernel::hardware_flags() & 0xf000_0000 != 0;
        if bracketed {
            message[1] |= 1;
            if bus_requests {
                send_i2c_request(3);
            }
        }
        kernel::HalSendSMCMessage(message.as_ptr(), reply.as_mut_ptr());
        if bracketed && bus_requests {
            send_i2c_request(5);
        }
        if reply[1] != 0 {
            pmc::print(
                c"BD: Failed to write I2C bus address %X, error code %u\n",
                &[u64::from(register), u64::from(reply[1])],
            );
        }
    }

    fn read_gpu_register(&mut self, index: u32) -> u32 {
        read_register(GPU_REGISTERS + index as usize * 4)
    }

    fn write_gpu_register(&mut self, index: u32, value: u32) {
        // SAFETY: the index was checked against the register block.
        unsafe {
            core::ptr::write_volatile((GPU_REGISTERS + index as usize * 4) as *mut u32, value)
        }
    }

    fn read_edid(&mut self, block: u8, output: &mut [u8; EDID_BLOCK_SIZE]) -> EdidRead {
        let Ok(function) = kernel::module_handle(c"xboxkrnl.exe")
            .and_then(|module| kernel::resolve_export(module, EDID_EXPORT))
        else {
            return EdidRead::Unsupported;
        };
        // SAFETY: the export takes (block, 128-byte buffer).
        let read = unsafe {
            kernel::call_export(
                function,
                u32::from(block),
                output.as_mut_ptr() as usize as u32,
                0,
                0,
            )
        };
        if read == 0 {
            EdidRead::Failed
        } else {
            EdidRead::Read
        }
    }

    fn dedicate_studio_socket(&mut self) -> Result<u16, Hresult> {
        studio::dedicate()
    }

    fn capture_start(&mut self, name: &[u8], path: &[u8], buffer_size: u32) -> Hresult {
        capture::start(name, path, buffer_size)
    }

    fn fast_cap_present(&mut self) -> bool {
        capture::fast_cap_present()
    }

    fn call_cap_present(&mut self) -> bool {
        capture::call_cap_present()
    }

    fn capture_stop(&mut self, drives: &DriveTable) -> Hresult {
        capture::stop(self, drives)
    }

    fn capture_set_flags(&mut self, flags: CaptureFlags) {
        capture::set_flags(flags);
    }

    fn capture_status(&mut self) -> Hresult {
        capture::status()
    }

    fn capture_abort(&mut self) -> Hresult {
        capture::abort()
    }

    fn cpu_profiler_start(
        &mut self,
        drives: &DriveTable,
        name: &[u8],
        interval: u32,
        flags: u32,
    ) -> Hresult {
        let path = drives.translate(self, name);
        let mut executable = [0u8; module_snapshot::PATH_LIMIT + 2];
        let length = drives.object_path_to_drive_path(
            self,
            module_snapshot::executable_object_path(),
            &mut executable,
        );
        profiler::start(
            path.as_ref().map(|path| path.as_bytes()),
            &executable[..length],
            interval,
            flags,
        )
    }

    fn cpu_profiler_stop(&mut self) -> Hresult {
        profiler::stop()
    }

    fn cpu_profiler_info(&mut self) -> Result<CpuProfilerInfo, Hresult> {
        profiler::info()
    }

    fn pix_post(&mut self, code: u32, payload: &[u32]) -> bool {
        pix::backend::post(code, payload)
    }

    fn pix_status(&mut self, version: u32, flags: u32) -> Option<[u32; 12]> {
        pix::backend::status(version, flags)
    }

    fn pix_frame_statistics(&mut self, frame: u32) -> Option<[u32; 3]> {
        pix::backend::frame_statistics(frame)
    }

    fn pix_frame_number(&mut self) -> i32 {
        pix::backend::frame_number()
    }

    fn pix_signal_event(&mut self, event: u32) {
        pix::backend::signal_event(event);
    }

    fn pix_set_trace(&mut self, enabled: bool) {
        pix::set_trace(enabled);
    }

    fn pix_counter_control(&mut self, group: u32, id: u32, enabled: bool) {
        pix::backend::counter_control(group, id, enabled);
    }

    fn pix_set_capture_value(&mut self, value: CaptureValue, data: u32) {
        pix::backend::set_capture_value(value, data);
    }

    fn pix_set_capture_text(&mut self, text: &[u8]) {
        pix::backend::set_capture_text(text);
    }

    fn pix_set_legacy_protocol(&mut self, legacy: bool) {
        pix::backend::set_legacy_protocol(legacy);
    }

    fn pix_set_gpu_capture(&mut self, enabled: bool) {
        pix::backend::set_gpu_capture(enabled);
    }

    fn pix_dogma(&mut self) -> Option<PixDogma> {
        pix::backend::dogma()
    }

    fn pix_boot_animation_loaded(&mut self) -> bool {
        kernel::module_handle(c"bootanim.xex").is_ok()
    }

    fn pix_capture_ready(&mut self) -> bool {
        pix::backend::capture_ready()
    }

    fn pix_trace_snapshot(&mut self) -> u32 {
        pix::backend::trace_snapshot()
    }

    fn pix_trace_read(&mut self, output: &mut [u8]) -> usize {
        pix::backend::trace_read(output)
    }
}
