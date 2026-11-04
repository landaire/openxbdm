//! Debug monitor data for retail kernels without `ExDebugMonitorService`.

use core::mem::size_of;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use xbox360::console::kernel_version;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360_sys::processor::HARDWARE_THREAD_COUNT;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::processor::current_thread;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::CdromChannelInformation;
use xbox360_sys::xboxkrnl::DebugMemoryStatistics;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::Kthread;
use xbox360_sys::xboxkrnl::MmStatistics;
use xbox360_sys::xboxkrnl::NtStatus;
use xbox360_sys::xboxkrnl::ProcessorMode;
use xbox360_sys::xboxkrnl::ThreadCreationFlags;
use xbox360_sys::xboxkrnl::WaitReason;

use super::address::thread_at;
use super::monitor::debug_monitor_data;

/// Instruction offsets in `XexPcToFileHeader` that materialize loader globals.
struct ModuleListSignature {
    /// `XboxKrnlVersion.build`, not the XBDM build reported by `dmversion`.
    build: u16,
    lock: (u32, u32),
    head: (u32, u32),
}

const MODULE_LIST_SIGNATURES: &[ModuleListSignature] = &[ModuleListSignature {
    build: 17559,
    lock: (3, 5),
    head: (9, 11),
}];

/// Kernel state used by debug monitor service 4.
struct CdromChannel {
    build: u16,
    channel: u32,
    start_packet: u32,
    start_next_packet: u32,
}

const CDROM_CHANNELS: &[CdromChannel] = &[CdromChannel {
    build: 17559,
    channel: 0x801a_6380,
    start_packet: 0x8009_e0e0,
    start_next_packet: 0x8009_df88,
}];

const STATUS_INVALID_PARAMETER: NtStatus = NtStatus(0xc000_000d);
const STATUS_INVALID_SYSTEM_SERVICE: NtStatus = NtStatus(0xc000_001c);
const STATUS_SUCCESS: NtStatus = NtStatus(0);
const RETAIL_PHYSICAL_PAGE_THRESHOLD: u32 = 0x2_0000;

/// Whether the running kernel is the retail build whose state is reconstructed here.
pub fn supported_kernel() -> bool {
    let version = kernel_version();

    version.major == 2 && version.minor == 0 && version.build == 17559 && version.qfe == 0x8000
}

const XEX_PC_TO_FILE_HEADER: Ordinal = match Ordinal::new(412) {
    Some(ordinal) => ordinal,
    None => panic!("ordinal 0"),
};

/// Decode `lis rD, imm16` as `(rD, imm16)`.
fn decode_lis(word: u32) -> Option<(u32, u16)> {
    (word >> 26 == 15 && (word >> 16) & 0x1f == 0).then(|| ((word >> 21) & 0x1f, word as u16))
}

/// Decode `addi rD, rA, imm16` as `(rA, imm16)`.
fn decode_addi(word: u32) -> Option<(u32, i16)> {
    (word >> 26 == 14).then(|| ((word >> 16) & 0x1f, word as i16))
}

/// Read the address materialized by a verified `lis` and `addi` pair.
fn materialized_address(function: u32, pair: (u32, u32)) -> Option<u32> {
    let word = |index: u32| {
        // SAFETY: `function` is a resolved kernel export whose code is mapped and readable.
        unsafe {
            core::ptr::with_exposed_provenance::<u32>((function + 4 * index) as usize)
                .read_volatile()
        }
    };
    let (register, high) = decode_lis(word(pair.0))?;
    let (base, low) = decode_addi(word(pair.1))?;

    (base == register).then(|| (u32::from(high) << 16).wrapping_add(low as i32 as u32))
}

/// Populate the loaded module list and its lock from `XexPcToFileHeader`.
pub fn adopt_module_list() -> bool {
    if !supported_kernel() {
        return false;
    }
    let build = kernel_version().build;
    let Some(signature) = MODULE_LIST_SIGNATURES
        .iter()
        .find(|signature| signature.build == build)
    else {
        return false;
    };
    let Some(function) = SystemModule::Kernel
        .handle()
        .and_then(|kernel| resolve_export(kernel, XEX_PC_TO_FILE_HEADER))
        .ok()
        .map(|address| address.raw())
    else {
        return false;
    };
    let (Some(head), Some(lock)) = (
        materialized_address(function, signature.head),
        materialized_address(function, signature.lock),
    ) else {
        return false;
    };

    let data = debug_monitor_data();
    // SAFETY: these are the loader globals that the query service would publish.
    unsafe {
        data.loaded_module_list.store(head, Ordering::Relaxed);
        data.loaded_module_list_lock.store(lock, Ordering::Relaxed);
    }

    true
}

/// Fill the debug-adjusted statistics service from the retail memory manager.
unsafe fn memory_statistics(address: u32) -> NtStatus {
    if address == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let words = core::ptr::with_exposed_provenance::<u32>(address as usize);
    // SAFETY: the service contract requires both length words to be readable.
    let (length, statistics_length) =
        unsafe { (words.read_unaligned(), words.add(1).read_unaligned()) };
    if length < size_of::<DebugMemoryStatistics>() as u32
        || statistics_length < size_of::<MmStatistics>() as u32
    {
        return STATUS_INVALID_PARAMETER;
    }

    let mut reply = DebugMemoryStatistics::new();
    // SAFETY: `reply.statistics` is live and its length field is initialized.
    let status = unsafe { xboxkrnl::MmQueryStatistics(&mut reply.statistics) };
    if !status.is_success() {
        return status;
    }
    reply.page_threshold = RETAIL_PHYSICAL_PAGE_THRESHOLD;

    // SAFETY: the service contract requires `address` to hold `length` writable bytes.
    unsafe {
        core::ptr::with_exposed_provenance_mut::<DebugMemoryStatistics>(address as usize)
            .write_unaligned(reply)
    };
    STATUS_SUCCESS
}

/// Return the retail SATA channel state reconstructed for the running kernel.
unsafe fn cdrom_channel(version: u32, length: u32, address: u32) -> NtStatus {
    if version != 1 || length < size_of::<CdromChannelInformation>() as u32 || address == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if !supported_kernel() {
        return STATUS_INVALID_SYSTEM_SERVICE;
    }
    let Some(channel) = CDROM_CHANNELS
        .iter()
        .find(|channel| channel.build == kernel_version().build)
    else {
        return STATUS_INVALID_SYSTEM_SERVICE;
    };
    let information = [
        size_of::<CdromChannelInformation>() as u32,
        1,
        channel.channel,
        channel.start_packet,
        channel.start_next_packet,
        0,
        0,
        0,
    ];

    // SAFETY: the service contract requires `address` to hold `length` writable bytes.
    unsafe {
        core::ptr::with_exposed_provenance_mut::<[u32; 8]>(address as usize)
            .write_unaligned(information)
    };
    STATUS_SUCCESS
}

/// Implement retail monitor services whose state exists without the devkit kernel.
pub unsafe fn debug_monitor_service(
    service: DebugMonitorService,
    first: u32,
    second: u32,
    third: u32,
) -> NtStatus {
    if service == DebugMonitorService::MemoryStatistics {
        // SAFETY: the caller upholds the selected service contract.
        unsafe { memory_statistics(first) }
    } else if service == DebugMonitorService::CdromChannel {
        // SAFETY: the caller upholds the selected service contract.
        unsafe { cdrom_channel(first, second, third) }
    } else {
        STATUS_INVALID_SYSTEM_SERVICE
    }
}

fn process_of(thread: &Kthread) -> u32 {
    thread.process
}

static TITLE_PROCESS_PROBE: AtomicU32 = AtomicU32::new(0);

/// Suspended title-process thread returned as a referenced object.
const TITLE_PROCESS_PROBE_FLAGS: ThreadCreationFlags = ThreadCreationFlags::SUSPENDED
    .union(ThreadCreationFlags::RETURN_THREAD_OBJECT)
    .union(ThreadCreationFlags::PROCESSOR2);
const _: () = assert!(TITLE_PROCESS_PROBE_FLAGS.bits() == 0x0400_0081);

extern "C" fn title_process_probe(_context: u32) -> u32 {
    // SAFETY: the current thread object is live while this routine runs.
    let process = process_of(unsafe { thread_at(current_thread()) });
    TITLE_PROCESS_PROBE.store(process, Ordering::Release);
    // SAFETY: a thread created without the XAPI wrapper terminates through this call.
    unsafe { xboxkrnl::ExTerminateThread(0) }
}

/// Resolve `KeTitleProcess` through a transient title-process thread.
fn title_process() -> Option<u32> {
    TITLE_PROCESS_PROBE.store(0, Ordering::Release);
    let mut object = 0u32;
    // SAFETY: `object` is live storage and the entry has the required start signature.
    let status = unsafe {
        xboxkrnl::ExCreateThread(
            &mut object,
            0x2000,
            core::ptr::null_mut(),
            0,
            title_process_probe as *const () as usize as u32,
            0,
            TITLE_PROCESS_PROBE_FLAGS,
        )
    };
    status.result().ok()?;
    let object = core::num::NonZeroU32::new(object)?;
    let thread = object.get() as usize as *mut Kthread;

    // SAFETY: `object` is the referenced, suspended thread returned above.
    // The wait keeps its process live until the probe is stored.
    let waited = unsafe {
        xboxkrnl::KeResumeThread(thread);
        let status = xboxkrnl::KeWaitForSingleObject(
            thread.cast(),
            WaitReason::Executive,
            ProcessorMode::Kernel,
            false,
            core::ptr::null(),
        );
        xboxkrnl::ObDereferenceObject(object.get());
        status
    };
    waited.result().ok()?;

    core::num::NonZeroU32::new(TITLE_PROCESS_PROBE.load(Ordering::Acquire))
        .map(|process| process.get())
}

/// Populate the system and title process pointers used by thread walks.
pub fn adopt_processes() -> bool {
    let data = debug_monitor_data();
    // SAFETY: the current thread object is live while this routine runs.
    let system = process_of(unsafe { thread_at(current_thread()) });
    // SAFETY: the current module runs in the kernel system process.
    unsafe { data.system_process.store(system, Ordering::Relaxed) };

    let Some(title) = title_process() else {
        return false;
    };
    // SAFETY: the probe read the title process from its own live thread object.
    unsafe { data.title_process.store(title, Ordering::Relaxed) };

    true
}

static PROCESSOR_BLOCKS: [AtomicU32; HARDWARE_THREAD_COUNT] =
    [const { AtomicU32::new(0) }; HARDWARE_THREAD_COUNT];

/// Record this hardware thread's processor control block at IPI level.
extern "C" fn record_processor_block(_context: u32) -> u32 {
    let pcr = Kpcr::current();
    PROCESSOR_BLOCKS[pcr.processor_number().index()].store(
        core::ptr::from_ref(&pcr.prcb).expose_provenance() as u32,
        Ordering::Release,
    );

    0
}
crate::exports::bridged!(record_processor_block_entry, record_processor_block);

/// Populate the processor count and processor block array used by capture.
pub fn adopt_processors() -> bool {
    for block in &PROCESSOR_BLOCKS {
        block.store(0, Ordering::Relaxed);
    }
    // SAFETY: the bridged routine writes only its indexed static slot.
    unsafe {
        xboxkrnl::KeIpiGenericCall(record_processor_block_entry as *const () as usize as u32, 0)
    };

    let count = usize::from(super::monitor::hardware_info().number_of_processors);
    if count == 0
        || count > PROCESSOR_BLOCKS.len()
        || PROCESSOR_BLOCKS[..count]
            .iter()
            .any(|block| block.load(Ordering::Acquire) == 0)
    {
        return false;
    }

    let data = debug_monitor_data();
    data.processor_count.store(count as u32, Ordering::Relaxed);
    // SAFETY: the static array stays mapped while the monitor is loaded.
    unsafe {
        data.processor_blocks.store(
            core::ptr::from_ref(&PROCESSOR_BLOCKS).expose_provenance() as u32,
            Ordering::Relaxed,
        )
    };

    true
}
