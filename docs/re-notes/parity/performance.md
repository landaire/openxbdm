# Parity: performance domain

Commands: `autoprof`, `capctrl`, `gpucount`, `lopctrl`, `pclist`, `perfstat`,
`pixcmd`, `pixpreview`, `querypc`, `screenshot`, `vd`, `xstudio`.
Specs: group1 (`autoprof`, `capctrl`), group4 (`gpucount`), group5
(`lopctrl`), group6 (`pclist`, `perfstat`, `pixcmd`, `pixpreview`,
`querypc`, `screenshot`), group8 (`vd`, `xstudio`).

## Server

Code: `crates/openxbdm-server/src/commands/performance.rs`,
`performance/counters.rs` (counter objects, sampler, `querypc`
evaluation), `performance/pix.rs` (`pixcmd`), `performance/studio.rs`
(Xbox Studio socket transport framing, unit-tested),
`performance/capture.rs` (capture flag word, buffer and chunk sizing,
record encoding, and the start/stop/abort/title terminate sequences over
an `Engine` trait, unit-tested).

| Command | Server | Host test |
| --- | --- | --- |
| autoprof | as stock exports 175/176 (hardware flag 0x10, XConfig 3/8) | read, write, malformed `xuid`, flag clear |
| capctrl | subcommand order, `HRESULT 0x%08x` text, start validates the file through the drive table (0x91f2eb68); start/stop/abort run `capture::{start, stop, abort}` | every subcommand, missing name, not instrumented, running start, stop and file name, call-cap service calls, full buffer on stop and abort, title hand-off |
| gpucount | as stock | enable, disable, neither |
| lopctrl | `profiler::Control` (0x91f32c90/0x91f33010/0x91f32e30/0x91f33090) shared by the command and exports 149-151; the backend translates the name | sequence, double start, flush failure, init failure and retry, translated path and directories, name without a drive |
| pclist | 202 enumeration of the counter directory; context in the connection scratch | directory order, missing directory |
| perfstat | `PerfFreq=0x%I64X` | value |
| pixcmd | full letter switch, stock argument walker, stale-byte reads | posts, payloads, replies, range rejection, `r` 203 |
| pixpreview | as stock | reply |
| querypc | stock evaluation over the object layout, including the non-advancing history and the stale rate | instantaneous, history, every error |
| screenshot | header and tile order of 0x91f4b048, stop/resume through the debugger domain | header text, page addresses, client decode equals the framebuffer |
| vd | every `cmd` path | peek/poke both banks, gpeek/gpoke, EDID 203, every failure |
| xstudio | token rule, `OK %u`/`NO` | token variants, listener failure |

## Host mock

`crates/openxbdm-server-host/src/backend/performance.rs`: the 32 built-in
counters in stock directory order with stock registration words and a
source word layout matching 0x91fae680 (page counts, then per-processor
idle/DPC/ISR pairs); `Counters::tick` runs the bucketed sampler. A tiled
front buffer (`Display::new`), video encoder banks, GPU registers, EDID
blocks, a simulated capture engine (instrumentation, buffers, written file
names) behind the server's capture sequences, and recording CPU profiler
and PIX engines.

## Xbox backend

Implemented with stock services: `perfstat` (KeQueryPerformanceFrequency
through a 64-bit return wrapper), `screenshot` (flip wait on the tick
count, display controller registers, VdGetCurrentDisplayInformation,
KeFlushCacheRange around each page), `vd` (VdRead/WriteDVERegisterUlong,
SMC I2C message 0x11 with the 0x1d0..0x1f5 bus requests, GPU MMIO, kernel
export 623), `pixcmd o` boot animation check (XexGetModuleHandle).

Counters (`backend/performance/counters.rs`): the `\DmCounters` directory
per process type (system creates, title opens; 0x91f2a7a8), the counter
object type (`cpmd`; default object 0x91fadda0, a signaled synchronization event),
registration (export 33), open (26), query (27), walk (53), the 32
built-in counters of 0x91f2b110, and the 100 ms periodic timer with DPC
0x91f2af38 (ten buckets linked through the object header, processor
idle/DPC/ISR times from the processor blocks at debug monitor data +0x5c,
page counts from export 75). The block at debug monitor data +0x20
(0x91fade40: size, title capture control/result pointers, capture
start/stop entries, frame count and frame ticks pointers) and the empty
block at +0x24 are published at initialization; the title terminate
routine clears the frame pointers and the second one (0x91f32418) the
title's directory handle. `querypc` raises the IRQL only around the
history and copied-sample reads, as export 27 does. The sampler DPC and
both title terminate routines enter through the export bridge.
0x91f2b110 initializes the sampler timer with `KeInitializeTimerEx` and
r5 = 2 (`li r5,2` before the call that initializes the timer at r28), the
system process type; the console backend passes `ProcessType::SYSTEM`.

Unload (no stock counterpart; stock never unloads): runs after the server
thread has exited. The sampler timer is cancelled, its DPC dequeued, one
sampler period waited and running samples drained; every counter object
and the directory are made temporary so a later monitor can create the
directory again, and no directory is opened or created afterwards.
Counters other modules still hold open keep their handles.

Xbox Studio (`backend/performance/studio.rs`): initialization 0x91f654e8
(kernel export 810 `NullCableRequest`, XAM export 1670 studio service,
then a status report through request 4) runs on the server thread right
after the network starts, which is where stock runs it (last in module
initialization, after XNetStartup/WSAStartup). Control codes 0x99 (device
status) and 0x9f (test mode); the server pass (0x91f65a18) after every
select; session start/stop 0x91f65850/0x91f65950 with the worker thread
0x91f656e8; `xstudio DedicateSocket` (0x91f65b18); the null-cable
transport (0x91f830e0) and the socket transport (0x91f83698). Transport
routines enter through the export bridge so the service's 64-bit
nonvolatile registers survive. Stock alerts the server thread after codes
0x99/0x9f and when the worker ends; here the server pass runs at most
20 ms apart without the alert. Unload clears the initialized flag and stops
the session (start also requires the flag, which stock never clears).

Deviations (Xbox Studio):

- Null-cable transport creation passes the null pointer to ExFreePool when
  the pool allocation fails (the kernel asserts and frees page 0); openxbdm
  returns 0x8007000e without the free.
- Socket transport result (routine 4): stock dereferences any request
  handle; a handle that names no request slot returns 0x80070057.
- Socket transport result with wait: when the connection ends during the
  wait, stock returns 0x80004002 without leaving the transport critical
  section, so a later call from another thread blocks forever; openxbdm
  leaves the section.

Capture engine (`backend/performance/capture.rs`, stock dmcap
0x91f27bb8..0x91f2a03c): per-processor blocks, record buffer and chunk
list from MmAllocatePhysicalMemoryEx (probe by bisection for the default
size), start/stop/reset IPIs (KeIpiGenericCall), the record hooks (exports
65, 66, 70, 71; 70/71 pass the caller's return address), the thread
switch routine at debug monitor data +0x1c, processor counters through
`pmc` (owner 0x63) and the memory controller counters at 0x7fd20100, the
capture file writer (module snapshot of export 131 with the data sizes,
then the chunks), the title terminate part (0x91f28a10), and exports 73,
74, 84, 90, 146, 162 (73 and 74 also published at +0x0c/+0x10 of the
title block). Exports 73 and 74 translate names on the server thread
(the drive table is server state); every kernel callback and title entry
enters through the export bridge.

Deviations (capture):

- Export 73 reads at most 0x140 name bytes; stock copies the title's
  string unbounded into a 0x141-byte stack buffer.
- Counter selectors above 0x13: stock prints `Invalid counter ID %d` and
  traps on every processor inside the start IPI; openxbdm prints and
  records without programming counters.
- Exports 73 and 74 when the server thread cannot serve the drive table
  (raised IRQL, server stopped, or called from the server thread): names
  do not translate (start fails with 0x82da000d unless recording; the
  file write fails with 0xc000000f, 0x80070002) and the snapshot keeps
  the executable's object path.
- Stock writes 0 or 0x91f29138 to the variable at debug monitor data
  +0x38; 0x91f29138 records only when 0x91fae7f0 is set, which nothing
  writes, so openxbdm leaves the variable alone.
- Unload (no stock counterpart): the thread switch routine is restored,
  every block disabled, and the buffers freed.

Module snapshot (`backend/performance/module_snapshot.rs`, export 131
0x91f282b0 and 132 0x91f28528): the 0xc000-byte MmAllocatePhysicalMemoryEx
block (`+0` 0xa, `+4` count, `+8` up to 0x80 records of 0x150 bytes {base,
size, byte-swapped time stamp, narrow name of at most 0x2a characters,
CodeView age, GUID, PDB path of at most 0x103 bytes}, `+0xa808` capture
start time, `+0xa814` debug name, `+0xa914` processor count, `+0xa918`
capture flags before the last stop, `+0xa934` executable drive path,
`+0xaa38` 0x5308, `+0xaa3c` performance frequency), both loaded module
lists under the loader lock; names of 0x2b characters or more print
`PERF: ignore module "%wZ"...` and the slot is reused. The CodeView
lookup is stock 0x91f280d8 without its lock (the caller holds it).

Instruction trace (`backend/performance/xtrace.rs`, stock
0x91f65e50..0x91f671e8; encoder and memory map in the server crate,
`commands/performance/xtrace.rs`, 0x91f671e8..0x91f67e90): control codes
0x38 (`service_start`, also `start_default` for PIX), 0x39
(`service_stop`), 0x3a (`service_instruction_count`), 0x3b
(`service_request_stop`); exports 133 (start), 134 (start at an address,
nested calls optional), 135 (buffer size, minimum 1 MiB, returns the
previous), 136 (stop), 137 (save a file-less session), 177 (session
exists), 195 (writer hardware thread, at most 5). Exports 133 and 136 have
their own bridged entries: the hooks stop at the 136 entry address, and the
internal start and stop paths (codes 0x38/0x39, PIX) call through those
entries, as stock's internal callers branch to the export bodies, so the
skip counts and the stop check see the same call structure. Mechanics as
stock:

- Start: the five spin lock routines run natively (kernel ordinals 0x125,
  0x4d, 0xb1, 0x10f, 0x105; stock reads them from its import thunks) are
  resolved once; the file is created (`FILE_OVERWRITE_IF`) and closed, the
  writer thread created (stack 0x8000, affinity `1 << n << 24`); the
  session memory is size limit + 64 KiB (NtAllocateVirtualMemory
  0x20003000, debug memory option 3, then title memory 1, shrinking the
  limit by a third down to 1 MiB); five buffers of `((limit - 0x78) / 5)
  & ~3` bytes and the encoder cache at the end. The first buffer holds the
  header (`TRAC`, 3, `MODL` 0x3000 words of the module snapshot when it can
  be allocated, `MMAP` count and `{page, pages, protection}` entries) and
  is queued alone. Hooks: title terminate registration (priority
  0x6f000000), debug monitor service 6 trace hook, and the debug routine
  chained in front of the current one. Single-step (MSR 0x400) is set last;
  the first 2 returns or 0x28 instructions are skipped so recording starts
  at the caller's next instruction.
- Trace exceptions: stop at the export 136 entry or on a stop request;
  spoofed routines are run natively with the traced r3 and their body up
  to `blr` is recorded with r4 = r3, r5 = 0x10, r11 = r31 = r3 - 0x10;
  hardware flag 0x02000000 disables spoofing for good (trace hook only).
  No free buffer: the record goes to a scratch area, the IAR is kept, and
  recording ends with the error flag.
- Writer: every 10 ms the queued buffers are appended in sequence order
  (open, seek to end of file, write, close), then the progress line every
  100000 instructions (500000 with the service 6 hook).
- Stop: timing line, remaining buffers, writer wait, mismatch report (30
  kept), memory freed only for a session with a file, hooks removed, the
  buffer-full report, `Spoofed %d functions.` through DbgPrint. Messages
  go through `OutputDebugString` (trap 0x14) as stock.

Deviations (instruction trace and snapshot):

- File names translate on the server thread (the drive table is server
  state). A name that does not translate, or a call when the server
  thread cannot serve (raised IRQL, server stopped, the server thread
  itself), fails the open; stock's open helper returns success with an
  uninitialized handle for an untranslatable name. The snapshot then keeps
  the executable's object path.
- A start after export 137 saved a session that was never stopped: stock
  registers the title terminate notification a second time (corrupting
  the kernel list) and chains its debug routine to itself after the
  assertion trap (recursion on the next exception); openxbdm keeps the
  registration and the previous routine, and still executes the trap.
- The second loaded module list is skipped when its head is null; stock
  reads it unconditionally.
- The lookup cache is cleared at a start one word at a time, and the
  encoder state and stream words are written with single word stores, so
  handlers that race a start, stop, or save (another single-stepped
  thread, a stop from another thread) see whole words; stock clears the
  cache with memset.
- Unload (no stock counterpart): hooks and the registration are removed
  and the writer threads, including those title termination abandons as
  stock does, are stopped and awaited through their handles (up to 16
  live writers are tracked; ended ones are closed when a new writer
  starts).

Gaps (Xbox):

- CPU sampling profiler: implemented (`backend/performance/profiler.rs`,
  engine 0x91f8eeb0..0x91f90bdf, exports 149-151) on the PMC module
  (`backend/performance/pmc.rs`, 0x91f90be0..0x91f92e58, exports
  196-211, event tables in `commands/performance/pmc.rs`). Deviations:
  the writer thread reports a file it cannot open or a failed prologue
  (and a name without an object path) as 0x82da0000, where stock never
  signals its starter and the command hangs; reads of the interrupted code
  and stack that stock guards with an exception handler are checked with
  `MmIsAddressValid` and count as faulted walks; the low words stock
  leaves uninitialized in the interval PRV values (0x1c8, 0x1e0, 0x1e8)
  are 0; the stale register stock prints in `[LOP] Error! %d`,
  `[LOP] Failed to create common header! %d` and
  `PMCSetTriggerProcessor - %d` is 0 or the processor; event decoding of
  unit 5 (stock dereferences string bytes as a pointer) names the invalid
  event; export 210 past counter 15 reports 7 instead of reading past the
  controls; export 198/196 with a setup index past 44 fail instead of
  applying memory past the table; export 211 waits with a wrapping tick
  difference; null function table copies are not passed to
  `MmFreePhysicalMemory`. The random interval generator stock seeds but
  never uses is omitted. Not verified on hardware: kernel exports 669-671
  semantics (routine arguments: trap frame, previous IRQL).
- PIX (`backend/performance/pix.rs` and `pix/`): stream ring 0x91fa2af0
  (`b`/`e` with IPI 0x91f56670 and the `CxSw` swap routine, `r` snapshot,
  codes 0x27/0x41/0x42/0x43/0x58/0x5e, DPC and server pass for
  `CounterDataAvailable`), status filter and texts (0x1b, 0x45 including
  title `pixcmd` lines), callbacks/owner/catma plugin (0x2f, 0x30, 0x59,
  0x5a, 0x3c, `n`/`y`, `h`), frame boundary with the counter and PMC
  samplers (0x2e, 0x52), capture and resource files (0x53, 0x54, 0x55,
  0x83, 0x84, 0x85, 0x87, 0x3f), HDD records (0x7f, 0x80), session creation
  gated by XAM feature 0x22, its lock, queue, status, statistics and state
  flags (0x44, 0x57).
- PIX capture engine (`pix/capture.rs` and `pix/capture/`, stock
  0x91f58f10 to 0x91f62560): title frame boundary part (0x91f622d8,
  0x91f62508) with session message processing (0x91f619d8: codes 1, 3,
  4, 5, 6, 7, 8, 10, 11, 12, 13, 15; while paused 3, 4, 6, 7, 8, 9, 12,
  14), module records (0x91f55db8), per-hardware-thread buffers installed
  by IPI (0x91f5e810, 0x91f5fd98) with the context swap record routine
  (0x91f5f948) and the 100 ms marker timer, temporary blocks for
  raised-level writers (0x91f5ee68, 0x91f5ed80) replaced by the server
  pass (0x91f62228), system and title physical memory buffers
  (0x91f5da20, 0x91f5d828), gather writes of eight buffers per request to
  `PixStream`/`PixDump` (0x91f5e090), frame records (0x91f5e5b8), GPU
  frame and command buffers with fence slots (0x51, 0x5c, 0x5d,
  0x91f5f838, 0x91f5f558, 0x91f5f6a0), audio capture (0x5b), timing
  requests (0x50) and events (0x8d, 0x8e), configuration (0x56), frame
  extraction into PIX capture files (0x91f594c8, 0x91f5ea90), video
  operations replaying frames through the title's frame record routines
  and XAudio, and movie data (0x91f5c0e8, 0x91f5c1d8, 0x91f5b140), title
  end part (0x91f62100) and the thread termination wait (0x91f5df80).
- PIX deviations: capture dwords past the eighth are not stored (stock
  overwrites the ring fields after its 8-entry array); `n`/`y` bit numbers
  of 64 and up are ignored (stock overwrites the owner and callbacks);
  tagged record padding bytes are zero (stock sends stale stack bytes);
  `r` stops at a freed ring (stock reads the freed pool block); engine
  message 0xe (`pixcmd w`) and 9 are discarded (stock executes a trap);
  the catma installer is not called when export 9 is missing (stock calls
  address 0).
- PIX capture engine deviations: internal consistency assertions (`twi
  31, 0, 0x19`) are not executed, including those on title input (frame
  records without a stop routine, message 6/7/8 payload checks, code 0x51
  `+0` nonzero); words stock leaves uninitialized are zero (frame record
  bits above the configuration and the frame index top byte, the
  halfword at frame record `+0x24`, buffer record count high halves,
  thread name padding, the formatted event arguments of a full code 0x8d
  buffer, empty processor slots of module record 0x46, the first previous
  requests of movie data); the server thread is not alerted by a DPC when
  a raised-level writer switches to its temporary block (the server pass
  runs at least every 20 ms); message 5 unloads the plugin image once
  (stock unloads it twice); code 0x5d without a session returns 1 (stock
  dereferences null); a frame range of zero frames prints 0 % in the
  video statistics (stock traps on the division); a code 0x50 type 0/2
  request without text formats an empty name (stock passes null to its
  formatter); a capture break inside a frame extraction ends it (stock
  reads uninitialized unit positions); code 0x5c with a zero size hands out one buffer (stock loops about 2^32 times); code 0x50 at raised level without a session returns 0 (stock dereferences null); GPU requests of more than 0xc8 command buffers use 0xc8 (stock overruns its stack list). The stack walk of the swap record
  accepts only the thread's own stack (openxbdm has no exception stacks).
  The vibration stop of the pause sets both motors to 0 without the
  capability query that only decides whether to swap the two speeds.

## Client

- `screenshot`: the body is decoded as 4 KiB 32x32 tiles in row-major
  order with `ceil((offsetx + width) / 32)` tiles per row, starting at
  (`offsetx`, `offsety`) of the first tile
  (`commands::screenshot::detile_32bpp`; the FFI decoder uses it).
- `pix/session.rs`: handler address and reply forms corrected.

## Nuances

- `querypc` never sees more than one sample: the history index stays 0.
- `querypc` instantaneous replies repeat the previous rate of the
  connection; `pclist` keeps its context in the high half of the same
  scratch value.
- `pixcmd` reads the letter at offset 7 and the `n`/`y` hex digits past
  the end of the line (stale receive-buffer bytes).
- `pixcmd d`, `v`, `o` reply `BUSY` when the post fails; other letters
  reply `NO`.
- `screenshot` with a zero framebuffer size sends `203-` and nothing else.
- `capctrl` replies carry non-2xx statuses for informational results
  (`427- HRESULT 0x82da001b` when fast-cap is absent).
- `capctrl stop` and `abort` call debug monitor service 2 with 0 only
  when call-cap alone is instrumented; `abort` reports stop failures other
  than a full buffer.
- A capture longer than 0x20000000 time base ticks cannot be stopped
  (0x82da0029).
