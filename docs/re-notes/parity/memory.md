# Parity: memory domain (memory, modules, images)

Specs: `commands/group1.md` (addtitlemem, advmem), `group2.md` (detour),
`group3.md` (getmem, getmemex), `group5.md` (memtrack, modsections,
modules), `group6.md` (pdbinfo), `group7.md` (setmem), `group8.md`
(traceimports, walkmem, xbeinfo, xexfield).
Server: `crates/openxbdm-server/src/commands/memory.rs`. Host mock:
`crates/openxbdm-server-host/src/backend/memory.rs`. Xbox backend:
`crates/openxbdm-server-xbox360/src/backend/memory.rs`. Tests:
`crates/openxbdm-server-host/tests/memory.rs`. Client:
`crates/openxbdm-client/src/commands/memory.rs`, `process.rs`.

The Xbox module enumeration reads the loader lists and lock from the debug
monitor data block (`ExDebugMonitorService` 1, copied at startup by
`kernel::register_debug_monitor`, as stock `_start` 0x91f32be8 does).

| Command | Wire | Host mock | Xbox backend |
| --- | --- | --- | --- |
| addtitlemem | matches | title module field 0x40801, console memory statistics | export 403 module, `RtlImageXexHeaderField` |
| advmem | matches | flash bytes, read/write failure injection | `\Device\Flash` read; block read-modify-write (IOCTL 0x3c0028) |
| detour | matches; records, file, and completions host-tested | engine in the server crate; trampolines mapped at 0x91f13230; writer and completion worker run synchronously; `MockBackend::detour_call` simulates title calls | stubs and trampolines in `.text` (`backend/memory/detour.rs`), logger on title threads, writer and completion threads |
| getmem | matches, including the stale-buffer quirk and breakpoint shadows | regions; device ranges fail reads | `MmIsAddressValid`, `MmDbgReadCheck` + device ranges |
| getmemex | matches; breakpoint bytes restored from any table entry; missing texts `missing ADDR` and `missing LENGTH` | regions | `MmDbgReadCheck` per page, direct copy |
| memtrack | matches | flags in effect, records | statics shared with debug monitor codes 8/9; pool records |
| modsections | matches | modules with section tables | loader lists, `RtlImageNtHeader`, section headers |
| modules | matches | modules, loader flag and NT header | loader lists, `RtlImageNtHeader`, `RtlImageDirectoryEntryToData(3)` |
| pdbinfo | matches | CodeView records | debug directory, first-entry quirk |
| setmem | matches, writes under breakpoints update the saved instruction | regions | `MmDbgWriteCheck`, `KeSweepIcacheRange` |
| traceimports | matches, including both DbgPrint lines | accepted names, request log | kernel export 719 |
| walkmem | matches | regions incl. a device-range overlap | `MmIsAddressValid` page walk |
| xbeinfo | matches; `ondiskonly` opens the file and leaves it open | executable object path | export 431 string, drive-table reverse mapping |
| xexfield | matches | inline and data fields | `RtlImageXexHeaderField` |

Debug monitor control codes owned here (Xbox, `backend/memory.rs`): 0x08
`service_memtrack_record_alloc`, 0x09 `service_memtrack_record_free`, 0x18
`service_get_module_proc_address`, 0x86 `service_adjust_memory_statistics`.

Settings file: `memory::memtrack_settings_lines` writes
`memtrack flags=0x%x stackdepth=0x%x`; `memory::ini_memtrack` restores it.

## Deviations

- `modules`, `modsections` and `xexfield` do not snapshot the loader list at
  the start of the reply. Each line re-walks the list under the loader lock,
  so a module loaded or unloaded during a reply can shift the remaining
  lines; `xexfield` fails the transfer (connection closed) when the module
  disappears mid-reply, where stock prints its copy.
- `traceimports`: when kernel export 719 is absent stock branches to
  address 0 on the server thread and crashes; this implementation reports
  `400- ` and prints the "not a valid choice" line.
- Allocation tracking diagnostics format `%p` as eight upper-case hex digits
  (the kernel formatter's form); not compared against a capture.
- `detour`: `Id` equal to 0x2e8 is rejected (stock reads past the table);
  an absent `file` is an empty name (stock copies an uninitialized buffer);
  the record pool starts zeroed (stock: uninitialized pool) and its
  storage (0x1c00 bytes, tag `Detr`, pool type 2) is allocated at the first
  `start` and kept after `stop` (stock allocates it at each start and frees
  it at stop; allocation failure returns the engine to state 0 in both);
  the completion worker exits when its poll wait sees the stop signal
  (stock hangs `stop`);
  an unlogged completion after a logged one in the same worker pass writes
  no record (stock requeues the previous record); the module unload walk is
  bounded by the entry count. The log name is translated when `start` and
  `stop` run on the server thread; stock translates it in the writer
  thread at start.
- Export 78 keeps up to 0x100 registered type names; stock stores them
  through an unallocated table and faults.
- Exports 10, 16, 40, and 212 run their server part through the
  dispatcher's server requests (breakpoint and drive tables, console
  memory); on the server thread or above passive level they return
  0x80004005.

## Detour engine

Shared engine (`crates/openxbdm-server/src/commands/memory/detour.rs`):
entry table with stock's list operations, record pool with lock-free
free/filled queues, the logger notifications 0-3, and the completion
slots. The console backend owns the stubs (copied from stock, entering the
Rust logger through a shim that keeps the full 64-bit r14-r31 and f1-f13),
the trampoline area (`li r12, id; b stub` written at module init through a
debugger mapping), and the writer/completion threads. The host mock writes
each queued record to the simulated log file at once and runs a
completion pass whenever one is queued; `MockBackend::detour_call` and
`service_detour_completions` drive title calls in tests. Module unload
(debugger event) releases entries in the unloaded range.

## Exports

Implemented in `crates/openxbdm-server-xbox360/src/backend/memory/exports.rs`:
10 get memory, 12 get proc address, 16 get xbe info, 40 set memory, 51 and
142 walk loaded modules, 52 walk module sections, 75 memory statistics
(wrapper over `performance::memory_statistics`), 77 type name, 78 register
type name, 79 track allocation, 80 untrack allocation, 123 walk committed
memory, 143 XEX header field, 145 module debug directory, 165 memory usage,
212 title workspace size.

## Client fixes

- `SetMem` accepts `404- set N bytes` (stopped at an unmapped or unwritable
  page) and returns the written count; empty data is sent (stock replies
  `200- set 0 bytes`).
- `GetMem` accepts length 0 and lengths above 0x10000; stock has no
  limit.
- `SectionFlags::LOADED` removed: stock never reports flag 0x1.
- `XbeInfo` documentation states that named queries return the running
  executable.
