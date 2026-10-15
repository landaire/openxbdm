# Debugger domain parity

Stock XBDM 2.0.21256.0. Server: `crates/openxbdm-server/src/commands/debugger.rs` and `debugger/` (`breakpoints.rs`, `context.rs`, `events.rs`, `kd.rs`). Host simulation: `crates/openxbdm-server-host/src/backend/debugger.rs`. Console: `crates/openxbdm-server-xbox360/src/backend/debugger.rs` and `dispatcher.rs`. Tests: `crates/openxbdm-server-host/tests/debugger.rs`.

## Commands

| Command | Stock handler | Host test | Notes |
| --- | --- | --- | --- |
| break | 0x91f48a38 | yes | `now` continues with the other flags after the trap. Data kinds: read 5, write 1, readwrite 2; execute fails `400- bad parameter`. Re-setting the identical data breakpoint writes 0 to the register (stock passes 0). |
| continue | 0x91f47f38 | yes | `exception` passes a generic exception on (not handled); see events. |
| crashdump | 0x91f498b0 | yes | Replies on the socket, then dumps. |
| dbgextld | 0x91f4f600 | yes | One extension slot, reference counted. |
| debugger | 0x91f49620 | yes | `connect` clears and `disconnect` sets the kd routing flag (0x91f975fc). |
| getcontext | 0x91f482b0 | yes | Lines come from a copy made when the command runs (0xa50-byte pool block). |
| getpid | 0x91f49908 | framework | |
| go | 0x91f44548 | yes | |
| halt | 0x91f47ef8 | yes | Always `400- `. |
| isbreak | 0x91f48c28 | yes | |
| isdebugger | 0x91f49480 | yes | |
| isstopped | 0x91f48d90 | yes | |
| kd | 0x91f435f8 | yes | |
| kdlite | 0x91f43db0 | yes | |
| kdnet | 0x91f43858 | yes | enable/disable/show/set, flash load and save failures. |
| nostopon / stopon | 0x91f44530 / 0x91f44518 | yes | |
| resume / suspend | 0x91f47ff8 / 0x91f47fa8 | yes | |
| setcontext | 0x91f48430 | yes | |
| stop | 0x91f445a8 | yes | |
| threadinfo | 0x91f48f28 | yes | |
| threads | 0x91f47d88 | yes | process objects read from debug monitor data +0x50 (system) and +0x54 (title); verified on hardware |
| threadstat | 0x91f47e50 | yes | |

## Debug events

The kernel calls the debug routine (`KiDebugRoutine`, located through debug monitor data +0x00) from `KiDispatchException2` on the faulting thread: `r3` trap frame, `r4` exception record, `r5` context (flags 0x17), `r6` 0 first chance / 1 second chance; nonzero return means handled and the context is restored. Thread creation and termination arrive through `ExRegisterThreadNotification` (routine at registration +0, called as `(registration, thread, create)` on the thread concerned). Stock processes both on the calling thread (0x91f3a980 -> 0x91f39fc0, 0x91f32530 -> 0x91f39b30).

The reimplementation splits this. Thread creation and termination are posted without waiting, as stock queues them, except a creation that may stop (`stopon createthread`, or a title entry thread). Every other event is posted to a slot while the calling thread waits on a synchronization event, but only while the server thread runs its pass loop; before the first pass and after the loop ends, the thread takes the in-place dispatch of a thread that cannot wait (below) or the event's default disposition, and a waiting thread is released at its next 100 ms check. While posted, the server thread takes it (`Backend::next_event`), runs the port of 0x91f39fc0 (`events.rs`), and completes it with a disposition (handled, write dump, chain to the previous routine, break after a thread start). A stopping event stays pending until `continue`, a state change that releases stopped threads (go from pending_title, request reboot_title, `kd except`, break-in), and what stock does after its wait (step over a breakpoint, assertion "ignore" answer, step past a trap) runs then.

Implemented dispatch, as in 0x91f39fc0: first-chance trap rewrite (0x91f39ef0); breakpoint (always stops; table breakpoints are lifted for a trace step and re-armed on the step exception; an embedded trap is stepped past); debug strings (stop on `debugstr`, string read from r3/r4); module load (stop on `modload`, description from the loader entry and image header, `modload` line format of 0x91f39080); module unload (breakpoints in the range removed); assertion prompts (`assert ... stop stop`, r3 set to 0x49 and Iar advanced when unchanged); rip; ntassert (0xc0000420, only when it can stop); single step and the data breakpoint (data kinds 1 and 2 print `write`/`read`; kind 5 prints nothing because the formatter knows only 1..3); generic exceptions (stop when second chance or `fce`; `first`/`noncont` flags; access violation `read=`/`write=`; thread-name exception 0x406d1388 names the thread); unhandled end (`kd lite` chain or Iar += 4 and r3 = 0); crash dump on unhandled second-chance exceptions unless dump mode is disabled; auto-go when nobody receives a stop notification in dump mode `enabled`; a stop requested while execution is stopped or pending waits until the state changes; data breakpoint register reprogrammed after each event. Control code 0xa4 enables the first-chance breakpoint/trace pass-through.

## Control dispatcher

`docs/re-notes/dispatcher.md` documents every code. `backend/dispatcher.rs` publishes the dispatcher at data block +0x18 and `KeDebugMonitorData` (ordinal 89), passes every result through the extension `OnTellDebugger` hook, implements the debugger codes (0x01 break-in poll, 0x19, 0x34, 0x35, 0x63, 0xa4) and routes other domains' codes to their `service_*` functions. Requests that need server state (settings write, break-in, kd lite refresh) are queued and applied by the server thread (`dispatcher::drain`).

## Events that cannot wait (stock deferred queue 0x91f39768)

Exceptions above passive level and on the server thread are dispatched in place by `dispatch_direct` (`debugger/direct.rs`) with the `DirectPolicy` the server publishes after every pass (`publish_direct_policy`). Up to dispatch level a notification is queued only when a debugger is attached and `eventdefer` selects its kind (break 1, debugstring 2, singlestep 4, assert 8, ntassert 0x10, databreak 0x20, rip 0x40); a queued assert or rip resolves as a continue (r3 = 0x49, Iar + 4), a queued data breakpoint steps over the register. On the server thread every line is sent. The platform captures text and module descriptions into pool nodes (tag `Ddfn`, pool type 2) and the server delivers them (`next_direct_notification`). Module unloads remove breakpoints in range even when no line is sent.

## `break now`

The command thread executes the real trap. The debug routine keeps the record and context (getcontext/isstopped/setcontext see them), lets the thread run past the trap, and the server processes the trap as a stopped event of the command thread; the reply is held until the thread is continued (`HeldReply`, dropped if the connection closes). Stock blocks its only command thread at the trap, so nothing can continue it short of a kernel debugger break-in; serving other connections meanwhile is the deliberate deviation. `setcontext` on that thread has no effect on execution. A bare `break now` replies `200- OK`.

## Execution requests from other threads

`request_execution(target, notify)` (stock 0x91f2da88 with the wait flag clear), `stop_at_pending_title(forever)` (`execution pending_title stop`; after the 15 s timeout the wait ends unreleased and the launching thread prints its trace and starts execution itself, as stock 0x91f523a0), and `report_pogo_module_start(name, module)` (stopon pogomodstart) post `DebugEvent::ExecutionRequest`, `PendingTitleStop`, and `PogoModuleStart` through the event slots. `threads_block_relaunch` ports 0x91f276d8 over the stopped-event table.

## Stack overflow

`install` stores the naked entry `stack_overflow_entry` (stock 0x91f23330, installed by 0x91f3bc38 right after the debug routine hook) through `KiStackOverflowNotification` (data block +0x58). The kernel calls it with interrupts off and `r3` = trap frame just before `KeBugCheckEx(0x2b, ...)`; the entry stores r13..r31 into the frame register area (GPR n at +0x50 + 8n, so r13 at +0xb8) and runs `stack_overflow` (stock 0x91f3aab0) behind the export bridge. That routine exchanges the notification pointer with 0 (one shot); returns at once when it was already 0 or the kernel debugger is enabled and attached (hardware flag 0x100); can stop when the thread's monitor record is debuggable, IRQL is passive, the trap frame Msr low word (+0x1b4) is nonzero and not (dump mode enabled without an attached debugger). Otherwise it returns unless the dump mode allows a dump. It builds the context with `KeContextFromKframes(frame, context)` (flags 0x17) and a 0x50-byte record (code 0xc00000fd, flags 1, address = frame +0x1ac). A thread that can stop sets the interrupt enable bit and posts `KIND_STACK_OVERFLOW` (`DebugEvent::StackOverflow`, `can_stop` true) until the disposition is no longer `handled`; `getcontext`/`setcontext` use the built context while it waits. The dump (data block +0x0c bit 0x40, `DumpWriteDump(record, context, 0)`) follows when the last disposition asks for it, or directly when the thread cannot stop. The routine returns the faulting address.

## Software breakpoint table

`breakpoints.rs` keeps stock's block chain (head 0x91fae980, spare 0x91fae97c). A block holds a count, 0x80 sorted addresses, the saved instruction words, flag bytes (bit 0 trap written; arming also skips bit 1, which has no writer) and the next link (stock 0x488 bytes, pool tag `Xbdm`, type 2). The lookup (0x91f25480) picks the block whose first address is at or below the address and whose successor's first address is above it, else the last block, then binary-searches it; a miss in a full block splits it with the spare (upper half moves) and continues in the half that covers the address. Set (0x91f26fc8) rejects unaligned addresses, allocates a spare when none is held, inserts with the saved word at the new index left as it was, and reports success even when the trap cannot be written. Remove (0x91f27178), clear all (0x91f27290: counts set to 0, blocks kept), module unload (0x91f26e90) and the getmemex restore (0x91f256d0) follow stock, including the whole-walk stop at a block whose first address is at or past the range end. Stale first addresses of emptied blocks keep steering the lookup, and an entry set below the head's first address goes to the last block, which can leave entries of earlier blocks unreachable. A step over a breakpoint records the block and index (0x91f27550) and re-arms whatever entry is there afterwards (0x91f27630).

## Exports

`crates/openxbdm-server-xbox360/src/backend/debugger/exports.rs` implements the debugger domain's exports with the same code as the commands: 8 (`continue`), 13/41 (`getcontext`/`setcontext` context reads and writes, by kernel context layout in caller memory), 15 (`threads` list; stops visiting at capacity, 0x82da0105), 19 (`go`), 21/373 (`debugger` flag, address word, port, from mirrors the server publishes each pass), 22 (`isstopped` stop record, `StopReason::encode`), 34/37 (`break addr=` clear/set), 35/48 (`resume`/`suspend`), 38 (data breakpoint by type 0/1/2/5), 39 (`break start`), 45 (`stop`), 46 (`stopon`/`nostopon` mask), 49 (record debug data word of the calling thread), 56 (`isbreak`), 82 (stack back trace from the caller's frame, `RtlGetStackLimits` krnl 0x12a, stock IAT 0x91f006b0), 83 (dump of the calling thread), 89 (size-versioned `threadinfo` record), 178/179 (`dbgextld` load and release), 180 (`ExCreateThread` with flags 0x4000026, suspended for caller flag 4). Exports needing server state go through `dispatcher::call_on_server` and return E_UNEXPECTED where it cannot run (server thread, above passive level); export 46 queues its change instead.

## `getcontext`

The handler reads the context once (export 13 semantics) into a 0xa50-byte pool block (`400- out of memory` when the allocation fails, as stock 0x91f482b0) and the lines come from that copy; the block is freed by the last continuation call, or at the next event pass when the connection closed first.

## Remaining gaps (precise)

- Event latency: posted events are seen at the server's next loop pass (select timeout 20 ms); stock processes them on the faulting thread at once.
- Stack overflow: stock marks the thread's monitor record (+0x10 bit 0x40) and 0x91f39fc0 sends any later exception of that thread straight to its unresolved path (dump, kd chain or Iar+4); here later exceptions are dispatched normally (a nested exception while the thread waits in its slot goes to the previous kernel debug routine). The kd, dump-mode and attached checks made before posting read the policy the server last published; the server repeats them on its own state. The notification is installed only when data block +0x58 is nonzero (stock stores through it unconditionally).
- Direct exceptions: a breakpoint trap (other than `break now`) above passive level or on the server thread goes to the previous kernel debug routine (stock stops, which crashes or hangs such a thread). A queued single step does not step over a table breakpoint at the next Iar (the table lives in server state).
- The isstopped type 0xd (data breakpoint stop) kind is read by stock from an uninitialized stack word; this reports `stopped`.
- The first breakpoint block is static and later blocks come from pool memory (stock takes every block from the pool), at most `BREAKPOINT_BLOCKS` (8) in all, so a set needing a split fails after the eighth block (0x240 ascending entries) or when pool allocation fails; stock fails only when pool allocation fails. Blocks are zeroed when obtained, so a split block's unused slots are zero rather than uninitialized pool memory.
- Record flag 0x100 (tested by 0x91f276d8 for trap 0x16 stops) has no known writer and is not modeled.
- Stopped-thread release by a state change applies only to debuggable threads, as stock's 0x91f2da88 does; a non-debuggable launcher thread in `stop_at_pending_title` therefore waits for its timeout.

## Nuances

- `assert` notifications that stop end in ` stop stop` (the assert formatter appends the suffix and falls into the common suffix code).
- `halt` always fails with `400- ` on dev kits.
- `debugger` settings line prints the address low byte first; a peer address taken from the connection is therefore written reversed.
- Re-setting an identical data breakpoint clears the hardware register until the next debug exception.
- isstopped of an ntassert stop reports `exception code=0xc0000420`, because the builder tests code 0x15.
- `continue exception` has no effect on breakpoints, single steps, asserts and rips; it only marks generic first-chance exceptions unhandled.
