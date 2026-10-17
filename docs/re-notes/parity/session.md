# Session domain parity

Stock XBDM 2.0.21256.0. Server: `crates/openxbdm-server/src/commands/session.rs` and `session/{capture,discovery,error,fastpipe,fileevent,notification,rpc,telllog}.rs`; notification tables in `crates/openxbdm-server/src/notify.rs` and `notify/`. Host mock: `crates/openxbdm-server-host/src/backend/session.rs`. Xbox: `crates/openxbdm-server-xbox360/src/backend/session.rs`. Tests: `crates/openxbdm-server-host/tests/session.rs`.

## Commands

| Command | Handler | Status |
| --- | --- | --- |
| bye | 0x91f43450 | done |
| dbgprint | 0x91f3eee8, continuation 0x91f3ee18, reader 0x91f3ed28, producer 0x91f3ebb0 | done; no producer texts (see gaps) |
| dedicate | 0x91f51838, routine 0x91f51640 | done |
| dmtelllog | 0x91f4e870, start 0x91f51b30, stop 0x91f51c60, writer 0x91f51938, producer 0x91f51d58; log engine exports 355..364 | done |
| fastpipe | 0x91f44038, 0x91f540c0, slots 0x91f53f70, data plane 0x91f52720..0x91f54134 | done; stock defects not reproduced |
| fileevent | 0x91f4e7f8, exports 152 (0x91f2f428) and 153 (0x91f2f4c0) | done |
| notify | 0x91f44268, registration 0x91f3cfe0 | done |
| notifyat | 0x91f441e8, worker 0x91f3c308, address parser 0x91f41b80 | done |
| notifyport | 0x91f44268 (same handler as `notify`) | done |
| rpc | 0x91f3e7c8, upload 0x91f3e540, call 0x91f3e630, stream 0x91f3e460 | done |
| spew | 0x91f50328 | done |
| srvproc | 0x91f4be00, affinity 0x91f78a68 | done |

## Notification channels and targets

- Registration 0x91f3cfe0 `(socket, port, addr, flags)`: port 0 attaches the socket alone; otherwise 0x91f3c0d8. On success the socket receives `205- now a notification channel` and `execution <state>` (0x91f391e0 type 3, state from 0x91f2d930(0) = 0x91fae664, names at 0x91f97608).
- Add target 0x91f3c0d8 `(addr, port, flags, reverse, socket)`: binds to an existing entry with the same address and port and no socket only when port != 0 and a socket is given. A new entry that is neither reverse nor given a socket connects blocking (0x91f3bed8) and sends the execution line. Failure clears the entry, closes the created socket and drops (addr, port). Debugger globals (0x91f9fef8, read by control code 0x0a) are set only on success.
- Add socket 0x91f3be18: when all 16 slots are full, a `null` line (type 0) goes to every channel through 0x91f39688, failing channels are pruned, and the allocation is retried once. With 16 live channels the 17th request fails with `400- notification limit exceeded` after the `null` lines.
- Per-socket send 0x91f389e0: FIONREAD drain (0x91f388a8), select writable for 60 s, send the line. Failure closes the socket and frees targets bound to its slot.
- Drop 0x91f38b60: matches entries by (addr, port), including freed entries that keep stale port and slot fields.
- Settings line 0x91f38ac8: `notifyat addr=%d.%d.%d.%d port=%d%s` with address bytes 3, 2, 1, 0 and suffix ` reverse` for flag 0x40000. The parser 0x91f41b80 also stores octets reversed, so a saved line restores the same target. From the settings file 0x91f311b8 calls 0x91f3c308(-1, line, 1): the target is stored as reverse and not connected.
- Persistent targets 0x91f3c440 (called from dminit 0x91f32628): non-reverse targets get a non-blocking connect; within a 30 s total wait a writable socket is set blocking, sent `hello` and registered. Timeout or `hello` failure drops the target. Reverse targets wait for `notify reconnectport=` within the same window and are dropped afterwards. The settings file is rewritten. openxbdm: `connect_persistent_targets` and `expire_reverse_targets`.

## Name discovery responder 0x91f42948

- UDP port 730.
- Request type 3 (identify): always answered.
- Request type 1 (lookup): byte 1 is the name length, followed by the name. Answered only when the name equals the debug name, compared case-insensitively.
- Reply: `02 len name` with the console's own spelling of the name.
- Request bit 0x80: the reply goes to the broadcast address instead of the sender.
- openxbdm: `answer_discovery`/`discovery_reply`; host `SharedHost::serve_discovery`. The client accepts a reply whose name matches ignoring ASCII case.

## Monitor control codes

Codes served through the private API dispatcher (kernel data ordinal 89, see `docs/re-notes/dispatcher.md`). Xbox: `backend/dispatcher.rs` routes them to `backend/session.rs`.

| Code | Stock | openxbdm |
| --- | --- | --- |
| 0x64 | 0x91f2f5c8 file event begin | `service_file_event_begin`: id assignment, title exclusion, `XBDMFE!Begin` text with path suffix; result 0 |
| 0x65 | 0x91f2f930 file event end | `service_file_event_end`: `XBDMFE!End` text; result 0 |
| 0x81 | 0x91f2b798 critical section wait begin | `service_cs_trace_wait_begin`: per-processor wait statistics, `E:` log line when area bit 2 is set |
| 0x82 | 0x91f2b828 critical section wait end | `service_cs_trace_wait_end`: same with `L:` |
| 0x88 | 0x91f51d58 log record | `service_tell_log_record`: queue `{u16 Length, u16, u32 Buffer}` to the open log |
| 0x89 | 0x91f51da8 log entry size | `service_tell_log_entry_size`: entry size when open, else 0 |
| 0x8a | 0x91f51dd0 log area mask | `service_tell_log_area`: mask when open, else 0 |
| 0xa8 | export 372 0x91f3ea50 rpc drain | `service_rpc_drain`: run queued calls for the thread name, newest first; result 0 |
| 0xa9 | export 36 0x91f3b070 send notification | `service_send_notification`: requires `!` before any byte <= 0x20; posted only at passive level; result 0 |

The critical section trace line format is `%c:%c 0x%016I64x 0x%08x 0x%08x 0x%08x 0x%08x %02d | 0x%08x 0x%08x %02d 0x%08x 0x%08x 0x%08x\r\n` (letter, `T`/`S` process type, time base, section, thread id, section +0x10 and +0x14 low halves, processor, owner, owner thread id, owner processor or -1, three return addresses). The line writer 0x91f2b530 caps the size at 0x400 and cuts a long line to size-2 characters plus LF.

## Posted notification queue

- `notify::PostedTexts`: 16 slots of 0x200 bytes, FIFO; texts longer than 0x200 bytes are cut.
- Producers: control codes 0x64, 0x65 and 0xa9 and exports 152..160 on the Xbox (`backend::session::post_notification`); `MockBackend::post_notification` on the host.
- Consumer: the server thread drains the queue on every pass of its select loop (at most 20 ms per pass) and before `fileevent` sends Start/Stop. Host: the timer thread, every 50 ms.
- Full queue: a passive-level thread other than the server thread sleeps 10 ms and retries; the server thread or a caller above passive level loses the text.
- Ordering: stock sends in the producing thread before the file operation proceeds. openxbdm sends later on the server thread, so a notification can follow command replies and other channel traffic produced in the meantime.

## Xbox imports added

| Name | Ordinal | Stock IAT slot |
| --- | --- | --- |
| RtlTryEnterCriticalSection | 321 | 0x91f006d0 |
| FscGetCacheElementCount | 32 | 0x91f00748 |
| FscSetCacheElementCount | 33 | 0x91f00744 |
| ExRegisterTitleTerminateNotification | 21 | 0x91f0067c |
| XexExecutableModuleHandle (data) | 403 | 0x91f006a0 |
| CreateFileA (xam) | 1095 | 0x91f00534 |
| _vsnprintf | 333 | 0x91f00800 |

Reused from other domains: KeResumeThread, RtlImageXexHeaderField, NtQueryInformationFile, NtFlushBuffersFile, ExCreateThread, KeWaitForSingleObject, KeWaitForMultipleObjects, KeSetEvent, NtWriteFile, ExAllocatePoolWithTag, ExAllocatePoolTypeWithTag, ExFreePool, ObDereferenceObject, ObReferenceObjectByHandle, KeSetAffinityThread, RtlInitializeCriticalSection, RtlEnterCriticalSection, RtlLeaveCriticalSection, KeEnterCriticalRegion, KeLeaveCriticalRegion, KfAcquireSpinLock, KfReleaseSpinLock, XexGetModuleHandle, XexGetProcedureAddress, KeGetCurrentProcessType, NtWaitForSingleObjectEx, NtClose, ExTerminateThread, KeDelayExecutionThread.

## Notification sessions (exports 6, 24, 25, 32, 36, 76, 370..372)

- Xbox: `backend/session/notifications.rs`; swap routine chain in `backend/session/swap.rs`.
- Session block 0xba4 bytes (tag `xnot`, pool tag 0x736e6d64): +4 next, +8 flags (0x10000 title), +0xc handler lists (0x20 per kind 1..=0x16), +0xb08+4*kind counts, +0xb64 16 processors (0x44-byte blocks, pool tag 0x68636d64, name <= 0x3f chars, handler +0x40).
- List lock 0x91fadc08 (IRQL byte 2 set by 0x91f3bc38): reader-writer spin lock word (0x91f23230 shared, 0x91f232bc exclusive, 0x91f23278/0x91f23304 release; wrappers 0x91f54e88/0x91f54f10 raise IRQL). Shared: delivery 0x91f395c0 and export 36; exclusive: exports 6, 24, 25, 32 and 0x91f3c9b0. A waiting writer keeps new readers out; an exclusive release clears the whole word.
- Export 25 `(flags, out)`: RtlAssert (dmnotify.c line 0xbf9) above passive level; the block pointer, or NULL before 0x8007000e, is stored through `out`. Exports 24 and 32 assert with lines 0xc5c and 0xce4.
- Export 6 `(session)`: readable check 0x91f26958 (MmDbgReadCheck outside the device ranges) and tag; frees every list entry equal to the session; 0x02da0000 also for a block that is not linked. Kernel hooks are not refreshed.
- Export 24 `(session, kind, handler)`: a duplicate handler or a full list (0x20) is ignored with 0x02da0000; a new kind-3 handler is called under the lock with `(3, 0x91fae664)` (0x91f2d930(0)).
- Hook refresh 0x91f3c8c8: kind 0xa writes 0x91f3b1c0 (or 0) through debug monitor data +0x10 when that word is nonzero; kind 0xf registers 0x91f3b1d0 with flag 1 in the swap chain (or removes it), tracked by 0x91f9fd98. 0x91f3b1d0 passes the thread ids (+0x14c) of the outgoing (r3) and incoming (r5) thread.
- Export 32 `(session, name, handler)`: removal compares through 0x91f411f0(processor name, name, strlen(name)), i.e. whole names ignoring case.
- Export 36 never calls processors: 0x91f411f0 is called with the text first and the kind length, and the text continues with `!`. A byte >= 0x80 before the `!` makes the text invalid (signed char). Returns 0x80070057 / 0x02da0000. openxbdm does not walk the processors.
- Delivery 0x91f395c0 (from 0x91f39ad0, before the channel line): handlers newest first at IRQL <= 2; kind exactly 5 (not 0x80000005) passes data + 4. The records follow formatter 0x91f391e0: kind 5 is the length 0x12c, then the module record of module formatter 0x91f39080 (name 0x104, base, size, timestamp, checksum, flags, pdata, pdata size, thread, image size); kind 6 (0x91f3a420) fills only name, base and size.
- Swap chain (8 routines 0x91fab78c, flags 0x91fab7ac, spin lock 0x91fab780): the dispatcher calls each routine with `(old thread, dispatcher frame, new thread)`; the frame's back chain is the kernel's frame. Title cleanup 0x91f64128 removes routines with flag 0 and reinstalls the dispatcher while routines remain, saving the dispatcher itself as the replaced routine when it is already installed.
- Exports 76 (stores 0x91fadd20, never read), 370 (loads 0x91fa3afc), 371 (exchanges it), 372 (control code 0xa8).
- Title termination (0x91f3c9b0, from 0x91f32398) unlinks title sessions without freeing them and refreshes the hooks of kinds 2..=0x17.
- Deviations: export 24 with kind 0 and a handler loops forever in stock with the lock held at IRQL 2; openxbdm removes the handler from the kind-1 list once and returns. The kind-6 record fields that stock leaves uninitialized are zero. Session handlers run on the server thread when the debugger delivers the event, not on the thread that raised it.

## File event exports (152..160)

- Xbox: `backend/session/file_events.rs` (with control codes 0x64/0x65); texts in `commands/session/fileevent.rs`. State: `FILE_EVENTS` (sequence 0x91f9735c, suppressed title 0x91f9f62c/0x91f9f630) under a spin lock in place of critical section 0x91fae520, enable flag 0x91f9f628 as an atomic read without the lock.
- `fileevent` and exports 152/153 share `file_events::switch` (Xbox) and `format_file_event_switch`; the command sends its text directly on the server thread, the exports through export 36.
- Sequence: stock's skip of 0 never fires (64-bit `addic.` compare), so the sequence wraps from 0xffffffff to 0; openxbdm (`FileEventId::next`) does the same.
- Stock sends Start/Stop while holding the critical section; openxbdm sends after releasing the spin lock (export 36 cannot run at the raised IRQL). Start/Stop from concurrent exports can reach the channels in the opposite order of their sequence numbers.
- Export 155 with a path after a fixed text of 0x1ff or more characters (long `Library=`): stock's strlen runs past its unterminated buffer or its path `_snprintf` writes past the buffer; openxbdm sends the fixed text without the path.

## Log engine (exports 355..364)

- Xbox: `backend/session/log_engine.rs` (create 0x91f79470, worker 0x91f78d48, destroy 0x91f79320, pending-queue wait routine 0x91f82f80, file summary 0x91f78c78). Object layout, queues and the worker follow stock; the queues are the lock-free queues of exports 302..309 (`lockfree::queue`), the object and queue cells come from export 300 or the caller allocator of the options.
- Create arguments: 355 `(processor, name, size, entries, block, out)`, 356 `(processor, context, callback, size, entries, block, out)`, 357 `(processor, name, size, entries, block, options, out)`, 358 `(processor, context, callback, size, entries, block, options, out)`. `options` is a 0x34-byte lock-free queue descriptor: it seeds both queue descriptors (flags, waits, allocator) and its allocator (+0x28/+0x2c/+0x30) also allocates the object and the queue cells. A name is used only without a callback; null selects `game:\logfile.txt` (0x91f0af7c via 0x91f99628).
- `dmtelllog` runs on the engine: start creates it as export 356 does (processor 5, writer callback `tell_log_write`), stop queues the closing record through export 363, reads the counters as export 364 and closes the engine. Control code 0x88 writes through export 363.
- 361 formats with no worker-thread check; 362 and 363 ignore calls from the worker thread. Stock formats with the kernel `vsprintf`; openxbdm calls the kernel `_vsnprintf` with the entry size.
- Deviations (stock corrupts memory, reads past its data or hangs):
  - An overflowing `entry_size * entries + 0x160` is refused with 0x8007000e; stock allocates the wrapped size and queues entries beyond it.
  - The file name copy ends at its 0x104-byte field (0x103 characters); stock's strcpy runs over the following fields.
  - 361/362 text that does not fit the entry is cut to entry size - 1 characters plus NUL; stock's `vsprintf` writes past the entry.
  - File-name mode writes an entry's text up to its first NUL within the entry; stock's strlen continues into the following entries.
  - A caller allocator returning null for a queue cell fails the create with 0x8007000e; stock stores through the null pointer.
  - `dmtelllog stop` waits for the worker thread instead of the done event, which a worker ended by a writer failure never signals (stock hangs); export 360 keeps stock's wait. This avoids the hang only for a log started without `block`: with `block`, producers drain the free queue after the worker ended and the stop's closing record waits for a free entry without limit, as in stock. The stop also waits for producers already inside export 363, which stock can leave using the freed engine.
  - The dmtelllog writer cuts an entry larger than its 0x2000-byte buffer to the free room; stock's memcpy runs past the buffer.

## Command processors (exports 30, 72)

- Xbox: `backend/session/processors.rs`. Registry 0x91f9ff98 (16 entries) under a critical section as 0x91facee0; `ProcessorBackend::find_processor`/`processor`/`remove_title_processors` give the server its view. Export 72 `(name, handler, dedicated)` and export 30 `(name, handler)` = 72 with 0; control codes 0x1c (`PIX`) and 0x32 (`{name, handler}`) go through export 30. Results 0x80070057 (NULL name, name of 64+ characters), 0x8007000e (table full), 0x02da0000.
- Calls use the stock ABI with a per-connection context `{continuation, count, buffer, size, scratch, remaining}` (stock connection +0x228) and a 0x58-byte scratch area; handler text 0x1fb bytes, continuation text and default data buffer 0x100 bytes. The transfer pump follows 0x91f423f8: the default buffer is supplied before and withdrawn after each call; 202 sends a NUL-terminated line from the data buffer (or `count` raw bytes), 203 `count` bytes; 204 receives at most the buffer size per call (`processor_receive_limit`, including stock's cut of a buffered piece to the buffer size past the remaining count), the continuation decrements `remaining`, and the final result selects 202, 203, 209 or a reset.
- A processor answering 205 takes the connection (0x91f51640 with its index). 202/203/204 without a continuation become `400-` with the text of the original result.
- Threads: system processors on a main-owned connection run on the server thread, as stock. Title-owned connections (stock flag 0x40000000) run their calls on one title command thread (flags 0x040002a5, stack 0x8000); connections dedicated to a flag-0x2 processor on a thread of their own (0x040002a5, plus 0x2 for a system processor). Title termination removes title processors, forgets the title threads and closes title-owned connections, including those dedicated to a title processor with its own thread.
- Differences in thread structure: the server thread does the socket I/O of every connection; the other threads run only the handler and continuation calls. A call that has not ended after 20 ms continues in the background; the server keeps servicing other connections and requests (so handlers can use exports that need the server thread) and finishes the connection's step when the call ends. Handlers of system processors run on the server thread as in stock; exports that need the server thread are unavailable to them.
- The title command thread exits after 30 s without a title-owned connection; a dedicated thread exits when its connection closes or changes owner. A call still running for a connection that closed keeps its slot until it ends; a new connection in that slot gets `422- dedicated connection required` for processor commands meanwhile.

## Remaining gaps

- Posted notification texts: texts up to 0x200 bytes are queued; longer texts, or texts finding the queue full, are sent by the server thread while the poster waits (`dispatcher::call_on_server`). The server thread and the log worker lose a text that does not fit. Queued texts are sent after the producing operation; ordering against debug events and server requests of the same thread is kept by draining the queue first.
- dbgprint: the reader's endless loop after a ring restart is not reproduced. No code emits the producer texts (CD-ROM / SATA patch routines 0x91f40088, 0x91f3f518, 0x91f3f180, 0x91f3f2d0, 0x91f3f6f0, 0x91f3fcd0, 0x91f3fd34, 0x91f3fe50, 0x91f3ffc4 are not implemented).
- `notifyat drop` with an invalid address does not match stale freed entries.
- Debug string delivery (0x91f38ce8) uses a 3 s writable wait that skips (not closes) a slow channel, and drains input of all channels every 120 s (0x91f38940); notify.rs `deliver_string` keeps the 60 s wait.
- rpc: argument copies are limited to the 16 register slots (stock overruns its frame). The call block is freed by the last of the runner and the stream.
- fastpipe: the slot[-1] write, double socket ownership, and the stalled pipe after a read buffer allocation failure (openxbdm closes the pipe) are not reproduced.
- A discovery lookup name with an embedded NUL is not matched.
- The host mock generates no 0x64/0x65 file events and runs no notification session handlers.
