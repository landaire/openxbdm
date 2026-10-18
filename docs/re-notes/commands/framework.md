# XBDM command framework

Image: stock XBDM 2.0.21256.0, base 0x91f00000. All addresses are virtual addresses in that image. Source file named by assertions: `dmserv.c` (server), `dmnotify.c` (notifications).

Terms:

- conn: one entry of the connection array at 0x91fab9e0, 8 entries, stride 0x298. Index `i` is `(addr - 0x91fab9e0) / 0x298`.
- ctx: the handler context, `&conn.ctx` = conn+0x228. Handlers recover the connection index as `(ctx - 0x91fab9e0) / 0x298`.
- main thread: the TCP server thread. Its thread object pointer is stored at 0x91fab984 and is asserted equal to the current thread at server start (0x91f50cf8).

## 1. Command dispatch

### Line entry point: 0x91f505f0 `(conn_index, line)`

Called by the receive path 0x91f509f0 (conn_index >= 0), by the title command thread (0x91f42d1c) and by the xbdm.ini line processor 0x91f311b8 with conn_index = -1.

Order of operations:

1. Command word length = number of bytes before the first space, CR or NUL.
2. If debug flag bit 0x1 of 0x91f9fef4 is set: `DbgPrint("XBDM(thr=0x%0.8x): %d:%s\n", thread, conn_index, line)`.
3. If conn_index >= 0: clear ctx (ctx+8 buffer = 0, ctx+0x14 = 0xffffffff, ctx+0 = 0, ctx+0x10 = conn+0x240), clear conn flags 0x1c000000, access mask = conn+0xc. If conn_index < 0: ctx = NULL, access mask = 0xffffffff.
4. Scan the command word for `!`. If found at offset p, the line is a command processor command (section 6). Otherwise the built-in table is used.
5. Built-in lookup 0x91f42278 `(access, line, word_len, resp, 0x1fb, ctx)`.
6. Result handling (below).

### Built-in table lookup: 0x91f42278

- Table 0x91f980a0, entry count at 0x91f97a8c (= 177), entries of 20 bytes:

```text
+0x00 u32 name pointer
+0x04 u32 any_of access mask
+0x08 u32 handler
+0x0c u32 all_of access mask
+0x10 u32 dispatch flags ("extra")
```

- Binary search on the table (sorted by name). Comparison 0x91f41148 folds `a`-`z` to upper case on both sides and compares exactly `word_len` bytes; the table name must end exactly at `word_len`. The command word therefore matches case-insensitively and exactly; no prefix matching. An empty command word (empty line, or line starting with a space) never matches.
- No match: return 0x82da0007 (`407- unknown command`).
- Match, checks in this order:
  1. Flags bit 0x2 and global 0x91f9f680 != 0: return 0x82da0007 (`407- unknown command`). 0x91f9f680 nonzero is the test-kit state; `consoletype` (0x91f4cf68) reports `testkit` when it is nonzero and `devkit` when zero. Bit 0x2 marks development-kit-only commands.
  2. Access check. If all_of (+0xc) != 0: pass iff `(all_of & access) == all_of`. Else if any_of (+0x4) == 0: pass. Else pass iff `(any_of & access) != 0`. Failure: 0x82da000e (`414- access denied`).
  3. Flags bit 0x4: the handler runs on a new thread via 0x91f421c8: `ExCreateThread(&h, 0, &id, 0, 0x91f42178, &args, 0x20)`, then `NtWaitForSingleObjectEx(h, KernelMode, FALSE, NULL)`, `NtClose(h)`; the handler result is returned. The result slot of `args` is zeroed first, so a thread that ends inside the handler gives 0 (no status line). A negative creation or wait status is returned unchanged (sent as `400- ` with empty text). Creation flag 0x20 is priority class 13; without SYSTEM_PROCESS (0x2) the thread belongs to the title process (observed: XAM's CIV server reports title-process thread ids for `civstart`). openxbdm: `ProcessorBackend::run_command_thread` (Xbox `backend/session/processors.rs`, start routine through the export bridge; the host runs the handler inline). A failed wait is repeated until the thread ends, since the handler's borrows live in the server's frame; stock returns at once and leaves the thread using its arguments. While the server thread waits, posts to it do not wait (`dispatcher::block_posts`; `parity/debugger.md`, "Events during a dispatch flag 0x4 command"), since the handler can wait for threads that post (XamMediaVerificationCreate waits for a worker whose DbgPrint reaches the debug routine).
  4. Otherwise, if 0x91fab984 != 0 and the current thread is not the main thread and flags bit 0x1 is clear: return 0x82da0016 (`422- dedicated connection required`). Bit 0x1 marks commands allowed on connections serviced by a dedicated or title thread.
  5. Call `handler(line, resp, 0x1fb, ctx)` and return its result.

Access bits (formatter 0x91f40878, used by `getuserpriv`):

| Bit | Name |
| --- | --- |
| 0x01 | read |
| 0x02 | write |
| 0x04 | control |
| 0x08 | config |
| 0x10 | manage |

Observed table values: any_of 0 (no check), 1, 2, 3 (read or write), 4, 8, 0x10. all_of is 3 (read and write both required) for `delete`, `fileeof`, `rename`; 0 for all others. Dispatch flags observed: 0, 1 (`bye`, `dedicate`), 2 (development-kit-only), 4 (`civinject`, `civstart`, `civstop`, `civverify`).

Commands with any_of 0 and all_of 0 run without privilege: `authuser`, `boxid`, `bye`, `dbgname`, `debugmode`, `dedicate`, `fastpipe`, `getuserpriv`, `keyxchg`, `playto`, `setreset`, `systime`, `tdecomp`. Handlers may perform further privilege checks themselves (for example `dbgname` with `name=` requires bit 0x8).

### Handler ABI

`HRESULT handler(const char *line, char *resp, u32 resp_size, ctx *ctx)`

- `line`: complete NUL-terminated command line including the command word (CR replaced by NUL).
- `resp`: text written after `NNN- `. It is offset 5 of a 0x200-byte line buffer; `resp_size` is 0x1fb. Empty on entry (first byte 0).
- `ctx`: NULL when executed from xbdm.ini.
- Return value: see section 4. A built-in handler returning 0 produces no status line; the handler has written to the socket itself or closed it (`bye`, `dedicate`, `notify`). A handler that reports a result code as text can also return 0 and send nothing: `dmtelllog` returns 0 when an area is added to an open log, the file open fails, or a partial stop leaves the log open. A command processor handler returning 0 is converted to 0x02da0000.

### Result handling in 0x91f505f0

For a nonzero result and conn_index >= 0:

1. Message text = handler text if `resp[0] != 0`, else the default text from 0x91f41c98 (section 4).
2. 0x02da0002 (202): ctx+4 = 0xffffffff (text line mode), set conn flag 0x04000000. 0x02da0003 (203): set 0x08000000. 0x02da0004 (204): set 0x10000000.
3. If any of 0x1c000000 is set and ctx+0 (continuation) is NULL: clear those flags; result becomes 0x8000ffff (`400- unexpected error`, or the handler text if any).
4. 0x02da0005 (205): call 0x91f51640 `(conn_index, processor_index)`; processor_index is -1 for built-ins. If it returns nonzero, nothing further is sent (that routine sent `205- connection dedicated`). If it returns 0, the result becomes 0x80004005 and the status line is sent.
5. Send the status line with 0x91f42028.
6. If the result is 0x02da0004 and ctx+0x14 == 0 (zero bytes expected), run the receive pump once immediately (`0x91f423f8(conn, 0)`).

Return value of 0x91f505f0: 1 normally; 0 only when the connection was handed to the title thread (section 6). The caller compacts the receive buffer only on 1.

### Status line builder: 0x91f42028 `(socket, hr, msg, buf)`

- If `(hr & 0x7fff0000) == 0x02da0000` (XBDM facility): if `(hr & 0xffff) > 0xff` the code becomes 0x82da0000. Otherwise hr is used as is.
- Other facility: hr becomes 0x02da0000 if hr >= 0, else 0x82da0000; if msg is NULL, msg = `unexpected error`.
- Text: `'2'` if code >= 0 else `'4'`, then `'0' + (low16 / 10)`, `'0' + (low16 % 10)`, `'-'`, `' '`, then msg (copied unless msg already is buf+5; NUL if msg is NULL).
- low16 values 100..255 yield a non-digit second character (no such code is produced by the framework).
- If debug flag bit 0x1 is set: `DbgPrint("XBDM(thr=0x%0.8x): R=%s\n", thread, buf)`.
- Sent with 0x91f41528.

### Line send: 0x91f41528 `(socket, text)`

Copies up to 0x3fe bytes into a 0x460-byte stack buffer, appends CR LF, one `send`. If the text is longer than 0x3fe bytes, sends the text, then `"\r\n"` (0x91f02af4) in a second `send`. Returns 0 if any `send` returns <= 0.

### xbdm.ini lines: 0x91f311b8

Lines from the settings file are dispatched with conn_index -1 after special keywords are handled (`wait`, `notify`, `notifyat`, `staticip`, `gateway`, `subnet`, `memtrack`, `drivemap`, `sysset`, `httpreg`, `netsim`, `xhttpproxy`). `notify` from the file is ignored. `notifyat` calls 0x91f3c308 with socket -1 (address must then be given with `addr=`). Other lines run with access 0xffffffff, ctx NULL and produce no output. Trace: debug flag bit 0x4 prints `XBDM: DoIniLine '%s'\n` for every line, empty ones included, before the keyword checks (site 0x91f311dc). A line with an empty command word stops there; keyword lines do not reach 0x91f505f0, so only the remaining lines print the bit 0x1 text `XBDM(thr=0x%0.8x): -1:%s\n`.

Backend requirement: none beyond the protocol core; a server needs a sorted, case-insensitive command registry carrying any_of/all_of masks and the three dispatch flags, and a test-kit flag.

Status: spec complete.

## 2. Connection lifecycle

### Listener (server thread 0x91f50cb0, created by 0x91f51370)

- Thread creation: `ExCreateThread(&0x91fab984, 0x8000, 0, 0, 0x91f50cb0, 0, 0x040004a6)`.
- TCP: `socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)`, `setsockopt(SOL_SOCKET, SO_REUSEADDR=1)`, bind port 730 (0x2da) on any address, `listen(backlog 8)`. Failure: socket closed, thread exits.
- UDP: `socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)`, SO_REUSEADDR, SO_BROADCAST (opt 0x20), bind port 730. Readable datagrams go to 0x91f42948 (discovery; not covered here). UDP failure is not fatal.
- Loop: `select` over the listener, the UDP socket and every connection whose owner (conn+0x14) is the main thread. A connection is in the write set if flag 0x08000000 or 0x04000000 is set, else in the read set (max 0x40 sockets per set). Timeout from 0x91f30580, capped to 300 s. After each pass, 0x91f62e88, 0x91f62228, 0x91f65a18 run (periodic work, not framework). The loop exits when 0x91fab9b4 (shutdown) is nonzero.
- Per ready connection: writable -> send pump `0x91f423f8(i, 1)`; readable -> receive `0x91f509f0(i)`.

### Accept

1. `accept`. Under critical section 0x91facec0:
   - If 0x91fab9b4 (shutdown) != 0: slot = 8 (reject).
   - Else first slot with socket == -1 and owner (conn+0x14) == 0; owner := main thread, socket stored.
2. No slot (8 connections in use or shutdown): send `401- max number of connections exceeded`, set 0x91f975fc = 1 (meaning unknown), `closesocket`.
3. Lock mode (0x91fab9ac != 0): access (conn+0xc) := 0; nonce at conn+0x20: `KeQuerySystemTime(conn+0x20)`, then word0 ^= timebase low word, word1 ^= timebase high word. Banner: `sprintf("201- boxid=0q%08x%08x nonce=0q%08x%08x", box[0], box[1], nonce[0], nonce[1])` where box is the 8 bytes at 0x91fab9a0.
4. Not locked: access := 0xffffffff; banner `201- connected`. conn+0x20 is not written, so the slot keeps the nonce of its last locked connection (verified in the accept code at 0x91f511fc..0x91f51288). The session key at conn+0x18 is not cleared either; the key-exchanged flag is (step 5).
5. Initialize: flags byte conn+4 (top byte, bits 0xff000000) := 0, conn+8 := 0, ctx+0x14 := 0xffffffff, ctx+8 := 0, ctx+0x10 := conn+0x240, ctx+0 := 0.

### Receive and line framing: 0x91f509f0 `(i)`

- If flag 0x10000000 (binary receive): run receive pump `0x91f423f8(i, 0)` and return.
- Receive buffer: conn+0x28, 0x200 bytes; fill count conn+8.
- Normal state: `recv(sock, buf + count, 0x200 - count)`. Overflow state (flag 0x02000000): `recv` into a 0x40-byte stack scratch area.
- `recv` <= 0: connection closed (0x91f41460).
- Normal state: count += n; if count >= 0x200, set overflow flag 0x02000000.
- CR search covers the newly received bytes plus the one byte before them (when the new data does not start at the buffer start). A line ends at a CR that is followed by at least one more byte. The byte after CR is not examined (LF is assumed). LF alone never terminates a line.
- No terminator yet: wait for more data.
- Overflow state with terminator: send `446- line too long` (0x82da002e), count := 0, clear overflow. Bytes after the terminator in that read are discarded.
- Otherwise: CR := NUL, call 0x91f505f0(i, conn+0x28). If it returns 1 and the socket is still open: move bytes after CR+1 to the buffer start, count := moved bytes.

Limits:

- A command line plus CR LF must fit in 0x200 bytes of buffered input. Overflow is decided on the total buffered byte count, so trailing bytes received in the same read count toward the limit.
- Only one line is dispatched per `recv`. Bytes after the first line remain buffered and are not scanned until another `recv` completes; the next CR found is in the new data, so a complete line left in the buffer is merged with the following line. Clients must wait for each response before sending the next command. openxbdm reproduces this; after a command that sends no reply, a pipelined line waits for the next receive.
- Handler response text: 0x1fb bytes. Continuation response text: 0x100 bytes.
- Empty line (`\r\n`): `407- unknown command`.

### Close: 0x91f41460 `(i)`

If a title thread exists and conn owner is that thread, atomically decrement 0x91f9fed4. Under 0x91facec0: `closesocket` if socket != -1, socket := -1, conn+8 := 0, conn+4 top byte := 0, conn+0x10 := 0, conn+0x14 := 0.

### bye (0x91f43450, any_of 0, flags 1)

ctx NULL: 0x80070057. Else sends `200- bye`, closes the connection, returns 0.

### Connection state layout (0x298 bytes)

| Offset | Size | Field |
| --- | --- | --- |
| 0x000 | 4 | socket, -1 = free |
| 0x004 | 4 | flags (table below) |
| 0x008 | 4 | bytes in receive buffer |
| 0x00c | 4 | access mask (0xffffffff when not locked) |
| 0x010 | 4 | dedicated command processor (section 6) or 0 |
| 0x014 | 4 | owner thread (main, dedicated or title thread; 0 when free or in hand-off) |
| 0x018 | 8 | used by `authuser passwd` path (XOR with challenge); see authentication notes |
| 0x020 | 8 | lock-mode nonce sent in banner |
| 0x028 | 0x200 | receive line buffer |
| 0x228 | 0x18 | ctx (table below) |
| 0x240 | 0x58 | ctx scratch, default target of ctx+0x10 |

Flags (assertion names from dmserv.c where known):

| Bit | Meaning |
| --- | --- |
| 0x01000000 | key exchange completed (tested by `authuser`) |
| 0x02000000 | receive overflow (line too long) |
| 0x04000000 | Multiline: 202 text output in progress |
| 0x08000000 | BinarySend: 203 output in progress |
| 0x10000000 | Binary: 204 input in progress |
| 0x20000000 | TransferringToTitle: buffered line to be dispatched by the title thread |
| 0x40000000 | TitleOwned: dedicated to a title-process processor |
| 0x80000000 | hand-off to title thread pending |

ctx (handler argument 4):

| Offset | Field |
| --- | --- |
| +0x00 | continuation function, NULL = none |
| +0x04 | byte count; 0xffffffff = text line mode |
| +0x08 | data buffer pointer; NULL = pump supplies a 0x100-byte stack buffer per call |
| +0x0c | data buffer size |
| +0x10 | scratch pointer, initially conn+0x240 |
| +0x14 | receive bytes remaining (204); 0xffffffff when idle; set to 0 by the send pump to signal abort |

Debug flags (0x91f9fef4); `thr` is the caller's thread object (`*(r13+0x100)`):

- 0x1, 0x91f505f0 site 0x91f50640: `XBDM(thr=0x%0.8x): %d:%s\n` (connection slot or -1, the line up to its NUL) before any other step.
- 0x1, status line builder 0x91f42028 site 0x91f42114: `XBDM(thr=0x%0.8x): R=%s\n` with the built line (no CR LF), printed before the send. Callers: 0x91f505f0 (every reply of a connection; settings-file lines send nothing), the 204 completion in 0x91f423f8, and the `446- line too long` reply in 0x91f509f0. The builder maps a result of another facility to 200/400 with `unexpected error` when no text is given, and an XBDM code above 0xff to 400.
- 0x2, receive pump 0x91f423f8: with bytes left in the line buffer (site 0x91f4249c) `XBDM(thr=0x%0.8x): BR(buffer): %d of %d bytes\n` with the bytes taken (min of buffered, remaining, buffer size; no text when 0) and the bytes remaining before the take; otherwise, only when a receive is issued (site 0x91f42560), `XBDM(thr=0x%0.8x): BR(recv): %d of %d bytes\n` with the `recv` result (0 when it returned <= 0 and the connection was closed) and the bytes remaining.
- 0x4: settings file reads and writes (DoIniLine above, the NetSim file in `group5.md`, the system writer in `parity/system.md`).
- 0x8: drive path translation 0x91f2e888 (`parity/filesystem.md`) and title resolution.

Backend requirement: TCP listener on port 730 with up to 8 concurrent sessions; time and timebase sources for the nonce; box identifier and lock state.

Status: spec complete.

## 3. Response modes

### Continuation ABI

`HRESULT cont(ctx *ctx, char *resp, u32 resp_size /* 0x100 */)`

The handler stores `cont` in ctx+0 (and optionally ctx+8/ctx+0xc and state in ctx+0x10) and returns 202, 203 or 204. The dispatcher sends the status line immediately (`202- multiline response follows`, `203- binary response follows`, `204- send binary data`, or handler text such as `202- memory data follows`). End of data is signalled by returning 0x82da0104.

Pump: 0x91f423f8 `(i, sending)`. Before each call, if ctx+8 is NULL, ctx+8 := stack buffer, ctx+0xc := 0x100; after the call a stack pointer left in ctx+8 is cleared. `resp[0]` is 0 on entry.

### 202 multiline

- Main loop places the socket in the write set; one continuation call per writable event.
- `cont` writes one NUL-terminated line into ctx+8 and returns >= 0. ctx+4 remains 0xffffffff; the pump sends the line with CR LF (send failure is not checked here).
- `cont` returns 0x82da0104: pump sends `.` (CR LF), resets ctx (ctx+8 = 0, ctx+0 = 0, ctx+0x14 = 0xffffffff, ctx+0x10 = conn+0x240) and clears 0x1c000000.
- `cont` returns another negative value: connection closed. No terminator is sent.

### 203 binary

- `cont` fills ctx+8 and sets ctx+4 = byte count, returns >= 0. The pump sends exactly ctx+4 bytes, looping on partial `send`. ctx+4 = 0 sends nothing for that event. The dispatcher does not initialize ctx+4 for 203; the continuation must set it.
- A `send` result <= 0: ctx+0x14 := 0, `cont` is called once more (abort notice), connection closed.
- 0x82da0104 ends the transfer; data placed in the buffer by that final call is not sent. No terminator line and no status line follow binary data.
- Other negative result: connection closed.
- Framing of binary data (length prefixes etc.) is defined by each command, not by the framework.

### 204 binary receive

- Handler sets ctx+0x14 = bytes expected (and may set ctx+8/ctx+0xc). Status `204- ...` is sent; the socket stays in the read set and 0x91f509f0 forwards to the pump.
- Each event: if receive-buffer bytes remain (conn+8 != 0, data that arrived after the command line), n = min(conn+8, ctx+0x14, ctx+0xc), copied from the line buffer and the line buffer compacted. Else n = min(ctx+0xc, ctx+0x14); if n != 0, `recv(sock, ctx+8, n)`; `recv` <= 0 closes the connection and n = 0. ctx+4 := n. `cont` is always called.
- The continuation must decrement ctx+0x14 itself. Results are ignored while ctx+0x14 != 0. To abort early, set ctx+0x14 = 0 and return an error.
- When ctx+0x14 == 0 and the socket is open: ctx+0x14 := 0xffffffff, clear 0x10000000, then by result:
  - 0x02da0002: ctx+4 := 0xffffffff, set 0x04000000 (switch to 202 output).
  - 0x02da0003: set 0x08000000 (switch to 203 output).
  - 0x02da0009: ctx is kept (no reset, no output mode). Used by fastpipe (`209- result code %d` at 0x91f08500); details: partial.
  - Other: ctx reset, flags 0x1c000000 cleared.
  - If an output flag is set and ctx+0 is NULL: flags cleared, code 0x8000ffff.
  - Status line sent with the continuation text if `resp[0] != 0`, else the default message. Example capture: `sendfile` -> `204- send binary data`, body, `200- OK`.
- Bytes that arrived with the command line are consumed only when the socket next becomes readable. [Derived from code: a body sent in the same segment as the command line is not processed until more data arrives.]

### 205 dedicated connection

See section 6. Literal `205- connection dedicated` (0x91f07f4c) and `205- now a notification channel` (0x91f045e0, section 5). No default text exists for 0x02da0005.

### 206

No `206-` literal exists in this image and the framework does not produce 206. One internal routine (0x91f29210, reached from 0x91f299c8) returns 0x02da0006; whether any handler propagates it is unknown (resolve by tracing callers of 0x91f29c00 and 0x91f29d08). If returned by a handler, the builder would send `206- ` with empty text.

Backend requirement: non-blocking or event-driven socket writes per connection with per-connection pull callbacks; inbound byte streaming with an explicit remaining count.

Status: partial: 0x02da0009 receive-completion semantics (fastpipe) and the 0x02da0006 producer are unresolved.

## 4. HRESULT to status and message

Mapper: 0x91f41c98 `(hr) -> const char *`. Unlisted codes return the empty string at 0x91f01cdf. Status digits come from the builder (section 1).

| HRESULT | Status | Default text |
| --- | --- | --- |
| 0x02da0000 | 200 | `OK` |
| 0x02da0001 | 201 | (empty) |
| 0x02da0002 | 202 | `multiline response follows` |
| 0x02da0003 | 203 | `binary response follows` |
| 0x02da0004 | 204 | `send binary data` |
| 0x02da0005 | 205 | (empty; dedicate path sends its own line) |
| 0x02da0009 | 209 | (empty) |
| 0x82da0000 | 400 | (empty) |
| 0x82da0001 | 401 | (empty) |
| 0x82da0002 | 402 | `file not found` |
| 0x82da0003 | 403 | `no such module` |
| 0x82da0004 | 404 | `memory not mapped` |
| 0x82da0005 | 405 | `no such thread` |
| 0x82da0006 | 406 | (empty) |
| 0x82da0007 | 407 | `unknown command` |
| 0x82da0008 | 408 | `not stopped` |
| 0x82da0009 | 409 | `file must be copied` |
| 0x82da000a | 410 | `file already exists` |
| 0x82da000b | 411 | `directory not empty` |
| 0x82da000c | 412 | `filename is invalid` |
| 0x82da000d | 413 | `file cannot be created` |
| 0x82da000e | 414 | `access denied` |
| 0x82da000f | 415 | `no room on device` |
| 0x82da0010 | 416 | `not debuggable` |
| 0x82da0011 | 417 | `type invalid` |
| 0x82da0012 | 418 | `data not available` |
| 0x82da0013 | 419 | (empty) |
| 0x82da0014 | 420 | `box is not locked` |
| 0x82da0015 | 421 | `key exchange required` |
| 0x82da0016 | 422 | `dedicated connection required` |
| 0x82da0017 | 423 | `bad parameter` |
| 0x82da0018..0x82da001b | 424..427 | (empty) |
| 0x82da001c | 428 | `out of memory` |
| 0x82da001d | 429 | (empty) |
| 0x82da001e | 430 | `path not found` |
| 0x82da001f..0x82da002d | 431..445 | (empty) |
| 0x82da002e | 446 | `line too long` |
| 0x82da0104 | 400 (low16 > 0xff) | (empty); internal end-of-data code |
| 0x8000ffff | 400 | `unexpected error` |
| 0x8007000e | 400 | `out of memory` |
| 0x80070057 | 400 | `bad parameter` |
| 0x80004005 and any other negative | 400 | (empty) |
| other non-negative, non-XBDM | 200 | (empty) |

Handler text always replaces the default text. Examples: `400- missing handler`, `400- notification limit exceeded`, `missing %s` from required-parameter helpers.

NTSTATUS mapper 0x91f41f18 `(status, fallback_hr)` used by handlers:

| NTSTATUS | HRESULT |
| --- | --- |
| 0x00000000 | 0x02da0000 |
| 0xc0000008 | 0x80070057 |
| 0xc0000022 | 0x82da000e |
| 0xc0000033 | 0x82da000c |
| 0xc0000034 | 0x82da0002 |
| 0xc0000035 | 0x82da000a |
| 0xc0000039 | 0x82da000c |
| 0xc000003a | 0x82da001e if fallback is 0x82da000d, else 0x82da0002 |
| 0xc000007f | 0x82da000f |
| 0xc000009a | 0x8007000e |
| 0xc00000ba | 0x82da0002 |
| 0xc0000101 | 0x82da000b |
| other | fallback_hr |

Backend requirement: none.

Status: spec complete.

## 5. Notification channels

### Tables (critical section 0x91fadd00)

- Notification sockets: 16 x u32 at 0x91fadd40, -1 = free. Allocation 0x91f3be18 `(socket, target_index)`; when full, 0x91f39ad0 prunes dead sockets and the allocation is retried once.
- Notification targets: 16 x 16 bytes at 0x91fadb00: +0 u32 IPv4 address (0 = free), +4 u16 port, +8 u32 flags (0x2 debug, 0x40000 reverse), +0xc i32 socket slot index or -1.
- Flags 0x2 on a target that gets a socket sets debugger-attach globals (0x91f9fef8 = 1, 0x91f9fefc = 0x91fadd00, 0x91f9ff00 = port, 0x91f9ff04 = 0, 0x91f9ff84 = 0, 0x91f975fc = 0); semantics belong to the debugger notes.

### notify (handler 0x91f44268, also `notifyport`)

1. ctx NULL: 0x80004005.
2. `reconnectport=` (dword) optional. If present, `getpeername` on the command socket; failure returns 0 (no reply line).
3. Flags: bare `debug` -> 0x2; bare `reverse` -> 0x40000.
4. 0x91f3cfe0 `(socket, port & 0xffff, peer_ip, flags)`:
   - port 0: socket added to the socket table.
   - port != 0: 0x91f3c0d8 attaches the socket to an existing target with the same address and port awaiting a reverse connection (socket slot -1), or creates a new target bound to this socket; event 0x91fab990 is signalled.
   - On success: sends `205- now a notification channel`, then the current execution state line (format type 3 below, state from 0x91f2d930(0)).
5. Success: under 0x91facec0 the conn socket field := -1 and the connection slot is released without closing the socket (0x91f41460). The handler returns 0 (no further line). If `reconnectport` was given, 0x91f31e48 runs (persistent settings save [INFERENCE]).
6. Failure: text `notification limit exceeded`, result 0x80004005 -> `400- notification limit exceeded`.

The channel is one-way after the 205 line. Commands sent on it are not read.

### notifyat (handler 0x91f441e8, parser 0x91f3c308)

- ctx NULL: 0x80004005.
- `port=` dword required; absent -> 0x80004005 (`400- ` empty text).
- `addr=` string (up to 0x13 chars) parsed by 0x91f41b80; absent -> peer address of the command socket (`getpeername`; failure -> 400). From xbdm.ini (socket -1) `addr` is required.
- Bare `drop`: 0x91f38b60 removes the target (address, port); result 200.
- Else flags `debug` (0x2), `reverse` (0x40000); 0x91f3c0d8 `(ip, port, flags, reverse, -1)` registers the target. A non-reverse target is connected immediately (0x91f3bed8, blocking) and receives the execution state line; failure removes the target.
- Success: 0x91f31e48 runs, `200- OK`.

The return value of 0x91f3c0d8 and the per-target behavior are in `group6.md` (`notifyat`) and `docs/re-notes/parity/session.md`.

### Outbound connection: 0x91f3bed8 `(ip, port, nonblocking)`

TCP socket, SO_REUSEADDR, bind local port `(random & 0x3fff) + 0x1000` (0x1000..0x4fff), set FIONBIO per argument, `connect` to ip:port. Blocking mode: sends the execution state line. Non-blocking: `WSAEWOULDBLOCK` (0x2733) is success. Failures print `[xbdm]SockCreateNotify: ...` diagnostics and close the socket.

### Persistent targets: 0x91f3c440 (EnsurePersistentSockets)

For each target: non-reverse targets get a non-blocking connect; reverse targets wait for a `notify reconnectport=` connection. Total wait 30 s (0x7530 ms). On writable: socket set blocking, line `hello` sent, socket registered. Connect timeout or `hello` failure drops the target. Reverse targets without a connection after the wait are dropped. Ends with 0x91f31e48.

### Delivery: 0x91f39688 `(type, data)`

- Formats into a 0x230-byte buffer with 0x91f391e0. Type 0 -> `null`. Type 2 (debug string) uses 0x91f38ce8: prefix built from `%s %sthread=0x%0.8x ` and `%sstring=`, string split at CR/LF and in 0x800-byte chunks; exact prefix values: partial.
- Sends only at PASSIVE_LEVEL (current IRQL byte r13+0x18 == 0); otherwise nothing is sent by this routine (deferral path 0x91f395c0 not analyzed).
- Per socket 0x91f389e0: liveness check 0x91f388a8, `select` writable with 60 s timeout, line + CR LF. Failure closes the socket, frees the slot and frees every target bound to that slot.

### Message formats (0x91f391e0; type in low 24 bits, bit 31 = thread stopped)

| Type | Format |
| --- | --- |
| 1 | `break addr=0x%08x thread=0x%08x` |
| 2 | debug string (see above) |
| 3 | `execution %s`; state 0 `stopped`, 1 `started`, 2 `rebooting`, 3 `pending`, 4 `reboot_title`, 5 `pending_title` (table 0x91f97608) |
| 4 | `singlestep addr=0x%08x thread=0x%08x` |
| 5 | `modload ` + module description (0x91f39080; see module notes) |
| 6 | `modunload name="%s" base=0x%08x size=0x%08x` |
| 7 | `create thread=0x%08x start=0x%08x` |
| 8 | `terminate thread=0x%08x` |
| 9 | `exception code=0x%08x thread=0x%08x address=0x%08x`, then for code 0xc0000005 ` %s=0x%08x` (`write` if access flag nonzero else `read`, address) else ` nparam=%lu params=0x%08x`, then ` first` if flags & 2, ` noncont` if flags & 1 |
| 12 | `assert thread=0x%08x straddr=0x%0.8x strlen=0x%0.8x` |
| 13 | `data %s=0x%08x addr=0x%08x thread=0x%08x` with `write` (1), `read` (2), `execute` (3) |
| 14 | `rip%s thread=0x%08x` or `rip%s thread=0x%08x string=%-*.*s` |
| 16 | `sectload name="%s" base=0x%08x size=0x%08x index=%d flags=%d` |
| 17 | `sectunload name="%s" base=0x%08x size=0x%08x index=%d flags=%d` |
| 19 | `stacktrace%s thread=0x%08x` or with ` string=%-*.*s` |
| 21 | `ntassert addr=0x%08x thread=0x%08x` |
| 22 | `pogomodstartup name="%s" module=0x%08x thread=0x%08x` |
| 10, 11, 15, 18, 20, >22 | no text (not sent by this routine) |

For stopped events (bit 31) the suffix ` stop` (0x91f03c4c) is appended (types 14 and 19 place it after the name).

Backend requirement: outbound TCP connections, peer address lookup, an event source for execution, module, thread, exception and debug-string events.

Status: partial: debug-string prefix strings, IRQL deferral queue.

## 6. Command processors and dedicate

### Registration: 0x91f431e8 `(name, handler, dedicated_thread)`; 0x91f51438 `(name, handler)` = same with dedicated_thread 0

Export ordinals: 72 (0x91f431e8) and 30 (0x91f51438). Internal use: private API dispatcher 0x91f3b4d0 code 0x1c registers `PIX` (string 0x91f041cc) with the argument as handler, code 0x32 calls export 30 with `{+0 name, +4 handler}`.

- name NULL: 0x80070057.
- handler NULL: unregister every slot whose name equals `name` (case-insensitive, exact); returns 0x02da0000.
- Register: first free slot of 16 at 0x91f9ff98. Table full or pool allocation failure: 0x8007000e. Record: `ExAllocatePoolWithTag(0x48, 0x68636d64)`: +0x00 name (max 63 chars, NUL-terminated), +0x40 handler, +0x44 flags. The name is copied for at most 0x3f characters; when the byte after them is not NUL (name of 64 or more chars) the record is freed and the result is 0x80070057. Flags bit 0x1 = registered from the title process (`KeGetCurrentProcessType() == 1`); bit 0x2 = dedicated_thread argument nonzero. No duplicate-name check. Success 0x02da0000. All of it runs under critical section 0x91facee0 inside `KeEnterCriticalRegion`.
- Title termination (0x91f42850): frees all records with flag 0x1, clears title thread state, and closes every connection with flag 0x40000000.

### Invocation: `NAME!rest` (0x91f505f0)

1. NAME = bytes before the first `!` in the command word; lookup 0x91f427c0 (case-insensitive, exact). Not found: `407- unknown command`.
2. Access bit 0x4 (control) required, else `414- access denied`.
3. If conn+0x10 is this processor: call it.
4. Else if processor flag 0x2 or the connection is dedicated to another processor: `422- dedicated connection required`.
5. Else if processor flag 0x1 (title-owned): call it if the current process is the title process; otherwise hand the connection to the title thread (0x91f50428 with transfer = 1). On successful hand-off nothing is sent and the line stays buffered; on failure `422- dedicated connection required`.
6. Else (system processor): call it if the current process is not the title process, else 422.
7. Call `handler(line, resp, 0x1fb, ctx)` with the full line including `NAME!`. Result 0 becomes 0x02da0000. Results are processed as for built-ins (202/203/204 apply). A 202/203/204 result with ctx+0 NULL becomes 0x8000ffff with the text chosen for the original result (handler text, else its default text, e.g. `400- multiline response follows`). 0x02da0005 calls 0x91f51640(conn, processor index): the processor takes the connection.

### dedicate (handler 0x91f51838, any_of 0, flags 1)

1. ctx NULL: 0x80070057.
2. Bare `global`: 0x91f51640(conn, -1). Returns 0 on success, else 0x80004005 (`400- `).
3. Else `handler=` string (0x100 bytes); absent: text `missing handler`, 0x80004005 -> `400- missing handler`. Unknown processor: 0x82da0002 (`402- file not found`). Else 0x91f51640(conn, index).

### Dedicate routine: 0x91f51640 `(conn, index)`

- Current thread must be the connection owner, else `DbgPrint("dm: rededicating a connection on the wrong thread!\n")` and return 0.
- index >= 0 with an empty slot: return 0.
- Processor flags & 3 == 1 (title-owned, shared thread): 0x91f50428(conn, index, 0) (title hand-off, sends `205- connection dedicated`).
- Processor flag 0x2: create a dedicated thread `ExCreateThread(&h, 0x8000, 0, 0, 0x91f50b98, conn, 0x040002a5 | ((~flags & 1) << 1))`; failure returns 0.
- Then: send `205- connection dedicated`; if owner was the title thread, decrement 0x91f9fed4; owner := 0; conn+0x10 := processor (NULL for `global`); flag 0x40000000 := processor flag 0x1.
  - Processor present: `KeResumeThread(h)`; the new thread becomes owner. For a processor with flags & 3 == 0, no thread was created: the routine calls `KeResumeThread` on a NULL handle and the connection is left with owner 0 [derived from code; not exercised].
  - `global`: owner := main thread, `KeAlertThread(main thread)` so the main loop picks the socket up again.
- Returns 1.

### Dedicated thread loop: 0x91f50b98 `(conn)`

Sets thread flags, owner := current thread, then while owner == current thread and socket != -1: blocking `select` on the single socket (write set when 0x08000000 or 0x04000000 is set, else read set); not ready -> close; writable -> send pump; readable -> 0x91f509f0. On exit `ObDereferenceObject(current thread)`. Built-in commands without dispatch flag 0x1 return 422 on this thread.

### Title command thread: 0x91f42aa0 (thread object at 0x91f9fed0)

- Created on first hand-off: `ExCreateThread(&0x91f9fed0, 0x8000, 0, 0, 0x91f42aa0, 0, 0x040002a5)`, then resumed; trace `XBDM: Creating new title command processor thread\n` (debug flag 0x1).
- Hand-off 0x91f50428 `(conn, index, transfer)`: only for a title-owned processor. If transfer == 0, sends `205- connection dedicated`. owner := 0, flags |= 0x40000000, 0x20000000 := transfer, increments 0x91f9fed8, sets 0x80000000, signals event 0x91f9fedc and alerts the title thread.
- The title thread claims connections with 0x80000000 (owner := title thread, adjusts counters 0x91f9fed8/0x91f9fed4). If 0x20000000 is set it clears it, dispatches the buffered line through 0x91f505f0 on the title thread, then removes `strlen(line) + 2` bytes from the receive buffer.
- It services its connections with `select` like the main loop and exits after 30 s without connections (`KeWaitForSingleObject` on event 0x91f9fedc with a relative 30 s timeout, 0x91f42b98) or on shutdown (`XBDM: Terminating title command processor thread=0x%0.8x\n`).
- Trace texts (debug flag 0x1): `XBDM: Creating new title command processor thread\n` (0x91f50428 site 0x91f504d8), `XBDM: New title command processor thread = 0x%0.8x\n` (0x91f42aa0 site 0x91f42ae8, its own thread object), and the termination text above (site 0x91f43104).

Backend requirement: registry of up to 16 named processors with per-processor threading mode; ability to move a connection to another service thread; process-type query for title versus system context.

openxbdm: the platform owns the registry (`ProcessorBackend::find_processor`; Xbox `backend/session/processors.rs` under a critical section). The server thread services every connection; the handler and continuation calls of a title-owned connection run on a title command thread, those of a connection dedicated to a processor with flag 0x2 on a thread of that connection, each created with stock's flags and stack size. A call that has not ended after 20 ms continues in the background (`ProcessorProgress::Running`, `Server::complete_processor_call`) and the connection is not serviced until it ends, so the server thread keeps servicing other connections and requests while a handler runs. The title command thread exits after 30 s without a title-owned connection; a dedicated thread exits when its connection closes or changes owner.

Status: spec complete; dedicate for processors with flags & 3 == 0 is derived from code only.

## 7. Private API dispatcher

Init 0x91f32628 fills the debug monitor block 0x91fade60, 0x91f3bc38 stores the dispatcher 0x91f3b4d0 at block +0x18, and the block address is stored into kernel data ordinal 89 (IAT slot 0x91f0056c). Callers use `p = *KernelVar89; if (p) result = p->+0x18(code, arg)`; the dispatcher has no XBDM export ordinal. XBDM calls it the same way (for example codes 0x89, 0x8a, 0x88 from 0x91f2b530). Session codes: 0x64, 0x65 (file events), 0x81, 0x82 (critical section trace), 0x88, 0x89, 0x8a (`dmtelllog`), 0xa8 (rpc drain), 0xa9 (export 36 send notification). Code table and issuers: `docs/re-notes/dispatcher.md`.

## Unknowns

- 0x91f975fc: set to 1 on connection rejection, set to 0 by debug notification targets. Meaning unknown; resolve by tracing its readers.
- ExCreateThread creation flags 0x040002a5, 0x040004a6: the monitor record code (0x91f31028) reads bit 0x400 (not debuggable), 0x200 (exempt from execution stops), and 0x100 (title entry); 0x20 is priority class 13 and 0x2 the system process (xbox360-sys `ThreadCreationFlags`); bit 0x4 is not tested by `ExCreateThread`.
- 0x02da0009 (209) is not used by fastpipe, which writes its `209-` line directly: `group3.md` (`fastpipe`).
