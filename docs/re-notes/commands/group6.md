# XBDM commands, group 6

Image: stock XBDM 2.0.21256.0, base 0x91f00000. Dispatch, access checks, ctx layout, continuation pumps and the status line builder are specified in `framework.md`; this file uses its terms (conn, ctx, any_of, all_of, dispatch flags).

Conventions used below:

- `400- ` means status 400 with empty text. It results from a non-XBDM-facility failure HRESULT (for example 0x80004005) when the handler wrote no text: 0x91f41c98 returns the empty string 0x91f01cdf for such codes.
- `200- OK`: handler returned 0x02da0000 with no text.
- Response buffer size is 0x1fb.
- ctx fields used: +0 continuation, +4 byte count of the current chunk (0xffffffff = text line mode), +8 data buffer pointer, +0xc data buffer size, +0x10 per-connection scratch (conn+0x240), +0x14 remaining count / state word.
- "map(st, d)" is the NTSTATUS converter 0x91f41f18 with default d:

| NTSTATUS | Result |
| --- | --- |
| 0x00000000 | 0x02da0000 |
| 0xC0000008 | 0x80070057 |
| 0xC0000022 | 0x82da000e (414 access denied) |
| 0xC0000033, 0xC0000039 | 0x82da000c (412 filename is invalid) |
| 0xC0000034, 0xC00000BA | 0x82da0002 (402 file not found) |
| 0xC0000035 | 0x82da000a (410 file already exists) |
| 0xC000003A | 0x82da001e (430 path not found) if d = 0x82da000d, else 0x82da0002 |
| 0xC000007F | 0x82da000f (415 no room on device) |
| 0xC000009A | 0x8007000e (400 out of memory) |
| 0xC0000101 | 0x82da000b (411 directory not empty) |
| other | d |

- Default texts referenced: 0x82da0011 `type invalid`, 0x82da0012 `data not available`, 0x82da0017 `bad parameter`, 0x82da001c `out of memory`, 0x80070057 `bad parameter`, 0x8000ffff `unexpected error`. 0x82da0018, 0x82da0019, 0x82da001a have no default text (empty).
- WriteIniFile = 0x91f31e48: persists configuration to xbdm.ini. No-op when the boot medium flag (kernel export ordinal 342 data, +0xe bit 0x400) is set, when loading is incomplete (0x91f9f668 == 0) or when the file was wiped (0x91f9f664 != 0). From the title process it signals the main thread and waits up to 1 s.

## notifyat

- Handler: 0x91f441e8. Access: 0x4 (control). all_of: 0. Extra: 0x0.
- Syntax: `notifyat port=<dword> [addr=<string>] [drop] [debug] [reverse]`
  - `port`: dword grammar, required; low 16 bits used.
  - `addr`: string, buffer 0x14 bytes; dotted decimal `a.b.c.d`. Optional; default is the peer address of the current connection.
  - `drop`, `debug`, `reverse`: flags (bare token or key=value both match).
- Behavior:
  1. ctx NULL (xbdm.ini): return 0x80004005 (`400- `). Note: worker 0x91f3c308 accepts socket -1 and an explicit `addr`, but this handler does not reach it without ctx.
  2. Worker 0x91f3c308 `(conn socket, line, 0)`:
     - `port` absent: fail.
     - `addr` present: parsed by 0x91f41b80. Accepts exactly four groups of 1 to 3 decimal digits, each reduced mod 256, separated by `.`, the fourth followed by NUL; else result 0. The first octet is stored in the least significant byte of the resulting dword (`a | b<<8 | c<<16 | d<<24`). The dword is later written unchanged (big-endian) into `sin_addr`, so `addr=a.b.c.d` targets the host with bytes `d.c.b.a`. The peer-address path stores `sin_addr` bytes unchanged. Observed from code; verify against live hardware before relying on it.
     - `addr` absent: `getpeername` on the connection socket; failure: fail.
     - `drop` present: 0x91f38b60 frees every target entry with this address and port (address word cleared; port and slot stay) and closes the socket in its slot when the slot is not negative, emptying the slot. An invalid `addr=` parses as 0, which matches free entries by their kept port, including the entries never used (port 0, slot 0). Result success.
     - Otherwise flags = 2 if `debug`, OR 0x40000 if `reverse`; add target 0x91f3c0d8 `(addr, port, flags, reverse ? 1 : 0, -1)`.
  3. Add target 0x91f3c0d8:
     - addr 0: fail.
     - Target table 0x91fadb00: 16 entries of 16 bytes `{u32 addr, u16 port, u32 flags, s32 socket_slot (-1 none)}`, lock 0x91fadd00. The first entry with addr 0 is used; table full: fail.
     - When not `reverse`: connect now via 0x91f3bed8 `(addr, port, 0)`: TCP socket, SO_REUSEADDR, bind to local port `(random & 0x3fff) + 0x1000`, FIONBIO 0 (blocking), connect. On connect the console sends one line `execution <state>` (0x91f391e0 type 3; state at 0x91fae664, names at 0x91f97608). The socket is placed in a free notification socket slot (array 0x91fadd40, 16 entries) by 0x91f3be18; if none is free, a `null` line goes to every channel, failing channels are pruned, and the search is retried once. Connect or slot failure: entry cleared, socket closed, matching entries dropped (0x91f38b60), fail.
     - When `reverse`: the entry is stored without connecting; a later `notify reconnectport=` from that address binds its socket to the entry. Result success.
     - When flags bit 0x2 (`debug`) and the registration succeeds: debugger target globals set: 0x91f9fef8 = 1, 0x91f9fefc = addr, 0x91f9ff00 = port, byte 0x91f9ff04 = 0, byte 0x91f9ff84 = 0, 0x91f975fc = 0.
  4. Worker failure: return 0x80004005 (`400- `). Success: WriteIniFile, return 0x02da0000 (`200- OK`). The settings writer 0x91f38ac8 emits `notifyat addr=%d.%d.%d.%d port=%d%s` for every used target entry, address bytes 3, 2, 1, 0 (so the line parses back to the same address) and suffix ` reverse` for flag 0x40000. A settings-file line runs 0x91f3c308(-1, line, 1): stored as reverse, not connected. At startup 0x91f3c440 connects the stored targets (see `parity/session.md`).
- Backend requirement: outbound TCP connect to a host:port, a persistent list of up to 16 notification targets, an execution-state source, persistent configuration storage.
- Status: spec complete.

## notifyport

- Handler: 0x91f44268. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `notifyport [reconnectport=<dword>] [debug] [reverse]`
- Behavior: converts the current command connection into a notification channel.
  1. ctx NULL: 0x80004005 (`400- `).
  2. `reconnectport` present: `getpeername` on the connection socket; on failure the handler returns 0, so no status line is sent and the connection stays a command connection. On success addr = peer address, port = value (low 16 bits). Absent: addr 0, port 0.
  3. flags = 2 if `debug`, OR 0x40000 if `reverse`.
  4. 0x91f3cfe0 `(socket, port, addr, flags)`:
     - port 0: place the connection socket in a free notification socket slot (no target entry).
     - port != 0: 0x91f3c0d8 `(addr, port, flags, 0, socket)`: reuse the target entry with the same addr and port whose slot is -1 and bind the socket to it, else create a new entry bound to this socket (no new connect). Flags bit 0x2 sets the debugger target globals (see `notifyat`) and sets event 0x91fab990.
     - On success sends `205- now a notification channel` on the socket, then the `execution <state>` line.
  5. Failure: text `notification limit exceeded`, return 0x80004005 (`400- notification limit exceeded`).
  6. Success: conn socket field set to -1 under lock 0x91facec0, connection record released (0x91f41460); if port != 0 WriteIniFile. Returns 0: no further status line. The `205-` line is the only reply.
- Backend requirement: hand an accepted TCP connection to the notification subsystem; persistent reconnect target storage.
- Status: spec complete.

## oddlog

- Handler: 0x91f4db78. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `oddlog stop` or `oddlog [file=<string>]`. `file`: buffer 0x104.
- Behavior:
  - `stop` flag present: 0x91f3d140 atomically swaps 0x91f97660 from 0 to 1 (initial value 1 = not logging). Was nonzero: return 0x82da0018 (`424- `). Else set event 0x91fad050, wait on 0x91fad060 (logger thread exit), clear busy flag 0x91f9fda0; text `stopped logging`, `200- stopped logging`.
  - Otherwise: `file` absent: name = `devkit:\OpticalDiscLog_%d.txt` formatted with the current value of counter 0x91f9ffd8 (initial 0); the counter is incremented before the start, even when the start then fails. Start 0x91f3dad0:
    1. Atomically swap busy flag 0x91f9fda0 from 0 to 1; was nonzero: 0x82da0019 (`425- `).
    2. Zero 0xa38-byte ring state at 0x91fad0a0, set +4 = 0x3f, reset event 0x91fad060, set 0x91f97660 = 0, copy name to 0x91facf40.
    3. ExCreateThread (stack 0x8000, start 0x91f3d878, flags 0x040002a6); wait on 0x91fad070 for thread init; status = 0x91fad080.
    4. Thread: create file via path translation 0x91f2eb68 (access 0x40000000, attributes 0x80, share 5, disposition 5 = overwrite-if), write the header below, signal init. Then loop: wait 0x91fad050, drain the 64-entry ring (entries of 0x28 bytes) writing one line per entry, append `DROP,0x%08x\r\n` when the drop counter (ring+8) is nonzero, until 0x91f97660 != 0; close file; set 0x91fad060.
    5. Init status with top two bits 0b11: result map(status, 0x82da000d), busy flag cleared. 0x91f97660 stays 0 after such a failure.
    6. Success: text `Logging to '<name>'`, `200- Logging to '...'`.
  - Header text (CRLF line ends):

```text
# Optical Disc Log Created on Console
# Log Format Information:
# READ,<StartSector>,<SectorCount>,<RequestTime_100ns>,<CompleteTime_100ns>,<NTSTATUS>,;for each read operation
# GMNT,<RootDirStartSector>,<RootDirSize_bytes>,<Time_100ns>,;when GDFX filesystem is mounted
# SSC ,<CurrentSpeed>,<TargetSpeed>,<NTSTATUS>,<Time_100ns>,;for each spindle speed change
# DROP,<DropCount>,;indicates dropped log entries
```

  - Record formats (0x91f3d410, tags `GMNT`, `READ`, `SSC `):
    - `GMNT,0x%08x,0x%016I64x,0x%016I64x\r\n`: root directory sector, size (zero-extended), time.
    - `READ,0x%08x,0x%08x,0x%016I64x,0x%016I64x,0x%08x\r\n`: start sector, sector count, request time, completion time, status.
    - `SSC ,%s,%s,0x%08X,0x%016I64x\r\n`: current and target speed names, status (upper-case hex), time.
    - Times are 64-bit timebase values divided by 5 (signed `divd`; 50 MHz timebase to 100 ns units).
    - Speed names (0x91f3d098): 1 `2.4x`, 2 `5x`, 3 `8x`, 4 `12x`, anything else `Unknown`.
  - Ring (0x91fad0a0): +0 read index (writer only), +4 allocation index, +8 drop counter, +0x10 64 entries of 0x28 bytes, entry +0 state (0 free, 1 being filled, 2 ready). Allocation (0x91f3d2c0): index = atomic increment of +4; when it reaches 0x40 it is replaced by index mod 0x40 with a compare-exchange. Claim (0x91f3d330): compare-exchange state 0 to 1; failure increments the drop counter and drops the record. Publish (0x91f3d3b0): state 1 to 2, then set event 0x91fad050. The writer drains ready entries from the read index, frees each, then swaps the drop counter to 0 and writes `DROP,0x%08x\r\n` when it was nonzero.
  - Drive events arrive through the monitor control routine (see docs/re-notes/dispatcher.md): 0x46 `{sector, count}` (0x91f3d210) latches the read start and its timebase; 0x47 (argument = status, 0x91f3d6e0) produces `READ` when a read start was latched; 0x48 `{sector, size, ...}` (0x91f3d7a0) produces `GMNT`; 0x49 `{current, target, status}` (0x91f3d808) produces `SSC `; 0x4a (argument = authentication state) keeps states 1 to 4, else 0, in 0x91f9fda4. All records are skipped while 0x91f97660 == 1. 0x46 and 0x47 also emit `ODD ` records into the trace stream 0x91f788b8 when it is active (0x91f62758); that stream is separate from this log.
  - After a failed start (file or header failure), 0x91f97660 stays 0, so `oddlog stop` replies `200- stopped logging`. A failed ExCreateThread leaves event 0x91fad060 reset, so a later `oddlog stop` waits forever.
- Backend requirement: optical drive event hook (reads, mounts, spindle speed), background file writer.
- Status: spec complete.

## pclist

- Handler: 0x91f486b0. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `pclist` (no parameters).
- Behavior:
  1. ctx NULL: 0x80004005 (`400- `).
  2. scratch[0] (enumeration context) = 0, continuation 0x91f48630, return 0x02da0002 (`202- multiline response follows`).
  3. Continuation, per line: if ctx+0x14 == 0, end (0x82da0104, `.` sent). Else 0x91f2adf0 enumerates the next object of object directory `\DmCounters` (system process: created by XBDM; title process: opened); restart scan when context is 0. Line: `name="%s" type=0x%08x` with the object name and the 16-bit counter type at counter object +0xa. Enumeration end (STATUS_NO_MORE_ENTRIES) or missing directory returns 0x82da0104, which ends the list with `.`. Other failure: ctx+0x14 = 0 and the error is returned; the pump treats a negative result other than 0x82da0104 as a connection failure (connection closed without `.`).
- Capture: `pclist.capture` matches (`name="Frames" type=0x00000011`, `%... ` rate counters type 0x21, page counters type 0x1).
- Backend requirement: enumerate registered performance counters with name and type.
- Status: spec complete.

## pdbinfo

- Handler: 0x91f4d018. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `pdbinfo addr=<dword>` (module base address, required).
- Behavior:
  1. `addr` absent: hr = 0x80070057. Lookup 0x91f280d8 `(addr, info, lock=1)` failure: hr = its result. In both cases the text is `HRESULT 0x%X` of hr (overwriting `missing addr`) and hr is returned: `400- HRESULT 0x80070057`, `400- HRESULT 0x80070490`.
  2. Lookup: under spin lock 0x91fade68, find a loaded module with base == addr in list 0x91fade64 (node +0x18 = base), else in list 0x91fadec4. Read the debug directory (image directory 6). If any entry has type 2 (CodeView; little-endian field), the CodeView record address = base + byte-swapped AddressOfRawData of the first directory entry (offset 0x14), regardless of which entry matched. Record must start with `RSDS`; copy 16-byte GUID, 4-byte age, path (up to 0x104 bytes). No module, no directory, no CodeView entry or no `RSDS`: 0x80070490.
  3. resp_size <= 0x12c: 0x8000ffff (`400- unexpected error`); never true with 0x1fb.
  4. Success text: 32 upper-case hex digits of the GUID bytes in file order, 8 upper-case hex digits of the age bytes in file order, then the PDB path, no separators. `200- <hex40><path>`.
- Backend requirement: find a loaded module by base address and read its PE debug directory.
- Status: spec complete.

## perfstat

- Handler: 0x91f4d260. Access: 0x1 (read). all_of: 0. Extra: 0x0.
- Syntax: `perfstat` (parameters ignored).
- Behavior: `PerfFreq=0x%I64X` of KeQueryPerformanceFrequency, `200- PerfFreq=0x...` (upper-case hex, no padding). Formatting failure: 0x82da0105 (status 400, empty text); unreachable in practice.
- Backend requirement: high-resolution timer frequency.
- Status: spec complete.

## pixcmd

- Handler: 0x91f57fe0 (ends 0x91f58e8c). Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `pixcmd <L>[ <args>]`. L is the byte at line offset 7; the parser assumes exactly one space after `pixcmd`. Arguments start at offset 9. Most subcommands read arguments only when strlen(line) >= 9.
  - Argument parser 0x91f55300: unsigned decimal digits, wrapping; consumes the first non-digit; then spaces, HT and LF are skipped; NUL ends the list. A missing required argument yields `NO`.
- Behavior: every path returns 0x02da0000 except `r`. Reply text is `OK`, `NO`, or as listed. L outside `a`..`y` or without a case (`f i j l s x`): `200- NO`.
- Queue: most cases post a message (code, payload <= 0x50 bytes) to the PIX engine with 0x91f5f000. Fails when no PIX session exists (0x91fab7cc == 0) or the 8-entry queue is full. Code 0xc replaces the payload of a queued code 0xc message. Posted: `OK`; failed: `NO`.
- Status query 0x91f5f130 `(out[12], ver, flags)`: fails if ver == 0, `(flags & 3) == 0` or no session. out = {0x5308, s+0x54, s+0x5f8, s+0x600, s+0x5fc, (XamGetSystemVersion() & 0x1fffff00) >> 8, 0x91f5c4e0(), s+0x640 / 2^20, s+0x50 >> 31, s+0x5f0, s+0x2b4, s+0xc838}.
- Globals: ver 0x91fa2a80, flags 0x91fa2a88, old flag 0x91fa2a84, frame count N 0x91fa2a60, enable bitmap 0x91fa2a30, callback table 0x91fa2a3c (5 entries).

| L | Arguments | Action and reply |
| --- | --- | --- |
| a | none | post 5, payload 0x1c bytes {1, 0...}. |
| b | none | zero 0x91fa2a30/34, fill 0x12 floats at 0x91fa2898 with -1.0, zero 0x24 dwords at 0x91fa28e0 and 0x91fa2970, KeIpiGenericCall(0x91f56670, 1), allocate 64 KiB trace ring (pool tag `PIXs`, 0x91f63ba8). Always `OK`. |
| c | [n] | post 1, payload {n or 1 if 0, 1, 0}. |
| d | [a [b]] | b defaults to a; a = b = 0 if no args. If N > b, a > 0, b >= a: post 7, payload {N-a, min(b-a+1, 200), 1}. Else signal PIX event 6 (0x91f63f28), `OK`. |
| e | none | zero 0x91fa2a30/34, KeIpiGenericCall(0x91f56670, 0), free trace ring. `OK`. |
| g | none | post 0xb. |
| h | none | payload 0x1c {1, 0, 1, h, proc1, a5, proc3}: h = handle 0x91fa2aa8 if set, else XexLoadImage(`\Device\Flash\dogma.xex`, 8, 0); failure `NO`. a5 from 0x91f54f98(h), proc1/proc3 = XexGetProcedureAddress(h, 1 / 3). Any failure with a freshly loaded image: unload, `NO`. Post 5. |
| k | a b text | strlen >= 9 and three items required else `NO`. a to 0x91f98ef8, b to 0x91fa2a7c, rest of line copied without bound to 0x91fa280c, 0x91fa2808 = 0. Post 4, payload {0}. |
| m | n | 0x91f5f230(n) frame statistics; failure `NO`; else `OK %u %u %u`. |
| n | 8 hex chars | 0x91f553c0 reads exactly 8 chars (non-hex ignored): group = bits 16..20, id = bits 0..15. group 1: clear bit id in bitmap. group 2..6: call callback[group-2](0x10, id) if set. `OK`. |
| o | a f s [t u] | payload 0x30 {a, 2, 2, 2, 2, -1, 0, 0, min(s, 0x1400000), 0, t or 1, u or 0}; t requires u. f bit0 clear zeroes word1, bit1 clear zeroes word3, bit2 clear zeroes word4. If module `bootanim.xex` is loaded: `BUSY`. Post 6. |
| p | none | status query with ver/flags; if it succeeds, ver >= 0x17e5 and out[2] < 0x17e5: `OldD3D`. Else post 0xa. |
| q | ver flags | store ver and flags; old flag = (ver < 0x1964), propagated to 0x91fa2ce4. Status query fails or ver <= 0x1770: `NO`. Else `OK` and 11 `%u` values: out[0..7], out[10], out[8], out[9]. |
| r | none | 0x91fa2a5c = 0, sample counters into the ring (0x91f56810, uses counter `%Thread0 Idle`), then 0x91f63248: n = bytes queued in the ring (multiple of 4), text `OK %d` with n, return 0x02da0003: `203- OK <n>` then n bytes of ring data (wrapping copy), then the ring read pointer advances. |
| t | none | post 3, payload {0}. |
| u | [m [x [y [z]]]] | m == 99: `OK 1` if 0x91f98ef4 != -1 and 0x91fa2a74 != 0, else `OK 0`. Else payload 0x18 {m even ? 1 : 0, 0, (m == 2 or 3), x, y, z}; word2 also to 0x91fa2aa4. If word2 == 0 and status query succeeds with out[2] < 0x209e: `OldD3D`. Else post 0xf. Optional values are read without whitespace skipping. |
| v | [a b c d] | with args all four required. a == 1 and b == 1: payload {1, 1, c, d}; else {N-a, b-a+1, c, d}. Post 0xc. |
| w | [a [b [c]]] | b defaults to a, c to 0. Range check as `d`; pass: post 0xe, payload {N-a, b-a+1, c}; fail: event 6, `OK`. |
| y | 8 hex chars | as `n` but sets the bit; callbacks get 0x11. `OK`. |

- Client: `pix/session.rs` names the handler 0x91f56b88; in this image the table entry is 0x91f57fe0. The client describes the same letter switch with positional decimal arguments.
- Backend requirement: a PIX profiler engine (message queue, trace ring, frame statistics, D3D version info), kernel IPI to all processors, XEX image load and export lookup.
- Corrections from the disassembly: `d`, `v`, and `o` reply `BUSY` (not `NO`) when the post fails. `k` stores the first value before checking for the second. `q` stores the version before checking for flags. `h` with a cached handle (0x91fa2aa8) posts even when the export lookups fail. The letter at offset 7 and the eight characters of `n`/`y` are read without a length check, so stale receive-buffer bytes take part. `w` without arguments uses a = b = c = 0 (rejected range: event 6, `OK`).
- PIX session: created at init (0x91f5c560) only when XAM feature 0x22 is enabled (0x91f521a8); otherwise `Pix streaming disabled` and every post fails.
- Engine messages (processed by the title's frame thread at each frame boundary, 0x91f619d8; a handler that is not finished keeps the message and counts steps):
  - 1 `c` `{frames, notify, file}` (0x91f60ea8): per-thread capture on stream 0 for `frames` frames (needs frame record flag 1, else `PIX!BadD3dVersion` when notifying), then stop and write the frames of the dump partition to the file (or `unnamed.pix2`, created in `E:\pix`); notify `PIX!Timing` when written, else `PIX!NO`.
  - 3 `t` (0x91f61140): instruction trace (`e:\pix\unnamed.pix2`) of the frame thread for one frame, then `PIX!Trace`.
  - 4 `k` (0x91f61140): event trace mode; the event named by `k`'s text on hardware thread `a`, after `b` occurrences, is traced (0x91f557c0, 0x91f558e0); `PIX!Trace` when it ends, `PIX!NO` after 10 s.
  - 5 `a`, `h`, code 0x54 `{notify, file, plugin, image, installer, information, poll}` (0x91f60fb0): needs frame record flag 2 or a plugin (else `PIX!BadD3dVersion`); event trace mode with the capture file (header 0x0100001b) current until the next frame, or until the plugin's poll routine stops reporting 0x8000000a; end record 0x01000018, `PIX!Gpu`.
  - 6 `o` (0x91f61330): requested configuration `{parts[4], +0x10 second buffer mask, +0x14 flags, +0x1c, +0x20, +0x24 size}` and stream 1 size; applied with a restart; `PIX!NoHarddrive` when stream 0 was requested but no dump partition exists.
  - 7 `d` `{first, frames, 1}` (0x91f5eb00): write frames to `unnamed.pix2` (`PIX!Timing`, else `PIX!NoFrame`).
  - 8 (code 0x57 only) `{first, frames, begin, write, context, mode}` (0x91f614d0): frame extraction through the title's routines.
  - 10 `p` (0x91f617b0): pause the title (`PIX!Pause`): stop with an execution stop notification, keep the frame and audio threads running, play captured audio through a monitor XAudio client; messages 3/4 (`PIX!NO`), 6, 7, 8, 9, 12, 14 are handled while paused; 11 `g` resumes.
  - 12 `v` `{first, frames, operation, argument}` (0x91f61568): replay frames through the title's frame record routines (`PIX!VideoOp <argument> Update|Done <frame>`, `PIX!VideoOpError <code>`).
  - 13 (code 0x57) `{flag}`: pause flag (session `+0x50` bit 30).
  - 14 `w` (paused only, 0x91f5d360): frames and audio as movie data in `unnamed.pix2` (`PIX!MovieData`, else `PIX!NoFrame`); refused (trap) when not paused.
  - 15 `u` (0x91f5d270): resource capture start/stop through plugin exports 7/8 (`PIX!StartFailed ResourceCapture` / `PIX!NotActive ResourceCapture` without them) or state report in the frame record; sets the code 0x87 information.
  - 9 is refused (trap) outside the pause; 2 finishes at the second frame; 11 finishes at once.
- Status: spec complete (engine: `parity/performance.md`).

## pixpreview

- Handler: 0x91f62560. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: any; parameters ignored.
- Behavior: unconditional text `HRESULT 0x82da0017`, return 0x82da0017: `423- HRESULT 0x82da0017`.
- Backend requirement: none.
- Status: spec complete.

## playto

- Handler: 0x91f4a270. Access: 0x0. all_of: 0. Extra: 0x2 (407 on test kit).
- Syntax: `playto set enable=<string>` or `playto show`.
- Behavior:
  1. `set` flag present: `enable` must have a value (bare token does not match); absent: text `Invalid parameter: <full line>`, return 0x82da0017. command = 1 if the first character of the value equals `0` (case-insensitive compare of 1 char), else 0.
  2. Else `show` flag: command = 2. Neither: `423- Invalid parameter: <full line>`.
  3. XMsgStartIORequest(app 0xf0, message 0x900002, no overlapped, input {u32 command, u32 out_ptr, u32 8}, 0xc). out = {u32 xmp_heap, u32 playto}. Failure: `423- Invalid parameter: <full line>`.
  4. Read title and debug XNADDR (NetDll_XNetGetTitleXnAddr, NetDll_XNetGetDebugXnAddr). Text `XMP_HEAP: %s, PlayTo: %s [T:%u.%u.%u.%u / D:%u.%u.%u.%u]` with `ON` when the value is nonzero else `OFF`, and the first four bytes (IP address) of each XNADDR. `200- ...`. Text written with unbounded sprintf.
- Backend requirement: system message to the media (XMP) service to set/read the PlayTo state; title and debug IP addresses.
- Status: spec complete.

## pogoctrl

- Handler: 0x91f4a458. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: one of
  - `pogoctrl start [module=<dword>]`
  - `pogoctrl stop [module=<dword>]`
  - `pogoctrl snapshot [phase=<string>] [reset=<dword>] [module=<dword>]`
  - `pogoctrl allocscale module=<dword> scale=<dword>`
  First matching flag in the order start, stop, snapshot, allocscale. `module` is a record address in the instrumented-module list 0x91fa38b4 (0 = all). Absent dword parameters are passed uninitialized (stack contents). `phase` buffer 0x141, zero-filled; the buffer is passed to 0x91f70880 whether or not `phase` is present, so an absent phase is the empty string.
- Behavior: result hr; text `HRESULT 0x%08x`; return hr.
  - No subcommand: hr = 0x82da0000: `400- HRESULT 0x82da0000`.
  - start (export 108, 0x91f70630): for each matching record set +0x81 = 1 and, if +0x80 == 0, start counting (0x91f6c090). stop (export 109, 0x91f706d0): +0x81 = 0, then 0x91f6c140 unless +0x80. hr 0x02da0000, or 0x82da0017 when module != 0 is not in the list.
  - snapshot (0x91f70880 with kind 1, 0x91f70770 per record): stop counting, convert the phase from UTF-8 into record +0x290 (wcsncpy, 0x104 units) and set +0x84 = 1 (always, since the phase is never NULL here; an empty phase gives `<base>-!<n>.pgc`), set count block +0x5c = 1 and +0x5e = reset for an extended block, write the profile (0x91f6d420), clear +0x5c/+0x5e, with reset store the time and clear the counts (0x91f70e40), and restart counting, also for a module that was stopped. hr as start.
  - allocscale (0x91f70978): module 0 or not found: 0x82da0017; record +0x7c (the count block, allocated at registration) already set: 0x82da0019; else record +0x6c = scale, 0x02da0000. Since every registered record has a block, a registered module always gives 0x82da0019.
  - Profile writer 0x91f6d420: names `<base>` or `<base>-<phase>` with `!<n>.pgc`, n from 1 to the first that can be created; the module's directory first, then `\Device\Harddisk0\Partition1\DEVKIT`; writes min(count block +0xc, +0x54) bytes, flushes, seeks to 0x52 and writes the byte 1, closes. Write, flush, and close failures only print; when no file can be created anywhere the console stops (fatal `Unable to write PGC file`: debug print, then KeBugCheck(0x1e)). Details, including the name construction and the directory scan that never affects the number, in docs/re-notes/pgo.md.
  - Replies: `200- HRESULT 0x02da0000`, `423- HRESULT 0x82da0017`, `425- HRESULT 0x82da0019`.
- Backend requirement: the PGO runtime (module list, count blocks, profile writer); modules enter the list through export 112 called by instrumented titles. See docs/re-notes/pgo.md.
- Status: spec complete.

## prevflash

- Handler: 0x91f4e320. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `prevflash [prevflashver=<dword>]`, default 0.
- Behavior: ExSetXConfigSetting(category 0xa, setting 2, &value, 4); return map(status, 0x8000ffff): `200- OK` or the mapped error (`400- unexpected error` for unlisted statuses).
- Backend requirement: write a 4-byte persistent configuration setting.
- Status: spec complete.

## querypc

- Handler: 0x91f48750. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `querypc name=<string> type=<dword>`; name buffer 0x100.
- Behavior:
  1. ctx NULL: `400- `.
  2. `name` absent: `400- missing name`. `type` absent: `400- missing type`.
  3. Open counter object `name` in `\DmCounters` (0x91f2aa20): no directory: 0x82da0002 (`402- file not found`); open failure: 0x82da000e (`414- access denied`).
  4. Query 0x91f2aab0 `(handle, type, scratch)` fills `{u64 value, u64 rate, u32 type}`; handle closed. Counter object: +8 u16 source kind, +0xa u16 counter type, +0xc source pointer or callback, +0xc0 ring index, rings of 11 samples. Word at +8 = `kind << 16 | type`.
     - word bit 0x80000: copy 0x18 bytes from the source.
     - word bit 0x100000: callback(type, object, out).
     - `(word ^ type) & 0x30 != 0`: 0x82da0011 (`417- type invalid`).
     - `type & 0xfc0 == 0` and counter class != 0x20: instantaneous read 0x91f2a5a0 (kind 1 callback, kind 2/3 u32 value and rate, kind 4 u64 value and rate); out.type = class (type & 0x30). Failure 0x82da0012.
     - class 0 (else): n = type & 0xf or 1; value = sum of last n samples; rate = n; out.type = counter type.
     - class != 0: n = type & 0xf or 10; value and rate are differences between the newest sample and the sample n back; out.type = 0x110, 0x20, 0x210, 0x50 or 0x90 by class and type bits (0x40 selects x1000 scaling), OR n. Ring index < 0 or rate 0: 0x82da0012 (`418- data not available`).
  5. Success: ctx+0x14 = 1, continuation 0x91f486e8, text `counter data follows`, `202- counter data follows`, one line `type=0x%08x vallo=0x%08x valhi=0x%08x ratelo=0x%08x ratehi=0x%08x`, then `.`.
- Capture: `querypc.capture` (`type=0x00000000` for counter `Debugger Pages` queried with type 1) matches the instantaneous path.
- Backend requirement: read a named performance counter: current value, rate and sample history.
- Output buffer: the query writes into the connection scratch area (ctx+0x10), which `pclist` also uses (enumeration context in its first dword). The instantaneous path writes only value and type, so `ratelo`/`ratehi` repeat whatever the scratch area held (the previous query's rate on this connection).
- History (verified against the disassembly of 0x91f2aab0 and 0x91f2a670): the sampler (DPC 0x91f2af38, timer period 100 ms, ten period buckets) never advances the history index. The first valid sample sets index 0 and writes slot 0 eleven times; later samples rewrite slot 0 `period` times. Slots 1..10 stay zero, so history queries see the latest sample minus zero. `n` larger than 11 (type & 0xf up to 15) reads below the history: the registration word, list links, and object header.
- Class selection: class 0x10 with 0x200 gives 0x210; with 0x40 gives 0x50 and value x1000; otherwise 0x90. Class 0x20 gives 0x20; class 0x30 gives 0x210. `(type & 0x130) == 0x110` takes the rate from the frame-number history and gives 0x110. The class 0x20 sampler stores the source rate (failing the sample if its high dword is nonzero); other classes store the tick count.
- Status: spec complete.

## reboot

- Handler: 0x91f49cd8. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `reboot [stop] [wait] [smcreset]` (flags). `title`, `directory`, `cmdline`, `warm`, `cold`, `nodebug` belong to `magicboot` (0x91f49de0) and are ignored here.
- Behavior:
  1. ctx NULL: return 0 (no reply).
  2. Send `200- OK` on the connection socket, sleep 200 ms.
  3. If boot-wait mode 0x91fadec8 == 0: `stop` sets it to 2, else `wait` sets it to 1.
  4. 0x91f3b208: 0x91f975fc = 1, 0x91f9fd90 = 0, WriteIniFile, notification `execution rebooting`, close every command connection (0x91f41038), close every notification socket, further shutdown (0x91f27290).
  5. `smcreset`: HalReturnToFirmware(4). Else current IRQL < 2: HalReturnToFirmware(6); else HalReturnToFirmware(1). Does not return.
- Client disagreement: `system.rs` sends `reboot TITLE= DIRECTORY= CMDLINE= WARM STOP NODEBUG WAIT`; this image's `reboot` honors only STOP, WAIT, SMCRESET.
- Backend requirement: console reboot (normal and SMC reset), persistent boot-wait mode.
- Status: spec complete.

## recovery

- Handler: 0x91f473b0. Access: 0x8 (config). all_of: 0. Extra: 0x0.
- Syntax: `recovery`.
- Behavior:
  - ctx NULL (xbdm.ini): set bit 0x80 of 0x91fade6c (boot to recovery requested), return 0x80004005.
  - ctx present: 0x91fadd94 = 1 (the ini writer then emits a `recovery` line), then reboot core 0x91f278a8 `(flags 4, no title, conn)`: sends `200- OK`, sleeps 200 ms, 0x91fa2328 = 1, 0x91f3b208 (writes xbdm.ini, `execution rebooting`, closes connections), HalReturnToFirmware(6) at IRQL < 2 else (1). The `recovery` line in xbdm.ini is executed on the next boot without ctx.
- Backend requirement: persistent recovery-boot request, reboot.
- Status: spec complete. Bit 0x80 of the monitor flags 0x91fade6c has no reader in the image (other bits: 0x2 export 39, 0x10 `xbdm.ini` present, 0x20 0x91f4c33c, 0x40 dump written); the request has no further effect inside the monitor.

## rename

- Handler: 0x91f46370. Access: any_of 0x0, all_of 0x3 (read and write required). Extra: 0x0.
- Syntax: `rename name=<string> newname=<string>`; buffers 0x141.
- Behavior:
  1. `newname` absent: `400- missing new name`.
  2. Translate newname (0x91f2e888, drive name to object name); failure: `402- new name does not exist`.
  3. `name` absent: `400- missing name`.
  4. Open name via 0x91f2eb68 (access 0x40100000, disposition open, options 0x20); any failure, including translation failure: 0x82da000e (`414- access denied`).
  5. NtSetInformationFile class 0xa with {8 zero bytes, ANSI_STRING new object name}; close; counter 0x91f9feec incremented.
  6. 0xC00000D4: 0x82da0009 (`409- file must be copied`). Other failure: map(st, 0x82da000d). Success `200- OK`.
- Backend requirement: rename/move a file within one volume.
- Status: spec complete.

## resetnetra

- Handler: 0x91f46510. Access: 0x4. all_of: 0. Extra: 0x2.
- Syntax: `resetnetra`.
- Behavior: XMsgStartIORequest(app 0xef, message 0xa00004, no overlapped, input {2, 0, 0}, 0xc); result ignored; `200- OK`.
- Backend requirement: system message to the network-configuration service requesting a reset.
- Status: spec complete.

## resume

- Handler: 0x91f47ff8. Access: 0x4. all_of: 0. Extra: 0x2.
- Syntax: `resume thread=<dword>` (thread id, required).
- Behavior: absent: `400- missing thread`. ObLookupAnyThreadByThreadId failure: 0x82da0005 (`405- no such thread`). Else KeResumeThread (one suspend count), dereference, `200- OK`.
- Client: `debug.rs` sends `resume THREAD=0x...`.
- Backend requirement: decrement a thread's suspend count by id.
- Status: spec complete.

## rpc

- Handler: 0x91f3e7c8. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `rpc version=<dword> (system|title) buf_size=<dword> [processor=<dword>] [thread=<string>]`.
- Behavior:
  1. `version` absent: `200- error=Version is not specified, expecting major version 4`. version != 4 (unsigned compare): `200- error=Version mismatch, expected 4 but got <n>` (n signed decimal). Both are result 0x02da0000.
  2. Flag `system` is tested first; else flag `title` is required. Neither, or `buf_size` absent: 0x82da0017 (`423- bad parameter`). processor default 5. `thread`: up to 63 chars; absent: empty.
  3. Allocate buf_size + 0x68 bytes (tag `drpc`, 32-bit sum); failure 0x82da001c (`428- out of memory`). Block: +0 queue link, +4 abort flag 0, +8 system flag, +0xc thread object, +0x10 buf_size, +0x18 qword 0x3e5, +0x20 thread name, +0x60 done flag 0, +0x68 data (buf_size bytes).
  4. Empty thread name: ExCreateThread(start 0x91f3e630, context block, suspended, flags `(system ? 2 : 0) | ((1 << (processor & 63)) << 24) | 0x81`; processor 8..63 gives no affinity bits); failure: free, return `status | 0x10000000` (`400- `).
  5. ctx: buffer = block+0x68, size = remaining = buf_size, continuation 0x91f3e540. Text `buf_addr=%p`: exactly 8 upper-case hex digits, no prefix, for example `204- buf_addr=4A0012E8`. Client then sends buf_size bytes.
  6. Upload complete (also with buf_size 0): own thread: KeResumeThread. Named thread: block pushed at the head of list 0x91f9fda8 (LIFO, RTL critical section 0x91f9766c). Return 0x02da0003: `203- binary response follows`.
  7. Upload aborted (connection closed with data remaining): abort flag set; own thread: resumed and released, the thread frees the block; named thread: block freed.
  8. Call (0x91f3e630), big-endian qwords relative to buf_addr: +0x00 out result; +0x08 out return value; +0x10 in 1 = return last error, out last error; +0x18 flags (bit 0: double return); +0x20 n int args; +0x28 m double args; +0x30 module name pointer (0 = none); +0x38 function address, or export ordinal when a module is given; +0x40 n int qwords then m doubles. Loaded into r3..r10 and f1..f8 from two 8-slot frame arrays (+0xa0, +0xe0); n and m are not bounded: integers 9..16 land in the double slots, a 17th integer or 9th double overwrites the saved registers (stock defect, `parity/session.md`). Module: XexGetModuleHandle failure 0xFFFFFFFF8007007E, XexGetProcedureAddress failure 0xFFFFFFFF8007007F at +0x00 (sign-extended), done set, no call. Success: +0x08 = r3 or f1; +0x10 = last error (zero-extended) only when it was exactly 1; done flag set, then +0x00 = 0.
  9. 203 stream (0x91f3e460), per call: wait up to 100 ms for completion (own thread: wait on the thread object; named thread: poll the done flag every 10 ms). Not done: send 8 bytes `00 00 00 00 00 00 03 E5` and repeat. Done: send 8 zero bytes, then buf_size bytes of the buffer, then end (block freed without waiting for the runner, which stores +0x00 after the done flag). Wire sequence: zero or more markers, 8 zero bytes, buffer; no length prefix or terminator. With buf_size 0 the transfer ends after the first 8-byte send, which may be a marker.
  10. Named-thread drain: XBDM export 372 (0x91f3ea50), also reached through private API code 0xa8 (kernel data ordinal 89, block +0x18) with the thread name. It takes blocks whose name matches byte for byte, newest first, and runs each call in the draining thread; a busy queue lock (RtlTryEnterCriticalSection) ends the drain. No XBDM code issues 0xa8; titles or system libraries call it.
- Backend requirement: execute a function call with integer/float arguments in a system or title thread context, export lookup by module and ordinal, kernel buffer exposed by address.
- Status: spec complete. Unknowns: which title or system libraries issue code 0xa8. Implementation differences: `parity/session.md`.

## runnuioobe

- Handler: 0x91f4d850. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `runnuioobe [enabled=<string>]`; buffer 0xa.
- Behavior: enabled = 1 unless the value equals `off` or `false` (case-insensitive). Update 0x91f4d350(setting 0xc, mask 0x20000000, set = !enabled): kernel export ordinal 700 of `xboxkrnl.exe` (resolved at first use, cached at 0x91f9ff94) called as (3, 0xc, ~mask, set ? mask : 0); if unavailable (0xC0000138): ExGetXConfigSetting(3, 0xc) then OR mask (set) or AND ~mask (clear), ExSetXConfigSetting. Result ignored; `200- OK`. Disabling sets the bit; enabling clears it.
- Backend requirement: read-modify-write of a persistent console configuration flag word.
- Status: spec complete.

## runoobe

- Handler: 0x91f4d7a0. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax and behavior: as `runnuioobe` with mask 0x40.
- Backend requirement: as `runnuioobe`.
- Status: spec complete.

## runoobecheckpoint

- Handler: 0x91f4d900. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax and behavior: as `runnuioobe` with mask 0x8000.
- Backend requirement: as `runnuioobe`.
- Status: spec complete.

## screenshot

- Handler: 0x91f4b1e8. Access: 0x4. all_of: 0. Extra: 0x0.
- Syntax: `screenshot` (parameters ignored).
- Behavior:
  1. Stop execution (0x91f25be0, execution state machine): result 0x02da0000 (stopped now), 0x82da001a (already stopped or pending) or 0x82da000e; saved, does not fail the command.
  2. Wait up to 500 ticks while GPU register 0x7fc81740 bit 31 is set.
  3. VdGetCurrentDisplayInformation(info). base = reg(0x7fc86110) + 0xC0000000; pitch = align32(info.u16@0) * 4; x0 = info+8, y0 = info+0xc, x1 = info+0x10, y1 = info+0x14.
  4. State: width = x1-x0, height = y1-y0, format = 0x80000000 | (((reg(0x7fc86104) >> 8) & 7) ? 0x182801b6 : 0x18280186), offsetx = x0 & 0x1f, offsety = y0 & 0x1f, sw = info+0x18, sh = info+0x1c, colorspace = byte info+4, source = base + (y0 & ~0x1f) * pitch + (x0 & ~0x1f) * 128.
  5. framebuffersize = (align32(y1) - (y0 & ~0x1f)) * (align32(x1) - (x0 & ~0x1f)) * 4 (multiple of 0x1000).
  6. Allocate 0x2000 bytes; failure: resume if stopped now, `400- `. Else `203- binary response follows`.
  7. Stream (0x91f4b048): first a CRLF line `pitch=0x%08x width=0x%08x height=0x%08x format=0x%08x offsetx=0x%08x offsety=0x%08x, framebuffersize=0x%08x sw=0x%08x sh=0x%08x colorspace=0x%x`. Then framebuffersize bytes in chunks of up to 0x2000: 4 KiB tiles (32x32 pixels, GPU memory tile layout unchanged) in row-major tile order, tiles per row = ceil((offsetx + width) / 32); after each row the source advances by pitch * 32. Cache flush on each source page before and after the copy. End: free buffer, resume execution if this command stopped it.
- Details (disassembly of 0x91f4b1e8 and 0x91f4b048): the GPU wait is a busy loop over the tick count (KeTimeStampBundle +0x10) for at most 500 ms; the base is `reg(0x7fc86110) - 0x40000000`. The header is sent as a text line (ctx+4 = 0xffffffff). When framebuffersize is 0 the first continuation call ends the transfer, so no header is sent. Tile column = tpr - 1 - ((pages_left - 1) mod tpr); a zero tile count with pages left traps (divide by zero). A failed send calls the continuation with ctx+0x14 = 0, which frees the buffer and resumes the title.
- Capture: `screenshot_small.capture` is synthetic (framebuffersize 0x20, not a multiple of 0x1000). The client decodes the body as tiles.
- Backend requirement: stop/resume title execution, front-buffer address and display geometry, raw framebuffer read.
- Status: spec complete.

## sendfile

- Handler: 0x91f44ca0. Access: 0x2 (write). all_of: 0. Extra: 0x0.
- Syntax: `sendfile name=<string> length=<dword>`; name buffer 0x141.
- Behavior:
  1. ctx NULL: `400- `. `name` absent: `400- missing name`. `length` absent: `400- missing length`. length stored as remaining count (ctx+0x14).
  2. Name beginning with `\Device\` (case-insensitive) is used as an NT path (0x91f2ec08); otherwise translated (0x91f2eb68). Create with access 0x40110000, allocation size length, attributes 0, share 0, disposition 5 (overwrite-if), options 0. Failure: map(st, 0x82da000d).
  3. Set end of file to length (class 0x14). Then NtCreateEvent (initially signaled). Failure of either: mark delete-on-close (class 0xd), close, counter 0x91f9feec incremented, map(st, 0x82da000d).
  4. Allocate 0x8000-byte double buffer (tag `bdbd`); ctx buffer = first half, size 0x4000; mode bits 0x80000000, 0x20000000, 0x10000000, 0x08000000 cleared; continuation 0x91f448d8 (shared with other upload commands). Return `204- send binary data`. length 0: the pump runs once immediately.
  5. Upload: data accumulates in a 0x4000 half; each full half (or the remainder at the end) is written with asynchronous NtWriteFile at the running file offset after waiting for the previous write; halves alternate.
  6. Completion: wait, close, counter incremented, free buffer: `200- OK`. Write failure: delete-on-close, close, error bit set; final reply 0x8000ffff (`400- unexpected error`). Connection loss before all bytes arrive: delete-on-close and close.
- Client: `file.rs` sends `sendfile NAME="..." LENGTH=0x...`; `sendfile_small.capture` shows 204 then 200.
- Backend requirement: create/overwrite a file of known size and stream writes to it.
- Status: spec complete.
