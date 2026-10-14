# XBDM commands, group 2

Image: stock XBDM 2.0.21256.0, base 0x91f00000. Framework terms (conn, ctx, main thread, continuation, status derivation, HRESULT and NTSTATUS mappers) are defined in `framework.md`. Rules used throughout:

- A handler result of 0 sends no status line.
- Status text is the handler text if any was written, else the default text of the HRESULT (`framework.md` section 4). `400- ` with nothing after the space means a negative HRESULT without default text (for example 0x80004005).
- Access column: any_of mask (bits: 0x1 read, 0x2 write, 0x4 control, 0x8 config). all_of is 0 for every command in this group except `delete` (all_of 3: read and write both required). Failure: `414- access denied`.
- Extra 0x2: development-kit only; on a test kit (0x91f9f680 != 0) the command answers `407- unknown command`. Extra 0x1: allowed on a dedicated or title-serviced connection; all others answer `422- dedicated connection required` there.
- Parameter forms: `flag` = matched by 0x91f41638 with mode 0, so both a bare token `key` and `key=...` match. `string`, `dword`, `qword` = `key=value` only (a bare token never matches). Keys are case-insensitive. dword grammar: C `strtol` base 0 (see the established helper notes).
- Byte 0x1e appears literally in some response texts. The server does not translate it; it is sent raw inside the status line.

## confignetra

- Handler: 0x91f46658. Access: 0x4. Extra: 0x2.
- Syntax: `confignetra [show] [relaxheartbeat=<string>] [customubootaddr=<dword>]`.
  - `show`: flag.
  - `relaxheartbeat`: string, buffer 10 bytes (value truncated to 9 chars). `on` (case-insensitive) = on; any other value = off.
  - `customubootaddr`: dword.
- Behavior:
  - Request record (12 bytes): +0 operation (0 = get, 1 = set), +4 flags (bit 31 relaxheartbeat on, bit 30 customubootaddr valid), +8 customubootaddr. Descriptor passed to XAM (12 bytes): {5, pointer to record, 0xc}. Every call is `XMsgStartIORequest(0xef, 0x00a00004, 0, &descriptor, 0xc)`.
  - Show routine 0x91f46560: requires operation 0 (trap otherwise), sets record flags to 0, issues the request. Failure: text `\x1e%s (err 0x%p)\x1e` with `confignetra: failed to getting VE device config! Are you not running in DC mode?` and the XAM result; returns 0x8000ffff -> `400- <text>`. Success: text `\x1e%s\x1erelaxheartbeat=%s customubootaddr=0x%p\x1e` with `[Current VE configurations]`, `on` if flags bit 31 else `off`, record+8; returns 0x02da0000 -> `200- <text>`. `%p` (kernel `_snprintf`, ordinal 314, formatter at kernel 0x8014de48: precision 8, upper-case hex like `%X`) prints exactly 8 upper-case hex digits, zero padded: `customubootaddr=0x00000ABC`.
  - With `show`: show routine only.
  - Without `show`:
    1. Get request (operation 0, flags 0). Failure: same failure text, 0x8000ffff.
    2. For each key in order `relaxheartbeat`, `customubootaddr`: the key must first be present as a token (flag lookup), then parsed.
       - `relaxheartbeat=` present: flags bit 31 := (value equals `on` case-insensitively). Counts as one change.
       - `customubootaddr=` parses: record+8 := value, flags bit 30 := (value != 0). Counts as one change.
       Fields not given keep the values returned by the get.
    3. No change counted: text `\x1e%s\x1e` with `Usage: xbsetcfg /confignetra {relaxheartbeat=[on|off]} {customubootaddr=<address>}`; returns 0x82da0007 -> `407- <text>`.
    4. Set request (operation 1). Failure: failure text, 0x8000ffff. Success: operation := 0, show routine output and result.
  - State: none in XBDM; all state lives behind the XAM message service.
- Backend requirement: read and write the data-center network configuration (relaxed heartbeat flag, custom boot address) through a platform service; report service failure codes.
- Status: spec complete. The meaning of XAM service 0xef message 0x00a00004 beyond the record layout is behind the XAM service and not observable through this command.

## consolefeatures

- Handler: 0x91f4ce20. Access: 0x4. Extra: 0x0.
- Syntax: `consolefeatures` (no parameters).
- Behavior:
  - Feature word from 0x91f4cd60:
    - bit 0x1 (DEBUGGING): set when bit 0x02000000 of the first dword of kernel data export ordinal 342 is clear.
    - bit 0x4 (1GB_RAM): set when bit 0x00010000 of that dword is set.
    - bit 0x2 (SECONDARY_NIC): `XNetGetOpt(3, 0x2f00, buf, &len)` with a 6-byte buffer; set unless the result is 0xc00000c0 or 0x2726.
  - Text: empty, then appended in this order with a leading space each: ` DEBUGGING`, ` SECONDARY_NIC`, ` 1GB_RAM`.
  - Returns 0x02da0000. With flags: `200-  DEBUGGING 1GB_RAM` (two spaces after the dash). No flags: text empty -> `200- OK`.
  - No failure path is reachable.
- Cross-check: capture `consolefeatures.capture` shows `200-  DEBUGGING 1GB_RAM`; matches.
- Backend requirement: report whether the console is a debug-capable kit, whether a secondary network interface exists, and whether 1 GiB of RAM is installed.
- Status: spec complete.

## consolemem

- Handler: 0x91f50150. Access: 0x4. Extra: 0x0.
- Syntax: `consolemem`.
- Behavior:
  - Value from 0x91f50088: feature word as in `consolefeatures`. If 1GB_RAM (0x4) is clear: 0. Else `ExDebugMonitorService(8, buf, 0, 0)` with a zeroed 0x90-byte buffer where +0 = 0x90 and +4 = 0x68. Service failure or returned +0 < 0x90: 0. Else 2 if dword +0x7c < dword +0x08 (unsigned), else 1.
  - Kernel service 8 (kernel 0x800a8bc8, reached from `ExDebugMonitorService` 0x80089390 of the running kernel): requires +0 >= 0x90 and +4 == 0x68, fills a 0x68-byte memory statistics block at +4 (0x800a8a00), then +0x6c..+0x8c. +0x08 is the kernel's first statistic after the block length: the physical page count [INFERENCE: name from use; it is the only page total and is compared with a page count]. +0x7c is the constant 0x20000 (0x20000 pages of 4 KiB = 512 MiB). So 2 means the kernel manages more than 512 MiB of pages, 1 means a 1 GiB console whose kernel manages at most 512 MiB.
  - Text `consolemem=0x%x`; returns 0x02da0000 -> `200- consolemem=0x2`.
- Cross-check: capture `consolemem.capture` `200- consolemem=0x2`; matches. The client models the three values as `ConsoleMem::{Standard, ExtraMemoryUnused, ExtraMemoryInUse}`.
- Backend requirement: report the console memory configuration class (0, 1 or 2) derived from the installed memory and a debug-monitor memory query.
- Status: spec complete. Shared with `addtitlemem` (0x91f515e0).

## consoletype

- Handler: 0x91f4cf68. Access: 0x4. Extra: 0x0.
- Syntax: `consoletype`.
- Behavior:
  - Global 0x91f9f680 (test-kit state). 0 -> text `devkit`; nonzero -> text `testkit`. Returns 0x02da0000.
  - A third branch (`reviewerkit`, and an assertion with 0x80004005) is unreachable because the selector is 0 or 1.
  - 0x91f9f680 is written only at startup (0x91f32628): set to 1 when bit 0x02000000 of the ordinal-342 flags word is set (the same bit that clears DEBUGGING; at 0x91f3272c, which also sets dump mode 0x91f9f660 to 1 (`enabled`) unconditionally, before the settings file is read at 0x91f329cc), or on a second path when the I2C settings block read (0x91f4e648: up to three attempts of 0x91f4e378(0, 0x20)) fails, the top nibble of that flags word is >= 4, and 0x91f9f678 == 0 (0x91f9f678 is set by a settings-file keyword in 0x91f311b8 at 0x91f313d8; when set, the internal drive map 0x91f2f0f8 runs first). The second path also sets dump mode 1 when it is 0, reads 0x80 bytes of `\Device\Flash` (0x91f43708) and, when that succeeds and dword +0x10 of the buffer is nonzero, clears it, rewrites the flash (0x91f43778) and calls `HalReturnToFirmware(6)`.
- Cross-check: capture `200- devkit`; matches. The client enumerates only `devkit` and `testkit`.
- Backend requirement: report development kit versus test kit.
- Status: spec complete.

## continue

- Handler: 0x91f47f38. Access: 0x4. Extra: 0x0.
- Syntax: `continue thread=<dword> [exception]`.
  - `thread`: dword, required.
  - `exception`: flag.
- Behavior:
  1. `thread` absent: text `missing thread`, 0x80004005 -> `400- missing thread`.
  2. 0x91f25c60(thread, exception_present):
     - `ObLookupAnyThreadByThreadId` fails: 0x82da0005 (`405- no such thread`).
     - Acquire the execution-state lock (0x91f2d930); state 3 (`pending`), 4 (`reboot_title`) or 5 (`pending_title`): 0x82da0005.
     - Under the thread's spin lock, debug record = thread+0x15c:
       - No record: nothing changes, result 0x02da0000.
       - Record flags (+0x10) bit 0x8 (stopped) clear: 0x82da0008 (`408- not stopped`).
       - Else: if the execution state is 0 (stopped) and the record is not marked suspended (+0x34 == 0), `KeSuspendThread` and mark +0x34 = 1. If `exception` given, set flags bit 0x4. Clear bit 0x8. `KeSetEvent(record+0x1c)`. If flags bit 0x200 is set, after releasing the lock wait 1 ms (`KeDelayExecutionThread`).
     - Release lock, dereference the thread. Result 0x02da0000 -> `200- OK`.
- Cross-check: client sends `continue THREAD=0x%08x [EXCEPTION]`; key case is irrelevant. Disagreement: the client documents `EXCEPTION` as single-step. Stock only sets record flag 0x4 before waking the stopped thread; its effect is decided by the exception path that waits on that event (not in this command).
- Backend requirement: resume one debugger-stopped thread, optionally marking the pending exception as continued; keep it suspended while the whole title is stopped.
- Flag semantics (resolved from 0x91f25e20 and the exception dispatcher 0x91f39fc0): after the wait, 0x91f25e20 returns record flag 0x4 and clears 0xc. For a generic exception (notification type 9) the dispatcher returns "handled" only when that value is 0, so `exception` passes the exception on to the next handler; second-chance exceptions are handled either way. Breakpoint, assert, rip, and single-step paths ignore the value. Flag 0x200 is set while the thread is stopped at a breakpoint or data breakpoint; `continue` then sleeps 1 ms after releasing the lock so the stepped thread runs first.
- Status: spec complete.

## crashdump

- Handler: 0x91f498b0. Access: 0x4. Extra: 0x0.
- Syntax: `crashdump` (parameters ignored).
- Behavior:
  1. Sends `200- OK` directly on the connection socket (0x91f41528).
  2. Waits 200 ms (`KeDelayExecutionThread`, relative).
  3. 0x91f26888(0): `RtlCaptureContext(&ctx)`, then `DumpWriteDump(0, &ctx, 0)`.
  4. Returns 0: no further status line.
  - ctx is used without a NULL check (from xbdm.ini, the socket lookup would use a NULL-derived index) [derived from code].
- Backend requirement: write a full system crash dump of the console on request.
- Status: partial: whether `DumpWriteDump` returns (and what the console does afterwards) is decided in the kernel.

## datacentermode

- Handler: 0x91f4da50. Access: 0x4. Extra: 0x0.
- Syntax: `datacentermode [enabled=<string>]`; buffer 10 bytes.
- Behavior:
  - enable := 1 if `enabled` equals `on` or `true` (case-insensitive); otherwise (other value or absent) 0.
  - 0x91f4d350(0xd, 0x400, enable): calls kernel ordinal 700 (resolved at run time with `XexGetProcedureAddress` from `xboxkrnl.exe`) as `(3, 0xd, ~0x400, enable ? 0x400 : 0)` [read-modify-write of a configuration dword]. If that returns 0xc0000138: `ExGetXConfigSetting(3, 0xd, &v, 4, 0)`, v |= 0x400 or v &= ~0x400, `ExSetXConfigSetting(3, 0xd, &v, 4)`.
  - Result is ignored. Returns 0x02da0000 -> `200- OK` always.
- Backend requirement: set or clear bit 0x400 of console configuration setting (category 3, id 0xd).
- Status: spec complete.

## dbgextld

- Handler: 0x91f4f600. Access: 0x4. Extra: 0x0.
- Syntax: `dbgextld name=<string>` or `dbgextld unload module=<dword>`.
  - `unload`: flag. `module`: dword, required with `unload`. `name`: string, buffer 0x40.
- Behavior, unload:
  1. `module` absent: text `missing module`, 0x82da0017 -> `423- missing module`.
  2. 0x91f2e6e0: under critical section 0x91fae5a0. If module != the loaded handle (0x91fae600): 0x82da0017 (`423- bad parameter`). Else reference count (0x91fae604) -= 1; if it reaches 0 unload: clear OnTellDebugger pointer, wait (1 ms steps) until in-use count 0x91fae5bc is 0, call the extension `PrepareToUnload` export if present, clear name/handle, `XexUnloadImage(handle)`; NTSTATUS mapped with fallback 0x80004005. When run in the title process the unload runs on a new system thread and is waited for. Otherwise 0x02da0000.
- Behavior, load:
  1. `name` absent: text `missing name`, 0x82da0017 -> `423- missing name`.
  2. 0x91f2e5e0 under 0x91fae5a0:
     - An extension is loaded and its name equals `name` (case-insensitive): reference count += 1, same handle.
     - Another extension is loaded: 0x82da002b -> `443- ` (empty text).
     - None loaded: path `_snprintf("%s\\DMEXT\\%s", "\\Device\\Harddisk0\\Partition1\\DEVKIT", name)` into 0x6c bytes (truncated). `XexLoadImage(path, 0xc, 0, &handle)` (on a new system thread when called in the title process). Success: resolve exports `OnLoad`, `OnTellDebugger`, `PrepareToUnload` (0x91f33ce0), store name (0x91fae5c0), handle, count 1, call `OnLoad()` if present. NTSTATUS mapped with fallback 0x80004005 (for example `402- file not found` for a missing file).
  3. Success: text `module=0x%08x` (handle); 0x02da0000.
- State: one extension slot (0x91fae5c0 name, 0x91fae600 handle, 0x91fae604 refcount, 0x91fae608 OnTellDebugger, 0x91fae60c PrepareToUnload).
- Cross-check: client load parses `module=`; unload sends `unload module=0x...`; consistent. `nuances.md` notes a second load fails with 443; consistent.
- Backend requirement: load and unload one executable module from the DEVKIT `DMEXT` directory, call named entry points in it, return a module handle.
- Status: spec complete.

## dbgname

- Handler: 0x91f51440. Access: 0x0. Extra: 0x0.
- Syntax: `dbgname [name=<string>]`; buffer 0x15 (value truncated to 20 chars).
- Behavior:
  - No `name`: copy the stored name (0x91fab9c0) into the text; 0x02da0000. Empty name -> `200- OK`.
  - With `name`: privilege = conn access mask (conn+0xc), or 0xffffffff when ctx is NULL. Bit 0x8 (config) clear: 0x82da000e (`414- access denied`). Else copy 0x15 bytes to 0x91fab9c0, force byte 0x14 = 0, then:
    - 0x91f4e6b0: persist to the 0x20-byte SMC I2C settings block (offset 0): read the block (0x91f4e378); read failure: stop (nothing printed). If byte 0 < 2 or byte 0 == 0xff: byte 0 := 2, byte 1 := 0x20, changed. If byte 0xa (stored length) differs from the name length, or the first `length` bytes at 0xb differ: changed. If changed: byte 0xa := length, bytes 0xb.. := name, bytes 0xb+length..0x1e := 0 (byte 0x1f untouched), write the whole block (0x91f4e4e0); write failure prints `dm: I2C write failed.\n`.
    - 0x91f31e48: write xbdm.ini (skipped on CD boot, before settings load completes, or after the file was wiped; from the title process the server thread is signalled and waited for up to 1 s). The ini line is `dbgname name=<name>` without quotes (0x91f31a90), so a name containing a space loads back truncated at the space.
    - Returns 0x02da0000.
- SMC I2C transfers (0x91f4e378 read, 0x91f4e4e0 write; `HalSendSMCMessage`, kernel ordinal 41): offset < 0x100 and offset + length <= 0x100, else 0x82da0017. The transfer is split into chunks of at most 8 bytes (the first chunk ends at the next 8-byte boundary). 16-byte message: read: +0 0x11, +1 0x10, +2 chunk length, +3 0xd4, +5 0xd4, +6 offset; reply +1 == 0 is success, data at reply +3. Write: +0 0x11, +1 (length + 1) << 4, +3 0xd4, +6 offset, data at +7; after each message `KeDelayExecutionThread` 2 ms on success, 3 ms and `dm: I2C Write failed.  Error=0x%x, Addr=%d, DataLen=%d, \n` on failure. Each chunk is tried twice; a chunk failing both times returns 0x82da0002. Success 0x02da0000.
- Startup: 0x91fab9c0 has no initializer other than the settings-file `dbgname` line (and export `DmSetXboxName` 0x91f513c8, which writes xbdm.ini first and then the I2C block). The I2C block is never read back into the name.
- Cross-check: capture `200- deanxbox`; matches. Client quotes the name; stock removes quotes, so spaces are kept.
- Backend requirement: read and write the 0x20-byte SMC I2C settings block; the name itself is monitor state.
- Status: spec complete.

## dbgprint

- Handler: 0x91f3eee8. Access: 0x1. Extra: 0x2.
- Syntax: `dbgprint start=<any>` | `dbgprint stop=<any>` | `dbgprint [reset=<any>]`. All three are string parameters (buffer 0x141); value ignored. A bare `start`, `stop` or `reset` token is not recognized.
- Behavior:
  1. ctx NULL: 0x82da0017.
  2. `start=`: capture already started (0x91f9fdb0 != 0): text `Debug capture already started`, 0x80004005. Else 0x91f3ea90 allocates a 0x8000-byte buffer (tag `Xbdm`; failure 0x82da001c), clears write offset (0x91f9fdb4) and read cursor (0x91f9fdb8), publishes the buffer; text = default message of the result (`OK` or `out of memory`); returns it.
  3. Else `stop=`: 0x91f3eb30 detaches and frees the buffer, clears offsets; text `OK`; 0x02da0000.
  4. Else capture not started: text `Debug capture not started (use 'start' option to start capture)`, 0x80004005.
  5. Else stream: ctx scratch word 0 := 0x91f9fdb0; `reset=` present: read cursor := 0. ctx+0x14 := 1, continuation 0x91f3ee18, text `Debug print strings follow`, returns 0x02da0002 -> `202- Debug print strings follow`.
  - Continuation: ctx+0x14 == 0 ends. Else read the next record from the global read cursor (0x91f3ed28): start of buffer when cursor 0; a record ends after an LF or after 0x100 bytes, and stops at a NUL; when the scan reaches a NUL past the write offset it restarts once at the buffer start (stock loops without end when the restarted scan meets a NUL with no LF before it); no data -> ctx+0x14 := 0, 0x82da0104 (`.`). A trailing LF is removed.
  - Producer 0x91f3ebb0 (`printf`-style, 0x230-byte stack buffer, max 0x1ff chars per message): returns without action unless capture is active (0x91f9fdb0 != 0); messages are appended with their NUL, which the next message overwrites; a message that does not fit before the end of the 0x8000 buffer is written at offset 0. Its only callers are the CD-ROM / SATA patch routines (0x91f40088 `XBDM: Updating CD-ROM driver.`, `XBDM: Updated Channel ISR.`, `XBDM: Patched CD-ROM driver for Kernel (ver=%04d)`; 0x91f3f518 DmSataFindCdromChannelObject messages; 0x91f3f180, 0x91f3f2d0, 0x91f3f6f0, 0x91f3fcd0, 0x91f3fd34, 0x91f3fe50, 0x91f3ffc4).
  - The read cursor is global, shared by all connections.
- Backend requirement: an in-memory ring of internal monitor trace messages with start, stop, reset and streaming read.
- Status: spec complete.

## debugger

- Handler: 0x91f49620. Access: 0x4. Extra: 0x0.
- Syntax: `debugger connect|disconnect|init [addr=<string>] [port=<dword>] [name=<string>] [user=<string>] [override]`.
  - `connect`, `disconnect`, `init`, `override`: flags. `addr`: string (0x14 bytes), dotted IPv4. `port`: dword. `name`: string 0x80 bytes. `user`: string 0x10 bytes.
- Behavior:
  - Address A: `addr=` parsed by 0x91f41b80 (four decimal octets of up to 3 digits, `.` separated, NUL after the fourth; error -> 0). The first octet is stored in the least significant byte. Without `addr=`: `getpeername` of the connection socket; sin_addr as loaded (network order); 0 on failure or closed socket.
  - Debugger record 0x91f9fef8 (0x9c bytes): +0 attached, +4 address, +8 port, +0xc name[0x80], +0x8c user[0x10].
  - `connect`:
    1. If attached, port != 0, a notification target with (address, port & 0xffff) exists (0x91f38c08 over the 16 targets at 0x91fadb00), and `override` absent: 0x82da000a -> `410- file already exists`.
    2. attached := 1. `port=` present: address := A, port := value, changed. `name=` present: stored, changed. `user=` present: stored, changed. 0x91f975fc := 0. Changed: write xbdm.ini (0x91f31e48). 0x02da0000.
  - `disconnect`: if port != 0 and not (`port=` given equal to stored port and A == stored address) and `override` absent: 0x82da000e -> `414- access denied`. Else zero the record, 0x91f975fc := 1, write xbdm.ini, 0x02da0000.
  - `init`: `port=` present: address := A, port := value, changed. `name=`, `user=` stored if present (not counted as change). attached unchanged. Changed: write xbdm.ini. 0x02da0000.
  - None: text `no command`, 0x80004005 -> `400- no command`.
- Backend requirement: store the attached debugger identity (address, port, name, user) persistently; query notification targets; peer address of the command connection.
- 0x91f975fc is the kernel debugger routing flag of `kd` (initialized from ordinal 342 bit 0x80): `connect` clears it (exceptions are handled by xbdm and reported to the debugger), `disconnect` sets it.
- Settings line (0x91f3ce50, written only while attached): `debugger init addr=%d.%d.%d.%d port=0x%0.8x%s%s%s%s%s`, the address bytes taken low byte first (so a peer address from getpeername is written reversed), then ` name="`, name, `"` when the name is non-empty and ` user=`, user when the user is non-empty; truncated to 0x1ff characters.
- Status: spec complete.

## debugmemsize

- Handler: 0x91f50028. Access: 0x4. Extra: 0x0.
- Syntax: `debugmemsize`.
- Behavior: 0x91f4ff88 issues `ExDebugMonitorService(8, buf, 0, 0)` as in `consolemem`. Success and returned size >= 0x90: value = (dword +0x70 >> 8) & 0xfff; else 0. Text `debugmemsize=0x%x`; 0x02da0000.
- Kernel service 8 copies a kernel global into +0x70 (kernel 0x801fdbc4 in the image at hand); the command reports bits 8..19 of it unchanged.
- Backend requirement: report the debug memory size field (12 bits) from the debug-monitor memory query.
- Status: spec complete. The unit of the kernel global is not observable through this command [INFERENCE: 256-byte units, from the shift].

## debugmode

- Handler: 0x91f4b8e8. Access: 0x0. Extra: 0x0.
- Syntax: `debugmode`.
- Behavior:
  1. Global 0x91fab9a8 == 0: 0x82da0007 -> `407- unknown command`.
  2. ctx NULL: 0x80004005.
  3. conn access mask (conn+0xc) := 0xffffffff; 0x02da0000.
  - No instruction in the image stores to 0x91fab9a8 and no data word points at it; its initial value is 0. The stock monitor therefore always answers `407- unknown command`.
- Backend requirement: none (or optional full-privilege switch if the gate is enabled).
- Status: spec complete.

## dedicate

- Handler: 0x91f51838. Access: 0x0. Extra: 0x1.
- Syntax: `dedicate global` | `dedicate handler=<string>`. `global`: flag. `handler`: string, 0x100 bytes.
- Behavior: specified in `framework.md` section 6 (dedicate and 0x91f51640). Summary: ctx NULL -> 0x80070057 (`400- bad parameter`); `global` -> move connection to the main thread; `handler=` absent -> `400- missing handler`; unknown processor -> `402- file not found`; dedicate routine failure -> `400- `; success sends `205- connection dedicated` and returns 0 (no further line).
- Backend requirement: move a connection to another service thread or command processor.
- Status: spec complete (see `framework.md` for the open items of the dedicate routine).

## deftitle

- Handler: 0x91f47410. Access: 0x4. Extra: 0x0.
- Syntax: `deftitle none` | `deftitle launcher` | `deftitle dir=<string> name=<string>`.
  - `none`, `launcher`: flags. `dir`: string 0x104 bytes. `name`: string, remaining space of a 0x100-byte path buffer.
- Behavior:
  - Target file: `\SystemRoot\dashboard.xbx` (ANSI string at 0x91f9770c).
  - Always first: open it with `FILE_WRITE_ATTRIBUTES | SYNCHRONIZE` (options 0x20); if it opens, `NtSetInformationFile(FileBasicInformation)` with zero times and attributes 0x80 (normal), close. Errors ignored.
  - `none`: open with `DELETE | SYNCHRONIZE`, share 0, options 0x20. Open fails: 0x02da0000. Opens: set delete disposition; failure 0x8000ffff (`400- unexpected error`), success 0x02da0000.
  - Else build path P in a zeroed 0x101-byte buffer:
    - `launcher`: P = `\SystemRoot\xshell.xex`; file part starts after the last backslash.
    - Else `dir=` absent: text `missing dir`, 0x80004005. `dir` translated with 0x91f2e888 (DM drive path to object path); failure 0x82da0002 (`402- file not found`). Append `\` unless already last. `name=` read into the rest; absent: text `missing name`, 0x80004005.
  - Check P exists: `NtOpenFile(SYNCHRONIZE, share read, options 0x60)`. Failure: NTSTATUS mapped with fallback 0x82da000e.
  - Replace the backslash before the file part with `;`: content `<directory>;<file>`.
  - `NtCreateFile(dashboard.xbx, GENERIC_WRITE | DELETE | SYNCHRONIZE, attributes 0, share 0, FILE_OVERWRITE_IF, options 0x20)`. Failure: 0x80004005 -> `400- `.
  - `NtWriteFile` of exactly 0x100 bytes (content then NUL padding). Write failure: set delete disposition; result 0x02da0000 if that succeeds, 0x8000ffff otherwise. Write success: 0x02da0000.
- Backend requirement: write, replace or delete the persistent default-title selection (directory and executable name); check that a file exists.
- Status: spec complete.

## delete

- Handler: 0x91f46848. Access: 0x0 any_of, all_of 0x3. Extra: 0x0.
- Syntax: `delete name=<string> [dir]`. `name`: string, 0x141 bytes. `dir`: flag.
- Behavior:
  1. `name` absent: text `missing name`, 0x80004005 -> `400- missing name`.
  2. After an optional leading `x`/`X`, if the name is exactly `<c>:\` (drive root): 0x82da000e (`414- access denied`).
  3. Open: names starting with `\Device\` (case-insensitive) are opened as object paths (0x91f2ec08); others are translated (0x91f2eb68 via 0x91f2e888; translation failure gives NTSTATUS 0xc000000f). Access `DELETE | SYNCHRONIZE`, share 0, `FILE_OPEN`, options 0x21 (directory) with `dir`, 0x60 (non-directory) without.
  4. Open failure: 0xc00000ba -> text `is a directory`, 0x82da000e; 0xc0000103 -> text `not a directory`, 0x82da000e; other NTSTATUS mapped with fallback 0x82da000e.
  5. `NtSetInformationFile(FileDispositionInformation, delete = 1)`; failure mapped with fallback 0x82da000e (for example `411- directory not empty`), success 0x02da0000. Close. Counter 0x91f9feec += 1 after every successful open.
- Cross-check: client sends `NAME="..."` and bare `DIR`; matches.
- Backend requirement: delete a file or an empty directory by DM path or object path; distinguish file-versus-directory mismatch.
- Status: spec complete.

## detour

- Handler: 0x91f4ea10. Access: 0x4. Extra: 0x2.
- Syntax (all selectors are flags, checked in this order):
  - `detour log available`
  - `detour log getentries [count=<dword>]`
  - `detour entry acquire`
  - `detour entry release Id=<dword>`
  - `detour entry query Id=<dword>`
  - `detour entry setinfo Id=<dword> addr=<dword> paramsize=<dword> flags=<dword> return=<dword> [sleep=<dword>] [disccallfreq=<dword>] [OverlappedOffset=<dword>] [ExtendedError=<dword>]`
  - `detour start file=<string>` (0x104 bytes)
  - `detour stop`
  - `detour getstate`
- State: engine state 0x91f9f500 (0 idle, 1 starting, 2 running, 3 stopping); status 0x91f9f4f8; entry table 0x91f9f514 (0x34-byte entries), max index 0x91f9f510; free list 0x91f9f508; log write count 0x91f9f44c, read count 0x91f9f450; log read handle 0x91f9f344; log file name 0x91f9f348. 0x82da002a below means `442- ` (empty text).
- Behavior:
  - `log available`: state != 2: 0x82da002a. Else text `available=0x%x` (write count - read count); 0x02da0000.
  - `log getentries`: count default 0. state != 2: 0x82da002a. Else text `OK count=0x%x entrysize=0x%x` (count, 0x70); returns 0x02da0003 -> `203- OK count=... entrysize=0x70`. Binary continuation 0x91f2bc90: per call, if read count >= write count or byte budget (count * 0x70) is exhausted: end. Else `NtReadFile(log read handle, 0x70 bytes)`; error: end. Sends 0x70 bytes, budget -= 0x70, read count += 1. The stream may end before count entries; no length is sent.
  - `log` with neither: 0x82da0007.
  - `entry acquire`: state != 2: 0x82da002a. Pop a free entry; none: 0x82da001c (`428- out of memory`). Success: text `hresult=0x%x id=0x%x` (0x02da0000, entry id word); 0x02da0000. Failures carry no text.
  - `entry release`: `Id` absent: result 0x82da0017. Else 0x91f2ce68: state != 2 -> 0x82da002a; Id > max -> 0x82da0000; else log a type-6 record and return the entry to the free list, 0x02da0000. Text `hresult=0x%x` (result); returns result.
  - `entry query`: `Id` absent: result 0x82da0017. Else 0x91f2bb30: state != 2 -> 0x82da002a; Id > max -> 0x82da0000; else enterdetour = entry+0x10 word, scribble = that + 8, size = 0x50; 0x02da0000. Text `hresult=0x%x enterdetour=0x%x scribble=0x%x size=0x%x` (zeros on failure); returns result.
  - `entry setinfo`: first missing of `Id`, `addr`, `paramsize`, `flags`, `return`: result 0x82da0017. Optional values default 0. Else 0x91f2cf30: state != 2 -> 0x82da002a; Id > max -> 0x82da0000; else log a type-5 record (Id, flags, timebase, system time, addr, paramsize, return) and store into the entry: +4 addr, +8 paramsize, +0xc return, +0x14 flags, +0x18 sleep, +0x1c disccallfreq, +0x24 OverlappedOffset, +0x28 ExtendedError; 0x02da0000. Text `hresult=0x%x`; returns result.
  - `entry` with no sub-selector: 0x82da0007.
  - `start`: 0x91f2d330: state 0 -> 1 atomically, else 0x82da002a. Copies `file` (not checked for presence; an absent parameter leaves the buffer uninitialized) to 0x91f9f348, creates two system threads (0x91f2d040, 0x91f2d2b8; stack 0x8000). Thread creation failure: state := 0. Result = NTSTATUS mapped with fallback 0x82da000d. Text `hresult=0x%x`. Worker 0x91f2d040 requires an entry table (0x91f9f510 and 0x91f9f514 nonzero), allocates the record pool, opens the translated log file for write (`FILE_OVERWRITE_IF`, attributes 0x80, share 7) and again for read, then state 1 -> 2.
  - `stop`: 0x91f2cd08: state 2 -> 3 atomically, else 0x82da002a. Signals and waits for the workers, deletes the translated log file, frees resources, state := 0; 0x02da0000. Text `hresult=0x%x`.
  - `getstate`: text `state=0x%x status=0x%x` (0x91f9f500, 0x91f9f4f8); 0x02da0000.
  - None of the above: 0x82da0007.
  - Results with text: `hresult=0x82da0017` style texts are sent with the status of the result (for example `423- hresult=0x82da0017`, `442- hresult=0x82da002a`, `400- hresult=0x82da0000`). The Id bound check accepts Id equal to the maximum.
- Engine layout (init 0x91f2c458, called by module init 0x91f32628):
  - Entry table: 0x91f9f510 = 0x2e8 entries, 0x91f9f514 = pool block of 0x2e8 * 0x34 bytes (tag 'Detr', pool type 2), linked in id order on the free list 0x91f9f508 (+0x2c prev, +0x30 next; in-use list 0x91f9f50c). Entry: +0 id, +4 addr, +8 paramsize, +0xc return, +0x10 trampoline, +0x14 flags, +0x18 sleep, +0x1c disccallfreq, +0x20 call count, +0x24 OverlappedOffset, +0x28 ExtendedError. Acquire (0x91f2b9e0) pops the free head, pushes it on the in-use head, and clears +0x14..+0x20 (not the prev link). Release (0x91f2ba48) unlinks the entry, pushes it on the free head, and clears +0x14; releasing the free head itself makes it its own successor (the next two acquires return it twice). Lists are guarded by the critical section 0x91f9e4cc; the logger reads entries without it.
  - Trampolines: 0x2e8 * 0x58 bytes at 0x91f13230 in the code section, filled with 0x7c000038 (`and r0,r0,r0`) in the image. Init writes, through the dword writer 0x91f26da0, `li r12, id` (0x39800000 | id) and `b 0x91f13000` at +0 and +4 of each. The host fills the 0x50-byte scribble area at +8 (`entry query`) with the relocated start of the hooked function and a branch back, then patches the function to branch to `enterdetour`.
  - Entry stub 0x91f13000: frame 0xc0; locals at r1+0x50 (= entry sp - 0x70): +0 hook id (r12), +4 sequence, +8 call flags, +0xc paramsize, +0x10 function to call, +0x14 return value, +0x18..+0x58 r3-r10 (std), +0x58 overlapped pointer; LR saved at entry sp - 8. Calls the logger 0x91f2c6d0(locals, entry sp + 0x10, 0); calls 0x91f1313c if flags & 0x20 and 0x91f1319c if flags & 0x40; if +0x10 is nonzero calls 0x91f130ac(stub frame, paramsize), else returns +0x14; stores r3 at +0x14, logs notification 3, returns +0x14.
  - 0x91f130ac: allocates max(paramsize, 0x40) + 0x30 bytes below the stub frame (no alignment), copies `paramsize` bytes from entry sp + 0x10 to the new sp + 0x10, reloads r3-r10 (ld) from the locals, and calls +0x10.
  - 0x91f1313c: frame 0xc0, f1-f13 at +0x50, logger(locals, area, 1). 0x91f1319c: frame 0x120, `stvx vN` at offsets 0x50 + 8 * (N - 1); stvx ignores the low four address bits, so v1, v3, ..., v11 are overwritten by v2, v4, ..., v12, and +0xc0..+0x120 holds whatever the stack contained; logger(locals, area, 2) logs 0xd0 bytes from +0x50.
  - Logger 0x91f2c6d0 (asserts id < count and notify <= 3), notification 0 (0x91f2c8fc): call count += 1 (atomic); discard = entry flag 0x4 clear and (disccallfreq == 0 or count % disccallfreq == 0); locals +0xc = paramsize, +8 = entry flags, +0x10 = trampoline + 8, +0x14 = return value, +4 = ++0x91f9f504 (never reset); overlapped = 0 unless entry flag 0x400: with flag 0x800 the low word of the 8-byte slot at locals + (OverlappedOffset + 3) * 8 (register index; r3 = 0), else the low word of the 8 bytes at stack + OverlappedOffset; overlapped 0 clears call flag 0x400; discard: +0x10 = 0, flags |= 8; else flags = (flags & ~0xc) | 4. Then a type-0 record (flag 0x1000 set on success, cleared if no record), type-4 records when call flag 0x80 and entry flag 0x1 (one per 0x68 bytes of the parameter area, at least one), and with entry flag 0x100 a sleep of `sleep` ms.
  - Notification 1 / 2 (0x91f2c8d0 / 0x91f2c89c): when call flag 0x1000 and entry flag 0x1, one type-2 record of the f1-f13 area / two type-3 records of the vector area.
  - Notification 3 (0x91f2c768): a discarded call with an overlapped pointer returns 0x3e5 (ERROR_IO_PENDING), stores 0x3e5 at overlapped+0, references the event handle at overlapped+0xc (ObReferenceObjectByHandle, any type; never dereferenced), and queues a completion (status = return value, delay = sleep if entry flag 0x200 else 0, ExtendedError); without one it returns the configured value. Entry flag 0x200 without an overlapped pointer sleeps `sleep` ms. Entry flag 0x2 with call flag 0x1000 logs a type-1 record.
  - Records (0x70 bytes, big endian; fields a type does not write keep the content of the pool record's previous use; the pool is uninitialized at start): `+0 type, +4 sequence, +8 time base` (read twice when its low word is 0) for types 0, 1, 5, 6, 7, then:

    | Type | Producer | Fields |
    | --- | --- | --- |
    | 0 call | notification 0 | +0x10 system time, +0x18 id, +0x1c call flags, +0x20..+0x60 r3-r10 (call flag 0x10 and entry flag 0x1), +0x60 sleep (entry flag 0x100) |
    | 1 return | notification 3 | +0x10 id, +0x14 call flags, +0x18 return value, +0x1c sleep (entry flag 0x200) |
    | 2 floating point | notification 1 | +0x08..+0x70 f1-f13 |
    | 3 vector | notification 2 | +0x08..+0x70 0x68 bytes of the vector area (two records) |
    | 4 stack | notification 0 | +0x08..+0x70 0x68 bytes of the parameter area |
    | 5 setinfo | `entry setinfo` | +4 = 0, +0x10 system time, +0x18 id, +0x1c flags, +0x20 addr, +0x24 paramsize, +0x28 return |
    | 6 release | `entry release`; module unload (0x91f2c608) | +4 = 0, +0x18 id; module unload also +0x10 system time |
    | 7 completion | completion worker | +0x10 id, +0x14 call flags, +0x18 status, +0x1c ExtendedError, +0x20 system time |

    Types 2, 3 and 4 write +4 sequence and +0 type and copy 0x68 bytes to +8 (0x91f2c0f8).
  - Record log (0x91f9f328): 0x40 records (0x1c00-byte pool block) moved between a free queue 0x91f9f334 and a filled queue 0x91f9f338 (exports 302/304/308, capacity 0x41). Allocation 0x91f2be68 counts a user (0x91f9f33c), fails while 0x91f9f330 != 2, and otherwise retries until a record is free, waiting on event 0x91f9f4c8 with an absolute timeout of 100 ms after 1601 (it returns at once). Queuing (0x91f2c038) drops the user and sets event 0x91f9f4d8.
  - Writer thread 0x91f2d040: 0x91f2cb28 resets status, counters, users, handles, allocates the pool and queues, opens the translated file `GENERIC_WRITE`, attributes 0x80, share 7, `FILE_OVERWRITE_IF`, options 0x20 (status to 0x91f9f4f8), then `GENERIC_READ|SYNCHRONIZE`, `FILE_OPEN`; translation failure is 0xc000000f. Failure: state 1 -> 0, cleanup, set 0x91f9f4e8, exit 1. Success: 0x91f9f330 := 2, state 1 -> 2; while state == 2: wait 0x91f9f4d8, then write each queued record with one `NtWriteFile` (write count += 1 on success) and return it to the pool (set 0x91f9f4c8). After stop: while users != 0, queued records go back to the pool unwritten; then handles closed, 0x91f9f4e8 set.
  - Completion worker 0x91f2d2b8 (object 0x91f9e4e8: critical section, 0x40 slots of 0x38 bytes from +0x1c with a LIFO free list at +0xe1c linked through +0x34, work event +0xe20, stop event +0xe30, both synchronization events): waits on (work, stop); on work runs 0x91f2c2f8: each in-use slot whose due tick (TickCount at queue + delay) has passed is completed in slot order (0x91f2b8b8: overlapped+0x18 = ExtendedError, +4 = 0, sync, +0 = status, KeSetEvent(event)), logs a type-7 record if the call flag 0x1000 is set, and returns to the free list; with pending slots it waits 200 ms on the stop event and repeats while that times out, else resets the work event. Slot: +0 in use, +4 sequence, +8 id, +0xc call flags, +0x10 overlapped, +0x14 status, +0x18 due, +0x2c ExtendedError, +0x30 event object. No free slot: the request stays at 0x3e5 forever.
  - `stop` (0x91f2cd08/0x91f2cd54): 0x91f9f330 := 0 before the state check; state 2 -> 3; sets 0x91f9f4d8 and waits for 0x91f9f4e8; deletes the translated log (`NtDeleteFile`, attributes 0x40); sets the stop event, waits for and dereferences the completion thread; resets the slots (pending completions are dropped), both events; state := 0. Entries stay acquired.
  - Module unload (0x91f3a3e8 in the event dispatcher, after breakpoints in the range are removed): 0x91f2c608(base, size) releases every in-use entry whose addr lies in [base, base + size), logging a type-6 record with system time.
- Stock defects: `Id` equal to the entry count passes the bound check and reads past the table. A worker poll wait consumes the stop signal, so `stop` with delayed completions pending hangs. With two due completions in one pass, the second of which was not logged, the worker writes into and requeues the previous pass record.
- Backend requirement: executable trampoline memory in the module image, register-preserving stubs, a lock-free record queue, writer and completion threads, and a log file of 0x70-byte records.
- Status: spec complete.

## dirlist

- Handler: 0x91f46b80. Access: 0x1. Extra: 0x0.
- Syntax: `dirlist name=<string>`; 0x141 bytes.
- Behavior:
  1. ctx NULL or `name` absent (text `missing name`): 0x80004005.
  2. Scratch: +0 handle, +4 entry counter := 0. ctx+0xc := 0x200, ctx+8 := pool buffer of 0x200 bytes; allocation failure 0x8007000e (`400- out of memory`). ctx+4 := 0xffffffff, continuation 0x91f46a30.
  3. Open directory: `\Device\` prefix (case-insensitive) opens the object path directly, else translated path. Access `FILE_LIST_DIRECTORY | SYNCHRONIZE`, share read/write, `FILE_OPEN`, options 0x21. Failure: buffer freed, NTSTATUS mapped with fallback 0x82da000e.
  4. Success: 0x02da0002 -> `202- multiline response follows`.
  - Continuation: `NtQueryDirectoryFile(handle, ..., buf, 0x190, NULL mask, restart = (counter == 0))`, one entry per call. ctx+0x14 == 0 or query failure (including end of directory): close, free, 0x82da0104 (`.`). Else counter += 1; name length clamped to buffer size - 1; line:
    `name="<name>" sizehi=0x%x sizelo=0x%x createhi=0x%08x createlo=0x%08x changehi=0x%08x changelo=0x%08x` then ` directory` if attribute 0x10, ` readonly` if 0x1, ` hidden` if 0x2, in that order.
    size = EndOfFile, create = CreationTime, change = LastWriteTime; hi/lo are the high and low 32 bits. Names are not escaped.
  - Entries whose name does not fit the 0x190-byte query buffer end the listing (query error).
- Cross-check: capture `dirlist_devkit.capture` matches the format, including `sizehi=0x0` (not zero padded) and ` directory`.
- Backend requirement: enumerate a directory with size, creation time, last write time and attributes.
- Status: spec complete.

## discoverable

- Handler: 0x91f46cc0. Access: 0x4. Extra: 0x0.
- Syntax: `discoverable enabled=<string>`; buffer 10 bytes.
- Behavior: value `on` or `true` (case-insensitive): byte 1; `off` or `false`: byte 0; `ExSetXConfigSetting(7, 0xf, &byte, 1)` (result ignored), 0x02da0000. Absent or other value: 0x82da0017 (`423- bad parameter`).
- Backend requirement: set the persistent network-discoverable flag (configuration category 7, id 0xf).
- Status: spec complete.

## dmtelllog

- Handler: 0x91f4e870. Access: 0x4. Extra: 0x0.
- Syntax: `dmtelllog start file=<string> area=<dword> [block=<dword>] [size=<dword>] [entries=<dword>]` | `dmtelllog stop [area=<dword>]`. `start`, `stop`: flags; `file` 0x104 bytes.
- State: log handle 0x91fa1fe4, file handle 0x91fa1fe8, flags 0x91fa1fec, area mask 0x91fa1ff0, entry size 0x91fa1ff4.
- Behavior:
  - Flag `start` is tested first. `start`: `file` (0x104 bytes) or `area` absent: 0x82da0017 (`423- bad parameter`). block := (value != 0), absent 0; `size` and `entries` raw, absent 0. 0x91f51b30:
    - Log already open: area != 0 and (mask & area) == 0: mask |= area, result 0. Else result 0x420. `file`, `block`, `size`, `entries` are ignored.
    - Not open: path `\Device\Harddisk0\Partition1\DEVKIT\%s` (sprintf into a 0xd0-byte stack buffer); DbgPrint `DmTellLog: Open file = %s`; `NtCreateFile(GENERIC_WRITE | SYNCHRONIZE, attributes 0x40, file attributes 0x80, share read/write, FILE_OVERWRITE_IF, options 0x60)`. DbgPrint `Logging mask = 0x%x` follows whether or not the open succeeded. Open failure: DbgPrint `DmTellLog: Failed to open file 0x%x`, result 0. Else size 0 -> 0x80, entries 0 -> 0x200; create the log engine (export 356, processor 5, writer 0x91f51938, size, entries, block). Engine failure: DbgPrint `DmTellLog: Unable to start Log`, file closed. Result = engine status | 0x10000000 (success 0x10000000, no memory 0x9007000e). On success area mask := area, entry size := size.
  - `stop`: area default 0. 0x91f51c60: not open: 0x494. Else mask &= ~area (always stored); if the new mask is nonzero and area != 0: result 0, log stays open. Else set the closing flag, queue a one-byte record (the worker then writes the 0x2000-byte buffer), DbgPrint `DmTellLog: Closing Log: dropped %d messages, missed %d messages`, stop and destroy the engine, `NtFlushBuffersFile` (status ignored), `NtClose`; result = close status | 0x10000000.
  - Text `hresult=0x%x` (result); returns result. Result 0 sends no line at all (the client waits for a reply that does not come). Positive results (0x420, 0x494, 0x10000000) are sent as `200- hresult=0x...`; negative ones (0x9007000e) as `400- hresult=0x...`.
  - Neither flag: 0x82da0007.
  - Engine (log engine exports 355..364, `exports.md`): entry_size * entries + 0x160 bytes (tag `Detr`, no overflow check); a worker thread (affinity processor 5) takes records in order and calls the writer. `block` = 1: a producer waits for a free entry; `block` = 0: a full log drops the record and counts it as dropped. Records are copied as min(len, entry_size) bytes into reused entries without a terminator. Producer 0x88 and the stop's closing record go through export 363; stop reads the counters with export 364 and closes with export 360.
  - Writer 0x91f51938: static 0x2000-byte buffer; each record contributes its bytes up to the first NUL within entry_size bytes; the buffer is written (NtWriteFile, appending) only when a record would overflow it or at close. The file holds the concatenated record texts with no header, separator or terminator. A write failure ends the worker without signalling completion; a later `stop` then waits forever.
  - Producer 0x91f51d58 (private API code 0x88): record `{u16 Length, u16, u32 Buffer}`; ignored when the log is closed or closing, or Length or Buffer is 0; area is not checked per record. Codes 0x89 and 0x8a return the entry size and mask while open, else 0. XBDM's own producer is the critical section trace (codes 0x81/0x82, see `parity/session.md`).
- Backend requirement: a buffered log writer to a DEVKIT file fed by title/system log messages, with reference counting by area bits.
- Status: spec complete. Implementation differences: `parity/session.md`.

## dmversion

- Handler: 0x91f4cd30. Access: 0x4. Extra: 0x0.
- Syntax: `dmversion`.
- Behavior: text `2.0.21256.0` (0x91f079fc); 0x02da0000.
- Cross-check: capture `200- 2.0.21256.0`; matches.
- Backend requirement: none (constant).
- Status: spec complete.

## drivefreespace

- Handler: 0x91f4af60. Access: 0x1. Extra: 0x0.
- Syntax: `drivefreespace name=<string>`; 0x141 bytes.
- Behavior:
  1. `name` absent: text `missing name`, 0x80004005.
  2. ctx+0xc := 0x200, ctx+8 := 0x200-byte pool buffer; failure 0x80004005 (`400- `). ctx+0x14 := 1, continuation 0x91f4ae70.
  3. Open the translated path only (no `\Device\` case): `FILE_LIST_DIRECTORY | SYNCHRONIZE`, share read/write, `FILE_OPEN`, options 0x21. Failure: NTSTATUS mapped with fallback 0x82da000e (buffer not freed).
  4. 0x02da0002 -> `202- multiline response follows`.
  - Continuation: second call (ctx+0x14 was 0): close, free, 0x82da0104 (`.`). First call: `NtQueryVolumeInformationFile(FileFsSizeInformation, 0x18)`. Failure: text `unknown error (%d)`, 0x80004005; the pump closes the connection after the 202 line without a terminator. Success, with bpu = SectorsPerAllocationUnit * BytesPerSector (32-bit), total = TotalAllocationUnits * bpu, free = AvailableAllocationUnits * bpu (64-bit):
    `freetocallerlo=0x%08x freetocallerhi=0x%08x totalbyteslo=0x%08x totalbyteshi=0x%08x totalfreebyteslo=0x%08x totalfreebyteshi=0x%08x` with free, total, free.
- Cross-check: capture `drivefreespace.capture` matches (freetocaller equals totalfree).
- Backend requirement: volume total and available bytes for a drive or directory path.
- Status: spec complete.

## drivelist

- Handler: 0x91f4adc8. Access: 0x1. Extra: 0x0.
- Syntax: `drivelist`.
- Behavior:
  1. Scratch: +0 phase := 0, +8 enumeration context := 0. `NtOpenDirectoryObject(scratch+4, "\??")`. Failure: NTSTATUS mapped with fallback 0x80004005.
  2. ctx+0x14 := 1, continuation 0x91f4aac0; 0x02da0002.
  - Continuation (one line per call, ctx+8 is the pump's 0x100-byte buffer):
    - Phase 0: `NtQueryDirectoryObject(dir, buf, 0x10c, restart = (context == 0), &context)`. Entries whose name has length >= 2 and contains `:`: skipped if any drive-table entry name compares equal (case-insensitive) over the first (length - 1) characters of the object name (so `E:` is skipped because of table name `E`, and a one-letter name is skipped if any table name starts with that letter). Else `NtOpenFile(SYNCHRONIZE, root = \??, name = text up to and including ':', share 7, options 0x21)`; success: line `drivename="%*.*s"` with the text before ':'. Failing entries are skipped. Query failure: close the directory, context := 0, phase := 1.
    - Phase 1: walk the drive table 0x91f96bf8 (0x2c-byte entries: +0 object path prefix, +4 prefix length, +8 name[0x20], +0x28 enabled; ends at prefix 0). For enabled entries, open translated `<name>:\` (SYNCHRONIZE, share 7, `FILE_OPEN`, options 0x21); success: line `drivename="%s"`. Failure for name `F` or `SMB`: enabled := 0 permanently. End of table: 0x82da0104 (`.`).
    - ctx+0x14 == 0 on entry: close in phase 0, return 0x80004005 (connection closed).
  - Static table (enabled in image): `A`(0), `DVD`(1), `E`(1), `DEVKIT`(1), `U`(0), `NET`(0), `MU0`(1), `MU1`(1), `HDD`(1), `MUINT`(1), `INTUSB`(1), `USBMASS0MU`(1), `USBMASS1MU`(1), then `F`, `SMB`, `Y`, `Z`, `FLASH`, `MU0SYS`, `MU1SYS`, `USBMASS0`, `USBMASS1`, `USBMASS2`, `MEDIA`, `MUINTSYS`, `HDDSYSEXT`, `HDDSYSAUX`, `INTUSBSYS`, `INTUSBSYSEXT`, `INTUSBSYSAUX`, `INTMMC`, `INTMMCSYS`, `INTMMCSYSEXT`, `INTMMCSYSAUX`, `HDDVD`, `HDDVDMU`, `HDDVDSYS`, `TRANSFERCABLE`, `USBMASS0MUSYS`, `USBMASS1MUSYS` (all 0, prefix `\Badpath`). Enable flags can change at run time (drive mapping).
- Cross-check: `drivelist_360.capture` (`SysCache0..2` from `\??`, then `E`, `DEVKIT`, `HDD`, `MUINT`, `INTUSB` from the table) matches. `drivelist.capture` (`D`, `E`, `Z`) is from another console generation.
- Drive table updates: the image table above is the default. Initialization then appends a hidden entry named `\x01` (data 0x91f973a4) -> `\SystemRoot`, disabled, through 0x91f2ef60 (map/append by case-sensitive name; the row keeps the caller's target pointer and the target length at mapping time; NULL target moves the last row into the removed row; names `F` and `SMB` refresh the network share drive from XConfig instead; at most 42 rows plus the terminator, so `\x01` is row 40 and one more name fits). When the ini line `drivemap internal=<nonzero>` was read (0x91f9f678), 0x91f2f0f8 remaps: `DEVICE` -> `\Device` (0, appended), `Y` -> `\Device\Harddisk0\SystemPartition` (1), `Z` -> `\Device\Harddisk0\Partition1` (1), `FLASH` -> `\Device\Flash` (1), `MU0SYS`/`MU1SYS` -> `\Device\Mu0System`/`Mu1System` (0), `USBMASS0..2` -> `\Device\Mass0..2` (0), `MUINTSYS` -> `\Device\BuiltInMuSfcSystem` (0), `HDDSYSEXT`/`HDDSYSAUX` -> `\Device\Harddisk0\SystemExtPartition`/`SystemAuxPartition` (0), `INTUSB` -> `\Device\BuiltInMuUsb\Storage` (1), `INTUSBSYS*` -> `\Device\BuiltInMuUsb\StorageSystem`/`SystemExtPartition`/`SystemAuxPartition` (0), `INTMMC` -> `\Device\BuiltInMuMmc\Storage` (1), `INTMMCSYS*` likewise (0), `HDDVD` -> `\Device\HdDvdRom`, `HDDVDMU` -> `\Device\HdDvdStorage`, `HDDVDSYS` -> `\Device\HdDvdPlayer`, `TRANSFERCABLE` -> `\Device\TransferCable` (0), `USBMASS0MU`/`USBMASS1MU` -> `\Device\Mass0PartitionFile\Storage`/`Mass1...` (1), `USBMASS0MUSYS`/`USBMASS1MUSYS` -> `...\StorageSystem` (0). Path translation 0x91f2e888 ignores the enable flag: every row, enabled or not, translates.
- Translation detail (0x91f2e888): unknown drives first try `ObTranslateSymbolicLink` on `\??\` + the whole path (snprintf limit 0x104); on success a trailing `\` of the input is kept. On failure the output is `\??\` + the path with the drive name upper-cased, and translation still succeeds; the open then fails in the object manager (typically `0xc000003a`).
- Backend requirement: enumerate accessible drive names from the object namespace and the monitor drive table.
- Status: spec complete. The `\??` phase also lists any symbolic link with `:` not matched by a table prefix (for example a `Q:` link).
