# XBDM command group 8

Source: stock XBDM 2.0.21256.0, image base 0x91f00000. Addresses are virtual
addresses in that image.

## Conventions used in this file

Status lines are composed by 0x91f42028. A handler HRESULT in facility 0x2da
gives status 200+n (success) or 400+n (failure); a low word above 0xff, or any
HRESULT outside facility 0x2da, gives plain 200 (success) or 400 (failure).
The text after `NNN- ` is the handler text buffer when nonempty, else the
message from 0x91f41c98. Messages for codes used below:

| HRESULT | Status | Message from 0x91f41c98 |
|---|---|---|
| 0x02da0000 | 200 | `OK` |
| 0x02da0002 | 202 | `multiline response follows` |
| 0x02da0003 | 203 | `binary response follows` |
| 0x02da0004 | 204 | `send binary data` |
| 0x82da0002 | 402 | `file not found` |
| 0x82da0003 | 403 | `no such module` |
| 0x82da0004 | 404 | `memory not mapped` |
| 0x82da0007 | 407 | `unknown command` |
| 0x82da000a | 410 | `file already exists` |
| 0x82da000c | 412 | `filename is invalid` |
| 0x82da000e | 414 | `access denied` |
| 0x82da000f | 415 | `no room on device` |
| 0x82da0014 | 420 | `box is not locked` |
| 0x82da0017 | 423 | `bad parameter` |
| 0x82da001c | 428 | `out of memory` |
| 0x82da001d | 429 | empty |
| 0x82da0025 | 437 | empty |
| 0x82da0101, 0x82da0105 | 400 | empty |
| 0x80004005 (E_FAIL) | 400 | empty |
| 0x8007000e | 400 | `out of memory` |
| 0x80070057 | 400 | `bad parameter` |
| 0x8000ffff | 400 | `unexpected error` |

An empty message yields the line `NNN- ` (trailing space, nothing after).
0x82da0104 returned by a continuation ends a 202/203 transfer (`.` line for 202).

NTSTATUS to HRESULT conversion 0x91f41f18(status, default):
STATUS_SUCCESS -> 0x02da0000; 0xc0000008 -> 0x80070057; 0xc0000022 -> 0x82da000e;
0xc0000033 and 0xc0000039 -> 0x82da000c; 0xc0000034 and 0xc00000ba -> 0x82da0002;
0xc0000035 -> 0x82da000a; 0xc000003a -> 0x82da001e if default is 0x82da000d,
else 0x82da0002; 0xc000007f -> 0x82da000f; 0xc000009a -> 0x8007000e;
0xc0000101 -> 0x82da000b; any other value -> default.

Connection context (handler arg4) fields used here, per the framework notes:
+0 continuation function, +4 byte count (-1 = text line mode), +8 buffer
pointer, +0xc buffer size, +0x10 pointer to 0x58-byte per-connection scratch,
+0x14 set to 0xffffffff by the dispatcher before each handler; a 204 handler
stores the bytes to receive there; the pump stores 0 there on a send failure.
Handlers that check `arg4 == 0` return E_FAIL (`400- `) when invoked without
a connection (xbdm.ini processing).

Kernel exports resolved at run time use 0x91f729d8 (XexGetProcedureAddress on
the xboxkrnl.exe handle at 0x91faded0, or the xam.xex handle at 0x91fadecc).
It returns 0 when the ordinal is absent.

Settings persistence: 0x91f31e48 schedules a rewrite of `\SystemRoot\xbdm.ini`
(no effect during CD boot or before the ini has been loaded).

## threadstat
- Handler: 0x91f47e50. Access: 0x4. Extra: 0x0.
- Syntax: `threadstat handle=<n>`. `handle` is located with 0x91f41638 (third
  argument 0, so a bare `handle` token also matches). The value text is parsed
  with C `strtoul(s, NULL, 0)` (0x91f758d0): leading white space skipped, `0x`
  hex, leading `0` octal, else decimal; parsing stops at the first invalid
  character and is not validated. For a bare `handle` token, parsing starts at
  the delimiter after the token, so `handle 0x10` also yields 0x10.
- Behavior:
  1. No `handle` token: return 0x82da0017, `423- bad parameter`.
  2. ObReferenceObjectByHandle(handle, ExThreadObjectType). On failure the
     NTSTATUS is converted with RtlNtStatusToDosError and stored as the thread
     last-error value; the response is `200- Error 0x%x` with that Win32 code
     (for example 6 for an invalid handle).
  3. On success the exit code is read: if the low byte of the dispatcher
     header signal state (thread object +4, 32-bit word, low byte) is 0 the
     value is 0x103 (STILL_ACTIVE); otherwise the dword at thread object
     +0x140 (exit status). Object dereferenced.
     Response `200- Exit Code 0x%x`.
  Format strings `Exit Code 0x%x` and `Error 0x%x` are written with
  _snprintf(arg2, arg3, ...). Always returns 0x02da0000 after a token is found.
- Handle resolution (K15574 ObReferenceObjectByHandle 0x800b5a48, K16547
  0x800b5dd8):
  - 0xfffffffe (`NtCurrentThread`) with a thread or NULL object type
    references the calling thread without a table lookup: `200- Exit Code
    0x103`.
  - Other handles are looked up in the table ObpGetCurrentObjectHandleTable
    selects (K15574 0x800b5e70, K16547 0x800b6200): the title table
    (ObTitleObjectHandleTable, K15574 0x801fe1a0, K16547 0x801fdd20) when
    KeGetCurrentProcessType returns 1, else the system table
    (ObSystemObjectHandleTable, K15574 0x801fe160, K16547 0x801fdce0). The
    process type is the byte at process +0x2f, copied to thread +0x73
    (KeInitializeProcess stores 1 for KeTitleProcess and 2 for
    KeSystemProcess). The handler runs on the server thread, which
    ExCreateThread flags 0x040004a6 place in KeSystemProcess (flag 0x2,
    K15574 0x80088ca8), so the lookup uses the system handle table; a
    title's handles do not resolve.
  - An unknown handle calls RtlRip(`Invalid handle specified`) and returns
    0xc0000008; a handle of another object type calls
    RtlRip(`Invalid handle type specified`) and returns 0xc0000024. Both
    become Win32 error 6.
- Backend requirement: resolve a thread handle in the system process
  handle table and report whether the thread has terminated and its exit
  status.
- Status: spec complete.

## title
- Handler: 0x91f47210. Access: 0x4. Extra: 0x0.
- Syntax: `title [nopersist] | title name=<str> [dir=<str>] [persist] [cmdline=<rest of line>]`.
  - `nopersist`: flag (bare token or key=value).
  - `name`: string, required unless `nopersist`; copied into 0x100 bytes
    (max 255 chars).
  - `dir`: string, optional, max 255 chars.
  - `persist`: flag.
  - `cmdline`: located with third argument 1 (`cmdline=` form only). The value
    is not copied with the string grammar: the raw remainder of the command
    line from the character after `=` to the end of the line, quotes and any
    later tokens included, is used (truncated to 255 chars). It must therefore
    be the last parameter.
  - `flags`: dword, honored only when arg4 == 0 (ini load); stored at
    0x91fa2324 and written to the ini as ` flags=0x%08x`.
- Behavior (network path, arg4 != 0):
  1. `nopersist` present: clear the persisted title strings (first byte of
     0x91fa232c image, 0x91fa242c drive, 0x91fa252c command line), write the
     ini twice (WriteIniFile at 0x91f472b8 and 0x91f4739c), return `200- OK`.
     All other parameters are ignored.
  2. `name` absent: text `missing name`, return E_FAIL: `400- missing name`.
  3. Resolve image and drive with FGetImageAndDrive 0x91f44608(name, dir):
     - `dir` present and nonempty: dir is translated with the XBDM path to
       object path routine 0x91f2e888 (requires `DRIVE:\...` form; drive table
       at 0x91f96bf8; unknown drives go through `\??\DRIVE:` symbolic link
       translation) into the drive string; image = drive string + `\` (added
       if missing) + name.
     - otherwise: drive = empty, image = 0x91f2e888(name).
     - translation failure or overflow while copying dir: `402- file not found`.
     - trace bit 8: on entry `[xbdm] FGetImageAndDrive(\n   szTitle='%s',\n   szDir='%s',\n   ...)\n`
       (`(null)` without `dir`); overflow texts `[xbdm] FGetImageAndDrive buffer
       overflow copying path\n`, `... appending '\\'\n`, `... appending title\n`
       (a name that does not fit is cut and the call still succeeds); at the
       end `[xbdm] FGetImageAndDrive succeeded:\n   oszImage='%s'\n   oszDrive='%s'\n`
       or `[xbdm] FGetImageAndDrive failed:\n`.
  4. FTitleExists 0x91f447c8(image, 0): images whose first 14 chars match
     `\device\cdrom0` (case-insensitive) are accepted without a check; others
     must open with NtOpenFile(SYNCHRONIZE, share read,
     FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE). Failure:
     `402- file not found`. Trace bit 8: `[xbdm] FTitleExists(oszImage='%s',fPostBoot=%s)\n`
     on entry and `[xbdm] FTitleExists() returning %s\n` after the open
     (`TRUE`/`FALSE`); a disc image accepted without the open has no second text.
  5. If `persist`: persisted strings 0x91fa232c = image, 0x91fa242c = drive,
     0x91fa252c = cmdline (each 0x100 bytes, forced NUL at byte 0xff, empty
     when absent).
  6. Always: current title strings 0x91fa2020 = image, 0x91fa2120 = drive,
     0x91fa2220 = cmdline (same limits). WriteIniFile (0x91f4712c). `200- OK`.
  7. The handler writes the ini again (0x91f4739c) whatever step 3 to 6
     returned, so a successful `title` writes it twice; with trace bit 4 each
     write prints its WriteIniFileImpl and echo texts.
- Behavior (ini path, arg4 == 0): `flags` applied first. `nopersist` clears the
  persisted strings (a debug assertion `!fLoadingIni` fires). Otherwise `name`
  is used directly as the image object path and `dir` (unprocessed, may be
  absent) as the drive; steps 4 to 7 apply. While the saved settings file runs
  both writes stop at the load gate (bit 4 text `XBDM: WriteIniFile - not
  finished loading`); `recint.ini` lines run after the gate opens.
- Ini output (0x91f51ed0): when the persisted image is nonempty,
  `title persist name="<image>"` + ` dir="<drive>"` if nonempty +
  ` cmdline="<cmdline>"` if nonempty + `"`... the writer emits
  `title persist name="` image, then `" dir="` drive, then `" cmdline="`
  cmdline, then `"`. When the current image is nonempty: `title`, optional
  ` flags=0x%08x` (if 0x91fa2324 != 0), ` name="` image, `" dir="` drive if
  nonempty, `"`, then ` cmdline=` + cmdline if nonempty.
- Consumers: boot title selection 0x91f52260 uses the current title unless it
  is empty or 0x91fa2328 is set (set by the reboot path 0x91f278a8); otherwise
  it uses the persisted title for boot types 0 and 4.
- Backend requirement: store a launch title (image object path, drive object
  path, command line) for the next reboot, with an optional persistent
  default; check that a file exists; persist settings.
- Client cross-check: `Title::Set` sends `title NAME="..."` and
  `Title::NoPersist` sends `title NOPERSIST`; both expect a 200 line.
  Consistent.
- Status: spec complete.

## traceimports
- Handler: 0x91f4fb38. Access: 0x4. Extra: 0x0.
- Syntax: `traceimports modulename=<str> [enabled=<str>]`.
  - `enabled`: string, max 9 chars; enable = 1 only if the value equals `on`
    (case-insensitive); otherwise and when absent, enable = 0.
  - `modulename`: string, max 0x103 chars, required.
- Behavior:
  1. `modulename` absent: return E_FAIL, `400- `.
  2. Resolve xboxkrnl ordinal 719 (0x2cf) through 0x91f729d8
     (`XexGetProcedureAddress`; 0 on failure) and call it as
     fn(modulename, enable). The address is not checked: an absent export
     branches to address 0 on the server thread, which has no exception
     handler (no `.pdata` handler on the dispatch path), so the monitor
     crashes and no reply is sent.
  3. Return value 0: DbgPrint `[xbdm] module '%s' is not a valid choice\n`;
     return E_FAIL, `400- `.
  4. Nonzero: DbgPrint `[xbdm] %s tracing for module %s, title reboot required
     to activate\n` with `enabled` or `disabled`; return `200- OK`.
- Backend requirement: configure kernel import tracing for a named module,
  taking effect at the next title launch.
- Status: spec complete.

## usbportctrl
- Handler: 0x91f501b0. Access: 0x8. Extra: 0x0.
- Syntax: `usbportctrl controller=<dword> port=<dword> (enable | disable)`.
  `enable` and `disable` are flags (bare or key=value); `enable` is tested
  first.
- Behavior:
  1. Resolve xboxkrnl export ordinal 825 (0x339). Absent: `414- access denied`.
  2. `controller` absent or unparsable: `423- bad parameter`.
  3. `port` absent: `423- bad parameter`.
  4. Neither `enable` nor `disable`: `423- bad parameter`.
  5. Call fn(controller, port, enable ? 1 : 0). Result NTSTATUS >= 0:
     `200- OK`. Negative: return status | 0x10000000 (for example 0xc0000001
     becomes 0xd0000001), which yields `400- `.
- Backend requirement: enable or disable power on a USB controller port.
- Status: spec complete.

## user
- Handler: 0x91f40f68. Access: 0x10. Extra: 0x0.
- Syntax: `user name=<str> remove` or `user name=<str> [read] [write] [control] [config] [manage]`.
  - `name`: string, max 63 chars, required.
  - `remove`: flag.
  - Privilege flags (0x91f40940, each bare or key=value): `read` 0x1,
    `write` 0x2, `control` 0x4, `config` 0x8, `manage` 0x10.
  - `passwd`: qword (`0q` + hex), honored only when arg4 == 0 (ini load).
- Behavior:
  1. `name` absent: `400- missing name` (E_FAIL).
  2. `remove`: under critical section 0x91facf20, open the user object by
     name in the user object directory (handle 0x91f9fecc, object type
     0x91f976a8, attributes 0). Not found: `402- file not found`. Found:
     ObMakeTemporaryObject and drop both references; schedule ini rewrite;
     `200- OK`. The lock state is not checked.
  3. Add (0x91f40680):
     - lock flag 0x91fab9ac == 0: `420- box is not locked`.
     - user already exists: `410- file already exists`.
     - ObCreateObject (type 0x91f976a8, name in directory 0x91f9fecc,
       attributes 0x10, body 0x10 bytes) failure: `400- out of memory`.
     - ObInsertObject failure: `400- out of memory`.
     - body: +0 qword password, +8 dword privileges, +0xc dword
       password-present flag (1 only for ini load with `passwd`; network
       requests always store 0 and an unspecified password qword).
     - handle closed, ini rewrite scheduled, `200- OK`.
- Backend requirement: persistent store of named users with privilege masks;
  lock state query.
- Name rules (xboxkrnl K15574 ObpLookupElementNameInDirectory,
  ObpComputeHashIndex, ObCreateObject, ObInsertObject,
  NtQueryDirectoryObject, RtlUpperChar; K16547, the console's kernel, has
  the same code, see `parity/security.md` "User directory"):
  - Lookup is case-insensitive (RtlCompareString with case folding):
    a-z and 0xe0-0xfe except 0xf7 fold to upper case; 0xff folds to `?`.
  - The directory has 13 buckets; bucket = h % 13 with h = (c | 0x20) +
    (h >> 1) + 3h over the name bytes below 0x80. New entries go to the
    head of their bucket. Enumeration (`userlist`, settings lines) visits
    buckets 0..12, each chain from its head; the context is a global entry
    index.
  - Names are paths relative to the directory: an empty name, a leading
    backslash, or an inner backslash never reaches a user (lookups fail;
    adding fails with `400- out of memory`); one trailing backslash is
    dropped (`name=bob\` is `bob`).
- Status: spec complete.

## userlist
- Handler: 0x91f4bf00. Access: 0x10. Extra: 0x0.
- Syntax: `userlist` (no parameters).
- Behavior:
  1. Lock flag 0x91fab9ac == 0: `420- box is not locked`.
  2. arg4 == 0: E_FAIL.
  3. Scratch dword (enumeration context) = 0; continuation 0x91f4be90;
     return `202- multiline response follows`.
  4. Each continuation call: if ctx+0x14 == 0 (send failure) end. Otherwise
     0x91f40e38: NtQueryDirectoryObject on directory 0x91f9fecc (0x4c-byte
     buffer, restart when the context dword is 0). STATUS_NO_MORE_ENTRIES
     (0x8000001a), lock cleared, or no directory handle: end (0x82da0104).
     Other failure: end. The entry name is copied into a zeroed 0x104-byte
     buffer and looked up again to obtain the privilege mask; lookup failure
     ends the list.
  5. Line: `name="%s"` followed by ` read`, ` write`, ` control`, ` config`,
     ` manage` for each set bit 0x1, 0x2, 0x4, 0x8, 0x10, in that order.
     No password is printed. Terminated by `.`.
- Backend requirement: enumerate stored users with privilege masks.
- Status: spec complete.

## vd
- Handler: 0x91f24130. Access: 0x3. Extra: 0x0.
- Syntax: `vd cmd=<str> ...`. `cmd` string, max 31 chars, compared
  case-insensitively.
  - `cmd=peek addr=<dword>`
  - `cmd=poke addr=<dword> data=<dword>`
  - `cmd=gpeek addr=<dword>`
  - `cmd=gpoke addr=<dword> data=<dword>`
  - `cmd=edid block=<dword>`
- Behavior. Every failure writes `HRESULT 0x%x` (lowercase hex, no padding)
  into the response text and returns that HRESULT, so the line is
  `NNN- HRESULT 0x<code>`.
  - `cmd` absent: `423- HRESULT 0x82da0017`.
  - Unrecognized `cmd` value: `200- OK`, no action.
  - peek: `addr` absent or >= 0x300: 423. addr < 0x100:
    VdReadDVERegisterUlong(addr), `200- 0x%08x`. 0x100 <= addr < 0x300: if
    flag 0x91fadd90 is 0, `404- HRESULT 0x82da0004`; else
    VdReadDVERegisterUlong(addr), `200- 0x%02x` of the low byte.
  - poke: `addr` absent or >= 0x300: 423. `data` absent: 423. addr > 0xff and
    data > 0xff: 423. addr < 0x100: VdWriteDVERegisterUlong(addr, data) (full
    32-bit data). Otherwise flag 0x91fadd90 == 0: 404; else write one byte via
    0x91f23f00: SMC message 0x11 (HalSendSMCMessage) carrying an I2C write of
    one byte to device 0x39 (addr 0x100..0x1ff) or 0x3d (addr 0x200..0x2ff),
    sub-address = addr low byte; for addr 0x1d0..0x1f5 the write is bracketed
    by 0x91f23e40 / 0x91f23ea0. An SMC error is only reported via DbgPrint
    `BD: Failed to write I2C bus address %X, error code %d\n`. Response
    `200- OK`.
  - gpeek: `addr` absent or > 0xfffc: 423. Reads the dword at
    0x7fc80000 + addr * 4 (GPU register index); `200- 0x%08x`.
  - gpoke: same `addr` checks; `data` absent: 423. Stores the dword at
    0x7fc80000 + addr * 4. `200- OK`.
  - edid: `block` absent or > 0xff: 423. Resolve xboxkrnl export ordinal 623
    (0x26f); absent: `407- HRESULT 0x82da0007`. Set continuation 0x91f24018,
    ctx+0x14 = 0x80, ctx+0xc = 0x80, allocate 0x80 bytes (0x91f330e0) into
    ctx+8; allocation failure: `400- HRESULT 0x82da0105`. Call fn(block,
    buffer); result 0: `429- HRESULT 0x82da001d` (buffer not freed). Nonzero:
    `203- binary response follows`, then exactly 128 bytes (one EDID block).
    The continuation sends 0x80 bytes once, then frees the buffer and ends.
  - Flag 0x91fadd90 is set at init to 1 when VdReadDVERegisterUlong(0xfe)
    >= 0x10000, else 0.
- Backend requirement: read and write video encoder registers (primary bank
  and the I2C-attached extended bank), read and write GPU MMIO registers, read
  a 128-byte EDID block from the attached display.
- Status: spec complete.

## verbose
- Handler: 0x91f4d140. Access: 0x8. Extra: 0x0.
- Syntax: `verbose level=<dword>` (required).
- Behavior:
  1. `level` absent: `400- missing level` (E_FAIL).
  2. Stores the value into the debug trace mask 0x91f9fef4, schedules an ini
     rewrite, `200- OK`. The ini writer emits `verbose level=%d` when the mask
     is nonzero.
  Bits observed in this image: 0x1 DbgPrint every status line
  (`XBDM(thr=0x%0.8x): R=%s\n`); 0x4 ini read/write trace; 0x8 path, file
  and title resolution trace; 0x20 media/device initialization messages.
- Backend requirement: a settable diagnostic trace mask, persisted.
- Status: spec complete.

## walkmem
- Handler: 0x91f47c38. Access: 0x4. Extra: 0x0.
- Syntax: `walkmem` (no parameters).
- Behavior:
  1. arg4 == 0: E_FAIL.
  2. Text `Valid Virtual Address Ranges Follow`; scratch dword (address cursor)
     = 0; ctx+0x14 = 1; continuation 0x91f47b38; return 0x02da0002, so the
     header line is `202- Valid Virtual Address Ranges Follow`.
  3. Region iterator 0x91f33e48 (cursor-based):
     - Page step: 4 KiB when the address is <= 0x3fffffff or in
       0x90000000..0x9fffffff; 64 KiB otherwise. A step goes to the next
       aligned page of that size.
     - While cursor < 0xa0000000: if MmIsAddressValid(cursor), extend the end
       pointer page by page while the page is valid and not inside one of the
       excluded ranges (inclusive): 0x7fc80000-0x7fc9ffff,
       0x7fd00000-0x7fdfffff, 0x7fea0000-0x7feaffff, 0x7fed0000-0x7fedffff,
       0x8fff0000-0x8fff0fff, 0x8fff1000-0x8fff1fff. If end > cursor a region
       [cursor, end) is reported. The cursor then moves to the page after end
       (or after cursor when the page was invalid or excluded).
     - protect = 0x40 when base is in 0x80000000..0x9fffffff, else 0x04.
     - Cursor >= 0xa0000000 with no region: end of list.
  4. Each line: `base=0x%0.8x size=0x%0.8x protect=0x%0.8x` (8 lowercase hex
     digits each). The continuation packs as many 52-byte lines as fit in the
     pump buffer per call; on wire each region is one CRLF line. Terminated
     by `.`.
- Backend requirement: enumerate valid virtual address ranges of the target
  below 0xa0000000, excluding device MMIO windows.
- Client cross-check: `WalkMem` parses `base= size= protect=` lines; capture
  `walkmem.capture` shows the same header and protect=0x00000004 for low
  ranges. Consistent.
- Status: spec complete.

## welcomedefault
- Handler: 0x91f4fc48. Access: 0x4. Extra: 0x0.
- Syntax: `welcomedefault [enabled=<str>]`. `enabled` string max 9 chars;
  enabled = 0 if the value equals `off` or `false` (case-insensitive), else 1
  (also when absent).
- Behavior: 0x91f4d350(setting 0xc, mask 0x08000000, set = !enabled):
  1. Call xboxkrnl export ordinal 700 (0x2bc, cached at 0x91f9ff94) as
     fn(3, 0xc, ~mask, set ? mask : 0).
  2. If that export is absent (STATUS 0xc0000138): ExGetXConfigSetting(category
     3, setting 0xc, 4 bytes); on success set or clear the mask bit and
     ExSetXConfigSetting.
  The result is ignored. Response `200- OK`.
  The bit is set when `enabled` is `off`/`false` and cleared otherwise.
- Backend requirement: set or clear a bit in a persistent console
  configuration dword (category 3, setting 0xc).
- Status: spec complete.

## welcomehide
- Handler: 0x91f4fcf8. Access: 0x4. Extra: 0x0.
- Syntax: `welcomehide [enabled=<str>]`, same grammar as welcomedefault.
- Behavior: identical to welcomedefault with mask 0x04000000. Bit set when
  `enabled` is `off`/`false`, cleared otherwise. `200- OK`.
- Backend requirement: as welcomedefault.
- Status: spec complete.

## writefile
- Handler: 0x91f454f8. Access: 0x2. Extra: 0x0.
- Syntax: `writefile name=<str> offset=<dword> length=<dword>`; all required.
  `name` max 0x140 chars.
- Behavior:
  1. arg4 == 0: E_FAIL.
  2. `name` absent: `400- missing name`.
  3. `offset` absent: `400- missing offset`.
  4. `length` absent: `400- missing length`. The value is stored directly in
     ctx+0x14 (bytes to receive).
  5. Open: if `name` begins with `\Device\` (case-insensitive) it is used as
     an object path (0x91f2ec08); otherwise it is translated with 0x91f2e888
     (failure gives STATUS 0xc000000f). NtCreateFile(access 0xc0100000
     GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE, OBJ_CASE_INSENSITIVE,
     AllocationSize = length, attributes 0, share 0, disposition FILE_OPEN,
     options 0 (asynchronous)). The file must exist.
  6. NtSetInformationFile(FilePositionInformation, offset as a 64-bit value
     with high dword 0).
  7. NtCreateEvent (notification, signaled).
  Failures in 5 to 7 close the handle and return 0x91f41f18(status,
  0x82da000e): object name not found gives `402- file not found`, invalid
  name gives `412- filename is invalid`, other failures typically
  `414- access denied`.
  8. Scratch: +0 handle, +4 0x8000-byte buffer (two 0x4000 halves; allocation
     not checked), +8 bytes in current half = 0, +0xc bytes written = 0,
     +0x10 event, +0x14/+0x18 I/O status, +0x20 64-bit file offset = offset,
     +0x28 flags: 0x20000000 set (write-at mode), 0x80000000, 0x10000000 and
     0x08000000 cleared. ctx+8 = buffer, ctx+0xc = 0x4000, continuation
     0x91f448d8. Return `204- send binary data`.
  9. Receive continuation 0x91f448d8 (shared with sendfile): received data is
     staged into 0x4000-byte halves and written with NtWriteFile at the
     running 64-bit offset (explicit ByteOffset), double buffered. In write-at
     mode a failing write closes the file and sets the error flag but does not
     delete the file; remaining bytes are still consumed. The file is not
     truncated or extended beyond the data written and attributes are not
     changed. When all `length` bytes are received the file is closed, the
     event closed, the buffer freed, and the text `%lu bytes written` is
     produced with the number of bytes successfully submitted. Final status:
     `200- <n> bytes written`; after a write error the continuation returns
     0x8000ffff, so the line is `400- <n> bytes written`.
- Backend requirement: open an existing file by XBDM or object path and
  write a byte range at a 32-bit offset from a streamed upload.
- Client cross-check: `FileUploadKind::WriteAt` sends
  `writefile NAME="..." OFFSET=<dec> LENGTH=<dec>` and expects 204 then 200.
  Disagreement: the client accepts u64 offset and size; the server parses
  32-bit dwords and seeks with the high dword 0, so offsets >= 4 GiB are not
  representable.
- `length=0`: the framework runs the receive pump once immediately; the
  writer submits a zero-byte write, closes the file and replies
  `200- 0 bytes written`. A write failure counts only whole 0x4000-byte
  halves submitted before it.
- Status: spec complete.

## xbeinfo
- Handler: 0x91f490c8. Access: 0x4. Extra: 0x0.
- Syntax: `xbeinfo running` or `xbeinfo name=<str> [ondiskonly]`.
  `running` flag is tested first; when present `name` is ignored. `name` max
  0x140 chars.
- Behavior:
  1. arg4 == 0: E_FAIL.
  2. Neither `running` nor `name`: `400- missing name`.
  3. Allocate 0x114 bytes; failure `400- out of memory`.
  4. 0x91f33c38(name or NULL, buffer, ondiskonly):
     - `ondiskonly` set: opens the named file (GENERIC_READ|SYNCHRONIZE,
       FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPEN) via path translation, ignores
       the result, leaves any handle open, and returns `402- file not found`
       unconditionally.
     - otherwise (`running`, or `name` without `ondiskonly`, regardless of
       the name): takes the running executable object path from the xboxkrnl
       data export ordinal 431 (`RtlInitAnsiString` of the NUL-terminated
       string), converts it with 0x91f2e750 into the 0x105-byte path buffer
       (below), and sets timestamp = 0, checksum = 0.
  5. Continuation 0x91f48fc8; `202- multiline response follows`, lines:
     `timestamp=0x%08x checksum=0x%08x` (both 0 in this build), then
     `name="<path>"` (no escaping), then `.`.
- Reverse translation 0x91f2e750(ANSI string, out, size); xbeinfo passes
  size 0x105, export 107 passes 0x104 (0x91f3e09c):
  - Rows of the drive table 0x91f96bf8 (+0 target pointer, +4 target
    length, +8 name) are scanned in table order until a row with a null
    target. A row matches when its target length L is at most the input
    length and `_strnicmp` (0x91f75508, ASCII case folding in the C locale)
    finds the first L characters equal. The enabled flag (+0x28) is not
    tested, and nothing has to follow the prefix: target `\Device\Mu0`
    matches `\Device\Mu0x\a.xex`.
  - First match: output = row name (all of it, unchecked) + `:` + the input
    after the first L characters, the remainder cut to size - 2 - name
    length characters, then NUL. No match: the input cut to size - 1
    characters, then NUL.
  - With the image table the first rows decide common paths:
    `\Device\Cdrom0\...` gives `A:\...` (row `A`, disabled, precedes
    `DVD`), `\Device\Harddisk0\Partition1\DEVKIT\...` gives `E:\...`, and
    `\Device\Harddisk0\Partition1\...` gives `HDD:\...`. No row has the
    target `\Device\Flash`, so `\Device\Flash\xshell.xex` is returned
    unchanged.
- Backend requirement: report the object path of the running title
  executable.
- Client cross-check: `xbeinfo_running.capture`:
  `timestamp=0x00000000 checksum=0x00000000`, `name="\Device\Flash\xshell.xex"`.
  Consistent. `XbeInfo::Named` will receive the running title's data, not the
  named file's.
- Status: spec complete.

## xexfield
- Handler: 0x91f492e8. Access: 0x4. Extra: 0x0.
- Syntax: `xexfield module=<str> field=<dword>`; both required. `module` max
  0x140 chars.
- Behavior:
  1. arg4 == 0: E_FAIL.
  2. `module` absent: `400- missing module`.
  3. `field` absent: `400- missing field`.
  4. Query 0x91f342f0(module, field, NULL, 0, &size) under the module list
     spin lock:
     - module lookup 0x91f33fb0(name, exact): case-insensitive exact match
       against loader entry base names (Unicode, +0x2c/+0x30), with fallback
       0x91f33628. Not found: `403- no such module`.
     - RtlImageXexHeaderField(module XEX header (+0x58), field) NULL:
       `437- ` (0x82da0025).
     - size by field low byte: 0x00 -> 0 except field 0x10100, which reports
       size 4 and returns the inline dword value itself; 0x01 -> 4;
       0xff -> first dword of the field data (blob length including that
       dword); other n -> n * 4.
  5. size 0: `200- OK`, no data.
  6. Allocate size bytes; failure `400- out of memory`. Query again to copy
     (truncation would give 0x82da0105). Failure frees and returns the HRESULT.
  7. Continuation 0x91f491f8, ctx+0x14 = size + 4;
     `202- multiline response follows`. Lines: `fieldsize=0x%08x`, then the
     data as uppercase hex, 32 bytes (64 hex chars) per line, the last line
     shorter, then `.`.
- Backend requirement: enumerate loaded modules by name and read optional
  header fields from their XEX headers.
- Status: spec complete.

## xhttpproxy
- Handler: 0x91f37ab0. Access: 0x4. Extra: 0x0.
- Syntax: `xhttpproxy [name=<str> [port=<dword>] [certsize=<dword>] [cert=<hex>]] [sys | sysonly] [force] [temp]`.
  - `name`: string max 255 chars. `port` and `certsize` are parsed only when
    `name=` is present (absent `port` = 0, absent `certsize` = 0).
  - Nonempty name requires port 1..0xffff; `name=""` requires port 0 (or
    absent). Otherwise `423- bad parameter` (no text).
  - `sysonly` implies sys; `sys`, `force`, `temp` are flags.
  - `cert`: key=value only; optional leading `"` skipped; pairs of hex digits
    (either case) until space, `"` or NUL.
- State: list head 0x91f975f0/0x91f975f4 protected by critical section
  0x91f975d8 inside a critical region. Entry: +0/+4 links, +8 flags,
  +0xc reference count, +0x10 consumer count, +0x14 name pointer, +0x18 port,
  +0x1c certificate pointer, +0x20 certsize, +0x24 name then certificate
  storage. Flags: 0x80000000 sys, 0x40000000 sysonly, 0x20000000 active,
  0x10000000 temp, 0x08000000 force, 0x04000000 certificate pending.
- Behavior:
  1. Find the active entry of the same scope (0x91f37800: sys bit equal).
     If found: clear active, decrement reference, free when reference and
     consumer counts are 0; text part A = `cleared`; ini rewrite needed if
     that entry was not temp. Else part A = empty.
  2. No name (and not `name` nonempty) and no `force`: result 0x02da0000.
  3. Otherwise allocate certsize + strlen(name)+1 (0 if no name) + 0x24
     bytes; failure 0x82da001c. Fill entry (reference 1), copy name and port,
     insert at the list head as active.
     - certsize 0: part B = ` applied`; ini rewrite if not temp; 0x02da0000.
     - `cert=` present: decode hex into the certificate area; more bytes than
       certsize, an invalid digit, or an odd digit count give 0x82da0007;
       decoded length != certsize gives 0x82da0007. On error the entry is
       unlinked and freed. Success: part B = ` applied`, ini rewrite if not
       temp, 0x02da0000.
     - certsize > 0 without `cert`: set certificate pending, reference + 1,
       scratch = {entry, received 0, certsize}, ctx+8 = certificate area,
       ctx+0xc = ctx+0x14 = certsize, continuation 0x91f37918; part B =
       ` applying`; return 0x02da0004.
  4. Ini rewrite scheduled when needed and arg4 != 0.
  5. Text: success `%hs%hs` (A, B); failure `err=0x%08x %hs%hs`.
     Examples: `200- OK` (nothing to clear, nothing set), `200- cleared`,
     `200-  applied`, `200- cleared applied`, `204-  applying`,
     `407- err=0x82da0007 cleared`, `428- err=0x82da001c `.
  6. Certificate receive 0x91f37918: copies received bytes up to certsize.
     Zero bytes received (connection failure): drop the entry if still
     active, end with 0x82da0101 (`400- `). Complete: clear pending, drop the
     extra reference, ini rewrite if not temp, `200- OK`.
- Ini output (0x91f37f18), for active, non-temp, non-pending entries:
  `xhttpproxy<S><F>` without name; `xhttpproxy<S> name="%s" port=%u<F>`; with
  certificate `xhttpproxy<S> name="%s" port=%u<F> certsize=%u cert=` followed
  by uppercase hex, where S is ` sysonly`, ` sys` or empty and F is ` force`
  or empty.
- Backend requirement: store HTTP proxy settings (host, port, optional
  certificate) per scope (title or system) for consumption by the network
  stack, persisted.
- Lookup 0x91f37800(sys, command): walks from the head (newest first) and
  returns the first active entry whose sys bit equals `sys`; with
  `command` 0 (title queries) a non-sys request also accepts a sys entry
  that is not sysonly.
- Consumers: the private API dispatcher 0x91f3b4d0 (jump table 0x91f03dc8,
  base 0x91f3b528):
  - code 165 (0x91f380f8): request `{type, ?, out name, out port, in/out
    force-only byte}`; type 1 looks up the title scope and adds a consumer
    reference, type 2 the system scope and adds a reference. If the entry
    has a name and the force-only byte is clear or the entry has the force
    bit, returns the name pointer, port and force bit.
  - code 166 (0x91f381f8): release by (name pointer, port): drops the
    consumer reference (type 1) or reference (type 2) and frees the entry
    when both counts reach 0.
  - code 167 (0x91f38320): certificate callback. Request dwords: [0] type
    (1..2), [2] name pointer, [3] port, [5] and [6] caller values, [7]
    context, [8] callback; type out of range or a zero in [2], [3], [5],
    [6] or [8] gives 0x82da0017. Finds the entry by (name pointer, port)
    and calls `callback([7], [5], [6], certificate, certsize)`: no entry or
    no certificate 0x82da0002, certificate pending 0x82da0150, negative
    callback result 0x82da0003, else 0x02da0000.
  - Title termination (0x91f32398 calls 0x91f38480 = 0x91f37860): every
    entry's consumer count is cleared; active temp non-sys entries are
    deactivated and lose their active reference; entries with no
    references are freed.
- Settings-file lines run with no context: a certsize without `cert`
  writes the continuation through a NULL context in stock (no NULL
  check). openxbdm drops the new entry and fails the line instead.
- Status: spec complete. The private API dispatcher is not implemented in
  openxbdm; the list layout matches stock so codes 165..167 can be served
  from it.

## xstudio
- Handler: 0x91f65d38. Access: 0x4. Extra: 0x0.
- Syntax: `xstudio DedicateSocket`. The first token after the command word
  (delimited by space, tab or LF) must equal `DedicateSocket` exactly
  (case-sensitive, same length).
- Behavior: always returns 0x02da0000.
  1. Missing or different token: `200- NO`.
  2. 0x91f65b18 (state block 0x91fab700, critical section 0x91fab718):
     - subsystem not initialized (+4 == 0): fail. Initialization 0x91f654e8
       requires xboxkrnl export ordinal 810 (0x32a) and xam export ordinal
       1670 (0x686).
     - stored subsystem HRESULT (+0x38) negative: fail.
     - session thread running (+0x34): if a dedicated listener exists (+0xc)
       and no client is attached (+0x48 == 0) the existing listener session
       is torn down (0x91f65950) first; otherwise fail.
     - socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); ioctlsocket FIONBIO 1;
       bind 0.0.0.0 port 0; listen backlog 1; getsockname gives the port.
       Any failure closes the socket and fails.
     - +0x44 = socket, +0xc = 1; 0x91f65850 starts the session (see below).
       Success is reported even when the session does not start (test mode,
       service refusal); the listener then stays open with no thread, and
       the next `DedicateSocket` replaces (leaks) it.
  3. Success: `200- OK %u` with the listening port; failure: `200- NO`.
- Subsystem (state block 0x91fab700: +0 spin lock, +4 initialized, +8
  device status byte, +0xc dedicated, +0x10 worker finished, +0x14 test
  mode, +0x18 critical section, +0x34 thread running, +0x38 HRESULT,
  +0x3c thread, +0x40 stop event, +0x44 listener, +0x48 client attached,
  +0x4c kernel export 810 `NullCableRequest`, +0x50 xam export 1670):
  - Init 0x91f654e8 (last step of module init, after the network starts):
    resolve both exports (failure: DbgPrint
    `XStudio: Failed initialization %d\n`, subsystem stays off), +0x38 = 0,
    +4 = 1, then `NullCableRequest(4, 0)`, which makes the kernel report the
    device status through control code 0x99.
  - Code 0x99 (0x91f65ab8, `{+0 u8 status}`, at raised IRQL): if +4, store
    the status in +8; alert the server thread. Code 0x9f (0x91f65dd0,
    `{+4 enable}`): DbgPrint `XStudioSlave: Setting Test Mode\n` or
    `XStudioSlave: Disabling Test Mode\n`, store +0x14 (not gated on +4);
    alert the server thread. Both return 0.
  - Server pass 0x91f65a18 (after every select of the server loop): if
    initialized and not dedicated, start the session when the status is
    nonzero and test mode is off, else stop it; stop it also when +0x10.
  - Start 0x91f65850 (under the critical section): only if no thread, test
    mode off and +0x38 >= 0; xam(1, &out) must succeed; CreateEventA (auto
    reset) as stop event; ExCreateThread(stack 0x4000, flags 0x1000042f,
    0x91f656e8) then ResumeThread; any failure closes the event.
  - Stop 0x91f65950: set the stop event, wait for the thread, close both
    handles, clear +0x34 and +0x10, then `NullCableRequest(4, 0)`.
  - Worker 0x91f656e8: dedicated: wait on {stop event, FD_ACCEPT event}
    (0x91f655e8; stop gives 0x80004004) and accept one connection, set
    +0x48, wrap it in a socket transport; otherwise create a null-cable
    transport, whose failure is stored in +0x38 and disables the subsystem
    for good. Then xam(0x101, &{transport, stop event}); release the
    transport (routine 1); close the accepted socket; clear +0xc and +0x48;
    when dedicated close the listener (+0x44 = -1); set +0x10; alert.
- Transport objects: six routines at +0: 0 kind (1 null cable, 2 socket),
  1 release, 2 receive(buffer, length, request), 3 send(buffer, length,
  request), 4 result(request, &transferred, wait), 5 cancel. A request is
  caller memory: +0 transfer count (null cable) or request handle (socket),
  +4 status (null cable), +0x10 event.
  - Null cable (0x91f830e0, pool tag 0x754e5358, 0x1c bytes, type 2): routines 2/3
    call `NullCableRequest(2 or 1, {buffer, length, event, process type,
    &request+0, &request+4})` after setting +0 = 0 and +4 = 0x103; status
    0xc000000e -> 0x80004002, 0xc0000017 -> 0x8007000e, 0xc0000002 ->
    0x80004001, other failures 0x80004005. Send and result assert (trap
    0x19) on a null event. Result returns 0x8000000a while +4 is 0x103 (or
    waits on the event), then stores +0 and returns 0x80004005 for a
    nonzero status. Cancel is request 3 with the process type.
  - Socket (0x91f83698, pool tag 0x734e5358, 0xd4 bytes, type 2): non-blocking
    socket, four request nodes, lists free/send/receive/completed. Each
    message is a 4-byte big-endian length then the body. Queueing fails
    with 0x80004002 when disconnected and 0x8007000e with no free node; the
    first request binds its event with WSAEventSelect(FD_READ|FD_WRITE) and
    sets it. Every call pumps sends then receives while connected. A
    received length larger than the buffer completes the request with
    0x80070057 and drops buffer-capacity bytes (not the message length),
    so the stream desynchronizes. A body of length 0 is read with a
    zero-length recv whose 0 result closes the transport. recv returning 0
    or any error except WSAEWOULDBLOCK cancels every queued request
    (0x80004004) and marks the transport disconnected. Receive buffers
    shorter than 4 bytes trap (0x19) and still receive 4 bytes. Result
    returns 0x8000000a while pending, or waits; when the transport
    disconnects during the wait it returns 0x80004002 without leaving its
    critical section.
- Backend requirement: open an ephemeral TCP listener and hand the accepted
  connection to the Xbox Studio service in XAM.
- Status: spec complete. The session protocol on either transport is
  implemented by XAM export 1670 (not in this image).
