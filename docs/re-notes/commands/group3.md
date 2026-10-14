# XBDM commands, group 3

Image: stock XBDM 2.0.21256.0, base 0x91f00000. Dispatch, access checks, response modes, status text and the NTSTATUS mapper are specified in `framework.md`; this file uses its terms (ctx, scratch = ctx+0x10, 202 line mode, 203 raw, 204 receive, end code 0x82da0104).

Conventions used below:

- "dword" = parameter parsed by 0x91f418d8 (strtol base 0, must end at space/CR/NUL). If the value has trailing junk the parameter counts as absent but the parsed prefix is still stored.
- "required dword" = 0x91f41b20: on absence writes `missing <name>` into the response text and returns false. Some handlers continue after that failure; the text then stays in the response unless overwritten.
- "flag" = token matched by 0x91f41638 with bare tokens allowed; keys compare case-insensitively and exactly.
- "path open" = if the name starts with `\Device\` (case-insensitive, 0x91f75508 is `_strnicmp`) it is opened directly with `NtCreateFile` (OBJ_CASE_INSENSITIVE); otherwise it is translated by 0x91f2e888 and then opened. Translation: an optional leading `x`/`X` before a drive letter is dropped (`xE:\a` -> `E:\a`); the text before `:` must be followed by `\`; the drive name is upper-cased and looked up in the drive table at 0x91f96bf8 (0x2c-byte entries, name at +8, target at +0); unknown drives are resolved through the symbolic link `\??\<DRIVE>:` with `ObTranslateSymbolicLink`; the remainder of the path is appended. Output limit 0x141 bytes. Translation failure yields NTSTATUS 0xc000000f (unmapped, so the handler fallback applies).
- Text with empty message: a negative result with empty handler text and no table message is sent as `400- ` (trailing space, nothing else).

## dumpmode
- Handler: 0x91f3cc68. Access: 0x8. Extra: 0x0.
- Syntax: `dumpmode [smart|enabled|disabled]`. Flags, tested in that order; the first present one wins.
- Behavior:
  - Flag table 0x91f97620: index 0 `smart`, 1 `enabled`, 2 `disabled`. If a flag is present, 0x91f3bb30(index) runs: reads the test-kit state (0x91f9f680 != 0); on a test kit, mode 0 (`smart`) is forced to 1 (`DbgPrint("Reset Dump mode to ENABLED for the TEST KIT!\n")`). Stores the mode in 0x91f9f660 and calls the settings writer 0x91f31e48 (persists xbdm.ini; skipped on CD boot, before settings load, or after wipe; from a title process it signals the server thread). Setter result is ignored.
  - Always replies `200- <name>` where name = table[mode] if mode < 3 else table[0] (`smart`).
  - No failure statuses.
- Backend requirement: persistent dump-mode setting; test-kit indicator; settings persistence.
- Status: spec complete.

## dumpsettings
- Handler: 0x91f2d730. Access: 0x8. Extra: 0x0.
- Syntax: `dumpsettings [rpt=<v>] [dst=<v>] [fmt=<v>] [path=<string>]`. Values for rpt/dst/fmt are strings up to 0x3e chars compared case-insensitively (0x91f75370):
  - `rpt`: `prompt`=0, `always`=1, `never`=2 (table 0x91f96bd0).
  - `dst`: `local`=0, `remote`=1 (table 0x91f96bdc).
  - `fmt`: `full`=0, `partial`=1, `noheap`=2, `retail`=3 (table 0x91f96be4).
  - `path`: string up to 0x102 chars, stored at 0x91f9f524. `path=` with an empty value clears it.
- Behavior:
  - Packed word 0x91f9f520: bits 0-3 rpt, 4-7 dst, 8-11 fmt. A recognised value replaces its field. Unrecognised values are ignored silently.
  - If any field or path was given, settings writer 0x91f31e48 runs.
  - Reply always 200, text from 0x91f2d458: `snprintf("rpt=%s dst=%s fmt=%s%s%s", rpt, dst, fmt, P, S)` where P = ` path=` and S = path if path is non-empty, else both empty. Output truncated to the buffer.
  - Range clamp in the formatter: rpt > 3, dst > 2, fmt > 4 become 0. The clamp bounds exceed the table sizes, so rpt=3 prints `local`, dst=2 prints `full`, fmt=4 reads past the fmt table (values only reachable from xbdm.ini; do not reproduce).
- Backend requirement: persistent crash-dump settings.
- Status: spec complete.

## dvdblk
- Handler: 0x91f4c6a8. Access: 0x1. Extra: 0x0.
- Syntax: `dvdblk block=<dword> count=<dword>`. block required. count required by helper but see quirk; limit 0x40 (unsigned).
- Behavior:
  1. ctx NULL: 0x80004005.
  2. `block` absent: `400- missing block`.
  3. `count` present and > 0x40: `sprintf("Invalid block count: '%d'.")` -> `400- Invalid block count: '<n>'.` (signed print).
  4. Size = count * 0x800. If `count` is absent, size = 0 and the text `missing count` remains (see 9). If `count` is present but has trailing text (required helper fails), its parsed prefix is used as the byte size without the 0x40 check and without the 0x800 multiplication; the text `missing count` remains.
  5. `ObReferenceObjectByName("\Device\Cdrom0", IoDeviceObjectType)`; failure `400- `.
  6. ctx+0xc = size; buffer = `ExAllocatePoolWithTag(size, 'xbdm')`, stored ctx+8; NULL -> dereference, `400- `.
  7. `IoSynchronousFsdRequest(IRP_MJ_READ=2, device, buffer, size, &offset)` with 64-bit offset = block * 0x800. Device dereferenced. Failure: buffer freed, `400- `.
  8. ctx+0x14 = size, continuation 0x91f4c658, result 0x02da0003: `203- binary response follows`.
  9. Quirk: with `count` absent the reply is `203- missing count` and zero data bytes (if the zero-size allocation succeeds; whether `ExAllocatePoolWithTag(0)` returns NULL is unknown).
  - Continuation 0x91f4c658: first call sets ctx+4 = size, ctx+0x14 = 0 (whole buffer sent at once); next call frees the buffer, returns end. Data is raw sectors, no length prefix.
- Backend requirement: raw sector read from the optical drive at 2048-byte granularity.
- Status: spec complete.

## dvdeject
- Handler: 0x91f4c800. Access: 0x1. Extra: 0x0.
- Syntax: `dvdeject [eject=<dword>]`, default 1.
- Behavior: `HalOpenCloseODDTray(value)`; result ignored; returns `200- OK`. [INFERENCE] nonzero opens the tray, 0 closes it.
- Backend requirement: open/close optical drive tray.
- Status: spec complete.

## dvdperf
- Handler: 0x91f4c208. Access: 0x4. Extra: 0x0.
- Syntax: `dvdperf start` | `dvdperf stop [report]`. Flags; `stop` is tested first.
- State: global trace buffer pointer 0x91fab980; shared debug-monitor block 0x91fade60: +0xc flag bit 0x20 = DVD trace enabled, +0x3c = current write pointer. [INFERENCE] records are written by the kernel optical driver through this block; no writer exists in XBDM.
- start: write pointer := 0; free the old buffer; allocate 0x200000 bytes; allocation failure returns `200- OK` silently. Else clear bit 0 of the first record's flag word (buf+8), set enable bit 0x20, write pointer := buffer start. `200- OK`.
- stop: ctx NULL -> 0x80004005. Atomically swap write pointer with 0 (old value = end), clear enable bit, take buffer from 0x91fab980 (global := 0). Scratch: +0x10 end, +0xc cursor = buffer, +8 buffer.
  - Without `report`: free buffer, `200- OK`.
  - With `report`: buffer NULL -> `400- nothing to report`. Else scratch+0 = first record's 64-bit timestamp (base), ctx+0x14 = 1, continuation 0x91f4c138, `202- multiline response follows`.
- Neither flag: `400- ` (0x80004005).
- Record (16 bytes, big-endian): +0 u64 time, +8 u32 W, +0xc u32 elapsed. W bit 0 = record valid; lba = (W >> 1) & 0xffffff; cblk = W >> 25.
- Continuation 0x91f4c138: while cursor < end: time := (time - base) / 1000 (written back), format `timestamp=%lu time=%d lba=%d cblk=%d` with timestamp = low 32 bits of the scaled time, time = elapsed; advance 16; if the record's valid bit is set, send the line (line mode) and return. Records with bit 0 clear are skipped. At end: free buffer, return end -> `.`.
- Backend requirement: optical-drive request tracing with timestamps, sector and block counts.
- Xbox: the monitor block is the debug monitor data copy at 0x91fade60 whose address dminit stores into kernel variable ordinal 89 (`KeDebugMonitorData`); flags at +0xc, write pointer at +0x3c. The optical driver writes the records.
- Status: partial: unit of `time`/timestamp ticks unknown (resolve in the kernel optical driver).

## enablewirelesscontrollers
- Handler: 0x91f4c398. Access: 0x4. Extra: 0x2 (development-kit only; test kit returns `407- unknown command`).
- Syntax: `enablewirelesscontrollers enabled=<string>` (up to 31 chars). Case-insensitive: `off`, `false` -> disable; `on`, `true` -> enable.
- Behavior:
  1. `enabled` absent: `423- bad parameter`, nothing printed.
  2. `DbgPrint("[xbdm] EnableWirelessControllers, enabled=%s\n")` with the copied value; this runs before the value is checked, so any other value prints and then gives `423- bad parameter`. A failed set in step 4 prints `[xbdm] EnableWirelessControllers, enabled=%s ExSetXConfigSetting failed %X\n`.
  3. `XInputdSetRFPowerMode(enable)`; failure `414- access denied`.
  4. `ExGetXConfigSetting(category 3, setting 0xd, 4 bytes)`; if it succeeds with length 4: bit 0x800 set when disabling, cleared when enabling; `ExSetXConfigSetting(3, 0xd)`. Failures only logged.
  5. `200- OK`.
- Backend requirement: wireless controller radio power control and persistent console configuration flag.
- Status: spec complete.

## eventdefer
- Handler: 0x91f3cdb8. Access: 0x8. Extra: 0x0.
- Syntax: `eventdefer [set [break] [debugstring] [singlestep] [assert] [ntassert] [databreak] [rip]]`. Flags.
- Behavior:
  - With `set`: mask := OR of bit i for each present name (table 0x91f9762c: 0 break, 1 debugstring, 2 singlestep, 3 assert, 4 ntassert, 5 databreak, 6 rip); names absent are cleared. Stored at 0x91f97604 (default 0x27), settings writer runs.
  - Reply 200; text = for each set bit in order, ` ` + name (note the leading space: `200-  break debugstring`). Mask 0: `200- OK`.
  - The mask selects which notifications (break 1, debugstring 2, singlestep 4, assert 0xc, databreak 0xd, rip 0xe; ntassert mapping not traced) are queued to the server thread by 0x91f39768 instead of being delivered inline.
- Backend requirement: persistent notification deferral mask.
- Status: spec complete.

## fastpipe
- Handler: 0x91f44038. Access: 0x0. Extra: 0x0.
- Syntax: `fastpipe [group=<dword>]`.
- Behavior:
  1. ctx NULL (settings file): 0x80004005, no line. Hardware flag word (kernel data ordinal 342, first dword) lacks bit 0x00010000: `400- `. The bit is the 1 GB RAM feature (` 1GB_RAM` in `consolefeatures`); fastpipe is available only on such consoles.
  2. group = value (strtol base 0) or 0 when absent or malformed. 0x91f540c0(socket, group):
     - First use starts the subsystem (0x91f53e18): one writer thread at 0x91f52ab8 (hardware thread 3) and three worker threads at 0x91f53ad0 (hardware thread 2); the threads run for the life of XBDM. Failure -> limit message.
     - Slot allocation 0x91f53f70: group 0 is replaced by an auto-incremented nonzero id (0x91fa2644, first id 1; the counter advances even when allocation fails). Six slots (0x91fab800, stride 0x3c, +0 socket, +0x24 group). Any occupied slot with a different group fails, so only one group exists at a time and group 0 succeeds only when no pipe is open. First pipe: saves `FscGetCacheElementCount(2)` and calls `FscSetCacheElementCount(2, 0x400)`. The first 0x5b4-byte read is posted before the 209 line. Defect: with all six slots used by the same group the free index stays -1 and slot -1 is written (not reproduced; limit exceeded).
     - On success sends `209- result code <group>` (signed decimal) directly on the socket, one send of text + CR LF; not the 0x02da0009 framework path.
  3. Failure: `400- fastpipe limit exceeded`; the connection stays a command connection.
  4. Success: connection socket field := -1 (socket now owned by the pipe), connection released via 0x91f41460, handler returns 0 (no further status line).
- Data plane (dmfastpipe.c, 0x91f52720..0x91f54134). The pipe carries only binary packets after the 209 line; the console sends only 12-byte replies. All fields big-endian.
  - Header: +0 u16 magic `CC` (0x4343, create) or `AA` (0x4141, data); +2 u16 file id; +4 u32 total length T including the header; +8 u32 AA file offset (CC: not read).
  - Framing: every packet starts with a 0x5b4-byte read. At 0x5b4 bytes the header is checked: other magic or T > 0x1000c closes the pipe (no reply); else the read continues to T bytes. Each packet consumes max(T, 0x5b4) bytes of the stream, so a packet shorter than 0x5b4 bytes must be padded to 0x5b4. Receive error or peer close closes the pipe.
  - `CC` body: +0xc u32 H; +0x10 u64 creation time; +0x18 u64 last write time; +0x20 u64 size S; +0x28 u32 attributes; +0x2c NUL-terminated path. `\Device\` paths open directly, others through XBDM path translation; access 0x40110000, allocation size S, attributes 0, share 0, FILE_OVERWRITE_IF, asynchronous. S_lo > 0x10000: end of file set to S. Open, end-of-file or event failure: reply map(status, 0x82da000d) (the file is deleted when it was opened). Context allocation failure: reply 0x8007000e.
  - Inline file: when `(0x10000 - H) >= S_lo` (unsigned 32-bit), S_lo bytes after the path NUL are written at offset 0 (none when S_lo is 0), the file is closed, and the reply is sent; times and attributes are not applied. Write failure: delete, map(status, 0x82da000d).
  - Queued file: blocks = ceil(S_lo / 0x10000). `AA` packets carry data at +0xc; length 0x10000, or S_lo & 0xffff for the last block. Offset must be below S_lo and a multiple of 0x10000, else 0xc0000173. File ids are global across pipes; an `AA` for an unknown id is kept and adopted by a later `CC` with that id. Completion is counted: any ceil(S_lo / 0x10000) successful writes complete the file (duplicates count, gaps are not detected). Only S_lo is used for files with S_hi != 0.
  - Completion: creation time, last write time and attributes are applied (basic information); failures, invalid offsets and the final query map to map(status, 0x8000ffff) and delete the file. After the first failure further blocks of that file are dropped.
  - Reply (12 bytes): u16 `BB` (0x4242), u16 file id, u32 T of the `CC` packet, u32 HRESULT (0 on success). One reply per `CC`: at once for inline files and creation failures, else after the last block or the first failure. The reply can arrive before the file handle is closed.
  - Closing any pipe closes every pipe of the group. When none remains, open files are marked done with their HRESULT unchanged (a partial file remains on disk at its full size, no reply is sent), kept `AA` packets are freed, and the saved cache count is restored.
- Backend requirement: hand a TCP connection to a high-throughput file-receive engine with grouped pipes; filesystem cache tuning.
- Status: spec complete. Stock defects not reproduced: `parity/session.md`.

## feature
- Handler: 0x91f44110. Access: 0x4. Extra: 0x0.
- Syntax: `feature enable=<dword> feature=<dword>`.
- Behavior:
  1. ctx NULL: `423- bad parameter`.
  2. `XexGetProcedureAddress(xam.xex, ordinal 515)`; failure returns `200- OK` with no action.
  3. `enable` absent: `423- 'enable' not specified`. `feature` absent: `423- 'feature' not specified`.
  4. Calls XAM ordinal 515 `(enable, feature)`; result ignored; `200- OK`.
- Backend requirement: forward a feature toggle to the system UI library.
- Status: partial: semantics of XAM ordinal 515 unknown.

## fileeof
- Handler: 0x91f45b10. Access: 0x0, all_of 0x3 (read and write). Extra: 0x0.
- Syntax: `fileeof name=<string> size=<dword> [mustcreate|cancreate]`. name up to 0x140 chars.
- Behavior:
  1. name absent: `400- missing name`. size absent: `400- missing size`.
  2. Disposition: `mustcreate` -> FILE_CREATE (2); else `cancreate` -> FILE_OVERWRITE_IF (5); else FILE_OPEN (1).
  3. Path open: access 0x40110000, allocation size = size, attributes 0, share 0, options 0x20.
  4. `NtSetInformationFile(FileEndOfFileInformation, size as u64)`, `NtClose`. File-change counter 0x91f9feec incremented after any successful open.
  5. Open or set failure: NTSTATUS mapper with fallback 0x82da000e. Success `200- OK`.
- Size is 32 bits; no high part.
- Backend requirement: open/create a file and set its end-of-file.
- Status: spec complete.
- Client disagreement: openxbdm-client `FileEof` sends a `CREATE` flag, which this server ignores (opens existing only); use `cancreate` or `mustcreate`. The client accepts u64 sizes; the server parses 32 bits.

## fileevent
- Handler: 0x91f4e7f8. Access: 0x4. Extra: 0x0.
- Syntax: `fileevent advise` | `fileevent unadvise`. Flags; `advise` tested first.
- Behavior: flag `advise` -> export 152 (0x91f2f428); else `unadvise` -> export 153 (0x91f2f4c0); neither: 0x80004005 (`400- `). Under critical section 0x91fae520: sequence 0x91f9735c += 1; enable flag 0x91f9f628 := 1 or 0; `XBDMFE!Start 0x%08x` or `XBDMFE!Stop 0x%08x` (sequence, 0x40-byte buffer) is sent through export 36 (0x91f3b070) to matching notification extensions and as a line to every notification socket. The export 36 result 0x02da0000 is the command result: `200- OK`.
- Sequence: every increment (here, in the 0x64 Begin, and in exports 155 and 157) is `addic.` of the zero-extended word followed by a zero test meant to skip 0; CR0 reflects the 64-bit sum, which is never zero, so the sequence wraps from 0xffffffff to 0. A Begin record that gets id 0 produces no End text.
- While enabled, the kernel file services report through control codes 0x64 (0x91f2f5c8, before the operation) and 0x65 (0x91f2f930, after it) with a 0x28-byte record: +0 event id, +4 operation 0..9, +8 handle, +0xc object attributes, +0x10 status, +0x14 length, +0x18 pointer to 64-bit offset, +0x24 create options.
  - Begin: title id from the executable module (XEX header field 0x40006, +0xc; 0 when absent). Titles 0xfffe07d1 and 0xfffe07ff produce no event; nor does the title that last terminated (recorded by title-terminate routine 0x91f32398) while it remains current. Else id := ++sequence, stored at record+0.
  - Begin text: `XBDMFE!Begin 0x%08x "Perf=0x%08x%08x" "Type=0x%08x" "ThreadId=0x%08x" "Handle=0x%08x" "Offset=0x%08x%08x" "Bytes=0x%08x" "Flags=0x%08x"`: id, time base, type (operations 3..9 -> 1..7, else 0), KTHREAD+0x14c, handle, offset, record+0x14, flags. Offset (operations 3..6): the given offset when nonzero, else the file position, else 0. Flags: 0x80000000 when the file mode (or create options for operations 0 and 1) has 0x20, 0x20000000 when it lacks 0x8, 0x40000000 for operations 5 and 6.
  - Path suffix (operations 0 and 1 with an object name): room = min(0x1fe - len, Length + 7); ` "Path=%s` written into room bytes, then `"` at len+room. The closing quote appears only when the name fills its room; a name longer than its Length field is cut.
  - End text (id != 0): `XBDMFE!End 0x%08x "Perf=0x%08x%08x" "Handle=0x%08x" "Result=0x%08x"`.
  - Texts are cut to 0x1ff characters and sent through export 36. Dispatcher result 0; the kernel performs the operation.
- Backend requirement: notification broadcast; file I/O event source (monitor control codes 0x64 and 0x65).
- Title-reported events (exports 154..160, see docs/re-notes/exports.md): `XBDMFE!Marker`, `XBDMFE!PseudoBegin` (two forms), `XBDMFE!PseudoEnd` (with and without `Handle=`), `XBDMFE!MarkThread`, `XBDMFE!UnmarkThread`. They check only the enable flag (no title check); 155 and 157 take an identifier from the shared sequence.
- Status: spec complete.

## flash
- Handler: 0x91f4a730. Access: 0x8. Extra: 0x0.
- Syntax: `flash size_<hw>=<dword> [ignoreversionchecking=<dword>] [stockimage]`.
- Hardware selector: kernel export ordinal 342 first dword & 0xff000003:

| value | parameter | suffix |
| --- | --- | --- |
| 0x00000003 | size_w2 | w2 |
| 0x02000003 | size_tw2 | tw2 |
| 0x10000003 | size_z | z |
| 0x12000003 | size_zt | zt |
| 0x20000003 | size_f | f |
| 0x22000003 | size_ft | ft |
| 0x30000003 | size_j | j |
| 0x32000003 | size_jt | jt |
| 0x40000003 | size_t | t |
| 0x42000003 | size_tt | tt |
| 0x50000003 | size_c | c |
| 0x52000003 | size_ct | ct |
| 0x60000003 | size_wi | wi |
| 0x62000003 | size_wit | wit |
| 0x80000003 | size_r | r |
| 0x82000003 | size_rt | rt |

- Behavior:
  1. ctx NULL: `400- `.
  2. Unknown hardware value, or size parameter absent: `400- unsupported hardware type, requires <suffix>` (unknown hardware passes a NULL suffix; CRT output for NULL `%s` unknown).
  3. `ignoreversionchecking` via required helper (absence writes `missing ignoreversionchecking`, later overwritten); default 0. Scratch: +0xc ignore flag, +0x10 = 1 if `stockimage` else 0, +4 size, +8 size rounded up to 0x4000.
  4. Allocate rounded size (tag 'Xbdm'); failure `400- Not enough memory` (0x82da0000).
  5. ctx+0x14 = size, ctx+8 = buffer, ctx+0xc = size, continuation 0x91f4a628; `204- send=<suffix>`.
  - Receive continuation: 0 bytes received (connection closed) -> free, 0x8000ffff. Accumulates until ctx+0x14 = 0, zero-pads to the rounded size, calls flash writer 0x91f735d0(buffer, rounded size, ignore flag, stockimage, 0). A positive Win32 error e becomes 0x80070000|e. Success `200- Done, new image flashed`; failure `<4xx>- Flash failed with HRESULT 0x%x`. Buffer freed.
  - Writer 0x91f735d0: requires size multiple of 0x4000 (else 0xc000000d); validates the image unless ignore flag set; programs flash; re-encrypts the boot loader with `XeKeysSaveBootLoader` (`XapiFlashKernelImage(): unable to reencrypt boot loader`); errors returned via `RtlNtStatusToDosError`.
- Backend requirement: receive and program a system flash image for the detected hardware revision.
- Status: partial: image validation rules inside 0x91f73260/0x91f732a8/0x91f734a0 not reconstructed.

## fmtfat
- Handler: 0x91f46eb0. Access: 0x8. Extra: 0x0.
- Syntax: `fmtfat partition=<dword> [force=<dword>]`. partition 1..5.
- Behavior:
  1. `force` via required helper (absence writes `missing force`, value 0).
  2. force == 0 and execution state (0x91f2d930) != 3: `408- not stopped`.
  3. `partition` absent: `400- missing partition`.
  4. partition < 1 or > 5: 0x82da0002 (`402- file not found`, or `402- missing force` if force was absent).
  5. Formats `\Device\Harddisk0\Partition<n>` via 0x91f72e58 with cluster size 0x4000 (XTAF signature, FAT chain initialised). Failure `414- unable to format`.
  6. Success `200- OK`, or `200- missing force` when force was absent (quirk).
- Execution state 3: [INFERENCE] `pending` (state name table 0x91f97608: stopped, started, rebooting, pending, reboot_title, pending_title).
- Format routine 0x91f72e58(device, 0x4000): `NtOpenFile(0x100003, share 0, options 0x18)`; `FileFsDeviceInformation` (device type); `IOCTL_DISK_GET_DRIVE_GEOMETRY` 0x70000 (bytes per sector at +4, shift = log2); `IOCTL_DISK_GET_PARTITION_INFO` 0x74004 (64-bit length at +8; 0 -> 0xc0000034). page = align(bytes per sector, 0x1000); cluster = max(0x4000, page); header = max(page, 0x1000); header >= length -> 0xc000007f. clusters = length / cluster + 1; FAT16 if clusters < 0xfff0 and device type != 0x46, else FAT32; FAT bytes = align(clusters * 2 or 4, page); no room for FAT plus one cluster -> 0xc000007f. Writes (page-sized, synchronous): zeros at 0; FAT from offset `header` (first page starts `FFF8 FFFF` or `FFFFFFF8 FFFFFFFF`, rest zero); one cluster of 0xff (root directory); then the header area from 0: page 0 = `XTAF`, u32 low dword of system time, u32 sectors per cluster (low byte), u32 1 (root cluster), u16 0, rest 0xff; later header pages zero. Then `IoDismountVolumeByFileHandle`, close. Buffer allocation failure 0xc000009a.
- Backend requirement: format a hard-disk partition as XTAF.
- Status: spec complete.

## getconsoleid
- Handler: 0x91f502b0. Access: 0x4. Extra: 0x0.
- Syntax: `getconsoleid`.
- Behavior: `XeKeysGetConsoleID(NULL, buf[13])`; failure returns status | 0x10000000 -> `400- `. Success `200- consoleid=<string>`.
- Backend requirement: read the console identifier string.
- Status: spec complete.

## getcontext
- Handler: 0x91f482b0. Access: 0x4. Extra: 0x0.
- Syntax: `getcontext thread=<dword> [control] [int] [fp] [vr] [full]`. Flags OR into ContextFlags: control 0x1, fp 0x2, int 0x4, vr 0x10, full 0x17.
- Behavior:
  1. ctx NULL or `thread` absent: `400- missing thread` (empty text when ctx NULL).
  2. 0x91f26260(thread id, context): `ObLookupAnyThreadByThreadId` failure or thread without debugger data: `405- no such thread`.
     - Thread stopped in an exception: requested groups copied from the exception frame (control: Msr +4, Iar +8, Lr +0xc, Ctr +0x10; int: Gpr0-31 +0x18, Cr +0x118, Xer +0x11c; fp +0x120 len 0x108; vr +0x230 len 0x810). Gpr1 replaced by a saved user stack pointer when debug-data flag 0x10000 is set.
     - Otherwise only control and int are returned, from the switch frame: Gpr0-Gpr13 = all ones, Gpr14-Gpr31 from the frame, Gpr1 = stack pointer, Cr from the frame, Xer = 0xffffffff, Msr = 0xffffffff, Iar and Lr from the frame, Ctr = all ones. fp and vr are dropped.
  3. Allocate 0xa50 bytes (tag 'dmcr'); failure `400- out of memory`.
  4. `202- multiline response follows`; continuation 0x91f48178 fills up to (ctx+0xc - 0x40) bytes per call (raw mode, lines include CRLF), then `.`.
- Line order and formats (offsets into the CONTEXT copy):
  - control: `Msr`, `Iar`, `Lr` as `%s=0x%08x`; `Ctr` as `%s=0q%016I64x`.
  - int: `Gpr0`..`Gpr31` as `0q%016I64x`; `Cr`, `Xer` as `0x%08x`.
  - fp: `Fpscr`, `Fpr0`..`Fpr31` as `0q%016I64x`.
  - vr: `Vscr`, `Vr0`..`Vr127` as `%s=0x%08X,0x%08X,0x%08X,0x%08X` (words in memory order).
- No groups selected: `202-` line then `.`.
- Backend requirement: read a thread's register context by thread id, distinguishing stopped and running threads.
- Status: spec complete.

## getfile
- Handler: 0x91f45898. Access: 0x1. Extra: 0x0.
- Syntax: `getfile name=<string> [offset=<dword> size=<dword>]`. name up to 0x140 chars. `size` is read only when `offset` is present and is then required.
- Behavior:
  1. ctx NULL: `400- `. name absent: `400- missing name`. offset present, size absent: `400- missing size`.
  2. Path open: access 0x80100000, share read|write, FILE_OPEN, options 0x20. Failure: NTSTATUS mapper, fallback 0x82da000e.
  3. `NtQueryInformationFile(FileNetworkOpenInformation)` failure: `400- unexpected error`. EOF high dword != 0: `400- file is too big`. Handle closed on these errors.
  4. Length = EOF. offset > EOF: length 0 (no error). 0 < offset <= EOF: seek (FilePositionInformation; failure mapped, fallback 414), length = EOF - offset. size != 0 and size < length: length = size.
  5. 0x3000-byte buffer (allocation not checked), continuation 0x91f456f0, ctx+0x14 = 1.
  6. Status `203- partial send` if offset != 0 or size != 0, else `203- binary response follows`.
  - Continuation: first call writes u32 little-endian length (4 bytes); saves SO_SNDBUF and sets it to 0x10000. Then reads min(remaining, 0x3000) bytes per call; a read failure sends zeros for that chunk. At end: close, free, restore SO_SNDBUF.
- Backend requirement: open and read files with offset; file size query.
- Status: spec complete.
- Client disagreement: openxbdm-client rejects a ranged reply whose advertised length differs from SIZE; the server clamps to the bytes available, treats SIZE=0 as "to end of file" and returns 0 bytes when OFFSET > EOF.

## getfileattributes
- Handler: 0x91f45d78. Access: 0x3 (read or write). Extra: 0x0.
- Syntax: `getfileattributes name=<string>` (up to 0x140 chars).
- Behavior:
  1. ctx NULL: `400- `. name absent: `400- missing name`.
  2. `\Device\` names used verbatim; others translated; translation failure `400- ` (0x82da0000).
  3. `NtQueryFullAttributesFile` into scratch; failure mapped, fallback 0x82da000e.
  4. `202- multiline response follows`, one line, then `.`:
     `sizehi=0x%x sizelo=0x%x createhi=0x%08x createlo=0x%08x changehi=0x%08x changelo=0x%08x%s%s%s`
     size = EndOfFile, create = CreationTime, change = LastWriteTime; suffixes ` directory` (0x10), ` readonly` (0x1), ` hidden` (0x2) in that order.
- Backend requirement: query file size, times and attributes.
- Status: spec complete. Matches capture `getfileattributes.capture`.

## gethddblk
- Handler: 0x91f4f788. Access: 0x1. Extra: 0x0.
- Syntax: `gethddblk name=<device object name> block=<dword> count=<dword>`. name up to 0xff chars; count <= 0x100.
- Behavior: as `dvdblk` with these differences: ctx NULL or name absent -> `400- ` (no text); the device is `name`; sector size 0x200; count > 0x100 -> `400- Invalid block count: '<n>'.`; count absent -> size 0 with text `missing count`; a count with trailing text uses its prefix as a byte size, as in `dvdblk`. Same continuation 0x91f4c658, raw data, `203-`.
- Backend requirement: raw sector read from a named block device at 512-byte granularity.
- Status: spec complete.

## getmem
- Handler: 0x91f478f0. Access: 0x4. Extra: 0x0.
- Syntax: `getmem addr=<dword> length=<dword>`. No length limit.
- Behavior:
  1. ctx NULL: `400- `. Missing: `400- missing addr` / `400- missing length`.
  2. addr stored at scratch+0, length at ctx+0x14; buffer 0x420 bytes (allocation not checked). `202- memory data follows`.
  3. Continuation 0x91f47770 (raw mode): up to 16 lines per call; each line up to 32 bytes as uppercase hex followed by CRLF. Per page (4 KiB) `MmIsAddressValid`; invalid page bytes are `??`. Each byte is read by 0x91f26bc8 (shows original bytes under software breakpoints; requires `MmDbgReadCheck` and the address class check below). Quirk: when that read fails, the two characters are left unwritten (stale buffer content) and the remaining bytes of the same page print `??`.
  4. End: free buffer, `.`.
- Backend requirement: per-byte virtual memory read with breakpoint hiding.
- Status: spec complete. Matches capture `getmem.capture`.

## getmemex
- Handler: 0x91f4b4c0. Access: 0x4. Extra: 0x0.
- Syntax: `getmemex addr=<dword> length=<dword>`.
- Behavior:
  1. The keys are looked up as `ADDR` and `LENGTH` (strings 0x91f076c8, 0x91f076c0; matching is case-insensitive). Missing: `400- missing ADDR` / `400- missing LENGTH` (observed on hardware). (ctx is dereferenced without a NULL check.)
  2. scratch+0 = addr, ctx+0x14 = length, buffer 0x402 bytes. `203- binary response follows`.
  3. Continuation 0x91f4b380, per call: n = min(remaining, 0x400). Pages of [addr, addr+n) are checked with 0x91f26958 (`MmDbgReadCheck` result not in 0x7fc80000-0x7fc9ffff, 0x7fd00000-0x7fdfffff, 0x7feaxxxx, 0x7fedxxxx, 0x8fff0000-0x8fff1fff). At the first unreadable page n is cut to the readable prefix and remaining := 0. Chunk = u16 little-endian header (n | 0x8000 when remaining is now 0) + n bytes copied, then breakpoint bytes restored (0x91f256d0).
  4. remaining 0 on entry: free, end. length=0 therefore sends no chunk at all.
- Backend requirement: bulk virtual memory read with readability probing and breakpoint hiding.
- Status: spec complete.

## getnetaddrs
- Handler: 0x91f354d8. Access: 0x1. Extra: 0x0.
- Syntax: `getnetaddrs`.
- Behavior: `XNetGetDebugXnAddr` and `XNetGetTitleXnAddr` (36-byte address records). Either returns 0: `442- debugstatus=0x%08x titlestatus=0x%08x`. Else `200- name=%hs debug=%hs title=%hs`: name = debug name (0x91fab9c0), debug/title = 72 uppercase hex characters of each record.
- Backend requirement: debug and title network address records; debug name.
- Status: spec complete. Matches capture `netaddrs.capture`.

## getpid
- Handler: 0x91f49908. Access: 0x4. Extra: 0x0.
- Syntax: `getpid`.
- Behavior: execution state 3 ([INFERENCE] pending): `405- no such thread`. Else the per-boot id 0x91fab9b0 is generated once (timebase plus system time, repeated until nonzero). `200- pid=0x%08x`.
- Backend requirement: per-boot random nonzero identifier; execution state.
- Status: spec complete. Matches capture `getpid.capture`.

## getsockinfo
- Handler: 0x91f345c8. Access: 0x1. Extra: 0x0.
- Syntax: `getsockinfo`.
- Behavior:
  1. Allocate 0x14000 bytes; failure `428- out of memory`.
  2. `XnpGetActiveSocketList(buf, &count)` with count = 0x800; nonzero result: free, `414- access denied`.
  3. `202- multiline response follows`; one line per 0x28-byte record (line mode), then `.`:
     `handle=0x%08x ownertype=%d flags=0x%08x addrfamily=%d socktype=%d protocol=%d localaddr=0x%08x remoteaddr=0x%08x localport=0x%04x remoteport=0x%04x tcpstate=%d`
     Record: +0 handle, +4 ownertype, +8 flags, +0xc family, +0x10 type, +0x14 protocol, +0x18 local addr, +0x1c remote addr, +0x20 u16 local port, +0x22 u16 remote port, +0x24 u8 tcp state.
  Lines go through a 0x100-byte buffer whose last byte is forced to NUL (at most 255 characters). The buffer is freed only by the final continuation call; a connection that drops mid-listing leaks it.
- Backend requirement: enumerate active network sockets.
- Client: owner type, family, type and protocol are signed (`%d`) and the TCP state is a byte; the client parses them as `i32` and `u8`.
- Status: spec complete. Matches capture `sockets.capture`.
