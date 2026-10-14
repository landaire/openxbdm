# XBDM command group 7

Image: stock XBDM 2.0.21256.0, base 0x91f00000. Commands: sendvfile, setconfig, setcontext, setdiscboot, setfileattributes, sethddblk, setmem, setreset, setretail, setserver, setsystime, setuserpriv, spew, srvproc, stop, stopon, suspend, sysfileupd, systeminfo, systime, tdecomp, threadinfo, threads.

## Conventions

- Framework, status builder, default messages and continuation ABI: see `framework.md`. `resp` is the handler text buffer (size 0x1fb). `ctx` is the per-command continuation context: ctx+0 continuation, ctx+4 byte count / 0xffffffff text-line mode, ctx+8 buffer, ctx+0xc buffer size, ctx+0x10 per-connection scratch area, ctx+0x14 remaining count / state.
- Empty handler text means the default message for the code. Default messages used below: 0x02da0000 `OK`, 0x02da0002 `multiline response follows`, 0x02da0003 `binary response follows`, 0x02da0004 `send binary data`, 0x82da0002 `file not found`, 0x82da0004 `memory not mapped`, 0x82da0005 `no such thread`, 0x82da0007 `unknown command`, 0x82da0008 `not stopped`, 0x82da000a `file already exists`, 0x82da000b `directory not empty`, 0x82da000c `filename is invalid`, 0x82da000d `file cannot be created`, 0x82da000e `access denied`, 0x82da000f `no room on device`, 0x82da001e `path not found`, 0x8000ffff `unexpected error`, 0x8007000e `out of memory`, 0x80070057 `bad parameter`. 0x80004005 (E_FAIL), 0x82da0006 and 0x82da001a have no default text: the line is `400- `, `406- `, `426- ` with nothing after the space.
- Non-XBDM-facility failures become status 400 (`400- <text>`).
- `missing X` is the text written by the required-dword helper 0x91f41b20 when parameter X is absent.
- NTSTATUS to HRESULT helper 0x91f41f18 `(status, default)`: 0 -> 0x02da0000; 0xc0000008 -> 0x80070057; 0xc0000022 -> 0x82da000e; 0xc0000033 and 0xc0000039 -> 0x82da000c; 0xc0000034 and 0xc00000ba -> 0x82da0002; 0xc0000035 -> 0x82da000a; 0xc000003a -> 0x82da001e if default is 0x82da000d, else 0x82da0002; 0xc000007f -> 0x82da000f; 0xc000009a -> 0x8007000e; 0xc0000101 -> 0x82da000b; any other value -> default.
- File open helpers: 0x91f2eb68 `(handle*, access, xbdm_path, alloc_size*, attrs, share, disposition, options)` translates the XBDM path with 0x91f2e888 (output limit 0x141 bytes) and calls NtCreateFile with OBJ_CASE_INSENSITIVE; translation failure returns 0xc000000f without calling the kernel. 0x91f2ec08 takes an NT object path without translation.
- Access bits: 0x1 read, 0x2 write, 0x4 control, 0x8 config, 0x10 manage. Extra 0x2 = development-kit-only (407 on a test kit).
- Execution state global 0x91fae664 (names from table 0x91f97608): 0 `stopped`, 1 `started`, 2 `rebooting`, 3 `pending`, 4 `reboot_title`, 5 `pending_title`.

## sendvfile

- Handler: 0x91f453f0. Access: 0x2. Extra: 0x0. Continuation: 0x91f44e88. Data writer: 0x91f448d8 (shared with sendfile).
- Syntax: `sendvfile count=<dword>`. `count` required (dword grammar).
- Behavior:
  1. `count` absent: text `missing count`, return 0x80004005 -> `400- missing count`.
  2. Scratch area (ctx+0x10) fields: +0x4c remaining files, +0x50 initial count. Flags word +0x28: clears 0x80000000, 0x40000000, 0x20000000, 0x10000000; sets 0x08000000 (multi-file mode).
  3. Allocates `(count + 0x2000) * 4` bytes, pool tag 0x62646264. Failure: return 0x8007000e -> `400- out of memory`. Bytes 0x8000.. (count dwords) are zeroed: per-file result array. Bytes 0..0x7fff: two 0x4000-byte receive buffers.
  4. ctx+8 = buffer, ctx+0xc = 0x4000, ctx+0x14 = 0x20. Return 0x02da0004 -> `204- send binary data`.
- Upload stream, repeated `count` times (all integers big-endian):

```text
+0x00 u32 header_len      0x20 + name length
+0x04 u64 creation_time   FILETIME
+0x0c u64 last_write_time FILETIME
+0x14 u64 file_size       only the low 32 bits of data are received
+0x1c u32 attributes
+0x20 name bytes          header_len - 0x20 bytes
then file_size(low 32 bits) bytes of file data
```

  - Name bytes are received into the start of the buffer (over the header). The server does not terminate the name; the sender must include the terminating NUL in header_len. Name limit: 0x4000 bytes.
  - If header_len == 0x20 and file_size == 0: the entry is skipped (no file), result 0.
  - Name starting with `\Device\` (case-insensitive, 8 chars): opened as an NT path (0x91f2ec08); otherwise translated as an XBDM path (0x91f2eb68). Open: access 0x40110000 (GENERIC_WRITE, DELETE, SYNCHRONIZE), allocation size = file_size, attributes 0, share 0, disposition 5 (overwrite-if), options 0 (asynchronous).
  - After open: NtSetInformationFile FileEndOfFileInformation (class 0x14) = file_size; NtCreateEvent (notification) for asynchronous writes. Any failure: the handle is marked delete-on-close (FileDispositionInformation, class 0xd), closed; result = 0x91f41f18(status, 0x82da000d); the file's data bytes are still consumed and discarded.
  - Data: received in 0x4000-byte buffers alternately; each buffer written with NtWriteFile at a running 64-bit offset, waiting on the event before reuse. Write failure: delete-on-close, close, result = 0x91f41f18(status, 0x8000ffff); remaining bytes of that file discarded.
  - On completion of a file (including zero-length): NtQueryInformationFile FileNetworkOpenInformation (0x22); on success NtSetInformationFile FileBasicInformation (4) with CreationTime = creation_time, LastWriteTime = last_write_time, other times 0, FileAttributes = attributes; query failure -> result 0x91f41f18(status, 0x82da000d). File closed. Each file close increments global 0x91f9feec.
  - Successful file: result entry stays 0x00000000.
- Completion: after the last file the continuation returns 0x02da0003 -> `203- binary response follows`, then sends `count * 4` bytes: one big-endian u32 HRESULT per file in upload order, then frees the buffer and ends (no `.` line).
- count=0: the first receive event (header bytes) frees the buffer and returns end-of-transfer while the receive state remains set; subsequent behavior is undefined. A reimplementation should not rely on it.
- Backend requirement: create/overwrite files by XBDM path or NT path, preallocate size, write sequential data, set end of file, set creation/last-write times and attributes, delete partially written files.
- Status: spec complete.

## setconfig

- Handler: 0x91f48cb0. Access: 0x8. Extra: 0x0.
- Syntax: `setconfig category=<dword> index=<dword> value=<dword>`. All required.
- Behavior:
  1. Missing parameter, checked in order category, index, value: `400- missing category` / `missing index` / `missing value`.
  2. ExSetXConfigSetting(category & 0xffff, index & 0xffff, &value, 4); value stored as a big-endian dword.
  3. Failure: text `setvalue failed`, `400- setvalue failed`. Success: `200- OK`.
- Backend requirement: write a 4-byte console configuration setting by (category, index).
- Status: spec complete.

## setcontext

- Handler: 0x91f48430. Access: 0x4. Extra: 0x2.
- Syntax: `setcontext thread=<dword> [<Reg>=<value> ...]`. `thread` required. Register keys are matched case-insensitively and exactly; any subset may be given; unknown keys are ignored.
- Register tables (name, context offset, kind):
  - 0x91f97738: `Msr` 0x4 dword, `Iar` 0x8 dword, `Lr` 0xc dword, `Ctr` 0x10 qword.
  - 0x91f97768: `Gpr0`..`Gpr31` at 0x18 + 8*n qword; `Cr` 0x118 dword; `Xer` 0x11c dword.
  - 0x91f97900: `Fpscr` 0x120 qword; `Fpr0`..`Fpr31` at 0x128 + 8*n qword (raw IEEE bits).
  - 0x91f97a90: `Vscr` 0x230 vector; `Vr0`..`Vr127` at 0x240 + 0x10*n vector.
  - dword: dword grammar (0x91f418d8). qword: `0q` + up to 16 hex digits (0x91f41960); `0x` is not accepted. vector (0x91f41a78): requires `key=`; value copied up to 62 chars, then exactly four comma-separated numbers parsed with C strtoul base-0 rules, each followed by `,`, space, CR or NUL; stored as four u32 in order. Fewer than four numbers read past the value terminator (indeterminate).
- Behavior:
  1. `thread` absent: `400- missing thread`.
  2. Reads the current context with flags 0x17 (control 0x1, floating point 0x2, integer 0x4, vector 0x10) via 0x91f26260. Thread lookup (ObLookupAnyThreadByThreadId) failure or no monitor record for the thread: `405- no such thread`.
  3. Overlays each register parameter present.
  4. Writes back via 0x91f26468: lookup failure or no record: `405- no such thread`. Thread not stopped at a debug event (no saved exception frame): `408- not stopped`. Otherwise copies control (Msr, Iar, Lr, Ctr), floating point (0x108 bytes from 0x120), integer (Gpr0..31, Cr, Xer; also Gpr1 low dword to the alternate stack slot when record flag 0x10000 is set) and vector (0x810 bytes from 0x230) into the saved frame. Success: `200- OK`.
- Backend requirement: read and write the saved register state of a thread stopped at a debug event; locate threads by ID.
- Status: spec complete.

## setdiscboot

- Handler: 0x91f4d4c8. Access: 0x4. Extra: 0x2.
- Syntax: `setdiscboot enable=<dword>`. Required; value 0 or 1.
- Behavior:
  1. `enable` absent: `400- missing enable`.
  2. Value other than 0 or 1: return 0x80004005, `400- `.
  3. or_mask = 0x80 (enable=0) or 0x2000 (enable=1); and_mask = ~or_mask & 0xfffdd77f (clears bits 0x00022880).
  4. Config modify 0x91f4d2d8(3, 0xc, and_mask, or_mask): calls xboxkrnl export ordinal 700 (resolved at first use through the kernel module handle and cached at 0x91f9ff94) with (category 3, index 0xc, and_mask, or_mask). Semantics from the fallback 0x91f4d350: new = (old & and_mask) | or_mask on the 4-byte setting.
  5. Negative status: text `Modify failed: 0x%08x` (status), `400- Modify failed: 0x........`. Success: `200- OK`.
- Backend requirement: atomic read-modify-write of a 4-byte configuration setting (category 3, index 0xc).
- Status: spec complete. Export ordinal 700 name is not present in the image.

## setfileattributes

- Handler: 0x91f46170. Access: 0x2. Extra: 0x0.
- Syntax: `setfileattributes name=<string> [readonly=<dword>] [hidden=<dword>] [createhi=<dword> createlo=<dword>] [changehi=<dword> changelo=<dword>]`. `name` up to 0x140 chars.
- Behavior:
  1. `name` absent: `400- missing name`.
  2. Open via XBDM path translation: access 0x100000 (SYNCHRONIZE), share 3, disposition 1 (open), options 0x20. Failure: 0x91f41f18(status, 0x82da000e).
  3. NtQueryInformationFile FileNetworkOpenInformation (0x22). Failure: 0x91f41f18(status, 0x80004005).
  4. mask/value: `readonly` present -> mask 0x1, value 0x1 if nonzero; `hidden` present -> mask 0x2, value 0x2 if nonzero. attributes = (old & ~mask) | (value & mask); if 0, use 0x80 (normal).
  5. FileBasicInformation (4): CreationTime = createhi:createlo, LastWriteTime = changehi:changelo; halves default to 0; LastAccessTime and ChangeTime 0 (0 = unchanged). NtSetInformationFile failure: 0x91f41f18(status, 0x80004005).
  6. Handle closed; global 0x91f9feec incremented. Success: `200- OK`.
- Backend requirement: query and set file attributes and creation/last-write times by XBDM path.
- Status: spec complete.

## sethddblk

- Handler: 0x91f4f9e0. Access: 0x2. Extra: 0x0. Continuation: 0x91f4f900.
- Syntax: `sethddblk name=<string> block=<dword> count=<dword>`. `name`: NT device object name (no path translation), up to 0xff chars. `block`: 512-byte sector index. `count`: sectors, at most 0x100.
- Behavior:
  1. ctx NULL: `400- `.
  2. `name` absent: `400- `.
  3. `block` absent: `400- missing block`.
  4. `count` absent: helper text `missing count` remains, length 0 is used and processing continues.
  5. count > 0x100: text `Invalid block count: '%d'.`, `400- Invalid block count: '<count>'.`.
  6. ObReferenceObjectByName(name, IoDeviceObjectType) failure: `400- `.
  7. Allocate count*512 bytes (pool tag 0x7862646d); failure: dereference, `400- `.
  8. Scratch: +0 block, +4 byte length, +8 device object, +0xc buffer. ctx+8 = buffer, ctx+0xc = ctx+0x14 = length. Return 0x02da0004: `204- send binary data` (or `204- missing count`).
  9. Receive: count*512 bytes. On completion: IoSynchronousFsdRequest(3 = write, device, buffer, length, byte offset = block * 512 as 64-bit). Dereference, free. Failure: `400- unexpected error`. Success: `200- OK`.
  10. A receive event with 0 bytes (connection loss, or length 0) frees resources and returns 0x80004005 (`400- `). With length 0 the framework runs this immediately after the 204 line, so the client sees `204- ...` then `400- `.
- Backend requirement: raw sector write to a named block device.
- Status: spec complete.

## setmem

- Handler: 0x91f479a8. Access: 0x4. Extra: 0x2. Byte writer: 0x91f26cb8.
- Syntax: `setmem addr=<dword> data=<hex>`. `addr` required. `data`: pairs of hex digits `[0-9a-fA-F]`, no prefix, ends at space, CR or NUL; optional.
- Behavior:
  1. `addr` absent: `400- missing addr`.
  2. `data` absent or empty: `200- set 0 bytes`.
  3. For each pair: a non-hex character in either position (including an odd trailing digit) copies `400- syntax error in data` into resp and returns 0x80004005, so the wire line is `400- 400- syntax error in data`. Bytes already written stay written.
  4. On entering each new 4 KiB page: MmIsAddressValid(address); invalid stops writing.
  5. Byte write under the breakpoint spinlock at raised IRQL: if a software breakpoint occupies the containing aligned dword, the byte is written into the saved original instruction instead of memory; else 0x91f26998 maps the address writable, the byte is written, KeSweepIcacheRange(addr, 1), MmDbgReleaseAddress. Mapping failure stops writing.
  6. All bytes written: `200- set N bytes`. Stopped early: `404- set N bytes` (N = bytes written, decimal).
- Backend requirement: write virtual memory byte-wise with page validity checks, instruction cache maintenance and breakpoint shadowing.
- Status: spec complete.

## setreset

- Handler: 0x91f434c0. Access: 0x0. Extra: 0x0.
- Syntax: `setreset [chord=<string>]`. Value truncated to 4 chars.
- Behavior:
  - With `chord`: ExSetXConfigSetting(2, 5, buf, 5): 5 bytes = chars, NUL, and uninitialized stack bytes if shorter than 4 chars. Failure: `400- Could not change reset key`. Success: `200- OK`.
  - Without `chord`: ExGetXConfigSetting(2, 5, buf, 5, &len); failure: `400- Could not change reset key`. Copies len bytes to resp and terminates: `200- <stored bytes>` (text ends at the first NUL; empty -> `200- OK`).
- Backend requirement: read/write the 5-byte reset chord configuration setting (category 2, index 5).
- Status: spec complete.

## setretail

- Handler: 0x91f4d408. Access: 0x2. Extra: 0x2.
- Syntax: `setretail and=<dword> or=<dword>`. Both required.
- Behavior:
  1. `and` absent: `400- missing and`. `or` absent: `400- missing or`.
  2. Config modify (see setdiscboot) on category 3, index 0xc with and_mask = `and`, or_mask = `or`.
  3. Negative status: `400- Modify failed: 0x%08x`. Success: `200- OK`.
- Backend requirement: atomic read-modify-write of configuration setting (3, 0xc).
- Status: spec complete.

## setserver

- Handler: 0x91f4d190. Access: 0x10. Extra: 0x0. Refresh: 0x91f2ec88.
- Syntax: `setserver none` or `setserver name=<string>` (up to 0xff chars). `none` matches as a bare token or key.
- Behavior:
  1. `none` present: 0x100-byte buffer zeroed. Else `name` required; absent: `400- missing server name`. The name buffer is not cleared beyond the NUL.
  2. ExSetXConfigSetting(3, 0x10, buf, 0x100). Failure: `400- save setting failed`.
  3. Refresh 0x91f2ec88: re-reads setting (3, 0x10); the server name is the text up to the first TAB (at most 0x3d chars). If valid and nonempty: XexLoadImage(`\SystemRoot\connectx.xex`, 8, 0, 0); on success the first drive-map entry named `F` or `SMB` (table 0x91f96bf8, 0x2c-byte entries) is pointed at `\Network\Smb\<server>` (buffer 0x91fae540) and enabled. If empty or invalid: that entry is pointed at `\Badpath` and disabled.
  4. `200- OK` (refresh result ignored).
- Backend requirement: persist the SMB server setting; map or unmap a network-share drive.
- Status: spec complete.

## setsystime

- Handler: 0x91f49a70. Access: 0x8. Extra: 0x0.
- Syntax: `setsystime clockhi=<dword> clocklo=<dword> [tz=<dword>]`. FILETIME halves.
- Behavior:
  1. `clockhi` or `clocklo` absent: `406- ` (no `missing` text; dword-optional helper used).
  2. NtSetSystemTime(clockhi:clocklo); NetDll_XnpNoteSystemTime(3); global 0x91fab97c = 1 (enables `systime`).
  3. `tz` absent: `200- OK`. `tz` value is ignored; only presence matters.
  4. ExGetXConfigSetting(3, 2, 4 bytes) failure: `200- OK`.
  5. If the first byte of setting (3, 2) is 0 (no zone configured), writes defaults, each failure -> `406- `: (3,1) = 0x1e0; (3,2) = `PST\0`; (3,3) = `PDT\0`; (3,6) = 0; (3,7) = 0xffffffc4; (3,4) bytes 0a 05 00 00; (3,5) bytes 04 01 00 00.
  6. Reads (3, 9); if 0, writes 1; write failure -> `406- `. `200- OK`.
- Backend requirement: set the system clock; read/write time-zone configuration settings.
- Status: spec complete.

## setuserpriv

- Handler: 0x91f4bd78. Access: 0x10. Extra: 0x0.
- Syntax: `setuserpriv name=<string> [read] [write] [control] [config] [manage]`. Name up to 0x7f chars. Privilege words match as bare tokens or keys anywhere on the line (parser 0x91f40940): read 0x1, write 0x2, control 0x4, config 0x8, manage 0x10.
- Behavior:
  1. `name` absent: `400- missing name`.
  2. User object lookup 0x91f40498: ObOpenObjectByName in the monitor user directory (root handle 0x91f9fecc, type 0x91f976a8). Not found: `402- file not found`.
  3. Replaces the user's privilege mask (object+8) with the parsed mask (no flags -> 0). `200- OK`. The handler does not persist the change.
- Backend requirement: per-user privilege table keyed by name.
- Status: spec complete.

## spew

- Handler: 0x91f50328. Access: 0x1. Extra: 0x2.
- Syntax: `spew <any>`.
- Behavior: DbgPrint(`SPEW: %hs\n`, full command line). `200- OK`.
- Backend requirement: write a line to the kernel debug output.
- Status: spec complete.

## srvproc

- Handler: 0x91f4be00. Access: 0x4. Extra: 0x0.
- Syntax: `srvproc [num=<dword>]`. Default 2.
- Behavior:
  1. `num` absent: helper writes `missing num`, num = 2 (text overwritten below).
  2. num >= 6: `407- unknown command`.
  3. Text `prev=%u` with the current processor number (KPCR byte r13+0x10c).
  4. 0x91f78a68(NtCurrentThread, num): KeSetAffinityThread(thread, 1 << num) on the thread executing the command (the connection server thread).
  5. `200- prev=<n>`.
- Backend requirement: report current CPU; set affinity of the server thread.
- Status: spec complete.

## stop

- Handler: 0x91f445a8. Access: 0x4. Extra: 0x2. Core: 0x91f25be0 -> 0x91f2da88(request 0, wait 0, notify 1).
- Syntax: `stop`. Arguments ignored.
- Behavior (state machine in `dmexec.c`, critical section 0x91fae620):
  - If a transition is in progress (0x91fae66c != 0) the request waits on the state events and retries.
  - State 1, 2 or 4: previous state saved at 0x91fae668; every thread of the two tracked processes (0x91fadeb4, then 0x91fadeb0) other than the caller, whose monitor record has flag 0x2000, record flag 0x2000000 and 0x8 clear and not already suspended by the monitor (record+0x34 == 0) is suspended (KeSuspendThread, record+0x34 = 1). State becomes 0. Notification type 3 sent: `execution stopped`. `200- OK`.
  - State 0, 3 or 5: text `already stopped`, `426- already stopped`.
  - Any other state value: `414- access denied`.
- Backend requirement: suspend all title/system threads under debugger control; execution-state tracking and notification.
- Status: spec complete.

## stopon

- Handler: 0x91f44518 -> 0x91f443d0(set=1, line, resp). Access: 0x4. Extra: 0x0.
- Syntax: `stopon [all] [fce] [debugstr] [createthread] [stacktrace] [modload] [pogomodstart]`. Bare tokens or keys.
- Behavior:
  - `all`: mask 0xffffffff, text `stop on all`.
  - Else mask: createthread 0x1, fce 0x2, debugstr 0x4, stacktrace 0x8, modload 0x10, pogomodstart 0x40. Unrecognized tokens are ignored.
  - Global 0x91fadd1c |= mask (atomic). `200- OK` or `200- stop on all`.
- Backend requirement: store stop-on event flags.
- Status: spec complete.

## suspend

- Handler: 0x91f47fa8. Access: 0x4. Extra: 0x2. Core: 0x91f267e8.
- Syntax: `suspend thread=<dword>`.
- Behavior: `thread` absent: `400- missing thread`. ObLookupAnyThreadByThreadId failure: `405- no such thread`. KeSuspendThread, dereference, `200- OK`.
- Backend requirement: suspend a thread by ID (any process).
- Status: spec complete.

## sysfileupd

- Handler: 0x91f64aa0. Access: 0x8. Extra: 0x0. Continuation: 0x91f64520. Source `sysfileupd.c`.
- Syntax:
  - `sysfileupd name=<ntpath> query=<nonzero>`
  - `sysfileupd name=<ntpath> ftimehi=<dword> ftimelo=<dword> localsrc=<ntpath>`
  - `sysfileupd name=<ntpath> ftimehi=<dword> ftimelo=<dword> size=<dword> crc=<dword>`
  - Paths are NT object paths (no translation), up to 0x1ff chars.
- Error text: every failure after allocation sends `400- HRESULT 0x%x` (`_snprintf`, overwriting any `missing` text). Win32 errors come from RtlNtStatusToDosError as 0x8007xxxx.
- Behavior:
  1. ctx NULL: `400- `.
  2. Allocate 0x4200 bytes (pool tag 0x75667378): data buffer 0x4000 + name 0x200. Failure: `400- HRESULT 0x8007000e`.
  3. `name` absent: HRESULT 0x80070057.
  4. Query mode (`query` nonzero): NtOpenFile(GENERIC_READ|SYNCHRONIZE, share 1, options 0x50), FileNetworkOpenInformation. Success: `200- 0x%I64x 0x%I64x` (end-of-file size, last-write time; no padding). Failure: HRESULT of the DOS error.
  5. `ftimehi`, `ftimelo` required; absent: HRESULT 0x80070057.
  6. Local copy mode (`localsrc` present): creates missing parent directories of `name` (0x91f64448), opens source (read, share 1, options 0x60), queries it, creates `name` (GENERIC_WRITE|SYNCHRONIZE, allocation = source size, attributes 0x80, share 0, overwrite-if, options 0x64), sets end of file, copies in 64 KiB chunks, sets all four times = ftime and attributes = source attributes. Failure: target marked delete-on-close; HRESULT of DOS error. Success: `200- OK`. No binary transfer.
  7. Upload mode: `size` (stored in ctx+0x14), `crc` required; absent: HRESULT 0x80070057.
  8. Temp name: `name` with the part after the last `\` replaced by `\temp%04x.tmp` (value = u16 at offset 0x12 of kernel data export ordinal 173). No `\` or less than 14 bytes of room: HRESULT 0x8007007b.
  9. Creates parent directories, then the temp file: NtCreateFile(GENERIC_WRITE|DELETE|SYNCHRONIZE, allocation = size, attributes 0x80, share 7, disposition 2 (create), options 0x4020). Sets end of file = size (failure: delete-on-close, close). Failures: HRESULT of DOS error.
  10. Running CRC = 0xffffffff. `204- send binary data`.
  11. Receive `size` bytes; each full 0x4000 buffer and the final partial buffer: CRC update (reflected CRC-32 table at 0x91f00f88, polynomial 0xedb88320, no final inversion), synchronous NtWriteFile. Write failure: temp deleted and closed; HRESULT text.
  12. After the last byte: CRC != `crc` -> STATUS_CRC_ERROR (0xc000003f) -> temp deleted -> `400- HRESULT 0x<dos-mapped>`. CRC equal -> finalize 0x91f64340: opens existing `name` (SYNCHRONIZE|FILE_WRITE_ATTRIBUTES) and sets attributes 0x80; renames temp to `name` with replace (FileRenameInformation 0xa); sets all four times = ftimehi:ftimelo and attributes 0x80; closes. Finalize failure: delete, HRESULT text. Success: `200- OK`.
  13. Connection loss before all bytes: buffer freed, temp marked delete-on-close, return 0x8000ffff with text `HRESULT 0x8000ffff` (handle not closed).
- CRC note: `crc` must equal the bitwise complement of the standard CRC-32 of the data.
- Backend requirement: NT-path file create/rename/delete, directory creation, attribute and time setting, local file copy, CRC-32.
- Reply results: the handler returns 0x02da0000 for every non-negative result, so query success is `200- 0x<eof> 0x<lastwrite>` and local copy mode always replies `200- OK` (0x91f64858 returns the positive Win32 error, which is never treated as a failure).
- Status: spec complete. Mid-stream write failure: subsequent buffers are written to handle 0 and the final status reflects the last failure [INFERENCE].

## systeminfo

- Handler: 0x91f4ccc8. Access: 0x1. Extra: 0x0. Collector: 0x91f4c840. Continuation: 0x91f4ca60.
- Syntax: `systeminfo`.
- Behavior:
  1. Collector fills a 0x20-byte record in the scratch area: +4 base kernel version (4 x u16 from XboxKrnlBaseVersion), +0xc kernel version (XboxKrnlVersion), +0x14 XDK version {2, 0, 0x5308 (21256), 0}, +0x1c flags derived from the first dword of kernel data export ordinal 342 (bits 0-1 platform, bits 28-31 system, bit 0x20 HDD) and 0x2000000 from global 0x91f9f680 (test kit).
  2. The handler copies its uninitialized stack buffer at sp+0x50 (frame 0x170) into resp with `strncpy`-like 0x91f73838 (bug); the 202 line text is indeterminate, or `multiline response follows` when it begins with NUL. The bytes are whatever the previous call at the same stack depth left there, typically the frame of the previous command handler run on the same thread (for example `getnetaddrs`, also frame 0x170, keeps the title address record at sp+0x50), so the text depends on command history. openxbdm sends empty text: `202- multiline response follows`.
  3. Returns 0x02da0002; lines:

```text
HDD=Enabled | HDD=Disabled
Type=TestKit | Type=DevKit
Platform=<P> System=<S>
BaseKrnl=%d.%d.%d.%d Krnl=%d.%d.%d.%d XDK=%d.%d.%d.%d
.
```

  - P by flags & 3: 0 `Alpha`, 1 `Mongrel`, 2 `Shiva`, 3 `Waternoose` (string has trailing space before `System=`).
  - S by flags & 0xf0000000: 0 `Xenon`, 0x1 `Zephyr`, 0x2 `Falcon`, 0x3 `Jasper`, 0x4 `Trinity`, 0x5 `Corona`, 0x6 `Winchester`, 0x8 `Ridgeway`, other `Unknown`.
- Backend requirement: kernel version, hardware revision, HDD presence, kit type.
- Status: spec complete; the 202 line text is indeterminate in stock (see 2).

## systime

- Handler: 0x91f499a0. Access: 0x0. Extra: 0x0.
- Syntax: `systime`.
- Behavior: global 0x91fab97c == 0 (no `setsystime` since boot; only direct writer found): `406- `. Else KeQuerySystemTime: `200- high=0x%x low=0x%x` (no zero padding).
- Disagreement: fixture `systime.capture` and client `SysTime` expect `200- clockhi=0x01da3411 clocklo=0x9a2b8200`. Format string 0x91f07270 in this image is `high=0x%x low=0x%x`.
- Backend requirement: read the system clock; flag set by setsystime.
- Status: spec complete.

## tdecomp

- Handler: 0x91f4f6e8. Access: 0x0. Extra: 0x0.
- Syntax: `tdecomp [UseGDFAttrib] [IgnoreGDFAttrib]`. Bare tokens or keys.
- Behavior: `UseGDFAttrib` sets global 0x91f9fef0 = 0; else `IgnoreGDFAttrib` sets it to 1; else unchanged. Text: `IgnoreGDFAttrib` if bit 0 set, else `NoGDFAttrib`. `200- <text>`. The value is not persisted.
- Consumer: monitor control code 0x7e (case 0x91f3b9bc of the control routine 0x91f3b4d0, published through kernel data export 89) returns 1 when DVD emulator flags 0x91f9fec8 have bit 0x2 (set by 0x91f3f7a8 when the attached drive identifies as `XBox 360 DVD Emu` with protocol `0002`), else the value of 0x91f9fef0. The system queries it to decide whether title decompression ignores GDF attributes.
- Backend requirement: one boolean setting readable by the control routine.
- Status: spec complete.

## threadinfo

- Handler: 0x91f48f28. Access: 0x4. Extra: 0x0. Collector: 0x91f265b0. Continuation: 0x91f48e70.
- Syntax: `threadinfo thread=<dword>`.
- Behavior:
  1. ctx NULL: `400- `. `thread` absent: `400- missing thread`.
  2. Lookup failure: `405- no such thread`.
  3. Collected under the thread's process spinlock: suspend = kernel suspend count (signed byte), minus 1 if the monitor suspended the thread during `stop`; priority (u8); TLS base; start address; stack base; stack limit; slack = 0x540 constant; create time hi/lo; name address and name length including NUL (from the monitor thread record, 0 if none); processor (u8); last error.
  4. `202- thread info follows`, one line, `.`:

```text
suspend=%d priority=%d tlsbase=0x%08x start=0x%08x base=0x%08x limit=0x%08x slack=0x%08x createhi=0x%08x createlo=0x%08x nameaddr=0x%08x namelen=0x%08x proc=0x%02X lasterr=0x%08x
```

  - If the line buffer is smaller than 0x100 the continuation returns 0x82da0105 (not observed with the 0x100 framework buffer).
- Capture `threadinfo.capture` matches.
- Backend requirement: per-thread scheduler and stack information by ID.
- Status: spec complete.

## threads

- Handler: 0x91f47d88. Access: 0x4. Extra: 0x0. Enumerator: 0x91f25f28. Continuation: 0x91f47cb8.
- Syntax: `threads`.
- Behavior:
  1. ctx NULL: `400- `. Allocate 0x400 bytes (capacity 0x100 IDs); failure: `400- out of memory`.
  2. Enumeration holds the execution-state busy count (0x91f2d930/0x91f2d9b8). State 3 (`pending`): empty list. Otherwise walks threads of process 0x91fadeb4 then 0x91fadeb0, creating monitor records on demand, and collects thread IDs whose record has flag 0x2000.
  3. More than 0x100 threads: `400- unexpected error`.
  4. `202- thread list follows`; IDs emitted in reverse collection order as `%d` (signed decimal) lines, several per send, then `.`.
- Capture `threads.capture` matches (IDs 0xfb000058 as `-83885992`).
- Backend requirement: enumerate debuggable thread IDs.
- Status: spec complete.

## Client disagreements

- `systime`: see above.
- `setmem`: early stop returns status 404 with `set N bytes`; client `SetMem::parse` uses `expect_ok` and fails on it.
- `stopon`: client tokens `titleinit`, `titleexit`, `debugger` are not recognized by this image (ignored); image tokens `modload`, `pogomodstart` are absent from the client.
