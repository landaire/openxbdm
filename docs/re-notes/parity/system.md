# System domain parity

Stock XBDM 2.0.21256.0. Server: `crates/openxbdm-server/src/commands/system.rs`. Host mock: `crates/openxbdm-server-host/src/backend/system.rs`. Xbox: `crates/openxbdm-server-xbox360/src/backend/system.rs` and `system/flash.rs`. Tests: `crates/openxbdm-server-host/tests/system.rs`.

## Commands

| Command | Handler | Status |
| --- | --- | --- |
| reboot | 0x91f49cd8 | done |
| magicboot | 0x91f49de0, core 0x91f278a8 | done; in-place relaunch through the routine registered by control code 0x20 |
| recovery | 0x91f473b0 | done |
| title | 0x91f47210, 0x91f46ff0, export 81 | done |
| deftitle | 0x91f47410 | done |
| systime | 0x91f499a0 | done (`200- high=0x%x low=0x%x`, `406- ` before `setsystime`) |
| setsystime | 0x91f49a70 | done |
| setdiscboot | 0x91f4d4c8 | done |
| setreset | 0x91f434c0 | done |
| flash | 0x91f4a730, continuation 0x91f4a628, writer 0x91f735d0 | done; host simulates the writer |

## Reboot core 0x91f278a8

1. Title given and FTitleExists fails: 402.
2. Execution state read under the exec lock (0x91f2d930 increments the lock count and returns 0x91fae664; 0x91f2d9b8 releases it).
3. Launch flags 0x91fa2324 := flags; a given title replaces the launch strings 0x91fa2020/0x91fa2120/0x91fa2220.
4. Forced cold boot (flags |= 4): `drivemap internal` (0x91f9f678) clear, hardware revision (ordinal 342 dword & 0xf0000000) >= 0x40000000, 0x91f9f680 clear (set at startup from hardware flag 0x02000000, the test-kit bit), and 0x91f4e648 fails: three attempts of 0x91f4e378, an SMC NVRAM read (HalSendSMCMessage command 0x11) of 0x20 bytes at offset 0.
5. flags & 6 == 0: execution state 4 (reboot_title) returns `200- OK` with no action. Else when the XAM title launch routine is registered (0x91fa200c nonzero) and 0x91f276d8 returns 0 (walks the system and title thread lists, 1 when a thread is in a state that blocks relaunch), exec state := 4 (0x91f2da88(4,0,1)), flags stored, routine 0x91fa2008(0), `200- OK`.
6. Otherwise `200- OK`, sleep 200 ms, 0x91fa2328 := 1, boot-wait mode, 0x91f3b208 (WriteIniFile, `execution rebooting`, close connections), HalReturnToFirmware(6).

## Settings file

- WriteIniFile gate 0x91f31e48: skipped on CD boot (ordinal 342 halfword +0xe bit 0x400), before load completes (0x91f9f668, set after the saved file is read, before recint.ini), and after a wipe (0x91f9f664, which no code in the image sets). From the title process it signals the server thread and waits up to 1 s. This domain writes at each stock WriteIniFile call (the `title` command writes once when the title is set and once more after it; `title nopersist` writes twice) instead of through `settings_dirty`, so the bit 4 texts repeat as in stock. The Xbox requests carry the caller's process type (`KeGetCurrentProcessType`) to the server thread for the title-process texts.
- WriteIniFileImpl 0x91f31d28: 0x4000-byte pool buffer (tag 'Xbdm'), `\SystemRoot\MobileJ.dat` (path `\x01:\MobileJ.dat`; dminit maps drive `\x01` to `\SystemRoot`), `GENERIC_WRITE|SYNCHRONIZE`, `FILE_OVERWRITE_IF`, options 0x20. Buffered writer 0x91f31860 flushes when the buffer fills; a write error raises bug check 0x2c.
- Line order (0x91f31a90, every line ends CR LF): `[xbdm]`; `verbose level=%d`; `wait`/`wait stop`/`wait forever`; title lines (0x91f51ed0); `dbgname name=`; `staticip use=%d, addr=0x%08x`; `subnet addr=0x%08x`; `gateway addr=0x%08x`; `dvdperf start`; `memtrack flags=0x%x stackdepth=0x%x`; notifyat (0x91f38ac8); lockmode/adminpw/user (0x91f40ab0); dumpsettings (0x91f2d5c0); dumpmode, eventdefer, debugger init (0x91f3ce50); httpreg (0x91f30c88); xhttpproxy (0x91f37f18); `recovery`.
- Loading (dminit 0x91f32628, reader 0x91f316b8): the reader first allocates its 0x4000-byte buffer with ExAllocatePoolTypeWithTag (0x91f330d8, tag 0x6d646258, pool type 2); when that fails it returns at once, so neither file is read, nothing is traced, and 0x91f9f668 stays clear. Otherwise `\SystemRoot\xbdm.ini` when it exists, else `\SystemRoot\MobileJ.dat`; then `\SystemRoot\recint.ini`; the buffer is freed at the end. Parser 0x91f315a0 with that buffer: lines end at CR or LF; a remainder starting with NUL ends the file; text without a terminator (including the last line of the file) loses its last byte.
- DoIniLine 0x91f311b8 (exact case-insensitive command word): `wait [forever|stop]` sets the mode unconditionally; `notify` ignored; `notifyat`, `staticip`, `gateway`, `subnet`, `memtrack`, `httpreg`, `netsim`, `xhttpproxy` go to their domains; `drivemap internal=` sets 0x91f9f678; `sysset videostd=` sets the video standard read by the alternate writer 0x91f31fb0 (console domain, `ini_sysset`); other lines run through the command table with all access and no output.
- Startup after load: internal drive map (0x91f2f0f8) when set; persistent notification targets (0x91f3c440); boot-wait consumer 0x91f32448 clears modes 1 and 2 and rewrites the file (mode 3 persists).

## Debug monitor control codes

Rows in docs/re-notes/dispatcher.md. Server-state logic is in `commands/system.rs` (host-tested); the Xbox services in `backend/system.rs` run it through `dispatcher::call_on_server`: inline under the startup lock until the command loop starts, then posted to the server thread with the caller blocked until the next pass serves it.

| Code | Stock | openxbdm |
| --- | --- | --- |
| 0x02 | 0x91f3b208 | `prepare_reboot`; then the server thread exits and later `call_on_server` requests fail |
| 0x17 | 0x91f321d8 | `wipe_settings` (no CD-boot or load gate) |
| 0x1d | 0x91f32110 | `copy_settings(SettingsCopy::File)` through a 0x1000-byte pool buffer |
| 0x20 | 0x91f51df8 | Xbox only: registration words, version, XAM listener; enables the in-place relaunch of `magicboot` |
| 0x21 | 0x91f523a0 | Xbox sequence on the caller's thread with three server steps in stock order: `trace_title_reboot` before pending_title; after the disc wait `title_reboot_stop`; after the stop or start `title_reboot_launch` and `launch_image_exists`. Execution transitions and the stop through the debugger (`request_execution`, `stop_at_pending_title`); on a timed-out stop the caller prints the bit 0x10 text and starts execution itself, as stock does |
| 0x22 | 0x91f32080 | `copy_settings(SettingsCopy::Memory)` |
| 0x77 | 0x91f52260 | `launch_override`; disc wait on the caller's thread |

0x1e and 0x1f (exports 92 and 91, the `sysset` block) belong to the console domain.

## Trace texts

Texts of the `verbose level=` mask (stock 0x91f9fef4), reproduced byte for byte. Server-thread code reads `state.console.trace_mask`; the settings writer and Xbox code on other threads read the published mirror.

Bit 4 (settings file):

| Stock site | Text | openxbdm |
| --- | --- | --- |
| 0x91f31758 LoadIniFile | `XBDM: LoadIniFile\n`, then 0x91f31538: `XBDM: Handle: 0x%0.8x, File Size: %d\n` (low dword of the end of file from FileNetworkOpenInformation) or `XBDM: NtQueryInformationFile Failed: 0x%0.8x\n`; only when the saved file opened, before its lines run | `load_settings`, `trace_settings_file`, `Backend::settings_file_size` |
| 0x91f3179c | `XBDM: g_fFinishedLoadingIniFile = TRUE\n`, whether or not the saved file opened | `load_settings` |
| 0x91f3182c | `XBDM: Finished loading recint.ini\n` after its lines ran | `load_settings` |
| 0x91f319e8 WriteIniSzNoCRLF | `XBDM: WriteIniSzNoCRLF: '%s'\n` for each text written; line terminators written directly (0x91f31860) are not echoed; WriteIniSz with a null text (end of the launch-title line, end of the `sysset` line of 0x91f31fb0) echoes `(null)` | `write_text`, `write_bytes`, `write_line` echo once per call; `end_line` does not echo; `end_null_line` / `echo_null` |
| 0x91f31d3c WriteIniFileImpl | `XBDM: WriteIniFileImpl - entry\n`; after the close `XBDM: WriteIniFileImpl - Done writing ini file...\n`, or `XBDM: WriteIniFileImpl - Failed Create: 0x%0.8x\n`; no second text when the 0x4000-byte buffer cannot be allocated | `write_settings_file`, `CreateSettingsError` |
| 0x91f31e70, 0x91f31ea0, 0x91f31ecc, 0x91f31f04 WriteIniFile | `XBDM: Cannot write xbdm.ini: CD boot\n`; `XBDM: WriteIniFile - not finished loading\n`; `XBDM: WriteIniFile - file wiped\n` (unreachable: flag without writer); `XBDM: WriteIniFile - called from title process - signal server\n` | `save_settings`, `Backend::title_process_caller` |
| 0x91f32014 alternate text | the inlined `(null)` echo after the `sysset` line | `copy_settings` |
| 0x91f32080 CaptureIniFile | `XBDM: CaptureIniFile - start\n`, `XBDM: CaptureIniFile - end\n` | `copy_settings` (memory) |
| 0x91f32110 WriteAltIniFile | `XBDM: WriteAltIniFile - start\n`, `XBDM: WriteAltIniFile - end\n` (no end text when the buffer cannot be allocated) | `copy_settings` (file) |
| 0x91f321d8 WipeIniFile | `XBDM: WipeIniFile - signaling system thread to wipe ini file.\n`; `XBDM: WipeIniFile - already wiped\n` (unreachable) | `wipe_settings` |

Bit 8 (title image paths):

| Stock site | Text | openxbdm |
| --- | --- | --- |
| 0x91f44628 FGetImageAndDrive | `[xbdm] FGetImageAndDrive(\n   szTitle='%s',\n   szDir='%s',\n   ...)\n` (no `dir`: `(null)`); `[xbdm] FGetImageAndDrive buffer overflow copying path\n`, `... appending '\\'\n`, `... appending title\n` (the last still succeeds with the cut image); `[xbdm] FGetImageAndDrive succeeded:\n   oszImage='%s'\n   oszDrive='%s'\n` or `[xbdm] FGetImageAndDrive failed:\n` | `image_and_drive`, `join_image_and_drive` |
| 0x91f447e8, 0x91f448a0 FTitleExists | `[xbdm] FTitleExists(oszImage='%s',fPostBoot=%s)\n` and `[xbdm] FTitleExists() returning %s\n` with `TRUE`/`FALSE`; a disc image accepted before boot gets no second text | `title_exists` |

Bit 0x10 (title launch):

| Stock site | Text | openxbdm |
| --- | --- | --- |
| 0x91f51ea0 | `[xbdm] Failed to register for XAM notifications.\n` | Xbox `service_register_xam_globals` |
| 0x91f523fc | `[xbdm] DmpTitleReboot: Reason=%d, g_XamGlobals.Flags=0x%08x\n` (the flags are the launch flags 0x91fa2324) | `trace_title_reboot` |
| 0x91f524bc | `[xbdm] DmpTitleReboot: stopping\n` | `title_reboot_stop` |
| 0x91f5254c | `[xbdm] DmpTitleReboot: DMN_EXEC_PENDING_TITLE state timed out\n` | Xbox `service_title_reboot` |
| 0x91f52564 | `[xbdm] DmpTitleReboot: not stopping\n` (reason 0 only; other reasons that do not stop print nothing) | `title_reboot_stop` |
| 0x91f525a8 | `[xbdm] DmpTitleReboot: updating launch info\n  ImageName='%s'\n   DDrive='%s'\n   CommandLine='%s'\n` | `title_reboot_launch` |
| 0x91f52658 | `[xbdm] DmpTitleReboot: updating [default] launch info\n  ImageName='%s'\n   DDrive='%s'\n   CommandLine='%s'\n` | `title_reboot_launch` |

The disc wait 0x91f52040 prints without a mask bit: `[xbdm] Timed-out waiting for media detect\n` and `[xbdm] XamGetMediaInfo() - (media=%d,type=%d)\n`.

Texts without a counterpart: `[XBDM] Error, WriteIniFile no server thread to signal.\n`, `[XBDM] Warning, WriteIniFile timeout waiting for server thread.\n` and the two WipeIniFile equivalents. openxbdm requests from other threads wait for the server without a time limit and do nothing when no server thread serves them.

## Deviations

- `setreset` stores zero bytes after the chord terminator; stock stores uninitialized stack bytes.
- `title nopersist` on the settings-file path fires an RtlAssert in stock; openxbdm clears the persistent title without it.
- `magicboot` from the settings file sends `200- OK` to an out-of-range connection slot in stock; openxbdm sends nothing.
- Control code 0x22: a text that fills the caller's buffer makes stock write it to handle 0 and bug check 0x2c; openxbdm keeps the bytes that fit and reports that count.
- Control code 0x1d with pad: the bytes after the text in the last 0x1000-byte write are zero; stock sends uninitialized or stale pool bytes.
- Control codes 0x02, 0x17, 0x1d, 0x21, 0x22 and 0x77 and exports 28, 42, 81 and 125 run their server-state part through `dispatcher::call_on_server`. Before the command loop starts they run inline on the caller's thread; afterwards they wait for the server thread's next pass (at most about 20 ms). They fail (do nothing) when issued on the server thread or above passive level, before the server state exists, or after code 0x02 stopped the server. Stock runs them on the caller's thread; for 0x17 and WriteIniFile from the title process stock also defers to the server thread, with a 1 s limit.
- Exports 28 and 125: the registered relaunch routine runs on the server thread; stock calls it on the caller's thread. A caller in the title process then ends its thread (`ExTerminateThread(0)`) as in stock.
- Control code 0x21 does not re-initialize stock's critical section 0x91fadca0 (the debug routine's lock); the debugger domain has no equivalent lock.
- `flash` writer (0x91f735d0): header offsets and sizes that leave the upload or boot loader buffer fail with `ERROR_INVALID_PARAMETER` (a hardware identifier offset outside the image fails the revision check); stock reads past the buffer. See `backend/system/flash.rs`.

## Remaining gaps

- `flash_commit` treats a missing image buffer as success. `flash_begin` always runs before the continuation, so the case is unreachable; removing it needs the buffer to move into the continuation, which the allocation-free server core cannot hold.

## Settled questions

- The recovery boot bit (0x91fade6c bit 0x80) has no reader in the image; `State::recovery_boot` records it.
- The wipe flag 0x91f9f664 has no writer in the image, so the WriteIniFile wipe gate never applies.
- The startup SMC branch of dminit (0x91f329d4..0x91f32a6c) is implemented by the console domain (`console::check_settings_block`, called from `load_settings` when `drivemap internal` is off).
