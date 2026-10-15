# Hardware domain parity

Commands: autoinput, avatar, bkgdmodetest, bootanim, builtinmu,
enablewirelesscontrollers, irtsweep, kinecthsmsg, mdetect, mixcmd,
mockcurrencyvalue, oddlog, playto, pogoctrl, runnuioobe, runoobe,
runoobecheckpoint, tdecomp, usbportctrl.

Specs: docs/re-notes/commands/group1.md (autoinput, avatar, bkgdmodetest,
bootanim, builtinmu), group3.md (enablewirelesscontrollers), group4.md
(irtsweep), group5.md (kinecthsmsg, mdetect, mixcmd, mockcurrencyvalue),
group6.md (oddlog, playto, pogoctrl, runnuioobe, runoobe, runoobecheckpoint),
group7.md (tdecomp), group8.md (usbportctrl).

## Code

- Server: `crates/openxbdm-server/src/commands/hardware.rs` (table, handlers,
  `queuepackets`/`setpacket` 204 continuations) and
  `commands/hardware/automation.rs` (virtual controller engine shared by both
  backends: queue playback, the 10 us advance timer, polls, and the
  `Controllers` orchestration that keeps binding, allocation and debugger
  extension messages outside the controller lock).
- Host mock: `crates/openxbdm-server-host/src/backend/hardware.rs`. Records
  every service request (binds, guide presses, debugger messages, radio,
  system messages, PlayTo, USB port power, avatar hooks, PGO operations,
  optical disc log starts) and replies from settable state, including
  injected failures.
- Xbox: `crates/openxbdm-server-xbox360/src/backend/hardware.rs`. Uses the
  services stock uses: XAutomationpBindController/UnbindController/
  InputXenonButton, XInputdSetRFPowerMode, ExGet/ExSetXConfigSetting and
  kernel export 700 (through console::Backend), XMsgStartIORequest,
  ExDebugMonitorService(8), XAM ordinals 0x3dd, 0x5f2, 0x827, 0x828, kernel
  ordinal 825, NetDll_XNetGetTitleXnAddr/DebugXnAddr, kernel data export 89
  (debug monitor block) and 173 (tick), Ke*Event, ExCreateThread, NtWriteFile.
  Controller state is static and spin-locked because the monitor control
  routine services polls on other threads.
- Monitor control services (routed by backend/dispatcher.rs):
  0x21 `service_automation_rebind`, 0x46 `service_odd_read_start`,
  0x47 `service_odd_read_complete`, 0x48 `service_odd_mount`,
  0x49 `service_odd_speed_change`, 0x4a `service_odd_auth_state`,
  0x7a `service_automation_get_state`, 0x7b `service_automation_get_status`,
  0x7c `service_automation_get_capabilities`, 0x7e
  `service_ignore_gdf_attributes` (after the dispatcher's DVD emulator check),
  and the NuiCam raw data requests in `backend/hardware/nuicam.rs`: 0x96
  complete, 0x97 queue, 0x98 flush, 0xa1 capture mode (the second title
  terminate routine in backend/performance.rs flushes too).
- Startup (`hardware::initialize`, stock order of 0x91f32628): drive
  authentication state from `\Device\CdRom0` IOCTL 0x240cc (0x91f3d558), XAM
  0x3dd input focus query (0x91f25288), kernel 0x30d NuiCam control routine
  (0x91f652b8); each resolved once with XexGetProcedureAddress.
- Optical disc trace stream: while the PIX stream is active
  (`performance::pix::stream_active`, stock 0x91f62758), control 0x46 writes
  an `ODD ` record `{time high, time low & ~1, sector, count, authentication
  state}` and 0x47 `{time high, time low | 1, status}` through
  `performance::pix::write_tagged_record` (stock 0x91f788b8), before the
  oddlog bookkeeping.

## Exports

Xbox `backend/hardware.rs` declares the stock exports that the commands
themselves call, so one implementation backs both: 147 (oddlog start, path
argument), 148 (oddlog stop), 166 (input focus of a user), 167 bind, 168
unbind, 169 connect, 170 disconnect, 171 setpacket (console-layout gamepad),
172 queue (console-layout packets, optional time and count arrays, accepted
count out), 173 clearqueue, 174 queryqueue (outputs cleared first). Results
are the stock HRESULTs (`0x02da0000`, `0x82da0017`, `0x82da002a`,
`0x82da001c`, `0x82da0007`, `0x82da0018`, `0x82da0019`, mapped file
statuses). The PGO exports are described in docs/re-notes/pgo.md.

## Tests

`crates/openxbdm-server-host/tests/hardware.rs` covers each command over TCP
with raw sessions (no client support exists for these commands): replies,
error statuses and texts, argument parsing order, devkit-only rejection on a
test kit, configuration bit edits, upload continuations (`204`, `400-` on an
empty upload, errors after the upload), playback timing through simulated
polls, debugger extension messages, and the optical disc log state machine.
Unit tests in `automation.rs` cover the playback engine.

## Divergences from stock

- `mixcmd xamheap` without a space at line offset 14: stock executes a trap;
  this server replies `423- bad parameter`.
- `autoinput bind` with a queue length whose allocation size does not fit in
  32 bits, and `queuepackets` with an upload size that does not fit in 32
  bits: stock truncates the size and overruns the allocation; this server
  replies `428- out of memory`.
- `pogoctrl` with `module`, `reset` or `scale` absent: stock passes
  uninitialized stack contents; this server uses 0 (every module, no reset,
  scale 0).
- `setpacket` debugger message: the pad byte after the user is uninitialized
  in stock and 0 here.
- `playto` failure text: stock formats `Invalid parameter: <line>` with an
  unbounded sprintf; this server truncates at the reply buffer.
- Playback timer: stock arms a 10 us timer when an entry without a poll count
  starts; this server evaluates it with the same millisecond tick right
  after the operation, which differs only if the tick advances within those
  10 us.
- Optical disc log: the file is created (after drive-table translation) and
  the header written by the start call before the writer thread is created;
  stock does both in the writer thread and waits for its status. A stop waits
  on the same notification "finished" event stock uses (0x91fad060), set by
  the writer on exit. When ExCreateThread fails both clear the busy flag, but
  stock leaves the finished event clear, so its next stop waits forever; this
  server sets it, and that stop replies `200- stopped logging`.
- Export 147 copies the name with strcpy into a static buffer of about 0x100
  bytes (0x91facf40); this server translates it on the server thread without
  that copy. When the server thread cannot take the request (called on it,
  above passive level, or after it stopped) the start fails as a failed
  translation does: STATUS_NO_SUCH_FILE, result `0x82da000d`.
- Drive authentication state at startup: stock reads the IOCTL output even
  when the request fails (uninitialized stack); this server uses 0 then.
- PGO runtime (backend/hardware/pgo.rs, docs/re-notes/pgo.md), where stock
  faults, overruns a buffer, or reads uninitialized memory:
  - Entry allocation failure in exports 181, 183, 186, 189: stock increments
    a counter at address 0x10 or 0x8; the increment is skipped (181 still
    returns 0x10).
  - A full extended block whose record left the list: stock uses the entry
    offset past the reservation; the entry is dropped.
  - Export 112 with an address outside every module: stock reads the loader
    entry from uninitialized stack; the name is empty (fatal
    `IrtPogoInit: GetModuleFileName failed`).
  - Registration before export 113: stock reads the header through a null
    pointer; fatal `Invalid header signature`. Export 113 with a null name:
    fatal `Could not read base filename from object.`. Export 115 with a
    null phase converts it as empty.
  - `OutputPath=` with an empty value: stock compares the unit before its
    stack buffer; it is taken as not a separator. A base path without `\`:
    stock faults; the path is kept.
  - Devkit fallback name: stock appends without a bound into a 0x104-unit
    stack buffer (and faults on a base path without `\`); the name is cut to
    the 0x104 units the name builder copies. A base path without `\` also
    faults stock's profile name builder (wcslen of a null separator); the
    name is built from the whole path.
  - A profile name that fills the 0x104-byte name buffer: stock leaves it
    unterminated; it ends at the buffer. A module path over 0x103 bytes in
    UTF-8 is cut there for `pogo.ini`.
  - A UTF-8 phase whose last sequence takes the terminator: stock copies
    uninitialized stack units after it; they are 0.
- PGO runtime, other differences: the 0x20000-byte key table (0x91fa3af4) is
  not allocated, keys are computed directly (same keys; its allocation
  failure cannot occur); the profile directory scan, whose result the image
  never uses, is not made; dispatch table writes that stock guards with an
  exception handler treat an unmapped entry as the fault (a mapped read-only
  table faults here); the probe slots of the module interface receive the
  second instruction word of this module's export entries, as stock stores
  its own.

## Gaps

- Xbox PGO export 107 (`pogo.ini`) needs the server's drive table and runs
  on the server thread; called on the server thread, above passive level, or
  after the server stopped, the file is not read and the result is
  0x02da0000.
- Host: the drive events (0x46..0x49) and polls are Xbox-side services; the
  host exercises playback through `Mock::poll` and has no optical drive.
- Control code 0x1a (stock `HalOpenCloseODDTray(1)`, result `0x02da0000`)
  has no case in the Xbox dispatcher; it returns 0 without opening the
  tray.

## Hardware differential results

Method: `xeedee parity record --commands
docs/re-notes/parity/hardware-commands.txt` against stock XBDM 2.0.21256.0
booted from flash and against openxbdm served by the kd host, each run
starting without `DEVKIT:\oxtest`; then `xeedee parity compare --variances
docs/re-notes/parity/hardware-variances.txt <stock> <openxbdm>`. Result:
399 exchanges, 0 differences outside the varying fields. Two stock runs
compared the same way also show 0 differences.

Coverage: 399 command lines over 134 of the 177 commands (read-only forms,
error paths rejected before any side effect, scratch files under
`DEVKIT:\oxtest`, framework lines: empty line, unknown command, case,
unknown processor, line too long). Excluded commands:

- Persistent state or reboot in every form: bootanim, civfail, civinject,
  civsetbits, civstart, civstop, civverify, crashdump, datacentermode,
  deftitle, dvdeject, fastpipe, flash, fmtfat, httpreg, iptvbootstrapurl,
  iptvprovidername, iptvprovisioningurl, iptvsupportinfo, kdnet,
  kinecthsmsg, livesigninrequired, lockmode, magicboot, mdetect, prevflash,
  reboot, recovery, resetnetra, runnuioobe, runoobe, runoobecheckpoint,
  screenshot (stops execution), setconfig, sethddblk, setsystime, stop,
  sysfileupd, title, user, userlist, welcomedefault, welcomehide.
- Lines that fault the devkit kernel, so they cannot be compared:
  `autoinput user=0x0 queuepackets count=0x0` (zero-size
  ExAllocatePoolTypeWithTag raises STATUS_ASSERTION_FAILURE in the kernel;
  stock makes the same call), `dvdperf stop` without a trace (stock frees a
  null buffer and ExFreePool asserts; openxbdm replies `200- OK`),
  `threadstat handle=0x0` (ObReferenceObjectByHandle raises the RIP
  `Invalid handle specified`; stock writes a dump and restarts, openxbdm
  replies `200- Error 0x6`), and `dvdblk block=0x0` (zero-size
  allocation).

Varying fields (hardware-variances.txt), each differing between two stock
runs or depending on the loaded image:

- File times of scratch files and directories (`dirlist`,
  `getfileattributes`, `getvfattr` records): created at run time.
- `getpid` pid: random per boot. `keyxchg` data: random.
- `getcontext` and `threadinfo` of the title thread: register values of a
  running thread and its creation time in this boot.
- `getsockinfo`: handles, client ports and connections in TIME_WAIT depend
  on the connection history. The flags of the listener (0x00808000) and of
  accepted connections (0x00808800) are equal.
- Counters: `mixcmd querystats`, `mixcmd xamheap`, `nicstats`, `pixcmd m`.
- `querypc` ratelo/ratehi: stock reports stale scratch words.
- `modules` and `walkmem`: the xbdm.xex line and the memory layout follow
  the loaded image and boot. The openxbdm image is reported with size
  0xe5000, checksum, timestamp and pdata 0 and without `dll`; these come
  from the image built by xex-link, not from the command.

Behavior established by the comparison: `threads` takes the debug monitor
data words +0x50 and +0x54 as the process objects; the listening socket
sets SO_REUSEADDR before bind (flag 0x00800000 on the listener and
accepted sockets); `getmemex` names its keys `ADDR` and `LENGTH` in the
missing texts.

Result counts: 378 exchanges equal, 21 equal outside the varying fields, 0
differ. Crash dumps written during the runs remain on the console in
`DEVKIT:\dumps\xshell.xex\`.
