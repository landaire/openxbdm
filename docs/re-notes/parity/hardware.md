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
- Optical disc log engine shared by both backends:
  `commands/hardware/odd.rs` (control-code argument layouts of 0x46, 0x48,
  0x49, the 64-slot record ring 0x91f3d2c0/0x91f3d330/0x91f3d3b0, the events
  0x91f3d210, 0x91f3d6e0, 0x91f3d7a0, 0x91f3d808, the writer pass
  0x91f3d878 with the record formats of 0x91f3d410, and reserve/start/stop
  0x91f3dad0/0x91f3d140) behind the `OddPlatform` trait (time base, file
  create/write/close, writer thread). Start is split into `odd_log_reserve`
  (busy check, ring reset) and `odd_log_start` so the path is translated
  only after the busy check, as in stock.
- Host mock: `crates/openxbdm-server-host/src/backend/hardware.rs`. Records
  every service request (binds, guide presses, debugger messages, radio,
  system messages, PlayTo, USB port power, avatar hooks, PGO operations)
  and replies from settable state, including injected failures. Its
  `OpticalDrive` implements `OddPlatform` (settable time base and file
  status, log files kept in memory); `Mock::odd_read_start`,
  `odd_read_complete`, `odd_mount` and `odd_speed_change` deliver drive
  events through the shared engine as control codes 0x46..0x49 do, and
  `Mock::is_connected` takes the engine path of polls 0x7b/0x7c.
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
  0x1a open tray (`HalOpenCloseODDTray(1)`, result `0x02da0000`, stock
  0x91f3b848), 0x21 `service_automation_rebind`, 0x46 `service_odd_read_start`,
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
polls, debugger extension messages, the optical disc log state machine, and
the log file content from injected drive events (`READ`, `GMNT`, `SSC `
records, events outside a log, warning file statuses). Unit tests in
`automation.rs` cover the playback engine; `odd.rs` covers record times and
the ring after a drop. `tests/filesystem.rs`
`pogo_ini_loads_through_the_published_table` covers export 107's file
reading with the published drive table.

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
  stock translates, creates and writes in the writer thread and waits for its
  status. A stop waits on the same notification "finished" event stock uses
  (0x91fad060), set by the writer on exit. When ExCreateThread fails both
  clear the busy flag, but stock leaves the finished event clear, so its next
  stop waits forever; this server sets it, and that stop replies `200-
  stopped logging`. A warning status from the file create starts the log
  without a writer; stock runs a writer that writes nothing.
- Export 147 copies the name with strcpy into a static buffer of about 0x100
  bytes (0x91facf40), an overrun for longer names; this server translates the
  name on the caller's thread with the published drive table, without that
  copy.
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
  - Export 107 with record 0 and an `OutputPath=` line: stock reads the
    base path at address 0x88 and faults; the line is skipped.
  - A count block read while export 112 on another thread is still
    creating it (export 110, `pogoctrl snapshot`): stock reads the header
    through the null block address and faults, or reads a block being
    written; the console stops with `PCILookupPGCHdr: CLIENTINFO not
    found`. Title termination in that window skips the record's shutdown
    profile.
- PGO runtime, other differences: the 0x20000-byte key table (0x91fa3af4) is
  not allocated, keys are computed directly (same keys; its allocation
  failure cannot occur); the profile directory scan, whose result the image
  never uses, is not made; dispatch table writes that stock guards with an
  exception handler treat an unmapped entry as the fault (a mapped read-only
  table faults here); the probe slots of the module interface receive the
  second instruction word of this module's export entries, as stock stores
  its own; record byte +0x6cb, which stock leaves zero, is set with a
  release store once the count block is written, and the readers of the
  block load it with acquire first; count resets clear word counters with
  word stores and doubleword counters with doubleword stores, so probes
  still running update whole counters (stock calls memset).

## Drive table off the server thread

Exports that stock serves inline on the caller's thread translate drive
paths with a copy of the drive table the server publishes after every change
(`Published::Drives`; control code 0x03, network share refresh, drivelist
F/SMB disable, settings load). Xbox `backend/filesystem/paths.rs` keeps the
copy under a spin lock; callers copy it out and translate at their own IRQL
through `CallerPaths` (`PathServices`: title memory reads with their own
scratch buffer, ObTranslateSymbolicLink, published trace mask, DbgPrint).
Converted: export 107 `pogo.ini` (0x91f3e038; `pgo::load_ini` takes the
table and `IniFiles`), 147 oddlog start, 73/74 capture start/stop, 149
profiler start, 131 module snapshot and the xtrace snapshot, 16 XBE info,
instruction trace file names, PIX capture files. Control code 0x03 stays on
the server thread because it changes the server-owned table.

## Gaps

None.

## Hardware differential results

Method: `xeedee parity record --commands
docs/re-notes/parity/hardware-commands.txt` against stock XBDM 2.0.21256.0
booted from flash and against openxbdm served by the kd host, each run
from a fresh boot with the kd host attached and without `DEVKIT:\oxtest`;
then `xeedee parity compare --variances
docs/re-notes/parity/hardware-variances.txt <stock> <openxbdm>`. Result:
1060 exchanges, 0 differences outside the varying fields. Two stock runs
of the 399-exchange list that preceded the `civ*` and breakpoint lines,
compared the same way, also show 0 differences.

Coverage: 138 of the 177 commands (read-only forms, error paths rejected
before any side effect, scratch files under `DEVKIT:\oxtest`, XAM media
verification sessions that end stopped, breakpoints at unmapped
addresses, framework lines: empty line, unknown command, case, unknown
processor, line too long). Excluded commands:

- Persistent state, user interface, or reboot in every form: bootanim,
  civfail (a message box that waits for dismissal), civsetbits,
  crashdump, datacentermode, deftitle, dvdeject, fastpipe, flash, fmtfat,
  httpreg, iptvbootstrapurl, iptvprovidername, iptvprovisioningurl,
  iptvsupportinfo, kdnet, kinecthsmsg, livesigninrequired, lockmode,
  magicboot, mdetect, prevflash, reboot, recovery, resetnetra,
  runnuioobe, runoobe, runoobecheckpoint, screenshot (stops execution),
  setconfig, sethddblk, setsystime, stop, sysfileupd, title, user,
  userlist, welcomedefault, welcomehide.
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
- `threads`: XAM starts and ends worker threads in bursts (thread
  notifications every few milliseconds), so a list can include one of
  them.
- `drivefreespace` of `E:` and `DEVKIT:`: free space follows files
  written between runs, such as crash dumps.

Behavior established by the comparison: `threads` takes the debug monitor
data words +0x50 and +0x54 as the process objects; the listening socket
sets SO_REUSEADDR before bind (flag 0x00800000 on the listener and
accepted sockets); `getmemex` names its keys `ADDR` and `LENGTH` in the
missing texts; 641 ascending breakpoints at unmapped addresses (more than
the 0x240 entries that eight blocks hold when filled in ascending order)
all succeed; an empty tray puts XAM's media verification in its no-media
mode.

Result counts: 1042 exchanges equal, 18 equal outside the varying fields,
0 differ. Crash dumps written during the runs remain on the console in
`DEVKIT:\dumps\xshell.xex\`.

## Checks outside the command list

Run on the same devkit against stock XBDM and against openxbdm, each with
the kd host attached; the results were the same on both unless noted.

- Key exchange: a client value of 1, the modulus plus 1, and the modulus
  gave shared values 1, 1 and 0, and 2^761 gave the server's public value
  while 2^705 did not. Each case was checked by setting `adminpw passwd=`
  with the key the expected shared value derives, then `authuser admin` on
  a new unlocked connection (`parity/security.md`, "Key exchange").
- Breakpoints of threads that cannot stop: with `debugger disconnect` and
  `dumpmode enabled`, a breakpoint in an xshell thread's loop produced
  `break addr=0x92055504 thread=0xf9000010` without ` stop`, and the
  thread kept running. With `dumpmode smart` the same breakpoint stopped
  the thread (`execution stopped`, `break ... stop`), `getmem` showed the
  original word, and `continue` with `go` released it.
- `break now` with the kd host attached: `200- OK`, and the trap reached
  the kernel debugger, which continued it. Without a kernel debugger and
  with `dumpmode smart`, stock sent no reply and restarted, and the free
  space of `E:` dropped by about 42 MB, the size of a crash dump.
- `civ*` passes over an empty tray, from one connection with client-side
  waits: `civverify milliseconds=500` then `civstatus` after 1 s gave
  `Blocks Checked 4 ... Total Blocks 264354`; a second `civverify` during
  a pass returned 0x21; after three 500 ms passes and 3 s of an unlimited
  pass the count was 23; `civstop` reset it to 0. XAM's
  `[CIV] Starting TEST BUILD of CIV server.` text came from a
  title-process thread (0xf9000020).
- CPU profiler: `lopctrl start name="E:\oxlop.bin" interval=0x100000
  flags=0x3f` for 5 s, `lopctrl info` (about 0x3b90 samples), `lopctrl
  stop`. In the file header at 0xc000 each processor's interrupt count
  (+0x104) equals its sampled (+0x11c) plus skipped (+0x134) counts.
- `notifyat port=0 addr=none drop` with notification channels open:
  `200- OK`, and the console closed the first channel.
- Debug event wake socket, with a probe system module under stock XBDM: a
  UDP select on the debug monitor caller was woken after 215 ms by a
  datagram sent at 200 ms, both to 127.0.0.1 and to the debug address.
  openxbdm printed no `no wake socket` text at start, so it kept its wake
  socket.
