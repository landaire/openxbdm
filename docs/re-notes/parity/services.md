# Parity: services domain (IPTV, CIV)

Specs: `commands/group1.md` (civ*) and `commands/group4.md` (iptv*).
Server: `openxbdm/server/src/commands/services.rs`. Host mock:
`openxbdm/server/host/src/backend/services.rs` (CIV) and the console
domain's XConfig store (IPTV). Xbox backend:
`openxbdm/server/xbox360/src/backend/services.rs`. Tests:
`openxbdm/server/host/tests/services.rs`. The client has no commands
for this domain.

| Command | Wire | Host mock | Xbox backend |
| --- | --- | --- | --- |
| civfail | matches; `%p` as 8 upper-case hex digits [INFERENCE] | handle counter, call log, injectable last error | ExCreateThread(flags 0x20); thread calls XAM 0x9c0(0xff) then HalReturnToFirmware(1) |
| civinject | matches | XAM 0x9bf: pending error counts, session open for two zero counts | XAM 0x9bf(hash, read) |
| civsetbits | matches except absent `on` | kernel detection mask semantics | kernel exports 0x295/0x296/0x292/0x294 |
| civstart | matches | XAM 0x9bb session state machine | XAM 0x9bb |
| civstatus | matches | XAM 0x9be record and check failure flag | XAM 0x9be with 0x18-byte record |
| civstop | matches | XAM 0x9bc reset | XAM 0x9bc |
| civverify | matches except absent `milliseconds` | XAM 0x9bd and the worker's no-media passes on the simulated millisecond clock (`services.now`) | XAM 0x9bd(m, 0, 0) |
| iptv, iptvdvr, iptvallowuninstall | matches | XConfig 3/0xc, export 700 and fallback, failure injection | console domain `modify_config_flag` |
| iptvbootstrapurl, iptvprovidername, iptvprovisioningurl, iptvsupportinfo | matches, including reads past a short line | XConfig 9/1..4 | console domain `xconfig_set` |

## Remaining differences

- `civfail` failure path: stock prints the server thread's stale last
  error; openxbdm prints the last error of the thread running the server
  (same field, different thread history). civinject, civstart, civstop
  and civverify (dispatch flag 0x4) run on a temporary title-process
  thread in both, so their resolution failures do not touch that field.
- `civsetbits` without `on` and `civverify` without `milliseconds`: stock
  uses an uninitialized stack variable. openxbdm sets no bit and uses the
  0x100 default budget respectively.
- Positional IPTV values read past a short line: stock connection buffers
  keep bytes from an earlier connection in the same slot; openxbdm clears
  the buffer when a connection is accepted.
- Verification timing: the host's worker runs on a millisecond clock the
  embedder sets (`services.now`); each no-media read and throttle wait
  takes exactly its timeout. On the console each wait (XAM ordinal 0x426:
  milliseconds times -10000 as a relative kernel timeout, 0x817ff0ac)
  ends somewhat after its timeout, so block ends drift later. Devkit run
  (empty tray, one session): `civverify milliseconds=500` three times,
  then `milliseconds=-1`; `civstatus` 3.0 s into the unlimited pass gave
  23 = 4 + 5 + 5 + 9. Without drift the tenth unlimited block ends at
  2800 ms and the count is 24; 23 means each 300 ms iteration ran at
  least about 22 ms long, while five 100 ms blocks still fit a 500 ms
  budget (under 25 ms per read). The host test
  `checked_blocks_accumulate_over_the_passes_of_a_session` replays the
  sequence and checks the 23/24 boundary.
- Drive mode: an empty tray selects the no-media mode (devkit: `Failed
  Reads 0`, `Total Blocks 264354` after a pass), the mode the host
  simulates. XAM selects it when IOCTL 0x24090 and
  IOCTL_CDROM_GET_DRIVE_GEOMETRY (0x2404c) both fail; the kernel's
  geometry handler (K16547 0x80116d90) fails with 0xc00002b6 when the
  device's sector count (+0x98) is zero. A disc in the tray (mode 1 or 2)
  is not simulated.
- The continuous verification mode (object flags 0x4, 0x8) is not
  simulated: commands never enter it; only XAM itself (0x8175ff28) does.
- `XamShowBadDiscErrorUI` shows a message box and returns when it is
  dismissed; the host has no user interface and records the call.
- XAM defect, not simulated by the host (the console backend calls XAM
  and meets it as stock does): when ExCreateThread fails in
  `XamMediaVerificationCreate`, 0x81a15790 polls forever for the worker
  (state stays 4) and `civstart` never replies.

## RE findings

- 0x91f418d8 (dword getter) stores the parsed prefix whenever the parameter
  is present, even when it then reports the parameter missing.
- 0x91f72b58 / 0x91f72ba0: SetLastError / GetLastError on KTHREAD+0x160.
  0x91f78c10: XexGetModuleHandle wrapper. 0x91f729d8: export by ordinal;
  entry-point address counts as absent (0xc0000263).
- Kernel export 700 = ExReadModifyWriteXConfigSettingUlong
  (`(old & and) | or`). Kernel 0x292..0x296 = XeKeysSecurity Initialize,
  LoadSettings, SaveSettings, SetDetected, GetDetected; hypervisor syscalls
  0x52 (initialize, clears the mask), 0x55 (set bit < 64), 0x56 (get, all
  ones when uninitialized).

## XAM verification service (xam.xex 2.0.16547, load 0x815f0000)

Source file `civremote.cpp`. Object 0x81d22368 (O); state word
0x81d7e0cc: 0 idle, 1 worker started, 2 continuous pass running, 3 ready,
4 busy, 5 worker startup failed. Stop flag 0x81d33c04. Pending injected
errors: 0x81d8e31c read, 0x81d8e320 hash. Object flags O+0xc: 0x1 and
0x2 hash detection seen, 0x4 verification disabled, 0x8 continuous mode,
0x10 startup check failed. O+0x1c is the 0x18-byte progress record (+4
failed reads, +8 failed hashes, +0xc blocks checked, +0x10 total blocks,
+0x14 completed).

- 0x9bb `XamMediaVerificationCreate(n)` (0x8175fed8 -> 0x81a16110): flags
  0x4 or 0x8: return 0. State 0 -> 4 or return 5. 0x81a15ec8: a worker
  handle still set returns 21; while flag 0x1 is clear,
  `XeKeysSecurityGetDetected() & 0x1000` (detection bit 12) sets flags
  0x3; builds the verifier (static 0x81d7e268, 0x81a17190) with the
  failure counts the last close kept (O+0x38, O+0x3c) and verifier flag 2
  from object flag 0x2; clears the stop flag; ExCreateThread(flags 0x21 |
  (1 << n) << 24, worker 0x81a15c00), resumed through 0x81d1252c. Then
  0x81a15790 polls until the state is 1 or 5: 1 clears O+0x28, O+0x2c,
  O+0x30, sets state 3 and returns the creation result (0); 5 returns
  0x571.
- Worker startup 0x81a15b38 -> 0x81a17b38: opens `\Device\CdRom0`
  (failure: its DOS error); IOCTLs 0x24090 and 0x2404c; both failing (no
  disc) select the no-media mode (verifier +0x100ac = 1: reads return
  zeros after a wait, total size 0x204d10 + 0x203d10). 0x81a17698 then
  fails the startup once for a pending hash error and once for a pending
  read error (each consumed, error RtlNtStatusToDosError(0xc0000156),
  verifier flag 0x8). A failed startup sets object flag 0x10 when
  verifier flag 0x8 is set, destroys the verifier, stores the error at
  O+0x34 and sets state 5. Success creates the request and exit events and
  sets state 1.
- 0x9bd `XamMediaVerificationVerify(m, apc, context)` (0x81a15fd0):
  flags 0x4 or 0x8: queue the APC to the caller and return 0. State 3 ->
  4 or return 0x21. Duplicates the caller's thread handle (failure:
  RtlNtStatusToDosError), stores m, signals the worker and returns 0
  without waiting. The worker runs 0x81a17f28 and sets state 3 after it.
- Pass 0x81a17f28: start time from the time base (XAM ordinal 0x42f,
  `mftb`), budget m * (QueryPerformanceFrequency / 1000) ticks. Each
  iteration checks one block (0x81a17c08), increments the checked count
  (verifier +4, zeroed only when `XamMediaVerificationCreate` builds the
  verifier, so it accumulates over the passes of a session) and copies
  the record: +4 failed reads (verifier
  +0x10080), +8 failed hashes (+0x48), +0xc checked, +0x10 total
  ((+0x1c + +0x20) >> 4 without a hash table: 0x408a2 for the no-media
  layout), +0x14 verifier flag 0x1. Then: stop flag set: the pass ends
  ("CIV aborted"). 0x81a17870 advances the position (verifier +0xc) by
  16 sectors; in the no-media mode it never reaches the end, so a pass
  never completes. m = -1: when the time since the last wait (or the
  start) exceeds the throttle interval (0, or 300 ms with verifier flag
  2; `cmpd`/`bf gt` at 0x81a18140), the worker waits 200 ms on its thread
  handle and moves the mark to the block's end time; with interval 0 this
  is after every block, so a steady unlimited pass checks one block per
  300 ms. Otherwise the pass
  ends once the time since its start reaches the budget; the check runs
  after every block, so a pass checks at least one block. A finished
  verification (verifier flag 0x1) fails the pass with 84. Verifier flag 2
  (detection bit 12 at startup) clears the finished flag and makes every
  pass unlimited with the 300 ms interval.
- Block check 0x81a17c08 in the no-media mode (verifier +0x100ac = 1):
  the hash index block (position >> 15) is read and its hash checked
  when it differs from the last one checked (verifier +0x10084, initially
  -1), then the target block is read and its hash checked. Each read
  (0x81a164c8) waits 100 ms (verifier +0x100b0, set by 0x81a16c08) on the
  worker's own thread handle and returns zeros; a pending read error
  fails it after the wait (status 0xc00000b5, failed reads + 1). The hash
  compare (0x81a16650) ignores the digest in this mode; a pending hash
  error fails it (failed hashes + 1). The first failure ends the block;
  a failed index check leaves the index unrecorded, so the next block
  reads it again.
- 0x9be `XamMediaVerificationFailedBlocks(record)` (0x81a15a48): record
  size other than 0x18 returns 8; copies the record; returns 0x570 when
  flag 0x10 is set and flag 0x4 is clear, else 0.
- 0x9bc `XamMediaVerificationClose()` (0x81a15998): state 0: trace, 0.
  Stop flag 0 -> 1 or return 5. Signals the worker, waits for its exit
  event (a running pass ends after the block in progress, or after the
  next block when the worker is in a throttle wait), then 0x81a15848:
  keeps the verifier's failure counts at O+0x38
  and O+0x3c, destroys the verifier, closes the events, clears O+0x28 and
  O+0x30, flags 0x18 and the state. The record's failure counters and
  total stay.
- 0x9bf `XamMediaVerificationInject(hash, read)` (0x8175ff68): both zero:
  Create(5), and on 0 the continuous mode 0x81a16200(3, 120000 ms,
  processor 5), which returns 21 when Create left the state at 3. Else
  each nonzero count is stored only when no error of its kind is pending
  (compare-and-swap with 0). Consumers: block read 0x81a165d4 (status
  0xc00000b5, failed reads +1, error 30), hash compare 0x81a1672c (failed
  hashes +1), startup 0x81a177ec.
- 0x9c0 `XamShowBadDiscErrorUI` (0x81787750): ignores its argument. With
  bit 0x4 of halfword 0x8e03860a set (XAM ordinal 0xb46) it logs its
  name through 0x819a7430 and returns 5. Else 0x817ac8e8(78, 9, 1): a
  message box for any user with XAM string resources 78 and 9, shown
  through ordinals 0x539 and 0x2ca; it waits for the overlapped result
  (0x43b), so the `civfail` thread reboots only after the box is
  dismissed.
