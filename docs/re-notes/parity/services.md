# Parity: services domain (IPTV, CIV)

Specs: `commands/group1.md` (civ*) and `commands/group4.md` (iptv*).
Server: `crates/openxbdm-server/src/commands/services.rs`. Host mock:
`crates/openxbdm-server-host/src/backend/services.rs` (CIV) and the console
domain's XConfig store (IPTV). Xbox backend:
`crates/openxbdm-server-xbox360/src/backend/services.rs`. Tests:
`crates/openxbdm-server-host/tests/services.rs`. The client has no commands
for this domain.

| Command | Wire | Host mock | Xbox backend |
| --- | --- | --- | --- |
| civfail | matches; `%p` as 8 upper-case hex digits [INFERENCE] | handle counter, call log, injectable last error | ExCreateThread(flags 0x20); thread calls XAM 0x9c0(0xff) then HalReturnToFirmware(1) |
| civinject | matches | call log | XAM 0x9bf(hash, read) |
| civsetbits | matches except absent `on` | kernel detection mask semantics | kernel exports 0x295/0x296/0x292/0x294 |
| civstart | matches | call log, configurable result | XAM 0x9bb |
| civstatus | matches | configurable record or error | XAM 0x9be with 0x18-byte record |
| civstop | matches | call log | XAM 0x9bc |
| civverify | matches except absent `milliseconds` | call log, configurable result | XAM 0x9bd(m, 0, 0) |
| iptv, iptvdvr, iptvallowuninstall | matches | XConfig 3/0xc, export 700 and fallback, failure injection | console domain `modify_config_flag` |
| iptvbootstrapurl, iptvprovidername, iptvprovisioningurl, iptvsupportinfo | matches, including reads past a short line | XConfig 9/1..4 | console domain `xconfig_set` |

## Remaining differences

- `civfail` failure path: stock prints the server thread's stale last
  error; openxbdm prints the last error of the thread running the server
  (same field, different thread history). openxbdm runs own-thread
  commands (civinject, civstart, civstop, civverify) on the server thread,
  so their resolution failures also update that field; stock runs them on a
  temporary thread.
- `civsetbits` without `on` and `civverify` without `milliseconds`: stock
  uses an uninitialized stack variable. openxbdm sets no bit and uses the
  0x100 default budget respectively.
- Positional IPTV values read past a short line: stock connection buffers
  keep bytes from an earlier connection in the same slot; openxbdm clears
  the buffer when a connection is accepted.
- XAM ordinals 0x9bb..0x9c0: semantics unknown (no xam.xex image). The host
  mock logs the requests and returns configured values instead of
  simulating verification.

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
