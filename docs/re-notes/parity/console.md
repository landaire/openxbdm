# Parity: console domain (identity and configuration)

Specs: `commands/group1.md` (altaddr, autoshutoff), `group2.md`
(confignetra, consolefeatures, consolemem, consoletype, datacentermode,
dbgname, debugmemsize, debugmode, discoverable, dmversion), `group3.md`
(dumpmode, dumpsettings, eventdefer, feature, getconsoleid, getnetaddrs),
`group4.md` (httpreg), `group5.md` (kiosk, livesigninrequired), `group6.md`
(resetnetra), `group7.md` (setconfig, setretail, setserver, systeminfo),
`group8.md` (verbose, welcomedefault, welcomehide).
Server: `crates/openxbdm-server/src/commands/console.rs`. Host mock:
`crates/openxbdm-server-host/src/backend/console.rs`. Xbox backend:
`crates/openxbdm-server-xbox360/src/backend/console.rs`. Tests:
`crates/openxbdm-server-host/tests/console.rs`. Client:
`crates/openxbdm-client/src/commands/info.rs`.

The domain also owns the simulated console configuration (XConfig) used by
the hardware, file system, performance, services and system domains:
`console::Backend::{xconfig_get, xconfig_set, xconfig_modify}` and
`console::modify_config_flag` (stock 0x91f4d350).

| Command | Wire | Host mock | Xbox backend |
| --- | --- | --- | --- |
| altaddr | matches | title address record and status | `NetDll_XNetGetTitleXnAddr(3)` |
| autoshutoff | matches, including the DbgPrint line | XConfig 7/2, inactivity update counter | `ExSetXConfigSetting`, `XamSetInactivityTimeFromConfig(1)` |
| confignetra | matches; `%p` is 8 upper-case digits (kernel formatter) | network service record, failure injection | `XMsgStartIORequest(0xef, 0xa00004)` with {5, record, 0xc} |
| consolefeatures | matches | feature flags | hardware flags, `XNetGetOpt(0x2f00)` |
| consolemem | matches (0, 1, 2) | memory statistics | `ExDebugMonitorService(8)` |
| consoletype | matches | `test_kit` | hardware flag 0x02000000 |
| datacentermode | matches | XConfig 3/0xd | export 700 or get/modify/set |
| dbgname | matches | I2C settings block, failure injection | SMC I2C via `HalSendSMCMessage` (0x91f4e378/0x91f4e4e0) |
| debugmemsize | matches | memory statistics | `ExDebugMonitorService(8)` +0x70 |
| debugmode | matches (always `407-`) | none | none |
| discoverable | matches | XConfig 7/0xf | `ExSetXConfigSetting` |
| dmversion | matches | none | none |
| dumpmode | matches, including the test-kit override | `test_kit` | none |
| dumpsettings | matches | none | none |
| eventdefer | matches | none | none |
| feature | matches | call log; absent export | `XexGetProcedureAddress(xam, 515)` and call |
| getconsoleid | matches | id or failure | `XeKeysGetConsoleID(NULL, buf)` |
| getnetaddrs | matches | both address records and statuses | `NetDll_XNetGet{Debug,Title}XnAddr(3)` |
| httpreg | command, settings line and registration task match | asynchronous HTTP/1.1 client over TCP | XAM `XHttp*` (0xc9-0xd8) driven by the server loop |
| kiosk | matches | XConfig 3/0xd and 0xb/3 | export 700 or fallback, `ExSetXConfigSetting` |
| livesigninrequired | matches | XConfig 3/0xd | export 700 or fallback |
| resetnetra | matches | reset counter | `XMsgStartIORequest` with {2, 0, 0} |
| setconfig | matches | XConfig, failure injection | `ExSetXConfigSetting` |
| setretail | matches, including `Modify failed: 0xc0000138` without export 700 | XConfig 3/0xc, export switch | export 700 only |
| setserver | matches except the bytes after the name (below) | XConfig 3/0x10, client load status | `ExSetXConfigSetting`, `XexLoadImage(connectx.xex, 8)`, drive table |
| systeminfo | lines match; 202 text differs (below) | versions and hardware flags | `XboxKrnlBaseVersion`, `XboxKrnlVersion`, hardware flags |
| verbose | matches, including the stored prefix of a rejected value | none | none |
| welcomedefault, welcomehide | matches | XConfig 3/0xc | export 700 or fallback |

Settings file lines (`console::*_settings_lines`): `verbose level=%d`,
`dbgname name=<name>` (unquoted), `dumpsettings ...`, `dumpmode <mode>`,
`eventdefer set ` plus ` <name>` per event (so two spaces before the first
name), `httpreg server=%s object=%s port=%u` or `httpreg clear`. The
alternate writer of control codes 0x1d and 0x22 (system domain) adds
`sysset[ videostd=0x%08x]` (`console::sysset_settings_lines`); the
settings-file `sysset videostd=` line goes to `console::ini_sysset`.
`console::initialize` runs before the settings file is read: a test kit
starts with dump mode `enabled`, and the network share drive is refreshed.
After the settings files, when `drivemap internal` is off,
`console::check_settings_block` (stock 0x91f329f0) reads the I2C settings
block up to three times; when every read fails on a console from Trinity on
(hardware flags generation >= 4), the console becomes a test kit (stock
0x91f9f680; `Backend::mark_test_kit`), dump mode `smart` becomes `enabled`,
and a nonzero dword at +0x10 of the 0x80-byte flash block at offset 0x80 is
cleared, written back, and the console restarts (`HalReturnToFirmware(6)`).
The meaning of that flash field is unknown.

The registration task (stock 0x91f30580) runs from `Server::poll_timers`.
`Server::title_terminated` runs `console::title_terminated` (stock
0x91f30998, from the title-terminate routine 0x91f32398): before system
software 0x20165400 a request in progress is closed and the state returns
to pending, so the task registers again.

Cross-thread state on the Xbox (`backend/console.rs`): the debug name is
published through `Backend::publish_debug_name` into a spin-locked static
(`console::debug_name()`, read by control codes 0x0b and 0x33); the settings
block of codes 0x1e/0x1f is held by the backend
(`Backend::{system_settings, set_system_settings}`). `Platform::debug_print`
passes the text as `DbgPrint("%.*s", ...)`, so the kernel applies the same
output limit as to stock's formatted messages.

## Control codes

| Code | Behavior | Implementation |
| --- | --- | --- |
| 0x1e | Stock export 92: copy min(+0 size, 0xc) bytes of `{+0 size, +4 flags, +8 video standard}`, keep flags bit 0, write the settings file. Returns 0. | `service_set_system_settings`; the write is requested from the server thread |
| 0x1f | Stock export 91: copy min(+0 size, 0xc) bytes back, restore the caller's size. Returns 0. | `service_get_system_settings` |
| 0x33 | Stock export 17 with `{+0 buffer, +4 size pointer}`: `0x80070057` for a NULL argument, `0x82da0105` when cut, else `0x02da0000`. | `service_get_debug_name`, `commands::console::copy_debug_name` |
| 0x17, 0x1d, 0x22 | Settings file wipe, alternate write, capture. | System domain (settings writer) |

## Exports

Implemented in `crates/openxbdm-server-xbox360/src/backend/console.rs`.
Readers use mirrors the server publishes through `Backend::publish`
(`commands::console::Published`: debug name, dump mode, dump settings,
event defer mask, trace mask, lab server registration). Writers build a
`commands::console::ExportedSetting`
and apply it on the server thread through `dispatcher::call_on_server`
(`apply_exported_setting`: store, publish, write the settings file, and
for export 43 the I2C block). Called on the server thread or above
passive level, a write export cannot reach the server and the setting is
dropped.

| Ordinal | Behavior |
| --- | --- |
| 17 | Debug name into `(buffer, size pointer)`; see control code 0x33. |
| 43 | Set the debug name (NULL clears; 20 bytes kept). |
| 91, 92 | Settings block of control codes 0x1f and 0x1e; 91 returns its argument. |
| 117, 118 | Crash dump mode get (NULL: `0x82da0017`) / set (test kit: 0 becomes 1 with the DbgPrint); any value is kept and reads back. |
| 119, 120 | Crash dump settings block (0x108 bytes: flags, path) get / set. |
| 121, 122 | Event defer mask get / set. |
| 140 | Test kit flag. |
| 161 | System information block (size >= 0x20 signed, cleared to its stated size). |
| 175, 176 | XConfig (3, 8) qword get / set, `0x82da0007` without hardware flag 0x10; failures are `status | 0x10000000`. 176 takes the value in one 64-bit register (`export_raw!` entry). |
| 194 | `(u64 *transaction, buffer, u32 *size)`: a nonzero `*size` without a buffer, or a buffer without a size pointer, is `0x82da0017`. Pending or in progress `0x82da0150`, cleared `0x82da0002`, failed `0x82da0100`, rejected `0x82da010a`, response too large `0x82da000f` (transaction and size 0). Registered: the response is copied when it fits; transaction and response length are always stored; `0x82da0105` when `*size` is too small; success without a size pointer. Logic: `HttpRegistration::export_response` on the published registration. |
| 213 | Debug memory size (`debugmemsize`); 0 when service 8 fails. |
| 214 | `consolemem` value (`ConsoleMemory::of`). |
| 220 | `consolefeatures` bits: 1 debugging, 2 secondary NIC, 4 1 GB (`KitFeatures::mask`). |

The XHttp status callback runs through a bridged entry (`http_status_entry`),
since XAM calls it with the console ABI.

## Remaining differences

- `httpreg` settings line for a stored object without a leading `/` or with
  an empty server: stock traps (`twui 0x19`) in the ini writer; openxbdm
  writes the line.
- `systeminfo` 202 line: stock copies stale stack bytes (command history
  dependent); openxbdm sends `202- multiline response follows`.
- `setserver name=`: stock writes the 0x100-byte setting with stale stack
  bytes after the name's NUL; openxbdm writes zeros.
- `verbose` trace texts (`commands::console::TraceMask`, mirror published
  for other threads): bit 0x1 command, status and title command processor
  thread lines, 0x2 binary receive progress, 0x4 settings file reads and
  writes (each WriteIniSzNoCRLF text echoed; `dumpsettings`, `eventdefer`
  and `httpreg` lines are one text each, as stock formats them into one
  buffer), 0x8 path and title image lookup, 0x10 title launch control
  codes, 0x20 startup CD-ROM messages. Sites and texts:
  `commands/framework.md`, `parity/system.md`. The `thr=` value is the
  server thread for every command, status and receive line, since openxbdm
  services title-owned connections' sockets on the server thread.
- `eventdefer` mask is stored and persisted; notification delivery in
  openxbdm is single-threaded, so deferral to the server thread has no
  observable effect.
- Control code 0x33 / export 17 with a zero size: stock underflows the
  size and copies the whole name past the buffer; openxbdm writes nothing
  and returns `0x82da0105` (`0x02da0000` for an empty name).
- XAM ordinal 515 (`feature`) semantics are unknown (no xam.xex image).
- XHttp request headers beyond `User-Agent` and `Host` are unknown (no
  xam.xex image); the host simulation sends only those.

## RE findings

- I2C settings block (SMC command 0x11, device 0xd4): read 0x91f4e378 and
  write 0x91f4e4e0, 8-byte chunks, two attempts, 2 ms / 3 ms pauses on
  write. Layout: +0 version 2, +1 size 0x20, +0xa debug name length, +0xb
  name. The block is write-only for the monitor; the name is loaded only
  from xbdm.ini. `DmSetXboxName` (0x91f513c8) writes xbdm.ini before the
  block, the `dbgname` handler after it.
- Kernel debug monitor service 8 (kernel 0x800a8bc8): +0x08 physical page
  count, +0x70 debug memory global, +0x7c constant 0x20000.
- Kernel `_snprintf` (ordinal 314, formatter 0x8014de48): `%p` = precision
  8, upper-case hex.
- 0x91f4d2d8 calls kernel export 700 only; 0x91f4d350 adds the get/modify/set
  fallback and maps the status with fallback 0x8000ffff.
- WriteIniFile body 0x91f31a90 order and the console emitters: see
  `commands/framework.md` and the system domain.

## Client fixes

- `ConsoleType` has only `DevKit` and `TestKit`; other replies are a parse
  error.
- `ConsoleMem` is an enum of the three stock values.
- `GetNetAddrs` parses names containing spaces and documents 36-byte records.
- `AltAddr` documents the title address.
