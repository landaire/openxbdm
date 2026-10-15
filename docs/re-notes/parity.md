# Parity summary

Reference: stock XBDM 2.0.21256.0 (`xbdm.xex`, base `0x91f00000`). This
table aggregates the domain records under `parity/` and the specifications
under `commands/`. Counts are taken from the code: the registry tables
(`COMMANDS` in `crates/openxbdm-server/src/commands/<domain>.rs`, joined by
`commands::TABLES`), the `export!`/`export_raw!` declarations in
`crates/openxbdm-server-xbox360/src/`, and the control dispatcher in
`crates/openxbdm-server-xbox360/src/backend/dispatcher.rs`.

Columns:

- Spec: status line of the command's section in `commands/group*.md`.
  `complete`: wire behavior and effects reconstructed. `wire complete`:
  wire behavior reconstructed; a callee outside xbdm is unknown.
  `partial`: an open question is listed under Remaining gaps.
- Server: registered in the `openxbdm-server` table with the stock access
  mask and dispatch flags.
- Host test: file under `crates/openxbdm-server-host/tests/` that sends
  the command over TCP to the simulated console.
- Xbox backend: the console backend in `openxbdm-server-xbox360`
  implements every service the command uses.
- Hardware verified: `yes`: every line of the command in
  `parity/hardware-commands.txt` produced the stock reply on a devkit,
  equal or equal outside the fields of `parity/hardware-variances.txt`.
  `excluded`: not run on hardware (persistent state, flash or disk
  writes, reboot, or a console fault); see
  [parity/hardware.md](parity/hardware.md#hardware-differential-results).

## Totals

| Domain | Commands | Spec complete | Exports | Parity record |
| --- | --- | --- | --- | --- |
| session | 12 | 12 | 29 | [parity/session.md](parity/session.md) |
| security | 9 | 9 | 7 | [parity/security.md](parity/security.md) |
| console | 29 | 28 | 18 | [parity/console.md](parity/console.md) |
| system | 10 | 9 | 4 | [parity/system.md](parity/system.md) |
| filesystem | 24 | 23 | 4 | [parity/filesystem.md](parity/filesystem.md) |
| memory | 14 | 12 | 17 | [parity/memory.md](parity/memory.md) |
| debugger | 24 | 22 | 25 | [parity/debugger.md](parity/debugger.md) |
| network | 10 | 10 | 13 | [parity/network.md](parity/network.md) |
| performance | 12 | 11 | 41 | [parity/performance.md](parity/performance.md) |
| hardware | 19 | 19 | 34 | [parity/hardware.md](parity/hardware.md) |
| services | 14 | 10 | 0 | [parity/services.md](parity/services.md) |
| generic | 0 | - | 61 | [exports.md](exports.md) |
| Total | 177 | 165 | 253 | |

All 177 stock command table entries are registered, and each has a host
test. All 253 populated export ordinals of the stock table are declared
(231 `export!`, 22 `export_raw!`); the 120 unused ordinals are the same as
stock (`exports.md`). Domain assignment of exports follows `exports.md`;
ordinal 146 is declared in `backend/performance/capture.rs` and counted
under debugger there.

## Hardware results

`xeedee parity record` sent the 399 lines of
`parity/hardware-commands.txt` to stock XBDM 2.0.21256.0 and to openxbdm
on the same devkit; `xeedee parity compare` with
`parity/hardware-variances.txt` reports:

| Exchanges | Equal | Equal outside varying fields | Differ |
| --- | --- | --- | --- |
| 399 | 378 | 21 | 0 |

The lines cover 134 of the 177 commands; the other 43 are excluded. On
the same console xshell loads against the openxbdm exports. Method,
exclusions, and varying fields:
[parity/hardware.md](parity/hardware.md#hardware-differential-results).

## Control dispatcher codes

Codes 0x01 to 0xa9 of `dm_control_dispatch` (`dispatcher.md`). Stock
routes 103 codes to a handler other than the default exit or the empty
routine (0x60 to 0x62); the rest reach only the extension hook, as in
openxbdm.

| Area | Stock handlers | Implemented | Codes |
| --- | --- | --- | --- |
| Debugger | 7 | 7 | 0x01 0x19 0x34 0x35 0x63 0xa4 0xa8 |
| System | 7 | 7 | 0x02 0x17 0x1d 0x20 0x21 0x22 0x77 |
| File system | 4 | 4 | 0x03 0x64 0x65 0x7e |
| Memory | 4 | 4 | 0x08 0x09 0x18 0x86 |
| Session | 6 | 6 | 0x0a 0x32 0x88 0x89 0x8a 0xa9 |
| Network | 15 | 15 | 0x0b..0x16 0xa5 0xa6 0xa7 |
| Hardware | 13 | 12 | 0x1a (missing) 0x46..0x4a 0x7a 0x7b 0x7c 0x96 0x97 0x98 0xa1 |
| Performance and PIX | 44 | 44 | 0x1b 0x1c 0x27 0x2e 0x2f 0x30 0x38..0x3c 0x3f 0x41..0x45 0x50..0x5e 0x7f 0x80..0x85 0x87 0x8d 0x8e 0x99 0x9f |
| Console | 3 | 3 | 0x1e 0x1f 0x33 |
| Total | 103 | 102 | |

## Commands

| Command | Domain | Spec | Server | Host test | Xbox backend | Hardware verified |
| --- | --- | --- | --- | --- | --- | --- |
| addtitlemem | [memory](parity/memory.md) | [complete](commands/group1.md#addtitlemem) | yes | `memory.rs` | yes | yes |
| adminpw | [security](parity/security.md) | [complete](commands/group1.md#adminpw) | yes | `security.rs` | yes | yes |
| advmem | [memory](parity/memory.md) | [partial](commands/group1.md#advmem) | yes | `memory.rs` | yes | yes |
| altaddr | [console](parity/console.md) | [complete](commands/group1.md#altaddr) | yes | `console.rs` | yes | yes |
| authuser | [security](parity/security.md) | [complete](commands/group1.md#authuser) | yes | `security.rs` | yes | yes |
| autoinput | [hardware](parity/hardware.md) | [complete](commands/group1.md#autoinput) | yes | `hardware.rs` | yes | yes |
| autoprof | [performance](parity/performance.md) | [partial](commands/group1.md#autoprof) | yes | `performance.rs` | yes | yes |
| autoshutoff | [console](parity/console.md) | [complete](commands/group1.md#autoshutoff) | yes | `console.rs` | yes | yes |
| avatar | [hardware](parity/hardware.md) | [complete](commands/group1.md#avatar) | yes | `hardware.rs` | yes | yes |
| bkgdmodetest | [hardware](parity/hardware.md) | [complete](commands/group1.md#bkgdmodetest) | yes | `hardware.rs` | yes | yes |
| bootanim | [hardware](parity/hardware.md) | [complete](commands/group1.md#bootanim) | yes | `hardware.rs` | yes | excluded |
| boxid | [security](parity/security.md) | [complete](commands/group1.md#boxid) | yes | `security.rs` | yes | yes |
| break | [debugger](parity/debugger.md) | [complete](commands/group1.md#break) | yes | `debugger.rs`, `memory.rs` | yes | yes |
| builtinmu | [hardware](parity/hardware.md) | [complete](commands/group1.md#builtinmu) | yes | `hardware.rs` | yes | yes |
| bye | [session](parity/session.md) | [complete](commands/group1.md#bye) | yes | `framework.rs`, `security.rs` | yes | yes |
| capctrl | [performance](parity/performance.md) | [complete](commands/group1.md#capctrl) | yes | `performance.rs` | yes | yes |
| civfail | [services](parity/services.md) | [wire complete](commands/group1.md#civfail) | yes | `services.rs` | yes | excluded |
| civinject | [services](parity/services.md) | [wire complete](commands/group1.md#civinject) | yes | `services.rs` | yes | excluded |
| civsetbits | [services](parity/services.md) | [complete](commands/group1.md#civsetbits) | yes | `services.rs` | yes | excluded |
| civstart | [services](parity/services.md) | [wire complete](commands/group1.md#civstart) | yes | `services.rs` | yes | excluded |
| civstatus | [services](parity/services.md) | [complete](commands/group1.md#civstatus) | yes | `services.rs` | yes | yes |
| civstop | [services](parity/services.md) | [complete](commands/group1.md#civstop) | yes | `services.rs` | yes | excluded |
| civverify | [services](parity/services.md) | [wire complete](commands/group1.md#civverify) | yes | `services.rs` | yes | excluded |
| confignetra | [console](parity/console.md) | [complete](commands/group2.md#confignetra) | yes | `console.rs` | yes | yes |
| consolefeatures | [console](parity/console.md) | [complete](commands/group2.md#consolefeatures) | yes | `console.rs` | yes | yes |
| consolemem | [console](parity/console.md) | [complete](commands/group2.md#consolemem) | yes | `console.rs` | yes | yes |
| consoletype | [console](parity/console.md) | [complete](commands/group2.md#consoletype) | yes | `console.rs` | yes | yes |
| continue | [debugger](parity/debugger.md) | [complete](commands/group2.md#continue) | yes | `debugger.rs` | yes | yes |
| crashdump | [debugger](parity/debugger.md) | [partial](commands/group2.md#crashdump) | yes | `debugger.rs` | yes | excluded |
| datacentermode | [console](parity/console.md) | [complete](commands/group2.md#datacentermode) | yes | `console.rs` | yes | excluded |
| dbgextld | [debugger](parity/debugger.md) | [complete](commands/group2.md#dbgextld) | yes | `debugger.rs` | yes | yes |
| dbgname | [console](parity/console.md) | [complete](commands/group2.md#dbgname) | yes | `console.rs`, `session.rs`, `system.rs`, `trace.rs` | yes | yes |
| dbgprint | [session](parity/session.md) | [complete](commands/group2.md#dbgprint) | yes | `session.rs` | yes | yes |
| debugger | [debugger](parity/debugger.md) | [complete](commands/group2.md#debugger) | yes | `debugger.rs`, `performance.rs` | yes | yes |
| debugmemsize | [console](parity/console.md) | [complete](commands/group2.md#debugmemsize) | yes | `console.rs` | yes | yes |
| debugmode | [console](parity/console.md) | [complete](commands/group2.md#debugmode) | yes | `console.rs` | yes | yes |
| dedicate | [session](parity/session.md) | [complete](commands/group2.md#dedicate) | yes | `session.rs` | yes | yes |
| deftitle | [system](parity/system.md) | [complete](commands/group2.md#deftitle) | yes | `system.rs` | yes | excluded |
| delete | [filesystem](parity/filesystem.md) | [complete](commands/group2.md#delete) | yes | `filesystem.rs` | yes | yes |
| detour | [memory](parity/memory.md) | [complete](commands/group2.md#detour) | yes | `memory.rs` | yes | yes |
| dirlist | [filesystem](parity/filesystem.md) | [complete](commands/group2.md#dirlist) | yes | `filesystem.rs` | yes | yes |
| discoverable | [console](parity/console.md) | [complete](commands/group2.md#discoverable) | yes | `console.rs` | yes | yes |
| dmtelllog | [session](parity/session.md) | [complete](commands/group2.md#dmtelllog) | yes | `session.rs` | yes | yes |
| dmversion | [console](parity/console.md) | [complete](commands/group2.md#dmversion) | yes | `console.rs`, `framework.rs`, `performance.rs`, `security.rs`, `trace.rs` | yes | yes |
| drivefreespace | [filesystem](parity/filesystem.md) | [complete](commands/group2.md#drivefreespace) | yes | `filesystem.rs` | yes | yes |
| drivelist | [filesystem](parity/filesystem.md) | [complete](commands/group2.md#drivelist) | yes | `filesystem.rs` | yes | yes |
| dumpmode | [console](parity/console.md) | [complete](commands/group3.md#dumpmode) | yes | `console.rs`, `system.rs` | yes | yes |
| dumpsettings | [console](parity/console.md) | [complete](commands/group3.md#dumpsettings) | yes | `console.rs`, `system.rs` | yes | yes |
| dvdblk | [filesystem](parity/filesystem.md) | [complete](commands/group3.md#dvdblk) | yes | `filesystem.rs` | yes | yes |
| dvdeject | [filesystem](parity/filesystem.md) | [complete](commands/group3.md#dvdeject) | yes | `filesystem.rs` | yes | excluded |
| dvdperf | [filesystem](parity/filesystem.md) | [partial](commands/group3.md#dvdperf) | yes | `filesystem.rs` | yes | yes |
| enablewirelesscontrollers | [hardware](parity/hardware.md) | [complete](commands/group3.md#enablewirelesscontrollers) | yes | `hardware.rs` | yes | yes |
| eventdefer | [console](parity/console.md) | [complete](commands/group3.md#eventdefer) | yes | `console.rs`, `debugger.rs`, `trace.rs` | yes | yes |
| fastpipe | [session](parity/session.md) | [complete](commands/group3.md#fastpipe) | yes | `session.rs` | yes | excluded |
| feature | [console](parity/console.md) | [partial](commands/group3.md#feature) | yes | `console.rs` | yes | yes |
| fileeof | [filesystem](parity/filesystem.md) | [complete](commands/group3.md#fileeof) | yes | `filesystem.rs` | yes | yes |
| fileevent | [session](parity/session.md) | [complete](commands/group3.md#fileevent) | yes | `session.rs` | yes | yes |
| flash | [system](parity/system.md) | [partial](commands/group3.md#flash) | yes | `system.rs` | yes | excluded |
| fmtfat | [filesystem](parity/filesystem.md) | [complete](commands/group3.md#fmtfat) | yes | `filesystem.rs` | yes | excluded |
| getconsoleid | [console](parity/console.md) | [complete](commands/group3.md#getconsoleid) | yes | `console.rs` | yes | yes |
| getcontext | [debugger](parity/debugger.md) | [complete](commands/group3.md#getcontext) | yes | `debugger.rs` | yes | yes |
| getfile | [filesystem](parity/filesystem.md) | [complete](commands/group3.md#getfile) | yes | `filesystem.rs`, `network/netcap.rs` | yes | yes |
| getfileattributes | [filesystem](parity/filesystem.md) | [complete](commands/group3.md#getfileattributes) | yes | `filesystem.rs` | yes | yes |
| gethddblk | [filesystem](parity/filesystem.md) | [complete](commands/group3.md#gethddblk) | yes | `filesystem.rs` | yes | yes |
| getmem | [memory](parity/memory.md) | [complete](commands/group3.md#getmem) | yes | `debugger.rs`, `framework.rs`, `memory.rs` | yes | yes |
| getmemex | [memory](parity/memory.md) | [complete](commands/group3.md#getmemex) | yes | `memory.rs` | yes | yes |
| getnetaddrs | [console](parity/console.md) | [complete](commands/group3.md#getnetaddrs) | yes | `console.rs` | yes | yes |
| getpid | [debugger](parity/debugger.md) | [complete](commands/group3.md#getpid) | yes | `debugger.rs` | yes | yes |
| getsockinfo | [network](parity/network.md) | [complete](commands/group3.md#getsockinfo) | yes | `network.rs` | yes | yes |
| getsum | [filesystem](parity/filesystem.md) | [complete](commands/group4.md#getsum) | yes | `filesystem.rs` | yes | yes |
| getuserpriv | [security](parity/security.md) | [complete](commands/group4.md#getuserpriv) | yes | `security.rs` | yes | yes |
| getvfattr | [filesystem](parity/filesystem.md) | [complete](commands/group4.md#getvfattr) | yes | `filesystem.rs` | yes | yes |
| getxnkeyinfo | [network](parity/network.md) | [complete](commands/group4.md#getxnkeyinfo) | yes | `network.rs` | yes | yes |
| getxnqoslookupinfo | [network](parity/network.md) | [complete](commands/group4.md#getxnqoslookupinfo) | yes | `network.rs` | yes | yes |
| getxnsecassocinfo | [network](parity/network.md) | [complete](commands/group4.md#getxnsecassocinfo) | yes | `network.rs` | yes | yes |
| go | [debugger](parity/debugger.md) | [complete](commands/group4.md#go) | yes | `debugger.rs` | yes | yes |
| gpucount | [performance](parity/performance.md) | [complete](commands/group4.md#gpucount) | yes | `performance.rs` | yes | yes |
| halt | [debugger](parity/debugger.md) | [complete](commands/group4.md#halt) | yes | `debugger.rs` | yes | yes |
| hdd | [filesystem](parity/filesystem.md) | [complete](commands/group4.md#hdd) | yes | `filesystem.rs` | yes | yes |
| httpreg | [console](parity/console.md) | [complete](commands/group4.md#httpreg) | yes | `console.rs` | yes | excluded |
| ipproxy | [network](parity/network.md) | [complete](commands/group4.md#ipproxy) | yes | `network/ipproxy.rs` | yes | yes |
| iptv | [services](parity/services.md) | [complete](commands/group4.md#iptv) | yes | `services.rs` | yes | yes |
| iptvallowuninstall | [services](parity/services.md) | [complete](commands/group4.md#iptvallowuninstall) | yes | `services.rs` | yes | yes |
| iptvbootstrapurl | [services](parity/services.md) | [complete](commands/group4.md#iptvbootstrapurl) | yes | `services.rs` | yes | excluded |
| iptvdvr | [services](parity/services.md) | [complete](commands/group4.md#iptvdvr) | yes | `services.rs` | yes | yes |
| iptvprovidername | [services](parity/services.md) | [complete](commands/group4.md#iptvprovidername) | yes | `services.rs` | yes | excluded |
| iptvprovisioningurl | [services](parity/services.md) | [complete](commands/group4.md#iptvprovisioningurl) | yes | `services.rs` | yes | excluded |
| iptvsupportinfo | [services](parity/services.md) | [complete](commands/group4.md#iptvsupportinfo) | yes | `services.rs` | yes | excluded |
| irtsweep | [hardware](parity/hardware.md) | [complete](commands/group4.md#irtsweep) | yes | `hardware.rs` | yes | yes |
| isbreak | [debugger](parity/debugger.md) | [complete](commands/group4.md#isbreak) | yes | `debugger.rs` | yes | yes |
| isdebugger | [debugger](parity/debugger.md) | [complete](commands/group4.md#isdebugger) | yes | `debugger.rs` | yes | yes |
| isstopped | [debugger](parity/debugger.md) | [complete](commands/group4.md#isstopped) | yes | `debugger.rs` | yes | yes |
| kd | [debugger](parity/debugger.md) | [complete](commands/group5.md#kd) | yes | `debugger.rs` | yes | yes |
| kdlite | [debugger](parity/debugger.md) | [complete](commands/group5.md#kdlite) | yes | `debugger.rs` | yes | yes |
| kdnet | [debugger](parity/debugger.md) | [complete](commands/group5.md#kdnet) | yes | `debugger.rs` | yes | excluded |
| keyxchg | [security](parity/security.md) | [complete](commands/group5.md#keyxchg) | yes | `security.rs` | yes | yes |
| kinecthsmsg | [hardware](parity/hardware.md) | [complete](commands/group5.md#kinecthsmsg) | yes | `hardware.rs` | yes | excluded |
| kiosk | [console](parity/console.md) | [complete](commands/group5.md#kiosk) | yes | `console.rs` | yes | yes |
| linkstate | [network](parity/network.md) | [complete](commands/group5.md#linkstate) | yes | `network.rs` | yes | yes |
| livesigninrequired | [console](parity/console.md) | [complete](commands/group5.md#livesigninrequired) | yes | `console.rs` | yes | excluded |
| lockmode | [security](parity/security.md) | [complete](commands/group5.md#lockmode) | yes | `security.rs` | yes | excluded |
| lopctrl | [performance](parity/performance.md) | [complete](commands/group5.md#lopctrl) | yes | `performance.rs` | yes | yes |
| magicboot | [system](parity/system.md) | [complete](commands/group5.md#magicboot) | yes | `system.rs` | yes | excluded |
| mdetect | [hardware](parity/hardware.md) | [complete](commands/group5.md#mdetect) | yes | `hardware.rs` | yes | excluded |
| memtrack | [memory](parity/memory.md) | [complete](commands/group5.md#memtrack) | yes | `memory.rs`, `system.rs` | yes | yes |
| mixcmd | [hardware](parity/hardware.md) | [complete](commands/group5.md#mixcmd) | yes | `hardware.rs` | yes | yes |
| mkdir | [filesystem](parity/filesystem.md) | [complete](commands/group5.md#mkdir) | yes | `filesystem.rs`, `trace.rs` | yes | yes |
| mockcurrencyvalue | [hardware](parity/hardware.md) | [complete](commands/group5.md#mockcurrencyvalue) | yes | `hardware.rs` | yes | yes |
| modsections | [memory](parity/memory.md) | [complete](commands/group5.md#modsections) | yes | `memory.rs` | yes | yes |
| modules | [memory](parity/memory.md) | [complete](commands/group5.md#modules) | yes | `memory.rs` | yes | yes |
| netcap | [network](parity/network.md) | [complete](commands/group5.md#netcap) | yes | `network.rs`, `network/netcap.rs` | yes | yes |
| netsim | [network](parity/network.md) | [complete](commands/group5.md#netsim) | yes | `network/netcap.rs`, `network/netsim.rs`, `trace.rs` | yes | yes |
| nicstats | [network](parity/network.md) | [complete](commands/group5.md#nicstats) | yes | `network.rs` | yes | yes |
| nostopon | [debugger](parity/debugger.md) | [complete](commands/group5.md#nostopon) | yes | `debugger.rs` | yes | yes |
| notify | [session](parity/session.md) | [complete](commands/group5.md#notify) | yes | `session.rs`, `trace.rs` | yes | yes |
| notifyat | [session](parity/session.md) | [complete](commands/group6.md#notifyat) | yes | `session.rs`, `system.rs` | yes | yes |
| notifyport | [session](parity/session.md) | [complete](commands/group6.md#notifyport) | yes | `session.rs` | yes | yes |
| oddlog | [hardware](parity/hardware.md) | [complete](commands/group6.md#oddlog) | yes | `hardware.rs` | yes | yes |
| pclist | [performance](parity/performance.md) | [complete](commands/group6.md#pclist) | yes | `performance.rs` | yes | yes |
| pdbinfo | [memory](parity/memory.md) | [complete](commands/group6.md#pdbinfo) | yes | `memory.rs` | yes | yes |
| perfstat | [performance](parity/performance.md) | [complete](commands/group6.md#perfstat) | yes | `performance.rs` | yes | yes |
| pixcmd | [performance](parity/performance.md) | [complete](commands/group6.md#pixcmd) | yes | `performance.rs` | yes | yes |
| pixpreview | [performance](parity/performance.md) | [complete](commands/group6.md#pixpreview) | yes | `performance.rs` | yes | yes |
| playto | [hardware](parity/hardware.md) | [complete](commands/group6.md#playto) | yes | `hardware.rs` | yes | yes |
| pogoctrl | [hardware](parity/hardware.md) | [complete](commands/group6.md#pogoctrl) | yes | `hardware.rs` | yes | yes |
| prevflash | [filesystem](parity/filesystem.md) | [complete](commands/group6.md#prevflash) | yes | `filesystem.rs` | yes | excluded |
| querypc | [performance](parity/performance.md) | [complete](commands/group6.md#querypc) | yes | `performance.rs` | yes | yes |
| reboot | [system](parity/system.md) | [complete](commands/group6.md#reboot) | yes | `system.rs` | yes | excluded |
| recovery | [system](parity/system.md) | [complete](commands/group6.md#recovery) | yes | `system.rs` | yes | excluded |
| rename | [filesystem](parity/filesystem.md) | [complete](commands/group6.md#rename) | yes | `filesystem.rs` | yes | yes |
| resetnetra | [console](parity/console.md) | [complete](commands/group6.md#resetnetra) | yes | `console.rs` | yes | excluded |
| resume | [debugger](parity/debugger.md) | [complete](commands/group6.md#resume) | yes | `debugger.rs` | yes | yes |
| rpc | [session](parity/session.md) | [complete](commands/group6.md#rpc) | yes | `session.rs` | yes | yes |
| runnuioobe | [hardware](parity/hardware.md) | [complete](commands/group6.md#runnuioobe) | yes | `hardware.rs` | yes | excluded |
| runoobe | [hardware](parity/hardware.md) | [complete](commands/group6.md#runoobe) | yes | `hardware.rs` | yes | excluded |
| runoobecheckpoint | [hardware](parity/hardware.md) | [complete](commands/group6.md#runoobecheckpoint) | yes | `hardware.rs` | yes | excluded |
| screenshot | [performance](parity/performance.md) | [complete](commands/group6.md#screenshot) | yes | `performance.rs` | yes | excluded |
| sendfile | [filesystem](parity/filesystem.md) | [complete](commands/group6.md#sendfile) | yes | `filesystem.rs`, `trace.rs` | yes | yes |
| sendvfile | [filesystem](parity/filesystem.md) | [complete](commands/group7.md#sendvfile) | yes | `filesystem.rs` | yes | yes |
| setconfig | [console](parity/console.md) | [complete](commands/group7.md#setconfig) | yes | `console.rs` | yes | excluded |
| setcontext | [debugger](parity/debugger.md) | [complete](commands/group7.md#setcontext) | yes | `debugger.rs` | yes | yes |
| setdiscboot | [system](parity/system.md) | [complete](commands/group7.md#setdiscboot) | yes | `system.rs` | yes | yes |
| setfileattributes | [filesystem](parity/filesystem.md) | [complete](commands/group7.md#setfileattributes) | yes | `filesystem.rs` | yes | yes |
| sethddblk | [filesystem](parity/filesystem.md) | [complete](commands/group7.md#sethddblk) | yes | `filesystem.rs` | yes | excluded |
| setmem | [memory](parity/memory.md) | [complete](commands/group7.md#setmem) | yes | `framework.rs`, `memory.rs` | yes | yes |
| setreset | [system](parity/system.md) | [complete](commands/group7.md#setreset) | yes | `system.rs` | yes | yes |
| setretail | [console](parity/console.md) | [complete](commands/group7.md#setretail) | yes | `console.rs` | yes | yes |
| setserver | [console](parity/console.md) | [complete](commands/group7.md#setserver) | yes | `console.rs` | yes | yes |
| setsystime | [system](parity/system.md) | [complete](commands/group7.md#setsystime) | yes | `system.rs` | yes | excluded |
| setuserpriv | [security](parity/security.md) | [complete](commands/group7.md#setuserpriv) | yes | `security.rs` | yes | yes |
| spew | [session](parity/session.md) | [complete](commands/group7.md#spew) | yes | `session.rs` | yes | yes |
| srvproc | [session](parity/session.md) | [complete](commands/group7.md#srvproc) | yes | `session.rs` | yes | yes |
| stop | [debugger](parity/debugger.md) | [complete](commands/group7.md#stop) | yes | `debugger.rs` | yes | excluded |
| stopon | [debugger](parity/debugger.md) | [complete](commands/group7.md#stopon) | yes | `debugger.rs`, `system.rs` | yes | yes |
| suspend | [debugger](parity/debugger.md) | [complete](commands/group7.md#suspend) | yes | `debugger.rs` | yes | yes |
| sysfileupd | [filesystem](parity/filesystem.md) | [complete](commands/group7.md#sysfileupd) | yes | `filesystem.rs` | yes | excluded |
| systeminfo | [console](parity/console.md) | [complete](commands/group7.md#systeminfo) | yes | `console.rs` | yes | yes |
| systime | [system](parity/system.md) | [complete](commands/group7.md#systime) | yes | `system.rs` | yes | yes |
| tdecomp | [hardware](parity/hardware.md) | [complete](commands/group7.md#tdecomp) | yes | `hardware.rs` | yes | yes |
| threadinfo | [debugger](parity/debugger.md) | [complete](commands/group7.md#threadinfo) | yes | `debugger.rs` | yes | yes |
| threads | [debugger](parity/debugger.md) | [complete](commands/group7.md#threads) | yes | `debugger.rs` | yes | yes |
| threadstat | [debugger](parity/debugger.md) | [partial](commands/group8.md#threadstat) | yes | `debugger.rs` | yes | yes |
| title | [system](parity/system.md) | [complete](commands/group8.md#title) | yes | `system.rs` | yes | excluded |
| traceimports | [memory](parity/memory.md) | [complete](commands/group8.md#traceimports) | yes | `memory.rs` | yes | yes |
| usbportctrl | [hardware](parity/hardware.md) | [complete](commands/group8.md#usbportctrl) | yes | `hardware.rs` | yes | yes |
| user | [security](parity/security.md) | [complete](commands/group8.md#user) | yes | `security.rs` | yes | excluded |
| userlist | [security](parity/security.md) | [complete](commands/group8.md#userlist) | yes | `security.rs` | yes | excluded |
| vd | [performance](parity/performance.md) | [complete](commands/group8.md#vd) | yes | `performance.rs` | yes | yes |
| verbose | [console](parity/console.md) | [complete](commands/group8.md#verbose) | yes | `console.rs`, `system.rs`, `trace.rs` | yes | yes |
| walkmem | [memory](parity/memory.md) | [complete](commands/group8.md#walkmem) | yes | `memory.rs` | yes | yes |
| welcomedefault | [console](parity/console.md) | [complete](commands/group8.md#welcomedefault) | yes | `console.rs` | yes | excluded |
| welcomehide | [console](parity/console.md) | [complete](commands/group8.md#welcomehide) | yes | `console.rs` | yes | excluded |
| writefile | [filesystem](parity/filesystem.md) | [complete](commands/group8.md#writefile) | yes | `filesystem.rs` | yes | yes |
| xbeinfo | [memory](parity/memory.md) | [partial](commands/group8.md#xbeinfo) | yes | `memory.rs` | yes | yes |
| xexfield | [memory](parity/memory.md) | [complete](commands/group8.md#xexfield) | yes | `memory.rs` | yes | yes |
| xhttpproxy | [network](parity/network.md) | [complete](commands/group8.md#xhttpproxy) | yes | `network.rs` | yes | yes |
| xstudio | [performance](parity/performance.md) | [complete](commands/group8.md#xstudio) | yes | `performance.rs` | yes | yes |

## Remaining gaps

Open specification questions:

- `advmem`: platform meaning of flash word 6 bit 0x100
  ([group1](commands/group1.md#advmem)).
- `autoprof`: meaning of hardware flag 0x10
  ([group1](commands/group1.md#autoprof)).
- `civfail`, `civinject`, `civstart`, `civverify`: XAM ordinals 0x9bb to
  0x9c0 (no xam.xex image); the host mock logs requests
  ([services](parity/services.md#remaining-differences)).
- `crashdump`: whether `DumpWriteDump` returns is decided in the kernel
  ([group2](commands/group2.md#crashdump)).
- `dvdperf`: unit of the `time` and timestamp ticks
  ([group3](commands/group3.md#dvdperf)).
- `feature`: XAM ordinal 515 semantics; XHttp request headers beyond
  `User-Agent` and `Host` ([console](parity/console.md#remaining-differences)).
- `flash`: image validation rules of 0x91f73260/0x91f732a8/0x91f734a0
  ([group3](commands/group3.md#flash)); `flash_commit` treats a missing
  image buffer as success ([system](parity/system.md#remaining-gaps)).
- `threadstat`: system or title handle table
  ([group8](commands/group8.md#threadstat)).
- `xbeinfo`: drive-prefix translation described only as far as used
  ([group8](commands/group8.md#xbeinfo)).

Implementation gaps:

- Control code 0x1a (`HalOpenCloseODDTray(1)`, result `0x02da0000`) has
  no case in the Xbox dispatcher; it returns 0 and does not open the tray.
- Session: no code emits the `dbgprint` producer texts of the CD-ROM and
  SATA patch routines; the reader's endless loop after a ring restart,
  stale `notifyat drop` matches, and the 3 s / 120 s debug string
  delivery timing are not reproduced; the host mock generates no
  0x64/0x65 file events ([session](parity/session.md#remaining-gaps)).
- Debugger: posted events wait for the next server pass (20 ms); stack
  overflow marking, direct exceptions above passive level, the 8-block
  breakpoint arena, and record flag 0x100
  ([debugger](parity/debugger.md#remaining-gaps-precise)).
- Hardware: PGO export 107 cannot read `pogo.ini` when called on the
  server thread, above passive level, or after the server stopped; the
  host has no optical drive events
  ([hardware](parity/hardware.md#gaps)).
- Performance: PIX and CPU profiler deviations
  ([performance](parity/performance.md#xbox-backend)); kernel exports
  669-671 semantics unverified.
- Security: directory rules come from the K15574 debug kernel, and DH
  inputs at or above the modulus were not traced in the kernel
  ([security](parity/security.md#unverified-on-hardware)).
- File system: no SO_SNDBUF change for `getfile`; `count=0` and overlong
  name cases of `getvfattr`/`sendvfile`
  ([filesystem](parity/filesystem.md#divergences-and-gaps)).

## Server-thread requests

Exports and control codes whose work changes server state call
`dispatcher::call_on_server`. Until the command loop starts they run
inline on the caller's thread under a startup lock, as stock runs them;
afterwards they are posted to the server thread and the caller waits for
its next pass (at most about 20 ms). They fail without running when
called on the server thread, above passive level, before the server
state exists, or after control code 0x02 stopped the server. The
domain records list the result each export returns in that case.

## Deliberate deviations

openxbdm differs from stock where stock faults, traps, overruns a buffer,
reads uninitialized memory, or leaks. Each case is listed in its domain
record:

- [console](parity/console.md#remaining-differences): `httpreg` ini
  trap, `systeminfo` stale 202 text, `setserver` stale bytes, control
  code 0x33 with size 0.
- [system](parity/system.md#deviations): `setreset` stale bytes, `title
  nopersist` assertion, `magicboot` from the settings file, control codes
  0x1d and 0x22.
- [filesystem](parity/filesystem.md#divergences-and-gaps): unchecked pool
  allocations, double free on `count=0`, unreadable title memory in
  control code 0x03.
- [memory](parity/memory.md#deviations): per-line loader walks,
  `traceimports` without export 719, `detour` table and pool cases,
  export 78 type names.
- [debugger](parity/debugger.md#remaining-gaps-precise): `isstopped` type
  0xd kind, breakpoint split slots.
- [network](parity/network.md#remaining-differences): snapshot leaks,
  `nicstats` stale stack, `xhttpproxy` null context, classifier compiler
  faults, `netsim` limit loops ([group5](commands/group5.md#netsim)).
- [performance](parity/performance.md#xbox-backend): PIX ring and capture
  engine traps, profiler stale registers.
- [hardware](parity/hardware.md#divergences-from-stock): `mixcmd`,
  `autoinput`, `pogoctrl`, `setpacket`, `playto`, optical disc log, PGO
  runtime faults.
- [security](parity/security.md#deliberate-difference): `ObInsertObject`
  double release, export 61 overlong names.
- [services](parity/services.md#remaining-differences): `civsetbits` and
  `civverify` uninitialized arguments, cleared connection buffers.
- [session](parity/session.md#remaining-gaps): `rpc` argument copies,
  `fastpipe` defects.

Further single-behavior entries are in `nuances.md`.
