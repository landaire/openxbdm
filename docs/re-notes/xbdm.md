# XBDM protocol and feature map

Stock XBDM 2.0.21256.0 (`xbdm.xex`, base `0x91f00000`).

## Protocol

The monitor listens on TCP port 730 and answers name discovery on UDP port
730. Requests are CRLF-terminated command lines. Responses use a
three-digit status and optional body:

| Code | Role |
| --- | --- |
| 200 | Single-line success |
| 201 | Connection banner |
| 202 | Text lines followed by a line containing only `.` |
| 203 | Binary body follows |
| 204 | Monitor is ready to receive a binary body |
| 205 | Connection dedicated to a handler |
| 400-499 | Command error |

`getmem` is a 202 text response, not a binary response. Each data line
contains hexadecimal byte pairs; an unreadable byte is `??`. Dispatch, reply
formatting, continuations, and command processors: `commands/framework.md`.

## Command table

The table at `0x91f980a0` holds 177 entries of 20 bytes:

```text
+0x00 u32 name pointer
+0x04 u32 any_of access mask
+0x08 u32 handler
+0x0c u32 all_of access mask
+0x10 u32 dispatch flags
```

Access bits: 0x1 read, 0x2 write, 0x4 control, 0x8 config, 0x10 manage.
Dispatch flags: 0x1 allowed on dedicated and title threads, 0x2
development-kit only, 0x4 runs on a new thread. Lookup is a
case-insensitive binary search by name.

Handlers may point into a shared function after its normal entry point. A
handler address is not proof of an independent function boundary.

## Implementation boundaries

- `openxbdm-core`: request line grammar, status codes, value encodings,
  and the authentication response function shared by client and server.
- `openxbdm-server`: the command engine. Each domain module under
  `src/commands/` owns its registry table (`COMMANDS`, joined by
  `commands::TABLES`), handlers, continuations, and a domain `Backend`
  trait. `openxbdm_server::Backend` is the union of the domain traits with
  `Platform` and `ProcessorBackend`; `Network` supplies sockets. A backend
  never writes protocol bytes.
- `openxbdm-server-host`: `MockBackend` simulates one console for every
  connection.
- `openxbdm-server-xbox360`: console backends, the control dispatcher, and
  the export table.

## Feature map

Specifications for every command are in `commands/group1.md` through
`commands/group8.md`, in alphabetical order of the command name. Coverage,
gaps, and deviations: `parity.md`.

| Domain | Commands | Server | Parity |
| --- | --- | --- | --- |
| Session, notification, and command processors | `bye`, `dbgprint`, `dedicate`, `dmtelllog`, `fastpipe`, `fileevent`, `notify`, `notifyat`, `notifyport`, `rpc`, `spew`, `srvproc` | `commands/session.rs` | [parity/session.md](parity/session.md) |
| Lock mode, users, and authentication | `adminpw`, `authuser`, `boxid`, `getuserpriv`, `keyxchg`, `lockmode`, `setuserpriv`, `user`, `userlist` | `commands/security.rs` | [parity/security.md](parity/security.md) |
| Console identity and configuration | `altaddr`, `autoshutoff`, `confignetra`, `consolefeatures`, `consolemem`, `consoletype`, `datacentermode`, `dbgname`, `debugmemsize`, `debugmode`, `discoverable`, `dmversion`, `dumpmode`, `dumpsettings`, `eventdefer`, `feature`, `getconsoleid`, `getnetaddrs`, `httpreg`, `kiosk`, `livesigninrequired`, `resetnetra`, `setconfig`, `setretail`, `setserver`, `systeminfo`, `verbose`, `welcomedefault`, `welcomehide` | `commands/console.rs` | [parity/console.md](parity/console.md) |
| Reboot, title launch, time, and flash | `deftitle`, `flash`, `magicboot`, `reboot`, `recovery`, `setdiscboot`, `setreset`, `setsystime`, `systime`, `title` | `commands/system.rs` | [parity/system.md](parity/system.md) |
| File system and storage | `delete`, `dirlist`, `drivefreespace`, `drivelist`, `dvdblk`, `dvdeject`, `dvdperf`, `fileeof`, `fmtfat`, `getfile`, `getfileattributes`, `gethddblk`, `getsum`, `getvfattr`, `hdd`, `mkdir`, `prevflash`, `rename`, `sendfile`, `sendvfile`, `setfileattributes`, `sethddblk`, `sysfileupd`, `writefile` | `commands/filesystem.rs` | [parity/filesystem.md](parity/filesystem.md) |
| Memory, modules, and images | `addtitlemem`, `advmem`, `detour`, `getmem`, `getmemex`, `memtrack`, `modsections`, `modules`, `pdbinfo`, `setmem`, `traceimports`, `walkmem`, `xbeinfo`, `xexfield` | `commands/memory.rs` | [parity/memory.md](parity/memory.md) |
| Debugger and threads | `break`, `continue`, `crashdump`, `dbgextld`, `debugger`, `getcontext`, `getpid`, `go`, `halt`, `isbreak`, `isdebugger`, `isstopped`, `kd`, `kdlite`, `kdnet`, `nostopon`, `resume`, `setcontext`, `stop`, `stopon`, `suspend`, `threadinfo`, `threads`, `threadstat` | `commands/debugger.rs` | [parity/debugger.md](parity/debugger.md) |
| Network inspection and simulation | `getsockinfo`, `getxnkeyinfo`, `getxnqoslookupinfo`, `getxnsecassocinfo`, `ipproxy`, `linkstate`, `netcap`, `netsim`, `nicstats`, `xhttpproxy` | `commands/network.rs` | [parity/network.md](parity/network.md) |
| Performance counters, capture, PIX, and graphics | `autoprof`, `capctrl`, `gpucount`, `lopctrl`, `pclist`, `perfstat`, `pixcmd`, `pixpreview`, `querypc`, `screenshot`, `vd`, `xstudio` | `commands/performance.rs` | [parity/performance.md](parity/performance.md) |
| Hardware, input automation, and PGO | `autoinput`, `avatar`, `bkgdmodetest`, `bootanim`, `builtinmu`, `enablewirelesscontrollers`, `irtsweep`, `kinecthsmsg`, `mdetect`, `mixcmd`, `mockcurrencyvalue`, `oddlog`, `playto`, `pogoctrl`, `runnuioobe`, `runoobe`, `runoobecheckpoint`, `tdecomp`, `usbportctrl` | `commands/hardware.rs` | [parity/hardware.md](parity/hardware.md) |
| IPTV and CIV | `civfail`, `civinject`, `civsetbits`, `civstart`, `civstatus`, `civstop`, `civverify`, `iptv`, `iptvallowuninstall`, `iptvbootstrapurl`, `iptvdvr`, `iptvprovidername`, `iptvprovisioningurl`, `iptvsupportinfo` | `commands/services.rs` | [parity/services.md](parity/services.md) |

Other records:

- `exports.md`: the export table and the behavior of each ordinal.
- `dispatcher.md`: the debug monitor control dispatcher (`KeDebugMonitorData` `+0x18`).
- `pgo.md`: the PGO instrumentation runtime.
- `module-loading.md`: kernel module search and boot-time replacement.
- `nuances.md`: single behaviors that require exact compatibility.
