# XBDM reverse-engineering notes

## Protocol

The monitor listens on TCP port 730. Requests are CRLF-terminated command lines. Responses use a three-digit status and optional body:

| Code | Observed role |
| --- | --- |
| 200 | Single-line success |
| 201 | Connection banner |
| 202 | Text lines followed by a line containing only `.` |
| 203 | Binary body follows |
| 204 | Monitor is ready to receive a binary body |
| 205 | Polite disconnect |
| 206 | Connection dedicated to a named handler |
| 400-499 | Command error |

`getmem` is a 202 text response, not a binary response. Each data line contains hexadecimal byte pairs. An unreadable byte is represented by `??`.

The analyzed command table uses 20-byte entries:

```text
u32 name_pointer
u32 access_flags
u32 handler_pointer
u32 zero
u32 extra_flags
```

Handlers may point into a shared function after its normal entry point. A handler address must not be treated as proof of an independent function boundary.

## Backend boundaries

The reimplementation separates protocol behavior from platform access:

- `ConsoleBackend`: debug name, monitor version, kit type, feature flags.
- `FileSystemBackend`: mounted drive enumeration and file deletion.
- `MemoryBackend`: bounded virtual-memory reads and writes.
- `ProcessBackend`: title process and later module, thread, context, and stop state access.
- `ResponseSink`: line, multiline, and later binary transport framing.

`openxbdm-core` owns parsing, status selection, hexadecimal encoding, and command sequencing. A backend never writes protocol bytes. This permits the same dispatcher to use deterministic host mocks or Xbox kernel-backed implementations.

## Command inventory

The analyzed XBDM image contains 174 structurally valid command entries. Access-flag meanings are not yet fully reconstructed. Values observed in the table are `0`, `1`, `2`, `3`, `4`, `8`, and `0x10`.

### Console and configuration

`adminpw`, `altaddr`, `authuser`, `autoshutoff`, `boxid`, `confignetra`, `consolefeatures`, `consolemem`, `consoletype`, `datacentermode`, `dbgname`, `debugmemsize`, `debugmode`, `deftitle`, `discoverable`, `dmversion`, `dumpmode`, `dumpsettings`, `eventdefer`, `feature`, `getconsoleid`, `getnetaddrs`, `getuserpriv`, `httpreg`, `kiosk`, `livesigninrequired`, `lockmode`, `notifyat`, `notifyport`, `recovery`, `resetnetra`, `setconfig`, `setdiscboot`, `setreset`, `setretail`, `setserver`, `setsystime`, `setuserpriv`, `systeminfo`, `systime`, `title`, `user`, `userlist`, `verbose`, `welcomedefault`, `welcomehide`.

### Session and notification

`bye`, `dbgprint`, `dedicate`, `dmtelllog`, `fastpipe`, `fileevent`, `keyxchg`, `notify`, `rpc`, `spew`, `srvproc`.

### Filesystem and storage

`delete`, `dirlist`, `drivefreespace`, `drivelist`, `dvdblk`, `dvdeject`, `dvdperf`, `fmtfat`, `getfile`, `getfileattributes`, `gethddblk`, `getsum`, `getvfattr`, `hdd`, `mkdir`, `prevflash`, `sendfile`, `sendvfile`, `setfileattributes`, `sethddblk`, `sysfileupd`, `writefile`.


### Memory, process, and debugger

`addtitlemem`, `advmem`, `break`, `continue`, `crashdump`, `dbgextld`, `debugger`, `detour`, `getcontext`, `getmem`, `getmemex`, `getpid`, `go`, `halt`, `isbreak`, `isdebugger`, `isstopped`, `kd`, `kdlite`, `kdnet`, `memtrack`, `modsections`, `modules`, `nostopon`, `pdbinfo`, `reboot`, `resume`, `setcontext`, `setmem`, `stop`, `stopon`, `suspend`, `threadinfo`, `threads`, `threadstat`, `traceimports`, `walkmem`, `xbeinfo`, `xexfield`.

### Network inspection and simulation

`getxnkeyinfo`, `getxnqoslookupinfo`, `getxnsecassocinfo`, `ipproxy`, `linkstate`, `netcap`, `netsim`, `nicstats`, `getsockinfo`, `xhttpproxy`.

### Performance, capture, and graphics

`autoprof`, `capctrl`, `gpucount`, `lopctrl`, `pclist`, `perfstat`, `pixcmd`, `pixpreview`, `querypc`, `screenshot`, `vd`, `xstudio`.

### Hardware and manufacturing controls

`autoinput`, `avatar`, `bkgdmodetest`, `bootanim`, `builtinmu`, `enablewirelesscontrollers`, `irtsweep`, `kinecthsmsg`, `mdetect`, `mixcmd`, `mockcurrencyvalue`, `oddlog`, `playto`, `pogoctrl`, `runnuioobe`, `runoobe`, `runoobecheckpoint`, `tdecomp`, `usbportctrl`.

### IPTV controls

`iptv`, `iptvallowuninstall`, `iptvbootstrapurl`, `iptvdvr`, `iptvprovidername`, `iptvprovisioningurl`, `iptvsupportinfo`.

### CIV controls

`civfail`, `civinject`, `civsetbits`, `civstart`, `civstatus`, `civstop`, `civverify`.

### Boot-related commands


`reboot` controls firmware return and title restart behavior.


## Override recovery subset

The Xbox target accepts `delete` only for `DEVKIT:\FlashEx\xbdm.xex`. Its worker thread attempts the same deletion before opening the TCP listener. This makes the override one-shot after the replacement module starts while denying arbitrary file deletion. File transfer remains unimplemented.

## Implemented mock surface

The host server implements a deliberately coherent subset rather than response scripts:

- Console state persists for one connection, including `dbgname` changes.
- Memory is a bounded range beginning at `0x80000000`; `setmem` changes subsequent `getmem` output.
- Unmapped reads produce `??` byte pairs.
- Drive and feature lists use the same response shapes consumed by openxbdm-client.
- Every new connection starts from deterministic state.

Captured byte scripts remain useful for exact client regressions. Backend mocks cover state transitions and server behavior that a playback transport cannot model.
