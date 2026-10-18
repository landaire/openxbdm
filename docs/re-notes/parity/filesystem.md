# Parity: file system domain

Server: `crates/openxbdm-server/src/commands/filesystem.rs`. Host mock:
`crates/openxbdm-server-host/src/backend/filesystem.rs`. Xbox:
`crates/openxbdm-server-xbox360/src/backend/filesystem.rs`. Tests:
`crates/openxbdm-server-host/tests/filesystem.rs`. Specs: group2..group8.

## Commands

| Command | State | Host test |
| --- | --- | --- |
| delete | stock | root 414, `is a directory`, `not a directory`, 411, missing name |
| dirlist | stock | line format, attribute suffixes, file opened as directory |
| drivefreespace | stock | client round trip |
| drivelist | stock | `\??` phase then drive table, `F`/`SMB` disable on failure |
| dvdblk, gethddblk | stock (count prefix quirk) | sector data, invalid count, `203- missing count` |
| dvdeject | stock | tray values |
| dvdperf | stock; no kernel or xam code writes records, so a console trace reports no lines | report lines, empty report, `nothing to report` |
| fileeof | stock | mustcreate/cancreate/open |
| fmtfat | stock | 408 not stopped, 402, 414, `200- missing force` |
| getfile | stock | whole, ranges, size 0, offset past end |
| getfileattributes | stock | format, translation forms |
| getsum | stock (CRC-32/MPEG-2) | independent CRC, unreadable block 0 |
| getvfattr | stock | records, failure record |
| hdd, prevflash | stock | XConfig values |
| mkdir | stock | 410, 430, 412, 413 |
| rename | stock | 409, 414, 402 new name |
| sendfile, writefile | stock (0x4000 staging) | failure deletes, `16384 bytes written` |
| sendvfile | stock | per-file HRESULTs, times, attributes |
| setfileattributes | stock | flags and times |
| sethddblk | stock | write then read back, `204- missing count` then `400- ` |
| sysfileupd | stock | CRC mismatch, replace, query |

Path translation (0x91f2e888), `\Device\` passthrough, drive table
(0x91f96bf8 plus hidden `\x01` row and `drivemap internal` remap) are
`DriveTable` in `State`; translation ignores enable flags. Translation and
the reverse conversion (0x91f2e750) take `PathServices` (title memory
reads, symbolic link translation, trace mask, DbgPrint). The server
publishes a copy of the table after every change (`Published::Drives`), so
exports translate on the caller's thread as stock does (hardware.md, Drive
table off the server thread).

Trace mask bit 0x8 (FFileNameToObName, `DriveTable::translate`), every
translation, wire-verified in `tests/trace.rs`: `[xbdm]
FFileNameToObName(sz='%s',...)` on entry (site 0x91f2e8ac, the name as
given, before the `x` prefix is dropped); `[xbdm] FFileNameToObName - drive
name in conversion table` on a table match (0x91f2e9c0); `[xbdm]
FFileNameToObName succeeded, osz='%s'` with the object name (0x91f2eb18);
`[xbdm] FFileNameToObName - not a drive path - failing` without `:\`
(0x91f2eb3c). `translate` reads the mask the server publishes
(`PathServices::published_trace_mask`), on and off the server thread.

## Deviations

Stock defects openxbdm does not reproduce:

- getfile/sendfile/getvfattr/sendvfile: stock does not check some pool
  allocations (crash); here they fail with `400- out of memory`.
- getvfattr/sendvfile `count=0`: stock frees the block on the first piece
  (0x91f45efc, 0x91f44ee0) and returns end of data while bytes are still
  expected, so the pump ignores the result (0x91f426b0), receives the next
  piece into the freed block and frees it again. Here the block is freed
  once and the rest of the input is taken without a reply, as on the wire.
- getvfattr name length 0: stock ends the upload with `200- OK` and leaks
  the block (0x91f45f34); here the block is freed.
- sendvfile names longer than 0x4000 bytes: the stock receive window
  (0x4000 less the name bytes, 0x91f4527c) reaches 0, the pump receives
  nothing and the readable socket brings the server thread back at once,
  so the connection never progresses and the server thread spins. Here
  the bytes past 0x4000 are dropped and the name is cut there.
- Control code 0x03 (0x91f2ef60): unreadable title memory leaves the table
  unchanged or translates as an empty target (stock faults).
- DMSATA producer (0x91f3ebb0): `dbgprint stop` waits for producers still
  writing before it frees the ring; the stock producer reloads the ring
  address for its copy (0x91f3ecf0) and can write into the freed block.

## Behavior notes

- getfile send buffer (continuation 0x91f456f0): the header call reads
  SO_SNDBUF (0x91f457f4) and, when that succeeds, sets 0x10000
  (0x91f45824); the end and abort paths restore a nonzero saved size
  (0x91f45764). `Network::send_buffer_size`/`set_send_buffer_size`; host
  test `getfile_sets_the_send_buffer_for_the_transfer`.
- Control code 0x03: a title row keeps the title's string pointer
  (`DriveTarget::Mapped`) and its length at mapping time, as the image
  does; the server thread runs the mapping through
  `dispatcher::call_on_server`.
- sendvfile header_len 0x20 with a nonzero size: no name bytes are
  expected, so the pump ends the upload with `200- OK` (0x91f44fb4,
  0x91f426ac); the block stays allocated and the file data is read as
  command lines (host test
  `sendvfile_header_without_name_for_data_ends_the_upload`).

## CD-ROM driver patch (DMSATA)

`crates/openxbdm-server-xbox360/src/backend/dvd_hotplug.rs`, installed at
startup in the order of stock module initialization 0x91f32b10..0x91f32ba8
(SMC tray notification, `\Device\Cdrom0` reference, patch). Each routine
writes its texts straight into the `dbgprint` ring through the producer
(0x91f3ebb0; spec in commands/group2.md, dbgprint):

| Stock | openxbdm | Purpose |
| --- | --- | --- |
| 0x91f40088 | `patch` | Copy the CD-ROM driver object with the start I/O routine replaced, hook the channel interrupt routine under the channel lock, probe for a DVD emulator. |
| 0x91f3f518 | `find_channel` | Locate the CD-ROM channel extension: static address per kernel build 0x760, 0x8c1/0x8cf/0x8d2, 0x973/0x974, else ExDebugMonitorService CD-ROM channel service; validate the register address 0x7fea1200 and the device. |
| 0x91f3f498 | `initialize` | Hot-plug DPC on hardware thread 2, reinitialization and inquiry requests. |
| 0x91f3f3d0 | `interrupt_hook` | Channel interrupt: hot-plug events to the hot-plug DPC, others to the channel's interrupt routine. |
| 0x91f3f180 | `hotplug_dpc`, `queue_reinitialize` | Acknowledge a removal; after an insertion cancel the channel's wait, reset and current request, queue the reinitialization request (0x91f3f2d0..0x91f3f3bc), restart the channel timer. |
| 0x91f3ff10 | `start_io_hook` | Start I/O of the driver copy: fail requests during power-down or under hardware flag 0x4000; start the reinitialization (0x91f3ffc4) or pass requests to the channel. |
| 0x91f3fe50 | `schedule_reinitialize` | Arm the channel wait routine for 3 ticks of 100 ms. |
| 0x91f3fcd0 | `start_reinitialize` | Issue SET FEATURES transfer mode 0x42 to the drive; device busy report at 0x91f3fd34. |
| 0x91f3f470 | `reinit_interrupt` | Pass the device status to the channel DPC. |
| 0x91f3fba0 | `finish_reinitialize` | Clear the initializing flag on success, start the inquiry, let the server thread send SMC 0x8b 0x66 and close the tray (0x91f510c4). |
| 0x91f3fa40, 0x91f3f9c0, 0x91f3f918, 0x91f3f7a8 | `issue_inquiry`, `inquiry_completion`, `detect_dvd_emulator`, `report_inquiry` | SCSI INQUIRY of the drive; DVD emulator state and hypervisor DVD emulation mode. |
| 0x91f3f6f0 | `tray_notification` | Trace SMC tray state messages. |

The routines reload the SATA register address from word 0 of the channel
extension on every use, as stock does (0x91f3f190, 0x91f3fce4); the
interrupt hook uses the register address the kernel passes.

Transfer aborts follow stock (0x91f423f8/0x91f509f0): a failed 203 send
calls the continuation once with `aborted` before closing; a 204 receive
of 0 bytes calls it with no data; 202 line sends are unchecked, so the
continuation runs to its end. Connections closed by other paths (title
exit, reboot) do not call it, as in stock. `sysfileupd` and `sendvfile`
keep their handles/blocks on connection loss as stock does.

File change counter 0x91f9feec (export 85) counts closes of files that
delete, fileeof, mkdir, rename, setfileattributes, the sendfile/writefile
writer, and sendvfile performed.

## Client changes

`FileEof` takes `size: u32` and `EofDisposition` (`MUSTCREATE`/`CANCREATE`);
`GetFileRange::Range` and `FileUploadKind` use u32 and the ranged
`getfile` accepts the advertised (clamped) length. CLI `file fileeof`
has `--mustcreate`/`--cancreate`; FFI `fileeof` takes
`FileEofDisposition`.
