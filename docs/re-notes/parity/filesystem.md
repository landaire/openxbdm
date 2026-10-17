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
| dvdperf | stock; trace tick unit unknown (spec partial) | report lines, `nothing to report` |
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
`DriveTable` in `State`; translation ignores enable flags.

Trace mask bit 0x8 (FFileNameToObName, `DriveTable::translate`), every
translation, wire-verified in `tests/trace.rs`: `[xbdm]
FFileNameToObName(sz='%s',...)` on entry (site 0x91f2e8ac, the name as
given, before the `x` prefix is dropped); `[xbdm] FFileNameToObName - drive
name in conversion table` on a table match (0x91f2e9c0); `[xbdm]
FFileNameToObName succeeded, osz='%s'` with the object name (0x91f2eb18);
`[xbdm] FFileNameToObName - not a drive path - failing` without `:\`
(0x91f2eb3c). `translate` holds only a backend, so it reads the mask the
server publishes (`console::Backend::trace_mask`); callers off the server
thread already translate through `dispatcher::call_on_server`.

## Divergences and gaps

- getfile: the SO_SNDBUF change (0x10000) has no Network trait operation;
  not wire-visible.
- getfile/sendfile/getvfattr/sendvfile: stock does not check some pool
  allocations (crash); here they fail with `400- out of memory`.
- getvfattr/sendvfile `count=0`: stock frees the block on the first piece
  and frees it again later; here the input is swallowed without a reply.
- sendvfile: names longer than 0x4000 bytes are truncated (stock receive
  window reaches 0); header_len 0x20 with nonzero size opens the empty
  name in the same call.
- Control code 0x03 (0x91f2ef60): a title row keeps the title's string
  pointer (`DriveTarget::Mapped`) and its length at mapping time, as the
  image does; the server thread runs the mapping through
  `dispatcher::call_on_server`. Unreadable title memory leaves the table
  unchanged or translates as an empty target (stock faults).
- DMSATA prints (stock 0x91f3ebb0 into the `dbgprint` ring) are queued in
  `dvd_hotplug.rs` and reach the ring on the next server pass.
- The DMSATA hot-plug DPC and StartReinitialize use the fixed CD-ROM SATA
  register address; stock reloads it from the channel extension, whose
  word `find_channel` validated.

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
