# XBDM command specifications, group 4

Source: stock XBDM 2.0.21256.0, image base 0x91f00000. Addresses are virtual
addresses in that image.

## Common rules used below

Dispatch, reply formatting, continuation pumps and the HRESULT text map are
specified in `framework.md`. Points relied on in this file:

- Handler call: `(line, resp, 0x1fb, ctx)`. `ctx` is connection slot + 0x228
  (slots of 0x298 bytes from 0x91fab9e0); NULL when run from xbdm.ini. Context
  words: [0] continuation, [1] byte count (0xffffffff = text line mode),
  [2] data buffer, [3] buffer size, [4] scratch pointer (default slot + 0x240),
  [5] bytes remaining.
- Reply text is `resp` if non-empty, else the mapped text. 0x80004005 and
  0x82da0000 map to an empty text, giving `400- ` (with trailing space).
  0x82da0104 is the end-of-data code of continuations.
- Extra bit 0x2: the command is reported as `407- unknown command` when the
  test-kit flag (0x91f9f680) is nonzero.
- Access value is the set of connection privilege bits of which at least one
  is required (0x1 read, 0x2 write, 0x4 control, 0x8 config, 0x10 manage),
  else `414- access denied`; 0 means always allowed.
- Parameter helpers: find token 0x91f41638 (flag mode when third argument is
  0), string 0x91f41880, dword 0x91f418d8 (strtol base 0), required dword
  0x91f41b20 (writes `missing %s` with the name exactly as spelled in the
  image and the handler then returns 0x80004005, giving `400- missing <name>`).
  Keys match case-insensitively.
- NTSTATUS to HRESULT map 0x91f41f18 `(status, default)`: 0 -> 0x02da0000;
  0xc0000008 -> 0x80070057; 0xc0000022 -> 0x82da000e; 0xc0000033 and
  0xc0000039 -> 0x82da000c; 0xc0000034 -> 0x82da0002; 0xc0000035 ->
  0x82da000a; 0xc000003a -> 0x82da001e if default is 0x82da000d, else
  0x82da0002; 0xc000007f -> 0x82da000f; 0xc000009a -> 0x8007000e;
  0xc00000ba -> 0x82da0002; 0xc0000101 -> 0x82da000b; anything else
  (including positive non-zero) -> default. All callers in this group pass
  default 0x8000ffff (`400- unexpected error`).
- XAM system version tests use XamGetSystemVersion; the value layout is
  major(4 bits) minor(4) build(16) qfe(8). 0x200a9a00 = 2.0.2714.0,
  0x201c7d00 = 2.0.7293.0.
- XAM procedures are resolved with XexGetProcedureAddress on the XAM module
  handle (0x91fadecc, set at init from `xam.xex`).

## getsum

- Handler: 0x91f4b688. Access: 0x4. Extra: 0x0.
- Syntax: `getsum ADDR=<dword> LENGTH=<dword> BLOCKSIZE=<dword>`. All three
  required, dword grammar.
- Behavior:
  1. `ADDR` absent: `400- missing ADDR`. Then `LENGTH`: `400- missing LENGTH`.
     Then `BLOCKSIZE`: `400- missing BLOCKSIZE`.
  2. BLOCKSIZE 0: text `Zero BLOCKSIZE not allowed.`, result 0x82da0017:
     `423- Zero BLOCKSIZE not allowed.`
  3. Scratch (ctx[4]) word 0 := BLOCKSIZE, word 1 := ADDR.
  4. On first use, a 0x400-byte CRC table is allocated (0x91f330e0) and stored
     in global 0x91fab978; it persists for the life of XBDM. Allocation
     failure: 0x80004005 (`400- `). Table entry i (0..255): v = i << 24, then
     8 times: if bit 31 of v is set, v = (v << 1) XOR 0x04c11db7, else
     v = v << 1.
  5. ctx[3] := 0x2000; ctx[2] := allocation of 0x2000 bytes (not checked for
     failure); ctx[5] := (LENGTH / BLOCKSIZE) * 4 (unsigned division; any
     remainder of LENGTH is ignored; 32-bit wrap not checked); ctx[0] :=
     continuation 0x91f4b568. Returns 0x02da0003: `203- binary response
     follows`.
  6. Continuation: when ctx[5] is 0, frees the 0x2000 buffer and returns
     0x82da0104 (end). Otherwise n = min(ctx[5], 0x2000); for each of n/4
     blocks it computes one dword and stores it in the buffer in native
     (big-endian) order, then advances the address by BLOCKSIZE. ctx[1] := n,
     ctx[5] -= n, returns 0x02da0000 so the pump sends n bytes.
  7. Block value: every 4 KiB page from (addr & ~0xfff) through
     ((addr + BLOCKSIZE - 1) & ~0xfff) is checked with 0x91f26958
     (MmDbgReadCheck must return non-NULL, and the returned address must not
     lie in any of the ranges 0x7fc80000-0x7fc9ffff, 0x7fd00000-0x7fdfffff,
     0x7fea0000-0x7feaffff, 0x7fed0000-0x7fedffff, 0x8fff0000-0x8fff0fff,
     0x8fff1000-0x8fff1fff; table at 0x91f9603c). If any page fails, the
     value is 0. Else crc = 0xffffffff; for each byte b of the block:
     crc = table[(crc >> 24) XOR b] XOR (crc << 8). No final inversion
     (parameters equal CRC-32/MPEG-2).
  8. Output: exactly 4 * (LENGTH / BLOCKSIZE) bytes, no length prefix, no
     terminator. If that is 0, the reply is the 203 line followed by no data.
- Backend requirement: test readability of target virtual pages and read
  target virtual memory.
- Status: spec complete.

## getuserpriv

- Handler: 0x91f4bc48. Access: 0x0. Extra: 0x0.
- Syntax: `getuserpriv me` (flag) or `getuserpriv name=<string>` (up to 0x7f
  characters).
- Behavior:
  1. Connection privileges: if ctx is NULL, 0xffffffff; else the dword at
     slot + 0xc of the connection slot that contains ctx.
  2. Flag `me` present: if ctx is NULL, 0x80004005 (`400- `). Else the
     connection privileges are reported (step 5).
  3. Otherwise: connection privileges lacking 0x10 (manage):
     `414- access denied`. `name` absent: `400- missing name`.
  4. User lookup 0x91f40de8: opens object `name` (ObOpenObjectByName with
     root directory handle 0x91f9fecc and object type 0x91f976a8, the XBDM
     user object type), reads the privilege dword at object + 8. Not found:
     0x82da0002 `402- file not found`.
  5. Success `200- <text>`: if the privilege value is 0, text `none`. Else
     the words for each set bit in this order, separated by single spaces:
     0x1 `read`, 0x2 `write`, 0x4 `control`, 0x8 `config`, 0x10 `manage`.
     Other bits are not reported. (The formatter 0x91f40878 writes a leading
     space at resp - 1, so the text starts with the first word.) With NULL
     ctx and no `me`, privileges 0xffffffff pass the manage check.
- Backend requirement: user account store with per-user privilege masks;
  per-connection privilege mask.
- Status: spec complete.

## getvfattr

- Handler: 0x91f460a8. Access: 0x3. Extra: 0x0.
- Syntax: `getvfattr count=<dword>` (required), followed by binary upload.
- Behavior:
  1. `count` absent: text `missing count`, `400- missing count`.
  2. Scratch (ctx[4]) layout: +0x00 := 0, +0x04 pool block, +0x08 index := 0,
     +0x28 phase flag bit 0x40000000 cleared (0 = length phase), +0x4c count.
     Pool block: ExAllocatePoolWithTag(count * 0x1c + 0x141, 'bdbd'), not
     checked for failure. Bytes 0..0x140 are the receive area; records start
     at +0x141.
  3. ctx[5] := 4, ctx[2] := pool block, ctx[3] := 0x141, ctx[0] :=
     continuation 0x91f45ea8. Returns 0x02da0004: `204- send binary data`.
  4. Upload format, repeated count times: 4-byte big-endian length L, then L
     bytes of file name. Each receive lands at the start of the receive area;
     names longer than 0x141 bytes are received in chunks that overwrite one
     another, and only the last chunk is used. The receive area is not
     NUL-terminated by XBDM; the name must carry its own NUL within L
     [INFERENCE: stale bytes from earlier names otherwise follow].
  5. Length phase: when 4 bytes have arrived, ctx[5] := L, phase := name.
     L = 0 leaves ctx[5] = 0 with result 0x02da0000, so the pump sends
     `200- OK` and resets the context; following upload bytes are parsed as
     commands. The pool block is not freed (0x91f45f34..0x91f45f54).
  6. Name phase, when ctx[5] reaches 0: record index i = scratch+8 (then
     incremented); record zeroed (0x1c bytes). If the name begins with
     `\Device\` (case-insensitive), it is copied (max 0x140 bytes) as the
     object path. Else it is translated by the drive-path routine 0x91f2e888
     (`X:\...` to an object name); failure sets record attributes to
     0xffffffff. The path is queried with NtQueryFullAttributesFile
     (OBJ_CASE_INSENSITIVE). Failure: attributes 0xffffffff, other fields 0.
     Success: record = 7 big-endian dwords: creation time high, creation time
     low, last write time high, last write time low, end-of-file size high,
     size low, file attributes.
  7. After the last record, result 0x02da0003 switches to 203 output
     (`203- binary response follows`). First send call (ctx[5] = 0xffffffff):
     ctx[2] := records, ctx[1] := count * 0x1c, ctx[5] := 0; the pump sends
     all records at once. Next call: pool freed, 0x82da0104.
  8. count = 0: the first 4 received bytes cause the pool to be freed
     (0x91f45ec4 index == count, 0x91f45efc export 9) and 0x82da0104
     returned while ctx[5] stays 4; the receive pump ignores results while
     ctx[5] != 0 (0x91f426b0), so it keeps receiving into the freed block
     and the continuation frees it again on every piece. Defective in the
     stock image.
- Backend requirement: query file attributes (creation time, last write time,
  size, attribute bits) by drive path or device path.
- Status: spec complete.

## getxnkeyinfo

- Handler: 0x91f34998. Access: 0x1. Extra: 0x0.
- Syntax: `getxnkeyinfo` (no parameters).
- Behavior:
  1. XAM version < 0x200a9a00: `407- unknown command`.
  2. XAM ordinal 0x82 not resolvable: `414- access denied`.
  3. Allocates 0xa000 bytes (0x91f330e0); failure: `428- out of memory`.
  4. Calls ordinal 0x82 as `fn(3, buffer, &count)` with count = 0x400 on
     input. Non-zero return: buffer freed, `414- access denied`.
  5. Scratch: [0] buffer, [1] count, [2] index 0. ctx[0] := continuation
     0x91f348c0, ctx[5] := count * 0x28. Returns `202- multiline response
     follows`.
  6. Continuation: for each 0x28-byte entry, one line (0x100-byte line
     buffer, truncated and NUL-forced at the last byte):
     `xnkid="%s" ownertype=%d flags=0x%08x qosdatasize=%u qosbps=%u`
     xnkid = entry bytes 0..7 as 16 uppercase hex digits; ownertype = dword
     +0x08; flags = +0x0c; qosdatasize = +0x10; qosbps = +0x14. Bytes
     +0x18..+0x27 unused. After the last entry: buffer freed, terminator `.`.
- Backend requirement: enumerate the network stack's key registrations
  (XNKID, owner type, flags, QoS data size and rate).
- The first argument 3 is the caller identifier XBDM passes to every
  network-stack call it makes for itself (also `XnpGetActiveSocketList` in
  `getsockinfo`, through 0x91f72490). Ordinal 0x82 fills at most `*count`
  0x28-byte key records and stores the record count; 0 means success. The
  XAM module handle is the one XBDM obtains at startup with
  `XexGetModuleHandle("xam.xex")` (0x91f326c4, stored at 0x91fadecc,
  returned by 0x91f31010). The ordinal is resolved with
  `XexGetProcedureAddress` on every call; any non-negative status counts.
- Status: spec complete. The XAM side of ordinal 0x82 is outside this
  image; XBDM depends only on the record layout above.

## getxnqoslookupinfo

- Handler: 0x91f34bf0. Access: 0x1. Extra: 0x0.
- Syntax: `getxnqoslookupinfo` (no parameters).
- Behavior:
  1. XAM version < 0x200a9a00: `407- unknown command`.
  2. XAM ordinal 0x83 not resolvable: `414- access denied`.
  3. `fn(3, NULL, &count)` with count = 0; result must be 0 or 0x2747
     (buffer too small), else `414- access denied`.
  4. count := count + 1; allocate count * 0x88 bytes; failure:
     `428- out of memory`. `fn(3, buffer, &count)`; non-zero: buffer freed,
     `414- access denied`.
  5. Scratch [0] buffer, [1] count, [2] index 0; ctx[0] := 0x91f34a98;
     ctx[5] := count * 0x88. `202- multiline response follows`.
  6. One line per 0x88-byte entry (0x100-byte line buffer, truncated):
     `ownertype=%d flags=0x%08x preq=%u ptx=%u prx=%u datarx=%u bps=%u targetaddr=0x%08x targetport=0x%04x state=%d retry=%d secaddr=0x%08x xnkid="%s" xnaddr="%s"`
     Fields: ownertype +0x04; flags +0x08; preq +0x18; ptx +0x1c; prx +0x20;
     datarx +0x24; bps +0x28; targetaddr +0x0c; targetport u16 +0x10;
     state u8 +0x12; retry u8 +0x13; secaddr +0x14; xnkid = bytes
     +0x2c..+0x33 as uppercase hex; xnaddr = bytes +0x34..+0x57 (0x24 bytes)
     as uppercase hex. Dword +0x00 and bytes +0x58..+0x87 unused. A fully
     populated line exceeds 255 characters and is truncated by the line
     buffer.
  7. After the last entry: buffer freed, `.`.
- Backend requirement: enumerate pending QoS lookups of the network stack.
- Ordinal 0x83 takes the same caller identifier 3 and `(buffer, &count)`;
  with a NULL buffer it reports the number of lookups in `count` and returns
  0 or 0x2747 (WSAEMSGSIZE). The extra record allocated beyond the reported
  count absorbs a lookup added between the two calls.
- Status: spec complete. The XAM side of ordinal 0x83 is outside this
  image.

## getxnsecassocinfo

- Handler: 0x91f347c0. Access: 0x1. Extra: 0x0.
- Syntax: `getxnsecassocinfo` (no parameters).
- Behavior:
  1. XAM version < 0x200a9a00: `407- unknown command`.
  2. XAM ordinal 0x81 not resolvable: `414- access denied`.
  3. Allocates 0x1e000 bytes; failure: `428- out of memory`.
  4. `fn(3, buffer, &count)` with count = 0x400; non-zero: buffer freed,
     `414- access denied`.
  5. Scratch [0] buffer, [1] count, [2] 0; ctx[0] := 0x91f34680; ctx[5] :=
     count * 0x78. `202- multiline response follows`.
  6. One line per 0x78-byte entry (0x100-byte buffer, truncated):
     `secaddr=0x%08x ownertype=%d flags=0x%08x xnkid="%s" xnaddr="%s" serviceid=%d remoteaddr=0x%08x remoteport=0x%04x state=%d nataddr=0x%08x natport=0x%04x`
     Fields: secaddr +0x00; ownertype +0x04; flags +0x08; xnkid bytes
     +0x10..+0x17 uppercase hex; xnaddr bytes +0x18..+0x3b uppercase hex;
     serviceid +0x3c; remoteaddr +0x40; remoteport u16 +0x44; state u8
     +0x46; nataddr +0x48; natport u16 +0x4c.
  7. After the last entry: buffer freed, `.`.
- Backend requirement: enumerate network security associations.
- Ordinal 0x81 takes the caller identifier 3 and `(buffer, &count)` with
  capacity 0x400 records, like ordinal 0x82.
- Status: spec complete. The XAM side of ordinal 0x81 is outside this
  image.

## go

- Handler: 0x91f44548. Access: 0x4. Extra: 0x0.
- Syntax: `go` (no parameters).
- Behavior: calls 0x91f25b50. Global execution state 0x91fae664 (names via
  table 0x91f97608: 0 `stopped`, 1 `started`, 2 `rebooting`, 3 `pending`,
  4 `reboot_title`, 5 `pending_title`); saved state 0x91fae668; busy count
  0x91fae66c; all under critical section 0x91fae620.
  1. Requested state: 4 if the current state is 3, else 1.
  2. State machine 0x91f2da88 (request, no wait, notify):
     - Request 1, current 0: new state := saved state. Threads are resumed
       (threads that XBDM suspended, marked by debug-data +0x34, get
       KeResumeThread) on both thread lists (0x91fadeb4 and 0x91fadeb0);
       when the saved state is 4 only list 0x91fadeb0 is resumed.
     - Request 1, current 5: new state 1; threads waiting in an exception
       (debug flag 0x8) are released (flags 0xc cleared, event signalled)
       and suspended threads resumed, both lists.
     - Request 1, current 1 or 4: no change, `408- not stopped`.
     - Request 1, current 2: assertion `ExecState machine failed.`, result
       0x82da0000 (`400- `).
     - Request 4, current 3: new state 4; list 0x91fadeb0 threads released
       and resumed.
     - If the busy count is non-zero the routine waits on the events at
       0x91fae65c and retries; a wait result of 1 returns `408- not stopped`.
  3. On a state change the notification `execution <name>` is sent to
     notification channels (0x91f39ad0 type 3).
  4. Success: `200- OK`. On 0x82da0008 the handler writes `not stopped`.
- Backend requirement: global stop/resume of title and system threads;
  execution state tracking and notification.
- Thread lists: 0x91fadeb4 and 0x91fadeb0 are debug monitor data +0x54 and
  +0x50, the addresses of the kernel's `KeTitleProcess` and
  `KeSystemProcess` pointers; threads are walked through process +4 (list
  head) and thread +0x110 (list entry) under the process spin lock
  (process +0).
- Status: spec complete.

## gpucount

- Handler: 0x91f43570. Access: 0x4. Extra: 0x0.
- Syntax: `gpucount enable` or `gpucount disable` (flags).
- Behavior: `enable` is tested first, then `disable`. Neither:
  `407- unknown command`. Either: calls 0x91f2af30 (argument 1 for enable,
  0 for disable), which returns 0x02da0000 without side effects:
  `200- OK`.
- Backend requirement: none.
- Status: spec complete.

## halt

- Handler: 0x91f47ef8. Access: 0x4. Extra: 0x2.
- Syntax: `halt [thread=<dword>]`.
- Behavior: `thread` is parsed (0 when absent) and passed to 0x91f25c58,
  which returns 0x82da0000 unconditionally. Reply: `400- ` (empty text). No
  state is changed. Gated by extra bit 0x2 (`407- unknown command` on test
  kits).
- Backend requirement: none.
- Status: spec complete. Disagreement: the client wrapper `Halt` in
  `openxbdm/client/src/commands/debug.rs` expects `200- OK`.

## hdd

- Handler: 0x91f4dc50. Access: 0x4. Extra: 0x0.
- Syntax: `hdd enable` or `hdd disable` (flags).
- Behavior: `enable` tested first (value 0), then `disable` (value 1).
  Neither: text `missing arguments`, `400- missing arguments`. Reads XConfig
  category 2 setting 6 (4 bytes) with ExGetXConfigSetting; on failure the
  NTSTATUS is mapped. Else bit 0 of the dword := value (enable clears it,
  disable sets it), written with ExSetXConfigSetting; that NTSTATUS is
  mapped: 0 -> `200- OK`.
- Backend requirement: persistent console configuration flag disabling the
  hard disk.
- Status: spec complete.

## httpreg

- Handler: 0x91f30a18. Access: 0x10. Extra: 0x0.
- Syntax: `httpreg clear` (flag) or
  `httpreg server=<string> object=<string> [port=<dword>]` (strings up to
  0xff characters).
- Behavior (critical section 0x91f97360 held throughout):
  1. If the registration state 0x91f9f638 is 1..7, the HTTP request,
     connection and session handles (0x91f9f648, 0x91f9f644, 0x91f9f640) are
     closed. Then server (0x91fae420), object (0x91fae320), port
     (0x91f9f63c), 0x91f9f658 and the 0x400-byte response buffer 0x91fadee0
     are cleared.
  2. `clear`: state := 8, `200- OK`.
  3. `server` absent: state := 10, `423- bad parameter`. `server` is stored
     before `object` is read; `object` absent: state := 10,
     `423- bad parameter` with the server kept.
  4. object not starting with `/`: state := 10, `412- filename is invalid`;
     the object stays stored.
  5. port := `port` or 0 (low 16 bits kept). state := 0, `200- OK`.
  6. After leaving the critical section, xbdm.ini is rewritten (0x91f31e48);
     the line saved is `httpreg server=%s object=%s port=%u` or
     `httpreg clear` when the object is empty (0x91f30c88). The writer traps
     (`twui 0x19`) when the object is nonempty and does not start with `/`
     or the server is empty, so `httpreg server=a object=b` (and
     `httpreg server= object=/b`) end in a debug trap while writing
     xbdm.ini. The settings-file loader (0x91f311b8) calls this handler for
     `httpreg` lines directly.
  7. Background task 0x91f30580, run on every pass of the server loop: in
     state 0 it waits until `XNetGetDebugXnAddr(3)` reports an address and,
     before system software 0x20165400, until the execution state is
     started; it then stores the address and tick, goes to state 8 when no
     object is set, and to state 10 when the address IP is 0. Otherwise
     0x91f300e0 draws 8 bytes from `XNetRandom` as the transaction, opens
     `XHttpStartup(3,0,0)`, `XHttpOpen(3, "Xbox Debugger/2.0.21256.0", 0,
     0, 0, 0x10000000)`, `XHttpConnect(server, port, 1)` and
     `XHttpOpenRequest(conn, "GET", URL, 0, 0, 0, 0)` with URL
     `_snprintf(0x400)` of
     `%hs?name=%hs&dbgmac=%02X%02X%02X%02X%02X%02X&dbgip=%u.%u.%u.%u&verflash=%u.%u.%u.%u&verxdk=2.0.21256.0&type=%u&locked=%i&transaction=%016I64X`
     (object, debug name, XNADDR +0xa..+0xf, XNADDR +0..+3, kernel version
     with qfe & 0x7fff, test kit flag, lock state != 0, transaction), sets
     status callback 0x91f2ffa0 and options 0x59 = 3 and 0x3f = 8, sends,
     and prints `XBDM: Attempting to register at [http://%hs[:%u]%hs]...`.
     A failed step prints `XBDM: Failed <step> (err = %d)!` with
     `GetLastError` and the task goes to state 10. States 1..7 are driven by
     `XHttpDoWork` and the callback; status 200 and a content length up to
     0x400 read the body into 0x91fadee0 (state 9, `XBDM: Received %u byte
     HTTP registration response.`), another status gives state 11, a larger
     body state 12, other failures state 10, each with its message. Export
     194 returns the body and the transaction. Every 30 seconds the network
     address is compared with the last one; a change restarts registration
     from state 0. The task returns the server loop's select timeout: 3600 s
     in state 8 or when no object is set, 1 ms while a request or the
     address is pending, 30 s after success or failure, else the time left
     of the 30 s period.
  8. Title termination (routine 0x91f32398 calls 0x91f30998): before system
     software 0x20165400, a request in states 1..7 is closed and the state
     returns to 0.
- Backend requirement: persistent settings file; outbound HTTP client;
  periodic work from the server loop.
- Status: spec complete. Unknown: further request headers XHttp adds (no
  xam.xex image).

## ipproxy

- Handler: 0x91f35b20. Access: 0x4. Extra: 0x0.
- Syntax: `ipproxy start ver=<dword> addr=<dword> port=<dword>` or
  `ipproxy stop`. The `start` flag is tested first, so `ipproxy stop start`
  takes the start path.
- State block 0x91f9f6a0 (zero at load): +0 register routine (nonzero =
  started), +4 inject routine, +8 socket, +0xc thread handle, +0x10 last
  receive tick, +0x14 last send tick, +0x18 host addr, +0x1c local addr,
  +0x20 host port u16, +0x22 local port u16, +0x24 0x5c0-byte receive
  buffer. Ticks are `KeTimeStampBundle` (krnl 0xad) +0x10, milliseconds.
  Netsim instance creation (0x91f365e8) sets the proxy bypass flag on the
  new instance when +0 is nonzero.
- Behavior, start:
  1. ver, addr, port: absent or unparsable values read as 0. ver = 0,
     addr = 0, port = 0 or port > 0xffff: `423- bad parameter` (ver is
     otherwise unused).
  2. +0 nonzero: `410- file already exists`.
  3. `XamGetSystemVersion() < 0x201c7d00`: `407- unknown command`.
  4. `XexGetProcedureAddress(xam, 0x8b, &+0)` then `(xam, 0x8c, &+4)`;
     either fails: `414- access denied`. When 0x8b resolves and 0x8c fails,
     +0 stays set: later starts return 410 and `stop` succeeds (its
     `closesocket(+8)`, `NtWaitForSingleObjectEx(+0xc)` and `NtClose` act
     on 0 / -1 handles).
  5. +0x18 := addr, +0x20 := port, +0x10 = +0x14 := tick. `socket(AF_INET,
     SOCK_DGRAM, IPPROTO_UDP)` (caller 3) into +8. `connect` to
     `{AF_INET, port, addr}` (both stored as given, i.e. the dword value is
     the address in network order and the port number is the port). If
     connect returns 0: `getsockname` into the same sockaddr; +0x22 := its
     port and +0x1c := first dword of `XNetGetDebugXnAddr(3)` (xam 0x4a),
     both stored before the getsockname result is tested. A socket error
     takes e = `WSAGetLastError()`; connect/getsockname errors close the
     socket (+8 := -1).
  6. `0x91f8c6a0(0x91f9fc84 instance, 1)` if a netsim instance exists:
     0x91f8d3d8 sets instance flag 0x80000000 (+0xa0) under the instance
     spin lock, so the simulator passes tunnel frames unchanged.
  7. `register(2, &{0x10, 0x5a7, 0x91f9f6a0, 0x91f355e8}, 1)` (record on
     the stack). Nonzero r: bypass flag cleared, socket closed, e = r.
  8. `ExCreateThread(&+0xc, 0x4000, NULL, NULL, 0x91f35798, 0x91f9f6a0,
     0x04000426)`; failure: bypass flag cleared, `register(2, NULL, 1)`
     (result ignored), socket closed, e = 10055.
  9. e != 0: +0 := 0 (+4 keeps its value), `400- err=%i`. e = 0 (also
     after a socket step whose `WSAGetLastError` is 0, leaving +0 set):
     `200- started ver=1 addr=0x%08x port=0x%04x` with +0x1c and +0x22
     (ver is the constant 1).
- Outbound hook 0x91f355e8(state, packet, &length), called by the network
  stack for outgoing IPv4 packets:
  1. IHL*4 > 20 (options) or flags word & 0x3fff (more fragments or offset):
     return 0. The version nibble is not tested; IHL < 5 is accepted.
  2. Protocol 6: the TCP checksum (+16) and urgent pointer (+18) are zeroed,
     message header `{0x02, dst ip}` (5 bytes), carried bytes = the whole
     segment. Protocol 17: header `{0x03, dst ip, dst port, src port}`
     (type 0x04 when dst ip is 255.255.255.255; 9 bytes), carried bytes =
     UDP payload. Other protocols: return 0. Lengths come from `*length`,
     not the IP total length.
  3. header + carried > 0x5c0: return 0 (a TCP packet keeps its zeroed
     checksum and urgent pointer).
  4. The IP header is rewritten in place: protocol 17, source := +0x1c,
     destination := +0x18; total length, identification, TTL and header
     checksum are left unchanged. A UDP header `{+0x22, +0x20, header +
     carried + 8, 0}` is built. `inject(3, pieces, 4, 1)` with pieces
     `{length, pointer}`: IP header, UDP header, message header, carried
     bytes. +0x14 := tick; return 1 (consumed).
- Receive thread 0x91f35798(state): `setsockopt(SOL_SOCKET, SO_RCVTIMEO,
  5000)`, then loop: `recv(+8, +0x24, 0x5c0, 0)`; -1 with WSAETIMEDOUT
  (10060) counts as 0 bytes, any other error ends the thread. Then if tick
  - +0x14 >= 20000: `send({0x01})`, +0x14 := tick (outbound tunnel traffic
  also defers the keepalive). Messages: 0x01 sets +0x10. 0x02 with >= 5
  bytes: `{src ip, TCP segment}`. 0x03/0x04 with >= 9 bytes: `{src ip, src
  port, dst port, payload}`. Others, and shorter ones, are ignored without
  touching +0x10. Valid packet messages set +0x10 and are injected with
  `inject(2, pieces, 3, 0)`: a 20-byte IPv4 header `{0x45, 0, total length,
  id 0, flags 0, TTL 1, protocol, checksum 0, src ip, 127.0.0.1 or
  255.255.255.255 for 0x04}`, then for TCP the segment and an empty piece
  `{0, NULL}`, for UDP the header `{src port, dst port, payload + 8,
  checksum 0}` and the payload. No timeout tears the tunnel down; +0x10 is
  never read.
- Behavior, stop: +0 = 0: `426- ` (0x82da001a, empty text).
  `register(2, NULL, 1)` nonzero r: `400- err=%i` (proxy stays started).
  Else `closesocket(+8)` (ends the pending receive), +8 := -1,
  `NtWaitForSingleObjectEx(+0xc, 0, 0, NULL)`, `NtClose(+0xc)`, +0xc = +0 =
  +4 := 0, bypass flag cleared, `200- stopped`.
- Neither flag: `423- bad parameter`.
- The XAM exports are known only by their use here: 0x8b
  `register(caller, record or NULL, 1)` installs or removes the outbound
  IP hook; 0x8c `inject(caller, pieces, count, flags)` sends (flags 1) or
  delivers (flags 0) a packet given as pieces.
- Backend requirement: XAM IP hook and inject exports; UDP socket; a
  thread.
- Status: spec complete. Behavior of the XAM exports themselves (and of
  `recv` for datagrams over 0x5c0 bytes) is outside the monitor image.

## iptv

- Handler: 0x91f4df08. Access: 0x4. Extra: 0x0.
- Syntax: `iptv enable` or `iptv disable` (flags, `enable` tested first).
- Behavior: neither: text `missing arguments`, result 0x80004005 ->
  `400- missing arguments`. Else 0x91f4d350(setting 0xc, mask 0x1000,
  enable): resolves kernel ordinal 700 (0x2bc,
  ExReadModifyWriteXConfigSettingUlong in the kernel image) once into
  0x91f9ff94 and calls it as `fn(3, 0xc, ~mask, enable ? mask : 0)`; the
  export reads the 4-byte setting, stores `(old & and) | or` under the
  XConfig lock, and returns the get or set status. If the ordinal is
  missing (0xc0000138), falls back to read XConfig category 3 setting 0xc
  (4 bytes), OR mask (enable) or AND ~mask (disable), write back; a failed
  read skips the write. The final NTSTATUS (export, failed read, or write)
  is mapped by 0x91f41f18 with fallback 0x8000ffff: 0 -> `200- OK`,
  0xc0000022 -> `414- access denied`, unlisted failures ->
  `400- unexpected error`.
- Backend requirement: persistent console configuration flag word
  (category 3, setting 0xc), bit 0x1000.
- Status: spec complete.

## iptvallowuninstall

- Handler: 0x91f4e288. Access: 0x4. Extra: 0x0.
- Syntax: `iptvallowuninstall enable|disable`.
- Behavior: as `iptv` with mask 0x02000000, inverted: `enable` clears the
  bit, `disable` sets it. Neither: `400- missing arguments`.
- Backend requirement: same flag word, bit 0x02000000.
- Status: spec complete.

## iptvbootstrapurl

- Handler: 0x91f4e0c8. Access: 0x4. Extra: 0x0.
- Syntax: `iptvbootstrapurl <value>`: positional value at fixed line offset
  0x11 (command word plus one separator character).
- Behavior: value copied with the value-copy rules (ends at space/CR/NUL
  outside quotes; quotes removed), at most 63 characters. Each byte is
  sign-extended and truncated to 16 bits (bytes 0x80..0xff become
  0xff80..0xffff), stored big-endian into a zeroed 0x80-byte buffer.
  ExSetXConfigSetting(9, 4, buffer, 0x80); NTSTATUS mapped as for `iptv`.
  No validation. The handler reads the connection receive buffer, where the
  CR is replaced by NUL in place: a line shorter than the offset reads the
  byte after the CR (normally LF) and then the remaining buffer bytes
  (pipelined data, or stale bytes of earlier longer lines on the same
  connection) up to a space, CR, or NUL.
- Backend requirement: persistent IPTV configuration string (category 9,
  setting 4, 64 UTF-16 units).
- Status: spec complete.

## iptvdvr

- Handler: 0x91f4e1e8. Access: 0x4. Extra: 0x0.
- Syntax: `iptvdvr enable|disable`.
- Behavior: as `iptv` with mask 0x00080000; enable sets, disable clears.
  Neither: `400- missing arguments`.
- Backend requirement: same flag word, bit 0x00080000.
- Status: spec complete.

## iptvprovidername

- Handler: 0x91f4dfa8. Access: 0x4. Extra: 0x0.
- Syntax: `iptvprovidername <value>`, positional at offset 0x11.
- Behavior: as `iptvbootstrapurl` with at most 59 characters, a 0x78-byte
  buffer and ExSetXConfigSetting(9, 1, buffer, 0x78).
- Backend requirement: IPTV configuration string (category 9, setting 1,
  60 UTF-16 units).
- Status: spec complete.

## iptvprovisioningurl

- Handler: 0x91f4e038. Access: 0x4. Extra: 0x0.
- Syntax: `iptvprovisioningurl <value>`, positional at offset 0x14.
- Behavior: as `iptvbootstrapurl` (63 characters, 0x80 bytes) with
  ExSetXConfigSetting(9, 2, buffer, 0x80).
- Backend requirement: IPTV configuration string (category 9, setting 2).
- Status: spec complete.

## iptvsupportinfo

- Handler: 0x91f4e158. Access: 0x4. Extra: 0x0.
- Syntax: `iptvsupportinfo <value>`, positional at offset 0x10.
- Behavior: as `iptvbootstrapurl` (63 characters, 0x80 bytes) with
  ExSetXConfigSetting(9, 3, buffer, 0x80).
- Backend requirement: IPTV configuration string (category 9, setting 3).
- Status: spec complete.

## irtsweep

- Handler: 0x91f4a5f0. Access: 0x4. Extra: 0x0.
- Syntax: `irtsweep` (parameters ignored).
- Behavior: writes `error status 0x%08x` with 0xc0000002 and returns
  0x82da0000: `400- error status 0xc0000002`. No side effects.
- Backend requirement: none.
- Status: spec complete.

## isbreak

- Handler: 0x91f48c28. Access: 0x4. Extra: 0x2.
- Syntax: `isbreak addr=<dword>` (required).
- Behavior:
  1. `addr` absent: `400- missing addr`.
  2. 0x91f257f8: if the software breakpoint table (0x91fae980, sorted pages
     of addresses, spin lock 0x91fae9c0) contains addr, type = 4. Else
     type = 0, and if addr equals the data breakpoint address 0x91fae934,
     type = data breakpoint kind 0x91fae93c (1 write, 2 read/write, 5 read;
     set by 0x91f27370, which programs DABR bits 0x2, 0x3, 0x1). Only exact
     address equality is tested.
  3. `200- type=%d`.
- Backend requirement: query software and hardware breakpoints by address.
- Status: spec complete. Disagreement: client `IsBreak` maps 1 Execution,
  2 DataRead, 3 DataWrite, 4 DataReadWrite, 5 DataExecute; the stock values
  are 4 software (execution), 1 write, 2 read/write, 5 read.

## isdebugger

- Handler: 0x91f49480. Access: 0x4. Extra: 0x0.
- Syntax: `isdebugger` (no parameters).
- Behavior: debugger record 0x91f9fef8 (+0 attached flag, +4 debugger IP,
  +8 port, +0xc name, +0x8c user; written by `debugger`).
  1. Flag 0: `200- OK`.
  2. If IP non-zero and running at passive level: when no notification
     channel matches IP and port (0x91f38c08 scans the 16 entries at
     0x91fadb00), `200- OK`.
  3. Name and user both empty: `410- file already exists`.
  4. Else `410- ` followed by `%s%s%s%s%s` = (`name="` if name non-empty),
     name, (`" ` if name non-empty), (`user=` if user non-empty), user.
     Example: `410- name="PC" user=dev`. Truncated to the response buffer.
- Backend requirement: record of the attached debugger (address, port,
  name, user) and notification channel table.
- Status: spec complete.

## isstopped

- Handler: 0x91f48d90. Access: 0x4. Extra: 0x0.
- Syntax: `isstopped thread=<dword>` (required).
- Behavior:
  1. `thread` absent: `400- missing thread`.
  2. 0x91f26058: ObLookupAnyThreadByThreadId fails: `405- no such thread`.
     No debug data (thread +0x15c) or debug flag 0x8 (stopped) clear:
     `408- not stopped`. Else status 200 and a stop record built from the
     saved exception record (debug data +8) and context (+0xc):
     - No exception record: type 0.
     - 0x80000003 with subcode (u16 at record +0x16): 0x14 -> type 2;
       0x16 -> type 1 (addr = context +8); 0x19, 0x1a -> type 0xc;
       0x1b -> type 0xe; others -> type 0. For 0xc and 0xe: value A = low
       32 bits of context +0x30, value L = low 16 bits of context +0x38.
     - 0x80000004: type 4 when the first exception parameter is non-zero,
       else type 0xd; addr = context +8.
     - Code 0x00000015: type 0x15, addr = context +8.
     - Other codes: type 9 with code, address (record +0xc), flags (bit 0
       when record flags bit 0 set, bit 1 when debug flag 0x2 set), and for
       0xc0000005 parameters 0 and 1, else parameter count and the address of
       the parameter array.
  3. Text by type:
     - 2: `debugstr thread=0x%08x stop`
     - 0xc: `assert thread=0x%08x straddr=0x%0.8x strlen=0x%0.8x` (A, L)
     - 1: `break addr=0x%08x thread=0x%08x`
     - 4: `singlestep addr=0x%08x thread=0x%08x`
     - 0x15: `ntassert addr=0x%08x thread=0x%08x`
     - 0xd: `data %s=0x%08x addr=0x%08x thread=0x%08x` with %s `write`,
       `read`, `execute` for kind 1, 2, 3; kind and data address come from
       record words the stop-record builder does not set (uninitialized
       stack); a kind outside 1..3 yields `stopped`.
     - 0xe: `rip thread=0x%08x`, or when A is non-zero
       `rip thread=0x%08x string=%-*.*s` (width and precision L, string read
       from target address A).
     - 9: `exception code=0x%08x thread=0x%08x address=0x%08x` then for
       0xc0000005 ` read=0x%08x` or ` write=0x%08x` (parameter 0 zero or
       not; value parameter 1), else ` nparam=%lu params=0x%08x`; then
       ` first` if flag bit 1, then ` noncont` if flag bit 0.
     - 0 or unformatted: `stopped`.
- Backend requirement: per-thread stop state with exception code, address,
  parameters and selected registers; read target memory for `rip` strings.
- Code 0x00000015: the builder compares `code - 0x80000003` with
  0x80000012 (32-bit wrap), i.e. code 0x15. The dispatcher raises ntassert
  as 0xc0000420, so a thread stopped at an ntassert reports type 9
  (`exception code=0xc0000420 ...`).
- Type 0xd reads its kind from a stack word the builder never writes
  (export 22 writes only the type, context +8 and the thread for it,
  0x91f2618c..0x91f261b0; the handler's buffer at sp+0x60 is not
  initialized, 0x91f48dd0; the formatter reads buffer +0xc, 0x91f392c8).
  This is a stock uninitialized read; the reimplementation reports
  `stopped` (the text for kinds outside 1..3) and lists it as a deviation.
- Status: spec complete; the type 0xd kind is a stock defect.
  Cross-check: capture `isstopped_running.capture` shows `408- not stopped`,
  matching.
