# XBDM command specifications, group 1

Source: stock XBDM 2.0.21256.0, image base 0x91f00000. Addresses are virtual
addresses in that image.

## Common dispatch rules used below

These rules come from the dispatcher (0x91f505f0), the table lookup
(0x91f42278), the reply formatter (0x91f42028), the HRESULT text map
(0x91f41c98) and the NTSTATUS map (0x91f41f18). They apply to every command in
this group.

- Table entry gates, in order:
  1. Extra bit 0x2: if the test-kit flag (0x91f9f680) is nonzero, the command is
     treated as absent: `407- unknown command`.
  2. Access: if access is 0 the command is always allowed. Otherwise
     (access AND connection privilege mask) must be nonzero, else
     `414- access denied`. Privilege bits (from 0x91f40878): 0x1 read,
     0x2 write, 0x4 control, 0x8 config, 0x10 manage. The connection privilege
     mask is connection slot +0xc (set by `authuser`).
  3. Extra bit 0x4: the handler runs on a newly created title-process thread
     (ExCreateThread flags 0x20, priority class 13, no SYSTEM_PROCESS); the
     dispatcher waits for it and uses its return value (`framework.md`).
  4. Otherwise, if a server thread is registered (0x91fab984) and the current
     thread is not it, the command is rejected with
     `422- dedicated connection required` unless extra bit 0x1 is set.
- Handler call: (line, text buffer, 0x1fb, connection context). The connection
  context is connection slot + 0x228; slots are 0x298 bytes starting at
  0x91fab9e0. Context words: [0] continuation routine, [1] bytes received in
  the last receive, [2] receive pointer, [3] receive buffer size, [4] scratch
  pointer (initially slot + 0x240), [5] bytes still expected.
- Return 0 from a handler: no reply is sent.
- Reply line: if the HRESULT facility (bits 16..30) is 0x2da and the low 16
  bits are <= 0xff, status = 200 + low16 when non-negative, 400 + low16 when
  negative; otherwise status 200 (non-negative) or 400 (negative). The status
  number is always written as `2` or `4` followed by two decimal digits of the
  low 16 bits. The text after `NNN- ` is the handler text if non-empty, else
  the mapped text below. HRESULTs with no mapping produce an empty text
  (reply `NNN- ` followed by CRLF).
- HRESULT text map (relevant entries): 0x02da0000 `OK`;
  0x02da0002 `multiline response follows`; 0x02da0003
  `binary response follows`; 0x02da0004 `send binary data`; 0x82da0002
  `file not found`; 0x82da0003 `no such module`; 0x82da0004
  `memory not mapped`; 0x82da0005 `no such thread`; 0x82da0007
  `unknown command`; 0x82da0008 `not stopped`; 0x82da0009
  `file must be copied`; 0x82da000a `file already exists`; 0x82da000b
  `directory not empty`; 0x82da000c `filename is invalid`; 0x82da000d
  `file cannot be created`; 0x82da000e `access denied`; 0x82da000f
  `no room on device`; 0x82da0010 `not debuggable`; 0x82da0011
  `type invalid`; 0x82da0012 `data not available`; 0x82da0014
  `box is not locked`; 0x82da0015 `key exchange required`; 0x82da0016
  `dedicated connection required`; 0x82da0017 `bad parameter`; 0x82da001c
  `out of memory`; 0x82da001e `path not found`; 0x82da002e `line too long`;
  0x8000ffff `unexpected error`; 0x8007000e `out of memory`; 0x80070057
  `bad parameter`. All other codes (including 0x80004005, 0x82da0000,
  0x82da0018, 0x82da001b, 0x82da001d, 0x82da0021..0x82da0027, 0x82da002a,
  0x82da002c) map to an empty text.
- Examples: 0x80004005 with no text -> `400- `; 0x82da0017 ->
  `423- bad parameter`; 0x82da002a -> `442- `; 0x02da0007 -> `207- ...`.
- NTSTATUS to HRESULT map (0x91f41f18, second argument is the default):
  0 -> 0x02da0000; 0xc0000008 -> 0x80070057; 0xc0000022 -> 0x82da000e;
  0xc0000033 and 0xc0000039 -> 0x82da000c; 0xc0000034 and 0xc00000ba ->
  0x82da0002; 0xc0000035 -> 0x82da000a; 0xc000003a -> 0x82da001e if the
  default is 0x82da000d, else 0x82da0002; 0xc000007f -> 0x82da000f;
  0xc000009a -> 0x8007000e; 0xc0000101 -> 0x82da000b; any other -> default.
- Required dword helper (0x91f41b20): on absence it formats `missing <name>`
  into the text buffer and returns false; whether the handler then fails is
  handler specific and stated per command.
- "Flag" below means the find-token helper with third argument 0: a bare
  token `name` or a `name=value` token both match; the key compare is
  case-insensitive.
- "XConfig get/set" means ExGetXConfigSetting / ExSetXConfigSetting
  (category, setting, buffer, size).
- XAM and kernel exports resolved at run time: 0x91fadecc holds the xam.xex
  module handle and 0x91faded0 the xboxkrnl.exe handle (0x91f32628). Ordinal
  resolution uses XexGetProcedureAddress or the GetProcAddress-style helper
  0x91f729d8 (handle from 0x91f78c10 "xam.xex").

## addtitlemem
- Handler: 0x91f515e0. Access: 0x4. Extra: 0x0.
- Syntax: `addtitlemem` (no parameters).
- Behavior:
  - Computes the console memory configuration value V (same routine as
    `consolemem`, 0x91f50088):
    - Hardware info word (kernel export ordinal 342, flags dword at offset 0):
      bit 0x10000 sets internal bit 0x4; bit 0x2000000 clear sets internal
      bit 0x1 (0x91f4cd60).
    - If internal bit 0x4 is clear, V = 0.
    - Else issue ExDebugMonitorService(8, buf, 0, 0) with a zeroed 0x90-byte
      buffer whose dword +0 = 0x90 and dword +4 = 0x68. If the call fails or
      the returned dword +0 is below 0x90, V = 0. Else V = 2 if dword +0x7c is
      unsigned-less-than dword +0x08, otherwise V = 1.
  - Result value R = 0. If V has bit 0x2 set:
    - Read the executable-module handle pointer (kernel export ordinal 403).
      If it is null: return 0x82da0003, reply `403- no such module`.
    - R = first dword of RtlImageXexHeaderField(module->XexHeader (+0x58),
      0x40801) when that call returns non-null; otherwise R stays 0.
  - Success: `200- addtitlemem=0x%x` (R, lowercase hex, no padding).
- Backend requirement: report the running title's additional-title-memory
  value (XEX optional header 0x40801) when the console is in the extended
  memory configuration; report 0 otherwise.
- Status: spec complete. Service 8 fields: +0x08 is the kernel physical
  page count and +0x7c the constant 0x20000 (512 MiB of pages), so V = 2
  means more than 512 MiB is present (see `consolemem`).

## adminpw
- Handler: 0x91f4bb30. Access: 0x10 (manage). Extra: 0x0.
- Syntax: `adminpw none` | `adminpw passwd=0q<hex>`.
  - `none`: flag.
  - `passwd`: qword (0q prefix, up to 16 hex digits).
- Behavior:
  - If `none` is present: clear the admin-password-set flag (0x91facefc = 0),
    write the settings file (0x91f31e48), reply `200- OK`.
  - Else select the decryption key K (8 bytes):
    - Context null (command replayed from the settings file): K = 0.
    - Context non-null: if connection flag bit 0x01000000 (slot +4; set by key
      exchange) is clear, return 0x82da0015, reply
      `421- key exchange required`. Else K = 8 bytes at slot +0x18 (session
      key).
  - `passwd` absent or malformed: text `missing passwd`, return 0x80004005,
    reply `400- missing passwd`.
  - Store P XOR K as the admin password (0x91facf00 = high dword XOR K[0..3],
    0x91facf04 = low dword XOR K[4..7]), set 0x91facefc = 1, write the
    settings file, reply `200- OK`.
  - Settings file line written while the flag is set (0x91f40ab0):
    `adminpw passwd=0q%08x%08x` (stored high, stored low). Replaying this line
    with a null context restores the same value.
  - Settings writes are skipped when hardware-info word +0xe bit 0x400 is set
    (DbgPrint "Cannot write xbdm.ini: CD boot").
- Backend requirement: persistent settings storage; per-connection session
  key from key exchange.
- Status: spec complete.

## advmem
- Handler: 0x91f43eb0. Access: 0x4. Extra: 0x0.
- Syntax: `advmem on` | `advmem off` | `advmem status` (flags, checked in
  that order).
- Behavior:
  - Reads 2 bytes at byte offset 6 of the raw flash device `\Device\Flash`
    (0x91f72bd0: NtCreateFile access 0xc0100000, OBJ_CASE_INSENSITIVE,
    FILE_OPEN, options 0x20; NtReadFile at the offset; NtClose; the result is
    the NtReadFile status). The value W is a big-endian 16-bit word; bit 0x100
    set means the feature is disabled.
  - Read failure: return 0x8000ffff, reply `400- unexpected error` (checked
    before any parameter).
  - `on`: if bit 0x100 is clear, reply `200- already enabled`. Else write
    W XOR 0x100 back to offset 6; failure: `400- unexpected error`;
    success: `200- enabled`.
  - Flash write 0x91f72c78: open as for the read; IOCTL 0x3c0028 returns a
    0x14-byte geometry whose dwords +0 and +8 multiply to the block size B.
    For each piece: when the offset is not B-aligned or fewer than B bytes
    remain, a B-byte bounce buffer (NtAllocateVirtualMemory MEM_COMMIT |
    MEM_RESERVE, PAGE_READWRITE, allocated once) receives the containing
    block (NtReadFile), the data is copied in, and the whole block is written
    back; aligned whole blocks are written from the caller's data. Any
    failure stops the loop; the buffer is released (MEM_RELEASE) and the
    handle closed.
  - `off`: if bit 0x100 is set, reply `200- already disabled`. Else write
    W XOR 0x100; failure `400- unexpected error`; success `200- disabled`.
  - `status`: `200- enabled` if bit 0x100 clear, else `200- disabled`.
  - None of the flags: text `improper command`, return 0x80004005, reply
    `400- improper command`.
- Backend requirement: read and write a 16-bit flag word at byte offset 6 of
  the console's raw flash.
- Meaning of flash word 6 bit 0x100: it withholds the development kit's
  additional memory, so the console runs with 512 MB instead of 1 GB from
  the next boot. `advmem on` (bit clear) gives 1 GB. Evidence from the
  devkit hypervisor image (HV 2.0.16547, `deanxbox-hv-16547.bin`,
  addresses are image offsets):
  - Startup routine 0x1cd8 (first call of the initialization sequence
    0x3040) copies the first 0x10 bytes of the flash header from
    0x80000200_c8000000 (0x68c) to the stack. When the boot flag halfword
    at hypervisor header +6 has bit 0x80, it sets bit 0x1 of the
    hypervisor word at r2 + 0x10000 + 0x69c8. When flash header +6 has bit
    0x100 (0x1d2c), it clears bit 0x80 of the boot flags (0x1d3c..0x1d48).
    The physical memory size word (r2 + 0x10000 + 0x69e0) becomes
    0x40000000 when bit 0x80 remains and 0x20000000 otherwise (0x1d4c..0x1d68).
    The hypervisor checks physical addresses against that word (for
    example 0x2838).
  - The kernel entry hands the boot flags over in r3 (`lhz r3, 6(0)`,
    0x1b6c; r4 = the hypervisor magic 0x5e4e). KiInitializeKernel stores
    them at XboxHardwareInfo +0xe (K15574 0x801a5cdc).
    MmInitializeSystemPhase0 (K15574 0x800ae5b0, K16547 0x800ae908) copies
    bit 0x80 to MmDevkitMemoryPresent and sets MmHighestPhysicalPage to
    0x3ffff (1 GB of 4 KB pages) when it is set, else 0x1ffff (512 MB).
  - No other test of the flash bit was found in the hypervisor, the
    kernels, xam or xbdm. The devkit's running boot flags are 0x009e: bit
    0x80 is set, so it currently runs with `advmem` enabled.
- Status: spec complete.

## altaddr
- Handler: 0x91f49a08. Access: 0x4. Extra: 0x0.
- Syntax: `altaddr` (no parameters).
- Behavior:
  - Calls NetDll_XNetGetTitleXnAddr(3, &xnaddr) (wrapper 0x91f71610).
  - Return value 0 or 1: return 0x80004005, reply `400- `.
  - Otherwise: `200- addr=0x%08x` with the first dword of the returned address
    structure (the title IPv4 address, network order as a big-endian dword).
- Cross-check: capture `altaddr.capture` shows `200- addr=0xc0a80119`;
  client parses it as an IPv4 address. Consistent.
- Backend requirement: report the title network stack's IPv4 address; fail
  while it is pending or absent.
- Status: spec complete.

## authuser
- Handler: 0x91f4b9a8. Access: 0x0. Extra: 0x0.
- Syntax: `authuser [passwd=0q<hex>] [resp=0q<hex>] (admin | name=<string>)`.
  - `passwd`, `resp`: qwords. `admin`: flag. `name`: string, up to 0xff
    characters.
- Behavior, in order:
  1. Context null: return 0x80004005, reply `400- `.
  2. If connection flag bit 0x01000000 (slot +4, key exchange done) is set and
     `passwd` parses: mode = set-password, V = passwd XOR session key
     (slot +0x18 high, slot +0x1c low).
  3. Else `resp` is required: missing gives text `missing response`, reply
     `400- missing response`. mode = response, V = resp.
  4. If `admin` is present: in set-password mode reply `400- missing response`
     (text `missing response`, 0x80004005). Otherwise authenticate as admin.
  5. Else `name` is required: missing gives `400- missing name`.
  6. Privilege computation (0x91f40538), challenge C = 8 bytes at slot +0x20:
     - Admin: if mode is response and the admin password is set (0x91facefc),
       privileges = 0xffffffff when H(adminpw, C) == V, else 0.
     - User: look up the user object by name in the user object directory
       (0x91f9fecc; ObOpenObjectByName, attributes 0). Not found: 0.
       User object: +0 password (8 bytes), +8 privilege mask, +0xc
       password-set flag.
       - Password set, mode response: privileges = user mask when
         H(user password, C) == V, else 0.
       - Password set, mode set-password: privileges 0, mode cleared.
       - Password not set, mode set-password: store V as the user password,
         set the flag, write the settings file, privileges = user mask, mode
         cleared.
       - Password not set, mode response: privileges 0, mode set to
         set-password.
  7. The result is stored to slot +0xc unconditionally (a failed attempt
     removes all privileges).
  8. Result 0 and mode set-password: return 0x82da0015,
     `421- key exchange required`. Result 0 otherwise: 0x82da000e,
     `414- access denied`. Nonzero: `200- OK`.
- Response function H(S, C) (0x91f403c0), all words big-endian 32-bit:
  - Block function E(K, B): K = (K0, K1), B = (B0, B1), table
    T = {0x283c481d, 0x9ad82aa1, 0x85a5e1f9, 0x1b23963c, 0xf70b4975,
    0xdfdc02c7, 0xf29176fc, 0x6b04bd38} (0x91f97688). For i = 0..7:
    B1 ^= (K1 ^ B0) + ((~B0) << 6) + (B0 >> 5) + T[i];
    B0 ^= (K0 ^ B1) + (B1 << 6) + ((~B1) >> 5) + T[7 - i]
    (arithmetic mod 2^32, logical shifts).
  - Mix F(X, D): X = D XOR E(X, D).
  - H: X = 0x2718281831415926; X = F(X, S); Y = F(X, C); X = F(X, Y);
    return X.
- Backend requirement: user database (name, password, privilege mask),
  persistent settings, per-connection challenge and session key.
- Producers: the challenge C (slot +0x20) is the lock-mode nonce written at
  accept (framework section 2); the session key (slot +0x18) and flag
  0x01000000 are written by `keyxchg`. An unlocked connection does not
  rewrite slot +0x20, so it inherits the nonce of the previous locked
  connection in the same slot (0 if none), and `authuser` works there with
  that challenge.
- Privilege computation details (0x91f40538, disassembly): a correct
  response for a user whose mask is 0 yields 0 and `414- access denied`;
  an unknown user leaves the mode unchanged, so `passwd=` for an unknown
  name gives `421- key exchange required`.
- Status: spec complete.

## autoinput
- Handler: 0x91f4f100. Access: 0x4. Extra: 0x0.
- Syntax: `autoinput user=<dword> <subcommand> [...]`. Subcommand flags are
  tested in this order: `connect`, `disconnect`, `bind queuelen=<dword>`,
  `unbind`, `queuepackets count=<dword> [timearray] [countarray]`,
  `clearqueue`, `queryqueue`, `setpacket`, `process`.
- Common:
  - `user` missing: return 0x82da0025, reply `437- missing user`.
  - No subcommand matches: `200- OK`.
  - Per-user automation state: pointer table 0x91f9e46c[4], protected by spin
    lock 0x91faea3c. State: +0 flags (0x80000000 connected,
    0x40000000 queue playback, 0x20000000 guide button latched), +4 queue
    length, +8 queued entry count, +0xc queue head index, +0x10 change
    counter, +0x14 remaining count of current entry, +0x18 current entry
    deadline (ms tick), +0x20 u64 sum of queued times, +0x28 u64 sum of queued
    counts, +0x30 entry array; entry = 12-byte gamepad packet, +0xc time,
    +0x10 count (0x14 bytes). Allocation size 0x48 + (queuelen - 1) * 0x14
    (0x48 when queuelen is 0), pool tag `dmau`.
  - Every backend returns 0x82da0017 (`423- bad parameter`) when user >= 4.
    A backend result of 0 is converted to `200- OK`.
- `connect`: no state -> 0x82da002a (`442- `). If not connected: set
  connected, clear playback, reset +8 and +0xc, increment +0x10, zero the
  current packet (+0x30, 12 bytes). `200- OK`.
- `disconnect`: no state -> `442- `. Clear connected and playback, reset +8,
  +0xc, increment +0x10, zero current packet. `200- OK`.
- `bind`: `queuelen` required (missing: `437- missing queuelen`). Allocate and
  zero state (failure 0x82da001c, `428- out of memory`), set queue length,
  set connected, install it (freeing any previous state), then call
  XAutomationpBindController(user). If that returns 0: remove and free the
  state, return 0x82da0007 (`407- unknown command`). Else send system
  notification 0x7d with {user, 1} through the callback at offset +0x18 of
  the interface pointed to by kernel export ordinal 89 (when non-null).
  `200- OK`.
- `unbind`: XAutomationpUnbindController(user) returning 0 gives
  `407- unknown command`. Else remove and free the state, send notification
  0x7d with {user, 0}. `200- OK`.
- `queuepackets`:
  - `count` required (missing: `437- missing count`). `timearray`,
    `countarray`: flags.
  - Expected binary size N = count * 12, plus count * 4 if `timearray`, plus
    count * 4 if `countarray`. Allocate N bytes (tag `UAMD`, 0x444d4155);
    failure `428- out of memory`.
  - Scratch record at context [4]: user, count, packet pointer, time array
    pointer or 0, count array pointer or 0. Context [2] = buffer, [3] = [5] =
    N, [1] = 0, continuation 0x91f4efa0. Reply `204- send binary data`.
  - Client then sends N bytes: count packets of 12 bytes, then the time array
    (count dwords) if requested, then the count array (count dwords) if
    requested. Multi-byte fields are little-endian on the wire. Packet layout:
    +0 u16 buttons, +2 u8 left trigger, +3 u8 right trigger, +4 i16 thumb LX,
    +6 LY, +8 RX, +0xa RY.
  - Continuation: a receive of 0 bytes returns 0x82da0000 (`400- `). Bytes
    accumulate until N are received. Then the 16-bit fields at packet offsets
    0, 4, 6, 8, 0xa and each array dword are byte-swapped, and the queue
    backend (0x91f24f90) runs:
    - Packet pointer null, or both arrays absent: `423- bad parameter`
      (a `queuepackets` without `timearray` and without `countarray` always
      fails this way after the data is received).
    - No state, not connected, or queue length 0: `442- `.
    - Accept n = min(count, queuelen - queued) entries; set playback flag.
      Each entry is written at index (head + queued) mod queuelen with its
      packet, time (0 if no array) and count (0 if no array); the time and
      count sums at +0x20 and +0x28 are increased. When the queue was empty,
      playback of the first entry starts (0x91f24af8).
    - Reply `200- queued=0x%08x` (n). The buffer is freed in all cases after
      processing.
  - count 0: N = 0; the reply `204- send binary data` is followed
    immediately by `400- ` from the continuation.
- `clearqueue`: no state or not connected: `442- `. Else reset +8 and +0xc,
  increment +0x10. `200- OK`.
- `queryqueue`: no state: `442- `. Else
  `200- nQueue=0x%08x, nPacket=0x%08x, t_remain_ms=0x%08x, t_remain_count=0x%08x`
  where nQueue = queue length; when connected and playing back: nPacket =
  queued count, t_remain_ms = (+0x20) + max(0, (+0x18) - current ms tick)
  saturated to 0xffffffff, t_remain_count = (+0x14) + (+0x28) saturated;
  otherwise those three are 0. The tick is kernel export ordinal 173
  (+0x10).
- `setpacket`:
  - Stores user in the scratch record, sets context [5] = 12, [1] = 0,
    continuation 0x91f4ef00, reply `204- send binary data`. The 12 bytes are
    received into the dispatcher's 0x100-byte temporary buffer.
  - Continuation: if the single receive did not return exactly 12 bytes,
    return 0x82da0000 (`400- `). Swap the 16-bit fields at 0, 4, 6, 8, 0xa.
  - Backend (0x91f24e20): no state or not connected: result 0x82da002a
    (`442- `). Else clear playback, reset +8, +0xc, +0x3c, +0x40, increment
    +0x10, copy the packet to +0x30. If buttons bit 0x400 is set and the latch
    0x20000000 is clear: set the latch and call
    XAutomationpInputXenonButton(user); if bit 0x400 is clear: clear the latch.
  - Whenever user < 4 (also without state or connection) call the monitor
    control routine with code 0x78 and
    {u8 user, pad, u16 buttons, u8 lt, u8 rt, i16 lx, ly, rx, ry}.
  - Success: `200- OK`.
- `process`: requires XAM ordinal 0x3dd (resolved at init into 0x91f9e47c);
  absent: `407- unknown command`. Else call it; nonzero result:
  `200- system`, zero: `200- title`.
- Backend requirement: virtual controller injection for four user slots:
  bind/unbind a virtual controller, set the current gamepad state, queue
  timed gamepad states, report queue state and which process receives input.
- Playback (0x91f24af8 start entry, 0x91f25168 advance, 0x91f25200 timer
  DPC, 0x91f25310 poll):
  - Starting the head entry increments +0x10. With an empty queue it clears
    the guide latch, +0x14 and +0x18. Otherwise it subtracts the entry's
    time and count from the sums, sets +0x14 = count (polls still owed) and
    +0x18 = tick + time (deadline in ms), and applies the guide button rule
    to the entry's packet. When +0x14 is 0 it arms the single global timer
    0x91fae9e0 for 10 us (the computed relative time is never negative, so
    the -100 fallback always applies).
  - Advance: while entries are queued, `tick - deadline >= 0` and +0x14 is
    0: head = (head + 1) mod queuelen, queued -= 1, start the new head.
  - The timer DPC runs the advance for every slot that is playing back.
    An entry with time 0 and count 0 therefore drains within microseconds;
    any other entry advances only from a poll after its deadline.
  - Poll (monitor control 0x7a, `{user, state out, status out}`): user >= 4
    or no state: result 0, nothing written. Not connected: status
    0xc000009d. Connected: status 0; state = {u32 +0x10, 12-byte gamepad}.
    Outside playback the gamepad is entry 0 (+0x30). During playback: run
    the advance, report +0x10, then the head packet (zeros when nothing is
    queued), decrement +0x14 when nonzero, and run the advance again when
    it was 0 or 1. Result 1.
  - Control 0x7b (`{user, -, status out}`): status 0 when connected, else
    0x48f. Control 0x7c (`{user, caps out, status out}`): when connected,
    status 0 and caps = {u8 1, u8 1, u16 0xe, u16 0xffff, u8 1, u8 1,
    u16 1 x4, u16 0x100, u16 0x100}; else 0x48f. Both return 1 when the slot
    has a state, else 0. Control 0x21 first calls
    XAutomationpBindController for every installed slot (0x91f24a90).
  - `clearqueue` keeps the playback flag, so polls then return a zero
    gamepad and `queryqueue` keeps reporting t_remain_count = +0x14.
- Kernel data export 89 holds the address of XBDM's debug monitor data
  block (0x91fade60, stored by module init 0x91f32628); its word +0x18 is
  the monitor control routine 0x91f3b4d0 (set in 0x91f3bc38). The
  "notifications" 0x78 and 0x7d are calls of that routine; neither code has
  a case, so the routine returns 0 and forwards (code, data, 0) to the
  `OnTellDebugger` export of a loaded debugger extension (0x91f2e2e8; the
  extension is loaded by 0x91f2e0e0, which also calls its `OnLoad`). The
  0x78 payload is 14 bytes: u8 user, one uninitialized pad byte, then the
  gamepad in console byte order.
- Status: spec complete.

## autoprof
- Handler: 0x91f4f4b0. Access: 0x4. Extra: 0x0.
- Syntax: `autoprof [xuid=0q<hex>]`.
- Behavior:
  - Both paths first require hardware-info flags (ordinal 342, dword +0) bit
    0x10; otherwise 0x82da0007, `407- unknown command`.
  - `xuid` absent or malformed: XConfig get category 3 setting 8, 8 bytes.
    Failure: NTSTATUS OR 0x10000000, reply `400- `. Success:
    `200- xuid==0q%016I64x` (note the doubled `=`; 16 lowercase hex digits).
  - `xuid` present: XConfig set category 3 setting 8 to the 8-byte value.
    Failure: NTSTATUS OR 0x10000000 (`400- `). Success: `200- OK`.
- Backend requirement: read and write the automatic sign-in profile XUID in
  console configuration.
- Both paths are exports 175 and 176 (0x91f24820, 0x91f248b0); the flag
  check is inside them.
- Hardware-info flag 0x10 marks development hardware. K16547 0x80168de8
  (K15574 OmniUsbDetectTopologyProblems 0x80165ed8) tests it before it
  accepts an internal wireless network adapter: with the bit set the
  adapter is allowed (trace text `[omni]: Allowing internal adapter
  (DEVKIT).`, K16547 0x80060244); with it clear the adapter is refused
  with 0xc0051012 (`[omni]: Ignoring internal adapter`). The devkit runs
  with hardware flags 0x400102b7, which has the bit set.
- Status: spec complete.

## autoshutoff
- Handler: 0x91f4f540. Access: 0x4. Extra: 0x2 (absent on test kits).
- Syntax: `autoshutoff timeout=<dword>` (hours).
- Behavior:
  - `timeout` absent: return 0x82da0000, reply `400- `.
  - Value not in {0, 1, 6}: 0x82da0017, `423- bad parameter`.
  - Write 16-bit value (timeout * 60) OR 0x8000 to XConfig category 7
    setting 2. Failure: `400- `. Success: call
    XamSetInactivityTimeFromConfig(1), reply `200- OK`.
  - Always DbgPrint `[xbdm] AutoShutoff, timeout=%u hr:0x%08X\n`.
- Backend requirement: set the console inactivity auto-shutoff interval.
- Status: spec complete.

## avatar
- Handler: 0x91f4fda8. Access: 0x4. Extra: 0x0.
- Syntax: one of `loadassetdelay=<dword>`, `querymarketplacedelay=<dword>`,
  `changemetadata=<dword>`, `simulateerrortype=<dword>
  simulateerrorvalue=<dword>` (tested in this order).
- Behavior:
  - Resolve XAM ordinal 0x5f2 into G with XexGetProcedureAddress on the
    cached XAM handle (no entry-point check, resolved on every call).
    Resolution failure: `200- OK` with no action, before any parameter is
    examined.
  - G(index, &fn) returns an HRESULT and a function pointer. G failure:
    reply with that HRESULT (text empty). fn null: 0x82da000e,
    `414- access denied`. fn failure: reply with its HRESULT.
  - `loadassetdelay`: index 0, fn(max(value, 0)) (signed clamp).
  - `querymarketplacedelay`: index 8, fn(max(value, 0)).
  - `changemetadata`: index 7, fn(value).
  - `simulateerrortype` and `simulateerrorvalue` both present: type >= 1
    gives 0x80004005, `400- `. Else index 5, fn(type, value).
  - No recognized parameter (or only one of the simulate pair): `200- OK`.
  - Success: `200- OK`.
- Backend requirement: avatar subsystem test hooks (asset-load delay,
  marketplace-query delay, metadata change, error simulation).
- Status: spec complete for XBDM. What each hook does is implemented
  inside XAM; XBDM only passes the values, so nothing further is
  reachable from this image.

## bkgdmodetest
- Handler: 0x91f4de20. Access: 0x4. Extra: 0x0.
- Syntax: `bkgdmodetest enable` | `bkgdmodetest disable` (flags; `enable`
  tested first).
- Behavior:
  - Neither flag: text `missing arguments`, 0x80004005,
    `400- missing arguments`.
  - XConfig get category 3 setting 0xd (4 bytes). Failure: map NTSTATUS
    with default 0x8000ffff (usually `400- unexpected error`).
  - New value = (old AND NOT 0x2) OR (0x2 if enable). XConfig set; result
    mapped the same way. Success `200- OK`.
- Backend requirement: set or clear bit 0x2 of console configuration
  category 3 setting 0xd.
- Status: spec complete. The consumer of bit 0x2 is outside this image
  (XBDM never reads it); the command name suggests a background mode test
  switch.

## bootanim
- Handler: 0x91f4d9b0. Access: 0x4. Extra: 0x0.
- Syntax: `bootanim [enabled=<string>]` (value buffer 10 bytes, so at most 9
  characters are compared).
- Behavior:
  - D = 1 if `enabled` equals `off` or `false` (case-insensitive), else
    D = 0 (including when absent).
  - Update bit 0x4 of XConfig category 3 setting 0xd: set when D = 1, clear
    when D = 0. Uses kernel ordinal 0x2bc (700) as
    fn(3, 0xd, and-mask NOT 0x4, or-mask) when available (cached in
    0x91f9ff94); if that returns 0xc0000138, fall back to XConfig get, modify,
    set.
  - Always `200- OK` (the update result is discarded).
- Backend requirement: enable or disable the boot animation in console
  configuration.
- Status: spec complete.

## boxid
- Handler: 0x91f4b948. Access: 0x0. Extra: 0x0.
- Syntax: `boxid`.
- Behavior:
  - Lock-mode box id not set (0x91fab9ac = 0): 0x82da0014,
    `420- box is not locked`.
  - Else `200- boxid=0q%08x%08x` (high dword 0x91fab9a0, low dword
    0x91fab9a4). The same value is persisted as the settings line
    `lockmode boxid=0q%08x%08x%s`.
- Cross-check: client test `kv.rs` parses `boxid=0q...` as a qword.
  Consistent.
- Backend requirement: persistent lock-mode box id.
- Status: spec complete.

## break
- Handler: 0x91f48a38. Access: 0x4. Extra: 0x2 (absent on test kits).
- Syntax, tested in order:
  1. `break now`
  2. `break start`
  3. `break clearall`
  4. `break addr=<dword> [clear]`
  5. `break (read|write|readwrite|execute)=<dword> size=<dword> [clear]`
     (`size` not required with `clear`).
- Behavior:
  - `now`: sleep 250 ms (KeDelayExecutionThread), execute a debug trap
    (trap code 0x16, 0x91f48a6c), then `200- OK` without testing the other
    keys (0x91f48a74). The command thread's record is not debuggable
    (0x91f50cf0 clears 0x2000), so the debug routine cannot stop it: the
    trap ends unresolved (crash dump unless disabled or the kernel debugger
    flag is set, then the `kd lite` chain, else r3 = 0 and Iar + 4).
  - `start`: if the execution state (0x91fae664) is 3 (`pending`) or 5
    (`pending_title`), set bit 0x2 in 0x91fade6c (break at title entry) and
    reply `200- OK`. Else text `execution not pending`, 0x80004005,
    `400- execution not pending`. State names (table 0x91f97608): 0 stopped,
    1 started, 2 rebooting, 3 pending, 4 reboot_title, 5 pending_title.
  - `clearall`: remove every software breakpoint and the data breakpoint,
    reprogram all processors (KeIpiGenericCall). `200- OK`.
  - `addr` present: without `clear`, set an execution breakpoint
    (0x91f26fc8): address not 4-byte aligned, or no block obtainable from
    pool memory, gives 0x80004005 (`400- `); an existing breakpoint is
    re-armed; up to 0x80 entries per block, a full block splits. With
    `clear`, remove it (0x91f27178); not found gives `400- `. Success
    `200- OK`.
  - `addr` absent: the text `missing addr` is formatted, then the data
    keywords are tested: `read` -> type 5, `write` -> 1, `readwrite` -> 2,
    `execute` -> 3. None present: reply `400- missing addr`.
  - Data breakpoint: without `clear`, `size` is required (missing:
    `400- missing size`). The text is cleared, then (0x91f27370):
    - Type nonzero and (addr AND 7) + size > 8: 0x80070057,
      `400- bad parameter`.
    - `clear` (type passed as 0): if addr equals the current data breakpoint,
      remove it; otherwise no change. `200- OK`.
    - A different data breakpoint already active: 0x8007000e,
      `400- out of memory`. The identical one (same address, size and
      type): the processors are reprogrammed with register value 0 (the
      code passes 0 instead of the stored value), the record is kept,
      `200- OK`; the stored value is reprogrammed after the next debug
      exception (0x91f27350).
    - Else program the single data address breakpoint on all processors
      with value (addr AND NOT 3) OR 0x4 OR access bits (write 0x2,
      readwrite 0x3, read 0x1). Type 3 (`execute`) asserts and returns
      0x80070057 (`400- bad parameter`).
- Cross-check: client `DataBreakKind::Execute` sends `EXECUTE=`; the stock
  handler rejects it with `400- bad parameter` (and triggers an RtlAssert).
  Other client forms (`break ADDR= [CLEAR]`, `break start`, `break
  clearall`, `READ/WRITE/READWRITE= SIZE=`) match.
- Backend requirement: software execution breakpoints, one hardware data
  breakpoint (read/write/readwrite, at most 8 bytes within one doubleword),
  break-on-title-entry, immediate debug break.
- Status: spec complete.

## builtinmu
- Handler: 0x91f4dd38. Access: 0x4. Extra: 0x0.
- Syntax: `builtinmu enable` | `builtinmu disable` (`enable` tested first).
- Behavior:
  - Neither flag: `400- missing arguments` (0x80004005).
  - XConfig get category 2 setting 6 (4 bytes); new value = (old AND NOT
    0x4) OR (0x4 if disable). XConfig set. Errors mapped through the NTSTATUS
    map with default 0x8000ffff. Success `200- OK`.
- Backend requirement: enable or disable the built-in memory unit (bit 0x4
  of console configuration category 2 setting 6 set = disabled).
- Status: spec complete.

## bye
- Handler: 0x91f43450. Access: 0x0. Extra: 0x1 (allowed on non-server
  threads).
- Syntax: `bye`.
- Behavior:
  - Context null: 0x80070057, `400- bad parameter`.
  - Send `200- bye` CRLF directly on the connection socket, close the
    connection (0x91f41460), return 0 (no further reply).
- Cross-check: every capture ends with `C> bye` / `S> 200- bye`. Consistent.
- Backend requirement: none beyond the connection.
- Status: spec complete.

## capctrl
- Handler: 0x91f49f68. Access: 0x4. Extra: 0x0.
- Syntax, tested in order: `start name=<path> [buffersize=<dword>]`,
  `fastcapenabled`, `callcapenabled`, `stop`, `flags=<dword>`,
  `profilingstatus`, `abort`.
- Reply: the handler always formats `HRESULT 0x%08x` with the result R into
  the text buffer (truncated to the buffer size), so the reply is
  `NNN- HRESULT 0x%08x` with NNN derived from R. No subcommand: R =
  0x82da0000 (`400- HRESULT 0x82da0000`).
- Subcommands:
  - `start`: `name` string (buffer 0x141) required; missing gives R =
    0x80070057 (`400- HRESULT 0x80070057`; the `missing name` text is
    overwritten). `buffersize` optional, default 0. Then (0x91f29d08):
    - Create/open the file (path helper 0x91f2eb68, access 0x40100000,
      attributes 0x80, share 1, disposition 5, options 0x20); failure R =
      0x82da000d. Close it, delete it (NtDeleteFile), record the start time
      (KeQuerySystemTime into 0x91fae7f8).
    - Clear 0x91fae7e8. Fast-cap module present = any loaded module whose
      XEX header has field 0x18200; call-cap module present = field 0x18102.
      Neither: R = 0x82da0023.
    - buffersize bit 31 set: requires title control words 0x91fade44 and
      0x91fade48 (else R = 0x82da001d); ORs (buffersize >> 20) AND 0xff and
      0x100 into the control word, polls every 60 ms for up to 15000 ms until
      it reads 0; R = dword at 0x91fade48, or 0x82da001d on timeout.
    - Else if only call-cap is present: ExDebugMonitorService(2, 1, 0, 0);
      failure 0xc0000040 gives R = 0x82da0024, other failure NTSTATUS OR
      0x10000000.
    - Then R = capture start (0x91f29210, name, buffersize AND 0x7fffffff,
      exclusive 1).
  - `fastcapenabled`: R = 0x02da0007 (`207- HRESULT 0x02da0007`) when a
    module of the first loader list has XEX header field 0x18200, else
    0x82da001b (export 84; 0x91f28ae0 walks the list under the loader
    lock).
  - `callcapenabled`: R = 0x02da0008 when field 0x18102 is present, else
    0x82da0021.
  - `stop` (export 74, 0x91f29dd8): R = stop recording (0x91f29830). If
    fast-cap is absent and call-cap present, ExDebugMonitorService(2, 0,
    0, 0). If flags (0x91f96078) bit 0x10000 is set: finish the counters
    (0x91f27db8); when R is not negative, R = that result if 0x91f96084 is
    nonzero, else 0x82da002c; release the counter unit (0x91f914c0(0x63))
    and set 0x91f96084 = 1. Flags reset to 0x20000; the previous flags go
    to 0x91fae800 (bit 31 set when R = 0x82da0026). Negative R other than
    0x82da0026 is returned without writing. Then the interlock 0x91f9e49c
    (held: 0x800700aa), write the file (0x91f28540), E =
    RtlNtStatusToDosError(status); unless R = 0x82da0026, R = E > 0 ?
    0x80070000 | (E AND 0xffff) : E. Final: negative R, else 0x02da0000.
  - `flags=<dword>` (export 90): 0x91f96078 = value AND 0x7fffffff; R =
    0x02da0000. A malformed value counts as absent.
  - `profilingstatus` (export 146, 0x91f28940): 0x82da0027 if 0x91fae7e8 =
    1; 0x82da0018 without buffers (0x91fae4a0 = 0) or when the lowest
    recording processor stopped (block +8 nonzero); 0x82da0026 when an
    enabled processor still recording has run out of buffer (block flag
    bit 31); else 0x02da0000.
  - `abort` (export 162, 0x91f29f60): as `stop` up to the flags reset,
    without the counter result and without writing; R = 0x02da0000 when
    the stop result is 0x82da0026 or not negative, else the stop result
    (for example 0x82da0018 without a capture).
- Flag word 0x91f96078: bits 0-5 recording processors; 0x10000 counter
  mode (each record ends with a counter value); bits 6-10 counter
  selector: 0-0x10 processor counter setup (table 0x91f96088, 0xa0 bytes
  each, bytes +0x98..+0x9d the counter number per processor), 0x11/0x12
  memory controller counter 0x7fd2010c with events 0xa/0xc, 0x13 the sum
  of 0x7fd2010c and 0x7fd20118 with events 0x19/0x1b, above 0x13 stock
  prints `Invalid counter ID %d` and traps (0x91f27ce8); 0x20000 (idle
  value) adds the starting processor to the mask, which then stays.
- Start (0x91f29210): interlock 0x91f9e49c (held: 0x800700aa); update the
  flags; a running capture (buffers and lowest recording processor block
  +8 = 0) gives 0x82da0019 when exclusive, else continues (result
  0x02da0006, the thread switch routine is not reinstalled). Copy the name
  (0x104 bytes) to 0x91fae820. Buffer size: nonzero `buffersize` rounded
  up to 4 KiB and capped at 0x10000000 (a value that wraps to 0 counts as
  0); 0 keeps the size of existing buffers or probes MmAllocatePhysicalMemoryEx
  by bisection for the largest whole MiB below 256 and takes 95 percent
  rounded up to 4 KiB (none: 0x82da001c). Counter mode acquires the
  counter unit (0x91f91428(0x63); refused: 0x82da002c). Existing buffers:
  every processor block is disabled (IPI 0x91f28048), the thread switch
  routine restored, and the buffers freed when the size changed. Chunk
  size: the buffer for one processor, else buffer/32 capped at 0x40000.
  Allocation: buffer (type 1, protect 0x404, 4 KiB aligned) and the chunk
  list (8 bytes per chunk per processor); failure 0x82da001c leaves
  whatever was allocated. With interrupts off: a title terminate since the
  start gives 0x82da0027 with the interlock still held; else each
  recording processor gets a chunk list slice and a first chunk. IPI
  0x91f27eb8 writes the start record on each recording processor; the
  thread switch routine at debug monitor data +0x1c is replaced by
  0x91f290d0 (previous kept at 0x91fae7ec).
- Stop recording (0x91f29830): interlock (0x800700aa); no buffers or the
  lowest recording processor already stopped: 0x82da0018; more than
  0x20000000 time base ticks since start: 0x82da0029 and recording goes on.
  Restore the thread switch routine; result 0x82da0026 when an enabled
  processor ran out of buffer, else 0x02da0000; IPI 0x91f29160 writes the
  stop record and closes each processor's last chunk.
- Records (per processor, 32-bit words; first word = kind << 29 | time
  base AND 0x1fffffff; one more counter word in counter mode): kind 0
  (export 65 `(a, b)`): a, b; kind 1 (export 66 `(a)`): a; kind 4
  (export 70) and 5 (export 71): the caller's return address; kind 7:
  code and value: 1 start and 5 thread switch (thread id at +0x14c of the
  current/incoming thread), 2 stop. The hooks write into the current
  processor's block with interrupts off; at the chunk limit (chunk size
  minus 0x21 words) a new chunk is taken (0x91f27e20: granted only while
  four chunks still fit; with the PIX discard flag 0x91fa2a50 the buffer
  starts over at its base and the processor's chunk list restarts), and
  an exhausted buffer stops the processor (flag bit 31).
- Capture file (0x91f28540, name translated at write time; open failure
  returns the status and keeps the buffers): the 0xc000-byte module
  snapshot of export 131 with the byte count of each processor's records
  at +0xa91c (u32 per processor), then each recording processor's chunks
  in order; end of file and allocation size set to the total. Invalid
  chunk bounds print `DmCapWrite: Invalid bufstart and bufend...` and
  fail with 0xc0000001; a chunk start off a page boundary calls RtlAssert
  (dmcap.c line 0x7ec). The buffers are then freed.
- Title terminate (0x91f28a10): 0x91fae7e8 = 1, counter mode finished as
  in `stop`, flags reset, every block disabled, and 0x91fae49c..0x91fae4bb
  zeroed (the buffers are forgotten, not freed).
- Title entries: debug monitor data +0x20 block +0x0c = export 73
  (0x91f29c00: start without the file step when recording, otherwise as
  `capctrl start`; exclusive 0) and +0x10 = export 74.
- Backend requirement: title profiler capture control (start to a file,
  stop, abort, query) for titles built with fast-cap or call-cap
  instrumentation.
- Status: spec complete.

## civfail
- Handler: 0x91f2a380. Access: 0x4. Extra: 0x0.
- Syntax: `civfail [reboot=<dword>]` (missing writes `missing reboot` but is
  treated as 0; the text is overwritten). As with every dword getter
  (0x91f418d8), a present but malformed value (`reboot=2z`) still stores
  its parsed prefix, so it counts.
- Behavior:
  - Creates a system thread `ExCreateThread(&h, 0, &id, 0, 0x91f2a370,
    reboot ? &reboot_var : NULL, 0x20)`. The thread (0x91f77a18) resolves
    xam.xex (0x91f78c10) and XAM ordinal 0x9c0 (0x91f729d8), calls it with
    0xff, then if its argument is nonzero calls HalReturnToFirmware(1). If
    xam.xex is not loaded the thread returns without rebooting; if only the
    ordinal is absent it still reboots.
  - Thread creation failure or null handle: `200- CreateThread failed 0x%x`
    with GetLastError (0x91f72ba0). ExCreateThread does not set the last
    error, so the value is whatever the server thread last stored. Success:
    `200- Thread created: 0x%p` (thread handle; the handle is not closed).
    `%p` comes from the kernel `_snprintf` (ordinal 0x13a); 8 upper-case
    hex digits [INFERENCE].
- Last error (shared by all CIV commands): SetLastError 0x91f72b58 stores
  RtlNtStatusToDosError(status) at KTHREAD+0x160 (PCR+0x100 = current
  thread) unless PCR+0x150 (DPC active) is nonzero; GetLastError reads it
  back (0 during a DPC). Module and export resolution failures set it.
  0x91f729d8 treats an export whose address equals the module entry point
  (handle+0x18) as absent with status 0xc0000263.
- XAM 0x9c0 is `XamShowBadDiscErrorUI` (xam.xex 0x81787750): it ignores
  its argument and shows the bad disc message box for any user, returning
  when the box is dismissed, so the reboot follows the dismissal. With
  XAM's flag 0x8e03860a bit 0x4 set it returns 5 without a box. Details:
  `parity/services.md`.
- Backend requirement: show the bad disc message box, then optionally
  reboot hard.
- Status: spec complete.

## civinject
- Handler: 0x91f2a040. Access: 0x4. Extra: 0x4 (runs on its own thread).
- Syntax: `civinject readerrors=<dword> hasherrors=<dword>` (both default to
  0).
- Behavior:
  - A missing or malformed parameter formats `missing readerrors` /
    `missing hasherrors` (the later one wins), counts as 0, and processing
    continues; the reply is then `200- missing <name>`.
  - Calls XAM ordinal 0x9bf(hasherrors, readerrors) (0x91f77a98) when
    resolvable; the result is ignored.
  - Reply `200- OK` when both are present.
- XAM 0x9bf is `XamMediaVerificationInject` (0x8175ff68): two zero counts
  open a verification session on processor 5 (as `civstart threadid=5`);
  otherwise each nonzero count is stored only when no error of that kind
  is pending. The next startup consumes one of each kind and fails; each
  block read and hash check of a pass consumes one. Details:
  `parity/services.md`.
- Backend requirement: inject read and hash errors into content
  verification.
- Status: spec complete.

## civsetbits
- Handler: 0x91f2a1e8. Access: 0x4. Extra: 0x2 (absent on test kits).
- Syntax: `civsetbits on=<dword>`: `on` is a detection bit index. When
  missing, the value is uninitialized stack data (stock defect); the
  `missing on` text is overwritten. A malformed value stores its prefix.
- Behavior:
  - Resolve kernel ordinals with XexGetProcedureAddress on the kernel
    handle (0x91faded0): 0x295 XeKeysSecuritySetDetected, 0x296
    XeKeysSecurityGetDetected, 0x292 XeKeysSecurityInitialize, 0x294
    XeKeysSecuritySaveSettings (export names from the kernel image). On the
    first failure, DbgPrint `Cannot load ordinal %d (%hs): 0x%x\n` (names
    `SET_DETECTED`, `GET_DETECTED`, `INITIALIZE`, `SAVE_SETTINGS`) and reply
    with result = the failure status, old = 0xbaadf00d, new = 0xdeadbeef.
  - Else: old = GetDetected(); Initialize(); SaveSettings(); if `on` is
    nonzero, result = SetDetected(on) (else result stays the last
    resolution status, 0); new = GetDetected().
  - Kernel semantics (console kernel image, hypervisor syscalls 0x52, 0x55,
    0x56): the detection state is a 64-bit mask. GetDetected returns it, or
    all ones before the security state is initialized. Initialize zeroes the
    0x400-byte security state (mask = 0) and marks it initialized.
    SetDetected(bit): bit >= 0x40 returns 0xc000000d; a bit already set
    returns 0; else the hypervisor sets the bit (failure returns its
    status) and the state is saved to flash; a failed save bugchecks
    (0x12d51); the save status is returned. Every call therefore clears all
    previously set bits before setting the new one.
  - Reply `200- Result 0x%x; old mask 0x%x, new mask 0x%x`; the masks are
    the low 32 bits.
- Backend requirement: read, reinitialize, and set the kernel's security
  detection mask.
- Status: spec complete.

## civstart
- Handler: 0x91f2a448. Access: 0x4. Extra: 0x4.
- Syntax: `civstart threadid=<dword>` (default 0; missing text is
  overwritten; a malformed value stores its prefix).
- Behavior: n = min(threadid, 5) (unsigned). Calls XAM ordinal 0x9bb(n)
  (0x91f77818). Value X = its return; if xam.xex is absent, the last-error
  value; if the ordinal is absent, the last-error value or 0 when it is
  0x7f. Reply `200- XSecurityCreateProcess 0x%x` (X).
- XAM 0x9bb is `XamMediaVerificationCreate` (0x81a16110): returns 5 when a
  session is open (also after a failed startup until `civstop`), else
  starts the verification worker on processor n and waits for its startup:
  0 when it is ready, 0x571 when the startup failed (an injected error, or
  the CD-ROM device not opening). Without a disc the worker reads in a
  no-media mode and starts. Details: `parity/services.md`.
- Backend requirement: start content verification on a processor.
- Status: spec complete.

## civstatus
- Handler: 0x91f2a0c0. Access: 0x4. Extra: 0x0.
- Syntax: `civstatus`.
- Behavior:
  - Calls XAM ordinal 0x9be (0x91f77980) with a 0x18-byte record whose
    dword +0 = 0x18. xam.xex absent: returns the last error. Ordinal
    absent: last error 0x7f zeroes the record with +0x14 = 1 and counts as
    success; any other last error is returned.
  - Nonzero return R: `200- XSecurityFailedBlocks returned 0x%x`.
  - Else `200- Blocks Checked %d, Failed Reads %d, Failed Hashes %d, Total Blocks %d, %hs.`
    with +0xc, +4, +8, +0x10, and `Completed` if +0x14 is nonzero else
    `In Progress`.
- XAM 0x9be is `XamMediaVerificationFailedBlocks` (0x81a15a48): it copies
  the session's record and returns 0x570 after a startup that failed an
  injected check (until `civstop`); a successful startup clears the
  checked count, total and completion flag (the total reads 0 until a
  pass checks a block); every checked block updates the record, and the
  checked count accumulates over the passes of a session. With no disc
  the total is 264354 and the verification never completes (devkit with
  an empty tray: confirmed).
- Backend requirement: report content verification progress counters.
- Status: spec complete.

## civstop
- Handler: 0x91f2a4c0. Access: 0x4. Extra: 0x4.
- Syntax: `civstop`.
- Behavior: calls XAM ordinal 0x9bc() (0x91f778a0) when resolvable (result
  ignored). Reply `200- XSecurityCloseProcess`.
- XAM 0x9bc is `XamMediaVerificationClose` (0x81a15998): without a session
  it does nothing; else it stops the worker and resets the session
  (checked count, completion flag, failure flag); the record's failure
  counters and total stay.
- Backend requirement: stop content verification.
- Status: spec complete.

## civverify
- Handler: 0x91f2a170. Access: 0x4. Extra: 0x4.
- Syntax: `civverify milliseconds=<dword>`. When missing, the value is
  uninitialized stack data (stock defect); the `missing milliseconds` text is
  overwritten. A malformed value stores its prefix.
- Behavior: m = milliseconds; if m <= 0 (signed) and m != -1, m = 0x100.
  Calls XAM ordinal 0x9bd(m, 0, 0) (0x91f778f0). Value X = its return;
  xam.xex absent: last error; ordinal absent: last error, or 0 when it is
  0x7f. Reply `200- XSecurityVerify 0x%x` (X).
- XAM 0x9bd is `XamMediaVerificationVerify` (0x81a15fd0): 0x21 unless a
  session is ready (none, a failed startup, or a pass still running);
  else it hands the budget to the worker and returns 0 at once. The
  worker checks blocks until m milliseconds have passed since the pass
  started (at least one block). Without a disc each block takes 100 ms,
  200 ms when it also reads a new hash index block (the first block and
  every 2048th). m = -1 runs until `civstop`, waiting 200 ms after each
  block (300 ms per block); with detection bit 12 set at `civstart` every
  pass runs until `civstop`, waiting 200 ms whenever more than 300 ms
  have passed since the last wait. `civstop` ends a pass after its
  current block.
  Details: `parity/services.md`.
- Backend requirement: run content verification for a time budget.
- Status: spec complete.
