# XBDM command specifications, group 5

Source: stock XBDM 2.0.21256.0, image base 0x91f00000. All addresses are image addresses.

## Common conventions used in this group

Dispatch (0x91f505f0, table lookup 0x91f42278):

- Command words are matched case-insensitively against the table at 0x91f980a0 (binary search). No match: `407- unknown command`.
- Extra bit 0x2: if global 0x91f9f680 is nonzero, the lookup fails with `407- unknown command`. 0x91f9f680 nonzero is the console type `testkit` (see 0x91f4cf68, which reports `devkit` / `testkit` / `reviewerkit`). Extra bit 0x2 therefore means "devkit only".
- Access: when the access field is nonzero it is ANDed with the connection privilege mask; zero result gives `414- access denied`.
- Handler response text buffer size is 0x1fb. Any handler size check against a smaller value is unreachable from the network.
- Status line (0x91f42028): HRESULT with facility 0x2da: status = 200 + low word (success) or 400 + low word (failure); low word > 0xff gives 400. Other success HRESULTs give 200; other failure HRESULTs give 400. Text is the handler text if the first byte is nonzero, else the message from 0x91f41c98.
- A handler that returns exactly 0 causes no status line at all.
- 0x91f41c98 messages: 0x02da0000 `OK`, 0x02da0002 `multiline response follows`, 0x02da0003 `binary response follows`, 0x02da0004 `send binary data`, 0x82da0002 `file not found`, 0x82da0003 `no such module`, 0x82da0004 `memory not mapped`, 0x82da0005 `no such thread`, 0x82da0007 `unknown command`, 0x82da0008 `not stopped`, 0x82da0009 `file must be copied`, 0x82da000a `file already exists`, 0x82da000b `directory not empty`, 0x82da000c `filename is invalid`, 0x82da000d `file cannot be created`, 0x82da000e `access denied`, 0x82da000f `no room on device`, 0x82da0010 `not debuggable`, 0x82da0011 `type invalid`, 0x82da0012 `data not available`, 0x82da0014 `box is not locked`, 0x82da0015 `key exchange required`, 0x82da0016 `dedicated connection required`, 0x82da0017 `bad parameter`, 0x82da001c `out of memory`, 0x82da001e `path not found`, 0x82da002e `line too long`, 0x8000ffff `unexpected error`, 0x8007000e `out of memory`, 0x80070057 `bad parameter`. Every other value maps to the empty string, giving lines such as `400- ` or `425- ` with no text.
- NTSTATUS to HRESULT (0x91f41f18(status, default)): 0 -> 0x02da0000; 0xc0000008 -> 0x80070057; 0xc0000022 -> 0x82da000e; 0xc0000033 and 0xc0000039 -> 0x82da000c; 0xc0000034 -> 0x82da0002; 0xc0000035 -> 0x82da000a; 0xc000003a -> 0x82da001e if default is 0x82da000d, else 0x82da0002; 0xc000007f -> 0x82da000f; 0xc000009a -> 0x8007000e; 0xc00000ba -> 0x82da0002; 0xc0000101 -> 0x82da000b; other -> default.
- Multiline (202) continuation: the handler stores a callback in ctx[0]. The server sets ctx[5] = 0xffffffff after sending the status line and calls the callback once per line. A success return sends the text at ctx[2] as a line. 0x82da0104 ends the body and sends `.`. Any other failure closes the connection (0x91f41460).
- 0x91f41b20 (required dword) writes `missing <name>` into the response text when the parameter is absent. Some handlers in this group ignore its return value, so that text can remain in a success response.
- 0x91f75370 is an ASCII case-insensitive full-string compare. 0x91f75508 is an ASCII case-insensitive compare of n characters.
- XConfig bit helper 0x91f4d350(setting, mask, set): calls xboxkrnl ordinal 700 (resolved at run time through 0x91f729d8) with (category 3, setting, ~mask, set ? mask : 0). If that ordinal is absent (STATUS 0xc0000138), it reads XConfig category 3 / setting as a dword through ExGetXConfigSetting, ORs in the mask (set) or clears it, and writes it back through ExSetXConfigSetting. It returns the last status.
- WriteIniFile (0x91f31e48): persists the XBDM configuration to xbdm.ini, unless the boot is from CD (ordinal 342 word +0xe bit 0x400), loading has not finished, or the file was wiped. It is relevant to lockmode, memtrack, and notify.
- Path translation 0x91f2e888(in, out, size) converts an XBDM path to an object path and returns false on failure. Its rules are documented with the file commands.

## kd
- Handler: 0x91f435f8. Access: 0x4. Extra: 0x2 (devkit only).
- Syntax: one flag, tested in this order: `enable`, `disable`, `except`, `exceptif`. Flags are found with 0x91f41638 using the third argument 0, so `name=value` forms also match.
- Behavior:
  - `enable`: global kd flag 0x91f975fc = 1; reply `200- kd enabled`.
  - `disable`: 0x91f975fc = 0; reply `200- kd disabled`.
  - `except`: 0x91f975fc = 1, then call 0x91f2de68, which resumes all stopped threads and signals the debug-event waiter (the same operation as continuing execution). Reply `200- OK`.
  - `exceptif`: if bit 0x80 of the dword referenced by xboxkrnl ordinal 342 is set, perform `except`. Otherwise nothing changes. Reply `200- OK` in both cases.
  - No flag: `400- improper command` (E_FAIL with text).
  - At initialization (0x91f3bc38), 0x91f975fc = (ordinal-342 dword & 0x80) >> 7. Reboot paths and debug notification registration also write the flag. While set, debug exceptions are passed to the kernel debugger instead of being handled by XBDM.
- Backend requirement: a boolean that routes debug exceptions to the kernel debugger; the ability to resume all stopped threads; the kernel-debugger-present bit.
- Status: spec complete.

## kdlite
- Handler: 0x91f43db0. Access: 0x4. Extra: 0x0.
- Syntax: flag `enable` or `disable` (`enable` is tested first).
- Behavior:
  1. Bit 0x02000000 of the ordinal-342 dword clear: `400- improper command`.
  2. `enable`: 0x91f43d20(mask 2, set). That routine is ExGetXConfigSetting(category 2, setting 6, 4 bytes), OR 2, then ExSetXConfigSetting(2, 6). On success: global 0x91f97600 = 1 and `200- kd lite enabled`.
  3. `disable`: the same routine clears bit 2. On success: 0x91f97600 = 0 and `200- kd lite disabled`.
  4. XConfig failure, or no flag: `400- improper command`.
  - At initialization, 0x91f9fd8c = 1 when ordinal-342 bit 0x02000000 is set and XConfig(2,6) bit 2 is set.
- Backend requirement: persistent console configuration dword (category 2, index 6) with bit read-modify-write; the kernel capability bit.
- Status: spec complete.

## kdnet
- Handler: 0x91f43858. Access: 0x4. Extra: 0x2.
- Syntax: one subcommand flag, tested in order: `enable`, `disable`, `show`, `set`. Parameters of `set`:
  - `IP=` dotted IPv4 string, at most 31 characters, parsed with 0x91f723d0 (inet_addr semantics; 0xffffffff means invalid).
  - `Port`: the flag must be present, then dword grammar, value <= 0xffff.
  - `Mac=` (key=value form required): string, at most 31 characters, six `-`-separated hex octets; an empty value means default.
- Settings record: 0x80 bytes read from and written to offset 0x80 of `\Device\Flash`. Writes are block read-modify-write through the flash device geometry (IOCTL 0x3c0028). Layout:
  - +0x00 u16 signature 0xca4a.
  - +0x08 u32 0x10.
  - +0x0c u32 0x48.
  - +0x10 u32 Enable.
  - +0x14 four bytes Target IP.
  - +0x18 six bytes Target MAC.
  - +0x1e u16 Host Port.
  - +0x20 four bytes Host IP.
  - +0x24 u32 Encrypted.
  - Other bytes are zero.
  - Load and save results are ORed with 0x10000000.
  - The record is valid (0x91f437e8) when Host IP (+0x20) is nonzero, the MAC is not all zero, and Port is nonzero.
- Behavior:
  1. Kernel build (XboxKrnlVersion u16 at +4) < 10914, or 11000 <= build < 12902: `407- kdnet is not supported on this flash version.<0x1e>`. The text ends in byte 0x1e.
  2. The record is loaded (status L).
  3. `enable`:
     - L failed: `200- kdnet: unable to load current kdnet settings: 0x%08x` (L).
     - Record invalid: `407- kdnet: can't enable kdnet without setting the parameters.`
     - Otherwise +0x10 = 1, save, then `200- kdnet enabled: 0x%08x` (save status). The status is 200 even when the save fails.
  4. `disable`: L failed: the same `unable to load` 200 reply. Otherwise +0x10 = 0, save, then `200- kdnet disabled: 0x%08x`.
  5. `show`: L failed: `200- kdnet: failed to load current settings: 0x%08X`. Otherwise one 200 line, `kdnet settings:<1e><09>Enable=%d<1e><09>Target IP: %d.%d.%d.%d<1e><09>Target MAC: %02X-%02X-%02X-%02X-%02X-%02X<1e><09>Host IP: %d.%d.%d.%d<1e><09>Host Port: %d<1e><09>Encrypted: %d<1e>`, where <1e> and <09> are the bytes 0x1e and 0x09.
  6. `set`: the load status is ignored. Signature, +8, +0xc are written as above and Enable = 1. Fields not supplied keep their flash values.
     - IP given: an invalid address is an error. Otherwise it is stored at +0x20.
     - Port flag: a missing or over-range value is an error. Otherwise stored at +0x1e.
     - Mac given and non-empty: fewer than six parts is an error. Each octet parsed as hex; trailing characters or > 0xff is an error, but parsing continues and stores the low byte.
     - Mac given but empty, or Mac absent and the stored MAC all zero: the MAC is read from XConfig(2, 1) (the console MAC) and its last byte decremented. A read failure sets the error to status | 0x10000000.
     - None of IP, Port, Mac supplied: error 0x82da0017. Otherwise the record is validated; invalid is error 0x82da0017.
     - On error or save failure: `kdnet set failed: error code 0x%08x`. The status is from that HRESULT: 423 for 0x82da0017, 400 for other values.
     - Success: `200- kdnet set succeeded.`
  7. No subcommand: `423- bad parameter`.
  - Target IP (+0x14) and Encrypted (+0x24) are never set by this command.
- Backend requirement: kernel build number; persistent 128-byte kdnet record in raw flash; the console MAC address.
- Status: spec complete.

## keyxchg
- Handler: 0x91f4c0a8. Access: 0x0. Extra: 0x0.
- Syntax: no parameters. After the status line the client sends exactly 0x60 binary bytes.
- Behavior:
  1. No connection context: E_FAIL (`400- `).
  2. Allocate 0xc0 bytes (pool tag 'HDmd'). Failure: `400- out of memory`.
  3. Set ctx[2] = buffer, ctx[3] = 0xc0, ctx[5] = 0x60 (expected byte count), ctx[0] = 0x91f4bf58, ctx[4] = 0. Reply `204- send binary data`.
  4. Receive: bytes are appended at buffer+0x60.
  5. When 0x60 bytes have arrived:
     - x = 0x60 random bytes (0x91f715a8).
     - shared = XeCryptBnDwLeDhModExp(client value at buffer+0x60, x, params 0x91f06090).
     - server public = XeCryptBnDwLeDhModExp(generator, x) written to buffer[0..0x60].
     - Connection field +0x18 (qword at 0x91fab9f8 + n*0x298) = 0, then the 0x60-byte shared value is absorbed with 0x91f402d8.
     - Connection flags (0x91fab9e4 + n*0x298) |= 0x01000000 (key exchanged).
     - Reply `203- binary response follows`.
  6. The server then sends the 0x60-byte server public value as raw binary and frees the buffer.
- DH parameters at 0x91f06090: dword 0x0c (12 qwords), dword pad; modulus 0x60 bytes at 0x91f06098; generator 0x60 bytes at 0x91f060f8, all zero except byte 0x91f06150 = 0x02. Values on the wire use the same byte layout as these tables: a 768-bit number in little-endian byte order. XeCryptBnDwLeDhModExp (kernel ordinal 0x15e) converts each 8-byte group with XeCryptBnQw_SwapDwQwLeBe, which byte-reverses each qword in place, into the kernel's least-significant-qword-first form (checked in the K15574 image: modexp normalization tests the top bit of qword n-1; DhInvalBase compares qword 0 last). The generator is therefore 2^705 and the modulus has the qword sequence FFFFFFFFFFFFFFFF, C90FDAA22168C234, ..., F44C42E9A63A3620, FFFFFFFFFFFFFFFF from least to most significant. The result is reduced mod the modulus (final XeCryptBnQwNeMod); a zero exponent yields 1. The base is not validated (no DhInvalBase call).
- Session key absorption (0x91f402d8): the state is two u32 words (S0, S1).
  - For each 8-byte chunk (a final short chunk is zero padded), the chunk is read as a little-endian qword: M0 is bytes 4..7 as a little-endian u32 and M1 is bytes 0..3 as a little-endian u32.
  - E = encrypt(key = S, value = M), then S0 = E0 ^ M0, S1 = E1 ^ M1.
  - encrypt (0x91f401e8) runs 8 rounds, i = 0..7, in 32-bit arithmetic: V1 ^= (K1 ^ V0) + ((~V0) << 6) + (V0 >> 5) + T[i]; then V0 ^= (K0 ^ V1) + ((~V1) >> 5) + (V1 << 6) + T[7-i].
  - T at 0x91f97688 = 283c481d 9ad82aa1 85a5e1f9 1b23963c f70b4975 dfdc02c7 f29176fc 6b04bd38.
- Backend requirement: random source; 768-bit modular exponentiation; per-connection key state and key-exchanged flag.
- Consumers of the key state: `authuser passwd=` and `adminpw passwd=` XOR the sent value with the session key qword (S0 high, S1 low).
- Status: spec complete.

## kinecthsmsg
- Handler: 0x91f4d610. Access: 0x4. Extra: 0x0.
- Syntax: optional flag `off`.
- Behavior: `off` present: set bit 0x20 of XConfig(3, 0xd); otherwise clear it. Uses 0x91f4d350; its result is ignored. Always `200- OK`.
- Backend requirement: persistent console settings dword (category 3, index 0xd) bit write.
- Status: spec complete.

## kiosk
- Handler: 0x91f4d668. Access: 0x4. Extra: 0x2.
- Syntax: `enabled=` string (required, at most 31 characters). `id=` dword (required when enabling).
- Behavior:
  1. `enabled` missing: `423- bad parameter`.
  2. `off` or `false` (case-insensitive): clear bit 0x40 of XConfig(3, 0xd) and id = 0.
  3. `on` or `true`: `id` missing gives `423- bad parameter`. Otherwise set bit 0x40.
  4. Any other value: `423- bad parameter`.
  5. After the bit update, ExSetXConfigSetting(category 0xb, setting 3, id dword, 4).
  6. Bit update or setting write failure: `414- access denied`. Success: `200- OK`.
- Backend requirement: persistent console settings (bit in 3/0xd, dword 0xb/3).
- Status: spec complete.

## linkstate
- Handler: 0x91f35990. Access: 0x4. Extra: 0x0.
- Syntax: flags `restore`, `disconnect`, `setflags` (tested in that order). `setflags` requires dwords `and` and `or`.
- Behavior:
  1. Missing `and` or `or` with `setflags`: `423- bad parameter`.
  2. state = NetDll_XNetGetEthernetLinkStatus(2), always queried.
  3. `restore` means and = 0xffffffff, or = 0. `disconnect` means and = 0, or = 0x00010000.
  4. Set: NetDll_XNetSetOpt(2, 0x1395, {and, or}, 8).
     - Result 0: `200- set, andflags=0x%08x orflags=0x%08x oldstate=0x%08x`.
     - Result 10022 (0x2726): `407- err=%i`. Other nonzero results: `400- err=%i`.
  5. No flag: `200- state=0x%08x`.
  - Also invoked for `linkstate` lines when netsim reloads a file (no response text).
- Backend requirement: read Ethernet link status; force the link state through and/or masks.
- Status: spec complete.

## livesigninrequired
- Handler: 0x91f4daf0. Access: 0x4. Extra: 0x0.
- Syntax: optional `enabled=` string (at most 9 characters).
- Behavior: value `on` (case-insensitive) sets bit 0x08 of XConfig(3, 0xd). Anything else, including absence, clears it. Always `200- OK`.
- Backend requirement: settings bit write as for kinecthsmsg.
- Status: spec complete.

## lockmode
- Handler: 0x91f4b7e8. Access: 0x10. Extra: 0x0.
- Syntax: flag `unlock`; qword `boxid=0q<hex>`; flag `encrypt`.
- State: lock state 0x91fab9ac (0 unlocked, 1 locked, 2 locked with file encryption); box id at 0x91fab9a0 (high dword) and 0x91fab9a4 (low dword).
- Behavior:
  1. `unlock`: state = 0, then 0x91f40c88 deletes every user object from the security user directory (all user records are removed). The result is 200.
  2. Otherwise, if state == 0: `boxid` is required. Missing: text `missing parameters` with E_FAIL (400). Present: the box id is stored and state = 1, result 200.
  3. Otherwise (already locked): state = 1. The box id is not changed, and an existing encrypt state 2 is reset to 1.
  4. `encrypt`: if state != 0, state = 2 and result 200. Otherwise the text is replaced by `box not locked; file encryption not enabled` and the result is unchanged. `lockmode unlock encrypt` therefore replies `200- box not locked; file encryption not enabled`, and a missing boxid with `encrypt` replies `400- box not locked; file encryption not enabled`.
  5. WriteIniFile is always called.
  - ini line when locked: `lockmode boxid=0q%08x%08x%s`, with suffix ` encrypt` when state == 2 (0x91f40ab0). `user` lines follow for each user.
  - Success text is empty, so the reply is `200- OK`.
- Backend requirement: persistent lock state, box id, user list removal.
- Status: spec complete.

## lopctrl
- Handler: 0x91f4a110. Access: 0x4. Extra: 0x0.
- Syntax: subcommand flag `start`, `stop`, or `info`.
  - `start` parameters: `name=` string (at most 0x140 characters, required), dword `interval` (default 0), dword `flags` (default 0).
- Behavior: every reply except a successful `info` is the text `HRESULT 0x%08x` with the result, and the status follows that result.
  - No subcommand: result 0x82da0000, giving `400- HRESULT 0x82da0000`.
  - `start` without name: 0x80070057, giving `400- HRESULT 0x80070057`.
  - `start` is export 149 (0x91f32e18 -> 0x91f32c90 with owner 1):
    1. Running flag 0x91fadd88 already 1: 0x82da0019 (status 425).
    2. First initialization (0x91fadd8c from 0 to 1): engine init 0x91f90768(flags). A result other than 0x02da0000 runs 0x91f90220, clears both flags, and is returned.
    3. Translate the name (0x91f2e888), create its parent directories (0x91f64448: every prefix ending before a `\`, NtCreateFile access 0x100001, attributes 0x80, share 3, FILE_CREATE, options 0x4021), then 0x91f90258(untranslated name, interval). A negative result clears the running flag and is returned.
    4. Success: 0x91fadd80 = 0, owner 0x91fadd84 = 1, result 0x02da0000.
  - `stop` is export 150 (0x91f330c8 -> 0x91f33010 with owner 1): not running 0x82da0018 (424); otherwise the engine stop result (0x02da0000, or 0x82da002d (445) when the counters are no longer owned); both flags are cleared. Every caller (exports 149/150 and the title terminate path 0x91f33090, which passes 0x91fadd84) uses owner 1 while running, so the 0x80070005 owner mismatch path is unreachable.
  - `info` is export 151 (0x91f32e30, outputs only written on success): 0x91fadd80 != 0 (set by title termination, cleared by the next successful start): 0x82da0027 (439); not running: 0x82da0018 (424); otherwise `200- elapsedTime=0x%08x totalSamp=0x%08x overheadInt=0x%08x`: whole seconds since sampling started (time base / KeQueryPerformanceFrequency, truncated), and the interrupt (header +0x104) and busy-interrupt (+0x14c) counts of the highest sampled processor.
  - Title termination (0x91f33090): stop as above, then 0x91fadd80 = 1. 0x91f32ff8 (read by 0x91f5f3b8) reports the running flag.
- Engine (0x91f8eeb0..0x91f90bdf):
  - flags: bits 0..5 sampled processors (0x91faae9c), bits 6..8 writer thread processor (0x91faae98), bits 9..12 buffer MiB (0x91faae8c).
  - Init 0x91f90768: buffers (0x91f8f058; failure `[LOP] CreateSharedBuffers Failed!!!` and 0x82da001c), zeroed 0x200-byte header with +0 = 0x201, +0x14 = processor mask, +0x194 `Microsoft CPU Profiler for Xbox`; MmQueryStatistics into a discarded local; a 0x994-byte random interval generator is seeded but its output is never used (the interval routine is called with randomize 0). Then 0x91f906e0: PMC acquire owner 0x64 (else 0x82da002c), kernel export 671 (set profile routine 0x91f90528), export 669 (enable on the processor mask; false gives 0x82da0017), PMC reset 0x91f91800. Missing `xboxkrnl.exe`: 0x82da0003; missing export: 0x82da0007. 0x91f90220 undoes it: export 670(1), 671(0), PMC release 0x64, free buffers.
  - Buffers 0x91f8f058: 64 KiB blocks per sampled processor: 8, 6, 5, 5, 4, 4 for 1..6 processors; with a MiB request `(MiB << 20) / ((n + 1) << 16)` capped at 18, title memory (NtAllocateVirtualMemory type 0x20003000, protect 4, option 3, then option 1), else option 2. Plus one staging area of the same size for the writer. Messages: `[LOP] Memory allocation failed! Invalid thread number of threads.`, `[LOP] Title Memory allocation failed! %d`, `[LOP] System Memory allocation failed! %d`.
  - Start 0x91f90258: already sampling: `[LOP] Already started`, 0x82da0019; the writer thread (0x91f8fcc0: ExCreateThread stack 0x8000, flags 0x4a2 | (1 << writer processor) << 24) must open the file and write the prologue (`[LOP] Prologue Failed!!!`, 0x82da0000); start time = KeQuerySystemTime (header +0x18) and the time base; 0x91f90138: PMC stop and clear owner 0x64, interval control PRV 0x1c8 bit 0x8000 (high word), PRV 0x1e0/0x1e8 = -interval in the high word, PMC start; failure stops the writer and returns 0x82da002c. Success returns 1.
  - Interrupt 0x91f90528 on each processor: unsampled processors return; the highest sampled processor reloads PRV 0x1e8 with -interval and waits for the reload bit (0x8fff11c8 bit 15); while sampling: header +0x104[p]++; IRQL > 2 or the idle thread without a DPC (PRCB +8 = current thread and PRCB +0x50 = 0): +0x134[p]++; else +0x11c[p]++ and, unless the processor's previous sample is still running (+0x14c[p]++), a sample: leaf-epilogue test (up to 13 instructions from the interrupted address until `blr`, all of ld/lwz/lfd/b/mtlr r12/opcode 31 xo 103), stack walk over the back chain within the thread's stack limits, at most 500 addresses (hitting 500, or a fault, counts +0x58[p] and records nothing).
  - Sample record (big-endian words): +0 0x0cdcdce8, +4 u64 time base, +0xc record size `(frames + 10) * 4`, +0x10 thread id, +0x14 trap frame +0x1a8 (link register), +0x18 word at r1-8, +0x1c r12, +0x20 instruction at the interrupted address, +0x24 processor number | 0x80000000 in a leaf epilogue, +0x28 frames (interrupted address, then the return addresses). Counters: +0x40 samples, +0xa4 bytes, +0x74 largest, +0x8c smallest record, +0xd4 stored, +0xec dropped (no free block).
  - Blocks per processor are an interlocked LIFO of free blocks and one of full blocks; a record that does not fit pads the block with zeros and queues it as full. The writer (0x91f8fa68) wakes every 250 ms, copies the full blocks (oldest first, only those whose first word is nonzero) to the staging area, zeroes them, returns them to the free list, and writes the staging area (a failed or short write counts header +0x08); after stop it also drains the partly filled blocks. At the end it writes the header again at file offset 0xc000 with +0x20 = start time + whole seconds * 10000000, and closes the file.
  - Stop 0x91f90310: sampling off, PMC stop/clear owner 0x64 (0x82da002d when not owned), export 670(1), export 671(0), PMC release, stop the writer, free the buffers.
- File format: 0xc000-byte module snapshot (export 131 with +0xa808 = system time, +0xa810 and +0xa918 = 0); the 0x200-byte header (+0x00 0x201, +0x08 write errors, +0x14 processor mask, +0x18 start FILETIME, +0x20 end FILETIME, +0x40/+0x58/+0x74/+0x8c/+0xa4/+0xbc/+0xd4/+0xec/+0x104/+0x11c/+0x134/+0x14c six-word per-processor arrays as above (+0xbc blocks per processor), +0x70 = 0x28, +0x194 the title); for each snapshot module, a 12-byte record (base, image size, exception directory size) followed by a copy of its exception directory; then 64 KiB sample blocks.
- Status: spec complete.

## magicboot
- Handler: 0x91f49de0. Access: 0x4. Extra: 0x0.
- Syntax: flags `warm` (0x4), `cold` (also 0x4; the image ORs the same bit), `wait` (0x1), `stop` (0x8). String parameters `title=`, `directory=`, `cmdline=`, each at most 255 characters.
- Behavior:
  1. `title` given and path translation fails: `402- file not found`. `directory` given and translation fails: `430- path not found`.
  2. Call the shared reboot routine 0x91f278a8(flags, title, directory, cmdline, connection index):
     1. Title given and not found (0x91f447c8): `402- file not found`.
     2. Save flags to 0x91fa2324. When a title is given, save title, directory and cmdline (0x100 each) at 0x91fa2020, 0x91fa2120, 0x91fa2220.
     3. If 0x91f9f678 == 0, the top nibble of the ordinal-342 dword is >= 4, the console is not a testkit (0x91f9f680), and 0x91f4e648 fails (three attempts of the SMC NVRAM read 0x91f4e378, 0x20 bytes at offset 0), then flags |= 0x4.
     4. The execution state is read under the exec lock (0x91f2d930 takes it, 0x91f2d9b8 releases it). If (flags & 6) == 0: state 4 (reboot_title) returns `200- OK` with no action; else when 0x91fa200c != 0 (the code 0x20 registration carried a version dword) and 0x91f276d8 returns 0, the state becomes reboot_title (0x91f2da88(4, 0, notify)), flags are stored, callback 0x91fa2008(0) runs, a title-process caller ends its thread, and the reply is `200- OK`. 0x91f276d8 walks the title and system threads and returns 1 when a thread stopped at an event other than a single step, a breakpoint of kind 0x14 or 0x17, a title breakpoint of kind 0x16/0x19/0x1a inside 0x82000000..0x8bfeffff or 0x92000000..0x9ffeffff, or an exception the debugger marked continuable.
     5. Otherwise, hard reboot: send `200- OK` on the connection, sleep 200 ms, set 0x91fa2328 = 1 (control codes 0x21 and 0x77 then leave the launch title for the next boot), and record the boot-wait mode (0x91fadec8 = 2 if `stop`, 1 if `wait`, when not already set). Then 0x91f3b208 (write xbdm.ini, `execution rebooting`, close connections) and HalReturnToFirmware(6), or (1) when IRQL >= 2. No further reply is sent.
- Backend requirement: reboot or relaunch the title with path, directory and command line; boot-time stop or wait-for-debugger options; file existence checks.
- Status: spec complete. The launch title is consumed by control code 0x21 (docs/re-notes/dispatcher.md).

## mdetect
- Handler: 0x91f4d570. Access: 0x4. Extra: 0x0.
- Syntax: optional `enabled=` string (at most 9 characters).
- Behavior: value `off` or `false` (case-insensitive) sets bit 0x01 of XConfig(3, 0xd). Otherwise the bit is cleared. A set bit means detection is disabled. Always `200- OK`.
- Backend requirement: settings bit write.
- Status: spec complete.

## memtrack
- Handler: 0x91f23b20. Access: 0x4. Extra: 0x0.
- Syntax: `cmd=` string (at most 31 characters, required; values compared case-insensitively): `enable`, `enableonce`, `disable`, `save`, `querystackdepth`, `querytype`, `queryflags`.
  - `enable` and `enableonce` parameters: dword `stackdepth` (default 0) and dword `flags` (default 0x1ff). Both are read with the required-dword helper; its result is ignored, but a present value always stores its parsed prefix (`stackdepth=4x` stores 4 and sets the text `missing stackdepth`).
  - `save` parameter: `filename=` string (at most 0x13f characters).
  - `querytype` parameter: dword `type` (required).
- Behavior: all failures reply `400- HRESULT 0x%x` (lower-case hex, no padding) except where noted.
  - `cmd` missing, unknown cmd, stackdepth > 0x20, or (flags & 0xff) == 0: 0x80070057.
  - `enable`: 0x91faea54 = stackdepth, 0x91faea58 = (old & ~0x1ff) | flags, WriteIniFile. Reply 200. Text is `OK` unless a parameter was missing, in which case the text is `missing stackdepth` or `missing flags` (the last one written).
  - `enableonce`: 0x91faea50 = stackdepth (never read anywhere), 0x91faea4c = flags (the flags in effect, immediately), 0x91faea58 |= 0x80000000. No WriteIniFile. Reply 200 with the same text rule.
  - `disable`: 0x91faea58 &= ~0x1ff, WriteIniFile. Reply `200- OK`.
  - `save`:
    - filename missing: 0x80070057.
    - 0x91f238e8: (0x91faea4c & 0x1ff) == 0 gives 0x80070426.
    - Otherwise create the translated file (0x91f2eb68: access 0x40110000, attributes 0x80, share 1, disposition 5 FILE_OVERWRITE_IF). On success stop the title (0x91f25be0), write each node of list 0x91faea40 as one record of ((0x91faea44 - 1) * 4 + 0x12) bytes (32-bit wrap; 0xe bytes because 0x91faea44 is 0), then resume (0x91f25b50) only if the stop returned 0x02da0000. A write failure marks the file for deletion (NtSetInformationFile class 0xd); the handle is closed.
    - The result is HRESULT_FROM_WIN32(RtlNtStatusToDosError(status)) of the open or write status. Failure: `400- HRESULT 0x%x`. Success: `200- OK`.
  - `querystackdepth`: `200- 0x%x` of 0x91faea44.
  - `queryflags`: `200- 0x%x` of 0x91faea4c.
  - `querytype`:
    - type missing: 0x80070057.
    - type (low 16 bits) >= the count at 0x91f96038 (initially 14): 0x80070057.
    - Otherwise reply 200 with the type name. Names 0..13: heap, virtual-mapped memory, contiguous memory, system memory, debugger memory, kernel pool, directory object, event, file, I/O completion, mutex, semaphore, timer, thread. Indexes >= 14 would come from the table at *0x91faea60, filled by 0x91f23af4, which has no callers; the count stays 14.
- Settings file: WriteIniFile writes `memtrack flags=0x%x stackdepth=0x%x` (0x91faea58, 0x91faea54); DoIniLine stores `flags` and `stackdepth` with the optional dword getter and then clears bit 31 of the flags.
- Tracking engine (alloctrk.c): records are created only by debug services routed through the debug monitor dispatcher (0x91f3b4d0, stored at debug monitor data +0x18): service 8 (0x91f3b73c) calls 0x91f23598(3, address, size, type) and service 9 (0x91f3b754) calls 0x91f236d8(address, size, type); the argument block is {address, size, type (low byte)}.
  - Track: requires (0x91faea4c & 0x1ff) != 0, type < 14 and the type enabled (type 0: flag 0x1, type 1: flag 0x2, types 2..13 always, others flag 0x80). Allocates a record with ExAllocatePoolWithTag('xmem'): +0 next, +4 type (u16), +6 size, +0xa address, +0xe stack area of 0x91faea44 dwords (zeroed, never filled). It is pushed at the head of 0x91faea40 under spin lock 0x91faea5c; 0x91faea48 counts records. Allocation failure reports `unable to allocate buffer for allocation tracking`.
  - Untrack: same flag/type gates; finds the record by address. Type mismatch: `mismatch allocator @ %p (was %s, expected %s)`. Size 0 or equal: unlink and free. Other size: `invalid size freeing %s @ %p`. Not found: `no history tracking found freeing %s @ %p size %d`.
  - Diagnostics (0x91f233b0): vsnprintf into 0x200 bytes; RtlAssert(text, alloctrk.c, 0x73) when flag 0x100 is set, else DbgPrint `DM: %s\n`.
  - 0x91faea44 (capture depth) is never written, so records carry no stack and `querystackdepth` always replies `0x0`.
- Backend requirement: allocation tracking flags shared with the debug service dispatcher, the record list, and a record dump to file.
- Status: spec complete.

## mixcmd
- Handler: 0x91f54aa0. Access: 0x1. Extra: 0x0.
- Syntax: the subcommand is the text starting at line offset 7, so a 6-character command word and one separator are assumed.
  - `querystats` and `countxamheaps` must equal the rest of the line exactly (case-sensitive).
  - `xamheap <hexid>` is a 7-character prefix compare. The character at offset 14 must be a space, otherwise the image executes a trap. The id is up to 8 hex digits and stops at NUL or space.
  - Any other text: `200- OK` with no action.
- Behavior:
  - `querystats`: ExDebugMonitorService(8, buffer of 0x90 bytes with dword0 = 0x90 and dword1 = 0x68). Failure: `400- ` (0x82da010a). Success: `200- OK querystats ` followed by the 0x90 bytes as 288 upper-case hex characters.
  - `countxamheaps`:
    - xam.xex ordinal 0x828 is resolved on first use; failure gives `414- access denied`.
    - Call it with a 12-byte struct (dword0 = 0xc). Failure: `400- `. Success: `200- OK countxamheaps System=%08X Coop=%08X` (struct dwords +4, +8).
  - `xamheap`:
    - xam.xex ordinal 0x827 is resolved on first use; failure gives 414.
    - A non-hex id character: `423- bad parameter`.
    - Call the ordinal (id, info class 1, {u32 address of a 0x20-byte name buffer, u32 address of a dword holding 0x20}), then (id, 3, struct of 0x18 bytes, dword0 = 0x18), then (id, 2, struct of 0x1c bytes, dword0 = 0x1c); each call runs only when the previous one succeeded. Any failure: `400- ` (0x82da010a); unless the failure is 0x80004005, DbgPrint `WRN[MIX]: XampHeapGetInfo for id %X info %d failed hr 0x%08X\n`.
    - The non-hex id character also prints `WRN[MIX]: Unsupported id char '%c'\n`. Failed querystats prints `WRN[MIX]: DMSVC_GET_DEVKIT_MEMORY_STATISTICS failed status 0x%08X\n`; failed countxamheaps prints `WRN[MIX]: XampHeapGetCount failed hr 0x%08X\n`.
    - Both XAM ordinals are resolved with XexGetProcedureAddress on the XAM handle (no entry-point check); a failed resolution is retried on the next use.
    - The handler also requires the reply buffer to hold at least 0x9f (querystats), 0x2f (countxamheaps) or 0x66 (xamheap) bytes, else 0x82da0105; the dispatcher's buffer is always larger.
    - Success: `200- OK xamheap Name=%s Data=` followed by the 0x18 bytes as 48 upper-case hex characters and then the 0x1c bytes as 56 upper-case hex characters.
- Backend requirement: devkit memory statistics block; XAM heap count and per-heap information (raw structures passed through as hex).
- Status: spec complete. The fields of the passed-through structures are not interpreted by XBDM.

## mkdir
- Handler: 0x91f46db0. Access: 0x2. Extra: 0x0.
- Syntax: `name=` string (at most 0x140 characters, required).
- Behavior:
  1. Missing: `400- missing name`.
  2. A name starting with `\Device\` (case-insensitive) is opened directly through 0x91f2ec08. Otherwise the path is translated through 0x91f2eb68; translation failure gives status 0xc000000f.
  3. NtCreateFile(access 0x100001, attributes 0x80, share 0, disposition FILE_CREATE, options 0x21 = directory and synchronous).
  4. Success: close the handle, increment the counter 0x91f9feec, `200- OK`.
  5. 0xc0000035: `410- file already exists`. Other failures map through 0x91f41f18 with default 0x82da000d, for example `413- file cannot be created`, `430- path not found`, `414- access denied`.
- Backend requirement: create a directory on a console volume.
- Status: spec complete.

## mockcurrencyvalue
- Handler: 0x91f4c510. Access: 0x4. Extra: 0x2.
- Syntax: `enabled=` string (at most 31 characters, required); dword `value` (required when enabling).
- Behavior:
  1. `enabled` missing: `423- bad parameter`.
  2. `on` or `true`: `value` is required (missing gives 423). The 20-byte message is {u32 1, u32 value, 12 zero bytes}.
  3. `off` or `false`: the message is all zero.
  4. Any other value: 423.
  5. XMsgStartIORequest(app 0xfe, message 0x23100, no overlapped, message, 0x14).
  6. The reply is `200- OK` only when that call returns 0x80070057. Any other return gives `414- access denied`. This is the literal behavior of the image.
- Backend requirement: deliver a mock currency setting to the system marketplace service.
- Status: spec complete.

## modsections
- Handler: 0x91f48978. Access: 0x4. Extra: 0x0.
- Syntax: `name=` string (at most 0x140 characters, required). The name must equal a loaded module base name (case-insensitive, no prefix match).
- Behavior:
  1. No context: `400- `. Missing name: `400- missing name`.
  2. Snapshot (0x91f340d0) under the loader lock:
     - Not found, or the module has no NT header: `403- no such module`.
     - Each entry is 0x110 bytes: name (up to 8 characters), base = module base + VirtualAddress, size = VirtualSize, index = 1-based section number, flags.
     - flags: 0x2 if Characteristics has 0x40000000, 0x4 if 0x80000000, 0x8 if 0x20000000, 0x10 if 0x80.
  3. Reply `202- multiline response follows`, then one line per section: `name="%s" base=0x%08x size=0x%08x index=%d flags=%d`, then `.`.
- Cross-check: matches modsections.capture (for example `.text` flags=10 and `.data` flags=6).
- Backend requirement: enumerate a loaded module's PE section headers.
- Status: spec complete.

## modules
- Handler: 0x91f488c8. Access: 0x4. Extra: 0x0.
- Syntax: no parameters.
- Behavior:
  1. No context: `400- `.
  2. Reply `202- multiline response follows`.
  3. The first callback builds a snapshot (0x91f338c0; initial capacity 10, grown and retried until it fits) of the loader lists at 0x91fade64 and 0x91fadec4. Only entries with loader flag 0x100000 and a valid NT header are included. Per entry:
     - name: base name, wide converted to narrow, up to 0x104 bytes.
     - base: DllBase.
     - size: loader SizeOfImage (entry +0x20).
     - check: OptionalHeader.CheckSum.
     - timestamp: FileHeader.TimeDateStamp.
     - pdata / psize: directory entry 3 address and size.
     - flags: 4 if FileHeader.Characteristics has 0x2000.
     - thread: 0.
     - osize: OptionalHeader.SizeOfImage.
  4. Line format: `name="%s" base=0x%08x size=0x%08x check=0x%08x timestamp=0x%08x pdata=0x%08x psize=0x%08x%s%s%s thread=0x%08x osize=0x%08x`. The three %s are ` tls` (flag 2), ` xbe` (flag 1) and ` dll` (flag 4), each or the empty string. Flags 1 and 2 are never set by this path.
  5. End: `.`. Out of memory during the snapshot closes the connection.
- Cross-check: matches modules_small.capture.
- Backend requirement: enumerate loaded modules with PE header fields.
- Status: spec complete.

## netcap
- Handler: 0x91f353a8 (start 0x91f34f80, stop 0x91f351e0). Access: 0x4. Extra: 0x0.
- Syntax: flag `start` or `stop`, tested in that order.
  - `start` parameters: dwords `maxframedata`, `buffersize`, `flags` (0 when absent or unparsable); `file=` (key=value form, copied into a 0x104-byte buffer, at most 0x103 characters, required; an empty value counts as present).
  - `flags` bits: 1 promiscuous mode; 2 skip received frames sent to ff:ff:ff:ff:ff:ff; 4 skip received frames whose destination has the group bit (byte 0 bit 0) and is not the broadcast address; 8 persistent: keep capturing across title termination, allocate from pool type 2 instead of 1, smaller buffer defaults. Transmitted frames are never filtered; frames of 6 bytes or less are never filtered.
- Globals: 0x91f9f690 capture context (nonzero while capturing), 0x91f9f694 flags, 0x91f9f698 first frame callback error.
- Behavior:
  - No flag: `423- bad parameter`.
  - `start`:
    1. Missing `file=`: `412- filename is invalid` (result 0x82da000c, no text).
    2. Already capturing: error 0x82da0008.
    3. Path translated with 0x91f2e888 into a 0x104-byte buffer; the raw `file=` text is used when translation fails.
    4. Buffer sizes: a nonzero `buffersize` gives chunk min(buffersize / 2, 0x4000). With `buffersize` 0: flags & 8 gives 0x2000 / 0x1000, otherwise 0x20000 / 0x4000.
    5. 0x91f67f78 installs the allocator pair: 0x91f34f60 (`ExAllocatePoolTypeWithTag(size, 'DMNC', 2)`) for flags & 8, else 0x91f34f70 (type 1); free is 0x91f52718 (ExFreePool).
    6. 0x91f67f90(0, maxframedata, 1): creates the 0xc8-byte context (below). Failure: 0x8007000e.
    7. 0x91f69c10(context, path, buffersize, chunk, mode 3): opens the capture file (below). Failure: destroy the context, report the result.
    8. flags & 1: `XNetSetOpt(2, 0x1390, &1, 4)`; nonzero result clears bit 0 of the stored flags.
    9. 0x91f9f698 = 0, 0x91f9f694 = flags.
    10. netsim instance (0x91f9fc84) present: chain the callbacks into it (0x91f8d428(instance, 0x91f34de0, 0x91f34e78, context, 0)); otherwise `NetDll_XnpEthernetInterceptSetCallbacks(2, 0x91f34de0, 0x91f34e78, context, 0)`. Intercept failure: result 0x82da0010 for 0x2735 (WSAEALREADY), the value itself when it is negative, else 0x80070000 | (value & 0xffff); then close (result ignored) and destroy the context. Promiscuous mode stays enabled on this path.
    11. Success: 0x91f9f690 = context, `200- started`.
    12. Failure text `err=0x%08x`. Negative results with bit 0x10000000 (a kernel status ORed with 0x10000000) are first mapped by 0x91f41f18 (NTSTATUS table, fallback the original result). The status keeps facility-0x2da results (e.g. `410- err=0x82da000a` for an existing file, `416- err=0x82da0010`); any other failure becomes 0x82da0000 (`400- err=0x8007000e`).
  - `stop` (also called by title termination 0x91f38480 with no text buffer when capturing and !(flags & 8)):
    1. Atomically take 0x91f9f690; zero: result 0x82da0023, `435- ` (no default text).
    2. result = 0x91f9f698 (read before the swap). flags & 1: `XNetSetOpt(2, 0x1390, &0, 4)`. netsim instance present: unchain (0x91f8c6a8(instance, 0, 0, 0, 0)), else `NetDll_XnpEthernetInterceptSetCallbacks(2, 0, 0, 0, 0)`.
    3. Close (0x91f68008 = 0x91f69d18), frame count (0x91f67ff0, context +0x48), destroy (0x91f68010); each result replaces `result` while it is not negative, so the first failure wins.
    4. result 0x8007001d: `438- stopped err=0x82da0026 frames=%u` (result 0x82da0026, not mapped). Otherwise map as in start step 12; negative: `200- stopped err=0x%08x frames=%u`, else `200- stopped frames=%u`. The status is 200 in both cases.
- Frame callbacks (0x91f34de0 transmit, 0x91f34e78 receive; arguments context, frame, length; return 0, frame not consumed): skip when 0x91f9f698 is negative; receive applies the flag 2/4 filters. Append with 0x91f67fe8 = 0x91f699f8(context, {frame, length}, 1 buffer, time 0, type 0, flags 0). A failing append is stored into 0x91f9f698 with an atomic compare-exchange from 0, so only the first failure is kept and later frames are skipped.
- Frame-log context (0xc8 bytes, created by 0x91f69f20 / 0x91f69e08): +0x00 spin lock, +0x04 saved IRQL, +0x08/+0x0c in-memory record list (memory mode only), +0x18 SYSTEMTIME from GetLocalTime (xam 0x444), +0x28 time base at creation, +0x38 longest frame (argument 1 of creation; 0 selects 0x5ea), +0x3c data limit (maxframedata; 0 selects 0xffffffff), +0x40 ticks per millisecond = (u32)(KeQueryPerformanceFrequency() * 0.001), +0x44 memory record count, +0x48 file record count, +0x4c memory bytes, +0x50 file bytes (frame length + 0x12 per record), +0x58 file object (0x68 bytes), +0xc0 flags: 0x80000000 time from mftb (always set), 0x40000000 memory mode (not used by netcap), 0x20000000 memory busy, 0x10000000 file open, 0x04000000 file open/close in progress, 0x02000000 memory limit hit, 0x01000000 file data limit hit, 0x00800000 a record failed with 0x8007001d.
- Append (0x91f699f8), under the context lock:
  1. Frame longer than +0x38 (0x5ea) and flags argument bit 0 clear: 0x80070018.
  2. Flag 0x02000000 or 0x01000000: 0x8007006f.
  3. File not open, or open/close in progress: success, frame dropped.
  4. length > +0x3c - +0x50 (unsigned 32-bit; once the 0x12-byte overhead pushes +0x50 past the limit the difference wraps and the limit stops applying): set 0x01000000, 0x8007006f.
  5. Time = (mftb - +0x28) * 1000 / +0x40, in microseconds. Write the record (0x91f6a730). 0x8007001d sets 0x00800000. Success: +0x48 += 1, +0x50 += length + 0x12.
- File object (0x91f6a410 init; +0x00 handle, +0x08 position, +0x10 record end at the last buffer write, +0x18 end of the last complete record (0 after a write fault), +0x28 = 1000, +0x2c table offset, +0x30 table bytes, +0x34 buffer spin lock, +0x3c buffer, +0x40 buffer size, +0x44 chunk, +0x48 buffered bytes, +0x4c writer thread object, +0x50 KEVENT (synchronization, type byte 1), +0x60 media type, +0x64 flags: 0x80000000 records carry a type trailer).
- File open (0x91f6b4e8, mode 3): `NtCreateFile(GENERIC_READ | GENERIC_WRITE, attributes 0, share FILE_SHARE_READ, disposition mode & 1 ? FILE_CREATE : FILE_OVERWRITE_IF, options FILE_SYNCHRONOUS_IO_NONALERT)`, object attributes 0x40, root directory 0 when the name starts with `\` and 0xfffffffd otherwise. With mode 3 an existing file fails with 0xc0000035 (`410- err=0x82da000a`). Then write the header (below). Allocate the buffer (buffersize; 0 would select 0x1000; chunk 0 selects buffersize / 2) and start the writer thread (0x91f6b440: `ExCreateThread(&object, 0, &id, 0, 0x91f6b428, file, flags)`, flags 0x040004a4 for mode bit 2, else 0x80, | 2 when KeGetCurrentProcessType() != 1). Kernel failures return status | 0x10000000; any failure closes the handle (0x91f6b210). The file stays on disk.
- Buffered write (0x91f6a730 and 0x91f6ae10/0x91f6a4e8): records are copied into the buffer under the buffer lock and the position advances; when the buffered bytes reach the chunk the writer thread event is set. If the buffer fills with bytes left over: at IRQL 0 (KPCR byte +0x18, the current IRQL; compared with 2 elsewhere, e.g. 0x91f25180) it yields with KeDelayExecutionThread(0) and retries; otherwise (always the case for appends, which hold the context spin lock) +0x18 = 0 and the result is 0x8007001d. While +0x18 is 0 every record fails with 0x8007001d. The writer thread (0x91f6b2a0) waits for the event and writes the buffer out in pieces of at most 0x10000 bytes at explicit offsets, setting +0x10 from +0x18 after each piece; it exits with 0x800704c7 when +0x4c was cleared. buffersize and chunk only change when bytes reach the file and whether a burst overflows the buffer (0x8007001d, `438` on stop); the file content is otherwise identical.
- Close (0x91f69d18): file not open: 0x800710df. Set 0x04000000, clear 0x10000000. Records > 0: 0x91f6b080 stops the thread (0x91f6a460: clear +0x4c, KeSetEvent(event, 1, 1), KeWaitForSingleObject(thread, 3, 1, 0, 0), ObDereferenceObject), writes the buffer, and when +0x18 is 0 moves the position back to +0x10. It then walks the records from 0xf4 to the position: each 16-byte record header is read back; a length larger than the remaining bytes, or differing length fields, fail with 0x8007000d. Each record offset is appended as a u32 at the table (first entry sets +0x2c to the position); +0x48 = records found. Then 0x91f6b360: stop the thread, write the buffer, set end of file and allocation size to the position (NtSetInformationFile classes 0x14 and 0x13), write {+0x2c, +0x30} at offset 0x18, close. Success returns 0x8007001d when 0x00800000 is set, else 0. A failure keeps 0x10000000 set and returns the error; destroy (0x91f69f78) then closes the handle without the table. Kernel errors are status | 0x10000000; short transfers 0x80070018.
- Capture file format (all fields little-endian):
  - 0x00 `GMBU`; 0x04 u8 1 (records carry the type trailer; 0 when mode bit 4 is set); 0x05 u8 2; 0x06 u16 1; 0x08 eight u16 local time of context creation (year, month, day of week, day, hour, minute, second, millisecond); 0x18 u32 frame table offset; 0x1c u32 frame table bytes (both 0 until closed, and 0 when no record was found); 0x38 u32 0x80 and 0x3c u32 0x74 (offset and size of the media block); other bytes 0.
  - Media block at 0x80 (0x74 bytes): +0x1c u32 100, +0x20 u32 media type 1, +0x24 u32 longest frame 0x5ea, +0x2c u32 1000, +0x50 u32 1; other bytes 0.
  - Records from 0xf4: u64 time in microseconds since context creation, u32 frame length, u32 frame length, frame bytes, u16 frame type 1. Frames are never truncated: frames over 0x5ea bytes fail with 0x80070018.
  - Frame table after the last record: one u32 absolute file offset per record. The file ends after the table.
- Backend requirement: Ethernet intercept callbacks or the netsim chain, XNetSetOpt, Nt file services, a writer thread with a KEVENT, time base and GetLocalTime.
- Status: spec complete. Unknown: meaning of the constant header bytes (0x05, 0x06, media block +0x1c, +0x2c, +0x50).

## netsim
- Handler: 0x91f37418. Access: 0x4. Extra: 0x0. Arguments (line, text, size, connection); the connection argument only selects persistence.
- Gate: XamGetSystemVersion() < 0x20278700 gives `407- unknown command`.
- Syntax and order of checks:
  1. `reload` (`file=`, string copy into 0x104 bytes; missing gives an empty name).
  2. `getnumqs`, then `getnumipv4redirs`.
  3. Flags `in` and `out`; dword `index` (missing, unparsable, or 0xffffffff all mean -1); `cfg=` (key=value form required). The cfg text skips one leading quote and is decoded by 0x91f364f0 (pairs of hex digits of either case up to a space, quote, or NUL, at most 0xdc bytes); a bad digit, odd count, or overflow returns 0x82da0007 (`407- unknown command`) before any subcommand is chosen. A cfg that decodes to 0 bytes counts as missing.
  4. `insertq`: exactly one of in/out and a cfg. `removeq`: index -1 takes in and out as given, both when neither is given; another index needs exactly one. `modifyq`: one direction, an index, a cfg. `getqstats` and `getq`: one direction and an index. `insertipv4redir`: a cfg; index optional. `removeipv4redir`: nothing required.
  5. Any requirement missing, or no subcommand: 0x82da0017 with no text (`423- bad parameter`).
- Error rule of the subcommand helpers (0x91f36a18..0x91f37378): text `err=0x%08x` with the raw result; the status keeps results whose bits 0x1fff0000 are 0x02da0000 and uses 0x82da0000 (400) for every other failure. Operations that need the instance return 0x82da0002 without one (`402- err=0x82da0002`).
- Library status values: 0x82da0008 instance exists, 0x82da000c no file, 0x82da000e XAM export 0x8e missing, 0x82da0010 intercept owned elsewhere (WSAEALREADY 0x2735), 0x82da0017 bad blob or index, 0x82da001a instance changed during destroy, 0x82da001c out of memory, 0x82da0026 serialization buffer too small, 0x82da0150 reload running.
- Instance (0xa8 bytes, vtable 0x91f0d240, allocator 0x91f36460 = `ExAllocatePoolTypeWithTag(size, 'DMNS', 2)`): +0x04 spin lock, +0x08 saved IRQL, +0x0c XAM export 0x8e (sends redirected frames; resolved at creation by 0x91f8c758), +0x10 in queues, +0x18 out queues, +0x20/+0x24 their counts, +0x28 redirects, +0x30 count, +0x34 sessions looked up for received frames, +0x3c for transmitted frames, +0x48 u64 timer due time (-1 idle), +0x50 KTIMER, +0x78 KDPC (routine 0x91f8ea50, byte +3 set to 3), +0x94/+0x98/+0x9c chained transmit/receive callback and context, +0xa0 flags (0x80000000 proxy bypass, set by 0x91f8d3d8; 0x40000000 receive frames meet the chain before the simulation and transmit frames after it, set by 0x91f8d428's last argument). Method 0 is `XeCryptRandom(buffer, length)` (0x91f8c748).
- Timer initialization (0x91f8ed88 region): `KeInitializeTimerEx` for the KTIMER at +0x50 with r5 = 2 (`li r5,2` before the call), the system process type; the console backend passes `ProcessType::SYSTEM`.
- Create (0x91f365e8): existing instance 0x82da0008. Allocate (0x82da001c) and resolve XAM 0x8e (0x82da000e). ipproxy started (0x91f9f6a0): bypass on. netcap capturing (0x91f9f690): chain its callbacks (0x91f8d428, flag 0) and `NetDll_XnpEthernetInterceptSetCallbacks(2, 0, 0, 0, 0)`. Then `NetDll_XnpEthernetInterceptSetCallbacks(2, 0x91f36470, 0x91f364b0, instance, 2)`. A nonzero intercept result maps to 0x82da0010 for 0x2735 (second call only), 0x80070000 | (value & 0xffff) when positive, else the value; the instance is freed and a capture moved off its own intercept stays detached.
- Destroy (0x91f36750): compare-exchange 0x91f9fc84 from the instance to 0 (mismatch 0x82da001a); `SetCallbacks(2, 0, 0, 0, 2)`; a capturing netcap is registered directly again (`SetCallbacks(2, 0x91f34de0, 0x91f34e78, context, 0)`); 0x91f8e788 removes every queue, cancels the timer, removes the DPC, and frees the instance. Redirects stay allocated (leak).
- Intercept callbacks 0x91f36470 (transmit) and 0x91f364b0 (receive) return 1 (frame taken) when 0x91f8e260 returns 0x02da0000.
- Frame processor 0x91f8e260(instance, direction 0 transmit / 1 receive, frame, length):
  1. Classify the frame with the frame library (0x91f68320): bit 1 Ethernet, 2 well-formed IPv4 (version 4, header length 20..total length, total length within the frame, source neither 255.255.255.255 nor multicast), 0x80 TCP with a complete header, 0x100 UDP whose length is 8..the datagram.
  2. Lock. Bypass: unlock, offer the frame to the chained callback of the direction; taken only when that returns nonzero.
  3. Chain before the simulation (receive when +0xa0 bit 30 is set, transmit when clear): unlock, call it; nonzero takes the frame; otherwise relock, the direction has no chained callback any more, and bypass is checked again.
  4. IPv4 frames (bits 1 and 2): the compared address is the destination (transmit) or source (receive); for TCP/UDP the compared port is the destination (transmit) or source (receive) port, else 0.
     - TCP/UDP: a session in the direction's list with (session protocol & frame protocol) != 0, rewritten address and port equal to the compared ones, refreshes its tick count and rewrites the frame back to the session's original address and port.
     - Otherwise the first redirect whose match address (0 = any) and match port (0 = any) equal the compared ones, and whose classifier accepts the frame (0x91f8c988), applies: the new address is the target address unless 0, the new port the target port unless 0. With session slots, 0x91f8ce98 records the flow in the other direction's list: the first free slot, or the slot already holding the same flow (refresh), whichever comes first in slot order; otherwise the last slot idle for at least 120000 ms (KeTimeStampBundle tick count) is unlinked and reused; none: the frame is taken and dropped (result 0x02da0000).
     - A rewritten frame is a pool copy (header 0x1c bytes, 0x91f8cb70; failure 0x82da001c, the frame passes untouched) flagged redirected (bit 31 of +0x18). Rewrite (0x91f8d008): the compared address field, then for TCP (flag 0x80) or UDP (0x100) with a 20-byte IP header the compared port field and the IP plus transport checksum (TCP 0x91f681a8 over frame length - 34 bytes; UDP 0x91f68098 over the UDP length field; a zero checksum becomes 0xffff; a segment over 0x5ea bytes zeroes the first 0x36 (TCP) or 0x2a (UDP) frame bytes instead); TCP/UDP with IP options keep every checksum; other frames get only the IP header checksum.
  5. The first queue of the direction whose classifier accepts the frame (no classifier accepts all) takes it: copy it if not yet copied (0x82da001c, frame passes), totalpkts += 1, totalbytes += length, enqueue at the time base (read again when its low word is 0; rate constant 49875000), and arm the timer for the queue's next release time. The frame is taken.
  6. No queue: unlock; a rewritten copy is emitted at once (step "emission" with the direction's remaining chained callback) and the frame taken; otherwise the frame is offered to the remaining chained callback, taken only when it returns nonzero.
  - Classifier errors (0x91f8c988 failing) return the error and the frame passes.
- Emission: transmit 0x91f8d1d8: chained callback (when given) first; when it returns 0, `NetDll_XnpEthernetInterceptXmit(2, frame, length)` (xam 0x6e), or XAM export 0x8e(2, frame, length, 0) for redirected copies. Receive 0x91f8d158: chained callback, then `NetDll_XnpEthernetInterceptRecv(2, frame, length)` (xam 0x6f). The copy is freed.
- Timer (0x91f8d350 arms, DPC 0x91f8dec0 runs): arming for time T does nothing when T >= +0x48; otherwise the relative due time is the clamped difference T - now shifted right by 62 bits and negated (so 0 or a few 100 ns: the DPC runs again at once while frames wait), `KeSetTimerEx(timer, due, 0, dpc)`, +0x48 = T. The DPC sets +0x48 = -1, drains every in queue (0x91f8d280: dropped frames count droppkts += 1, dropbytes += frame length, and are freed; released frames are collected in order), emits the received frames outside the lock with the receive chain only when bit 30 is clear, rereads the time base, drains the out queues, arms the timer for the earliest next release of all queues, and emits the transmitted frames with the transmit chain only when bit 30 is set.
- Queues (0x91f8cbc0; type 1 0x78 bytes, 2 0x110, 3 0xf0): +0x00 links, +0x08 classifier, +0x0c stage object (at +0x58), +0x10 type, +0x14 settings (0x24 bytes: +0x18 mask, +0x1c packet limit, +0x20 byte limit, +0x24 rate, +0x28 token rate, +0x2c bucket depth, +0x30 loss, +0x34/+0x36 latency), +0x38 statistics block (+0x38 size 0x20, +0x40 totalbytes, +0x48 dropbytes, +0x50 totalpkts, +0x54 droppkts).
- Stage objects; every stage keeps frames in release-time order (insert after the last frame not later, 0x91f93bd0) with byte and frame counts. Methods: 0 enqueue(frame, size, now, rate), 1 dequeue(now, rate) giving the frame and a dropped flag, 2 next release time (default: the first frame's time, not before now; none -1), 3 flush, 4 empty. Dropping a frame (0x91f93dd8) sets its bit 0x40000000, removes it from the counts, sets its time 0 and moves it in front of the frames not dropped, so it leaves at the next dequeue and is counted as a drop.
  - Type 1, unshaped (vtable 0x91f0f590): frames leave at once in arrival order. Accepts no settings.
  - Type 2, link (vtable 0x91f0f5a4, three stages pulled front to back, one frame per stage per dequeue, 0x91f94338; next time is the minimum of the stages, 0x91f94490):
    1. Rate with limits (vtable 0x91f0f554): a frame costs its wire size max(length + 4, 64) + 8; it is released (bits = cost * 8) * 49875000 / rate ticks after the last frame not dropped, or after now. Rate 0xffffffff is unlimited; byte limit default 0x20000, packet limit default 200 (0xffffffff unlimited); excess frames are dropped from the back.
    2. Latency (vtable 0x91f0f568): release after now + uniform random in [min, max] ms (49875 ticks per ms; XeCryptRandom u64 modulo span + 1); without the reorder bit no earlier than the last frame not dropped.
    3. Loss (vtable 0x91f0f57c): with loss L > 0, draw r = 0 when L >= 100000, else uniform in [0, 100000] (u32 modulo 100001); r <= L drops the frame.
  - Type 3, token bucket (vtable 0x91f0f5b8, two stages pulled back to front: the last stage first, then the bucket feeds it until it has nothing, 0x91f94508; next time is that of the last stage holding frames, 0x91f94680):
    1. Bucket with limits (vtable 0x91f0f52c): tokens refill by `step` bytes per `period` ticks up to the depth; a frame leaves when tokens >= its length (dropped frames cost 0). Token rate R bits/s: b = R / 49875000 * 0.125 bytes per tick; b >= 1 gives step trunc(b), period 1; else step 1, period trunc(1 / b). Defaults: unlimited tokens and depth, limits 0x20000 bytes and 200 frames.
    2. Rate (vtable 0x91f0f540): released length * 8 * 49875000 / rate ticks after the last frame not dropped or now.
- cfg blob of queues (parser 0x91f8c260, validation 0x91f8bc38, application 0x91f8e800, serialization 0x91f8c058):
  - Byte 0 version with high nibble 1; byte 1 type 1..3 (insertq only; the modifyq blob has no type byte); big-endian u32 mask; then for the mask bits, big-endian: 0x1 packet limit u32, byte limit u32; 0x2 rate u32 (bits/s); 0x4 token rate u32 (bits/s); 0x8 bucket depth u32 (bytes); 0x10 loss u32 (per 100000); 0x20 latency min u16, max u16 (ms). Mask bits 0x40 (reorder), 0x80 (bucket starts full), 0x100 (bucket starts empty) take no bytes.
  - Trailing bytes are a classifier program for insertq (below) and 0x82da0017 for modifyq. insertq parses the settings, then the program, then validates the settings, so a program error wins over a settings error.
  - Validation (0x82da0017): rate 0, token rate 0, loss > 100000, latency min > max, both 0x80 and 0x100, 0x80/0x100 without 0x8. The validated mask keeps 0x1..0x20, 0x40 only with 0x20, 0x80/0x100 only with 0x8; other bits are dropped.
  - Application: type 1 rejects every field bit; type 2 rejects 0x4 and 0x8; type 3 rejects 0x10 and 0x20 (0x82da0017, nothing applied). Each present field replaces the stored one and reconfigures its stage (limits drop excess frames at once; latency stores the reorder bit; depth caps the tokens; 0x80 fills and 0x100 empties the bucket and restarts its clock). Bit 0x8 without 0x80/0x100 clears both from the stored mask; the stored mask is ORed with the new one (type 1 keeps mask 0).
  - Serialization (getq, persistence): version 0x10, the type, the stored mask, the stored fields, then the classifier program; a short buffer is 0x82da0026. So getq shows the applied settings, not the inserted blob.
  - insertq (0x91f8ea98): parse, validate, allocate (0x82da001c), apply, then insert before `index` (0..count-1) or append (-1); an index >= count is 0x82da0017. `index=` reports the position. modifyq (0x91f8ec80) applies to the queue at the index.
- Redirect blob (0x91f8c548, validation 0x91f8bf98, serialization 0x91f8c418): 15 bytes: version (high nibble 1), match IPv4 address, match port u16, target address, target port u16, session count u16, then an optional classifier program (parsed before validation). Target address and port both 0, or more than 500 sessions: 0x82da0017. The redirect (0x91f8cd50) holds `sessions` 0x1c-byte slots (+0x08 protocol, 0x80000000 free; +0x0c tick count; +0x10 rewritten address; +0x14 original address; +0x18 rewritten port; +0x1a original port).
- Classifier programs (library 0x91f84708..0x91f8b0b0, object 0x58 bytes from 0x91f86b78; netsim builds them with 0x91f8bb08: limits 0x80 name bytes, 0x20 items, 0x40 nodes, feature set 0xdd):
  - Header: version byte with high nibble 1 (0x8007051a otherwise); flags byte: bit 0 must be clear (0x80070459), bit 1 little-endian values, bits 2..3 string table header (0: none, 4: u8 table length and u8 longest string, 8: u16 pair, 0xc: u32 pair; big-endian regardless of bit 1), bits 4..5 counts (0: u8 node count, 0x10: u8 items and u8 nodes, 0x20: u8 items and u16 nodes, 0x30: u16 pair). The table and counts must fit the bytes (0x8007000d) and longest <= table length; then the string table bytes.
  - Items, `item count` times: wire type byte; flags byte (1 named, refused by netsim; 2 an 8-byte tag follows; 4 fixed; 0x38 field index width 1/2/4/8 bytes, 0 refused); the field index (1..0x55 into the field table 0x91f0ca48, names at 0x91f99660); the initial value of the wire type. Netsim refuses any program whose item is not a field (0x91f8bb08 checks flag 4 of each item's type information and index 1..0x55).
  - Values by wire type: 1 null, 2 false, 3 true, 4..7 i8/i16/i32/i64, 8..0xb u8/u16/u32/u64, 0xe MAC (6 bytes), 0xf IPv4 (4), 0x10 IPv6 (16) copied as they are, 0x11 opaque (no bytes; items only), 0x12 string reference (an offset into the table, width by table length, pointing at a length prefix of the longest-string width and the bytes). The netsim feature set refuses 0xc/0xd (floating point) and 0x13.
  - Nodes in postfix order, `node count` bytes of opcodes: 1..0xb, 0xe..0x10 and 0x12 constants; 0x21 a name (string reference shorter than 0x80 bytes); 0x22 an item reference (index width by item count, index < item count); 0x23..0x44 operators (op - 0x20): 3 assignment (first operand must be a name or item), 4/5 indexed names (refused), 6 negate, 8 logical not, 9 complement, 0x1e String.Length (one operand), 0x1c conditional (three), 0x1f..0x24 String.Compare/IndexOf/Contains/StartsWith/EndsWith/Substring with a u16 operand count (2..3, IndexOf 2..5, at most the node count), all others binary: 0xa mul, 0xb div, 0xc mod, 0xd add, 0xe sub, 0xf shl, 0x10 shr, 0x11 lt, 0x12 gt, 0x13 le, 0x14 ge, 0x15 eq, 0x16 ne, 0x17 and, 0x18 xor, 0x19 or, 0x1a logical and, 0x1b logical or. Opcodes 0x27 and 0x3d are refused. Bytes must end exactly with one expression; a constant expression is refused by 0x91f8bb08.
  - Stored copy (0x91f871f8): the parse objects are copied into 0x10 item objects and 0x20 node objects; a program with more than 16 items or 32 nodes fails with 0x82da001c (0x8007000e from the copy).
  - Serialization (0x91f87318): canonical big-endian form: version 0x10; flags 0x04/0x08/0x0c for the smallest table header that holds the table length and longest string, 0x10 when there are items (u8 counts); the distinct strings in reverse order of first use, each with a length prefix of the longest-string width; items with flags 0x08 (u8 index) plus 2/4, the tag, the index, and the value; nodes as parsed. An item holding a string makes the item encoder fail with 0x80070545, so `getq` of such a queue answers `400- err=0x80070545` and the settings file stops that list at it.
  - Evaluation (0x91f8c988 driving 0x91f89310): the frame is parsed once (0x91f68320). Items are read lazily, left to right, when an operator needs them: a declared non-null value is used as is; otherwise the field getter of the table (presence mask, getter, type, offset, size, byte order) reads the frame or the parse information; a field whose protocol flag is absent reads false, 0, a zero address, or an empty string. XSP subtype fields (0x70000..0x180000) are present when the subtype bits equal the mask. Logical and/or short-circuit unless the right operand is a literal; comparisons and arithmetic run in 64 bits, unsigned when either operand is unsigned, with stock's result types; addresses compare bytewise, only with addresses of the same type; division by zero, negative shift counts in signed arithmetic, arithmetic or truth tests on addresses or strings, and bad string function arguments are errors. The result is converted to a truth value. An error makes the frame pass the simulator.
  - Frame parse (0x91f697a0): Ethernet (flag 1); ethertype 0x800 IPv4 (2, with the checks above), 0x806 ARP (4, hardware type 1 or 6, IPv4, sizes 6/4, opcode 1/2, sender MAC not multicast, sender and target IP neither broadcast, multicast nor loopback), 0x3c12/0x3c13/0x8863/0x8864 (8), 0x88d9 LLTD (0x10), other types > 0x5dc: payload, <= 0x5dc 802.3 (0x2000). IPv4 protocols: ICMP (0x20, type/code table: types 0, 4, 8, 9, 10, 13..18 any code, 3 code < 14, 5 code < 4, 11/12 code < 2), IGMP (0x40), TCP (0x80), UDP (0x100), 0x32 (0x800). UDP to a unicast or broadcast Ethernet and IPv4 destination: port 53 either side DNS (0x200), 67/68 DHCP (0x400 when option 53 is found in the options or the overloaded file/sname fields), 137..139 NetBIOS (0x1000), 500/500 IKE (0x4000), 88 Kerberos (0x200000), both ports above 0x400 the secure protocol (XSP subtypes 0x10000..0x60000 for data packets, 0x70000..0x180000 for key exchange). Malformed headers set 0x80000000.
- Removal: removeq (0x91f8e0e8) marks every frame of the queue dropped, drains it, and frees it; index -1 removes all of the direction, another index one queue (0x82da0017 past the end). removeipv4redir (0x91f8d960) unlinks the redirect's session slots. After a removal with an instance, a count of zero in queues, out queues and redirects destroys the instance; a destroy failure is the result.
- Subcommands:
  - `getnumqs`: `200- in=%u out=%u` (0 and 0 with no instance). `getnumipv4redirs`: `200- num=%u`.
  - `insertq` (0x91f36a18) and `insertipv4redir` (0x91f370f0): create the instance when missing; on failure an instance created here is destroyed. Success `200- index=%u`.
  - `removeq` (0x91f36b50): no instance: index -1 gives `200- removed=0 inleft=0 outleft=0`, else 402. Success `200- removed=%u inleft=%u outleft=%u` (removed summed over the directions, counts read before a destroy).
  - `modifyq` (0x91f36cf0): `200- OK`.
  - `getqstats` (0x91f36da8): `200- totalpkts=%u totalbytes=0q%08x%08x droppkts=%u dropbytes=0q%08x%08x`.
  - `getq` (0x91f36ef0): `200- cfg=<upper-case hex>`; nothing is written (`200- OK`) when the text size is not above (bytes + 2) * 2.
  - `removeipv4redir` (0x91f37220): no instance: index -1 gives `200- removed=0 left=0`, else 402. Success `200- removed=%u left=%u`.
- Persistence: after a successful insertq, removeq, modifyq, insertipv4redir or removeipv4redir from a connection (not the no-instance paths), NetSimWriteIniFile (0x91f36290): no stored name, or no 0x4000-byte pool buffer: nothing. `NtCreateFile(GENERIC_WRITE, attributes 0, share 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT)`; failure: nothing. Lines with CR LF through the 0x4000-byte buffered writer (0x91f31a50/0x91f31860, a failed write stops the system with bug check 0x2c): `[xbdm]`, `netsim insertq in cfg=<HEX>` per in queue, `netsim insertq out cfg=<HEX>` per out queue, `netsim insertipv4redir cfg=<HEX>` per redirect, upper-case hex of the serialized blobs.
- `reload` (0x91f36818):
  1. Atomic exchange of the busy flag 0x91f9f69c with 1; already set: 0x82da0150 with no text (`400- `).
  2. A non-empty `file=` is translated with 0x91f2e888 (0x104 bytes; the raw text when translation fails) and stored at 0x91f9fc88 (at most 0x103 characters). Without one and with no stored name: 0x82da000c.
  3. An existing instance is destroyed; a failure is the result.
  4. `NtCreateFile(GENERIC_READ, attributes 0, share 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT)`; failure maps through 0x91f41f18 with default 0x82da0000 (`402-` for a missing file). 0x4000-byte buffer, failure 0x82da001c.
  5. Line reader 0x91f315a0: lines end at CR or LF; a remainder starting with NUL ends the file; text that fills the buffer or ends the file without a terminator loses its last byte. Each line (0x91f35f88): command `netsim` runs this handler with no text and no connection; `linkstate` runs 0x91f35990 with no text; other lines are ignored. A failing line sets a flag.
  6. Free the buffer; with the flag set rewrite the file (NetSimWriteIniFile), then close the reader handle. The rewrite opens the file while the reader handle, opened with share 0, is still open.
  7. Text `file="%hs"` with the stored name in every case but step 1; status from the result (line failures do not change it). Clear the busy flag.
- Settings file (DoIniLine 0x91f311b8): `netsim` lines run this handler with no connection, except that a line containing `reload` is skipped while `XeKeysGetStatus()` has bit 0x8 set.
- Trace (mask 0x91f9fef4 bit 0x4): 0x91f35f88 prints `XBDM: NetSimReadIniLine '%s'\n` for every line before the command check and `XBDM: NetSimReadIniLine processing command failed (0x%08x)\n` with a failing result. NetSimWriteIniFile prints `XBDM: NetSimWriteIniFile - No filename configured.\n`, or `- Starting to write "%hs".\n` (stored name) followed by `- No memory!\n`, `- Failed to create file: 0x%08x\n` (NTSTATUS), or `- Done writing ini file.\n` after the close.
- Exports wrapping these helpers (all persisting): 215 link disconnect/restore (runs linkstate with `netsim disconnect` / `netsim restore`), 216 insert queue from a settings struct and classifier text (0x91f8bdd0 compiles the text), 217 remove one queue, 218 remove all queues, 219 modify queue, 221 queue statistics, 223 queue counts, 224 insert redirect, 225 remove redirect, 226 redirect count (0x91f38848).
- Backend requirement: the Ethernet intercept (`NetDll_XnpEthernetInterceptSetCallbacks`, `Xmit`, `Recv`, XAM 0x8e), a kernel timer and DPC, `XeCryptRandom`, `XeKeysGetStatus`, Nt file services, the netcap and ipproxy hooks.
- Status: implemented. Implementation differences, each stock misbehavior: the 0x91f93ea0/0x91f93ee0 limit loops follow each dropped frame to its new position and corrupt the stage list when one change must drop more than one frame (possible only when modifyq lowers a limit below several queued frames); openxbdm drops the last frames still counted instead. Destroy frees redirects that stock leaks; a classifier error after a redirect copy leaks the copy in stock and frees it in openxbdm. Signed division (and remainder) of i64::MIN by -1 traps in stock; in openxbdm it fails the evaluation, and constant folding fails with 0x80070216. A DNS root question name reads the uninitialized name buffer in stock (empty in openxbdm), and DNS header fields past the end of the frame read memory past the frame in stock (zero in openxbdm). Unverified: whether the console file system refuses the reload rewrite while the share-0 reader handle is open; the exact resolution of fixed items whose field is fetched again (openxbdm keeps a declared value and reads each field once per frame) [INFERENCE]; the classifier evaluator and frame parser run only on the console backend and have no host test.

## nicstats
- Handler: 0x91f34d08. Access: 0x1. Extra: 0x0.
- Syntax: dword `deviceflags` (optional, default 0xffffffff). The required-dword helper writes `missing deviceflags`, which the reply overwrites.
- Behavior:
  1. NicGetStats(deviceflags, buffer). The result is ignored and the buffer is not cleared beforehand.
  2. Reply 200 with `tb=0q%I64x rub=0q%I64x ru1b=0q%I64x ru2b=0q%I64x rmb=0q%I64x rbb=0q%I64x tf=%u ruf=%u ru1f=%u ru2f=%u rmf=%u rbf=%u tue=%u toe=%u rfe=%u rce=%u roe=%u`.
  3. Fields: u64 at +0x00, +0x08, +0x10, +0x18, +0x20, +0x28; u32 at +0x30 through +0x58 in step 4. %I64x is lower-case hex without padding.
- Backend requirement: NIC transmit and receive counters (bytes, frames, error classes).
- Status: spec complete.

## nostopon
- Handler: 0x91f44530 (tail call to 0x91f443d0 with set = 0). Access: 0x4. Extra: 0x0.
- Syntax: flags `all`, or any of `fce` (0x2), `debugstr` (0x4), `createthread` (0x1), `stacktrace` (0x8), `modload` (0x10), `pogomodstart` (0x40).
- Behavior:
  - `all`: mask 0xffffffff, text `stop on none`.
  - Otherwise the mask is the OR of the given flags.
  - The stop-on mask 0x91fadd1c is atomically ANDed with ~mask.
  - Reply `200- stop on none` or `200- OK`. With no flags the mask is 0: nothing changes and the reply is `200- OK`.
- Cross-check disagreement: the client NoStopOn says "Without any flags, disables everything". The stock server disables nothing. The client also sends `titleinit`, `titleexit` and `debugger`, which the server ignores, and cannot send `modload` or `pogomodstart`.
- Backend requirement: a stop-on event mask.
- Status: spec complete.

## notify
- Handler: 0x91f44268. Access: 0x4. Extra: 0x0.
- Syntax: dword `reconnectport` (optional); flags `debug` (0x2) and `reverse` (0x40000).
- Behavior:
  1. No context: `400- `.
  2. With `reconnectport`: getpeername on the command socket. Failure: the handler returns 0 and no reply is sent. Otherwise addr = peer IPv4 address, port = reconnectport & 0xffff. Without it, addr and port are 0.
  3. Registration (0x91f3cfe0):
     - port 0: the current socket becomes a notification channel.
     - Otherwise 0x91f3c0d8 `(addr, port, flags, 0, socket)`: the entry with the same addr and port and no socket is bound to this socket, else a new entry is created bound to it (no connect). Debugger globals are set only on success.
     - With flag 2, the server sets 0x91f9fef8 = 1 and the kd flag 0x91f975fc = 0, so debug events go to XBDM.
     - Socket slot allocation 0x91f3be18: with all 16 slots in use, a `null` line goes to every channel, failing channels are pruned, and the allocation is retried once.
  4. Registration success: the server writes `205- now a notification channel` on the socket, then `execution <state>` (0x91f391e0 type 3; state 0x91fae664 read by 0x91f2d930(0): `stopped`, `started`, `rebooting`, `pending`, `reboot_title`, `pending_title`). The connection slot releases the socket (slot socket = -1, connection object closed) and the handler returns 0, so the dispatcher sends nothing more. With reconnectport, WriteIniFile runs, which writes `notifyat addr=%d.%d.%d.%d port=%d%s` (address bytes 3, 2, 1, 0; suffix ` reverse` for flag 0x40000) for each table entry.
  5. Registration failure: `400- notification limit exceeded`.
- Client: `Client<Connected>::into_notification_channel` reads the 205 line and the `execution` line; further lines are notifications.
- Backend requirement: convert a command connection into an asynchronous notification channel; a persistent reconnect target list.
- Status: spec complete. See `parity/session.md`.
