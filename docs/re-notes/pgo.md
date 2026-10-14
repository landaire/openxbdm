# PGO instrumentation runtime

Stock code 0x91f6b900..0x91f71600, the `pogo.ini` loader 0x91f3e038 with
its line handler 0x91f3dcb8, and the `pogoctrl` handler 0x91f4a458.
Profile-guided-optimization instrumented titles call the exports below to
register their modules and to record call, path, and value profiles; the
runtime writes the profiles to `.pgc` files. Status: reverse engineered
completely and reimplemented in
`crates/openxbdm-server/src/commands/hardware/pgo.rs` (pure logic) and
`crates/openxbdm-server-xbox360/src/backend/hardware/pgo.rs` (runtime and
exports). Deviations are listed in parity/hardware.md and nuances.md.

## Globals

| Address | Meaning |
| --- | --- |
| 0x91fa38b4 | Module record list head, newest first. Pushed without a lock other than the registration lock; walked without one. |
| 0x91fa3ac0 | Registration critical section, initialized on the first registration (0x91fa3ae0 = initialized). |
| 0x91fa36a8 | Base profile name (UTF-16, 0x104 units) from export 113. |
| 0x91fa3adc / 0x91fa38b0 | Module header and module word table from export 113. |
| 0x91fa3ae1 | A full-buffer sweep runs. |
| 0x91fa3ae4 | Thread record list head. |
| 0x91fa3ae8 | Sweep event: CreateEventA(NULL, manual, signaled), created once. |
| 0x91f9904c | TLS index of the thread records; KeTlsAlloc runs on every new registration and replaces it. |
| 0x91fa3af4 | 0x20000-byte table `t[i] = reverse16(i) ^ 0xaaaa`, allocated once and refilled on every registration. Call tree keys are `t[lo] << 16 | t[hi]`, which is `reverse32(key) ^ 0xaaaaaaaa`. |
| 0x91fa36a0/1/2 | `ValidateVPLE`, `ValidateEPLH`, `ValidateVPLH` (default 0). |
| 0x91f99050/1 | `EnableSweepOnOverflow`, `EnableSweepFullBuffer` (default 1). |
| 0x91f99052 | Enable byte tested by export 112; nothing writes it (always 1). |
| 0x91fa3ae2 | Set by every registration; nothing reads it. |
| 0x91fa36a4 | Page size 0x1000. |

Failures go through 0x91f71120 -> 0x91f74280 (UTF-16 text to ANSI, raw
debug print `twui 0x14`) and then 0x91f71078 = KeBugCheck(0x1e). The texts
are the wide strings referenced from 0x91f98fc8..0x91f99048. The write
warnings of the profile writer only print.

## Module record (0x6d0 bytes, title heap, HEAP_ZERO_MEMORY)

| Offset | Field |
| --- | --- |
| +0x00 | next |
| +0x04 | the module's 24-dword probe dispatch table |
| +0x08..+0x67 | dispatch values while counting (24 dwords) |
| +0x68 | address inside the module (identity) |
| +0x6c | `AllocScale` (1 at creation) |
| +0x70 | `MaxTitleMemory` |
| +0x74 | header +8 |
| +0x7c | count block |
| +0x80 | byte: dead (a dispatch table write faulted, or another module took the address) |
| +0x81 | byte: counting requested |
| +0x84 | dword: profile names carry the phase |
| +0x88 | profile base path (UTF-16, 0x104) |
| +0x290 | phase (UTF-16, 0x104, padded with zeros; may be unterminated) |
| +0x498 | module file name (UTF-16, 0x104) |
| +0x6a0 | 1 |
| +0x6a4 / +0x6a8 / +0x6ac / +0x6b0 | header +0x18 (count slots), +0x14 (call trees), +0x1c (value lists), *(header +0x58) (words) |
| +0x6b4 | header +0x60 (call tree descriptors, 8 bytes: u16 counters, u16 value lists) |
| +0x6b8/+0x6bc/+0x6c0 | stub routines (export 112 arguments 3-5) |
| +0x6c4 | never written (0) |
| +0x6c8 | byte: header +0x10 bit 0x08000000 |
| +0x6c9 | byte: extended count block (1 at creation; `StandardPGC=1` clears it) |
| +0x6ca | byte: `TestCounterOverflow` |
| +0x6cc | module interface (export 112 argument 7) |

Start (0x91f6c090) stores +0x08.. into the dispatch table; stop
(0x91f6c140) stores stub 0 into entries 0-5 and 21-23, stub 1 into 6-8 and
12-17, stub 2 into 9-11, and leaves 18-20. Both write each entry with an
atomic exchange under an exception handler that sets +0x80.

## Module header (export 113 argument 2)

`'POGO'` (0x4f474f50) at +0, version 0x2b at +4 (otherwise fatal
`Invalid header signature` / `Invalid header version`), +8 module word,
+0x10 flags, +0x14 call trees, +0x18 count slots, +0x1c value lists, +0x58
word count, +0x60 call tree descriptors.

## Module interface (export 112 argument 7)

Words 0..9 become dispatch entries 0,1,3,4,6,7,9,10,12,13 (2, 5, 8, 11 and
14-23 are 0). For an extended block words 0, 1, and 3..9 are first copied
from export 112 argument 8 (word 2 is left). *(+0x34) receives the count
block and *(+0x38) its counters. *(+0x3c), *(+0x44)..*(+0x58) receive the
probes 182, 184, 190, 187, 185, 191, 188 (extended) or 181, 183, 189, 186,
183, 189, 186 (standard); the image loads 8 bytes at each export's entry and
stores the low word, so the slot receives the export's second instruction
word, not its address.

## Count block

Allocated with NtAllocateVirtualMemory(MEM_COMMIT, PAGE_READWRITE) of the
reserved size when the module registers; the header is laid out by
0x91f6bd68 (`CountBlockHeader::new`, snapshot-tested).

| Offset | Field |
| --- | --- |
| +0x00 | `"OGOP"` bytes |
| +0x04 | version: 0x030000c0 extended (4-byte counters), else standard 0x11000000 (8-byte counters) |
| +0x08 | module word |
| +0x0c | bytes in use (atomic bump pointer) |
| +0x10 | FILETIME of creation or last reset, whole milliseconds (GetSystemTime + SystemTimeToFileTime) |
| +0x18/+0x1c | count slots + 1 / offset (after the 0x78 or 0x2a0-byte header) |
| +0x20/+0x24 | value lists + 1 / offset (heads 4 bytes extended, 8 standard) |
| +0x28 | entries inserted by 183 and 186 |
| +0x2c/+0x30 | call trees + 1 / offset (8-byte descriptors; descriptor 0 unused, +4 holds the tree root) |
| +0x34 | entries inserted by 181 |
| +0x38/+0x3c | words / offset (copied from export 113 argument 3) |
| +0x50 | byte 1 |
| +0x51 | byte: record +0x6a0 != 0 |
| +0x54 | committed size (page aligned) |
| +0x58 | reserved size |
| +0x5c | extended: byte, why the profile is written (1 `pogoctrl`, 2 export 110, 3 shutdown, 4 full buffer, 5 overflow); standard: dword 1 |
| +0x5d | extended: byte 1, 0 for the shutdown profile |
| +0x5e | extended: byte, counts reset after this profile |
| +0x5f, +0x60 | extended: bytes set for a full-buffer profile; standard +0x60: dword 1, 0 for the shutdown profile |
| +0x61 | byte: a probe dropped data |
| +0x64 | thread records created |
| +0x6c | generation, raised by each full-buffer sweep |
| +0x70 | probes running on threads without a record |
| +0x74 | extended: record +0x6c4 (the payload given to failed contexts) |

Reserved size: standard `align(4 * (used + 0xf0 * lists + 7 * sum(counters * 8 + lists_i * 0xf8 + 0x10)))`,
then scaled by `AllocScale` plus 3 when +0x6c8 is set; extended
`align(MaxTitleMemory)` or `used + 0xc * lists + 0xb * sum(counters * 4 + (lists_i + 1) * 16)`,
at least `used + max(counters * 4 + (lists_i + 4) * 4 + (lists_i ? 0xc : 0))`.
`TestCounterOverflow` fills `width * count slots` bytes of counters with 0x7f.

Entry allocation (inlined in every probe): atomic add to +0x0c; past +0x54
the block grows to `align(offset + 0x1000)` (0x91f6bc18, KeBugCheck with an
empty text past +0x58). An extended block with `EnableSweepFullBuffer`
whose request passes +0x58 is swept instead: the thread leaves its probe,
takes the registration lock, and if still full stops probes (0x91f6c8d8:
reset the sweep event, set 0x91fa3ae1, raise +0x6c, wait until no other
thread record is inside a probe and +0x70 is 0, freeing records of ended
threads), stops counting, writes a profile (kind 4), clears every count
and entry (0x91f70f88), restarts counting, and signals the event.

## Thread records (0x10 bytes, title heap)

`{state, duplicated thread handle, next, thread id}`; state is the record's
address inside a probe and r13 outside. Only threads whose KTHREAD +0x72
byte is 1 get one (0x91f713b8); others count in block +0x70.

## Probe context (exports 182, 185, 188, 191, 193)

`{key, thread record, block, generation, payload, descriptor}`. Export 182
fills all but the key, which the caller stores; 193 refreshes the payload
when the generation changed.

## Exports

| Ordinal | Stock | Signature | Behavior |
| --- | --- | --- | --- |
| 106 | 0x91f70628 | `u32 (u32 address)` | 0x91f6bb40 without a name: never matches, returns 0. |
| 107 | 0x91f3e038 | `HRESULT (char *object_path, record)` | Load `pogo.ini`; `pogomodstartup` with stop when `stopon pogomodstart`. 0x82da000c for a path of 0x140 bytes or more, or a drive path without `\` before offset 0xfc; else 0x02da0000. |
| 108 | 0x91f70630 | `HRESULT (record or 0)` | Set +0x81, start unless dead. 0x82da0017 for an unknown record. |
| 109 | 0x91f706d0 | `HRESULT (record or 0)` | Clear +0x81, stop unless dead. |
| 110 | 0x91f70918 | `HRESULT (char *phase or NULL, u32 reset, record or 0)` | 0x91f70880 with kind 2. |
| 111 | 0x91f6cba8 | `void (void)` | Fatal `IrtClientAbort`. |
| 112 | 0x91f703f8 | `void (table, address, stub0, stub1, stub2, unused, interface, words)` | Stop the table with the stubs; register (or revive the record of the same address and module name, which only reconnects the interface); start or stop by +0x81; keeps the caller's last error. |
| 113 | 0x91f6b900 | `void (char *base_name, header, words)` | UTF-8 to 0x91fa36a8 (fatal `Could not read base filename from object.` when it does not fit). |
| 114 | 0x91f6d5d0 | `void (u32 address, wchar_t *phase)` | Lookup without a name never matches: no effect. |
| 115 | 0x91f6d6c0 | `void (u32 address, char *phase)` | Fatal `Could not convert sweep phase name to Unicode.` for 0x104 bytes or more, else as 114. |
| 181 | 0x91f6f7d0 | `u64 *(block, descriptor, u32 key)` | Path tree (keys transformed as above, links +4 smaller / +8 larger) entry with `(counters + lists) * 8 + 0x10` bytes; increments slot 0 (64-bit) when the descriptor has counters; returns the slots. +0x34 counts insertions. |
| 182 | 0x91f6fb18 | `void (block, descriptor, u32 key, context)` | Call tree entry of `(counters + lists) * 4 + 0x10` bytes; increments 32-bit counter 0, which wraps (the `addic.`/`ble` toward export 192 tests the 64-bit sum of a zero-extended word and is never taken); fills the context. |
| 183 | 0x91f6dd18 | `void (block, list, u64 value)` | Sorted list at list +4 of `{u64 value, u64 count, next}`; +0x28 counts insertions. |
| 184 | 0x91f6e030 | `void (block, list, u64 value)` | Value must be a zero- or sign-extended 32-bit value (else block +0x61). Sorted list of `{value, count, next}` under a head word at list +0 that also holds a 4-bit insertion counter in bits 30-31 and 0-1. |
| 185 | 0x91f6e448 | `void (block, list, u64 value, context)` | As 184 for a list inside the context's call tree entry, rebased after a sweep. |
| 186 | 0x91f6e8f8 | `void (block, list, u64 value)` | As 183 with list +0 counting entries; past 10 entries new values count as 0x7fffffff. |
| 187 | 0x91f6ec48 | `void (block, list, u64 value)` | As 184; every insertion raises the head counter; past 10, 0x7fffffff. |
| 188 | 0x91f6f148 | `void (block, list, u64 value, context)` | 185 with the limit of 187. |
| 189 | 0x91f6f6f0 | `void (block, list, u64 value, table)` | 183 with the bucket of value in a range table (+4 count, +6 flags: 1 wide, 2 signed, +8 sorted entries). |
| 190 | 0x91f6f740 | `void (block, list, u64 value, table)` | 184 with the bucket. |
| 191 | 0x91f6f790 | `void (block, list, u64 value, table, context)` | 185 with the bucket. |
| 192 | 0x91f70920 | `void (block)` | Counter overflow: fatal `counter overflowed 2^31` unless `EnableSweepOnOverflow`; then profile with reset, kind 5. The image itself never calls it (see 182). |
| 193 | 0x91f6d940 | `u32 (context)` | Wait out a sweep, find or insert the context's key again; 1, or 0 with payload = block +0x74. |

64-bit values arrive in one register. The bucket search 0x91f6ca28 keeps
its below flag once set: an exact match at entry i is `2i + 2` only when no
step went down; a miss is `2i + 1` after any downward step, else `2i + 3`.

## Profiles

0x91f70880 / 0x91f70770 (snapshot): stop counting; with a phase convert it
from UTF-8 into +0x290 (wcsncpy 0x104) and set +0x84, without one clear
+0x290 only; for an extended block set +0x5c = kind and +0x5e = reset;
write; clear them; with reset store the time and clear counts
(0x91f70e40, entries kept); start counting, also for a stopped module.

Base path (0x91f6d8a0 / 0x91f6d298 / 0x91f6cd40): the base name with `/` as
`\`, joined to the lowercased module file name: a name with a drive stands
alone, a rooted name takes the module's drive, a relative name replaces the
module's file name. `OutputPath` replaces the directory (0x91f70b18).

Writer 0x91f6d420: names are `<base>` or `<base>-<phase>` (fatal
`BuildPath: path too long` past 0x104 units), then `!<n>.pgc` from n = 1:
the UTF-16 name converts to UTF-8 and `!%u.pgc` is printed at the name's
length in units. The directory scan for `<name>!*.pgc` compares the
character after the name, always `!`, so numbering always starts at 1; the
file is created new (GENERIC_WRITE), and when that fails an open of the
existing file decides between the next number and giving up. When the
module directory fails the name moves under
`\Device\Harddisk0\Partition1\DEVKIT` with the base path's last component;
when that fails too: fatal `Unable to write PGC file`. The file receives
min(+0x0c, +0x54) bytes of the block, a flush, a seek to 0x52 and the byte
1, and is closed.

Shutdown 0x91f6d7f8 (last call of the title-terminate routine 0x91f32398):
for each record with a block stop, clear +0x84, mark the block (extended
+0x5d = 0, +0x5c = 3; standard +0x60 = 0) and write; then forget the list,
thread records, event, table, and TLS index.

## pogo.ini (0x91f3e038, lines 0x91f3dcb8)

The module's object path converts to a drive path; `pogo.ini` in its
directory, else `xe:\pogo.ini`, is read with the settings reader
0x91f315a0 (0x1000-byte buffer). `[name]` opens the module's section when
it equals the object path, the drive path, or, when the line has no `\`,
the file name (case-insensitive); `;` lines are comments. Inside, `key=value`
keys match as case-insensitive prefixes in this order: `AllocScale`
(decimal, `strtoul` then end, space, tab or `;`), `OutputPath` (translated
drive path, else as written), `DisableDataCollection` (`1`: export 109),
`StandardPGC`, `TestCounterOverflow`, `MaxTitleMemory` (decimal),
`ValidateEPLH`, `ValidateVPLH`, `ValidateVPLE`, `EnableSweepOnOverflow`,
`EnableSweepFullBuffer` (first character `1`). Options need a registered
record without a block (0x82da0017 / 0x82da0019, ignored by the loader).
