# Kernel debugger network transport (kdnet)

Source: running kernel image read from the console (build 16547, base
0x80040000). Addresses are virtual addresses in that image. Status: framing,
session rules, state changes, manipulate requests used by `openxbdm-kd`,
debug I/O and host file I/O are reverse engineered and verified on hardware
unless marked otherwise.

## Components

| Address | Purpose |
|--------:|---------|
| 0x801b3fd0 | Debugger initialization. Selects the transport table pointer at 0x801cdb78: the network table 0x801cdb88 when the kdnet record is valid (0x801b3b78), otherwise the serial table 0x801cdb94. |
| 0x801cdb88 | Network table: init 0x801b3f70, receive 0x801ba588, send 0x801ba848. |
| 0x801cdb94 | Serial table: init 0x801b9d58, receive 0x801bad88, send 0x801bb108 (byte stream with 0xaa trailer, ids 0x80800000/1; not used over the network). |
| 0x801b5740 / 0x801b5e50 | Receive and send wrappers. Convert message headers between little-endian wire order and native order (0x801b52c0 manipulate in, 0x801b59e8 manipulate out, 0x801b57b0 state change, 0x801b5de0 debug I/O, 0x801b55b8 file I/O). |
| 0x80219560 | Network transport state. +0x08 enable, +0x0c target IP from flash, +0x10 target MAC, +0x18 host IP, +0x1c host port, +0x1e host MAC (from ARP), +0x24 encrypted flag (header offset 0x38 instead of 0x2a when set; not analyzed), +0xc0 current target IP, +0xc4 target MAC, +0xcc..+0xe0 DHCP state, +0x104 u64 sent in beacons (no writer found). |
| 0x801b8ff0 | Network bring-up: DHCP (0x801b8e68), APIPA fallback with ARP probe (0x801b89d0, 169.254.x.y from the time base), ARP for the host or gateway (0x801b87c8). Failure text is stored at +0x10c. |
| 0x801b7e00 | ARP responder for the target IP. |
| 0x801b8280 | UDP receive filter: destination MAC = target MAC, source MAC = host MAC, source IP = host IP, destination IP = target IP, protocol 17, source and destination port = host port. |
| 0x801b4990 | Break-in poll, called from the clock interrupt (0x8009ce78) while debugging is enabled. |
| 0x801b9ee8 | Trap entry (exception record, context, second-chance flag). Dispatches debug services by trap number. |
| 0x801b7138 | Stop loop: sends a state change, then serves manipulate requests until a continue. |
| 0x801bb368 / 0x801bb5b0 | Breakpoint insert / remove. Table at 0x802244d0: 32 entries of 12 bytes {u8 flags, u32 original word at +4, u32 address at +8}. Breakpoint word 0x0fe00016 (`twi 31, r0, 22`, stored at 0x802216c8). Handle = index + 1. |

## Addressing

The kernel uses its own MAC (kdnet record) and IP: DHCP, otherwise an APIPA
address that is written back to the flash record. The host must reach the
target IP on the local link and send from the configured host port.

## Datagram types

| Length | Direction | Meaning |
|-------:|-----------|---------|
| 12 | target to host | Beacon, every 3 s while idle or waiting (0x801ba418): u64 LE (+0x104 of the state, observed 0), u32 LE host IP. |
| < 16, first byte `b` | host to target | Break-in. In the poll it stops the kernel; while the kernel is already stopped it is latched (0x802196a7) and stops the kernel again right after the next continue. |
| >= 16 | both | Packet. |

## Packet header (little-endian)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0x00 | 4 | Leader: 0x30303030 data, 0x69696969 control |
| 0x04 | 2 | Packet type |
| 0x06 | 2 | Payload byte count (max 0x580, 0x801cd7f4) |
| 0x08 | 4 | Packet id |
| 0x0c | 4 | Checksum: 32-bit sum of payload bytes |

Packet types: 2 manipulate, 3 debug I/O, 4 acknowledge, 5 resend, 6 reset,
7 state change, 8 break-in poll (internal), 9 (message 0x3330, not
analyzed), 0xb file I/O. Control packets (4, 5, 6) have no payload.

## Session rules

Receive (0x801ba588), send (0x801ba848):

- The kernel numbers its data packets from 0 and adds 2 after each
  acknowledged packet (0x801cdb80). It expects the host's next id in
  0x801cdb84 (initially 0x80000000) and adds 2 per accepted packet; the id
  of an accepted packet is not checked.
- Data packet accepted: acknowledge with the same id. Wrong type, byte count
  above 0x580, or checksum mismatch: resend request.
- Waiting for an acknowledgement: an acknowledge with the current id ends
  the wait. A data packet with the expected id counts as acknowledgement and
  is answered with a resend request; other data packets are acknowledged and
  dropped. Reset: expected id = reset id, reply reset with the kernel's next
  id, resend. Resend: resend.
- Timeout 0.5 s per attempt. Debug prints (0x3230), load symbols (0x3031),
  file I/O open (0x3430) and type 9 give up after 3 retries and clear the
  debugger-present flag (bit 0x100 of 0x801c0030); other packets are retried
  forever.
- Debugger present (bit 0x100) is set by any received datagram and by an
  acknowledgement. Without it, stops send their state change once and do not
  wait.

## State change (type 7)

0xf0-byte header; fields below +0xc4 little-endian, control report from
+0xc4 big-endian (0x801bb6d8).

| Offset | Size | Field |
|-------:|-----:|-------|
| 0x00 | 4 | 0x3030 exception, 0x3031 load symbols |
| 0x04 | 2 | Processor level (0) |
| 0x06 | 2 | Processor |
| 0x08 | 4 | Number of processors |
| 0x10 | 8 | Thread (sign-extended) |
| 0x18 | 8 | Program counter (sign-extended context IAR) |
| 0x20 | 4 | Exception code / path length |
| 0x24 | 4 | Exception flags |
| 0x28 | 8 | Chained record / image base |
| 0x30 | 8 | Exception address / process id |
| 0x38 | 4 | Parameter count / image checksum |
| 0x3c | 4 | - / image size |
| 0x40 | 8 x 15 | Exception parameters / +0x40 byte unload flag |
| 0xb8 | 4 | First chance |
| 0xc0 | 4 | Instruction byte count (0x10) |
| 0xc4 | 16 | Instructions at the program counter |
| 0xd4 | 4 | CR |
| 0xd8 | 8 | CTR |
| 0xe0 | 4 | LR |
| 0xe4 | 8 | GPR 3 |

Load symbols carry the NUL-terminated image name as data. Building the
report (0x801b6618) removes every breakpoint inside the 16 reported
instruction bytes (0x801bb658), so the breakpoint that caused a stop is
already gone when the host sees it.

Trap numbers (`twi 31, r0, N`; exception parameter 0 is the instruction):
0x14 print, 0x15 prompt, 0x16 breakpoint, 0x17 load symbols, 0x18 unload
symbols, 0x19 assertion (code 0xc0000420), 0x1a break/ignore/terminate
prompt, 0x1b RIP, 0x1c (calls 0x801b41b0, not analyzed).

The kernel does not advance the program counter past a breakpoint trap
when it continues (0x801b9fdc advances only for service 0x1b). The host must
step over hard-coded traps, for example the break-in trap in 0x800af588.

## Manipulate (type 2)

Header 0x38 bytes: +0 api, +4 processor level, +6 processor, +8 status,
+0x10 api fields. Data follows. Dispatcher jump table at 0x801b7204 indexed
by the byte table at 0x8006b308.

| Api | Handler | Fields | Notes |
|----:|--------:|--------|-------|
| 0x3130 | 0x801b60c0 | +0x10 u64 address, +0x18 u32 count, reply +0x1c actual | Count clamped to 0x548. |
| 0x3131 | 0x801b6158 | +0x10 address, data | Reply +0x1c actual. |
| 0x3132 | 0x801b61e8 | Reply data 0xa40 context | Exceeds the packet limit over the network; overruns the transmit buffer and stops the transport. Do not use. |
| 0x3133 | 0x801b62a8 | Data 0xa40 context | Same size problem. |
| 0x3134 | 0x801b6520 | +0x10 address, reply +0x18 handle | Address must be 4-aligned. |
| 0x3135 | 0x801b65a0 | +0x10 handle | Fails if the entry is free. |
| 0x3136 | (loop) | +0x10 status | Sign bit clear: handled, resume at the context IAR. Set: not handled. |
| 0x3137 / 0x3138 | 0x801bb708 / 0x801bb890 | Control space: offset < 0xa60 into the per-processor block 0x80227680 + n*0xa60, or 0xfffff000..0xfffff003 special values | |
| 0x3139 / 0x313a | 0x801bb970 | | Always 0xc000000d. |
| 0x313b | | | Reboot (0x8008b9b8(2)). |
| 0x313c | | +0x10 status | As 0x3136; control-set hook 0x801bb700 is empty. |
| 0x313d / 0x313e | 0x801b66c8 / 0x801b67c0 | Physical memory read/write | |
| 0x3146 | 0x801b6890 | Version: 0x10c, build, protocol 6, flags 0xb, machine 0x1f2, +0x1a 0xc, +0x20 kernel base, +0x28 0x801c07cc, +0x30 0x801cdb10 | |
| 0x3147 / 0x3148 | 0x801b6990 / 0x801b6ac8 | Breakpoint lists | |
| 0x3149 | | | Bug check 0xe2. |
| 0x3150 | 0x801b43e8 | Processor in header | Switch processor. |
| 0x3151 | 0x801b6940 | | Always 0xc0000001. |
| 0x3156 | 0x801b6b78 | +0x10 start, +0x18 length, +0x20 pattern length | Search memory. |
| 0x3159 | 0x801b6fd0 | | Calls 0x801b6e30 when 0x802196b8 is set; not analyzed. |
| 0x315f | 0x801b6350 | +0x10 offset, +0x14 length, reply +0x18 | Context range read. Length is not clamped; keep each range at most 0x548. |
| 0x3160 | 0x801b6438 | +0x14 offset, +0x18 length, data | Stages into 0x8022b4c0; commits the whole record when a range ends at 0xa40. |

## Context record (0xa40 bytes, big-endian, not byte-swapped)

From 0x80097910 (trap frame to context): +0 flags (1 control, 2 floating
point, 4 integer, 0x10 vector), +4 MSR, +8 IAR, +0xc LR, +0x10 CTR (u64),
+0x18 GPR0-31 (u64), +0x118 CR, +0x11c XER, +0x120 FPSCR (u64), +0x128
FPR0-31, +0x228 trap frame +0x1bc (not analyzed), +0x230 0x810 bytes of
vector state (layout not analyzed).

## Single step

There is no trace support: setting MSR[SE] in the context leads to bug check
0x2b from the trace handler (0x8009c7fc). The host steps by inserting
breakpoints at the successors of the current instruction and continuing.

## Debug I/O (type 3)

Debug I/O header 0x10: +0 0x3230 print / 0x3231 prompt, +6 processor, +8
length, +0xc prompt reply capacity; text follows. A prompt waits for a
type 3 reply with the reply text.

## Host file I/O (type 0xb)

Senders: open 0x801b3748, read 0x801b3950, close 0x801b3a90. Field
conversion 0x801b55b8 (requests and replies; a reply's fields are converted
for the api in the reply header, so a reply must echo the api). 0x3432 is
converted like a read but has no sender. Each sender holds the debugger lock
(0x801b7028 / 0x801b70c0) for the whole exchange.

Header 0x40 bytes, little-endian; u64 fields are true little-endian:

| Offset | Open 0x3430 | Read 0x3431 | Close 0x3433 |
|-------:|-------------|-------------|--------------|
| 0x00 | api | api | api |
| 0x04 | reply status | reply status | reply status |
| 0x08 | u32 desired access (0x120089) | u64 handle | u64 handle |
| 0x0c | u32 file attributes (0x80) | | |
| 0x10 | u32 share access (3) | u64 file offset | |
| 0x14 | u32 create disposition (1, open) | | |
| 0x18 | u32 create options (0x20) | u32 length | |
| 0x20 | reply: u64 handle | | |
| 0x28 | reply: u64 file size | | |

Request fields not listed are uninitialized stack contents, including the
status word.

- Open: data is the NUL-terminated UTF-16LE path. The sender refuses names
  whose doubled byte length exceeds 0x540 with 0xc000000d; the terminator
  is not counted, so a 0x2a0-byte name gives a 0x582-byte payload, above
  the packet limit (not observed). The path is built from an ANSI string by
  widening each byte (0x801a7af0 only swaps the bytes of each unit). The
  module loader hook 0x8009f430 prefixes `host:` to the object name, for
  example `host:\Device\Flash\xbdm.xex`. On success the kernel stores the
  reply handle in a 16-entry table at 0x80222040, where zero marks a free
  entry, so a handle must be nonzero. The kernel's handle is the table
  index + 1. The loader hook passes no size pointer and reports a size of
  0xfffffd to its caller (meaning not analyzed); the shadow-boot loader
  (0x80081168) uses the reply size to allocate memory. Reply data, if any,
  goes to a 0x1000-byte buffer at 0x802234d0 and is ignored. Any error
  status makes the loader open the object from its own device (0x80090920).
- Read: the length is min(remaining, 0x540) (0x801cd7f4 - 0x40). The reply
  carries the data directly after the 0x40-byte header; the kernel takes
  the count from the payload length (0x801ba588 returns payload length -
  header length) and copies at most the request's length. A longer reply
  fails the checksum, which covers the whole payload but is computed over
  the copied bytes, and is answered with a resend request. A short reply is
  accepted; the kernel requests the rest. A successful reply with no data is
  repeated forever (the remaining count does not change), so end of file
  must be an error status (the host uses 0xc0000011). An error status ends
  the read with the bytes received so far. The loader reads 0x800-byte
  units, so requests come as 0x540 + 0x2c0.
- Close: only the status is used; success frees the table entry.

Flow: the request is a normal data packet (acknowledged by the host). The
sender then waits for the reply without a deadline: a receive timeout only
repeats the receive. Any other receive failure resends the whole request.
The open request belongs to the packets that give up after 3 send retries
and clear the debugger-present flag; reads and closes are retried forever.
Without the debugger-present flag the open fails at once with 0xc0000354
and nothing is sent.

Paths requested during a stock boot (build 16547, no hard disk), in order:

```
host:\Device\Flash\bootanim.xex
host:\xboxromw2d.bin                  (shadow boot, 0x80081348)
host:\Device\Cdrom0\xam.xex
host:\Device\Harddisk0\Partition1\xam.xex
host:\Device\Flash\xam.xex
host:\Device\Harddisk0\Partition1\xbdm.xex
host:\Device\Flash\xbdm.xex
host:\Device\Harddisk0\Partition1\602215511305_secexp.xex
host:\Device\Flash\xstudio.xex
host:\Device\BuiltInMuUsb\Storage\602215511305_secexp.xex
host:\Device\BuiltInMuSfc\602215511305_secexp.xex
host:\Device\Harddisk0\Partition1\ximecore.xex
host:\Device\Flash\ximecore.xex
host:\Device\Harddisk0\Partition1\Xam.Community.xex
host:\Device\Flash\Xam.Community.xex
host:\Device\Harddisk0\Partition1\Xam.DataCenterAgent.xex
host:\Device\Flash\Xam.DataCenterAgent.xex
host:\Device\Harddisk0\Partition1\cert.xex
host:\Device\Flash\cert.xex
host:\Device\Flash\xshell.xex           (several times)
host:\Device\Flash\huduiskin.xex
```

Serving `host:\Device\Flash\xbdm.xex` from a host file was verified: the
kernel read all 258048 bytes, closed the file, loaded the image and XBDM
answered on port 730. The load-symbols stop of an image arrives after the
image is mapped and before its entry point runs; memory written during that
stop persists.

## Nuances

- A break-in datagram sent to a stopped kernel is latched and causes a new
  stop right after the next continue. Wait for pending retransmissions before
  sending one.
- With a host present the kernel waits for the host at every module load,
  print and stop; a host must stay responsive or close its socket. A file
  request is never abandoned once acknowledged.
- A file reply is accepted whatever its packet id, so a stale host packet
  retransmitted after a lost acknowledgement would be taken as the answer
  to the next request. The kernel sends a new file request only after
  consuming the previous reply, so the host drops its outstanding packet
  when one arrives.
- Breakpoints in the kd poll path (0x801b4990 and its callees) hang the
  transport when stepped through.
