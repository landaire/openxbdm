# Parity: network domain

Specs: `commands/group3.md` (getsockinfo), `group4.md` (getxnkeyinfo,
getxnqoslookupinfo, getxnsecassocinfo, ipproxy), `group5.md` (linkstate,
netcap, netsim, nicstats), `group8.md` (xhttpproxy), `dispatcher.md` (control
codes 0x0b..0x16, 0xa5..0xa7).
Server: `crates/openxbdm-server/src/commands/network.rs` and
`commands/network/{ipproxy,netcap,netsim,xhttpproxy}.rs`. Host mock:
`crates/openxbdm-server-host/src/backend/network.rs` and `backend/network/`.
Xbox backend: `crates/openxbdm-server-xbox360/src/backend/network.rs` and
`backend/network/`. Tests: `crates/openxbdm-server-host/tests/network.rs` and
`tests/network/`. Client: `crates/openxbdm-client/src/commands/perf.rs`
(`GetSocketInfo`).

| Command | Wire | Host mock | Xbox backend |
| --- | --- | --- | --- |
| getsockinfo | matches; lines limited to 255 characters | socket table, unavailable/out-of-memory injection, per-connection snapshot | `NetDll_XnpGetActiveSocketList(3)` into a 0x800-record pool buffer |
| getxnkeyinfo | matches, version gate 0x200a9a00 | key table | XAM ordinal 0x82 via `XexGetProcedureAddress`, 0x400 records |
| getxnqoslookupinfo | matches, including truncation at 255 characters | lookup table | XAM ordinal 0x83: count query (0 or 0x2747), count + 1 records |
| getxnsecassocinfo | matches | association table | XAM ordinal 0x81, 0x400 records |
| linkstate | matches (`state=`, `set, ...`, 407/400 `err=`) | link status and forcing masks, error injection | `XNetGetEthernetLinkStatus(2)`, `XNetSetOpt(2, 0x1395, {and, or}, 8)` |
| nicstats | matches (`%I64x` lower case, unpadded) | counters, query log | `NicGetStats(deviceflags, 8-aligned 0x60-byte block)` |
| xhttpproxy | matches, including `cleared`/` applied`/` applying` texts, 204 certificate upload, settings lines | proxy list with references | pool list with the stock entry layout under a critical section; control codes 0xa5..0xa7 |
| ipproxy, netcap, netsim | see below | | |

Settings file: `staticip use=%d, addr=0x%08x`, `subnet addr=0x%08x`,
`gateway addr=0x%08x` (always written; `use=1,` reads back through the
getter's prefix rule) and `xhttpproxy...` lines for active, persistent,
complete entries, oldest first, certificate hex in 0x1ff-byte chunks. Title
termination (`Server::title_terminated`, stock 0x91f38480) drops temporary
title proxies and stops a non-persistent capture.

## Remaining differences

- getsockinfo/getxn*: stock leaks the snapshot when a connection drops
  mid-listing; openxbdm frees it on the connection's next snapshot.
- nicstats: a failed `NicGetStats` prints zeros where stock prints stale
  stack contents.
- xhttpproxy from the settings file with `certsize` and no `cert`: stock
  writes through a NULL context; openxbdm drops the entry and fails the line.
- Exports that change server state (163, 164, 216-219, 224, 225) run their
  helper on the server thread through `dispatcher::call_on_server`. Called
  on the server thread itself (from a command processor) or above passive
  level they return 0x82da0000 without running; stock runs the helper
  inline (above passive level stock's file write faults). Exports 216 and
  224 compile the text and build the blob on the caller's thread first, as
  stock does.
- Classifier text compiler (exports 216, 224), where stock faults: rule 4
  or 5/6 (`name[...]`, `name(...)`) reduced over a non-name operand, which
  only happens after an earlier builder error has freed operands, makes
  stock read the operand's value word as an item position; for an operator
  node, a pointer word, or a narrow integer word with stale bytes it
  faults, and openxbdm returns 0x8007048a. After a constant index stock
  then drops a non-string operand as a string reference and faults;
  openxbdm drops nothing. Signed division of `i64::MIN` by -1 traps in
  stock and wraps in openxbdm. Case-insensitive string functions on bytes
  0x80..0xfe raise a CRT assertion in stock; openxbdm compares the byte
  unchanged.

## Exports

Xbox only: `crates/openxbdm-server-xbox360/src/backend/network/exports.rs`.
Structure codecs and blob builders: `commands/network/netsim/api.rs` (unit
tested). The helpers are the command cores (`netcap::start_capture`,
`netcap::stop_capture`, `netsim::{insert_queue, remove_queues,
modify_queue, insert_redirect, remove_redirects}`, `network::link_error`)
called with persistence on and no reply text. Exports 216 and 224 compile
their text with `netsim::classifier::compile_text` (see below).

| Ordinal | Stock | Arguments | Behavior |
| --- | --- | --- | --- |
| 163 | 0x91f384d0 | name, maxframedata, buffersize, flags | flags bit 8 from the system process (process type 1): 0x82da0022; else the `netcap start` core, kernel statuses mapped |
| 164 | 0x91f38530 | - | the `netcap stop` core result (0x82da0026 for lost frames, 0x82da0023 when idle) |
| 215 | 0x91f38540 | disconnect | reads the link state, then `disconnect` or `restore` flags; 10022 gives 0x82da0007, other errors 0x82da0000 |
| 216 | 0x91f38570 | inbound, index (-1 appends), type, settings*, classifier text*, index out* | settings (0x24 bytes, size dword 0x24) validated (0x82da0017), text compiled unless null (compiler status returned raw; a constant true program adds no classifier, constant false is 0x82da0010), blob built with the type byte when type != 0 (0x82da0026 when it exceeds 0xdc bytes); the insert result is mapped to facility 0x2da and the index (-1 on failure) stored |
| 217 | 0x91f38650 | inbound, index (-1 all) | `removeq` of one direction |
| 218 | 0x91f38670 | inbound, outbound, removed out* | `removeq` of every queue; count or 0 stored |
| 219 | 0x91f38688 | inbound, index, settings* | settings validated, blob built without the type byte, `modifyq` |
| 221 | 0x91f38718 | inbound, index, counters* | no instance 0x82da0002; counters size dword not 0x20 or bad index 0x82da0017; writes `{u64 0, u64 total bytes, u64 dropped bytes, u32 total packets, u32 dropped packets}` |
| 222 | 0x91f36eb8 | inbound, index, type out*, settings out* | no instance 0x82da0002 (unmapped); settings size dword not 0x24 or bad index 0x82da0017; writes the type and the stored settings with a zero size dword |
| 223 | 0x91f38728 | inbound out*, outbound out* | queue counts, 0 without an instance; always 0x02da0000 |
| 224 | 0x91f38738 | index, match address*, match port, target address*, target port, classifier text*, sessions, index out* | null addresses read as 0.0.0.0; no target address and target port (low 16 bits) 0, or sessions (32 bits) above 500: 0x82da0017; then as 216 with the redirect blob |
| 225 | 0x91f38838 | index (-1 all), removed out* | `removeipv4redir`; count or 0 stored |
| 226 | 0x91f38848 | count out* | redirect count; always 0x02da0000 |

Queries 221, 222, 223, 226 read the instance on the caller's thread
(the instance pointer is a static), unsynchronized with its destruction,
as stock.

### Classifier text compiler

`commands/network/netsim/classifier/{compile,grammar,variant}.rs`,
`classifier::compile_text`. Stock only compiles text in exports 216 and
224 (0x91f8bdd0 has no other caller); the commands take hex blobs. The
library runs with feature set 0xdd and compile flags 0x27, which fixes
every option the port specializes on (no floats, no escapes, names become
items, built-in string functions only).

- Lexer 0x91f85af0: operators, `//` and `/* */` comments, `"..."` strings
  (no escapes), keywords `TRUE FALSE true false`, address literals
  (0x91f858e8: MAC `xx-...`, IPv4, IPv6 with eight groups, scanned past
  operators once every separator is seen, last group may be empty),
  integers (decimal, `0x`, suffixes `u`, `l`, `ll` in stock's order rules;
  i32 unless the value, more than 10 decimal or 8 hex digits, or `ll`
  needs 64 bits; `.` and `f` start a disabled float literal: 0x80070545).
  Lexer errors replace the status and end the input.
- Parser 0x91f86688: Berkeley yacc 1.9 driver, tables at
  0x91f0b020..0x91f0c09e copied into `grammar.rs` (43 rules, 77 states,
  500-entry stack: 0x800703e9). The first syntax error (0x80070545) is
  kept; the parser keeps reducing after builder errors, so later rules can
  pop missing operands (0x800710d2) and replace the status.
- Builder 0x91f88668 (via 0x91f89260): pops the rule's operands from the
  node stack, folds all-constant operands with the value library (`&&`/`||`
  also fold a false/true constant left operand; `?:` folds on a constant
  condition), declares names as items (0x20 items, names below 0x80 bytes),
  `name[k]` as an array item plus an element item, resolves
  `String.Length/Compare/IndexOf/Contains/StartsWith/EndsWith/Substring`
  with their operand counts (0x80020004/0x8002000e), and otherwise
  allocates an operator node (0x40 node objects, reused when freed:
  0x8007000e).
- 0x91f8bdd0: a constant result gives no classifier (true) or 0x82da0010
  (false); every item name is then bound case-insensitively to the field
  table 0x91f99660 (0x55 names, unknown: 0x82da0025).
- The program serializes through 0x91f87318 (`write_program`). String
  references follow stock's entry/dependent links exactly, since the table
  order and the link-as-position reads above depend on them. Programs with
  more than 16 items or 32 nodes compile and serialize; `insertq` then
  refuses them (0x82da001c) as stock does.
- Unit tests (compile.rs, variant.rs): serialized bytes and error statuses
  for about 100 texts; every expected value was produced by executing the
  stock image (0x91f8bdd0, then 0x91f87318 with 0xdc output bytes, or the
  value library functions directly) in an instruction-level PowerPC
  emulator. A differential run of more than 60000 generated texts (valid
  and malformed) against the same emulation matched, except where stock
  faults.

### ipproxy
- Wire-verified by host tests (crates/openxbdm-server-host/tests/network/ipproxy.rs):
  - `start_and_stop_report_the_tunnel`: `200- started ver=1 addr=0xc0a8011a port=0x%04x` (local UDP port, debug XNADDR address); the hook is installed, the bypass flag is set, and the socket is connected to addr:port; `200- stopped` clears everything.
  - `start_validates_parameters`: missing, zero or unparsable ver/addr/port, port > 0xffff, no flag, an unknown flag, and `stop start` all give `423- bad parameter`.
  - `start_twice_and_stop_without_start`: `410- file already exists`; `426- `.
  - `start_requires_the_system_version`: 0x201c7cff gives `407- unknown command`; 0x201c7d00 passes.
  - `missing_exports_deny_access`: `414- access denied`; a missing inject export leaves the proxy started (410, then stop gives 200).
  - `socket_errors_are_reported`: `400- err=10050`, not started. `socket_error_zero_reports_started`: last error 0 gives `200- started ... addr=0x00000000 port=0x0000`, still started.
  - `register_failures_are_reported`: start gives `400- err=-2147467259` with everything undone; stop gives `400- err=5` and the proxy stays started.
  - `thread_failure_reports_no_buffers`: `400- err=10055`, hook removed, socket closed.
  - `host_messages_are_injected`: TCP/UDP/broadcast messages become synthetic IPv4 packets; short messages are ignored.
  - `outbound_packets_reach_the_host`: a UDP packet sent through the hook arrives as `{0x03, dst ip, dst port, src port, payload}`.
  - `keepalive_follows_a_quiet_interval`: after 20 s without sending, any wake sends `{0x01}`; a keepalive from the host updates the receive clock.
- Unit tests (tunnel.rs): byte-exact encapsulate/decapsulate, including the zeroed checksum on oversized TCP, the size limit, and the fragment/options/protocol filters.

### netcap
Wire-verified by host tests in crates/openxbdm-server-host/tests/network/netcap.rs:
- `netcap` with no subcommand: `423- bad parameter`; `netcap start` without `file=`: `412- filename is invalid`; `netcap stop` when idle: `435- `.
- `netcap start file=e:\cap.bin`: `200- started`; frames go to `\Device\Harddisk0\Partition1\DEVKIT\cap.bin` (raw text when untranslatable). Default buffers are 0x20000/0x4000; flags 8 gives 0x2000/0x1000; buffersize sets chunk = min(size/2, 0x4000).
- `netcap stop`: `200- stopped frames=N`. File bytes checked exactly: header, media block, records with microsecond times, frame table, table location at 0x18. An empty capture has a zero table location.
- Second start: `408- err=0x82da0008`; existing file: `410- err=0x82da000a`.
- Receive filters (flags 2/4) skip received broadcast/multicast frames, not transmitted ones. Promiscuous mode (flags 1) is turned off on stop; a refused enable clears the flag.
- Callback errors: maxframedata exhaustion gives `200- stopped err=0x8007006f frames=1`; an oversize frame gives `err=0x80070018`; a buffer overflow gives `438- stopped err=0x82da0026 frames=1`.
- Close failure with a kernel status: `200- stopped err=0x82da000f frames=0` (0xd000007f mapped).
- Start failures: `400- err=0x8007000e` (context allocation); intercept WSAEALREADY `416- err=0x82da0010`; other intercept codes `400- err=0x80072747`. The file is finished empty and promiscuous mode stays on.
- The capture file is created in the simulated file system (create-new, read/write access, share read; names without a leading backslash resolve below `\??\`, standing in for root handle 0xfffffffd), so `getfile` reads it (`getfile_reads_the_finished_capture`). A missing directory gives `402- err=0x82da0002` (`missing_directories_fail_the_start`).
- Simulator chaining (`captures_chain_into_the_network_simulator`): a running capture moves into a new netsim instance and back to its own intercept when the instance is released; a capture started while an instance exists skips the intercept. A failed instance creation leaves the capture attached but unrouted until the next instance (`failed_simulator_creation_leaves_the_capture_unrouted`).

### netsim (wire-verified by crates/openxbdm-server-host/tests/network/netsim.rs)
- Version gate (< 0x20278700): `407- unknown command` (requires_the_system_version).
- getnumqs/getnumipv4redirs/removeq/removeipv4redir without an instance: `in=0 out=0`, `num=0`, `removed=0 inleft=0 outleft=0`, `removed=0 left=0` (counts_without_an_instance).
- Parameter rules: no/unknown subcommand, missing direction, both directions, missing/empty cfg, missing index: `423- bad parameter`; bad hex (odd count, bad digit) `407- unknown command` before subcommand selection (parameter_errors).
- insertq ordering, `index=` before position and append, quoted cfg (insertq_orders_queues_and_reports_the_index).
- insertq rejections `423- err=0x82da0017` (bad type, field without a stage, zero rate, loss > 100000, both bucket start bits, trailing classifier bytes, index past end); the instance created for a failed insert is destroyed (insertq_rejections).
- Instance creation failures: `400- err=0x80070005`, `416- err=0x82da0010` (instance_creation_failures).
- getq returns applied settings (unknown mask bits dropped), `402- err=0x82da0002` without instance, `423- err=0x82da0017` bad index (getq_reports_the_applied_settings).
- modifyq: blob without type byte, merge, bucket start-bit clearing, `200- OK`, kind mismatch and bad index 423, no instance 402 (modifyq_merges_settings).
- getqstats exact format `totalpkts=5 totalbytes=0q0000000100000002 droppkts=1 dropbytes=0q0000000000000040` (getqstats_prints_counters).
- removeq per index/direction, both directions by default, instance released when idle (removeq_releases_the_idle_instance).
- Redirects: insert/position, target validation, >500 sessions, removal counts, release (redirects).
- Persistence file content `[xbdm]` + in/out queue lines + redirect lines with CR LF and upper-case hex; header-only after release; failed mutations/queries leave the file (mutations_rewrite_the_configured_file).
- reload: destroys the previous instance, runs netsim and linkstate lines (link forced to DISCONNECT), ignores other lines, does not rewrite on success, reuses the stored name (reload_executes_netsim_and_linkstate_lines); unterminated last line loses its last byte (reload_drops_the_last_byte_of_an_unterminated_file); `412- file=""`, `402- file="...missing.ini"`, untranslated name stored raw, busy `400- ` (reload_errors).
- Trace mask bit 0x4 (tests/trace.rs `netsim_settings_file`): each file line `XBDM: NetSimReadIniLine '%s'` (0x91f35fa0, empty lines between CR and LF included) and `XBDM: NetSimReadIniLine processing command failed (0x%08x)` for a failing line; the writer prints `XBDM: NetSimWriteIniFile - No filename configured.` (0x91f362d0), `- Starting to write "%hs".` (0x91f362f4), `- No memory!` (0x91f36344), `- Failed to create file: 0x%08x` with the NTSTATUS (0x91f36424), `- Done writing ini file.` (0x91f36408). The writer holds only a backend and reads the published mask.
- Unit tests (openxbdm-server): queue blob field order, header checks, validation bit filtering, merge rejections and start-bit clearing, serialization round trip, redirect blob parse/serialize/validation.
