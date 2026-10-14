# Reverse-engineering status

Status labels:

- `identified`: purpose and entry point are known; behavior is not fully reconstructed.
- `partial`: principal behavior is reconstructed; edge behavior remains.
- `verified`: behavior was exercised against the live devkit or an exact captured artifact.
- `implemented`: present in openxbdm and exercised through its public surface.

## Source artifacts

| Artifact | Evidence | Status |
| --- | --- | --- |
| `xbdm.xex` | Flash file and Binary Ninja image have SHA-256 `36d0cd5e14ddbbcd070ace19c725ff9f2a2c96344c55161da7acac62bee348bd`; loaded module base `0x91f00000` | verified |
| Live XBDM | `dmversion` reports `2.0.21256.0`; module size is `0x000af000` | verified |

## XBDM components

| Component | Status | Notes |
| --- | --- | --- |
| TCP command framing | implemented | CRLF requests; 200 through 206 reply classes |
| Host mock server | implemented | Real TCP surface, isolated state per connection, exercised end to end by the published openxbdm-client library |
| Console information backend | implemented | `dbgname`, `dmversion`, `consoletype`, `consolefeatures` |
| Filesystem backend | partial | `drivelist`; Xbox target `delete` restricted to `DEVKIT:\FlashEx\xbdm.xex` |
| Memory backend | implemented | Bounded `getmem` and `setmem`, per-byte readability, and partial-write counts |
| Process backend | partial | `getpid` only |
| File transfer | identified | `getfile`, `sendfile`, `sendvfile`, `writefile` |
| Debug control | identified | breakpoints, halt, continue, stop, suspend, resume, contexts |
| Notifications | identified | `notify`, `notifyat`, `notifyport`, dedicated channels |
| Performance counters | identified | `pclist`, `querypc`, `perfstat` |
| Screenshot and PIX | identified | `screenshot`, `pixcmd`, `pixpreview` |
| Authentication and users | identified | challenge exchange, users, privileges, lock modes |
| Discovery | identified | UDP discovery handled by openxbdm-client on the PC side |
| Xbox 360 target binary | implemented | Hardware-format system-debugger XEX; verified on hardware as a `DEVKIT:\DMEXT` extension at `0x90a00000`, where it starts its worker and unloads cleanly |
| Boot-time replacement | verified | `DEVKIT:\FlashEx\xbdm.xex` with a matching bounding path loads in place of flash XBDM, including under a shadowboot of the generated boot region; see `module-loading.md` |

Flash image parsing, boot-chain research, and shadowboot image assembly are maintained in acceleration under `doc/re-notes`.
