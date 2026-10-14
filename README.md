# openxbdm

Clean-room Rust reimplementation of the Xbox 360 [XBDM][xbdm] (Xbox Debug
Monitor): a client library and CLI, and a server that replaces the
monitor on the console.

[xbdm]: https://xboxdevwiki.net/Xbox_Debug_Monitor

## What it is

Xbox 360 devkits speak a TCP protocol on port 730 (and answer UDP
discovery broadcasts on 731). The protocol is text-line-oriented with
optional multi-line and binary bodies. Historically the only way to talk
to a devkit was Microsoft's proprietary `xbdm.dll` / XDK tools.

`openxbdm-client` is a pure-Rust client: a typed transport layer (including a
`MockTransport` for tests), parsers for every response shape, framed
command building, discovery, and high-level wrappers around the common
commands (directory listing, file up/download, memory read/write,
notification subscription, reboot, etc.).

The workspace contains:

- `openxbdm-client`: async client library.
- `openxbdm-cli`: the `openxbdm` command-line client.
- `openxbdm-ffi`: C/C++ bindings for the client.
- `openxbdm-server`: allocation-free, `no_std` command parsing and backend dispatch.
- `openxbdm-server-host`: the `openxbdm-server` TCP server backed by deterministic mocks.
- `openxbdm-server-xbox360`: the Xbox 360 system-debugger module.

## Quick start

Every wire verb is a type implementing [`openxbdm_client::Command`]. You hand one
to `Client::run` and get back the decoded `Output` associated type.

```rust,no_run
use openxbdm_client::Client;
use openxbdm_client::commands::{DbgName, DirList};
use openxbdm_client::transport::tokio::connect;

#[tokio::main]
async fn main() -> openxbdm_client::Result<()> {
    // `connect` returns a `Compat<TcpStream>` that implements the
    // `futures_io` traits the client needs.
    let transport = connect("192.168.1.26:730").await?;
    let mut client = Client::new(transport).read_banner().await?;

    // Single-line response -> String.
    let name: String = client.run(DbgName::Get).await?;
    println!("console name: {name}");

    // Multi-line response -> Vec<DirEntry> with typed fields.
    let entries = client.run(DirList { path: r"DEVKIT:\".into() }).await?;
    for entry in entries {
        println!(
            "{:<40} {:>10} {}",
            entry.name,
            entry.size,
            if entry.is_directory { "DIR" } else { "FILE" },
        );
    }
    Ok(())
}
```

If you need a verb that doesn't have a typed wrapper yet, drop down to
`client.send_line("any xbdm verb").await?` for the raw `Response`.

Or use the CLI:

```
cargo install openxbdm-cli
openxbdm -H 192.168.1.26 systime
openxbdm -H 192.168.1.26 file ls 'DEVKIT:\'
openxbdm -H 192.168.1.26 file get 'DEVKIT:\my-capture.xbm'
openxbdm -H 192.168.1.26 dump-module xboxkrnl.exe /tmp/xboxkrnl.exe
```

## Features

| flag        | what it enables                                              |
| ----------- | ------------------------------------------------------------ |
| `cli`       | The `openxbdm` binary (`clap`, `indicatif`, `tabled`, etc.). |
| `tokio`     | `tokio::net::TcpStream` transport. Implied by `cli`.         |
| `jiff`      | `jiff::Zoned` conversions on time-bearing response types.    |
| `image`     | PNG screenshot decode via the `image` crate.                 |
| `capture`   | Video capture over the PIX! protocol and `.xbm` detiling.    |
| `dangerous` | In-memory patches to xbdm (nand-dump, drivemap-enable, etc). |

All non-transport, non-CLI features are off by default.

## Status

Implemented and exercised against a real v10888-based devkit (`xbdm-main-nov11`):

- Core command layer: `directory listing`, `getfile`, `sendfile`,
  `getmem`, `setmem`, `reboot`, `threadinfo`, etc.
- Notification channel (async events on a second connection).
- UDP discovery and ping.
- `PIX!{...}` video capture with intermediate `.xbm` decode into NV12.
- Dangerous helpers: `drivemap` enable/persist, in-memory code patching
  (strictly opt-in via the `dangerous` feature).

Not implemented:

- No MP4 encoding in-crate; the `capture` path shells out to `ffmpeg`
  for H.264 muxing.

## Mock server

```text
cargo run -p openxbdm-server-host -- --listen 127.0.0.1:1730
openxbdm -H 127.0.0.1:1730 dmversion
```

Each connection gets isolated mock state.

## Xbox 360 module

`build_xbox360.sh` builds the console module with the PowerPC target from the
adjacent `llvm-xbox-360` repository (override with `LLVM_XBOX_360`) and writes
`target/openxbdm.xex`: load address `0x91f00000`, system-debugger DLL flags,
build 21256 import versions, small pages, compression, and development-key
encryption.

The module is deployed as `DEVKIT:\FlashEx\xbdm.xex`. The kernel searches
`\Hdd\`, `\Devkit\`, and `\FlashEx\` before `\SystemRoot\` when it loads a
system module by bare name. XAM loads XBDM with a flag that only admits images
whose bounding path names the file being loaded, so the build sets the
bounding path to `\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex`. A
module that fails to load leaves stock XBDM in place. Before starting its TCP
listener the module tries for up to 30 seconds to remove
`DEVKIT:\FlashEx\xbdm.xex`; while that file exists, every cold boot loads the
module.

## Reverse-engineering records

- `docs/re-notes/status.md`: feature inventory and implementation status.
- `docs/re-notes/xbdm.md`: command table, protocol behavior, and backend boundaries.
- `docs/re-notes/module-loading.md`: kernel module search and boot-time replacement.
- `docs/re-notes/nuances.md`: behaviors requiring exact compatibility.

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
