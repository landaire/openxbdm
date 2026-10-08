# xeedee

Async-first Rust reimplementation of the Xbox 360 [XBDM][xbdm] (Xbox Debug
Monitor) protocol, plus a CLI that wraps it.

[xbdm]: https://xboxdevwiki.net/Xbox_Debug_Monitor

## What it is

Xbox 360 devkits speak a TCP protocol on port 730 (and answer UDP
discovery broadcasts on 731). The protocol is text-line-oriented with
optional multi-line and binary bodies. Historically the only way to talk
to a devkit was Microsoft's proprietary `xbdm.dll` / XDK tools.

`xeedee` is a pure-Rust client: a typed transport layer (including a
`MockTransport` for tests), parsers for every response shape, framed
command building, discovery, and high-level wrappers around the common
commands (directory listing, file up/download, memory read/write,
notification subscription, reboot, etc.).

## Quick start

Every wire verb is a type implementing [`xeedee::Command`]. You hand one
to `Client::run` and get back the decoded `Output` associated type.

```rust,no_run
use xeedee::Client;
use xeedee::commands::{DbgName, DirList};
use xeedee::transport::tokio::connect;

#[tokio::main]
async fn main() -> xeedee::Result<()> {
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
cargo install xeedee
xeedee -H 192.168.1.26 systime
xeedee -H 192.168.1.26 file ls 'DEVKIT:\'
xeedee -H 192.168.1.26 file get 'DEVKIT:\my-capture.xbm'
xeedee -H 192.168.1.26 dump-module xboxkrnl.exe /tmp/xboxkrnl.exe
```

## Features

| flag        | what it enables                                              |
| ----------- | ------------------------------------------------------------ |
| `cli`       | The `xeedee` binary (`clap`, `indicatif`, `tabled`, etc.).   |
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

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT license

at your option.
