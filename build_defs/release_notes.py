#!/usr/bin/env python3
"""Prints the notes of a GitHub release.

Usage: build_defs/release_notes.py --version VERSION --commit SHA [--date YYYY-MM-DD]

The notes name the build date and commit, list the files that
build-executables.yml uploads, and give the console installation steps.
The date defaults to the current UTC date.
"""

import argparse
import datetime
import sys

NOTES = """\
Built on {date} from {commit}.{nightly}

## Console module

openxbdm replaces the Xbox Debug Monitor (xbdm.xex) of an Xbox 360
development kit and serves the XBDM protocol on TCP port 730.

| File | Use |
| --- | --- |
| `openxbdm-boot-guard-{version}.xex` | Console module for `DEVKIT:\\FlashEx\\xbdm.xex`, with startup safety checks to preserve XBDM connectivity |
| `openxbdm-{version}.xex` | Console module for temporary deployment through the kernel debugger host |

### Installation in DEVKIT:\\FlashEx

The kernel loads `DEVKIT:\\FlashEx\\xbdm.xex` at boot in place of the
monitor in flash. The boot-guard build runs for one boot only: it starts
when the marker file `DEVKIT:\\FlashEx\\openxbdm.arm` exists, deletes the
marker, and deletes `xbdm.xex` before it accepts connections, so the next
boot loads the monitor in flash again. With the stock monitor running:

1. Copy the module to the console:

       xeedee -H <console> file put openxbdm-boot-guard-{version}.xex 'DEVKIT:\\FlashEx\\xbdm.xex'

2. Copy a marker file, a local file `openxbdm.arm` with any content:

       xeedee -H <console> file put openxbdm.arm 'DEVKIT:\\FlashEx\\openxbdm.arm'

3. Turn the console off and on.

Repeat the steps for each boot with openxbdm. If the console stops during
an armed boot, turn it off and on: without the marker, the module deletes
`xbdm.xex` and restarts the console into the monitor in flash.

### Loading from a kernel debugger host

With kdnet enabled on the console, `openxbdm-kd` supplies the module at
boot. Stop the host and restart the console to return to the stock
monitor:

    openxbdm-kd host --file 'host:\\Device\\Harddisk0\\Partition1\\DEVKIT\\FlashEx\\xbdm.xex=openxbdm-{version}.xex'

## Host tools

- `xeedee-{version}-<target>`: the `xeedee` XBDM client, the
  `openxbdm-kd` kernel debugger host, and the `xeedee-controller` application.
- `xeedee-ffi-{version}-<target>`: the openxbdm-ffi shared and static
  libraries and their C++ headers.

Targets: `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`,
`x86_64-pc-windows-msvc`.
"""

NIGHTLY = " Nightly builds are not versioned releases; each one replaces the previous."


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="the release version, for example 0.1.0 or nightly")
    parser.add_argument("--commit", required=True, help="the commit the release was built from")
    parser.add_argument("--date", type=datetime.date.fromisoformat, help="the build date (default: today, UTC)")
    args = parser.parse_args()

    date = args.date or datetime.datetime.now(datetime.timezone.utc).date()
    sys.stdout.write(
        NOTES.format(
            date=date.isoformat(),
            commit=args.commit,
            version=args.version,
            nightly=NIGHTLY if args.version == "nightly" else "",
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
