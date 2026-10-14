# System module loading

Evidence: build 16547 development kernel captured from the live console. Addresses are kernel virtual addresses.

## Path symbolic links

The routine at `0x80081010` creates the boot-time object links. When `XboxHardwareInfo + 0x0e` has bit `0x0400` set, `\SystemRoot` names `\Device\CdRom0` and no other links are created. Otherwise it compares the flash device against the opened `\Device\Flash` object:

- On a match it creates the links below and points `\SystemRoot` at `\Device\Flash`.
- Otherwise `\SystemRoot` names `\Device\FlashFs` and the links below are not created.

| Link | Target |
| --- | --- |
| `\Hdd` | `\Device\Harddisk0\Partition1` |
| `\Devkit` | `\Device\Harddisk0\Partition1\DEVKIT` |
| `\FlashEx` | `\Device\Harddisk0\Partition1\DEVKIT\FlashEx` |

The live kernel log contains `Loaded DLL xbdm.xex (\Device\Flash\xbdm.xex)`, so the live console takes the matching path.

## Bare-name search

`0x800a3978` resolves a module name that carries no directory. A title searches one prefix. A system module searches the four ANSI strings at `0x801c0824` in order:

1. `\Hdd\`
2. `\Devkit\`
3. `\FlashEx\`
4. `\SystemRoot\`

For each prefix the routine opens the file and calls the image loader at `0x800a2f90`. A failed open or a failed load moves to the next prefix (`0x800a3b50`-`0x800a3b70`). XAM loads XBDM by the bare name `xbdm.xex` (`0x817513b0`, kernel ordinal 409) with flags `0x4000000c` and minimum version `0x201b2500`.

## Bounding path

When `0x80208b64` is zero (the flash `\SystemRoot` case), `0x800a2f90` reads the image's BoundingPath optional header (`0x000080ff`):

- If the header is absent and the load flags contain `0x40000000`, the load fails with `C000008B` (`0x800a30f0`).
- If the header is present, the resolved device path of the file must match it (`0x800afd90`, then `0x8009edc8`); otherwise the load fails with `C00000CC`.

The failure is silent when a later prefix succeeds. Stock flash modules carry their own flash paths, for example `\Device\Flash\xbdm.xex`, so a stock XBDM copied into `\FlashEx\` is rejected. A runtime probe confirmed the rule: a module in `DEVKIT:\FlashEx` loads by bare name with flags `0x8` or `0xc`, fails with flags `0x4000000c` without a bounding path, and loads with flags `0x4000000c` when its bounding path is `\Device\Harddisk0\Partition1\DEVKIT\FlashEx\<name>`.

Consequences:

- `HDD:\xbdm.xex`, `DEVKIT:\xbdm.xex`, and `DEVKIT:\FlashEx\xbdm.xex` each take precedence over the flash copy when the image's bounding path names that file.
- A replacement that the loader rejects leaves stock XBDM loading from `\SystemRoot\`.
- A replacement that loads and then fails cannot be skipped automatically. The module removes its own file before it opens its listener.

## Hardware result

With openxbdm built at `0x91f00000` with the bounding path `\Device\Harddisk0\Partition1\DEVKIT\FlashEx\xbdm.xex` and placed at `DEVKIT:\FlashEx\xbdm.xex`, a cold reboot brought up openxbdm as the console debug monitor: `dbgname` returned `openxbdm-deanxbox` and `consolefeatures` listed `OPENXBDM`. On that boot, without retries, the file was still present and the restricted `delete` command removed it afterward.

The same override works under shadowboot. With the compiler-generated `0xe0000`-byte boot region (SHA-256 `3164f39c830537eeb3ca0a7f14078be53b249d1f878a558f73d7dc4ad73bb5a4`) at `HDD:\xboxromw2d.bin` and openxbdm at `DEVKIT:\FlashEx\xbdm.xex`, an XBDM `reboot` was followed by:

- openxbdm `dbgname` returning `openxbdm-deanxbox`, `dmversion` returning `2.0.21256.0`, and `consolefeatures` listing `DEBUGGING` and `OPENXBDM`.
- openxbdm `getmem 0x801c003e 2` through openxbdm returning `02 9e`. Before the reboot the field read `00 9e`; bit `0x0200` marks the shadowed boot.
- `delete NAME="DEVKIT:\FlashEx\xbdm.xex"` returning `402- file not found`, so the worker's retried startup removal deleted the override.

## Import library identifiers

The kernel table at `0x801c0834` pairs the loader's module names (`xboxkrnl`, `xam`, `xbdm`, `connectx` at `0x80041ab8` in 32-byte slots) with import identifiers, starting `0x45dc17e0` for `xboxkrnl` and `0xfca15c76` for `xam`. It is read by `0x800a24d0`.
