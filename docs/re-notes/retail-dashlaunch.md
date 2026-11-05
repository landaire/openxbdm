# Retail DashLaunch support

Retail support and the hardware evidence in this note were contributed by [tuxuser](https://github.com/tuxuser) in the [`task/openxbdm_retail_compat` branch](https://github.com/landaire/openxbdm/compare/main...tuxuser:openxbdm:task/openxbdm_retail_compat). The port keeps the observed behavior while adapting it to the current server architecture.

## Verified environment

- Retail kernel `2.0.17559.0`.
- DashLaunch 3.21 with `launch.xex` export 1 identifying itself as `DL30`.
- A console kernel patched to permit direct kernel memory writes.
- The retail-encrypted XEX at `0x91500000`, loaded as a DashLaunch plugin.

Other retail kernel builds are not inferred. Module-list discovery rejects an unknown kernel build instead of using unverified offsets. DashLaunch data is rejected unless its layout identifier is `DL30`.

## Kernel differences

The retail kernel exports `ExDebugMonitorService`, but its implementation returns `STATUS_INVALID_SYSTEM_SERVICE` for every service. The retail build implements the services whose underlying kernel state still exists and leaves devkit-only mechanisms unavailable.

The retail kernel also lacks the devkit `MmDbgReadCheck`, `MmDbgWriteCheck`, and `MmDbgReleaseAddress` behavior used to modify executable text. The retail build validates addresses with `MmIsAddressValid`, rejects device ranges, and writes through the kernel mapping supplied by the patched console. It calls `KeFlushCacheRange` to write back the data cache, then `KeSweepIcacheRange` to invalidate the instruction cache. The devkit build retains the `MmDbg*` path and uses the same cache synchronization after the mapped write.

Debug monitor registration is reconstructed from verified kernel and DashLaunch state:

- `XexPcToFileHeader` ordinal 412 contains verified `lis` and `addi` pairs for the loaded-module list head and lock on build 17559. Retail keeps title modules on this list, so there is no second user-mode list to publish.
- The system process comes from the current system thread.
- A transient non-system thread reports the title process.
- An IPI records each active hardware thread's processor control block. `XboxHardwareInfo.NumberOfProcessors` supplies the count.
- DashLaunch `ldata` offsets `0x21c` and `0x220` provide `KiDebugRoutine` and the single-step patch address after its `DL30` identifier and target kernel are validated. Reconstruction is enabled only for raw kernel version `2.0.17559.0x8000`, which is displayed as `2.0.17559.0`.
- The reconstructed block remains private to the plugin. Retail does not publish the control dispatcher through `KeDebugMonitorData` because safe plugin unload would require a trampoline outside the unloadable image.

| Kernel routine variable | Retail behavior |
| --- | --- |
| `KiDebugRoutine` | Resolved through validated DashLaunch data. Exceptions, breakpoints, and the XTrace fallback use it. |
| `KiStackOverflowNotification` | Unavailable. Stack overflows do not enter the monitor's stop and dump path before the kernel bug check. |
| `KiContextSwapNotification` | Unavailable. Kernel thread-switch notifications are not delivered, and performance capture cannot install its thread-switch recorder. |
| Kernel callback notification | Unavailable. Registered kernel-callback notification handlers are not called. |
| Trace-hook variable from service 6 | Unavailable. XTrace handles single-step exceptions through `KiDebugRoutine` instead of the earlier, faster trace hook. |

Monitor service behavior:

| Debug monitor service | Retail behavior |
| --- | --- |
| Memory statistics | Reimplemented with `MmQueryStatistics`. Debug-pool counts are zero because retail has no debug pool. The base memory threshold is 512 MiB, so `consolemem`, `debugmemsize`, performance counters, and raw statistics queries retain useful results. |
| CD-ROM channel discovery | Reconstructed from the kernel 17559 symbols for the channel extension and packet routines. The retail plugin does not install the persistent hot-plug hooks because their asynchronous channel work cannot be detached safely during plugin unload. |
| Kernel call capture | Unavailable. Retail images have neither the devkit call-cap instrumentation nor its kernel patching service. |
| DVD emulation mode | Unavailable. Inquiry and mode selection are part of the disabled hot-plug hook path, and the retail hypervisor has no corresponding devkit mode-selection call. |
| Trace hook | XTrace uses the `KiDebugRoutine` fallback described above. |

The retail kernel compiles out the stack-overflow, context-swap, callback, DVD command trace, and pre-debug notification call sites. Supplying pointer variables alone would not restore them. They require validated kernel code patches and remain disabled rather than patching unverified instruction sites.

## Network differences

The `DebugMonitor` XAM network caller is not initialized on retail. The retail build uses `SystemApp`, skips `NetDll_XNetStartup` and `NetDll_WSAStartup`, and applies socket option `0x5801` to listeners and discovery sockets. Without that option, loopback worked but a LAN peer received no response in the verified environment.

## Image layout

`launch.xex` occupies the devkit module range at `0x91f00000` on retail. The retail image uses `0x91500000`, a verified free range between resident system modules. Its manifest selects that address, retail encryption, and no devkit bounding path.
