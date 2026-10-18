# Debug monitor control dispatcher

Stock XBDM 2.0.21256.0 (`xbdm.xex`, base `0x91f00000`). The kernel debug monitor data block (`0x68` bytes, xbdm copy at `0x91fade60`) is published through `KeDebugMonitorData` (xboxkrnl ordinal 89). Field `+0x18` is the control dispatcher `dm_control_dispatch` (`0x91f3b4d0`), installed by `0x91f3bc38`. Kernel, xam, title libraries, and xbdm itself call it as `result = block->+0x18(code, arg)`.

Kernel references are taken from two images: `xboxkrnld` 15574 (symbolized, "K15574") and the `deanxbox` kernel 16547 that runs this xbdm ("K16547", unsymbolized; its 54 `KeDebugMonitorData` load sites occur in the same order with the same codes as K15574, so K15574 names apply). Codes not issued by either kernel are issued by modules outside the kernel; their issuer is `Unknown` unless it is xbdm itself. Binary Ninja names below are the names applied in the database.

## Dispatch mechanics

```text
dm_control_dispatch(r3 = code, r4 = arg):
  if code - 1 > 0xa8: result = 0
  else: jump 0x91f3b528 + u16[0x91f03dc8 + 2 * (code - 1)]
  case exits: 0x91f3bb10 -> result = 0
              0x91f3bb14 -> result = callee r3 (or case-computed value)
              0x91f3b56c -> result = 1
  return dm_dispatch_call_extension_hook(code, arg, result)
```

`dm_dispatch_call_extension_hook` (`0x91f2e2e8`): when a debugger extension loaded through export 178 exports `OnTellDebugger` (pointer at `0x91fae608`), xbdm calls `OnTellDebugger(code, arg, result)` and its return value replaces `result`. The call is bracketed by `KeEnterCriticalRegion`/`KeLeaveCriticalRegion` at IRQL 0, otherwise by `KeSetCurrentProcessType(2)`/`KeSetCurrentProcessType(0)`, with an interlocked in-use count at `0x91fae5bc` (extension unload spins on it). Every code, including default-routed codes, reaches the hook; default-routed codes have an effect only through an extension.

Where the table says "residual", the case exits through `0x91f3bb14` but the callee defines no return value; `r3` holds whatever the callee's last call left. A reimplementation should return 0 for these; no observed caller depends on the value.

Blocking: "yes" = may wait on a dispatcher object, take a critical section, perform file I/O, create threads, or call a caller-supplied function. "no" = spin locks or plain memory only. The extension hook can block for any code.

## Data block fields used by the kernel

The block is filled by `ExDebugMonitorService(1, block)` (kernel pointers) and then by xbdm. Only `+0x0c` and `+0x18` are dereferenced through `KeDebugMonitorData` in K15574 and K16547.

| Offset | Set by | Content | Kernel use |
| --- | --- | --- | --- |
| `+0x00` | kernel | `&KiDebugRoutine` (`0x801fba84` in K15574) | xbdm saves the old value in `0x91fadd24` and stores `0x91f3a980` through it. Called by `KiDispatchException2`: `0x80097944` with `r6 = 0` (first chance) and `0x80097994` with `r6 = 1` (second chance); `r3` = KiDispatchException2 arg 2, `r4` = arg 1 (exception record, code at `+0`), `r5` = arg 4 (context, `+0` set to `0x17`). |
| `+0x0c` | shared | flags | `KeBugCheckEx` (`0x80096630`, K16547 `0x80096970`) ORs in 4. xbdm KiDebugRoutine passes bit 2 to `DumpWriteDump` and sets bit `0x40` after writing a dump. |
| `+0x18` | xbdm | `dm_control_dispatch` | All call sites below. |
| `+0x20` | xbdm | `0x91fade40`: `+0x00` = `0x20`, `+0x0c` = `0x91f29c00` (export 73), `+0x10` = `0x91f29dd8` (export 74), `+0x18`/`+0x1c` = 0 | None in K15574/K16547. Unknown: consumer (not the kernel). |
| `+0x24` | xbdm | `0x91fade30` | None in K15574/K16547. Unknown: consumer and layout. |
| `+0x58` | kernel | `&KiStackOverflowNotification` (`0x801fb914`) | xbdm stores `0x91f23330` through it. Called from `KiCommonInterruptHandlerDummy` (`0x8009c4c0`, `bnectrl`) with `r3` = stack pointer of the faulting frame, immediately before `KeBugCheckEx(0x2b, r1, [r1+0x1ac], [r1+0x58], [r1+0x1a8])`. |

Other kernel-filled fields: `+0x04` `PsLoadedModuleList`, `+0x08` `XexLoadedModuleListLock`, `+0x1c` `KiContextSwapNotification`, `+0x4c` `KeNumberProcessors` value, `+0x50` `KeSystemProcess`, `+0x54` `KeTitleProcess`, `+0x5c` `KiProcessorBlock`, `+0x60` `MmHighestPhysicalPage` value, `+0x64` `PsLoadedUsermodeModuleList`. `DumpWriteDump` (K15574 `0x801aaf48`) records the address of `KeDebugMonitorData` in the dump range list; it does not call the block.

## Kernel call sites of `+0x18`

| Code | K15574 function | K15574 call | K16547 call | Argument |
| --- | --- | --- | --- | --- |
| 0x01 | `KdPollBreakIn` | `0x801b005c` | `0x801b4a74` | `r4 = 0` |
| 0x32 | `OmniInitDbgCommandProcessor` | `0x80165950` | `0x80168860` | `{+0 name, +4 handler 0x80165800}` |
| 0x32 | `NuiCamInitDbgCommandProcessor` | `0x8018b350` | `0x8018e258` | `{+0 name, +4 handler}` |
| 0x46 | `SataCdRomStartRead` | `0x800c77a4` | `0x800c7b74` | `{+0 LBA, +4 transfer sectors}` (same values as the CDB) |
| 0x47 | `SataCdRomStartRead` | `0x800c7858` | `0x800c7c28` | `r4 = 0xc00000b5` (failure path) |
| 0x47 | `SataCdRomFinishRead` | `0x800c73f8` | `0x800c77c8` | `r4 = completion status` |
| 0x48 | `OdfxGdfMountVolume` | `0x800dd754` | `0x800ddaa4` | `{+0..+0xc}` = four LE dwords from GDF volume descriptor `+0x14, +0x18, +0x1c, +0x20` |
| 0x49 | `SataCdRomSscFinishSpeedDecrease`, `...Increase`, `...SetSpeedToMaximum`, `...SetSpeedToDesired` | `0x800c5604`, `0x800c5724`, `0x800c5848`, `0x800c6b5c` | `0x800c59d4`, `0x800c5af4`, `0x800c5c18`, `0x800c6f2c` | `{+0 speed index, +4 index - 1, +8 r5 of caller}` |
| 0x4a | `SataCdRomFinishGetDriveGeometry` | `0x800c68e0` | `0x800c6cb0` | `r4 = 0, 3 or 5` (auth state) |
| 0x4a | `SataCdRomXGD2AuthenticationSequence`, `SataCdRomDeauthDrive` | `0x800c7bdc`, `0x800c81e8` | via `0x800c7f70`, `0x800c857c` | `r4 = 3 or 4` |
| 0x4a | `SataCdRomClearAuthenticationStateInternal` | `0x800c8038` | `0x800c8408` | `r4 = 0` |
| 0x5b | `XAUDIO::CRenderDriver::ThreadProc` | `0x8015c21c` | `0x8015ee34` | `r4` = rendered sample block |
| 0x64 / 0x65 | `NtCreateFile`, `NtOpenFile`, `NtReadFile`, `NtWriteFile`, `NtReadFileScatter`, `NtWriteFileGather`, `NtFlushBuffersFile`, `NtDeleteFile`, `NtClose`, `FscSetCacheElementCount` | e.g. `NtCreateFile` `0x80090560` / `0x800905d8` | e.g. `0x80090898` / `0x80090910` | file event record, see code 0x64 |
| 0x78 | `RgcInputReportTransferComplete`, `IrdRecordControllerInput`, `WgcInputReportTransferComplete` | `0x8012a054`, `0x80130758`, `0x80132528` | `0x8012aa18`, `0x80131a00`, `0x80133d10` | input report record (`+0 u8 0xff, +2 u16 ...` for Ird) |
| 0x79 | `HidKeyboardInterruptInComplete` | `0x8011a0f0` | `0x8011a4c8` | `{+0 u8, +1 u8, +2 6 key bytes}` |
| 0x7f | `SataDiskStartReadWrite` | `0x800ca2c0` | `0x800ca6b0` | `{+0 is_write, +4 start, +8 length >> 9}` |
| 0x80 | `SataDiskFinishReadWrite` | `0x800ca160` | `0x800ca550` | `r4 = status` |
| 0x81 | `RtlpWaitCriticalSection` (before wait) | `0x800b2a10` | `0x800b2da0` | `r4` = critical section |
| 0x82 | `RtlpWaitCriticalSection` (after wait) | `0x800b2a70` | `0x800b2e00` | `r4` = critical section |
| 0x86 | `MmQueryStatistics` (after fill) | `0x800a8840` | `0x800a8b98` | `r4` = `MM_STATISTICS` |
| 0x88 | `DmPrintData` | `0x800af654` | `0x800af9e4` | `{+0 u16 length, +4 text}`; sent only if `0x8a` mask has the caller category bit |
| 0x89 | `DmPrintData` | `0x800af50c` | `0x800af89c` | `r4 = 0`; result caps message length (max `0x400`) |
| 0x8a | `DmPrintData` | `0x800af538` | `0x800af8a0` region | `r4 = 0` |
| 0x96 | `NuiCamCaptureRawData` | `0x8018b46c` | `0x8018e374` | `{+0 (r3 == 4), +4 u16, +6 u8, +8 data, +0xc length}` |
| 0x99 | `NullCableReportDeviceStatus` | `0x8019f8ec` | `0x801a3c2c` | `{+0 u8 status}` |
| 0x9b | `NuiCamCaptureFrameStart` | `0x8018b3fc` | `0x8018e304` | `{+0 (r3 == 4), +4 u32, +8 u64}` |

For codes 0x64 and 0x65 the kernel skips the file operation when the 0x64 result is nonzero and returns record `+0x10` as the status; xbdm always returns 0 for 0x64.

## xbdm self-calls through `+0x18`

| Code | Issuer | Argument |
| --- | --- | --- |
| 0x0d, 0x0f, 0x11, 0x13 | `dm_ctl_0b_apply_xnet_config` | `0` |
| 0x34 | `dm_monitor_set_current_thread_name` (`0x91f78888`) | name |
| 0x43, 0x5e | `pix_stream_write_tagged_record` (`0x91f788b8`) | `{ptr, dwords}` / list |
| 0x50 | `pix_timing_end_event` (buffer full) | `{+0 1, rest 0}` |
| 0x78 | export 171 `set_automation_gamepad_state` | stack record at `r1+0x50`; Unknown: layout |
| 0x7d | exports 167/168 bind/unbind automation controller | stack record at `r1+0x50`; Unknown: layout |
| 0x89, 0x8a | `0x91f2b530` (TellLog line writer), `cs_trace_log_line` | `0` |

## Notification types

`0x91f39ad0(type, data)` dispatches to registered handlers and formats text for notification sessions; `0x91f39d08(type, data, stop)` additionally sets bit 31 (`DM_STOPTHREAD`) and suspends the thread. Formatter jump table `0x91f03c58`:

| Type | Text |
| --- | --- |
| 1 | `break addr= thread=` |
| 2 | debugstr (formatted by `0x91f38ce8`) |
| 3 | `execution %s`; state 0 stopped, 1 started, 2 rebooting, 3 pending, 4 reboot_title, 5 pending_title |
| 4 | `singlestep addr= thread=` |
| 5 | `modload ...` |
| 6 | `modunload name= base= size=` |
| 7 | `create thread= start=` |
| 8 | `terminate thread=` |
| 9 | `exception code= thread= address=` |
| 0xc | `assert thread= straddr= strlen=` |
| 0xd | `data %s= addr= thread=` |
| 0xe, 0x13 | `%s%s thread= [string=]` (rip) |
| 0x10 | `sectload ...` |
| 0x11 | `sectunload ...` |
| 0x15 | `ntassert addr= thread=` |
| 0x16 | `pogomodstartup name= module= thread=` |
| 0xa, 0xb, 0xf, 0x12, 0x14 | no text |

Dispatcher cases that produce notifications: 0x02 (type 3 state 2), 0x21 (type 3 states 5 and 1, stop flag), 0x64/0x65 (`XBDMFE!` text), 0x1b/0x85 (`PIX!` text), 0xa9 (caller text), 0x2e/0x52/0x56 indirectly through PIX capture paths.

## Codes

Domains: DBG debugger/execution control, MEM memory/modules, FS filesystem, CON console, NET network, PERF performance/PIX, HW hardware/input, SES session/notification, SYS system/title launch, SVC services.

| Code | Case | Callee | Argument (r4) | Return | Effect | Domain | Blocking | Issuer |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0x01 | `0x91f3b718` | `dm_ctl_01_poll_break_in` | unused (0) | 0 | Requires IRQL >= DISPATCH. If any title/system thread has xbdm thread data `+0xc != 0` (stopped by xbdm), queues DPC `0x91fadc80` (`0x91f39bf0`): sets `0x91f975fc = 1`, ORs `0x100` into the ordinal 342 flags word (XboxHardwareInfo, `[INFERENCE]` from ordinal order), then resumes all xbdm-stopped threads and sends execution started. `[INFERENCE]` hands control to the kernel debugger. | DBG | no (DPC deferred) | K: `KdPollBreakIn` |
| 0x02 | `0x91f3b720` | `dm_ctl_02_prepare_reboot` (`0x91f3b208`) | unused | 0 | `0x91f975fc = 1`, `0x91f9fd90 = 0`, WriteIniFile (`0x91f31e48`, gated), notification type 3 data 2 (`execution rebooting`, no state change), `0x91f41038`: `0x91fab9b4 = 1`, alert and wait for the server thread to exit, close every connection slot socket. Same routine as the hardware reboot path of `0x91f278a8`. openxbdm: `system::prepare_reboot` through `call_on_server`, then the server thread exits; later `call_on_server` requests fail. | SYS | yes | Unknown (not kernel) |
| 0x03 | `0x91f3b728` | `dm_ctl_03_set_drive_mapping` | `{+0 char name[0x20], +0x20 target path or NULL}` | 0 | `0x91f2ef60(name, target, 1)`: add/replace a drive mapping in table `0x91f96bf8` (`0x2c`-byte entries: `+0 target, +4 length, +8 name, +0x28 flag`), storing the caller's target pointer and its length at mapping time; NULL target moves the last row into the removed row. Names `F`/`SMB` ignore the target and remap the SMB share from XConfig (3, 0x10) via connectx.xex. openxbdm runs it on the server thread through `call_on_server`; the caller waits. | FS | yes (XexLoadImage) | Unknown |
| 0x04-0x07 | `0x91f3bb10` | none | - | 0 | Default. Extension hook only. | - | no | Unknown |
| 0x08 | `0x91f3b73c` | `dm_ctl_08_memtrack_record_alloc` | `{+0 ptr, +4 size, +8 u8 allocator type}` | residual | Records allocation in memtrack history when enabled for the type. | MEM | no | Unknown |
| 0x09 | `0x91f3b754` | `memtrack_record_free` (via `j_`) | `{+0 ptr, +4 size, +8 u8 type}` | HRESULT when tracked (0, `0x80070057`, `0x80070018`, `0x80070490`); otherwise residual | Removes history entry, logs mismatch. | MEM | no | Unknown |
| 0x0a | `0x91f3b70c` | inline | unused | `[0x91f9fef8]` | Returns the notification-sessions-active flag (set by `0x91f3c0d8` when a connection requests notifications; gates notification queueing). | SES | no | Unknown |
| 0x0b | `0x91f3b76c` | `dm_ctl_0b_apply_xnet_config` | unused | 0 | Builds XNet config (static IP from codes 0xd/0xf/0x11/0x13, DHCP host name = debug name) and calls `NetDll_XnpConfig(3, &cfg, 0)`. | NET | yes `[INFERENCE]` | Unknown |
| 0x0c | `0x91f3b774` | `dm_write_ini_file` | value | value | `[0x91faddbc]` = value (`staticip use=`), writes ini. | NET | yes | Unknown |
| 0x0d | `0x91f3b77c` | inline | unused | `[0x91faddbc]` | Get static IP enable. | NET | no | xbdm (0xb) |
| 0x0e | `0x91f3b784` | `dm_write_ini_file` | value | value | `[0x91faddb8]` = static IP address, writes ini. | NET | yes | Unknown |
| 0x0f | `0x91f3b78c` | inline | unused | `[0x91faddb8]` | Get static IP address. | NET | no | xbdm (0xb) |
| 0x10 | `0x91f3b794` | `dm_write_ini_file` | value | value | `[0x91faddb4]` = subnet mask, writes ini. | NET | yes | Unknown |
| 0x11 | `0x91f3b79c` | inline | unused | `[0x91faddb4]` | Get subnet mask. | NET | no | xbdm (0xb) |
| 0x12 | `0x91f3b7a4` | `dm_write_ini_file` | value | value | `[0x91faddb0]` = gateway, writes ini. | NET | yes | Unknown |
| 0x13 | `0x91f3b7ac` | inline | unused | `[0x91faddb0]` | Get gateway. | NET | no | xbdm (0xb) |
| 0x14 | `0x91f3b7b4` | `dm_xnet_get_config_status` | unused | status `+0x4` | `NetDll_XnpGetConfigStatus(3, 0x91fadc20)`, returns dword 1. Unknown: field meaning. | NET | no `[INFERENCE]` | Unknown |
| 0x15 | `0x91f3b7cc` | same | unused | status `+0x8` | As 0x14, dword 2. | NET | no `[INFERENCE]` | Unknown |
| 0x16 | `0x91f3b7e4` | same | unused | status `+0xc` | As 0x14, dword 3. | NET | no `[INFERENCE]` | Unknown |
| 0x17 | `0x91f3b7fc` | `dm_ctl_17_wipe_ini_file` (`0x91f321d8`) | unused | 0 | Skipped when `0x91f9f664` is set (no code sets it; trace bit 4 `XBDM: WipeIniFile - already wiped`). Title process: bit 4 `XBDM: WipeIniFile - signaling system thread to wipe ini file.`, `0x91f9f670 = 1`, alert the server thread (`0x91fab984`), wait up to 1 s on `0x91faddc0`; else `WriteIniFileImpl(1)` (`0x91f31d28`, bit 4 `entry`/`Done writing ini file...` texts): create `\SystemRoot\MobileJ.dat` with `FILE_OVERWRITE_IF` and write nothing. No CD-boot or load gate. | SYS | yes | Unknown |
| 0x18 | `0x91f3b804` | `dm_ctl_18_get_module_proc_address` | `{+0 module name, +4 ordinal}` | address or 0 | `XexGetModuleHandle` + `XexGetProcedureAddress`. | MEM | no | Unknown |
| 0x19 | `0x91f3b814` | inline | unused | 0/1 | 1 if IRQL is PASSIVE; else 1 only if `[0x91f975fc] != 0` and ordinal 342 flags bit `0x100`. Unknown: caller purpose. | DBG | no | Unknown |
| 0x1a | `0x91f3b848` | `HalOpenCloseODDTray(1)` | unused | `0x02da0000` | Opens the optical drive tray; the result goes through the extension hook (`0x91f3bb14`) as for every code. openxbdm: `ControlCode::OPEN_TRAY` in backend/dispatcher.rs. | HW | yes `[INFERENCE]` (SMC request) | Unknown |
| 0x1b | `0x91f3b6b0` | `pix_post_status(9, arg)` | text | 1 if send status >= 0 (derived from callee residual) | Offers status 9 to the PIX notification filter; else sends `arg` as a notification. | PERF | yes | Unknown |
| 0x1c | `0x91f3b6c0` | export 30 `register_command_processor("PIX", arg)` | handler | HRESULT | Registers the `PIX` command processor. | PERF | yes | Unknown |
| 0x1d | `0x91f3b858` | `dm_ctl_1d_write_alt_ini_file` (`0x91f32110`) | `{+0 file handle, +4 length out, +8 u8 pad}` | 0 | `0x1000`-byte pool buffer (tag `Xbdm`, not zeroed); writer `{+0 handle, +4 buffer, +8 capacity, +0xc count, +0x10 total, +0x14 pad}`; text `0x91f31fb0` = WriteIniFile text (`0x91f31a90`) + `sysset[ videostd=0x%08x]` CR LF + `recovery` CR LF; final flush; `+4` = total bytes of text. With pad the final `NtWriteFile` is the whole buffer (stale bytes after the text). Write failure: bug check `0x2c`. Allocation failure: nothing, `+4` untouched. | SYS | yes | Unknown |
| 0x1e | `0x91f3b870` | export 92 | `{+0 size, +4 flags, +8 videostd}` | 0 | Copies up to `0xc` bytes to `0x91fade20` (`sysset videostd=`), masks flags to bit 0, writes ini. | CON | yes | Unknown |
| 0x1f | `0x91f3b87c` | export 91 | `{+0 size, ...}` | 0 | Copies `0x91fade20` (up to min(size, `0xc`)) to arg, keeps `+0`. | CON | no | Unknown |
| 0x20 | `0x91f3b888` | `dm_ctl_20_register_xam_globals` (`0x91f51df8`) | `{+0 size >= 8, +4 title launch routine, +8 xam version}` | 0 | Trap `twi 31,0,0x19` for NULL or size < 8. Copies min(size, `0xc`) bytes to `0x91fa2004`. Version `0x91fa2000` = `0x20076000` when the stored size <= 8, else `+8` (trap when <= `0x20076000`). `XamNotifyCreateListenerInternal(1, 1, 0xa)` into `0x91f9f67c` (never read); on failure trace bit 0x10 `[xbdm] Failed to register for XAM notifications.`. The relaunch of `0x91f278a8` needs `0x91fa200c != 0` and calls `0x91fa2008(0)`. | SYS | yes | Unknown |
| 0x21 | `0x91f3b894` | `automation_rebind_controllers`, `dm_ctl_21_title_reboot` (`0x91f523a0`) | launch info `{+0 reason, +0x10 ImageName[0x100], +0x110 DDrive[0x100], +0x210 CommandLine[0x100], +0x310 u32}` | 1 when the launch info was replaced and FTitleExists(image, post-boot) succeeds, else 0 | Copies `+0x18` to `+0x1c` of every processor's wait statistics (IPI `0x91f2b3d8`); re-initializes critical section `0x91fadca0`. NULL arg: exec (5, notify 0), exec (1, notify 1), 0. Otherwise trace bit 0x10 `Reason=%d, g_XamGlobals.Flags=0x%08x` (launch flags `0x91fa2324`), then exec (5, notify 0). Reason 4: version < `0x20183800` and image `\Device\Cdrom0*`: disc wait `0x91f52040(image, 5000)`; stop = flags `0x91fa2324` & 9, flags &= ~8. Reason 0: no stop, bit 0x10 `not stopping`. Other reasons: stop = stop-on `0x91fadd1c` & `0x20` (`stopon all`). Stop: bit 0x10 `stopping`, notification `0x80000003` data 5, thread data `+0x10 |= 8`, wait on thread event `+0x1c` (15 s, or forever when flags & 8); timeout: bit 0x10 `DMN_EXEC_PENDING_TITLE state timed out`, exec (1, notify 1). No stop: exec (1, notify 1). Then the launch title `0x91fa2020` (when set and `0x91fa2328` clear) replaces the launch info (bit 0x10 `updating launch info` with the three strings) and is cleared, WriteIniFile; else reasons 0/4 take the persistent title `0x91fa232c` (`updating [default] launch info`); else return 0. Version > `0x20076000`: `+0x310 = 0`. Texts start with `[xbdm] DmpTitleReboot: `. | SYS | yes | Unknown |
| 0x22 | `0x91f3b864` | `dm_ctl_22_capture_ini_file` (`0x91f32080`) | `{+0 buffer, +4 size in, length out}` | 1 | Writer over the caller's buffer with handle 0 and no pad; text `0x91f31fb0`; `+4` = count. No final flush; a text that fills the buffer is written to handle 0, which fails and bug checks `0x2c` (openxbdm keeps the bytes that fit). | SYS | yes | Unknown |
| 0x23-0x26 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x27 | `0x91f3b534` | `pix_stream_write_dword` | dword value (bits 24..31 of a packet's first dword = dword count) | 1 written, 0 dropped | Appends to PIX stream ring `0x91fa2af0`; packet owned by current PCR until complete. | PERF | no | Unknown |
| 0x28-0x2d | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x2e | `0x91f3b560` | `pix_frame_boundary(arg, 0)` (`0x91f57cf0`) | frame value | 1 | Frame number `0x91fa2a60`, count `0x91fa2a5c`; while the stream is active samples the time counters, PMC set, callbacks, groups and frame marker. In a title process then runs the capture engine without a frame record (`0x91f62508`: record `{+4 1000, +0x18 GPU idle wait 0x91f5cf38}`) and, with state flag 1, the module records `0x91f55db8` (thread record 0x46, module records 0x66/0x67). | PERF | yes | Title (frame boundary) `[INFERENCE]` |
| 0x2f | `0x91f3b6d4` | `pix_register_event_callback` | `{+0 type 2..6, +4 callback}` | 1 | Sets `0x91fa2a3c[type-2]`, replays state; type 2 starts counter plugin. | PERF | yes | Unknown |
| 0x30 | `0x91f3b6e0` | `pix_unregister_event_callback` | type 2..6 (value) | 1 | Clears slot; type 2 stops counter plugin. | PERF | no | Unknown |
| 0x31 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x32 | `0x91f3b8a4` | export 30 `register_command_processor(+0, +4)` | `{+0 name, +4 handler}` | HRESULT | Registers a command processor. | SES | yes | K: Omni/NuiCam init |
| 0x33 | `0x91f3b8b0` | export 17 `get_xbox_name(+0, +4)` | `{+0 buffer, +4 size pointer}` | `0x02da0000`, `0x82da0105` (truncated), `0x80070057` | Copies console debug name. | CON | no | Unknown |
| 0x34 | `0x91f3b8c0` | `dm_set_thread_debug_name(-1, arg)` | name | 0 | Names the current thread (pool tag `Dmtd`, thread data `+0x20`). | DBG | no (pool alloc) | xbdm |
| 0x35 | `0x91f3b8d0` | `dm_set_thread_debug_name(+0, +4)` | `{+0 thread id, +4 name}` | 0 | Names thread by id (creates xbdm thread data if missing). | DBG | no (pool alloc) | Unknown |
| 0x36, 0x37 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x38 | `0x91f3b610` | `NtCreateFile` + export 133 `xtrace_start_recording` | unused | export 133 result: 1 when recording started, 0 when a session exists or setup failed | Creates directory `e:\pix` (access `0x100001`, attributes `0x80`, share 0, `FILE_CREATE`, options `0x21`; result ignored), then starts single-stepping the calling thread into `e:\pix\unnamed.pix2`. The dispatcher's own way out is skipped (2 returns or 0x28 instructions) and recording starts at the instruction after the call. | PERF | yes (file I/O, thread creation) | Not issued by the kernels or xbdm |
| 0x39 | `0x91f3b65c` | export 136 `xtrace_stop_recording` | unused | 0 without a session; else 1, or 0 when the writer thread's last file write failed | Sets the stop request, prints timing, queues the current buffer, waits for and closes the writer thread, prints mismatches, frees the memory of a session with a file, removes the hooks, prints the buffer-full report and `Spoofed %d functions.`. | PERF | yes (waits on the writer thread) | Not issued by the kernels or xbdm |
| 0x3a | `0x91f3b698` | `xtrace_instruction_count` (`0x91f66468`) | unused | low dword of `0x91fa2e80` while a session exists, else 0 | `0x91fa2e80` counts every instruction the trace handler encoded since arming (recorded or not, including the instruction after `sc`/`twi` and natively run routine bodies); `0x91fa2e78` counts the recorded ones. | PERF | no | Not issued by the kernels or xbdm |
| 0x3b | `0x91f3b6a0` | `xtrace_request_stop` (`0x91f66490`) | unused | 1 | `0x91fa2d34 = 1`: the next trace exception clears MSR[SE] without recording; the session and its memory stay until export 136. | PERF | no | Not issued by the kernels or xbdm |
| 0x3c | `0x91f3b6a8` | `pix_get_hw_thread_slot` | unused | `0x91fa2838 + 16 * hw thread` | Stores `0x91fa282c` (a flags word only titles write) in slot `+0`. xbdm never reads the slots or the flags word again; their meaning belongs to the issuing title library (not in this image). | PERF | no | Unknown |
| 0x3d, 0x3e | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x3f | `0x91f3b664` | `pix_set_discard_output` | flag value | 1 | `0x91fa2a50` = flag; nonzero discards capture file writes. | PERF | yes | Unknown |
| 0x40 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x41 | `0x91f3b688` | `pix_stream_unregister_consumer(+0, +4)` | `{+0 callback, +4 context}` | 1 | Clears matching consumer slot (5 slots at `0x91fa2b20`). | PERF | no | Unknown |
| 0x42 | `0x91f3b670` | `pix_stream_register_consumer(+0, +4, 0)` / `pix_stream_clear_consumers` | `{+0 callback, +4 context}` or NULL | residual (non-NULL) / 1 (NULL) | Registers consumer with flag 0; NULL clears all flag-0 slots. | PERF | no | Unknown |
| 0x43 | `0x91f3b540` | `pix_stream_write_block(+0, +4, 1)` | `{+0 ptr, +4 dwords}` | residual | Appends block to PIX stream ring, queues ring DPC. | PERF | no | xbdm |
| 0x44 | `0x91f3b704` | `pix_get_state_flags` | unused | flag bits | 1/2 capture state, 4 global flag, 8 capture buffers allocated (`0x91f28bc0`, fast-cap/call-cap engine), 0x10 CPU sampling profiler running (`0x91f32ff8`, `lopctrl`), 0x20 stream active, 0x40/0x80 capture sub-states. | PERF | yes | Unknown |
| 0x45 | `0x91f3b528` | `pix_notify_filter_control` | `{+0 0xc, +4 op, +8 data}` | 0, `0x8000ffff`, or op 0 result | op 0: data `{0x14, line, response, size, context}` runs the `pixcmd` handler `0x91f57fe0` on the title's command line (byte `line+7` is the `pixcmd` letter, as on the wire) with the title's response buffer; op 1: data `{0xc, fn}` installs the PIX status filter. | PERF | no | Unknown |
| 0x46 | `0x91f3b8dc` | `odd_trace_read_start(+0, +4)` | `{+0 LBA, +4 sectors}` | 0 | `ODD ` stream record when stream active; latches read start for ODD log. | HW | no | K: `SataCdRomStartRead` |
| 0x47 | `0x91f3b8ec` | `odd_trace_read_complete(arg)` | status (value) | 0 | `ODD ` completion record; `READ` log record. | HW | no | K: `SataCdRomFinishRead`, `SataCdRomStartRead` |
| 0x48 | `0x91f3b8f8` | `odd_trace_gdf_mount(+0, +4)` | GDF descriptor dwords | 0 | `GMNT` log record. | HW | no | K: `OdfxGdfMountVolume` |
| 0x49 | `0x91f3b908` | `odd_trace_speed_change(+0, +4, +8)` | `{+0, +4, +8}` | 0 | `SSC ` log record. | HW | no | K: `SataCdRomSsc*` |
| 0x4a | `0x91f3b91c` | `odd_set_auth_state(arg)` | state (value) | 0 | `0x91f9fda4` = 1, 2, 3, 4 kept, else 0. | HW | no | K: `SataCdRom*Auth*`, `FinishGetDriveGeometry` |
| 0x4b-0x4f | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x50 | `0x91f3b584` | `pix_timing_buffer_request` (`0x91f61f08`) | `{+0 type, +4, +8 text, +0xc va_list, +0x10 dwords (type 5)}` | 1 when the caller may write, else 0 | Per-thread capture buffer full: at passive level the processor's buffer (PCR +0x2b0/+0x2b4) is queued and replaced (`0x91f61cb8`); in event trace mode (session +0x18) types 0/2 format the text (`_vsnprintf`, 0x23 bytes) for the owner callback (events 0xe0/0xe1/0xe2 during message 5) and the instruction trace of message 4. At IRQL >= 2 or priority >= 0x12 switches to the 0x800-byte temporary block (`0x91f5ee68`) and leaves the replacement to the server pass. | PERF | yes | xbdm timing writers (`0x91f77b00`, `0x91f77c78`, `0x91f78188`, `0x91f78760`); title timing libraries |
| 0x51 | `0x91f3b590` | `pix_capture_frame_buffer` (`0x91f5ebb0`) | `{+0 unused, +4 close, +8 output}` | 0xfff when a buffer was handed out, else 0 | GPU frame buffer (type 0xe): `+4` queues the open one as full; with `+8` a new buffer is taken and its first data dword stored there (0 when the queue would exceed the free buffers; sets output pause bit 0x20000000). | PERF | yes | Title (D3D) `[INFERENCE]` |
| 0x52 | `0x91f3b574` | `pix_frame_boundary(0, arg)` | frame record `{+0 frame, +0xc flags (bit 2: 0x40-byte record with routines), +0x10 frame buffer cursor, +0x18 stop routine, +0x1c argument, +0x30 check, +0x34 completion, +0x38 position, +0x3c submit}`; out `+0x20 0x5308, +0x24 revision, +0x28 state, +0x2c (bit 2) +0x20 of the session` | 1 | As 0x2e with the frame from `*arg`; the title part is `0x91f622d8`: start capturing on the first frame, process session messages (`0x91f619d8`), write the frame record to the record streams, report state bits 1 per-thread capture, 2 capture to file, 4 GPU capture, 0x10 no frame buffer, 0x20/0x40/0x80 resource capture. | PERF | yes | Title (D3D frame boundary) `[INFERENCE]` |
| 0x53 | `0x91f3b5f8` | `pix_capture_file_open_cmd1` | path | 0 on open failure, else derived | Opens PIX capture file (`0x91f98ef0`), queues capture command 1. | PERF | yes | Unknown |
| 0x54 | `0x91f3b604` | `pix_capture_file_open_cmd5` | path | residual | Opens PIX capture file, queues capture command 5. | PERF | yes | Unknown |
| 0x55 | `0x91f3b5c0` | `pix_capture_file_write_record` | `{+0 type, +4 dwords, +8 data}` | 1, 0 if no file | Appends `{type | 0x80000000, dwords + 2}` + data. | PERF | yes | Unknown |
| 0x56 | `0x91f3b5cc` | `pix_capture_configure` (`0x91f61228`) | `{+0 size, +4 dump enable, +8 title pool enable, +0xc..+0x18 (size >= 0x1c) title budget override flag/size, system budget override flag/size}` | 0 if size < 0xc, else 1 | Stores session `+0x87dc..+0x87f0`; a running capture is stopped, reallocated and restarted. | PERF | yes | Title `[INFERENCE]` |
| 0x57 | `0x91f3b5d8` | `pix_queue_message(+0, +4, +8)` (`0x91f564a0` to `0x91f5f000`) | `{+0 code, +4 payload, +8 size <= 0x50}` | stale | Queues a session message (codes in `parity/performance.md` and group6 `pixcmd`); code 0xc replaces a queued one. | PERF | yes | Title `[INFERENCE]` |
| 0x58 | `0x91f3b5e4` | `pix_stream_register_consumer(+0, +4, 1)` | `{+0 callback, +4 context}` | residual | Registers stream consumer with flag 1. | PERF | no | Unknown |
| 0x59 | `0x91f3b6ec` | `pix_acquire_event_owner` | callback | 1 acquired, 0 busy | Single owner `0x91fa2a38`; starts counter plugin. | PERF | yes | Unknown |
| 0x5a | `0x91f3b6f8` | `pix_release_event_owner` | callback | 1 released, 0 not owner | Stops counter plugin. | PERF | no | Unknown |
| 0x5b | `0x91f3b59c` | `pix_capture_audio_samples` (`0x91f60328`) | block of 0x600 float samples | 1 | While capturing audio (part 3 on): samples x 32768, truncated and saturated to 16 bits, staged in session `+0xe280`; every 0x2000 samples a type 0xc buffer is queued with record `{(drops << 16 | staged) << 3 | 5, sequence, QPC >> 10}`, then the queues are serviced if both session locks are free within 25000 ticks. | PERF | no (spin lock) | K: XAudio render thread |
| 0x5c | `0x91f3b5a8` | `pix_capture_command_buffers` (`0x91f604c8`) | `{+0 status, +4 bytes, +8 alignment, +0xc offset out, +0x10 address array out, +0x14 count out, +0x18 frame out}` | 1 when buffers were handed out | Hands out type 0xd command data buffers for the frame and opens a fence slot (session `+0x150`, 4 x 0x14) with the status (refusals: 1 rate limit, 2 no free buffers with `+0x1c`, 3 too large, 4 GPU part off). | PERF | yes | Title (D3D) `[INFERENCE]` |
| 0x5d | `0x91f3b5b4` | `pix_capture_fence(+0, +4, +8)` (`0x91f5d718`) | `{+0 fence frame, +4, +8}` | 1 | Completes the oldest fence slot (`+0xc`, `+0x10`) and records the frame the GPU reached (`+0xe168`); the next frame writes the slot's buffers and record. Dereferences the missing session. | PERF | no | Title (D3D GPU callback) `[INFERENCE]` |
| 0x5e | `0x91f3b554` | `pix_stream_write_block_list` (`0x91f62998`) | `{ptr, dwords}` pairs, ptr 0 ends | 1 written, `0xffffffff` dropped | Atomic multi-block append to PIX stream ring. `pix_stream_write_tagged_record` falls back to code 0x43 only when this returns 0 (an extension hook result). | PERF | no | xbdm |
| 0x5f | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x60-0x62 | `0x91f3b928`, `0x91f3b934`, `0x91f3b940` | `dm_ctl_noop` | unused | 0 | No operation. | - | no | Unknown |
| 0x63 | `0x91f3b94c` | inline | unused | 0 | If ordinal 342 flags bit `0x02000000`: `0x91f97600 = 0x91f9fd8c` (XConfig (2, 6) bit 1). `0x91f97600 != 0` makes xbdm KiDebugRoutine chain to the saved original routine. | DBG | no | Unknown |
| 0x64 | `0x91f3b974` | `file_event_begin` | file event `{+0 event id (out), +4 op 0..9, +8 handle, +0xc object attributes, +0x10 status, +0x14 length, +0x18 pointer to 64-bit offset, +0x24 create options}` (`0x28` bytes) | 0 | `0x91f2f5c8`. When file events are enabled (`0x91f9f628`) and the current title is neither `0xfffe07d1`/`0xfffe07ff` nor the last terminated title: assigns id, sends `XBDMFE!Begin 0x%08x "Perf=" "Type=" "ThreadId=" "Handle=" "Offset=" "Bytes=" "Flags="` (plus ` "Path=` for operations 0 and 1) through export 36. Kernel performs the operation. | FS | yes | K: Nt file services |
| 0x65 | `0x91f3b980` | `file_event_end` | same record, `+0x10` = result | 0 | `0x91f2f930`. For id != 0 and events enabled, same title exclusion: sends `XBDMFE!End 0x%08x "Perf=" "Handle=" "Result="` through export 36. | FS | yes | K: Nt file services |
| 0x66-0x76 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x77 | `0x91f3b98c` | `dm_ctl_77_get_launch_override` (`0x91f52260`) | launch info (layout of 0x21) | 0 | Launch title `0x91fa2020` when set and `0x91fa2328` clear (not cleared), else for reasons 0/4 the persistent title `0x91fa232c`, else nothing. Strings copied with `strncpy(0x100)` and a terminator at `+0xff`. When copied and version > `0x20076000`: reason 4 with image `\Device\Cdrom0*` runs the disc wait `0x91f52040(image, 5000)`, then `+0x310 = 0`. Disc wait: resolve xam ordinal `0x1a3` once, poll `XamLoaderGetDvdTrayState` every 100 ms up to 50 times while nonzero (still nonzero: DbgPrint `[xbdm] Timed-out waiting for media detect`), call `0x1a3(&media, &type)` and DbgPrint `[xbdm] XamGetMediaInfo() - (media=%d,type=%d)`, and when media is nonzero open the image (`NtOpenFile` SYNCHRONIZE, share read, options `0x60`); the result is not used. | SYS | yes (disc wait) | Unknown |
| 0x78 | `0x91f3bb10` | none | input report | 0 | Default; extension hook only. | HW | no | K: Rgc/Ird/Wgc input; xbdm export 171 |
| 0x79 | `0x91f3bb10` | none | keyboard report | 0 | Default; extension hook only. | HW | no | K: `HidKeyboardInterruptInComplete` |
| 0x7a | `0x91f3b998` | `automation_get_input_state` | `{+0 user, +4 state out, +8 status out}` | residual | Supplies automation gamepad state; status `0xc000009d` if not bound. | HW | no | Unknown |
| 0x7b | `0x91f3b9b0` | `automation_get_connection_status` | `{+0 user, +8 status out}` | residual | Status 0 or `0x48f`. | HW | no | Unknown |
| 0x7c | `0x91f3b9a4` | `automation_get_capabilities` | `{+0 user, +4 caps out, +8 status out}` | residual | Fixed gamepad capabilities or `0x48f`. | HW | no | Unknown |
| 0x7d | `0x91f3bb10` | none | - | 0 | Default; extension hook only. | HW | no | xbdm exports 167/168 |
| 0x7e | `0x91f3b9bc` | inline | unused | 1 or `[0x91f9fef0]` | 1 when DVD emulator state `0x91f9fec8` bit 1; else `0x91f9fef0`. Unknown: writer of `0x91f9fef0` (no code reference). | FS | no | Unknown |
| 0x7f | `0x91f3b9d8` | `hdd_trace_io_start(+0, +4, +8)` | `{+0 is_write, +4 start, +8 sectors}` | 0 | `HDD ` stream record when stream active. | PERF | no | K: `SataDiskStartReadWrite` |
| 0x80 | `0x91f3b9ec` | `hdd_trace_io_complete(arg)` | status (value) | 0 | `HDD ` completion record. | PERF | no | K: `SataDiskFinishReadWrite` |
| 0x81 | `0x91f3b9f8` | `cs_trace_wait_begin` (`0x91f2b798`) | critical section | 0 | Counts the wait in per-processor statistics at KPCR+0x2d0 (+0x18 title, +0x20 system) when enabled; `E:` TellLog line (`0x91f2b680`, through codes 0x89/0x8a/0x88) when mask & 2. | PERF | no `[INFERENCE]` | K: `RtlpWaitCriticalSection` |
| 0x82 | `0x91f3ba04` | `cs_trace_wait_end` (`0x91f2b828`) | critical section | 0 | Same with counters +0x1c title, +0x24 system, and an `L:` line. | PERF | no `[INFERENCE]` | K: `RtlpWaitCriticalSection` |
| 0x83 | `0x91f3ba10` | `resource_capture_begin` | `{+0 path, +4 flag}` | residual | Opens resource capture file `0x91f98ef4`, writes header and timer record. | PERF | yes | Unknown |
| 0x84 | `0x91f3ba1c` | `resource_capture_write_record` | `{+0 type, +4 dwords, +8 data}` | 1, 0 if no file | Appends record; truncation request past 512 MiB. | PERF | yes | Unknown |
| 0x85 | `0x91f3ba28` | `resource_capture_end` | `{+0 notify}` | 1, 0 if no file | Closes; optional `PIX!Resource Complete/Trunc`. | PERF | yes | Unknown |
| 0x86 | `0x91f3ba40` | `dm_ctl_86_adjust_memory_statistics` | `MM_STATISTICS` | 0 | Replaces with debug-adjusted statistics (ExDebugMonitorService 8) when length is `0x68`. Unknown: adjusted field names. | MEM | no | K: `MmQueryStatistics` |
| 0x87 | `0x91f3ba34` | `resource_capture_get_info` | `u32[3]` out | 1, 0 for NULL | Copies `0x91fa2adc..0x91fa2ae4`. | PERF | no | Unknown |
| 0x88 | `0x91f3baa8` | `tell_log_write_message` (`0x91f51d58`) | `{+0 u16 length, +2 u16 unused, +4 text}` | 0 | Queues the record to the open `dmtelllog` engine (export 363); ignored when the log is closed or closing, or length or text is 0. Area mask not tested; issuers test code 0x8a. | SES | yes (`block=1` waits for a free entry) | K: `DmPrintData`; xbdm (`0x91f2b530`) |
| 0x89 | `0x91f3bab4` | `tell_log_get_max_message_size` | unused | size or 0 | | SES | no | K: `DmPrintData`; xbdm |
| 0x8a | `0x91f3babc` | `tell_log_get_category_mask` | unused | mask or 0 | | SES | no | K: `DmPrintData`; xbdm |
| 0x8b, 0x8c | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x8d | `0x91f3ba4c` | `pix_nuicam_begin_timing_event` (`0x91f56628`) | event name | 0 | Names the current thread `NuiCam Driver` (code 0x34) and writes a named begin record (kind 0x1d) into the processor's capture buffer; a full buffer uses the formatted writer `0x91f78188` with code 0x50 type 0. | PERF | no | Unknown (not xbdm) |
| 0x8e | `0x91f3ba58` | `pix_timing_end_event` (`0x91f78760`) | unused | 0 | End record (kind 0) in the processor's capture buffer; a full buffer asks code 0x50 type 1. | PERF | yes (via 0x50) | Unknown (not xbdm) |
| 0x8f-0x95 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0x96 | `0x91f3ba64` | `nuicam_complete_raw_data_request` | `{+0 bool, +4 u16, +6 u8, +8 data, +0xc length}` | 0 | Completes oldest queued raw-data request, sets its event. | HW | no | K: `NuiCamCaptureRawData` |
| 0x97 | `0x91f3ba70` | `nuicam_queue_raw_data_request` | request node `{+0/+4 links, +8 event, +0xc buffer, +0x10 size, +0x14, +0x1c u16, +0x1e u8, +0x1f}` | 0 | Queues request; first enables capture via xam ordinal `0x30d` callback `{0xa, 1}`. | HW | no | Unknown |
| 0x98 | `0x91f3ba7c` | `nuicam_flush_raw_data_requests` | unused | 0 | Empties request list. | HW | no | Unknown |
| 0x99 | `0x91f3ba84` | `xstudio_set_device_status` (`0x91f65ab8`) | `{+0 u8 status}` | 0 | Under spin lock `0x91fab700` taken at raised IRQL: if the studio subsystem is initialized (`0x91fab704`), stores the byte in `0x91fab708` and alerts the server thread, whose pass (`0x91f65a18`) starts the null-cable session for a nonzero status or stops it. Also issued through `NullCableRequest(4, 0)` from studio init and session stop. openxbdm: `performance::studio::service_set_device_status`; the server pass runs within 20 ms without the alert. | PERF | no | K: `NullCableReportDeviceStatus` |
| 0x9a-0x9e | `0x91f3bb10` | none | - | 0 | Default. 0x9b is issued by K `NuiCamCaptureFrameStart`. | - | no | Unknown / K (0x9b) |
| 0x9f | `0x91f3ba9c` | `xstudio_set_test_mode` (`0x91f65dd0`) | `{+4 enable}` | 0 | DbgPrint `XStudioSlave: Setting Test Mode\n` / `XStudioSlave: Disabling Test Mode\n`; stores `+4` in `0x91fab714` under the spin lock (not gated on init); alerts the server thread. Test mode stops the null-cable session and blocks every session start. openxbdm: `performance::studio::service_set_test_mode`. | PERF | no | Unknown |
| 0xa0 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0xa1 | `0x91f3ba90` | `nuicam_set_capture_mode` | `{+0 op, +4 value in/out}` | 0 | op 1: returns old mode, sets 1; else sets value; flushes requests; xam callback `{0xa, value or 0}`. | HW | no | Unknown |
| 0xa2, 0xa3 | `0x91f3bb10` | none | - | 0 | Default. | - | no | Unknown |
| 0xa4 | `0x91f3bac4` | inline | value | 0 | `0x91f9fd90 = (arg != 0)`; consulted by xbdm KiDebugRoutine for `0x80000003`/`0x80000004` exceptions. Unknown: caller purpose. | DBG | no | Unknown |
| 0xa5 | `0x91f3bad8` | `http_proxy_acquire` | `{+0 mode 1|2, +8 name out, +0xc port out, +0x10 u8 in/out}` | residual | Selects active `xhttpproxy` entry, increments reference. | NET | yes | Unknown |
| 0xa6 | `0x91f3bae4` | `http_proxy_release` | `{+0 mode, +8 name, +0xc port}` | residual | Decrements reference, frees at zero. | NET | yes | Unknown |
| 0xa7 | `0x91f3baf0` | `http_proxy_invoke_cert_callback` | `{+0 mode, +8 name, +0xc port, +0x14, +0x18, +0x1c ctx, +0x20 callback}` | XBDM status | Calls callback with proxy certificate. | NET | yes | Unknown |
| 0xa8 | `0x91f3bafc` | export 372 | thread name | 0 | Executes all queued remote call requests for the named thread. | DBG | yes | Unknown |
| 0xa9 | `0x91f3bb08` | export 36 `send_notification` (`0x91f3b070`) | text | 0 | Text needs `!` before any byte <= 0x20, else nothing. Calls notification extension handlers whose name prefix matches (list `0x91fadc00`), then at IRQL 0 sends the text to every notification socket. xbdm calls export 36 directly (`fileevent`, codes 0x64/0x65). | SES | yes (critical section at IRQL 0) | Unknown |

Unknown (global): issuers of the codes marked Unknown are outside K15574/K16547 and outside xbdm; candidates are xam and statically linked title libraries (D3D/PIX, XAudio, XInput), not verified because those images are not loaded.
