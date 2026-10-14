# Behavioral nuance ledger

- XBDM command table entries are 20 bytes, but handler pointers may target labels inside shared functions.
- Command access flags are observed values only. Their semantic names are not assigned yet.
- `getmem` returns 202 text with hexadecimal bytes. Unmapped bytes use `??`; they are not omitted.
- `setmem` can report a shorter count than requested if a page becomes unwritable or unmapped.
- Binary download and upload bodies use different status codes: 203 sends data, 204 requests data.
- Notification traffic uses a dedicated connection and may arrive independently of command replies.
- Internal drive setup is not known to be idempotent. Re-running symbolic-link registration can encounter existing names.
- Mock server state is per connection. This prevents one test from changing another test's debug name or memory.
- Mock memory uses a bounded mapped range. Out-of-range access must remain distinguishable from access denial and malformed arguments.
- Console callees store r3-r10 into the caller frame at sp+0x10..sp+0x50. The Xbox target calls every import through a stub that allocates that area. Without it, `DbgPrint` overwrote the saved LR of `_start` with a live register value and the loader thread jumped into `.bss`.
- Stock XBDM `dbgextld name=` loads `DEVKIT:\DMEXT\<name>`. It has one extension slot; a second load fails with `443` until the first is unloaded with `dbgextld unload module=<handle>`.
- Stock XBDM owns TCP port 730. A replacement module loaded beside it cannot listen and retries every second.
