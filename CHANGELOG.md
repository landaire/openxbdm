# Changelog

## Unreleased

- Add allocation-free XBDM request dispatch with console, filesystem, memory, and process backend interfaces.
- Add bounded memory transfers with exact unreadable-byte and partial-write reporting.
- Add a deterministic TCP mock server compatible with openxbdm-client information and memory commands.
- Add an end-to-end TCP test that exercises stateful mock behavior through the published openxbdm-client library.
- Record the XBDM command inventory and behavior nuances.
- Call Xbox imports through stubs that reserve the console parameter home area.
- Build the Xbox module with the small-page image flag required for the `0x90000000` region.
- Deploy the Xbox module as `DEVKIT:\FlashEx\xbdm.xex` with a matching bounding path; it attempts to remove that file at startup and accepts `delete` only for it.
- Implement Xbox target `getmem` through the kernel debugger read check (ordinal 427).
