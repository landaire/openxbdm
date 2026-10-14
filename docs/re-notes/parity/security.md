# Parity: security domain (lock mode, users, authentication)

Specs: `commands/group1.md` (adminpw, authuser, boxid), `group4.md`
(getuserpriv), `group5.md` (keyxchg, lockmode), `group7.md` (setuserpriv),
`group8.md` (user, userlist); `framework.md` section 2 (lock-mode banner).
Shared primitives: `crates/openxbdm-core/src/auth.rs` (response function,
768-bit modular exponentiation, session key). Server:
`crates/openxbdm-server/src/commands/security.rs`. Host mock:
`crates/openxbdm-server-host/src/backend/security.rs`. Xbox backend:
`crates/openxbdm-server-xbox360/src/backend/security.rs`. Tests:
`crates/openxbdm-server-host/tests/security.rs`. Client:
`crates/openxbdm-client/src/commands/security.rs`,
`Client::{banner, lock_challenge, key_exchange}`.

| Command | Wire | Host mock | Xbox backend |
| --- | --- | --- | --- |
| adminpw | matches (`421` without key exchange, `400- missing passwd`, `none`) | server state | server state |
| authuser | matches, including the stored zero privileges after a failure and `421` for users without a password | user directory | user directory |
| boxid | matches | server state | server state |
| getuserpriv | matches (`me`, `none`, word order, manage check, `402`) | user directory | user directory |
| keyxchg | matches: 204, 0x60 bytes in, 203, 0x60 bytes out | `random_bytes` (xorshift) | `XNetRandom` |
| lockmode | matches, including the encrypt texts and relock rules | user removal | user removal |
| setuserpriv | matches; does not save settings | user directory | user directory |
| user | matches, including object-manager name rules | simulated directory | kernel objects |
| userlist | matches: directory order, ends when unlocked meanwhile | simulated directory | `NtQueryDirectoryObject` |

Settings lines (`settings_lines`, stock 0x91f40ab0): `lockmode
boxid=0q%08x%08x[ encrypt]` while locked, `adminpw passwd=0q%08x%08x`
while set, then while locked one `user name="<name>"[ passwd=0q..][
<privileges>]` line per user in directory order. Replayed lines run with
no connection: `adminpw` uses a zero key and `user` honors `passwd=`.

Framework: the lock-mode banner nonce is kept per connection slot
(`Server::nonces`); an unlocked connection inherits it as stock does.

## User directory

Stock keeps users as permanent objects (type 0x91f976a8, pool tag `SUmd`,
body: password qword, privilege dword, password-set dword) in an unnamed
object directory (handle 0x91f9fecc). The Xbox backend does the same with
its own object type whose allocate and free procedures are the kernel's
`ExAllocatePoolTypeWithTag` and `ExFreePool` exports. The host mock
reproduces the directory rules taken from the K15574 kernel image: 13
buckets, `h = (c | 0x20) + (h >> 1) + 3h` over bytes below 0x80, newest
entry first in a bucket, global-index enumeration, `RtlUpperChar` case
folding, and relative path resolution of names with backslashes.

## Exports

Exports 58-64 (`docs/re-notes/exports.md`) share the commands' state: the
lock mode (stock 0x91fab9ac: 0 unlocked, 1 locked, 2 locked with file
encryption) and the user directory. The logic is in
`commands/security.rs` (`set_user_access`, `user_access`, `walk_users`,
`add_user`, `enable_security`, `security_enabled`, `remove_user`), also
used by `setuserpriv` and `user`; the Xbox glue in `backend/security.rs`
runs each on the server thread through `dispatcher::call_on_server` and
writes the settings file before returning where stock calls the writer
(61, 64). Host test: `exports_share_lock_state_and_users_with_commands`.

| Ordinal | Stock | Behavior |
| --- | --- | --- |
| 58 | 0x91f40d98 | Store the access dword of a user; `0x82da0002` when absent. Not saved. |
| 59 | 0x91f40de8 | Read the access dword; `0x82da0002` when absent. |
| 60 | 0x91f40e38 | Walk users: `E_INVALIDARG` for a null walk position; `0x82da0104` while unlocked or at the end; fills a 0x104-byte `DM_USER` (zeroed name buffer, access at +0x100); `E_UNEXPECTED` when the named user vanished. |
| 61 | 0x91f40680 (via 0x91f407a8) | Create a user with no password: `0x82da0014` while unlocked, `0x82da000a` when it exists, `E_OUTOFMEMORY` when the object cannot be created; saves the settings. |
| 62 | 0x91f40f30 | Lock (nonzero) or unlock: the mode becomes 1 or 0, so enabling drops file encryption and keeps the box id; unlocking deletes every user. Not saved. |
| 63 | 0x91f40648 | `E_INVALIDARG` for a null output; stores whether the mode is nonzero. |
| 64 | 0x91f407e8 | Delete a user; `0x82da0002` when absent; saves the settings on success. |

Stock's writer called from a title thread signals the server thread and
waits up to one second; from a system thread it writes directly. Every
export here waits for the server thread. Called on the server thread
itself (a command processor callback), above passive level, or after the
server stopped, the server state is unreachable and the export returns
`E_UNEXPECTED`; stock runs these exports on the calling thread (above
passive level its critical section and object manager calls are invalid).

## Deliberate difference

- A failed `ObInsertObject` (names with a leading or a single inner
  backslash, `400- out of memory`) already releases the creation
  reference. Stock dereferences the object once more (0x91f40764), which
  releases freed pool. The Xbox backend does not repeat that release; the
  reply is the same.
- Export 61 accepts names longer than the 64 bytes the 0x4c-byte
  directory query buffer holds. The kernel query (0x800b41f0) truncates
  the copied name but reports its full length, and stock export 60 copies
  that many bytes from its stack buffer into the 0x104-byte record,
  reading past the buffer and, beyond 0x104 bytes, writing past the
  record. openxbdm ends the walk (and `userlist`) at such an entry.

## Unverified on hardware

- The directory rules come from the K15574 debug kernel, not the kernel
  the target console runs.
- The DH base is not validated by the kernel. A client value at or above
  the modulus is reduced before exponentiation here; the kernel's
  Montgomery routines were not traced for that input.
- Network `user` requests leave the stock password field uninitialized
  with the password-set flag clear; the value is never read, so the Xbox
  backend stores zero.
