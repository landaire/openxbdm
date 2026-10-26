# Parity: security domain (lock mode, users, authentication)

Specs: `commands/group1.md` (adminpw, authuser, boxid), `group4.md`
(getuserpriv), `group5.md` (keyxchg, lockmode), `group7.md` (setuserpriv),
`group8.md` (user, userlist); `framework.md` section 2 (lock-mode banner).
Shared primitives: `openxbdm/core/src/auth.rs` (response function,
768-bit modular exponentiation, session key). Server:
`openxbdm/server/src/commands/security.rs`. Host mock:
`openxbdm/server/host/src/backend/security.rs`. Xbox backend:
`openxbdm/server/xbox360/src/backend/security.rs`. Tests:
`openxbdm/server/host/tests/security.rs`. Client:
`openxbdm/client/src/commands/security.rs`,
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
reproduces the kernel's directory rules: 13 buckets, `h = (c | 0x20) +
(h >> 1) + 3h` over bytes below 0x80, newest entry first in a bucket,
global-index enumeration, `RtlUpperChar` case folding, and relative path
resolution of names with backslashes. The rules were read from K15574
(PDB symbols); K16547, the kernel the console runs, has the same code: its
object manager 0x800b3990..0x800b6790 and string routines
0x800afad0..0x800aff90 match K15574 0x800b3600..0x800b6400 and
0x800af740..0x800afc00 instruction for instruction except for global data
addresses and call targets of the same routines, and its `RtlUpperChar`
table (0x800429c0) equals K15574's (0x80042988).

## Key exchange

`XeCryptBnDwLeDhModExp` (K16547 0x801508f8) does not validate or reduce
the base. `XeCryptBnQwNeModExp` (0x801511a0) copies it raw into its power
table and multiplies with full products reduced by
`XeCryptBnQwNe_BenalohMod` (0x80150f88), which keeps every 1536-bit
product congruent modulo the group modulus and within 768 bits; the result
is reduced with `XeCryptBnQwNeMod` (0x80156620) at the end. These routines
and their helpers match K15574 (0x8014e908..0x8014fdb0,
0x801547f0..0x80155060) instruction for instruction except for call
targets and the default group address. A client value at or above the
modulus therefore yields (value mod modulus) ^ x mod modulus, which
`dh_mod_exp` computes by subtracting the modulus first. An emulation of the
reduction routine over products with bases in [modulus, 2^768) kept
congruence and ended within two correction additions.

The group table at 0x91f06090 reaches the kernel without the per-qword
byte swap applied to client values (0x80150970..0x80150988), so the
kernel reads each table qword big-endian: the generator is 2^761 and, in
wire layout, each modulus qword is the table qword byte reversed.

On the devkit, stock XBDM confirmed both results. A client value of
2^761 made the shared value equal to the server's public value, and 2^705
did not. The modulus plus 1 gave a shared value of 1 and the modulus gave
0. Each case was checked by setting `adminpw passwd=` with the key that
the expected shared value derives and then authenticating with `authuser
admin` on a new unlocked connection. Test:
`stock_group_reduces_the_modulus_and_its_successor` (`openxbdm-core`).

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
- Network `user` requests: stock copies an uninitialized stack qword into
  the password field (0x91f40770) with the password-set flag clear. Every
  reader of the field (the response check 0x91f405d0, the settings line
  0x91f40a40) runs only while the flag is set, and each store that sets
  the flag writes the password with it (`authuser` 0x91f40610/0x91f40614;
  the add copy 0x91f40778/0x91f40780 for a settings line with `passwd=`),
  so the value is never observable. The Xbox backend stores zero.
