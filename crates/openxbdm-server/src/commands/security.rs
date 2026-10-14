//! Security commands: lock mode, users, privileges, and authentication.
//!
//! Users live in the platform's user directory (the monitor keeps them as
//! kernel objects in an unnamed object directory); this module applies the
//! monitor's rules on top of it.

use core::fmt::Write as _;

use openxbdm_core::auth;
use openxbdm_core::auth::DH_LENGTH;
use openxbdm_core::auth::DhValue;
use openxbdm_core::auth::SessionKey;
use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;
use openxbdm_core::status::Hresult;

use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::system;
use crate::commands::system::SettingsFile;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::state::LockMode;
use crate::state::ServerState;
use crate::text::Text;

/// Bytes of a stored user name, including the terminator.
pub const USER_NAME_CAPACITY: usize = 0x40;
/// Name buffers of `getuserpriv` and `setuserpriv`.
const LOOKUP_NAME_CAPACITY: usize = 0x80;
/// Name buffer of `authuser`.
const AUTH_NAME_CAPACITY: usize = 0x100;

const fn entry(
    name: &'static str,
    any_of: Access,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry {
        name,
        any_of,
        all_of: Access::NONE,
        flags: DispatchFlags::NONE,
        handler,
    }
}

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry("adminpw", Access::MANAGE, admin_password),
    entry("authuser", Access::NONE, authenticate_user),
    entry("boxid", Access::NONE, box_id),
    entry("getuserpriv", Access::NONE, get_user_privileges),
    entry("keyxchg", Access::NONE, key_exchange),
    entry("lockmode", Access::MANAGE, lock_mode),
    entry("setuserpriv", Access::MANAGE, set_user_privileges),
    entry("user", Access::MANAGE, user),
    entry("userlist", Access::MANAGE, user_list),
];

/// Privilege words in the order the monitor parses and prints them.
const PRIVILEGE_WORDS: [(Access, &str); 5] = [
    (Access::READ, "read"),
    (Access::WRITE, "write"),
    (Access::CONTROL, "control"),
    (Access::CONFIG, "config"),
    (Access::MANAGE, "manage"),
];

/// A user or administrator password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Password(pub u64);

/// A user record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct User {
    /// `None` until the user sets one through `authuser` after a key
    /// exchange, or a settings line supplies it.
    pub password: Option<Password>,
    pub privileges: Access,
}

/// A name as the user directory query returns it: at most 64 bytes, the
/// name room of the 0x4c-byte query buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserName {
    bytes: [u8; USER_NAME_CAPACITY],
    length: u8,
}

impl UserName {
    /// `None` when `name` does not fit.
    pub fn new(name: &[u8]) -> Option<Self> {
        if name.len() > USER_NAME_CAPACITY {
            return None;
        }
        let mut bytes = [0; USER_NAME_CAPACITY];
        bytes[..name.len()].copy_from_slice(name);
        Some(Self {
            bytes,
            length: name.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

impl core::fmt::Debug for UserName {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self.as_bytes().escape_ascii())
    }
}

/// The user directory could not create the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserCreationFailed;

/// Global state of this domain.
#[derive(Debug, Default)]
pub struct State {
    /// Stored administrator password: the sent value XORed with the
    /// sender's session key.
    pub admin_password: Option<Password>,
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// `userlist`: index of the next directory entry.
    UserList(u32),
    KeyExchange(KeyExchange),
}

/// `keyxchg` transfer: the client value is received, then the server value
/// is sent in the same buffer.
#[derive(Debug)]
pub struct KeyExchange {
    value: DhValue,
    phase: KeyExchangePhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyExchangePhase {
    Receiving,
    Sending,
    Sent,
}

/// The user directory. Names follow the console object manager: lookups
/// ignore case, a single trailing backslash is ignored, and enumeration
/// order is the directory's hash order.
pub trait Backend {
    fn find_user(&mut self, name: &[u8]) -> Option<User>;
    /// Replace the record of an existing user; false when not found.
    fn store_user(&mut self, name: &[u8], user: User) -> bool;
    /// Create a user known not to exist.
    fn create_user(&mut self, name: &[u8], user: User) -> Result<(), UserCreationFailed>;
    /// Delete a user; false when not found.
    fn remove_user(&mut self, name: &[u8]) -> bool;
    /// Name of the directory entry at `index`, or `None` past the end.
    fn user_name_at(&mut self, index: u32) -> Option<UserName>;
}

pub(crate) fn resume(continuation: &mut Continuation, cx: &mut ContinuationContext<'_>) -> Hresult {
    match continuation {
        Continuation::UserList(index) => resume_user_list(index, cx),
        Continuation::KeyExchange(exchange) => resume_key_exchange(exchange, cx),
    }
}

/// Settings lines: the lock state, the administrator password, and, while
/// locked, one line per user.
pub(crate) fn settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    let lock = state.lock;
    if lock.is_locked() {
        let suffix = if lock.mode == LockMode::LockedEncrypted {
            " encrypt"
        } else {
            ""
        };
        system::write_line(
            backend,
            file,
            format_args!(
                "lockmode boxid=0q{:08x}{:08x}{suffix}",
                lock.box_id[0], lock.box_id[1]
            ),
        );
    }
    if let Some(Password(password)) = state.security.admin_password {
        system::write_line(
            backend,
            file,
            format_args!(
                "adminpw passwd=0q{:08x}{:08x}",
                (password >> 32) as u32,
                password as u32
            ),
        );
    }
    if !lock.is_locked() {
        return;
    }
    let mut index = 0;
    while let Some(name) = backend.user_name_at(index) {
        index += 1;
        let Some(user) = backend.find_user(name.as_bytes()) else {
            continue;
        };
        // Stock formats the line into one buffer (0x91f40ab0), so the
        // settings trace echoes it once.
        let mut line = crate::text::Text::<0x200>::new();
        let _ = line.push_bytes(b"user name=\"");
        let _ = line.push_bytes(name.as_bytes());
        let _ = line.push_bytes(b"\"");
        if let Some(Password(password)) = user.password {
            let _ = write!(
                line,
                " passwd=0q{:08x}{:08x}",
                (password >> 32) as u32,
                password as u32
            );
        }
        for (bit, word) in PRIVILEGE_WORDS {
            if user.privileges.intersects(bit) {
                let _ = write!(line, " {word}");
            }
        }
        system::write_bytes(backend, file, line.as_bytes());
        system::end_line(backend, file);
    }
}

fn parse_privileges(line: &CommandLine<'_>) -> Access {
    PRIVILEGE_WORDS
        .iter()
        .filter(|(_, word)| line.has(word))
        .fold(Access::NONE, |privileges, &(bit, _)| privileges.union(bit))
}

/// Append ` read`, ` write`, ... for each privilege held.
fn push_privileges<const N: usize>(text: &mut Text<N>, privileges: Access) {
    for (bit, word) in PRIVILEGE_WORDS {
        if privileges.intersects(bit) {
            let _ = write!(text, " {word}");
        }
    }
}

fn qword(words: [u32; 2]) -> u64 {
    (u64::from(words[0]) << 32) | u64::from(words[1])
}

/// `lockmode unlock` | `lockmode boxid=<qword> [encrypt]` | `lockmode encrypt`.
fn lock_mode(invocation: &mut Invocation<'_>) -> Hresult {
    let mut result = Hresult::OK;
    let lock = &mut invocation.state.lock;
    if invocation.line.has("unlock") {
        lock.mode = LockMode::Unlocked;
        remove_all_users(invocation.backend);
    } else if lock.is_locked() {
        // Relocking keeps the box id and drops file encryption.
        lock.mode = LockMode::Locked;
    } else if let Some(box_id) = invocation
        .line
        .param("boxid")
        .and_then(|value| value.qword())
    {
        lock.box_id = [(box_id >> 32) as u32, box_id as u32];
        lock.mode = LockMode::Locked;
    } else {
        invocation.set_text(format_args!("missing parameters"));
        result = Hresult::FAIL;
    }
    if invocation.line.has("encrypt") {
        if invocation.state.lock.is_locked() {
            invocation.state.lock.mode = LockMode::LockedEncrypted;
            result = Hresult::OK;
        } else {
            invocation.set_text(format_args!("box not locked; file encryption not enabled"));
        }
    }
    invocation.state.settings_dirty = true;
    result
}

/// Delete every user. Each deletion restarts the enumeration, as entries
/// shift.
fn remove_all_users(backend: &mut dyn AnyBackend) {
    let mut index = 0;
    while let Some(name) = backend.user_name_at(index) {
        if backend.remove_user(name.as_bytes()) {
            index = 0;
        } else {
            index += 1;
        }
    }
}

fn box_id(invocation: &mut Invocation<'_>) -> Hresult {
    let lock = invocation.state.lock;
    if !lock.is_locked() {
        return Hresult::from_error_code(ErrorCode::BOX_NOT_LOCKED);
    }
    invocation.set_text(format_args!(
        "boxid=0q{:08x}{:08x}",
        lock.box_id[0], lock.box_id[1]
    ));
    Hresult::OK
}

/// `adminpw none` | `adminpw passwd=<qword>`. A connection must have
/// exchanged keys; the stored value is the sent value XORed with the
/// session key (zero for settings lines).
fn admin_password(invocation: &mut Invocation<'_>) -> Hresult {
    if invocation.line.has("none") {
        invocation.state.security.admin_password = None;
        invocation.state.settings_dirty = true;
        return Hresult::OK;
    }
    let key = match invocation.session.as_deref() {
        // Settings lines carry the stored value unencrypted.
        None => SessionKey(0),
        Some(session) => match session.session_key {
            Some(key) => key,
            None => return Hresult::from_error_code(ErrorCode::KEY_EXCHANGE_REQUIRED),
        },
    };
    let Some(password) = invocation
        .line
        .param("passwd")
        .and_then(|value| value.qword())
    else {
        invocation.set_text(format_args!("missing passwd"));
        return Hresult::FAIL;
    };
    invocation.state.security.admin_password = Some(Password(password ^ key.0));
    invocation.state.settings_dirty = true;
    Hresult::OK
}

/// How `authuser` uses its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    /// The value is the response to the banner challenge.
    Response,
    /// The value is a new password (decrypted with the session key).
    SetPassword,
}

/// `authuser (resp=<qword> | passwd=<qword>) (admin | name=<string>)`.
/// The resulting privileges replace the connection's, even when zero.
fn authenticate_user(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Hresult::FAIL;
    };
    let line = invocation.line;
    let password = session.session_key.and_then(|key| {
        line.param("passwd")
            .and_then(|value| value.qword())
            .map(|password| password ^ key.0)
    });
    let (mut mode, value) = match password {
        Some(password) => (AuthMode::SetPassword, password),
        None => match line.param("resp").and_then(|value| value.qword()) {
            Some(response) => (AuthMode::Response, response),
            None => {
                invocation.text.set_bytes(b"missing response");
                return Hresult::FAIL;
            }
        },
    };
    let challenge = auth::Nonce(qword(session.nonce));

    let privileges = if line.has("admin") {
        if mode == AuthMode::SetPassword {
            invocation.text.set_bytes(b"missing response");
            return Hresult::FAIL;
        }
        match invocation.state.security.admin_password {
            Some(Password(secret))
                if auth::response(auth::Password(secret), challenge).0 == value =>
            {
                Access::ALL
            }
            _ => Access::NONE,
        }
    } else {
        let Some(name) = line.param("name") else {
            invocation.text.set_bytes(b"missing name");
            return Hresult::FAIL;
        };
        let mut buffer = [0u8; AUTH_NAME_CAPACITY];
        let name = name.copy_into(&mut buffer);
        match invocation.backend.find_user(name) {
            None => Access::NONE,
            Some(user) => match (user.password, mode) {
                (Some(Password(secret)), AuthMode::Response) => {
                    if auth::response(auth::Password(secret), challenge).0 == value {
                        user.privileges
                    } else {
                        Access::NONE
                    }
                }
                (Some(_), AuthMode::SetPassword) => {
                    mode = AuthMode::Response;
                    Access::NONE
                }
                (None, AuthMode::SetPassword) => {
                    let updated = User {
                        password: Some(Password(value)),
                        ..user
                    };
                    invocation.backend.store_user(name, updated);
                    invocation.state.settings_dirty = true;
                    mode = AuthMode::Response;
                    user.privileges
                }
                (None, AuthMode::Response) => {
                    mode = AuthMode::SetPassword;
                    Access::NONE
                }
            },
        }
    };
    session.access = privileges;
    if privileges != Access::NONE {
        Hresult::OK
    } else if mode == AuthMode::SetPassword {
        Hresult::from_error_code(ErrorCode::KEY_EXCHANGE_REQUIRED)
    } else {
        Hresult::from_error_code(ErrorCode::ACCESS_DENIED)
    }
}

/// `getuserpriv me` | `getuserpriv name=<string>` (needs manage).
fn get_user_privileges(invocation: &mut Invocation<'_>) -> Hresult {
    let access = invocation.access();
    let privileges = if invocation.line.has("me") {
        if invocation.session.is_none() {
            return Hresult::FAIL;
        }
        access
    } else {
        if !access.intersects(Access::MANAGE) {
            return Hresult::from_error_code(ErrorCode::ACCESS_DENIED);
        }
        let Some(name) = invocation.line.param("name") else {
            invocation.text.set_bytes(b"missing name");
            return Hresult::FAIL;
        };
        let mut buffer = [0u8; LOOKUP_NAME_CAPACITY];
        let name = name.copy_into(&mut buffer);
        match invocation.backend.find_user(name) {
            Some(user) => user.privileges,
            None => return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND),
        }
    };
    invocation.text.clear();
    if privileges == Access::NONE {
        invocation.text.set_bytes(b"none");
    } else {
        // The monitor writes each word with a leading space one byte before
        // the reply text, so the first space is dropped.
        let mut words = Text::<48>::new();
        push_privileges(&mut words, privileges);
        invocation
            .text
            .set_bytes(words.as_bytes().get(1..).unwrap_or_default());
    }
    Hresult::OK
}

/// `setuserpriv name=<string> [read] [write] [control] [config] [manage]`:
/// replaces the user's privileges. The change is not written to settings.
fn set_user_privileges(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(name) = invocation.line.param("name") else {
        invocation.text.set_bytes(b"missing name");
        return Hresult::FAIL;
    };
    let mut buffer = [0u8; LOOKUP_NAME_CAPACITY];
    let name = name.copy_into(&mut buffer);
    let privileges = parse_privileges(&invocation.line);
    set_user_access(invocation.backend, name, privileges)
}

/// Replace the privileges of an existing user (`setuserpriv`, export 58).
pub fn set_user_access(backend: &mut dyn AnyBackend, name: &[u8], access: Access) -> Hresult {
    match backend.find_user(name) {
        Some(user)
            if backend.store_user(
                name,
                User {
                    privileges: access,
                    ..user
                },
            ) =>
        {
            Hresult::OK
        }
        _ => Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND),
    }
}

/// Privileges of a user (export 59).
pub fn user_access(backend: &mut dyn AnyBackend, name: &[u8]) -> Result<Access, Hresult> {
    backend
        .find_user(name)
        .map(|user| user.privileges)
        .ok_or(Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND))
}

/// `user name=<string> remove` | `user name=<string> [privileges]`.
/// Settings lines may also carry `passwd=<qword>`.
fn user(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(name) = invocation.line.param("name") else {
        invocation.text.set_bytes(b"missing name");
        return Hresult::FAIL;
    };
    let mut buffer = [0u8; USER_NAME_CAPACITY];
    let name = name.copy_into(&mut buffer);
    if invocation.line.has("remove") {
        return remove_user(invocation.state, invocation.backend, name);
    }
    let password = match invocation.session {
        None => invocation
            .line
            .param("passwd")
            .and_then(|value| value.qword())
            .map(Password),
        Some(_) => None,
    };
    let privileges = parse_privileges(&invocation.line);
    add_user(
        invocation.state,
        invocation.backend,
        name,
        User {
            password,
            privileges,
        },
    )
}

/// Create a user while the box is locked (`user`, export 61).
pub fn add_user(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
    user: User,
) -> Hresult {
    if !state.lock.is_locked() {
        return Hresult::from_error_code(ErrorCode::BOX_NOT_LOCKED);
    }
    if backend.find_user(name).is_some() {
        return Hresult::from_error_code(ErrorCode::FILE_ALREADY_EXISTS);
    }
    if backend.create_user(name, user).is_err() {
        return Hresult::OUT_OF_MEMORY;
    }
    state.settings_dirty = true;
    Hresult::OK
}

/// Delete a user (`user remove`, export 64).
pub fn remove_user(state: &mut ServerState, backend: &mut dyn AnyBackend, name: &[u8]) -> Hresult {
    if !backend.remove_user(name) {
        return Hresult::from_error_code(ErrorCode::FILE_NOT_FOUND);
    }
    state.settings_dirty = true;
    Hresult::OK
}

/// Lock (`true`) or unlock the box (export 62). Locking drops file
/// encryption and keeps the box id; unlocking deletes every user. The
/// settings are not written.
pub fn enable_security(state: &mut ServerState, backend: &mut dyn AnyBackend, enable: bool) {
    if enable {
        state.lock.mode = LockMode::Locked;
    } else {
        state.lock.mode = LockMode::Unlocked;
        remove_all_users(backend);
    }
}

/// Whether the box is locked (export 63).
pub fn security_enabled(state: &ServerState) -> bool {
    state.lock.is_locked()
}

/// The user at walk position `position`, advancing it (export 60); the
/// walk restarts at position 0. `END_OF_DATA` ends the walk, also while
/// the box is unlocked.
pub fn walk_users(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    position: &mut u32,
) -> Result<(UserName, Access), Hresult> {
    if !state.lock.is_locked() {
        return Err(Hresult::END_OF_DATA);
    }
    let name = backend
        .user_name_at(*position)
        .ok_or(Hresult::END_OF_DATA)?;
    *position += 1;
    let user = backend
        .find_user(name.as_bytes())
        .ok_or(Hresult::UNEXPECTED)?;
    Ok((name, user.privileges))
}

fn user_list(invocation: &mut Invocation<'_>) -> Hresult {
    if !invocation.state.lock.is_locked() {
        return Hresult::from_error_code(ErrorCode::BOX_NOT_LOCKED);
    }
    let Some(session) = invocation.session.as_deref_mut() else {
        return Hresult::FAIL;
    };
    session.continuation = crate::continuation::Continuation::Security(Continuation::UserList(0));
    Hresult::MULTILINE
}

/// One `name="<name>" <privileges>` line per user. The list also ends when
/// the box is unlocked meanwhile.
fn resume_user_list(index: &mut u32, cx: &mut ContinuationContext<'_>) -> Hresult {
    if !cx.state.lock.is_locked() {
        return Hresult::END_OF_DATA;
    }
    let Some(name) = cx.backend.user_name_at(*index) else {
        return Hresult::END_OF_DATA;
    };
    *index += 1;
    let Some(user) = cx.backend.find_user(name.as_bytes()) else {
        return Hresult::END_OF_DATA;
    };
    let _ = cx.line.push_bytes(b"name=\"");
    let _ = cx.line.push_bytes(name.as_bytes());
    let _ = cx.line.push_bytes(b"\"");
    push_privileges(cx.line, user.privileges);
    Hresult::OK
}

/// `keyxchg`: receives the client's 0x60-byte public value, replies with
/// the server's, and sets the session key from the shared secret.
fn key_exchange(invocation: &mut Invocation<'_>) -> Hresult {
    let Some(session) = invocation.session.as_deref_mut() else {
        return Hresult::FAIL;
    };
    session.continuation =
        crate::continuation::Continuation::Security(Continuation::KeyExchange(KeyExchange {
            value: DhValue([0; DH_LENGTH]),
            phase: KeyExchangePhase::Receiving,
        }));
    session.receive_remaining = Some(DH_LENGTH as u32);
    Hresult::SEND_BINARY
}

fn resume_key_exchange(exchange: &mut KeyExchange, cx: &mut ContinuationContext<'_>) -> Hresult {
    match exchange.phase {
        KeyExchangePhase::Receiving => {
            let remaining = cx.session.receive_remaining.unwrap_or(0) as usize;
            if cx.received.is_empty() {
                cx.session.receive_remaining = Some(0);
                return Hresult::UNEXPECTED;
            }
            let offset = DH_LENGTH - remaining;
            let count = cx.received.len().min(remaining);
            exchange.value.0[offset..offset + count].copy_from_slice(&cx.received[..count]);
            let remaining = remaining - count;
            cx.session.receive_remaining = Some(remaining as u32);
            if remaining != 0 {
                return Hresult::OK;
            }
            let mut exponent = DhValue([0; DH_LENGTH]);
            cx.backend.random_bytes(&mut exponent.0);
            let shared = auth::dh_mod_exp(Some(&exchange.value), &exponent);
            exchange.value = auth::dh_mod_exp(None, &exponent);
            exchange.phase = KeyExchangePhase::Sending;
            cx.session.session_key = Some(SessionKey::derive(&shared));
            Hresult::BINARY
        }
        KeyExchangePhase::Sending => {
            cx.binary[..DH_LENGTH].copy_from_slice(&exchange.value.0);
            cx.binary_len = DH_LENGTH;
            exchange.phase = KeyExchangePhase::Sent;
            Hresult::OK
        }
        KeyExchangePhase::Sent => Hresult::END_OF_DATA,
    }
}
