//! Security commands: lock mode, users, privileges, and authentication.
//!
//! Users live in the platform's user directory (the monitor keeps them as
//! kernel objects in an unnamed object directory); this module applies the
//! monitor's rules on top of it.

mod error;
mod key_exchange;

use openxbdm_core::auth;
use openxbdm_core::auth::SessionKey;
use openxbdm_core::line::CommandLine;
use openxbdm_core::status::ErrorCode;

use self::key_exchange::key_exchange;
use self::key_exchange::resume_key_exchange;
use crate::access::Access;
use crate::backend::Backend as AnyBackend;
use crate::commands::system;
use crate::commands::system::SettingsFile;
use crate::continuation::ContinuationContext;
use crate::invocation::Invocation;
use crate::registry::CommandEntry;
use crate::registry::DispatchFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::LockMode;
use crate::state::ServerState;
use crate::text::Text;

pub use self::error::UserCreationFailed;
pub use self::key_exchange::KeyExchange;

/// Bytes of a stored user name, including the terminator.
pub const USER_NAME_CAPACITY: usize = 0x40;
/// Name buffers of `getuserpriv` and `setuserpriv`.
const LOOKUP_NAME_CAPACITY: usize = 0x80;

pub(crate) const COMMANDS: &[CommandEntry] = &[
    entry("adminpw", Access::MANAGE, admin_password),
    entry("authuser", Access::empty(), authenticate_user),
    entry("boxid", Access::empty(), box_id),
    entry("getuserpriv", Access::empty(), get_user_privileges),
    entry("keyxchg", Access::empty(), key_exchange),
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

/// Global state of this domain.
#[derive(Debug)]
pub struct State {
    /// Stored administrator password: the sent value XORed with the
    /// sender's session key.
    pub admin_password: Option<Password>,
}

impl State {
    pub const fn new() -> Self {
        Self {
            admin_password: None,
        }
    }
}

/// Transfers started by this domain.
#[derive(Debug)]
pub enum Continuation {
    /// `userlist`: index of the next directory entry.
    UserList(u32),
    KeyExchange(KeyExchange),
}

/// How `authuser` uses its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    /// The value is the response to the banner challenge.
    Response,
    /// The value is a new password (decrypted with the session key).
    SetPassword,
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

const fn entry(
    name: &'static str,
    any_of: Access,
    handler: crate::registry::Handler,
) -> CommandEntry {
    CommandEntry::new(
        name,
        any_of,
        Access::empty(),
        DispatchFlags::empty(),
        handler,
    )
}

pub(crate) fn resume(
    continuation: &mut Continuation,
    cx: &mut ContinuationContext<'_>,
) -> CommandResult {
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
            let _ = line.push_bytes(b" passwd=0q");
            let _ = line.push_hex32((password >> 32) as u32);
            let _ = line.push_hex32(password as u32);
        }

        let _ = line.push_bytes(privilege_words(user.privileges).as_bytes());
        system::write_bytes(backend, file, line.as_bytes());
        system::end_line(backend, file);
    }
}

fn parse_privileges(line: &CommandLine<'_>) -> Access {
    PRIVILEGE_WORDS
        .iter()
        .filter(|(_, word)| line.has(word))
        .fold(Access::empty(), |privileges, &(bit, _)| {
            privileges.union(bit)
        })
}

/// ` read`, ` write`, ... for each privilege held.
fn privilege_words(privileges: Access) -> Text<48> {
    let mut words = Text::new();

    for &(bit, word) in &PRIVILEGE_WORDS {
        if privileges.intersects(bit) {
            let _ = words.push_bytes(b" ");
            let _ = words.push_bytes(word.as_bytes());
        }
    }

    words
}

fn qword(words: [u32; 2]) -> u64 {
    (u64::from(words[0]) << 32) | u64::from(words[1])
}

/// `lockmode unlock` | `lockmode boxid=<qword> [encrypt]` | `lockmode encrypt`.
fn lock_mode(invocation: &mut Invocation<'_>) -> CommandResult {
    let lock = &mut invocation.state.lock;
    let result = if invocation.line.has("unlock") {
        lock.mode = LockMode::Unlocked;
        remove_all_users(invocation.backend);
        Ok(Reply::Ok)
    } else if lock.is_locked() {
        // Relocking keeps the box id and drops file encryption.
        lock.mode = LockMode::Locked;
        Ok(Reply::Ok)
    } else if let Some(box_id) = invocation.line.qword("boxid") {
        lock.box_id = [(box_id >> 32) as u32, box_id as u32];
        lock.mode = LockMode::Locked;
        Ok(Reply::Ok)
    } else {
        invocation.set_text(format_args!("missing parameters"));
        Err(CommandError::Fail)
    };

    let result = if !invocation.line.has("encrypt") {
        result
    } else if invocation.state.lock.is_locked() {
        invocation.state.lock.mode = LockMode::LockedEncrypted;
        Ok(Reply::Ok)
    } else {
        invocation.set_text(format_args!("box not locked; file encryption not enabled"));
        result
    };

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

fn box_id(invocation: &mut Invocation<'_>) -> CommandResult {
    let lock = invocation.state.lock;
    if !lock.is_locked() {
        return Err(ErrorCode::BoxNotLocked.into());
    }

    invocation.set_text(format_args!(
        "boxid=0q{:08x}{:08x}",
        lock.box_id[0], lock.box_id[1]
    ));

    Ok(Reply::Ok)
}

/// `adminpw none` | `adminpw passwd=<qword>`. A connection must have
/// exchanged keys; the stored value is the sent value XORed with the
/// session key (zero for settings lines).
fn admin_password(invocation: &mut Invocation<'_>) -> CommandResult {
    if invocation.line.has("none") {
        invocation.state.security.admin_password = None;
        invocation.state.settings_dirty = true;
        return Ok(Reply::Ok);
    }

    let key = match invocation.session.as_deref() {
        // Settings lines carry the stored value unencrypted.
        None => SessionKey(0),
        Some(session) => match session.session_key {
            Some(key) => key,
            None => return Err(ErrorCode::KeyExchangeRequired.into()),
        },
    };

    let Some(password) = invocation.line.qword("passwd") else {
        invocation.set_text(format_args!("missing passwd"));
        return Err(CommandError::Fail);
    };

    invocation.state.security.admin_password = Some(Password(password ^ key.0));
    invocation.state.settings_dirty = true;

    Ok(Reply::Ok)
}

/// `authuser (resp=<qword> | passwd=<qword>) (admin | name=<string>)`.
/// The resulting privileges replace the connection's, even when zero.
fn authenticate_user(invocation: &mut Invocation<'_>) -> CommandResult {
    /// Name buffer of `authuser`.
    const AUTH_NAME_CAPACITY: usize = 0x100;

    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };

    let line = invocation.line;
    let password = session
        .session_key
        .and_then(|key| line.qword("passwd").map(|password| password ^ key.0));
    let (mode, value) = match password {
        Some(password) => (AuthMode::SetPassword, password),
        None => match line.qword("resp") {
            Some(response) => (AuthMode::Response, response),
            None => {
                invocation.text.set_bytes(b"missing response");
                return Err(CommandError::Fail);
            }
        },
    };

    let challenge = auth::Nonce(qword(session.nonce));

    let (privileges, mode) = if line.has("admin") {
        if mode == AuthMode::SetPassword {
            invocation.text.set_bytes(b"missing response");
            return Err(CommandError::Fail);
        }

        let privileges = match invocation.state.security.admin_password {
            Some(Password(secret))
                if auth::response(auth::Password(secret), challenge).0 == value =>
            {
                Access::UNRESTRICTED
            }
            _ => Access::empty(),
        };

        (privileges, mode)
    } else {
        let Some(name) = line.param("name") else {
            invocation.text.set_bytes(b"missing name");
            return Err(CommandError::Fail);
        };

        let mut buffer = [0u8; AUTH_NAME_CAPACITY];
        let name = name.copy_into(&mut buffer);
        match invocation.backend.find_user(name) {
            None => (Access::empty(), mode),
            Some(user) => match (user.password, mode) {
                (Some(Password(secret)), AuthMode::Response) => {
                    let accepted = auth::response(auth::Password(secret), challenge).0 == value;
                    let privileges = if accepted {
                        user.privileges
                    } else {
                        Access::empty()
                    };

                    (privileges, AuthMode::Response)
                }
                (Some(_), AuthMode::SetPassword) => (Access::empty(), AuthMode::Response),
                (None, AuthMode::SetPassword) => {
                    let updated = User {
                        password: Some(Password(value)),
                        ..user
                    };
                    invocation.backend.store_user(name, updated);
                    invocation.state.settings_dirty = true;

                    (user.privileges, AuthMode::Response)
                }
                (None, AuthMode::Response) => (Access::empty(), AuthMode::SetPassword),
            },
        }
    };

    session.access = privileges;

    if privileges != Access::empty() {
        Ok(Reply::Ok)
    } else if mode == AuthMode::SetPassword {
        Err(ErrorCode::KeyExchangeRequired.into())
    } else {
        Err(ErrorCode::AccessDenied.into())
    }
}

/// `getuserpriv me` | `getuserpriv name=<string>` (needs manage).
fn get_user_privileges(invocation: &mut Invocation<'_>) -> CommandResult {
    let access = invocation.access();
    let privileges = if invocation.line.has("me") {
        if invocation.session.is_none() {
            return Err(CommandError::Fail);
        }

        access
    } else {
        if !access.intersects(Access::MANAGE) {
            return Err(ErrorCode::AccessDenied.into());
        }

        let Some(name) = invocation.line.param("name") else {
            invocation.text.set_bytes(b"missing name");
            return Err(CommandError::Fail);
        };

        let mut buffer = [0u8; LOOKUP_NAME_CAPACITY];
        let name = name.copy_into(&mut buffer);
        match invocation.backend.find_user(name) {
            Some(user) => user.privileges,
            None => return Err(ErrorCode::FileNotFound.into()),
        }
    };

    invocation.text.clear();
    if privileges == Access::empty() {
        invocation.text.set_bytes(b"none");
    } else {
        // The monitor writes each word with a leading space one byte before
        // the reply text, so the first space is dropped.
        let words = privilege_words(privileges);
        invocation
            .text
            .set_bytes(words.as_bytes().get(1..).unwrap_or_default());
    }

    Ok(Reply::Ok)
}

/// `setuserpriv name=<string> [read] [write] [control] [config] [manage]`:
/// replaces the user's privileges. The change is not written to settings.
fn set_user_privileges(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(name) = invocation.line.param("name") else {
        invocation.text.set_bytes(b"missing name");
        return Err(CommandError::Fail);
    };

    let mut buffer = [0u8; LOOKUP_NAME_CAPACITY];
    let name = name.copy_into(&mut buffer);

    let privileges = parse_privileges(&invocation.line);

    set_user_access(invocation.backend, name, privileges).map(|()| Reply::Ok)
}

/// Replace the privileges of an existing user (`setuserpriv`, export 58).
pub fn set_user_access(
    backend: &mut dyn AnyBackend,
    name: &[u8],
    access: Access,
) -> Result<(), CommandError> {
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
            Ok(())
        }
        _ => Err(ErrorCode::FileNotFound.into()),
    }
}

/// Privileges of a user (export 59).
pub fn user_access(backend: &mut dyn AnyBackend, name: &[u8]) -> Result<Access, CommandError> {
    backend
        .find_user(name)
        .map(|user| user.privileges)
        .ok_or(CommandError::Status(ErrorCode::FileNotFound))
}

/// `user name=<string> remove` | `user name=<string> [privileges]`.
/// Settings lines may also carry `passwd=<qword>`.
fn user(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(name) = invocation.line.param("name") else {
        invocation.text.set_bytes(b"missing name");
        return Err(CommandError::Fail);
    };

    let mut buffer = [0u8; USER_NAME_CAPACITY];
    let name = name.copy_into(&mut buffer);
    if invocation.line.has("remove") {
        return remove_user(invocation.state, invocation.backend, name).map(|()| Reply::Ok);
    }

    let password = match invocation.session {
        None => invocation.line.qword("passwd").map(Password),
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
    .map(|()| Reply::Ok)
}

/// Create a user while the box is locked (`user`, export 61).
pub fn add_user(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
    user: User,
) -> Result<(), CommandError> {
    if !state.lock.is_locked() {
        return Err(ErrorCode::BoxNotLocked.into());
    }

    if backend.find_user(name).is_some() {
        return Err(ErrorCode::FileAlreadyExists.into());
    }

    if backend.create_user(name, user).is_err() {
        return Err(CommandError::OutOfMemory);
    }

    state.settings_dirty = true;

    Ok(())
}

/// Delete a user (`user remove`, export 64).
pub fn remove_user(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    name: &[u8],
) -> Result<(), CommandError> {
    if !backend.remove_user(name) {
        return Err(ErrorCode::FileNotFound.into());
    }

    state.settings_dirty = true;

    Ok(())
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
/// walk restarts at position 0. [`CommandError::EndOfData`] ends the walk,
/// also while the box is unlocked.
pub fn walk_users(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    position: &mut u32,
) -> Result<(UserName, Access), CommandError> {
    if !state.lock.is_locked() {
        return Err(CommandError::EndOfData);
    }

    let name = backend
        .user_name_at(*position)
        .ok_or(CommandError::EndOfData)?;
    *position += 1;

    let user = backend
        .find_user(name.as_bytes())
        .ok_or(CommandError::Unexpected)?;

    Ok((name, user.privileges))
}

fn user_list(invocation: &mut Invocation<'_>) -> CommandResult {
    if !invocation.state.lock.is_locked() {
        return Err(ErrorCode::BoxNotLocked.into());
    }

    let Some(session) = invocation.session.as_deref_mut() else {
        return Err(CommandError::Fail);
    };

    session.continuation = crate::continuation::Continuation::Security(Continuation::UserList(0));

    Ok(Reply::Multiline)
}

/// One `name="<name>" <privileges>` line per user. The list also ends when
/// the box is unlocked meanwhile.
fn resume_user_list(index: &mut u32, cx: &mut ContinuationContext<'_>) -> CommandResult {
    if !cx.state.lock.is_locked() {
        return Err(CommandError::EndOfData);
    }

    let Some(name) = cx.backend.user_name_at(*index) else {
        return Err(CommandError::EndOfData);
    };

    *index += 1;
    let Some(user) = cx.backend.find_user(name.as_bytes()) else {
        return Err(CommandError::EndOfData);
    };

    let _ = cx.line.push_bytes(b"name=\"");
    let _ = cx.line.push_bytes(name.as_bytes());
    let _ = cx.line.push_bytes(b"\"");
    let _ = cx
        .line
        .push_bytes(privilege_words(user.privileges).as_bytes());

    Ok(Reply::Ok)
}
