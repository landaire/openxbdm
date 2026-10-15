//! User directory: users are permanent kernel objects of a private object
//! type in an unnamed object directory, as the monitor keeps them.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_server::Access;
use openxbdm_server::Server;
use openxbdm_server::commands::security;
use openxbdm_server::commands::security::Password;
use openxbdm_server::commands::security::User;
use openxbdm_server::commands::security::UserCreationFailed;
use openxbdm_server::commands::security::UserName;

use super::Console;
use super::dispatcher;
use super::dispatcher::ServerService;
use crate::exports::export;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::ObCreateObject;
use crate::kernel::ObInsertObject;
use crate::kernel::ObMakeTemporaryObject;
use crate::kernel::ObjectAttributes;

/// Kernel export ordinals of the pool routines the object type uses.
const EX_ALLOCATE_POOL_TYPE_WITH_TAG: u32 = 11;
const EX_FREE_POOL: u32 = 15;
/// Object attribute: the object stays after its last handle closes.
const OBJ_PERMANENT: u32 = 0x10;
/// Body: password high, password low, privileges, password-set flag.
const USER_BODY_SIZE: u32 = 0x10;
/// Directory query buffer: counted name, type, then the name bytes.
const QUERY_LENGTH: usize = 0x4c;
const QUERY_NAME_OFFSET: usize = 0xc;

/// Console object type descriptor.
#[repr(C)]
struct ObjectType {
    allocate: AtomicU32,
    free: AtomicU32,
    close: AtomicU32,
    delete: AtomicU32,
    parse: AtomicU32,
    default_object: AtomicU32,
    pool_tag: AtomicU32,
}

static USER_OBJECT_TYPE: ObjectType = ObjectType {
    allocate: AtomicU32::new(0),
    free: AtomicU32::new(0),
    close: AtomicU32::new(0),
    delete: AtomicU32::new(0),
    parse: AtomicU32::new(0),
    default_object: AtomicU32::new(0),
    pool_tag: AtomicU32::new(u32::from_be_bytes(*b"SUmd")),
};

/// Wait target of the object type; users are not waitable.
static DEFAULT_OBJECT: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Copy)]
enum Directory {
    Uncreated,
    Created(u32),
    Unavailable,
}

/// Platform state of this domain.
pub struct Data {
    directory: Directory,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            directory: Directory::Uncreated,
        }
    }

    /// Handle of the user directory, created on first use.
    fn directory(&mut self) -> Option<u32> {
        if let Directory::Uncreated = self.directory {
            self.directory = create_directory().map_or(Directory::Unavailable, Directory::Created);
        }
        match self.directory {
            Directory::Created(handle) => Some(handle),
            Directory::Uncreated | Directory::Unavailable => None,
        }
    }

    /// Referenced user object reached by `name`.
    fn open(&mut self, name: &[u8]) -> Option<u32> {
        let directory = self.directory()?;
        let string = AnsiString::new(name);
        let attributes = ObjectAttributes {
            root_directory: directory,
            object_name: &string,
            attributes: 0,
        };
        let mut handle = 0;
        let object_type = core::ptr::from_ref(&USER_OBJECT_TYPE) as u32;
        if failed(kernel::ObOpenObjectByName(
            &attributes,
            object_type,
            0,
            &mut handle,
        )) {
            return None;
        }
        let mut object = 0;
        let status = kernel::ObReferenceObjectByHandle(handle, 0, &mut object);
        kernel::NtClose(handle);
        (!failed(status)).then_some(object)
    }
}

fn failed(status: u32) -> bool {
    (status as i32) < 0
}

fn create_directory() -> Option<u32> {
    let module = kernel::module_handle(c"xboxkrnl.exe").ok()?;
    let allocate = kernel::resolve_export(module, EX_ALLOCATE_POOL_TYPE_WITH_TAG).ok()?;
    let free = kernel::resolve_export(module, EX_FREE_POOL).ok()?;
    USER_OBJECT_TYPE.allocate.store(allocate, Ordering::Relaxed);
    USER_OBJECT_TYPE.free.store(free, Ordering::Relaxed);
    USER_OBJECT_TYPE.default_object.store(
        core::ptr::from_ref(&DEFAULT_OBJECT) as u32,
        Ordering::Relaxed,
    );
    let mut handle = 0;
    (!failed(kernel::NtCreateDirectoryObject(
        &mut handle,
        core::ptr::null(),
    )))
    .then_some(handle)
}

fn body(object: u32) -> *mut [u32; 4] {
    object as usize as *mut [u32; 4]
}

fn read_user(object: u32) -> User {
    // SAFETY: `object` is a referenced user object with a 0x10-byte body.
    let [high, low, privileges, password_set] = unsafe { core::ptr::read_volatile(body(object)) };
    let password =
        (password_set != 0).then_some(Password((u64::from(high) << 32) | u64::from(low)));
    User {
        password,
        privileges: Access::from_bits(privileges),
    }
}

fn write_user(object: u32, user: User) {
    let (password, password_set) = match user.password {
        Some(Password(password)) => (password, 1),
        None => (0, 0),
    };
    // SAFETY: `object` is a referenced user object with a 0x10-byte body.
    unsafe {
        core::ptr::write_volatile(
            body(object),
            [
                (password >> 32) as u32,
                password as u32,
                user.privileges.bits(),
                password_set,
            ],
        );
    }
}

impl security::Backend for Console {
    fn find_user(&mut self, name: &[u8]) -> Option<User> {
        let object = self.security.open(name)?;
        let user = read_user(object);
        kernel::ObDereferenceObject(object);
        Some(user)
    }

    fn store_user(&mut self, name: &[u8], user: User) -> bool {
        let Some(object) = self.security.open(name) else {
            return false;
        };
        write_user(object, user);
        kernel::ObDereferenceObject(object);
        true
    }

    fn create_user(&mut self, name: &[u8], user: User) -> Result<(), UserCreationFailed> {
        let directory = self.security.directory().ok_or(UserCreationFailed)?;
        let string = AnsiString::new(name);
        let attributes = ObjectAttributes {
            root_directory: directory,
            object_name: &string,
            attributes: OBJ_PERMANENT,
        };
        let mut object = 0;
        if failed(ObCreateObject(
            core::ptr::from_ref(&USER_OBJECT_TYPE) as u32,
            &attributes,
            USER_BODY_SIZE,
            &mut object,
        )) {
            return Err(UserCreationFailed);
        }
        let mut handle = 0;
        let status = ObInsertObject(object, &attributes, 1, &mut handle);
        // A failed insertion already released the creation reference.
        // Stock dereferences again here (0x91f40764), a double release.
        if failed(status) {
            return Err(UserCreationFailed);
        }
        // Drops the pointer bias; the handle and the permanent directory
        // entry keep the object until the body is written.
        kernel::ObDereferenceObject(object);
        write_user(object, user);
        kernel::NtClose(handle);
        Ok(())
    }

    fn remove_user(&mut self, name: &[u8]) -> bool {
        let Some(object) = self.security.open(name) else {
            return false;
        };
        ObMakeTemporaryObject(object);
        // The reference from the open and the one the permanent object held.
        kernel::ObDereferenceObject(object);
        kernel::ObDereferenceObject(object);
        true
    }

    fn user_name_at(&mut self, index: u32) -> Option<UserName> {
        /// The kernel writes a counted name with a pointer at the start.
        #[repr(C, align(4))]
        struct Buffer([u8; QUERY_LENGTH]);
        let directory = self.security.directory()?;
        let mut buffer = Buffer([0; QUERY_LENGTH]);
        let mut context = index;
        let status = kernel::NtQueryDirectoryObject(
            directory,
            buffer.0.as_mut_ptr(),
            QUERY_LENGTH as u32,
            u32::from(index == 0),
            &mut context,
            core::ptr::null_mut(),
        );
        if failed(status) {
            return None;
        }
        let bytes = &buffer.0;
        let length = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        UserName::new(bytes.get(QUERY_NAME_OFFSET..QUERY_NAME_OFFSET + length)?)
    }
}

/// Longest name an export reads: an ANSI string counts at most 0xfffe
/// bytes.
const EXPORT_NAME_LIMIT: u32 = 0xfffe;
/// Size of the `DM_USER` record the user walk fills: the name, then the
/// access mask at +0x100.
const USER_RECORD_SIZE: u32 = 0x104;
const USER_RECORD_ACCESS: u32 = 0x100;

/// Arguments of a security export, passed to the server thread on the
/// caller's stack.
#[repr(C)]
struct Request {
    first: u32,
    second: u32,
}

/// Run `service` on the server thread with the caller's two arguments.
/// Called on the server thread itself, above passive level, or after the
/// server stopped, the server state is unreachable and the export fails
/// with E_UNEXPECTED.
fn on_server(service: ServerService, first: u32, second: u32) -> u32 {
    let request = Request { first, second };
    dispatcher::call_on_server(service, core::ptr::from_ref(&request) as u32)
        .unwrap_or(Hresult::UNEXPECTED.0)
}

fn request<'a>(argument: u32) -> &'a Request {
    // SAFETY: `on_server` passes a `Request` that lives until the call returns.
    unsafe { &*(argument as usize as *const Request) }
}

/// Bytes of the caller's NUL-terminated name; a null name is empty, as
/// RtlInitAnsiString makes it.
fn name<'a>(address: u32) -> &'a [u8] {
    if address == 0 {
        return &[];
    }
    let mut length = 0;
    // SAFETY: the caller passes a NUL-terminated string.
    while length < EXPORT_NAME_LIMIT
        && unsafe { core::ptr::read_volatile((address + length) as usize as *const u8) } != 0
    {
        length += 1;
    }
    // SAFETY: the `length` bytes before the terminator were just read.
    unsafe { core::slice::from_raw_parts(address as usize as *const u8, length as usize) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: the caller passes a writable output location.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) };
}

/// Write the settings file before the export returns, as stock's writer
/// does when called outside the title process.
fn save_settings(server: &mut Server, console: &mut Console) {
    server.save_settings_if_dirty(console);
}

extern "C" fn set_user_access(user: u32, access: u32) -> u32 {
    on_server(
        |_, console, _, argument| {
            let request = request(argument);
            security::set_user_access(
                console,
                name(request.first),
                Access::from_bits(request.second),
            )
            .0
        },
        user,
        access,
    )
}
export!(58, set_user_access);

extern "C" fn get_user_access(user: u32, access: u32) -> u32 {
    on_server(
        |_, console, _, argument| {
            let request = request(argument);
            match security::user_access(console, name(request.first)) {
                Ok(found) => {
                    write_u32(request.second, found.bits());
                    Hresult::OK.0
                }
                Err(result) => result.0,
            }
        },
        user,
        access,
    )
}
export!(59, get_user_access);

/// `walk` holds the directory position; `record` receives a `DM_USER`.
extern "C" fn walk_users(walk: u32, record: u32) -> u32 {
    if walk == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    on_server(
        |server, console, _, argument| {
            let request = request(argument);
            // SAFETY: the caller passes a writable walk position.
            let position = unsafe { &mut *(request.first as usize as *mut u32) };
            match security::walk_users(&server.state, console, position) {
                Ok((user, access)) => {
                    let record = request.second;
                    // SAFETY: the caller passes a `DM_USER` record.
                    unsafe {
                        core::ptr::write_bytes(
                            record as usize as *mut u8,
                            0,
                            USER_RECORD_SIZE as usize,
                        );
                        core::ptr::copy_nonoverlapping(
                            user.as_bytes().as_ptr(),
                            record as usize as *mut u8,
                            user.as_bytes().len(),
                        );
                    }
                    write_u32(record + USER_RECORD_ACCESS, access.bits());
                    Hresult::OK.0
                }
                Err(result) => result.0,
            }
        },
        walk,
        record,
    )
}
export!(60, walk_users);

extern "C" fn add_user(user: u32, access: u32) -> u32 {
    on_server(
        |server, console, _, argument| {
            let request = request(argument);
            let user = User {
                password: None,
                privileges: Access::from_bits(request.second),
            };
            let result = security::add_user(&mut server.state, console, name(request.first), user);
            save_settings(server, console);
            result.0
        },
        user,
        access,
    )
}
export!(61, add_user);

extern "C" fn enable_security(enable: u32) -> u32 {
    on_server(
        |server, console, _, argument| {
            security::enable_security(&mut server.state, console, request(argument).first != 0);
            Hresult::OK.0
        },
        enable,
        0,
    )
}
export!(62, enable_security);

extern "C" fn is_security_enabled(enabled: u32) -> u32 {
    if enabled == 0 {
        return Hresult::INVALID_ARGUMENT.0;
    }
    on_server(
        |server, _, _, argument| {
            write_u32(
                request(argument).first,
                u32::from(security::security_enabled(&server.state)),
            );
            Hresult::OK.0
        },
        enabled,
        0,
    )
}
export!(63, is_security_enabled);

extern "C" fn remove_user(user: u32) -> u32 {
    on_server(
        |server, console, _, argument| {
            let result =
                security::remove_user(&mut server.state, console, name(request(argument).first));
            save_settings(server, console);
            result.0
        },
        user,
        0,
    )
}
export!(64, remove_user);
