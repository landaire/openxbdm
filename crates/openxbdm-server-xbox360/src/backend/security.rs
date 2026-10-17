//! User directory: users are permanent kernel objects of a private object
//! type in an unnamed object directory, as the monitor keeps them.

use core::mem::offset_of;
use core::ptr::NonNull;
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
use openxbdm_server::reply::CommandError;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::resolve_export;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::Handle;
use xbox360_sys::xboxkrnl::ObCreateObject;
use xbox360_sys::xboxkrnl::ObInsertObject;
use xbox360_sys::xboxkrnl::ObMakeTemporaryObject;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ObjectAttributes;
use xbox360_sys::xboxkrnl::PoolTag;

use super::Console;
use super::dispatcher;
use crate::exports::export;
use crate::kernel;
use crate::net::XamNetwork;

/// Pool tag of user objects.
const USER_POOL_TAG: PoolTag = PoolTag::new(*b"SUmd");

/// Longest name an export reads: an ANSI string counts at most 0xfffe
/// bytes.
const EXPORT_NAME_LIMIT: usize = 0xfffe;

static USER_OBJECT_TYPE: ObjectType = ObjectType {
    allocate: AtomicU32::new(0),
    free: AtomicU32::new(0),
    close: AtomicU32::new(0),
    delete: AtomicU32::new(0),
    parse: AtomicU32::new(0),
    default_object: AtomicU32::new(0),
    pool_tag: USER_POOL_TAG,
};

/// Wait target of the object type; users are not waitable.
static DEFAULT_OBJECT: AtomicU32 = AtomicU32::new(0);

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
    fn directory(&mut self) -> Option<Handle> {
        if let Directory::Uncreated = self.directory {
            self.directory = create_directory().map_or(Directory::Unavailable, Directory::Created);
        }

        match self.directory {
            Directory::Created(handle) => Some(handle),
            Directory::Uncreated | Directory::Unavailable => None,
        }
    }

    /// Referenced user object reached by `name`.
    fn open(&mut self, name: &[u8]) -> Option<UserReference> {
        let directory = self.directory()?;

        let string = kernel::ansi_string(name);
        let attributes = ObjectAttributes {
            root_directory: directory,
            object_name: &string,
            attributes: ObjectAttributeFlags::empty(),
        };
        let mut handle = Handle::NULL;
        let object_type = core::ptr::from_ref(&USER_OBJECT_TYPE) as u32;
        // SAFETY: `attributes`, its name and `handle` are live locals; the
        // object type is a static descriptor.
        let open_status =
            unsafe { xboxkrnl::ObOpenObjectByName(&attributes, object_type, 0, &mut handle) };
        if !open_status.is_success() {
            return None;
        }

        let mut object = 0;
        // SAFETY: `handle` was opened above and is closed only here.
        let status = unsafe { xboxkrnl::ObReferenceObjectByHandle(handle, 0, &mut object) };
        // SAFETY: as above.
        unsafe { xboxkrnl::NtClose(handle) };
        if !status.is_success() {
            return None;
        }

        // SAFETY: the open by name accepts only objects of the user type,
        // whose body is a `UserObject`, and a successful reference returns
        // its nonzero address.
        Some(UserReference(unsafe {
            NonNull::new_unchecked(core::ptr::with_exposed_provenance_mut(object as usize))
        }))
    }
}

impl security::Backend for Console {
    fn find_user(&mut self, name: &[u8]) -> Option<User> {
        let reference = self.security.open(name)?;

        Some(reference.object().user())
    }

    fn store_user(&mut self, name: &[u8], user: User) -> bool {
        let Some(reference) = self.security.open(name) else {
            return false;
        };

        reference.object().set(user);

        true
    }

    fn create_user(&mut self, name: &[u8], user: User) -> Result<(), UserCreationFailed> {
        /// `ObInsertObject` keeps the creation reference until the caller
        /// drops it.
        const INSERT_POINTER_BIAS: u32 = 1;

        let directory = self.security.directory().ok_or(UserCreationFailed)?;

        let string = kernel::ansi_string(name);
        let attributes = ObjectAttributes {
            root_directory: directory,
            object_name: &string,
            attributes: ObjectAttributeFlags::PERMANENT,
        };
        let mut object = 0;
        // SAFETY: `attributes`, its name and `object` are live locals; the
        // object type is a static descriptor.
        let create_status = unsafe {
            ObCreateObject(
                core::ptr::from_ref(&USER_OBJECT_TYPE) as u32,
                &attributes,
                size_of::<UserObject>() as u32,
                &mut object,
            )
        };
        if !create_status.is_success() {
            return Err(UserCreationFailed);
        }

        let mut handle = Handle::NULL;
        // SAFETY: `object` was created above with these attributes.
        let insert_status =
            unsafe { ObInsertObject(object, &attributes, INSERT_POINTER_BIAS, &mut handle) };
        // A failed insertion already released the creation reference.
        // Stock dereferences again here (0x91f40764), a double release.
        if !insert_status.is_success() {
            return Err(UserCreationFailed);
        }

        // Drops the pointer bias; the handle and the permanent directory
        // entry keep the object until the body is written.
        // SAFETY: the creation reference is held after a successful insert.
        unsafe { xboxkrnl::ObDereferenceObject(object) };

        // SAFETY: the object was created with an uninitialized `UserObject`
        // body, written here without reading it; the open handle keeps the
        // object alive.
        unsafe { (object as usize as *mut UserObject).write(UserObject::new(user)) };

        // SAFETY: `handle` came from the insertion and is closed only here.
        unsafe { xboxkrnl::NtClose(handle) };

        Ok(())
    }

    fn remove_user(&mut self, name: &[u8]) -> bool {
        let Some(reference) = self.security.open(name) else {
            return false;
        };

        let object = reference.address();
        // SAFETY: a permanent object holds a reference of its own, which
        // this releases after making it temporary; dropping `reference`
        // then releases the one from the open.
        unsafe {
            ObMakeTemporaryObject(object);
            xboxkrnl::ObDereferenceObject(object);
        }
        drop(reference);

        true
    }

    fn user_name_at(&mut self, index: u32) -> Option<UserName> {
        let directory = self.security.directory()?;

        let mut query = DirectoryQuery {
            name_length: 0,
            _name_maximum_length: 0,
            _name_buffer: 0,
            _object_type: 0,
            name: [0; 0x40],
        };
        let mut context = index;
        // SAFETY: `query` holds the size passed and `context` is a live
        // local.
        let status = unsafe {
            xboxkrnl::NtQueryDirectoryObject(
                directory,
                (&raw mut query).cast(),
                size_of::<DirectoryQuery>() as u32,
                index == 0,
                &mut context,
                core::ptr::null_mut(),
            )
        };
        if !status.is_success() {
            return None;
        }

        UserName::new(query.name.get(..usize::from(query.name_length))?)
    }
}

#[derive(Debug, Clone, Copy)]
enum Directory {
    Uncreated,
    Created(Handle),
    Unavailable,
}

/// Console object type descriptor.
#[repr(C)]
struct ObjectType {
    allocate: AtomicU32,
    free: AtomicU32,
    close: AtomicU32,
    delete: AtomicU32,
    parse: AtomicU32,
    default_object: AtomicU32,
    pool_tag: PoolTag,
}

/// Body of a user object of [`USER_OBJECT_TYPE`].
#[repr(C)]
struct UserObject {
    password_high: AtomicU32,
    password_low: AtomicU32,
    privileges: AtomicU32,
    /// Nonzero when the password words hold a password.
    password_set: AtomicU32,
}

const _: () = {
    assert!(offset_of!(UserObject, password_low) == 0x4);
    assert!(offset_of!(UserObject, privileges) == 0x8);
    assert!(offset_of!(UserObject, password_set) == 0xc);
    assert!(size_of::<UserObject>() == 0x10);
};

impl UserObject {
    fn new(user: User) -> Self {
        let [high, low, privileges, password_set] = Self::words(user);

        Self {
            password_high: AtomicU32::new(high),
            password_low: AtomicU32::new(low),
            privileges: AtomicU32::new(privileges),
            password_set: AtomicU32::new(password_set),
        }
    }

    fn user(&self) -> User {
        let high = self.password_high.load(Ordering::Relaxed);
        let low = self.password_low.load(Ordering::Relaxed);
        let privileges = self.privileges.load(Ordering::Relaxed);
        let password_set = self.password_set.load(Ordering::Relaxed);

        let password =
            (password_set != 0).then_some(Password((u64::from(high) << 32) | u64::from(low)));

        User {
            password,
            privileges: Access::from_bits_retain(privileges),
        }
    }

    fn set(&self, user: User) {
        let [high, low, privileges, password_set] = Self::words(user);

        self.password_high.store(high, Ordering::Relaxed);
        self.password_low.store(low, Ordering::Relaxed);
        self.privileges.store(privileges, Ordering::Relaxed);
        self.password_set.store(password_set, Ordering::Relaxed);
    }

    /// Body words of `user`, in field order.
    fn words(user: User) -> [u32; 4] {
        let (password, password_set) = match user.password {
            Some(Password(password)) => (password, 1),
            None => (0, 0),
        };

        [
            (password >> 32) as u32,
            password as u32,
            user.privileges.bits(),
            password_set,
        ]
    }
}

/// A counted reference to a user object, released when dropped.
struct UserReference(NonNull<UserObject>);

impl UserReference {
    fn object(&self) -> &UserObject {
        // SAFETY: the reference this value holds keeps the object alive.
        unsafe { self.0.as_ref() }
    }

    /// Object address as the object manager takes it.
    fn address(&self) -> u32 {
        self.0.as_ptr() as u32
    }
}

impl Drop for UserReference {
    fn drop(&mut self) {
        // SAFETY: `Data::open` took this reference, released only here.
        unsafe { xboxkrnl::ObDereferenceObject(self.address()) };
    }
}

/// `NtQueryDirectoryObject` result: counted name, object type, then the
/// name bytes the counted name points to.
#[repr(C)]
struct DirectoryQuery {
    name_length: u16,
    _name_maximum_length: u16,
    _name_buffer: u32,
    _object_type: u32,
    name: [u8; 0x40],
}

const _: () = {
    assert!(offset_of!(DirectoryQuery, name) == 0xc);
    assert!(size_of::<DirectoryQuery>() == 0x4c);
};

/// `DM_USER` record the user walk fills.
#[repr(C)]
struct UserRecord {
    name: [u8; 0x100],
    access: u32,
}

const _: () = {
    assert!(offset_of!(UserRecord, access) == 0x100);
    assert!(size_of::<UserRecord>() == 0x104);
};

impl UserRecord {
    /// # Safety
    ///
    /// `record` is writable for a `DM_USER` at any alignment.
    unsafe fn fill(record: *mut Self, name: &UserName, access: Access) {
        let bytes = name.as_bytes();

        // SAFETY: per the contract of this fn; the name is a byte array.
        let slots = unsafe { &mut *(&raw mut (*record).name) };
        *slots = [0; 0x100];
        slots[..bytes.len()].copy_from_slice(bytes);

        // SAFETY: per the contract of this fn.
        unsafe { (&raw mut (*record).access).write_unaligned(access.bits()) };
    }
}

/// A security export's arguments, passed to the server thread on the
/// caller's stack. Caller addresses stay unread until the server step
/// uses them, so an export whose server step does not run reads none. A
/// name is the caller's string address.
enum Request {
    SetAccess {
        name: u32,
        access: Access,
    },
    GetAccess {
        name: u32,
        access: *mut u32,
    },
    Walk {
        position: *mut u32,
        record: *mut UserRecord,
    },
    Add {
        name: u32,
        access: Access,
    },
    Enable(bool),
    IsEnabled(*mut u32),
    Remove(u32),
}

fn create_directory() -> Option<Handle> {
    /// Kernel export ordinals of the pool routines the object type uses.
    const EX_ALLOCATE_POOL_TYPE_WITH_TAG: Ordinal = Ordinal::new(11).unwrap();
    const EX_FREE_POOL: Ordinal = Ordinal::new(15).unwrap();

    let module = SystemModule::Kernel.handle().ok()?;
    let allocate = resolve_export(module, EX_ALLOCATE_POOL_TYPE_WITH_TAG)
        .ok()?
        .raw();
    let free = resolve_export(module, EX_FREE_POOL).ok()?.raw();

    USER_OBJECT_TYPE.allocate.store(allocate, Ordering::Relaxed);
    USER_OBJECT_TYPE.free.store(free, Ordering::Relaxed);
    USER_OBJECT_TYPE.default_object.store(
        core::ptr::from_ref(&DEFAULT_OBJECT) as u32,
        Ordering::Relaxed,
    );

    let mut handle = Handle::NULL;
    // SAFETY: `handle` is a live local; a null name creates an unnamed
    // directory.
    unsafe { xboxkrnl::NtCreateDirectoryObject(&mut handle, core::ptr::null()) }
        .is_success()
        .then_some(handle)
}

/// Run `request` on the server thread. Called on the server thread itself,
/// above passive level, or after the server stopped, the server state is
/// unreachable and the export fails with E_UNEXPECTED.
///
/// # Safety
/// The addresses in `request` follow the export contracts: a name is 0, a
/// NUL-terminated string, or [`EXPORT_NAME_LIMIT`] readable bytes, an output
/// pointer and the walk position are writable dwords, and the `DM_USER`
/// record is writable, all at any alignment. They stay valid until this
/// returns.
unsafe fn on_server(mut request: Request) -> Hresult {
    dispatcher::call_on_server_with(&mut request, serve).map_or(Hresult::UNEXPECTED, Hresult)
}

/// Posted only by [`on_server`], whose contract covers the pointers.
fn serve(
    server: &mut Server,
    console: &mut Console,
    _network: &mut XamNetwork,
    request: &mut Request,
) -> u32 {
    let result = match *request {
        Request::SetAccess { name, access } => {
            // SAFETY: per the contract of `on_server`. A null name is empty,
            // as RtlInitAnsiString makes it.
            let name =
                unsafe { kernel::bounded_c_string(name, EXPORT_NAME_LIMIT) }.unwrap_or_default();

            security::set_user_access(console, name, access)
        }
        Request::GetAccess { name, access } => {
            // SAFETY: per the contract of `on_server`; null as above.
            let name =
                unsafe { kernel::bounded_c_string(name, EXPORT_NAME_LIMIT) }.unwrap_or_default();

            security::user_access(console, name).map(|found| {
                // SAFETY: per the contract of `on_server`.
                unsafe { access.write_unaligned(found.bits()) }
            })
        }
        // The server walk reads the position only while the box is locked,
        // so the caller's dword is read under the same condition.
        Request::Walk { position, record } if security::security_enabled(&server.state) => {
            // SAFETY: per the contract of `on_server`.
            let start = unsafe { position.read_unaligned() };
            let mut current = start;
            let result = security::walk_users(&server.state, console, &mut current);

            if current != start {
                // SAFETY: per the contract of `on_server`.
                unsafe { position.write_unaligned(current) };
            }

            result.map(|(user, access)| {
                // SAFETY: per the contract of `on_server`.
                unsafe { UserRecord::fill(record, &user, access) }
            })
        }
        Request::Walk { .. } => Err(CommandError::EndOfData),
        Request::Add { name, access } => {
            let user = User {
                password: None,
                privileges: access,
            };
            // SAFETY: per the contract of `on_server`; null as above.
            let name =
                unsafe { kernel::bounded_c_string(name, EXPORT_NAME_LIMIT) }.unwrap_or_default();

            let result = security::add_user(&mut server.state, console, name, user);
            save_settings(server, console);

            result
        }
        Request::Enable(enable) => {
            security::enable_security(&mut server.state, console, enable);

            Ok(())
        }
        Request::IsEnabled(enabled) => {
            let value = u32::from(security::security_enabled(&server.state));
            // SAFETY: per the contract of `on_server`.
            unsafe { enabled.write_unaligned(value) };

            Ok(())
        }
        Request::Remove(name) => {
            // SAFETY: per the contract of `on_server`; null as above.
            let name =
                unsafe { kernel::bounded_c_string(name, EXPORT_NAME_LIMIT) }.unwrap_or_default();

            let result = security::remove_user(&mut server.state, console, name);
            save_settings(server, console);

            result
        }
    };

    crate::exports::export_result(result).0
}

/// Write the settings file before the export returns, as stock's writer
/// does when called outside the title process.
fn save_settings(server: &mut Server, console: &mut Console) {
    server.save_settings_if_dirty(console);
}

// SAFETY (each export below): the export contract of its ordinal is the
// contract of `on_server`.

extern "C" fn set_user_access(user: u32, access: u32) -> Hresult {
    // SAFETY: see above.
    unsafe {
        on_server(Request::SetAccess {
            name: user,
            access: Access::from_bits_retain(access),
        })
    }
}
export!(58, set_user_access);

extern "C" fn get_user_access(user: u32, access: u32) -> Hresult {
    // SAFETY: see above.
    unsafe {
        on_server(Request::GetAccess {
            name: user,
            access: access as usize as *mut u32,
        })
    }
}
export!(59, get_user_access);

/// `walk` holds the directory position; `record` receives a `DM_USER`.
extern "C" fn walk_users(walk: u32, record: u32) -> Hresult {
    if walk == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    // SAFETY: see above.
    unsafe {
        on_server(Request::Walk {
            position: walk as usize as *mut u32,
            record: record as usize as *mut UserRecord,
        })
    }
}
export!(60, walk_users);

extern "C" fn add_user(user: u32, access: u32) -> Hresult {
    // SAFETY: see above.
    unsafe {
        on_server(Request::Add {
            name: user,
            access: Access::from_bits_retain(access),
        })
    }
}
export!(61, add_user);

extern "C" fn enable_security(enable: u32) -> Hresult {
    // SAFETY: the request holds no pointer.
    unsafe { on_server(Request::Enable(enable != 0)) }
}
export!(62, enable_security);

extern "C" fn is_security_enabled(enabled: u32) -> Hresult {
    if enabled == 0 {
        return Hresult::INVALID_ARGUMENT;
    }

    // SAFETY: see above.
    unsafe { on_server(Request::IsEnabled(enabled as usize as *mut u32)) }
}
export!(63, is_security_enabled);

extern "C" fn remove_user(user: u32) -> Hresult {
    // SAFETY: see above.
    unsafe { on_server(Request::Remove(user)) }
}
export!(64, remove_user);
