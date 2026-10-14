//! Simulated user directory.
//!
//! The console keeps users as objects in an unnamed kernel object
//! directory. This reproduces the observable rules of that directory: 13
//! hash buckets with new entries at the head of their bucket, enumeration
//! by bucket then chain position, case-insensitive names, and path
//! resolution of names that contain backslashes.

use openxbdm_server::commands::security;
use openxbdm_server::commands::security::User;
use openxbdm_server::commands::security::UserCreationFailed;
use openxbdm_server::commands::security::UserName;

use super::MockBackend;

const BUCKETS: usize = 13;

/// Simulated state of this domain.
#[derive(Debug, Default)]
pub struct Mock {
    buckets: [Vec<(Vec<u8>, User)>; BUCKETS],
}

impl Mock {
    /// Users in enumeration order.
    pub fn users(&self) -> impl Iterator<Item = (&[u8], &User)> {
        self.buckets
            .iter()
            .flatten()
            .map(|(name, user)| (name.as_slice(), user))
    }

    fn position(&self, element: &[u8]) -> Option<(usize, usize)> {
        let bucket = hash_index(element);
        self.buckets[bucket]
            .iter()
            .position(|(name, _)| names_equal(name, element))
            .map(|index| (bucket, index))
    }

    /// The entry an open by `name` reaches.
    fn find(&self, name: &[u8]) -> Option<(usize, usize)> {
        self.position(element(name)?)
    }
}

/// Bucket of a name: bytes below 0x80 are folded to lower case and mixed;
/// other bytes are skipped.
fn hash_index(name: &[u8]) -> usize {
    let hash = name
        .iter()
        .filter(|&&byte| byte < 0x80)
        .fold(0u32, |hash, &byte| {
            u32::from(byte | 0x20)
                .wrapping_add(hash >> 1)
                .wrapping_add(hash.wrapping_mul(3))
        });
    (hash % BUCKETS as u32) as usize
}

/// The kernel's ANSI upper-case mapping: ASCII letters, Latin-1 letters
/// 0xe0..=0xfe except 0xf7, and 0xff to `?` (its upper case is outside
/// the character set).
fn upper(byte: u8) -> u8 {
    match byte {
        b'a'..=b'z' | 0xe0..=0xf6 | 0xf8..=0xfe => byte - 0x20,
        0xff => b'?',
        _ => byte,
    }
}

fn names_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&a, &b)| a == b || upper(a) == upper(b))
}

/// Element an open or insertion of `name` relative to the directory
/// resolves to. An empty name is the directory itself and a leading
/// backslash is rejected, so neither reaches a user; a name with an inner
/// backslash would continue through a user object and fails; one trailing
/// backslash is ignored.
fn element(name: &[u8]) -> Option<&[u8]> {
    if name.is_empty() || name[0] == b'\\' {
        return None;
    }
    match name.iter().position(|&byte| byte == b'\\') {
        None => Some(name),
        Some(split) if split + 1 == name.len() => Some(&name[..split]),
        Some(_) => None,
    }
}

impl security::Backend for MockBackend {
    fn find_user(&mut self, name: &[u8]) -> Option<User> {
        let (bucket, index) = self.security.find(name)?;
        Some(self.security.buckets[bucket][index].1)
    }

    fn store_user(&mut self, name: &[u8], user: User) -> bool {
        let Some((bucket, index)) = self.security.find(name) else {
            return false;
        };
        self.security.buckets[bucket][index].1 = user;
        true
    }

    fn create_user(&mut self, name: &[u8], user: User) -> Result<(), UserCreationFailed> {
        let element = element(name).ok_or(UserCreationFailed)?;
        if self.security.position(element).is_some() {
            return Err(UserCreationFailed);
        }
        self.security.buckets[hash_index(element)].insert(0, (element.to_vec(), user));
        Ok(())
    }

    fn remove_user(&mut self, name: &[u8]) -> bool {
        let Some((bucket, index)) = self.security.find(name) else {
            return false;
        };
        self.security.buckets[bucket].remove(index);
        true
    }

    fn user_name_at(&mut self, index: u32) -> Option<UserName> {
        let (name, _) = self.security.buckets.iter().flatten().nth(index as usize)?;
        UserName::new(name)
    }
}
