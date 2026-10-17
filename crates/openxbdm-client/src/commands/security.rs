//! Lock mode, users, privileges, and authentication.
//!
//! A locked console greets each connection with its box id and a challenge
//! ([`LockChallenge`]) and grants no privileges until `authuser` succeeds.
//! Passwords travel only after a key exchange
//! ([`crate::Client::key_exchange`]), XORed with the [`SessionKey`].

use crate::commands::error::report_argument;
use crate::commands::error::report_parse;
use crate::commands::kv::parse_kv_line;
use crate::commands::kv::value_qword;
use crate::error::Error;
use crate::error::ParseError;
use crate::protocol::ArgBuilder;
use crate::protocol::Command;
use crate::protocol::ExpectedBody;
use crate::protocol::Qword;
use crate::protocol::Response;

pub use openxbdm_core::auth::AuthResponse;
pub use openxbdm_core::auth::BoxIdentifier;
pub use openxbdm_core::auth::DH_LENGTH;
pub use openxbdm_core::auth::DhValue;
pub use openxbdm_core::auth::Nonce;
pub use openxbdm_core::auth::Password;
pub use openxbdm_core::auth::SessionKey;
pub use openxbdm_core::auth::dh_mod_exp;
pub use openxbdm_core::auth::response;

/// Privilege bits of a user or connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Privileges(pub u32);

impl Privileges {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(0x01);
    pub const WRITE: Self = Self(0x02);
    pub const CONTROL: Self = Self(0x04);
    pub const CONFIG: Self = Self(0x08);
    pub const MANAGE: Self = Self(0x10);

    /// Words in the order the console prints them.
    const WORDS: [(Self, &'static str); 5] = [
        (Self::READ, "read"),
        (Self::WRITE, "write"),
        (Self::CONTROL, "control"),
        (Self::CONFIG, "config"),
        (Self::MANAGE, "manage"),
    ];

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn append_flags(self, mut builder: ArgBuilder) -> ArgBuilder {
        for (bit, word) in Self::WORDS {
            if self.contains(bit) {
                builder = builder.flag(word);
            }
        }

        builder
    }

    /// Parse space-separated privilege words.
    fn parse_words(text: &str) -> Result<Self, ParseError> {
        text.split(' ')
            .filter(|word| !word.is_empty())
            .try_fold(Self::NONE, |privileges, word| {
                Self::WORDS
                    .iter()
                    .find(|(_, known)| *known == word)
                    .map(|&(bit, _)| privileges.union(bit))
                    .ok_or(ParseError::UnrecognizedShape)
            })
    }
}

/// Box id and challenge from the banner of a locked console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockChallenge {
    pub box_id: BoxIdentifier,
    pub nonce: Nonce,
}

impl LockChallenge {
    /// Parse the banner text after `201- `. `None` for an unlocked
    /// console, whose banner carries neither `boxid` nor `nonce`.
    pub fn from_banner(text: &str) -> Result<Option<Self>, ParseError> {
        let kv = parse_kv_line(text);
        if kv.get("boxid").is_none() && kv.get("nonce").is_none() {
            return Ok(None);
        }

        let box_id = value_qword(kv.require("boxid")?, "boxid")?;
        let nonce = value_qword(kv.require("nonce")?, "nonce")?;

        Ok(Some(Self {
            box_id: BoxIdentifier(box_id),
            nonce: Nonce(nonce),
        }))
    }
}

/// `boxid`: the box id of a locked console. An unlocked console replies
/// `420- box is not locked`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BoxId;

impl Command for BoxId {
    type Output = BoxIdentifier;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("boxid").finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;

        let kv = parse_kv_line(&head);
        let value = kv.require("boxid").map_err(report_parse)?;

        value_qword(value, "boxid")
            .map(BoxIdentifier)
            .map_err(report_parse)
    }
}

/// `lockmode`: lock or unlock the console. Unlocking deletes every user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    /// Lock with this box id. On a locked console the box id is kept and
    /// file encryption is turned off unless `encrypt` is set.
    Lock {
        box_id: BoxIdentifier,
        encrypt: bool,
    },
    Unlock,
}

impl Command for LockMode {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let builder = ArgBuilder::new("lockmode");
        let builder = match *self {
            Self::Lock { box_id, encrypt } => {
                let builder = builder.qword("boxid", Qword(box_id.0));
                if encrypt {
                    builder.flag("encrypt")
                } else {
                    builder
                }
            }
            Self::Unlock => builder.flag("unlock"),
        };

        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        expect_ok(response)
    }
}

/// What `authuser` proves for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credential {
    /// [`response`] of the password and the banner challenge.
    Response(AuthResponse),
    /// First password of a user that has none; needs a key exchange.
    NewPassword { password: Password, key: SessionKey },
}

/// `authuser`: replace the connection's privileges with the account's.
/// A failed attempt leaves the connection with none. A user without a
/// password answers a response with `421- key exchange required`. The
/// administrator password is set only through [`AdminPassword`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthUser {
    Admin {
        response: AuthResponse,
    },
    User {
        name: String,
        credential: Credential,
    },
}

impl Command for AuthUser {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let builder = ArgBuilder::new("authuser");
        let builder = match self {
            Self::Admin { response } => builder.qword("resp", Qword(response.0)).flag("admin"),
            Self::User { name, credential } => {
                let builder = match *credential {
                    Credential::Response(response) => builder.qword("resp", Qword(response.0)),
                    Credential::NewPassword { password, key } => {
                        builder.qword("passwd", Qword(key.encrypt(password)))
                    }
                };

                builder.quoted("name", name).map_err(report_argument)?
            }
        };

        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        expect_ok(response)
    }
}

/// `adminpw`: set or clear the administrator password. Setting needs a
/// key exchange on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminPassword {
    Clear,
    Set { password: Password, key: SessionKey },
}

impl Command for AdminPassword {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let builder = ArgBuilder::new("adminpw");
        let builder = match *self {
            Self::Clear => builder.flag("none"),
            Self::Set { password, key } => builder.qword("passwd", Qword(key.encrypt(password))),
        };

        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        expect_ok(response)
    }
}

/// `user name=... <privileges>`: add a user to a locked console. The user
/// sets a password with its first [`AuthUser`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddUser {
    pub name: String,
    pub privileges: Privileges,
}

impl Command for AddUser {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let builder = ArgBuilder::new("user")
            .quoted("name", &self.name)
            .map_err(report_argument)?;

        Ok(self.privileges.append_flags(builder).finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        expect_ok(response)
    }
}

/// `user name=... remove`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveUser {
    pub name: String,
}

impl Command for RemoveUser {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("user")
            .quoted("name", &self.name)
            .map_err(report_argument)?
            .flag("remove")
            .finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        expect_ok(response)
    }
}

/// One `userlist` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEntry {
    pub name: String,
    pub privileges: Privileges,
}

impl UserEntry {
    /// Parse `name="<name>"[ <word>]...`. The name is printed without
    /// escaping, so the privilege words are taken from the end.
    fn parse(line: &str) -> Result<Self, ParseError> {
        let mut rest = line
            .strip_prefix("name=\"")
            .ok_or(ParseError::UnrecognizedShape)?;

        let mut privileges = Privileges::NONE;
        for (bit, word) in Privileges::WORDS.iter().rev() {
            if let Some(stripped) = rest
                .strip_suffix(word)
                .and_then(|text| text.strip_suffix(' '))
            {
                rest = stripped;
                privileges = privileges.union(*bit);
            }
        }

        let name = rest
            .strip_suffix('"')
            .ok_or(ParseError::UnrecognizedShape)?;

        Ok(Self {
            name: name.to_owned(),
            privileges,
        })
    }
}

/// `userlist`: users of a locked console in the console's directory order.
#[derive(Debug, Clone, Copy, Default)]
pub struct UserList;

impl Command for UserList {
    type Output = Vec<UserEntry>;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        Ok(ArgBuilder::new("userlist").finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Multiline
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let lines = response
            .expect_multiline()
            .map_err(rootcause::Report::new)?;

        lines
            .iter()
            .map(|line| UserEntry::parse(line).map_err(report_parse))
            .collect()
    }
}

/// `getuserpriv`: privileges of this connection, or of a user (needs
/// manage).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetUserPrivileges {
    Me,
    User(String),
}

impl Command for GetUserPrivileges {
    type Output = Privileges;

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let builder = ArgBuilder::new("getuserpriv");
        let builder = match self {
            Self::Me => builder.flag("me"),
            Self::User(name) => builder.quoted("name", name).map_err(report_argument)?,
        };

        Ok(builder.finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        let head = response.expect_ok().map_err(rootcause::Report::new)?;
        if head == "none" {
            return Ok(Privileges::NONE);
        }

        Privileges::parse_words(&head).map_err(report_parse)
    }
}

/// `setuserpriv`: replace a user's privileges. The console does not save
/// the change to its settings file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetUserPrivileges {
    pub name: String,
    pub privileges: Privileges,
}

impl Command for SetUserPrivileges {
    type Output = ();

    fn wire_line(&self) -> Result<String, rootcause::Report<Error>> {
        let builder = ArgBuilder::new("setuserpriv")
            .quoted("name", &self.name)
            .map_err(report_argument)?;

        Ok(self.privileges.append_flags(builder).finish())
    }

    fn expected(&self) -> ExpectedBody {
        ExpectedBody::Line
    }

    fn parse(&self, response: Response) -> Result<Self::Output, rootcause::Report<Error>> {
        expect_ok(response)
    }
}

fn expect_ok(response: Response) -> Result<(), rootcause::Report<Error>> {
    response.expect_ok().map_err(rootcause::Report::new)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_lines() {
        let key = SessionKey(0x0102_0304_0506_0708);
        let lines = [
            LockMode::Lock {
                box_id: BoxIdentifier(0x0011_2233_4455_6677),
                encrypt: true,
            }
            .wire_line()
            .unwrap(),
            LockMode::Unlock.wire_line().unwrap(),
            AuthUser::Admin {
                response: AuthResponse(0xfeed),
            }
            .wire_line()
            .unwrap(),
            AuthUser::User {
                name: "dev kit".into(),
                credential: Credential::NewPassword {
                    password: Password(0x0102_0304_0506_0709),
                    key,
                },
            }
            .wire_line()
            .unwrap(),
            AdminPassword::Clear.wire_line().unwrap(),
            AdminPassword::Set {
                password: Password(0x10),
                key,
            }
            .wire_line()
            .unwrap(),
            AddUser {
                name: "bob".into(),
                privileges: Privileges::READ.union(Privileges::MANAGE),
            }
            .wire_line()
            .unwrap(),
            RemoveUser { name: "bob".into() }.wire_line().unwrap(),
            GetUserPrivileges::Me.wire_line().unwrap(),
            SetUserPrivileges {
                name: "bob".into(),
                privileges: Privileges::NONE,
            }
            .wire_line()
            .unwrap(),
        ];
        insta::assert_snapshot!(lines.join("\n"));
    }

    #[test]
    fn user_entries() {
        let entries: Vec<_> = [
            "name=\"bob\" read write control config manage",
            "name=\"a\" read\"\"",
            "name=\"\"",
        ]
        .iter()
        .map(|line| UserEntry::parse(line).unwrap())
        .collect();
        insta::assert_debug_snapshot!(entries);
    }

    #[test]
    fn banner_challenge() {
        assert!(matches!(LockChallenge::from_banner("connected"), Ok(None)));
        assert_eq!(
            LockChallenge::from_banner("boxid=0q0011223344556677 nonce=0q8899aabbccddeeff")
                .unwrap(),
            Some(LockChallenge {
                box_id: BoxIdentifier(0x0011_2233_4455_6677),
                nonce: Nonce(0x8899_aabb_ccdd_eeff)
            })
        );
        assert!(LockChallenge::from_banner("boxid=0q0011223344556677 nonce=0qXYZ").is_err());
        assert!(LockChallenge::from_banner("boxid=0q0011223344556677").is_err());
    }
}
