//! Lock mode, users, privileges, and authentication over TCP.
//!
//! The response function and the key exchange are recomputed here from
//! their descriptions in docs/re-notes/commands (group1 `authuser`, group5
//! `keyxchg`), independently of the server's implementation.

mod common;

use std::io::Read;
use std::io::Write;

use common::RawSession;
use common::TestServer;
use common::run;
use openxbdm_client::Error;
use openxbdm_client::ErrorCode;
use openxbdm_client::commands::AddUser;
use openxbdm_client::commands::AdminPassword;
use openxbdm_client::commands::AuthResponse;
use openxbdm_client::commands::AuthUser;
use openxbdm_client::commands::BoxId;
use openxbdm_client::commands::BoxIdentifier;
use openxbdm_client::commands::Credential;
use openxbdm_client::commands::GetUserPrivileges;
use openxbdm_client::commands::LockChallenge;
use openxbdm_client::commands::LockMode;
use openxbdm_client::commands::Password;
use openxbdm_client::commands::Privileges;
use openxbdm_client::commands::SetUserPrivileges;
use openxbdm_client::commands::UserEntry;
use openxbdm_client::commands::UserList;
use openxbdm_client::commands::security::DhValue;
use openxbdm_core::status::Hresult;
use openxbdm_server::Access;
use openxbdm_server::commands::security;
use openxbdm_server::commands::security::User;
use openxbdm_server::state::ServerState;
use openxbdm_server_host::Host;
use openxbdm_server_host::backend::MockBackend;

const BOX_ID: &str = "0q0011223344556677";

const ROUNDS: [u32; 8] = [
    0x283c481d, 0x9ad82aa1, 0x85a5e1f9, 0x1b23963c, 0xf70b4975, 0xdfdc02c7, 0xf29176fc, 0x6b04bd38,
];

fn block(key: [u32; 2], value: [u32; 2]) -> [u32; 2] {
    let [mut b0, mut b1] = value;
    for i in 0..8 {
        b1 ^= (key[1] ^ b0)
            .wrapping_add((!b0) << 6)
            .wrapping_add(b0 >> 5)
            .wrapping_add(ROUNDS[i]);
        b0 ^= (key[0] ^ b1)
            .wrapping_add(b1 << 6)
            .wrapping_add((!b1) >> 5)
            .wrapping_add(ROUNDS[7 - i]);
    }
    [b0, b1]
}

fn split(value: u64) -> [u32; 2] {
    [(value >> 32) as u32, value as u32]
}

fn join(words: [u32; 2]) -> u64 {
    (u64::from(words[0]) << 32) | u64::from(words[1])
}

/// F(X, D) = D xor E(X, D).
fn mix(x: [u32; 2], d: [u32; 2]) -> [u32; 2] {
    let e = block(x, d);
    [d[0] ^ e[0], d[1] ^ e[1]]
}

/// H(S, C).
fn respond(secret: u64, challenge: u64) -> u64 {
    let x = mix(split(0x2718281831415926), split(secret));
    let y = mix(x, split(challenge));
    join(mix(x, y))
}

/// Session key absorption of the shared value.
fn absorb(bytes: &[u8]) -> u64 {
    let mut state = [0u32; 2];
    for chunk in bytes.chunks(8) {
        let mut padded = [0u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);
        let m = split(u64::from_le_bytes(padded));
        let e = block(state, m);
        state = [e[0] ^ m[0], e[1] ^ m[1]];
    }
    join(state)
}

/// Group parameters at 0x91f06090: the 0x60-byte modulus and generator.
const MODULUS: [u8; 96] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x34, 0xc2, 0x68, 0x21, 0xa2, 0xda, 0x0f, 0xc9,
    0xd1, 0x1c, 0xdc, 0x80, 0x8b, 0x62, 0xc6, 0xc4, 0x74, 0xcc, 0x67, 0x8a, 0x08, 0x4e, 0x02, 0x29,
    0x22, 0x9b, 0x13, 0x3b, 0xa6, 0xbe, 0x0b, 0x02, 0xdd, 0x04, 0x34, 0x8e, 0x79, 0x08, 0x4a, 0x51,
    0x1b, 0x43, 0x3a, 0xcd, 0xb3, 0x19, 0x95, 0xef, 0x37, 0x14, 0x5f, 0xf2, 0x6d, 0x0a, 0x2b, 0x30,
    0x45, 0xc2, 0x51, 0x6d, 0x6d, 0x35, 0xe1, 0x4f, 0xc6, 0x7e, 0x5e, 0x62, 0x76, 0xb5, 0x85, 0xe4,
    0x20, 0x36, 0x3a, 0xa6, 0xe9, 0x42, 0x4c, 0xf4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// 768-bit number, least significant qword first; the wire bytes are its
/// little-endian encoding.
type Big = [u64; 12];

fn big(bytes: &[u8; 96]) -> Big {
    std::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()))
}

fn wire(value: &Big) -> [u8; 96] {
    let mut bytes = [0u8; 96];
    for (i, limb) in value.iter().enumerate() {
        bytes[i * 8..i * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn at_least(a: &Big, b: &Big) -> bool {
    a.iter().rev().cmp(b.iter().rev()) != std::cmp::Ordering::Less
}

fn sub(a: &mut Big, b: &Big) {
    let mut borrow = false;
    for (x, y) in a.iter_mut().zip(b) {
        let (d, b1) = x.overflowing_sub(*y);
        let (d, b2) = d.overflowing_sub(u64::from(borrow));
        *x = d;
        borrow = b1 || b2;
    }
}

/// (a + b) mod m for a, b < m.
fn add_mod(a: &Big, b: &Big, m: &Big) -> Big {
    let mut sum = [0u64; 12];
    let mut carry = false;
    for i in 0..12 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(u64::from(carry));
        sum[i] = s;
        carry = c1 || c2;
    }
    if carry || at_least(&sum, m) {
        sub(&mut sum, m);
    }
    sum
}

fn bit(value: &Big, index: usize) -> bool {
    value[index / 64] >> (index % 64) & 1 != 0
}

fn mul_mod(a: &Big, b: &Big, m: &Big) -> Big {
    let mut result = [0u64; 12];
    for index in (0..768).rev() {
        result = add_mod(&result, &result, m);
        if bit(b, index) {
            result = add_mod(&result, a, m);
        }
    }
    result
}

fn pow_mod(base: &Big, exponent: &Big, m: &Big) -> Big {
    let mut base = *base;
    if at_least(&base, m) {
        sub(&mut base, m);
    }
    let mut result = [0u64; 12];
    result[0] = 1;
    let top = (0..768)
        .rev()
        .find(|&index| bit(exponent, index))
        .map_or(0, |index| index + 1);
    for index in (0..top).rev() {
        result = mul_mod(&result, &result, m);
        if bit(exponent, index) {
            result = mul_mod(&result, &base, m);
        }
    }
    result
}

fn generator() -> Big {
    let mut bytes = [0u8; 96];
    bytes[0x58] = 2;
    big(&bytes)
}

/// A short private exponent keeps the test-side arithmetic fast.
fn exponent() -> Big {
    let mut value = [0u64; 12];
    value[0] = 0x9e37_79b9_7f4a_7c15;
    value
}

/// Run `keyxchg` on a raw session and return the session key.
fn exchange_keys(session: &mut RawSession) -> u64 {
    let modulus = big(&MODULUS);
    let public = pow_mod(&generator(), &exponent(), &modulus);
    assert_eq!(session.command("keyxchg"), "204- send binary data");
    session.stream.write_all(&wire(&public)).unwrap();
    assert_eq!(session.line(), "203- binary response follows");
    let mut server = [0u8; 96];
    session.reader.read_exact(&mut server).unwrap();
    let shared = pow_mod(&big(&server), &exponent(), &modulus);
    absorb(&wire(&shared))
}

fn qword(value: u64) -> String {
    format!("0q{value:016x}")
}

/// The challenge of a locked banner.
fn challenge(banner: &str) -> u64 {
    let nonce = banner
        .strip_prefix(&format!("201- boxid={BOX_ID} nonce=0q"))
        .unwrap_or_else(|| panic!("unexpected banner {banner:?}"));
    assert_eq!(nonce.len(), 16);
    u64::from_str_radix(nonce, 16).unwrap()
}

/// Security lines of the stored settings file.
fn settings(server: &TestServer) -> Vec<String> {
    let host = server.host.lock();
    let text =
        String::from_utf8(host.backend.system.settings.clone().expect("settings file")).unwrap();
    text.split("\r\n")
        .filter(|line| {
            ["lockmode", "adminpw", "user "]
                .iter()
                .any(|prefix| line.starts_with(prefix))
        })
        .map(str::to_owned)
        .collect()
}

/// A connection opened before locking keeps full access.
fn locked_server() -> (TestServer, RawSession) {
    let server = TestServer::start();
    let mut admin = server.raw();
    assert_eq!(admin.line(), "201- connected");
    assert_eq!(
        admin.command(&format!("lockmode boxid={BOX_ID}")),
        "200- OK"
    );
    (server, admin)
}

#[test]
fn lock_mode_changes_banner_and_denies_access() {
    let server = TestServer::start();
    let mut admin = server.raw();
    assert_eq!(admin.line(), "201- connected");
    assert_eq!(admin.command("boxid"), "420- box is not locked");
    assert_eq!(admin.command("lockmode"), "400- missing parameters");
    assert_eq!(
        admin.command("lockmode boxid=0qxyz"),
        "400- missing parameters"
    );
    assert_eq!(
        admin.command("lockmode encrypt"),
        "400- box not locked; file encryption not enabled"
    );
    assert_eq!(
        admin.command("lockmode unlock encrypt"),
        "200- box not locked; file encryption not enabled"
    );
    assert_eq!(
        admin.command(&format!("lockmode boxid={BOX_ID}")),
        "200- OK"
    );
    assert_eq!(admin.command("boxid"), format!("200- boxid={BOX_ID}"));
    assert_eq!(admin.command("dmversion"), "200- 2.0.21256.0");
    assert_eq!(settings(&server), [format!("lockmode boxid={BOX_ID}")]);

    let mut locked = server.raw();
    challenge(&locked.line());
    assert_eq!(locked.command("dmversion"), "414- access denied");
    assert_eq!(locked.command("lockmode unlock"), "414- access denied");
    assert_eq!(locked.command("boxid"), format!("200- boxid={BOX_ID}"));
    assert_eq!(locked.command("getuserpriv me"), "200- none");
    assert_eq!(locked.command("getuserpriv name=x"), "414- access denied");

    // Relocking keeps the box id; encryption is dropped unless requested.
    assert_eq!(admin.command("lockmode boxid=0q1 encrypt"), "200- OK");
    assert_eq!(
        settings(&server),
        [format!("lockmode boxid={BOX_ID} encrypt")]
    );
    assert_eq!(admin.command("lockmode"), "200- OK");
    assert_eq!(settings(&server), [format!("lockmode boxid={BOX_ID}")]);

    assert_eq!(admin.command("lockmode unlock"), "200- OK");
    assert_eq!(admin.command("boxid"), "420- box is not locked");
    assert!(settings(&server).is_empty());
    let mut unlocked = server.raw();
    assert_eq!(unlocked.line(), "201- connected");
    assert_eq!(
        unlocked.command("getuserpriv me"),
        "200- read write control config manage"
    );
}

#[test]
fn users_round_trip() {
    let server = TestServer::start();
    let mut admin = server.raw();
    admin.line();
    assert_eq!(
        admin.command("user name=bob read"),
        "420- box is not locked"
    );
    assert_eq!(admin.command("userlist"), "420- box is not locked");
    assert_eq!(
        admin.command(&format!("lockmode boxid={BOX_ID}")),
        "200- OK"
    );

    assert_eq!(admin.command("user"), "400- missing name");
    assert_eq!(admin.command("user name=bob write read"), "200- OK");
    assert_eq!(admin.command("user name=bob"), "410- file already exists");
    assert_eq!(admin.command("user name=BOB"), "410- file already exists");
    assert_eq!(admin.command("user name=alice manage"), "200- OK");
    assert_eq!(admin.command("user name=frank"), "200- OK");
    assert_eq!(admin.command("user name=carol config=1 control"), "200- OK");
    // Object-manager name rules: inner or leading backslashes and empty
    // names cannot be created; one trailing backslash is dropped.
    assert_eq!(admin.command(r"user name=a\b"), "400- out of memory");
    assert_eq!(admin.command(r"user name=\a"), "400- out of memory");
    assert_eq!(admin.command("user name="), "400- out of memory");
    assert_eq!(admin.command(r"user name=dave\"), "200- OK");
    assert_eq!(admin.command("getuserpriv name=DAVE"), "200- none");
    assert_eq!(admin.command(r"getuserpriv name=dave\"), "200- none");

    assert_eq!(admin.command("getuserpriv name=Bob"), "200- read write");
    assert_eq!(admin.command("getuserpriv"), "400- missing name");
    assert_eq!(
        admin.command("getuserpriv name=nobody"),
        "402- file not found"
    );
    assert_eq!(
        admin.command("setuserpriv name=bob control manage"),
        "200- OK"
    );
    assert_eq!(admin.command("getuserpriv name=bob"), "200- control manage");
    assert_eq!(
        admin.command("setuserpriv name=nobody read"),
        "402- file not found"
    );
    assert_eq!(admin.command("setuserpriv"), "400- missing name");

    // Directory order: hash bucket, newest first within a bucket.
    assert_eq!(admin.command("userlist"), "202- multiline response follows");
    assert_eq!(
        admin.multiline(),
        [
            "name=\"frank\"",
            "name=\"alice\" manage",
            "name=\"carol\" control config",
            "name=\"dave\"",
            "name=\"bob\" control manage",
        ]
    );
    // setuserpriv is not saved; the file still holds bob's earlier mask.
    assert_eq!(
        settings(&server),
        [
            format!("lockmode boxid={BOX_ID}"),
            "user name=\"frank\"".to_owned(),
            "user name=\"alice\" manage".to_owned(),
            "user name=\"carol\" control config".to_owned(),
            "user name=\"dave\"".to_owned(),
            "user name=\"bob\" read write".to_owned(),
        ]
    );

    assert_eq!(
        admin.command("user name=nobody remove"),
        "402- file not found"
    );
    assert_eq!(admin.command("user name=Alice remove"), "200- OK");
    assert_eq!(
        admin.command("getuserpriv name=alice"),
        "402- file not found"
    );

    // Unlocking deletes every user.
    assert_eq!(admin.command("lockmode unlock"), "200- OK");
    assert_eq!(
        admin.command(&format!("lockmode boxid={BOX_ID}")),
        "200- OK"
    );
    assert_eq!(admin.command("userlist"), "202- multiline response follows");
    assert!(admin.multiline().is_empty());
    assert_eq!(admin.command("getuserpriv name=bob"), "402- file not found");
}

#[test]
fn admin_password_and_response() {
    let (server, mut admin) = locked_server();
    assert_eq!(
        admin.command("adminpw passwd=0q1234"),
        "421- key exchange required"
    );
    let key = exchange_keys(&mut admin);
    assert_eq!(admin.command("adminpw"), "400- missing passwd");
    let password = 0x0bad_c0de_1234_5678u64;
    assert_eq!(
        admin.command(&format!("adminpw passwd={}", qword(password ^ key))),
        "200- OK"
    );
    assert_eq!(
        settings(&server),
        [
            format!("lockmode boxid={BOX_ID}"),
            format!("adminpw passwd={}", qword(password))
        ]
    );

    let mut session = server.raw();
    let nonce = challenge(&session.line());
    assert_eq!(session.command("authuser"), "400- missing response");
    assert_eq!(session.command("authuser resp=0q1"), "400- missing name");
    // Without a key exchange `passwd` is ignored.
    assert_eq!(
        session.command("authuser passwd=0q1 admin"),
        "400- missing response"
    );
    let response = respond(password, nonce);
    assert_eq!(
        session.command(&format!("authuser admin resp={}", qword(response ^ 1))),
        "414- access denied"
    );
    assert_eq!(
        session.command(&format!("authuser admin resp={}", qword(response))),
        "200- OK"
    );
    assert_eq!(
        session.command("getuserpriv me"),
        "200- read write control config manage"
    );
    assert_eq!(session.command("dmversion"), "200- 2.0.21256.0");
    // A failed attempt removes the privileges again.
    assert_eq!(
        session.command("authuser admin resp=0q0"),
        "414- access denied"
    );
    assert_eq!(session.command("dmversion"), "414- access denied");

    exchange_keys(&mut session);
    assert_eq!(
        session.command("authuser passwd=0q1 admin"),
        "400- missing response"
    );

    assert_eq!(admin.command("adminpw none"), "200- OK");
    assert_eq!(settings(&server), [format!("lockmode boxid={BOX_ID}")]);
    assert_eq!(
        session.command(&format!("authuser admin resp={}", qword(response))),
        "414- access denied"
    );
}

#[test]
fn user_sets_password_after_key_exchange() {
    let (server, mut admin) = locked_server();
    assert_eq!(admin.command("user name=bob read write"), "200- OK");

    let mut session = server.raw();
    let nonce = challenge(&session.line());
    assert_eq!(
        session.command("authuser name=nobody resp=0q0"),
        "414- access denied"
    );
    assert_eq!(
        session.command("authuser name=bob resp=0q0"),
        "421- key exchange required"
    );
    let key = exchange_keys(&mut session);
    let password = 0x5555_aaaa_0f0f_f0f0u64;
    assert_eq!(
        session.command(&format!(
            "authuser name=bob passwd={}",
            qword(password ^ key)
        )),
        "200- OK"
    );
    assert_eq!(session.command("getuserpriv me"), "200- read write");
    assert_eq!(session.command("dmversion"), "414- access denied");
    assert_eq!(
        settings(&server),
        [
            format!("lockmode boxid={BOX_ID}"),
            format!("user name=\"bob\" passwd={} read write", qword(password))
        ]
    );
    // A password cannot be replaced this way.
    assert_eq!(
        session.command(&format!("authuser name=bob passwd={}", qword(1 ^ key))),
        "414- access denied"
    );
    assert_eq!(
        session.command(&format!(
            "authuser name=bob resp={}",
            qword(respond(password, nonce))
        )),
        "200- OK"
    );

    let mut other = server.raw();
    let nonce = challenge(&other.line());
    assert_eq!(
        other.command(&format!(
            "authuser name=BOB resp={}",
            qword(respond(password, nonce) ^ 2)
        )),
        "414- access denied"
    );
    assert_eq!(
        other.command(&format!(
            "authuser name=BOB resp={}",
            qword(respond(password, nonce))
        )),
        "200- OK"
    );
    assert_eq!(other.command("getuserpriv me"), "200- read write");
}

#[test]
fn unlocked_connection_reuses_the_slot_challenge() {
    let (server, mut admin) = locked_server();
    let key = exchange_keys(&mut admin);
    let password = 0x77u64;
    assert_eq!(
        admin.command(&format!("adminpw passwd={}", qword(password ^ key))),
        "200- OK"
    );

    let mut locked = server.raw();
    let nonce = challenge(&locked.line());
    assert_eq!(locked.command("bye"), "200- bye");
    assert_eq!(admin.command("lockmode unlock"), "200- OK");

    // The new connection takes the freed slot and its stale challenge.
    let mut unlocked = server.raw();
    assert_eq!(unlocked.line(), "201- connected");
    assert_eq!(
        unlocked.command(&format!(
            "authuser admin resp={}",
            qword(respond(password, nonce))
        )),
        "200- OK"
    );
}

#[test]
fn settings_restore_lock_users_and_admin_password() {
    let mut host = Host::default();
    host.backend.system.settings = Some(
        format!(
            "[xbdm]\r\nlockmode boxid={BOX_ID} encrypt\r\nadminpw passwd={}\r\nuser name=\"bob\" passwd={} read\r\nuser name=\"eve\" write\r\n",
            qword(0x42),
            qword(0x99)
        )
        .into_bytes(),
    );
    let server = TestServer::with_host(host);
    let mut session = server.raw();
    let nonce = challenge(&session.line());
    assert_eq!(
        session.command(&format!(
            "authuser name=bob resp={}",
            qword(respond(0x99, nonce))
        )),
        "200- OK"
    );
    assert_eq!(session.command("getuserpriv me"), "200- read");
    assert_eq!(
        session.command("authuser name=eve resp=0q0"),
        "421- key exchange required"
    );
    assert_eq!(
        session.command(&format!(
            "authuser admin resp={}",
            qword(respond(0x42, nonce))
        )),
        "200- OK"
    );
    assert_eq!(
        session.command("userlist"),
        "202- multiline response follows"
    );
    assert_eq!(
        session.multiline(),
        ["name=\"eve\" write", "name=\"bob\" read"]
    );
}

#[test]
fn client_commands() {
    run(async {
        let server = TestServer::start();
        let mut admin = server.client().await;
        assert_eq!(admin.banner(), "connected");
        assert_eq!(admin.lock_challenge().unwrap(), None);
        let box_id = BoxIdentifier(0x0011_2233_4455_6677);
        admin
            .run(LockMode::Lock {
                box_id,
                encrypt: false,
            })
            .await
            .unwrap();
        assert_eq!(admin.run(BoxId).await.unwrap(), box_id);
        let read = Privileges::READ;
        admin
            .run(AddUser {
                name: "bob".into(),
                privileges: read,
            })
            .await
            .unwrap();
        admin
            .run(SetUserPrivileges {
                name: "bob".into(),
                privileges: read.union(Privileges::CONFIG),
            })
            .await
            .unwrap();
        assert_eq!(
            admin.run(UserList).await.unwrap(),
            [UserEntry {
                name: "bob".into(),
                privileges: read.union(Privileges::CONFIG)
            }]
        );
        let key = admin
            .key_exchange(&DhValue(wire(&exponent())))
            .await
            .unwrap();
        admin
            .run(AdminPassword::Set {
                password: Password(0x1234),
                key,
            })
            .await
            .unwrap();
        assert!(settings(&server).contains(&format!("adminpw passwd={}", qword(0x1234))));

        let mut user = server.client().await;
        let challenge = user.lock_challenge().unwrap().unwrap();
        assert_eq!(challenge.box_id, box_id);
        let name = String::from("bob");
        let error = user
            .run(AuthUser::User {
                name: name.clone(),
                credential: Credential::Response(AuthResponse(0)),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(error.current_context(), Error::Remote { code, message }
                if *code == ErrorCode::KEY_EXCHANGE_REQUIRED && message == "key exchange required"),
            "{error:?}"
        );
        let key = user
            .key_exchange(&DhValue(wire(&exponent())))
            .await
            .unwrap();
        user.run(AuthUser::User {
            name,
            credential: Credential::NewPassword {
                password: Password(0x77),
                key,
            },
        })
        .await
        .unwrap();
        assert_eq!(
            user.run(GetUserPrivileges::Me).await.unwrap(),
            read.union(Privileges::CONFIG)
        );

        let mut again = server.client().await;
        let LockChallenge { nonce, .. } = again.lock_challenge().unwrap().unwrap();
        again
            .run(AuthUser::Admin {
                response: AuthResponse(respond(0x1234, nonce.0)),
            })
            .await
            .unwrap();
        assert_eq!(
            again
                .run(GetUserPrivileges::User("bob".into()))
                .await
                .unwrap(),
            read.union(Privileges::CONFIG)
        );
    });
}

/// Run a security export body on the host's server state, then write dirty
/// settings as the console glue does for exports 61 and 64.
fn export<T>(server: &TestServer, body: impl FnOnce(&mut ServerState, &mut MockBackend) -> T) -> T {
    let mut host = server.host.lock();
    let Host {
        server, backend, ..
    } = &mut *host;
    let result = body(&mut server.state, backend);
    server.save_settings_if_dirty(backend);
    result
}

#[test]
fn exports_share_lock_state_and_users_with_commands() {
    let server = TestServer::start();
    let mut admin = server.raw();
    admin.line();
    assert!(!export(&server, |state, _| security::security_enabled(
        state
    )));
    let unlocked = export(&server, |state, backend| {
        security::add_user(
            state,
            backend,
            b"eve",
            User {
                password: None,
                privileges: Access::READ,
            },
        )
    });
    assert_eq!(unlocked, Hresult(0x82da_0014));
    assert_eq!(
        export(&server, |state, backend| security::walk_users(
            state, backend, &mut 0
        )),
        Err(Hresult(0x82da_0104))
    );

    assert_eq!(
        admin.command(&format!("lockmode boxid={BOX_ID} encrypt")),
        "200- OK"
    );
    assert!(export(&server, |state, _| security::security_enabled(
        state
    )));
    // Enabling security over an encrypted lock keeps the box id, drops
    // encryption, and writes nothing until the next settings write.
    export(&server, |state, backend| {
        security::enable_security(state, backend, true)
    });
    assert_eq!(
        settings(&server),
        [format!("lockmode boxid={BOX_ID} encrypt")]
    );
    let access = Access::READ.union(Access::CONTROL);
    let added = export(&server, |state, backend| {
        security::add_user(
            state,
            backend,
            b"eve",
            User {
                password: None,
                privileges: access,
            },
        )
    });
    assert_eq!(added, Hresult::OK);
    assert_eq!(
        settings(&server),
        [
            format!("lockmode boxid={BOX_ID}"),
            "user name=\"eve\" read control".to_owned()
        ]
    );
    assert_eq!(admin.command("getuserpriv name=EVE"), "200- read control");
    let again = export(&server, |state, backend| {
        security::add_user(
            state,
            backend,
            b"Eve",
            User {
                password: None,
                privileges: access,
            },
        )
    });
    assert_eq!(again, Hresult(0x82da_000a));

    // The access word is stored as given, including bits no command names.
    let raw = Access::from_bits(0x8000_0001);
    assert_eq!(
        export(&server, |_, backend| security::set_user_access(
            backend, b"eve", raw
        )),
        Hresult::OK
    );
    assert_eq!(
        export(&server, |_, backend| security::user_access(backend, b"eve")),
        Ok(raw)
    );
    assert_eq!(admin.command("getuserpriv name=eve"), "200- read");
    assert_eq!(
        export(&server, |_, backend| security::set_user_access(
            backend, b"nobody", raw
        )),
        Hresult(0x82da_0002)
    );
    assert_eq!(
        export(&server, |_, backend| security::user_access(
            backend, b"nobody"
        )),
        Err(Hresult(0x82da_0002))
    );

    assert_eq!(admin.command("user name=bob write"), "200- OK");
    let mut walked = Vec::new();
    let mut position = 0;
    let end = loop {
        match export(&server, |state, backend| {
            security::walk_users(state, backend, &mut position)
        }) {
            Ok((name, access)) => walked.push((
                String::from_utf8(name.as_bytes().to_vec()).unwrap(),
                access.bits(),
            )),
            Err(end) => break end,
        }
    };
    assert_eq!(end, Hresult(0x82da_0104));
    assert_eq!(
        walked,
        [("eve".to_owned(), 0x8000_0001), ("bob".to_owned(), 0x2)]
    );

    assert_eq!(
        export(&server, |state, backend| security::remove_user(
            state, backend, b"nobody"
        )),
        Hresult(0x82da_0002)
    );
    assert_eq!(
        export(&server, |state, backend| security::remove_user(
            state, backend, b"BOB"
        )),
        Hresult::OK
    );
    assert_eq!(admin.command("getuserpriv name=bob"), "402- file not found");
    assert_eq!(
        settings(&server),
        [
            format!("lockmode boxid={BOX_ID}"),
            "user name=\"eve\" read".to_owned()
        ]
    );

    // Disabling security unlocks the box and deletes every user.
    export(&server, |state, backend| {
        security::enable_security(state, backend, false)
    });
    assert_eq!(admin.command("boxid"), "420- box is not locked");
    assert_eq!(
        admin.command(&format!("lockmode boxid={BOX_ID}")),
        "200- OK"
    );
    assert_eq!(admin.command("getuserpriv name=eve"), "402- file not found");
}
