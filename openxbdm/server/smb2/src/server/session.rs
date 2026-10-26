//! SESSION_SETUP (MS-SMB2 3.3.5.5) and LOGOFF (3.3.5.6).

use crate::auth::AuthStep;
use crate::backend::Backend;
use crate::backend::UserKind;
use crate::server::Connection;
use crate::server::MAX_SESSIONS;
use crate::server::Server;
use crate::server::SupersededSession;
use crate::server::error::RequestError;
use crate::server::negotiate::SecurityMode;
use crate::server::request::Body;
use crate::server::request::Completion;
use crate::server::request::Exchange;
use crate::server::request::Failure;
use crate::server::request::Handled;
use crate::server::request::check_signature;
use crate::server::request::empty_body;
use crate::server::security;
use crate::server::security::Nonce;
use crate::server::security::SigningKey;
use crate::server::tables::Session;
use crate::server::tables::SessionId;
use crate::server::tables::SessionSlot;
use crate::server::tables::SessionState;
use crate::server::wire;
use crate::server::wire::Dialect;
use crate::server::wire::HEADER_SIZE;

const _: () = assert!(MAX_SESSIONS <= u8::MAX as usize);

/// Flags of a SESSION_SETUP request (MS-SMB2 2.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupRequestFlags(u8);

impl SetupRequestFlags {
    const BINDING: Self = Self(0x1);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// SESSION_SETUP SessionFlags of a reply (MS-SMB2 2.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionFlags(u16);

impl SessionFlags {
    const NONE: Self = Self(0);
    const IS_GUEST: Self = Self(0x1);
    const IS_NULL: Self = Self(0x2);
    const ENCRYPT_DATA: Self = Self(0x4);

    const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// The session a SESSION_SETUP reply names, and the key that signs it.
pub(super) type SetupSession = Option<(SessionId, Option<SigningKey>)>;

impl Connection {
    pub(super) fn session_setup(
        &mut self,
        exchange: &mut Exchange<'_>,
        id: SessionId,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> (Handled, SetupSession) {
        // Fixed part of the reply body; the security buffer follows.
        const REPLY_FIXED: usize = 8;

        struct Outcome {
            completion: Completion,
            length: usize,
            flags: SessionFlags,
            key: Option<SigningKey>,
        }

        let body = match exchange.fixed_body(25, 24) {
            Ok(body) => body,
            Err(failure) => return (Err(failure), None),
        };
        if SetupRequestFlags(wire::u8_at(body, 2)).contains(SetupRequestFlags::BINDING) {
            return (Err(Failure::Error(RequestError::BindingNotAccepted)), None);
        }

        let client_requires_signing =
            SecurityMode(u16::from(wire::u8_at(body, 3))).contains(SecurityMode::SIGNING_REQUIRED);
        let token = match wire::buffer(
            exchange.message,
            24,
            usize::from(wire::u16_at(body, 12)),
            usize::from(wire::u16_at(body, 14)),
        ) {
            Some(token) => token,
            None => return (Err(Failure::Error(RequestError::InvalidRequest)), None),
        };

        let previous = SessionId(wire::u64_at(body, 16));
        let slot = match self.setup_slot(exchange, id, backend) {
            Ok(slot) => slot,
            Err(failure) => return (Err(failure), None),
        };
        let session_id = self.session(slot).id;
        if output.len() < REPLY_FIXED {
            return (Err(Failure::Disconnect), None);
        }

        let dialect = self.dialect();
        if dialect == Some(Dialect::SMB_3_1_1)
            && self.session(slot).state == SessionState::InProgress
        {
            let entry = self.session_mut(slot);
            entry.preauth = entry.preauth.update(exchange.message);
        }

        let step = self.auths[usize::from(slot.0)].step(token, &mut output[REPLY_FIXED..], backend);
        let outcome = match step {
            Ok(AuthStep::Continue { length }) => Outcome {
                completion: Completion::MoreProcessingRequired,
                length,
                flags: SessionFlags::NONE,
                key: None,
            },
            Ok(AuthStep::Complete { length, session }) => {
                let config = exchange.config;
                let negotiated = self.negotiated;
                let entry = self.session_mut(slot);
                let established = entry.state == SessionState::InProgress;
                match entry.state {
                    SessionState::InProgress => {
                        entry.kind = session.kind;
                        if let (Some(key), Some(negotiated)) = (session.session_key, negotiated) {
                            let (signing, encryption) = security::derive_keys(
                                negotiated.dialect,
                                &key,
                                &entry.preauth,
                                negotiated.signing,
                                negotiated.cipher,
                            );
                            entry.signing = Some(signing);
                            entry.encryption = encryption;
                            entry.encrypt_data = config.encrypt_data && encryption.is_some();
                        }
                        entry.signing_required = entry.signing.is_some()
                            && (config.signing_required || client_requires_signing);
                        entry.state = SessionState::Valid;
                    }
                    // Re-authentication keeps the session's keys; it must
                    // establish the same kind of user.
                    SessionState::Valid if entry.kind != session.kind => {
                        self.remove_session(slot, server, backend);
                        return (
                            Err(Failure::Error(RequestError::AccessDenied)),
                            Some((session_id, None)),
                        );
                    }
                    // Re-authentication of the same kind of user.
                    SessionState::Valid => {}
                }

                if established && previous.0 != 0 && previous != session_id {
                    self.supersede(previous, session.kind, server, backend);
                }

                let entry = self.session(slot);
                let mut flags = match session.kind {
                    UserKind::Authenticated => SessionFlags::NONE,
                    UserKind::Guest => SessionFlags::IS_GUEST,
                    UserKind::Anonymous => SessionFlags::IS_NULL,
                };
                if entry.encrypt_data {
                    flags = flags.union(SessionFlags::ENCRYPT_DATA);
                }

                // The final reply of an authenticated session is signed
                // (MS-SMB2 3.3.5.5.3); guest and anonymous sessions have
                // no key.
                Outcome {
                    completion: Completion::Success,
                    length,
                    flags,
                    key: entry.signing,
                }
            }
            Err(error) => {
                self.remove_session(slot, server, backend);
                return (Err(Failure::Error(error.into())), Some((session_id, None)));
            }
        };

        output[..REPLY_FIXED].fill(0);
        wire::put_u16(output, 0, 9);
        wire::put_u16(output, 2, outcome.flags.0);
        wire::put_u16(output, 4, (HEADER_SIZE + REPLY_FIXED) as u16);
        wire::put_u16(output, 6, outcome.length as u16);

        (
            Ok(Body {
                completion: outcome.completion,
                length: REPLY_FIXED + outcome.length,
            }),
            Some((session_id, outcome.key)),
        )
    }

    /// Record an interim SESSION_SETUP reply in its session's
    /// preauthentication integrity hash (SMB 3.1.1).
    pub(super) fn hash_setup_reply(&mut self, id: SessionId, reply: &[u8]) {
        if self.dialect() != Some(Dialect::SMB_3_1_1) {
            return;
        }

        let Some(slot) = self.find_session(id) else {
            return;
        };
        let entry = self.session_mut(slot);
        if entry.state == SessionState::InProgress {
            entry.preauth = entry.preauth.update(reply);
        }
    }

    /// The session a SESSION_SETUP continues or starts.
    fn setup_slot(
        &mut self,
        exchange: &Exchange<'_>,
        id: SessionId,
        backend: &mut dyn Backend,
    ) -> Result<SessionSlot, Failure> {
        if id.0 != 0 {
            let slot = self.find_session(id).ok_or(RequestError::SessionNotFound)?;
            let session = *self.session(slot);
            if session.state == SessionState::Valid {
                if !exchange.encrypted {
                    // A session that requires encryption is not
                    // re-authenticated in the clear; it stays as it is.
                    if session.encrypt_data {
                        return Err(Failure::Error(RequestError::AccessDenied));
                    }
                    check_signature(exchange, &session)?;
                }

                // A setup on a valid session starts a re-authentication
                // unless one is under way.
                if !self.auths[usize::from(slot.0)].in_progress() {
                    self.auths[usize::from(slot.0)].reset();
                }
            }

            return Ok(slot);
        }

        let index = self
            .sessions
            .iter()
            .position(Option::is_none)
            .ok_or(RequestError::TableFull)?;
        let id = self.new_session_id(backend);
        self.sessions[index] = Some(Session {
            id,
            state: SessionState::InProgress,
            kind: UserKind::Anonymous,
            signing: None,
            signing_required: false,
            encryption: None,
            encrypt_data: false,
            preauth: self.preauth,
            next_nonce: Nonce::FIRST,
        });
        self.auths[index].reset();

        Ok(SessionSlot(index as u8))
    }

    /// A random identifier that is nonzero and unused on this connection.
    fn new_session_id(&self, backend: &mut dyn Backend) -> SessionId {
        loop {
            let mut bytes = [0; 8];
            backend.random_bytes(&mut bytes);
            let id = SessionId(u64::from_le_bytes(bytes));
            if id.0 != 0 && id.0 != u64::MAX && self.find_session(id).is_none() {
                return id;
            }
        }
    }

    pub(super) fn logoff(
        &mut self,
        exchange: &Exchange<'_>,
        server: &mut Server,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        exchange.fixed_body(4, 4)?;

        if let Some(slot) = exchange.session {
            self.remove_session(slot, server, backend);
        }

        Ok(Body::success(empty_body(output)))
    }

    /// End the session `previous` that a new logon of `kind` replaces
    /// (MS-SMB2 3.3.5.5.3): here when this connection holds it, otherwise
    /// through the server's queue for the platform.
    fn supersede(
        &mut self,
        previous: SessionId,
        kind: UserKind,
        server: &mut Server,
        backend: &mut dyn Backend,
    ) {
        let superseded = SupersededSession { id: previous, kind };
        if self.find_session(previous).is_some() {
            self.end_session(server, backend, superseded);
        } else {
            server.supersede(superseded);
        }
    }

    /// End the session a logon on another connection superseded, if this
    /// connection holds it and it is of the same kind: its tree connects,
    /// opens, and waiting requests go as with LOGOFF. Returns whether it
    /// ended.
    pub fn end_session(
        &mut self,
        server: &mut Server,
        backend: &mut dyn Backend,
        superseded: SupersededSession,
    ) -> bool {
        let Some(slot) = self.find_session(superseded.id) else {
            return false;
        };

        let session = self.session(slot);
        if session.state != SessionState::Valid || session.kind != superseded.kind {
            return false;
        }
        self.remove_session(slot, server, backend);

        true
    }

    /// Remove a session with its tree connects, opens, and the requests
    /// that wait for it.
    fn remove_session(
        &mut self,
        slot: SessionSlot,
        server: &mut Server,
        backend: &mut dyn Backend,
    ) {
        self.close_opens_where(server, backend, |open| open.session == slot);

        for pending in &mut self.pending {
            if pending.is_some_and(|pending| pending.session == slot) {
                *pending = None;
            }
        }

        for tree in &mut self.trees {
            if tree.is_some_and(|tree| tree.session == slot) {
                *tree = None;
            }
        }

        self.sessions[usize::from(slot.0)] = None;
        self.auths[usize::from(slot.0)].reset();
    }

    fn session(&self, slot: SessionSlot) -> &Session {
        self.sessions[usize::from(slot.0)]
            .as_ref()
            .expect("session slot of a handled request is occupied")
    }

    fn session_mut(&mut self, slot: SessionSlot) -> &mut Session {
        self.sessions[usize::from(slot.0)]
            .as_mut()
            .expect("session slot of a handled request is occupied")
    }
}
