//! NTLMSSP and SPNEGO acceptor for SMB 2 SESSION_SETUP.
//!
//! Clients authenticate with NTLMv2 (MS-NLMP), either inside SPNEGO
//! (RFC 4178) or as raw NTLMSSP messages. Each reply uses the framing of
//! the request it answers.

mod der;
mod error;
mod ntlm;
mod spnego;
#[cfg(test)]
mod tests;

use crate::backend::Backend;
use crate::backend::COMPUTER_NAME_CAPACITY;
use crate::backend::UserKind;
use crate::crypto::constant_time_eq;
use ntlm::Flags;
use spnego::NegState;
use spnego::NtlmPosition;
use spnego::Reply;

pub use error::AuthError;
pub use error::NtlmMessage;

/// Longest NEGOTIATE kept for the MIC. Clients send 40 bytes or a few
/// more with domain and workstation names.
const NEGOTIATE_CAPACITY: usize = 256;
/// Longest MechTypeList kept for mechListMIC; room for about ten OIDs.
const MECH_TYPES_CAPACITY: usize = 128;

/// Session key from NTLM: the ExportedSessionKey of MS-NLMP.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionKey(pub [u8; 16]);

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SessionKey(..)")
    }
}

/// An authenticated logon.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatedSession {
    pub kind: UserKind,
    /// ExportedSessionKey; `None` for guest and anonymous.
    pub session_key: Option<SessionKey>,
}

/// Outcome of one [`Authenticator::step`].
#[derive(Debug, Clone, Copy)]
pub enum AuthStep {
    /// Send `length` bytes of `output` with STATUS_MORE_PROCESSING_REQUIRED.
    Continue { length: usize },
    /// Authentication finished; send `length` bytes with STATUS_SUCCESS.
    Complete {
        length: usize,
        session: AuthenticatedSession,
    },
}

/// A bounded copy of a message.
struct Record<const N: usize> {
    bytes: [u8; N],
    length: usize,
}

impl<const N: usize> Record<N> {
    const fn new() -> Self {
        Self {
            bytes: [0; N],
            length: 0,
        }
    }

    fn set(&mut self, data: &[u8]) -> Result<(), AuthError> {
        let too_large = AuthError::MessageTooLarge {
            length: data.len(),
            capacity: N,
        };

        self.bytes
            .get_mut(..data.len())
            .ok_or(too_large)?
            .copy_from_slice(data);
        self.length = data.len();

        Ok(())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// How the client frames its tokens.
#[derive(Clone, Copy)]
enum Framing {
    Raw,
    /// `mic_required`: NTLMSSP was not the client's first mechanism, so
    /// mechListMIC is mandatory (RFC 4178 section 5).
    Spnego {
        mic_required: bool,
    },
}

/// Values of the CHALLENGE sent.
#[derive(Clone, Copy)]
struct Challenge {
    flags: Flags,
    server_challenge: [u8; 8],
}

#[derive(Clone, Copy)]
enum Stage {
    Initial,
    /// SPNEGO selected NTLMSSP without a NEGOTIATE; it comes next.
    SpnegoNegotiate {
        mic_required: bool,
    },
    /// CHALLENGE sent; AUTHENTICATE comes next.
    Authenticate {
        framing: Framing,
        challenge: Challenge,
    },
}

/// Server side of one authentication exchange. Holds no allocation; the
/// state is a few hundred bytes.
pub struct Authenticator {
    stage: Stage,
    negotiate: Record<NEGOTIATE_CAPACITY>,
    challenge: Record<{ ntlm::CHALLENGE_CAPACITY }>,
    /// The client's MechTypeList DER, valid with [`Framing::Spnego`].
    mech_types: Record<MECH_TYPES_CAPACITY>,
}

impl Authenticator {
    pub const fn new() -> Self {
        Self {
            stage: Stage::Initial,
            negotiate: Record::new(),
            challenge: Record::new(),
            mech_types: Record::new(),
        }
    }

    /// Process one SESSION_SETUP security buffer. Writes the reply
    /// security buffer into `output`. After an error or completion the
    /// authenticator is back in its initial state.
    pub fn step(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        backend: &mut dyn Backend,
    ) -> Result<AuthStep, AuthError> {
        let result = match self.stage {
            Stage::Initial => self.begin(input, output, backend),
            Stage::SpnegoNegotiate { mic_required } => {
                self.spnego_negotiate(input, output, backend, mic_required)
            }
            Stage::Authenticate { framing, challenge } => {
                self.finish(input, output, backend, framing, challenge)
            }
        };

        if !matches!(result, Ok(AuthStep::Continue { .. })) {
            self.reset();
        }

        result
    }

    /// Forget any exchange in progress.
    pub fn reset(&mut self) {
        self.stage = Stage::Initial;
        self.negotiate.length = 0;
        self.challenge.length = 0;
        self.mech_types.length = 0;
    }

    /// Whether an exchange has started and not finished.
    pub fn in_progress(&self) -> bool {
        !matches!(self.stage, Stage::Initial)
    }

    fn begin(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        backend: &mut dyn Backend,
    ) -> Result<AuthStep, AuthError> {
        if input.starts_with(&ntlm::SIGNATURE) {
            let challenge = self.challenge(input, backend)?;
            let token = self.challenge.as_bytes();
            output
                .get_mut(..token.len())
                .ok_or(AuthError::OutputTooSmall)?
                .copy_from_slice(token);
            self.stage = Stage::Authenticate {
                framing: Framing::Raw,
                challenge,
            };
            return Ok(AuthStep::Continue {
                length: token.len(),
            });
        }

        let init = spnego::parse_init(input).ok_or(AuthError::MalformedToken)?;
        let mic_required = match init.ntlm {
            NtlmPosition::Absent => return Err(AuthError::MechanismNotOffered),
            NtlmPosition::First => false,
            NtlmPosition::Later => true,
        };

        self.mech_types.set(init.mech_types)?;

        // An optimistic token for another mechanism is ignored. When NTLMSSP
        // is not the preferred mechanism, the first reply demands a
        // mechListMIC (RFC 4178 section 3.2).
        let Some(token) = init.mech_token.filter(|_| !mic_required) else {
            let state = if mic_required {
                NegState::RequestMic
            } else {
                NegState::AcceptIncomplete
            };
            let length = write_reply(
                &Reply {
                    state,
                    supported_mech: true,
                    response_token: None,
                    mech_list_mic: None,
                },
                output,
            )?;

            self.stage = Stage::SpnegoNegotiate { mic_required };
            return Ok(AuthStep::Continue { length });
        };

        let challenge = self.challenge(token, backend)?;
        let length = write_reply(
            &Reply {
                state: NegState::AcceptIncomplete,
                supported_mech: true,
                response_token: Some(self.challenge.as_bytes()),
                mech_list_mic: None,
            },
            output,
        )?;

        self.stage = Stage::Authenticate {
            framing: Framing::Spnego { mic_required },
            challenge,
        };

        Ok(AuthStep::Continue { length })
    }

    fn spnego_negotiate(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        backend: &mut dyn Backend,
        mic_required: bool,
    ) -> Result<AuthStep, AuthError> {
        let token = client_resp(input)?
            .response_token
            .ok_or(AuthError::MalformedToken)?;

        let challenge = self.challenge(token, backend)?;

        let length = write_reply(
            &Reply {
                state: NegState::AcceptIncomplete,
                supported_mech: false,
                response_token: Some(self.challenge.as_bytes()),
                mech_list_mic: None,
            },
            output,
        )?;

        self.stage = Stage::Authenticate {
            framing: Framing::Spnego { mic_required },
            challenge,
        };

        Ok(AuthStep::Continue { length })
    }

    /// Answer a NEGOTIATE: build the CHALLENGE in `self.challenge`.
    fn challenge(
        &mut self,
        negotiate: &[u8],
        backend: &mut dyn Backend,
    ) -> Result<Challenge, AuthError> {
        let flags = ntlm::challenge_flags(negotiate)?;
        self.negotiate.set(negotiate)?;

        let mut server_challenge = [0u8; 8];
        backend.random_bytes(&mut server_challenge);

        let mut name = [0u8; COMPUTER_NAME_CAPACITY];
        let name_length = backend.computer_name(&mut name);
        let name = name
            .get(..name_length)
            .ok_or(AuthError::InvalidComputerName {
                length: name_length,
            })?;

        let time = backend.system_time();

        // Cannot fail: the buffer holds a CHALLENGE for the longest name.
        self.challenge.length = ntlm::write_challenge(
            flags,
            &server_challenge,
            time,
            name,
            &mut self.challenge.bytes,
        )
        .ok_or(AuthError::InvalidComputerName {
            length: name_length,
        })?;

        Ok(Challenge {
            flags,
            server_challenge,
        })
    }

    fn finish(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        backend: &mut dyn Backend,
        framing: Framing,
        challenge: Challenge,
    ) -> Result<AuthStep, AuthError> {
        let (token, client_mic) = match framing {
            Framing::Raw => (input, None),
            Framing::Spnego { .. } => {
                let response = client_resp(input)?;
                let token = response.response_token.ok_or(AuthError::MalformedToken)?;
                (token, response.mech_list_mic)
            }
        };

        let exchange = ntlm::Exchange {
            negotiate: self.negotiate.as_bytes(),
            challenge: self.challenge.as_bytes(),
            flags: challenge.flags,
            server_challenge: challenge.server_challenge,
        };

        let outcome = ntlm::authenticate(token, &exchange, backend)?;

        let length = match framing {
            Framing::Raw => 0,
            Framing::Spnego { mic_required } => {
                // Guest and anonymous logons have no key to protect the
                // mechanism list with.
                let server_mic = match outcome.session_key {
                    Some(key) => {
                        self.mech_list_mic(&key, outcome.flags, client_mic, mic_required)?
                    }
                    None => None,
                };

                write_reply(
                    &Reply {
                        state: NegState::AcceptCompleted,
                        supported_mech: false,
                        response_token: None,
                        mech_list_mic: server_mic.as_ref().map(|mic| &mic[..]),
                    },
                    output,
                )?
            }
        };

        Ok(AuthStep::Complete {
            length,
            session: AuthenticatedSession {
                kind: outcome.kind,
                session_key: outcome.session_key.map(SessionKey),
            },
        })
    }

    /// Verify the client's mechListMIC and produce the server's (RFC 4178
    /// section 5). Without a client MIC none is sent unless required.
    fn mech_list_mic(
        &self,
        session_key: &[u8; 16],
        flags: Flags,
        client_mic: Option<&[u8]>,
        required: bool,
    ) -> Result<Option<[u8; 16]>, AuthError> {
        let Some(client_mic) = client_mic else {
            return if required {
                Err(AuthError::MechListMicMissing)
            } else {
                Ok(None)
            };
        };

        let mech_types = self.mech_types.as_bytes();
        let expected = ntlm::first_message_signature(
            session_key,
            flags,
            ntlm::Direction::ClientToServer,
            mech_types,
        )
        .ok_or(AuthError::MechListMicUnsupported)?;

        if !constant_time_eq(&expected, client_mic) {
            return Err(AuthError::MechListMicMismatch);
        }

        ntlm::first_message_signature(
            session_key,
            flags,
            ntlm::Direction::ServerToClient,
            mech_types,
        )
        .map(Some)
        .ok_or(AuthError::MechListMicUnsupported)
    }
}

/// SPNEGO NegTokenInit offering only NTLMSSP, for the security buffer of
/// the SMB 2 NEGOTIATE response. Returns its length, or `None` when
/// `output` is too small.
pub fn negotiate_token(output: &mut [u8]) -> Option<usize> {
    let token = &spnego::NEGOTIATE_TOKEN;
    output.get_mut(..token.len())?.copy_from_slice(token);

    Some(token.len())
}

fn write_reply(reply: &Reply<'_>, output: &mut [u8]) -> Result<usize, AuthError> {
    spnego::write_resp(reply, output).ok_or(AuthError::OutputTooSmall)
}

/// Parse a NegTokenResp from the client; a client that rejects the
/// negotiation ends it.
fn client_resp(input: &[u8]) -> Result<spnego::NegTokenResp<'_>, AuthError> {
    let response = spnego::parse_resp(input).ok_or(AuthError::MalformedToken)?;

    if response.state == Some(NegState::Reject) {
        return Err(AuthError::ClientRejected);
    }

    Ok(response)
}
