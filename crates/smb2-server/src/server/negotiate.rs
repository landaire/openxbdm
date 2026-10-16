//! NEGOTIATE (MS-SMB2 3.3.5.4) with the SMB 3.1.1 negotiate contexts, and
//! the multi-protocol negotiate of SMB 1 clients (MS-SMB2 3.3.5.3).

use crate::backend::Backend;
use crate::server::Body;
use crate::server::Connection;
use crate::server::Exchange;
use crate::server::Failure;
use crate::server::Handled;
use crate::server::Negotiation;
use crate::server::RequestError;
use crate::server::ServerConfig;
use crate::server::security::Cipher;
use crate::server::security::PreauthHash;
use crate::server::security::SigningAlgorithm;
use crate::server::wire;
use crate::server::wire::Command;
use crate::server::wire::Credits;
use crate::server::wire::Dialect;
use crate::server::wire::HEADER_SIZE;
use crate::server::wire::HeaderFlags;
use crate::server::wire::MessageId;
use crate::server::wire::header;
use crate::transport;

/// Dialects in order of preference.
const DIALECTS: [Dialect; 5] = [
    Dialect::SMB_3_1_1,
    Dialect::SMB_3_0_2,
    Dialect::SMB_3_0,
    Dialect::SMB_2_1,
    Dialect::SMB_2_0_2,
];

/// SecurityMode of a NEGOTIATE (MS-SMB2 2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(super) struct SecurityMode(pub u16);

impl SecurityMode {
    pub const SIGNING_ENABLED: Self = Self(0x1);
    pub const SIGNING_REQUIRED: Self = Self(0x2);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Global capabilities of a NEGOTIATE (MS-SMB2 2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(super) struct GlobalCapabilities(pub u32);

impl GlobalCapabilities {
    pub const NONE: Self = Self(0);
    pub const ENCRYPTION: Self = Self(0x40);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// A negotiate context type (MS-SMB2 2.2.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ContextType(u16);

impl ContextType {
    const PREAUTH_INTEGRITY_CAPABILITIES: Self = Self(0x0001);
    const ENCRYPTION_CAPABILITIES: Self = Self(0x0002);
    const SIGNING_CAPABILITIES: Self = Self(0x0008);
}

/// A preauthentication integrity hash algorithm (MS-SMB2 2.2.3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HashAlgorithm(u16);

impl HashAlgorithm {
    const SHA_512: Self = Self(0x0001);
}

/// Fixed part of the request and reply bodies.
const REQUEST_FIXED: usize = 36;
const REPLY_FIXED: usize = 64;

/// Salt bytes of the preauthentication integrity context.
const SALT: usize = 32;

/// SMB 1 header length and the offset of its command byte.
const SMB1_HEADER: usize = 32;
const SMB1_COMMAND: usize = 4;
const SMB1_NEGOTIATE: u8 = 0x72;
/// Dialect buffer format byte.
const SMB1_DIALECT_FORMAT: u8 = 0x02;

/// What the client's SMB 3.1.1 negotiate contexts asked for.
#[derive(Debug, Clone, Copy, Default)]
struct Contexts {
    preauth: bool,
    /// The client sent an encryption context; the chosen cipher, if any.
    encryption: Option<Option<Cipher>>,
    /// The client sent a signing context; the chosen algorithm.
    signing: Option<SigningAlgorithm>,
}

/// The parameters a NEGOTIATE settles.
#[derive(Debug, Clone, Copy)]
pub(super) struct Negotiated {
    pub dialect: Dialect,
    pub cipher: Option<Cipher>,
    pub signing: SigningAlgorithm,
}

/// The dialect the server picks from a list of dialect revisions.
pub(super) fn select_dialect(offered: &[u8]) -> Option<Dialect> {
    DIALECTS.into_iter().find(|dialect| {
        offered
            .as_chunks::<2>()
            .0
            .iter()
            .any(|pair| u16::from_le_bytes(*pair) == dialect.0)
    })
}

impl Connection {
    pub(super) fn negotiate(
        &mut self,
        exchange: &Exchange<'_>,
        backend: &mut dyn Backend,
        output: &mut [u8],
    ) -> Handled {
        let body = exchange.fixed_body(36, REQUEST_FIXED)?;
        let count = usize::from(wire::u16_at(body, 2));
        let offered = body
            .get(REQUEST_FIXED..REQUEST_FIXED + count * 2)
            .filter(|_| count != 0)
            .ok_or(RequestError::InvalidRequest)?;
        let dialect = select_dialect(offered).ok_or(RequestError::Unsupported)?;
        let capabilities = GlobalCapabilities(wire::u32_at(body, 8));
        let contexts = if dialect == Dialect::SMB_3_1_1 {
            let contexts = wire::buffer(
                exchange.message,
                REQUEST_FIXED,
                wire::u32_at(body, 28) as usize,
                exchange
                    .message
                    .len()
                    .saturating_sub(wire::u32_at(body, 28) as usize),
            )
            .ok_or(RequestError::InvalidRequest)?;
            let contexts = parse_contexts(contexts, usize::from(wire::u16_at(body, 32)))?;
            if !contexts.preauth {
                return Err(Failure::Error(RequestError::InvalidRequest));
            }
            contexts
        } else {
            Contexts::default()
        };
        let negotiated = Negotiated {
            dialect,
            cipher: match dialect {
                Dialect::SMB_3_1_1 => contexts.encryption.flatten(),
                Dialect::SMB_3_0 | Dialect::SMB_3_0_2
                    if capabilities.contains(GlobalCapabilities::ENCRYPTION) =>
                {
                    Some(Cipher::Aes128Ccm)
                }
                _ => None,
            },
            signing: match dialect {
                Dialect::SMB_3_1_1 => contexts.signing.unwrap_or(SigningAlgorithm::AesCmac),
                Dialect::SMB_3_0 | Dialect::SMB_3_0_2 => SigningAlgorithm::AesCmac,
                _ => SigningAlgorithm::HmacSha256,
            },
        };
        self.client_guid.0.copy_from_slice(&body[12..28]);
        self.client_capabilities = capabilities;
        self.client_security_mode = SecurityMode(wire::u16_at(body, 4));
        self.negotiated = Some(negotiated);
        self.negotiation = Negotiation::Done(dialect);
        let length = negotiate_reply(
            &exchange.config,
            backend,
            &negotiated,
            Some(&contexts),
            output,
        )
        .ok_or(Failure::Disconnect)?;
        Ok(Body::success(length))
    }

    /// Record a NEGOTIATE request and its reply in the connection's
    /// preauthentication integrity hash (SMB 3.1.1).
    pub(super) fn hash_negotiate(&mut self, request: &[u8], reply: &[u8]) {
        if self.dialect() == Some(Dialect::SMB_3_1_1) {
            self.preauth = PreauthHash::ZERO.update(request).update(reply);
        }
    }

    /// Answer an SMB 1 negotiate that offers an SMB 2 dialect with an SMB
    /// 2 NEGOTIATE reply; returns the end of the reply in `response`.
    pub(super) fn negotiate_multi_protocol(
        &mut self,
        config: &ServerConfig,
        backend: &mut dyn Backend,
        request: &[u8],
        response: &mut [u8],
    ) -> Option<usize> {
        if self.negotiation != Negotiation::Initial
            || request.get(SMB1_COMMAND) != Some(&SMB1_NEGOTIATE)
            || request.len() < SMB1_HEADER + 3
            || request[SMB1_HEADER] != 0
        {
            return None;
        }
        let byte_count = usize::from(wire::u16_at(request, SMB1_HEADER + 1));
        let dialects = request.get(SMB1_HEADER + 3..SMB1_HEADER + 3 + byte_count)?;
        let mut wildcard = false;
        let mut smb_2_0_2 = false;
        let mut rest = dialects;
        while let [SMB1_DIALECT_FORMAT, tail @ ..] = rest {
            let end = tail.iter().position(|&byte| byte == 0)?;
            match &tail[..end] {
                b"SMB 2.???" => wildcard = true,
                b"SMB 2.002" => smb_2_0_2 = true,
                _ => {}
            }
            rest = &tail[end + 1..];
        }
        let dialect = if wildcard {
            self.negotiation = Negotiation::Wildcard;
            Dialect::WILDCARD
        } else if smb_2_0_2 {
            self.negotiation = Negotiation::Done(Dialect::SMB_2_0_2);
            Dialect::SMB_2_0_2
        } else {
            return None;
        };
        let negotiated = Negotiated {
            dialect,
            cipher: None,
            signing: SigningAlgorithm::HmacSha256,
        };
        if dialect != Dialect::WILDCARD {
            self.negotiated = Some(negotiated);
        }
        if !self.credits.consume(MessageId(0)) {
            return None;
        }
        let start = transport::HEADER_LENGTH;
        let output = &mut response[start..];
        let length = negotiate_reply(
            config,
            backend,
            &negotiated,
            None,
            &mut output[HEADER_SIZE..],
        )?;
        output[..HEADER_SIZE].fill(0);
        output[..4].copy_from_slice(&wire::PROTOCOL_ID);
        wire::put_u16(output, header::STRUCTURE_SIZE, HEADER_SIZE as u16);
        wire::put_u16(output, header::COMMAND, Command::NEGOTIATE.0);
        wire::put_u16(output, header::CREDITS, self.credits.grant(Credits(1)).0);
        wire::put_u32(output, header::FLAGS, HeaderFlags::SERVER_TO_REDIR.0);
        Some(start + HEADER_SIZE + length)
    }
}

/// The security mode the server announces.
pub(super) const fn security_mode(config: &ServerConfig) -> SecurityMode {
    if config.signing_required {
        SecurityMode::SIGNING_ENABLED.union(SecurityMode::SIGNING_REQUIRED)
    } else {
        SecurityMode::SIGNING_ENABLED
    }
}

/// The capabilities the server announces for a dialect.
pub(super) const fn capabilities(negotiated: &Negotiated) -> GlobalCapabilities {
    match negotiated.dialect {
        Dialect::SMB_3_0 | Dialect::SMB_3_0_2 if negotiated.cipher.is_some() => {
            GlobalCapabilities::ENCRYPTION
        }
        _ => GlobalCapabilities::NONE,
    }
}

/// Read the negotiate contexts of an SMB 3.1.1 NEGOTIATE (MS-SMB2
/// 2.2.3.1).
fn parse_contexts(mut contexts: &[u8], count: usize) -> Result<Contexts, Failure> {
    let mut found = Contexts::default();
    for index in 0..count {
        if contexts.len() < 8 {
            return Err(Failure::Error(RequestError::InvalidRequest));
        }
        let kind = ContextType(wire::u16_at(contexts, 0));
        let length = usize::from(wire::u16_at(contexts, 2));
        let data = contexts
            .get(8..8 + length)
            .ok_or(RequestError::InvalidRequest)?;
        match kind {
            ContextType::PREAUTH_INTEGRITY_CAPABILITIES => {
                if found.preauth || data.len() < 4 {
                    return Err(Failure::Error(RequestError::InvalidRequest));
                }
                let algorithms = usize::from(wire::u16_at(data, 0));
                let list = data
                    .get(4..4 + algorithms * 2)
                    .filter(|_| algorithms != 0)
                    .ok_or(RequestError::InvalidRequest)?;
                if !list
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|pair| u16::from_le_bytes(*pair) == HashAlgorithm::SHA_512.0)
                {
                    return Err(Failure::Error(RequestError::NoPreauthenticationHash));
                }
                found.preauth = true;
            }
            ContextType::ENCRYPTION_CAPABILITIES => {
                if found.encryption.is_some() || data.len() < 2 {
                    return Err(Failure::Error(RequestError::InvalidRequest));
                }
                let ciphers = usize::from(wire::u16_at(data, 0));
                let list = data
                    .get(2..2 + ciphers * 2)
                    .filter(|_| ciphers != 0)
                    .ok_or(RequestError::InvalidRequest)?;
                let offered = |cipher: Cipher| {
                    list.as_chunks::<2>()
                        .0
                        .iter()
                        .any(|pair| u16::from_le_bytes(*pair) == cipher.wire())
                };
                found.encryption = Some(
                    [Cipher::Aes128Gcm, Cipher::Aes128Ccm]
                        .into_iter()
                        .find(|&cipher| offered(cipher)),
                );
            }
            ContextType::SIGNING_CAPABILITIES => {
                if found.signing.is_some() || data.len() < 2 {
                    return Err(Failure::Error(RequestError::InvalidRequest));
                }
                let algorithms = usize::from(wire::u16_at(data, 0));
                let list = data
                    .get(2..2 + algorithms * 2)
                    .filter(|_| algorithms != 0)
                    .ok_or(RequestError::InvalidRequest)?;
                let offered = |algorithm: SigningAlgorithm| {
                    list.as_chunks::<2>()
                        .0
                        .iter()
                        .any(|pair| u16::from_le_bytes(*pair) == algorithm.wire())
                };
                // Without a common algorithm the connection signs with
                // AES-CMAC (MS-SMB2 3.3.5.4).
                found.signing = Some(
                    [
                        SigningAlgorithm::AesGmac,
                        SigningAlgorithm::AesCmac,
                        SigningAlgorithm::HmacSha256,
                    ]
                    .into_iter()
                    .find(|&algorithm| offered(algorithm))
                    .unwrap_or(SigningAlgorithm::AesCmac),
                );
            }
            // Compression, the network name, transport, and RDMA contexts
            // ask for nothing the server offers; the reply omits them.
            _ => {}
        }
        if index + 1 < count {
            let next = wire::align8(8 + length);
            contexts = contexts.get(next..).ok_or(RequestError::InvalidRequest)?;
        }
    }
    Ok(found)
}

/// Write a NEGOTIATE reply body; returns its length.
fn negotiate_reply(
    config: &ServerConfig,
    backend: &mut dyn Backend,
    negotiated: &Negotiated,
    contexts: Option<&Contexts>,
    output: &mut [u8],
) -> Option<usize> {
    if output.len() < REPLY_FIXED {
        return None;
    }
    let token = crate::auth::negotiate_token(&mut output[REPLY_FIXED..])?;
    let max_io = config.max_io() as u32;
    output[..REPLY_FIXED].fill(0);
    wire::put_u16(output, 0, 65);
    wire::put_u16(output, 2, security_mode(config).0);
    wire::put_u16(output, 4, negotiated.dialect.0);
    output[8..24].copy_from_slice(&config.guid.0);
    wire::put_u32(output, 24, capabilities(negotiated).0);
    wire::put_u32(output, 28, max_io);
    wire::put_u32(output, 32, max_io);
    wire::put_u32(output, 36, max_io);
    wire::put_u64(output, 40, backend.system_time().0);
    wire::put_u64(output, 48, config.start_time.0);
    wire::put_u16(output, 56, (HEADER_SIZE + REPLY_FIXED) as u16);
    wire::put_u16(output, 58, token as u16);
    let mut length = REPLY_FIXED + token;
    let Some(contexts) = contexts.filter(|_| negotiated.dialect == Dialect::SMB_3_1_1) else {
        return Some(length);
    };
    // Contexts start 8-byte aligned from the SMB 2 header.
    let first = wire::align8(HEADER_SIZE + length) - HEADER_SIZE;
    let mut count = 0u16;
    let mut salt = [0; SALT];
    backend.random_bytes(&mut salt);
    let mut preauth = [0u8; 6 + SALT];
    wire::put_u16(&mut preauth, 0, 1);
    wire::put_u16(&mut preauth, 2, SALT as u16);
    wire::put_u16(&mut preauth, 4, HashAlgorithm::SHA_512.0);
    preauth[6..].copy_from_slice(&salt);
    length = append_context(
        output,
        first,
        ContextType::PREAUTH_INTEGRITY_CAPABILITIES,
        &preauth,
    )?;
    count += 1;
    if let Some(cipher) = contexts.encryption {
        let mut data = [0u8; 4];
        wire::put_u16(&mut data, 0, 1);
        wire::put_u16(&mut data, 2, cipher.map_or(0, Cipher::wire));
        length = append_context(
            output,
            wire::align8(HEADER_SIZE + length) - HEADER_SIZE,
            ContextType::ENCRYPTION_CAPABILITIES,
            &data,
        )?;
        count += 1;
    }
    if contexts.signing.is_some() {
        let mut data = [0u8; 4];
        wire::put_u16(&mut data, 0, 1);
        wire::put_u16(&mut data, 2, negotiated.signing.wire());
        length = append_context(
            output,
            wire::align8(HEADER_SIZE + length) - HEADER_SIZE,
            ContextType::SIGNING_CAPABILITIES,
            &data,
        )?;
        count += 1;
    }
    output[REPLY_FIXED + token..first].fill(0);
    wire::put_u16(output, 6, count);
    wire::put_u32(output, 60, (HEADER_SIZE + first) as u32);
    Some(length)
}

/// Write a negotiate context at `start`; returns its end.
fn append_context(
    output: &mut [u8],
    start: usize,
    kind: ContextType,
    data: &[u8],
) -> Option<usize> {
    let end = start + 8 + data.len();
    let context = output.get_mut(start..end)?;
    context.fill(0);
    wire::put_u16(context, 0, kind.0);
    wire::put_u16(context, 2, data.len() as u16);
    context[8..].copy_from_slice(data);
    Some(end)
}
