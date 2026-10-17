//! Connection-oriented DCE/RPC PDUs (C706 chapter 12, MS-RPCE 2.2.2).

use super::PduError;
use super::ndr::Writer;

/// Common header of every PDU.
pub(super) const COMMON_HEADER_LENGTH: usize = 16;
/// Header of request and response PDUs.
pub(super) const CALL_HEADER_LENGTH: usize = 24;
/// Fixed part of a bind or alter_context body: max_xmit_frag,
/// max_recv_frag, assoc_group_id, n_context_elem and reserved bytes.
pub(super) const BIND_BODY_LENGTH: usize = 12;
/// Size of a syntax identifier: UUID and 32-bit version.
const SYNTAX_LENGTH: usize = 20;
/// NDR transfer syntax 8a885d04-1ceb-11c9-9fe8-08002b104860 version 2.
const NDR_SYNTAX: [u8; SYNTAX_LENGTH] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00,
];

/// Protocol version of a PDU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RpcVersion {
    pub major: u8,
    pub minor: u8,
}

impl RpcVersion {
    const V5_0: Self = Self { major: 5, minor: 0 };

    /// Versions 5.0 and 5.1.
    const fn supported(self) -> bool {
        self.major == Self::V5_0.major && self.minor <= 1
    }
}

/// First data representation byte: integer and character formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataFormat(pub u8);

impl DataFormat {
    /// Little-endian integers, ASCII characters.
    const LITTLE_ENDIAN_ASCII: Self = Self(0x10);
}

/// pfc_flags of a PDU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PduFlags(pub u8);

impl PduFlags {
    pub const NONE: Self = Self(0);
    pub const FIRST_FRAGMENT: Self = Self(0x01);
    pub const LAST_FRAGMENT: Self = Self(0x02);
    const DID_NOT_EXECUTE: Self = Self(0x20);
    pub const MAYBE: Self = Self(0x40);
    const OBJECT_UUID: Self = Self(0x80);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Association group identifier of a bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AssociationGroup(pub u32);

/// Features offered in a bind time feature negotiation acknowledgement
/// (MS-RPCE 2.2.2.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BindTimeFeatures(u16);

impl BindTimeFeatures {
    const NONE: Self = Self(0);
}

/// ptype of a PDU header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketType(pub u8);

impl PacketType {
    pub const REQUEST: Self = Self(0);
    const RESPONSE: Self = Self(2);
    const FAULT: Self = Self(3);
    pub const BIND: Self = Self(11);
    const BIND_ACK: Self = Self(12);
    const BIND_NAK: Self = Self(13);
    pub const ALTER_CONTEXT: Self = Self(14);
    const ALTER_CONTEXT_RESPONSE: Self = Self(15);
    pub const AUTH3: Self = Self(16);
    pub const CO_CANCEL: Self = Self(18);
    pub const ORPHANED: Self = Self(19);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallId(pub u32);

/// Presentation context identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ContextId(pub u16);

/// Status of a fault PDU (C706 appendix E, MS-RPCE 2.2.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FaultStatus(pub u32);

impl FaultStatus {
    /// nca_s_op_rng_error: the operation number is not in the interface.
    pub const OPERATION_RANGE: Self = Self(0x1c01_0002);
    /// nca_s_unk_if: the presentation context was not accepted.
    pub const UNKNOWN_INTERFACE: Self = Self(0x1c01_0003);
    /// nca_s_proto_error.
    pub const PROTOCOL_ERROR: Self = Self(0x1c01_000b);
    /// nca_s_fault_invalid_tag: a union discriminant has no arm.
    pub const INVALID_TAG: Self = Self(0x1c00_0006);
    /// nca_s_fault_remote_no_memory: the request stub exceeds the buffer.
    pub const REMOTE_NO_MEMORY: Self = Self(0x1c00_001b);
    /// nca_s_fault_ndr: the stub data is malformed.
    pub const NDR: Self = Self(0x0000_06f7);
}

/// provider_reject_reason of a bind_nak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RejectReason(pub u16);

impl RejectReason {
    pub const NOT_SPECIFIED: Self = Self(0);
    pub const LOCAL_LIMIT_EXCEEDED: Self = Self(2);
    /// MS-RPCE extension: the bind carries an auth verifier.
    pub const AUTHENTICATION_TYPE_NOT_RECOGNIZED: Self = Self(8);
}

/// Outcome of one presentation context of a bind or alter_context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ContextResult {
    Accepted,
    /// Bind time feature negotiation (MS-RPCE 3.3.1.5.3).
    NegotiateAck,
    AbstractSyntaxNotSupported,
    TransferSyntaxesNotSupported,
    LocalLimitExceeded,
}

impl ContextResult {
    /// Evaluate a context element's abstract syntax and transfer syntaxes.
    pub fn evaluate(abstract_syntax: &[u8], transfer_syntaxes: &[u8]) -> Self {
        /// srvsvc interface 4b324fc8-1670-01d3-1278-5a47bf6ee188 version 3.0.
        const SRVSVC_SYNTAX: [u8; SYNTAX_LENGTH] = [
            0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e,
            0xe1, 0x88, 0x03, 0x00, 0x00, 0x00,
        ];
        /// First eight UUID bytes of the bind time feature negotiation syntax
        /// 6cb71c2c-9812-4540-xxxx-xxxxxxxxxxxx; the rest carries the client's
        /// feature bits.
        const BIND_TIME_FEATURE_PREFIX: [u8; 8] = [0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45];

        let mut ndr = false;
        let mut negotiate = false;
        for syntax in transfer_syntaxes.as_chunks::<SYNTAX_LENGTH>().0 {
            ndr |= *syntax == NDR_SYNTAX;
            negotiate |= syntax[..BIND_TIME_FEATURE_PREFIX.len()] == BIND_TIME_FEATURE_PREFIX;
        }

        let srvsvc = abstract_syntax == SRVSVC_SYNTAX;
        if srvsvc && ndr {
            Self::Accepted
        } else if negotiate {
            Self::NegotiateAck
        } else if srvsvc {
            Self::TransferSyntaxesNotSupported
        } else {
            Self::AbstractSyntaxNotSupported
        }
    }

    /// Write the p_result_t: result, reason, and transfer syntax.
    fn put(self, writer: &mut Writer<'_>) {
        let (result, reason) = match self {
            Self::Accepted => (0, 0),
            Self::NegotiateAck => (3, BindTimeFeatures::NONE.0),
            Self::AbstractSyntaxNotSupported => (2, 1),
            Self::TransferSyntaxesNotSupported => (2, 2),
            Self::LocalLimitExceeded => (2, 3),
        };
        writer.u16(result);
        writer.u16(reason);

        if self == Self::Accepted {
            writer.bytes(&NDR_SYNTAX);
        } else {
            writer.bytes(&[0; SYNTAX_LENGTH]);
        }
    }
}

/// The common header of a received fragment.
#[derive(Debug, Clone, Copy)]
pub(super) struct FragmentHeader {
    pub packet_type: PacketType,
    pub flags: PduFlags,
    pub length: usize,
    auth_length: usize,
    pub call_id: CallId,
}

impl FragmentHeader {
    pub fn parse(head: &[u8; CALL_HEADER_LENGTH]) -> Self {
        Self {
            packet_type: PacketType(head[2]),
            flags: PduFlags(head[3]),
            length: usize::from(u16::from_le_bytes([head[8], head[9]])),
            auth_length: usize::from(u16::from_le_bytes([head[10], head[11]])),
            call_id: CallId(u32::from_le_bytes([head[12], head[13], head[14], head[15]])),
        }
    }

    /// Check the version, data representation, packet type, and length of
    /// the common header in `head`, which this header was parsed from.
    pub fn validate(&self, head: &[u8; CALL_HEADER_LENGTH]) -> Result<(), PduError> {
        let version = RpcVersion {
            major: head[0],
            minor: head[1],
        };
        if !version.supported() {
            return Err(PduError::UnsupportedVersion { version });
        }

        let format = DataFormat(head[4]);
        if format != DataFormat::LITTLE_ENDIAN_ASCII {
            return Err(PduError::UnsupportedDataRepresentation { format });
        }

        let packet_type = self.packet_type;
        let minimum = self
            .minimum_length()
            .ok_or(PduError::UnexpectedType { packet_type })?;

        if self.length < minimum {
            return Err(PduError::FragmentTooShort {
                packet_type,
                length: self.length as u32,
                minimum: minimum as u32,
            });
        }

        Ok(())
    }

    pub fn has_auth(&self) -> bool {
        self.auth_length != 0
    }

    /// Bytes of the header the receiver collects before the body.
    pub fn head_length(&self) -> usize {
        if self.packet_type == PacketType::REQUEST {
            CALL_HEADER_LENGTH
        } else {
            COMMON_HEADER_LENGTH
        }
    }

    /// Bytes from the start of the fragment to the stub or body.
    fn body_start(&self) -> Option<usize> {
        match self.packet_type {
            PacketType::REQUEST if self.flags.contains(PduFlags::OBJECT_UUID) => {
                Some(CALL_HEADER_LENGTH + 16)
            }
            PacketType::REQUEST => Some(CALL_HEADER_LENGTH),
            PacketType::BIND | PacketType::ALTER_CONTEXT => Some(COMMON_HEADER_LENGTH),
            _ => None,
        }
    }

    /// Smallest valid fragment length of this type, or `None` for types a
    /// client does not send.
    fn minimum_length(&self) -> Option<usize> {
        let fixed = match self.packet_type {
            PacketType::BIND | PacketType::ALTER_CONTEXT => COMMON_HEADER_LENGTH + BIND_BODY_LENGTH,
            PacketType::REQUEST => self.body_start()?,
            PacketType::AUTH3 | PacketType::CO_CANCEL | PacketType::ORPHANED => {
                COMMON_HEADER_LENGTH
            }
            _ => return None,
        };

        // An auth verifier is preceded by an 8-byte sec_trailer.
        let auth = if self.has_auth() {
            8 + self.auth_length
        } else {
            0
        };

        Some(fixed + auth)
    }

    /// Byte range of the fragment holding the stub or bind body.
    pub fn body(&self) -> Option<(usize, usize)> {
        let auth = if self.has_auth() {
            8 + self.auth_length
        } else {
            0
        };

        Some((self.body_start()?, self.length.checked_sub(auth)?))
    }
}

/// Fixed fields of a bind or alter_context body.
#[derive(Debug, Clone, Copy)]
pub(super) struct BindRequest {
    pub max_transmit: u16,
    pub max_receive: u16,
    /// `None` when the bind does not name a group (assoc_group_id 0).
    pub group: Option<AssociationGroup>,
    pub context_count: usize,
}

impl BindRequest {
    pub fn parse(body: &[u8]) -> Option<Self> {
        let fixed = body.get(..BIND_BODY_LENGTH)?;

        Some(Self {
            max_transmit: u16::from_le_bytes([fixed[0], fixed[1]]),
            max_receive: u16::from_le_bytes([fixed[2], fixed[3]]),
            group: match u32::from_le_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]) {
                0 => None,
                group => Some(AssociationGroup(group)),
            },
            context_count: usize::from(fixed[8]),
        })
    }
}

/// One p_cont_elem_t of a bind body.
pub(super) struct ContextElement<'a> {
    pub id: ContextId,
    pub abstract_syntax: &'a [u8],
    pub transfer_syntaxes: &'a [u8],
}

impl<'a> ContextElement<'a> {
    /// Parse the element at `cursor` and advance it past the element.
    pub fn parse(body: &'a [u8], cursor: &mut usize) -> Option<Self> {
        let fixed_end = cursor.checked_add(4 + SYNTAX_LENGTH)?;
        let fixed = body.get(*cursor..fixed_end)?;
        let count = usize::from(fixed[2]);
        let end = fixed_end + count * SYNTAX_LENGTH;
        let transfer_syntaxes = body.get(fixed_end..end)?;
        *cursor = end;

        Some(Self {
            id: ContextId(u16::from_le_bytes([fixed[0], fixed[1]])),
            abstract_syntax: &fixed[4..],
            transfer_syntaxes,
        })
    }
}

/// Negotiated fragment sizes and association group.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// Largest fragment the server sends.
    pub transmit: u16,
    /// Largest fragment the server accepts.
    pub receive: u16,
    pub group: AssociationGroup,
}

impl Limits {
    /// Limits for a bind; `None` when the client cannot receive a fragment
    /// with stub data.
    pub fn negotiate(request: &BindRequest) -> Option<Self> {
        /// Smallest fragment the server sends: a response header and one 8-byte
        /// unit of stub data.
        const MINIMUM_FRAGMENT: u16 = (CALL_HEADER_LENGTH + 8) as u16;
        /// Largest fragment the server negotiates, the Windows default.
        const MAXIMUM_FRAGMENT: u16 = 4280;
        /// Association group of a bind that does not name one.
        const ASSOCIATION_GROUP: AssociationGroup = AssociationGroup(0x0000_1000);

        if request.max_receive < MINIMUM_FRAGMENT {
            return None;
        }

        Some(Self {
            transmit: request.max_receive.min(MAXIMUM_FRAGMENT),
            receive: request.max_transmit.min(MAXIMUM_FRAGMENT),
            group: request.group.unwrap_or(ASSOCIATION_GROUP),
        })
    }
}

/// A bind_ack, or an alter_context_resp when `alter`.
pub(super) fn put_bind_ack(
    writer: &mut Writer<'_>,
    fragment_length: usize,
    call_id: CallId,
    alter: bool,
    limits: &Limits,
    results: &[ContextResult],
) {
    /// Secondary address of the bind_ack, a NUL-terminated port name.
    const SECONDARY_ADDRESS: &[u8] = b"\\PIPE\\srvsvc\0";

    let packet_type = if alter {
        PacketType::ALTER_CONTEXT_RESPONSE
    } else {
        PacketType::BIND_ACK
    };

    put_header(
        writer,
        packet_type,
        PduFlags::FIRST_FRAGMENT.union(PduFlags::LAST_FRAGMENT),
        fragment_length,
        call_id,
    );

    writer.u16(limits.transmit);
    writer.u16(limits.receive);
    writer.u32(limits.group.0);

    let address: &[u8] = if alter { &[] } else { SECONDARY_ADDRESS };
    writer.u16(address.len() as u16);
    writer.bytes(address);
    writer.align(4);

    writer.u8(results.len() as u8);
    writer.u8(0);
    writer.u16(0);

    for &result in results {
        result.put(writer);
    }
}

pub(super) fn put_bind_nak(
    writer: &mut Writer<'_>,
    fragment_length: usize,
    call_id: CallId,
    reason: RejectReason,
) {
    put_header(
        writer,
        PacketType::BIND_NAK,
        PduFlags::FIRST_FRAGMENT.union(PduFlags::LAST_FRAGMENT),
        fragment_length,
        call_id,
    );

    writer.u16(reason.0);
    // p_rt_versions_supported_t: one protocol version, 5.0.
    writer.u8(1);
    writer.u8(RpcVersion::V5_0.major);
    writer.u8(RpcVersion::V5_0.minor);
    writer.align(4);
}

pub(super) fn put_fault(
    writer: &mut Writer<'_>,
    fragment_length: usize,
    call_id: CallId,
    context: ContextId,
    status: FaultStatus,
) {
    // The server's operations have no side effects, so no faulted call has
    // executed.
    put_header(
        writer,
        PacketType::FAULT,
        PduFlags::FIRST_FRAGMENT
            .union(PduFlags::LAST_FRAGMENT)
            .union(PduFlags::DID_NOT_EXECUTE),
        fragment_length,
        call_id,
    );

    writer.u32(0);
    writer.u16(context.0);
    writer.u8(0);
    writer.u8(0);
    writer.u32(status.0);
    writer.u32(0);
}

pub(super) fn put_response_header(
    writer: &mut Writer<'_>,
    flags: PduFlags,
    fragment_length: usize,
    call_id: CallId,
    allocation_hint: u32,
    context: ContextId,
) {
    put_header(
        writer,
        PacketType::RESPONSE,
        flags,
        fragment_length,
        call_id,
    );

    writer.u32(allocation_hint);
    writer.u16(context.0);
    writer.u8(0);
    writer.u8(0);
}

fn put_header(
    writer: &mut Writer<'_>,
    packet_type: PacketType,
    flags: PduFlags,
    fragment_length: usize,
    call_id: CallId,
) {
    /// Remaining data representation bytes: IEEE floating point, reserved.
    const DATA_REPRESENTATION_TAIL: [u8; 3] = [0, 0, 0];

    writer.u8(RpcVersion::V5_0.major);
    writer.u8(RpcVersion::V5_0.minor);
    writer.u8(packet_type.0);
    writer.u8(flags.0);
    writer.u8(DataFormat::LITTLE_ENDIAN_ASCII.0);
    writer.bytes(&DATA_REPRESENTATION_TAIL);
    writer.u16(fragment_length as u16);
    writer.u16(0);
    writer.u32(call_id.0);
}
