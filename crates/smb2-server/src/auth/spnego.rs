//! SPNEGO tokens (RFC 4178) as an acceptor sees them.

use super::der::Reader;
use super::der::Tag;
use super::der::Writer;
use super::der::encoded_length;

/// Content octets of OID 1.3.6.1.5.5.2.
const SPNEGO_OID: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Content octets of OID 1.3.6.1.4.1.311.2.2.10.
const NTLMSSP_OID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// NegotiationToken choices.
const NEG_TOKEN_INIT: Tag = Tag::context(0);
const NEG_TOKEN_RESP: Tag = Tag::context(1);
/// NegTokenInit fields.
const MECH_TYPES: Tag = Tag::context(0);
const MECH_TOKEN: Tag = Tag::context(2);
/// NegTokenResp fields.
const NEG_STATE: Tag = Tag::context(0);
const SUPPORTED_MECH: Tag = Tag::context(1);
const RESPONSE_TOKEN: Tag = Tag::context(2);
/// Field of both NegTokenInit and NegTokenResp.
const MECH_LIST_MIC: Tag = Tag::context(3);

/// GSS initial context token offering NTLMSSP only.
pub(super) const NEGOTIATE_TOKEN: [u8; 30] = [
    Tag::APPLICATION_0.0,
    0x1c,
    Tag::OID.0,
    0x06,
    0x2b,
    0x06,
    0x01,
    0x05,
    0x05,
    0x02,
    NEG_TOKEN_INIT.0,
    0x12,
    Tag::SEQUENCE.0,
    0x10,
    MECH_TYPES.0,
    0x0e,
    Tag::SEQUENCE.0,
    0x0c,
    Tag::OID.0,
    0x0a,
    0x2b,
    0x06,
    0x01,
    0x04,
    0x01,
    0x82,
    0x37,
    0x02,
    0x02,
    0x0a,
];

/// Where NTLMSSP appears in the initiator's mechanism list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum NtlmPosition {
    First,
    Later,
    Absent,
}

/// The initiator's NegTokenInit.
pub(super) struct NegTokenInit<'a> {
    /// DER encoding of the MechTypeList, the input of mechListMIC.
    pub mech_types: &'a [u8],
    pub ntlm: NtlmPosition,
    pub mech_token: Option<&'a [u8]>,
}

/// A NegTokenResp from the initiator.
pub(super) struct NegTokenResp<'a> {
    pub state: Option<NegState>,
    pub response_token: Option<&'a [u8]>,
    pub mech_list_mic: Option<&'a [u8]>,
}

/// Parse an initial context token. `None` when malformed.
pub(super) fn parse_init(input: &[u8]) -> Option<NegTokenInit<'_>> {
    let mut token = Reader::new(Reader::new(input).expect(Tag::APPLICATION_0)?);
    if token.expect(Tag::OID)? != SPNEGO_OID {
        return None;
    }
    let choice = token.expect(NEG_TOKEN_INIT)?;
    let mut fields = Reader::new(Reader::new(choice).expect(Tag::SEQUENCE)?);
    let mut mech_types = None;
    let mut mech_token = None;
    while !fields.is_empty() {
        let field = fields.read()?;
        match field.tag {
            MECH_TYPES => mech_types = Some(Reader::new(field.content).read()?),
            MECH_TOKEN => mech_token = Some(Reader::new(field.content).expect(Tag::OCTET_STRING)?),
            _ => {}
        }
    }
    let mech_types = mech_types.filter(|list| list.tag == Tag::SEQUENCE)?;
    let mut ntlm = NtlmPosition::Absent;
    let mut mechanisms = Reader::new(mech_types.content);
    let mut first = true;
    while !mechanisms.is_empty() {
        let oid = mechanisms.expect(Tag::OID)?;
        if oid == NTLMSSP_OID && ntlm == NtlmPosition::Absent {
            ntlm = if first {
                NtlmPosition::First
            } else {
                NtlmPosition::Later
            };
        }
        first = false;
    }
    Some(NegTokenInit {
        mech_types: mech_types.encoding,
        ntlm,
        mech_token,
    })
}

/// Parse a NegTokenResp. `None` when malformed.
pub(super) fn parse_resp(input: &[u8]) -> Option<NegTokenResp<'_>> {
    let choice = Reader::new(input).expect(NEG_TOKEN_RESP)?;
    let mut fields = Reader::new(Reader::new(choice).expect(Tag::SEQUENCE)?);
    let mut response = NegTokenResp {
        state: None,
        response_token: None,
        mech_list_mic: None,
    };
    while !fields.is_empty() {
        let field = fields.read()?;
        match field.tag {
            NEG_STATE => {
                let value = Reader::new(field.content).expect(Tag::ENUMERATED)?;
                response.state = Some(NegState::from_wire(value)?);
            }
            RESPONSE_TOKEN => {
                response.response_token =
                    Some(Reader::new(field.content).expect(Tag::OCTET_STRING)?)
            }
            MECH_LIST_MIC => {
                response.mech_list_mic = Some(Reader::new(field.content).expect(Tag::OCTET_STRING)?)
            }
            _ => {}
        }
    }
    Some(response)
}

/// NegTokenResp negState values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum NegState {
    AcceptCompleted = 0,
    AcceptIncomplete = 1,
    Reject = 2,
    RequestMic = 3,
}

impl NegState {
    /// Content octets of the ENUMERATED; `None` for other values.
    fn from_wire(value: &[u8]) -> Option<Self> {
        match value {
            [0] => Some(Self::AcceptCompleted),
            [1] => Some(Self::AcceptIncomplete),
            [2] => Some(Self::Reject),
            [3] => Some(Self::RequestMic),
            _ => None,
        }
    }

    const fn wire(self) -> u8 {
        self as u8
    }
}

/// Fields of an outgoing NegTokenResp.
pub(super) struct Reply<'a> {
    pub state: NegState,
    pub supported_mech: bool,
    pub response_token: Option<&'a [u8]>,
    pub mech_list_mic: Option<&'a [u8]>,
}

const fn wrapped_octets(length: usize) -> usize {
    encoded_length(encoded_length(length))
}

/// Encode `reply`; returns its length, or `None` when `output` is too
/// small.
pub(super) fn write_resp(reply: &Reply<'_>, output: &mut [u8]) -> Option<usize> {
    let supported_mech = encoded_length(encoded_length(NTLMSSP_OID.len()));
    let fields = encoded_length(encoded_length(1))
        + if reply.supported_mech {
            supported_mech
        } else {
            0
        }
        + reply
            .response_token
            .map_or(0, |token| wrapped_octets(token.len()))
        + reply
            .mech_list_mic
            .map_or(0, |mic| wrapped_octets(mic.len()));
    let mut writer = Writer::new(output);
    writer.header(NEG_TOKEN_RESP, encoded_length(fields))?;
    writer.header(Tag::SEQUENCE, fields)?;
    writer.header(NEG_STATE, encoded_length(1))?;
    writer.element(Tag::ENUMERATED, &[reply.state.wire()])?;
    if reply.supported_mech {
        writer.header(SUPPORTED_MECH, encoded_length(NTLMSSP_OID.len()))?;
        writer.element(Tag::OID, &NTLMSSP_OID)?;
    }
    for (tag, octets) in [
        (RESPONSE_TOKEN, reply.response_token),
        (MECH_LIST_MIC, reply.mech_list_mic),
    ] {
        if let Some(octets) = octets {
            writer.header(tag, encoded_length(octets.len()))?;
            writer.element(Tag::OCTET_STRING, octets)?;
        }
    }
    Some(writer.position())
}

#[cfg(test)]
mod tests {
    use super::NEGOTIATE_TOKEN;
    use super::NegState;
    use super::NtlmPosition;
    use super::Reply;
    use super::parse_init;
    use super::write_resp;

    #[test]
    fn negotiate_token_parses_as_ntlm_only_init() {
        let init = parse_init(&NEGOTIATE_TOKEN).unwrap();
        assert_eq!(init.ntlm, NtlmPosition::First);
        assert!(init.mech_token.is_none());
        assert_eq!(init.mech_types, &NEGOTIATE_TOKEN[16..]);
    }

    #[test]
    fn kerberos_first_init_with_optimistic_token() {
        let token: &[u8] = &[
            0x60, 0x2f, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x25, 0x30, 0x23,
            0xa0, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02,
            0x02, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2,
            0x06, 0x04, 0x04, 0x6e, 0x82, 0x01, 0x00,
        ];
        let init = parse_init(token).unwrap();
        assert_eq!(init.ntlm, NtlmPosition::Later);
        assert_eq!(init.mech_token, Some(&[0x6e, 0x82, 0x01, 0x00][..]));
        assert_eq!(init.mech_types, &token[16..41]);
    }

    #[test]
    fn accept_incomplete_without_token() {
        let mut output = [0u8; 64];
        let length = write_resp(
            &Reply {
                state: NegState::AcceptIncomplete,
                supported_mech: true,
                response_token: None,
                mech_list_mic: None,
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(
            output[..length],
            [
                0xa1, 0x15, 0x30, 0x13, 0xa0, 0x03, 0x0a, 0x01, 0x01, 0xa1, 0x0c, 0x06, 0x0a, 0x2b,
                0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a
            ]
        );
    }
}
