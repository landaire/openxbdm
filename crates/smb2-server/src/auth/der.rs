//! The subset of ASN.1 DER that SPNEGO uses: single-byte tags with
//! definite lengths.

/// Identifier octet of an element.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct Tag(pub u8);

impl Tag {
    pub const OCTET_STRING: Self = Self(0x04);
    pub const OID: Self = Self(0x06);
    pub const ENUMERATED: Self = Self(0x0a);
    pub const SEQUENCE: Self = Self(0x30);
    pub const APPLICATION_0: Self = Self(0x60);

    /// Constructed context-specific tag `[number]`.
    pub const fn context(number: u8) -> Self {
        Self(0xa0 | number)
    }
}

/// One tag-length-value element.
#[derive(Clone, Copy)]
pub(super) struct Element<'a> {
    pub tag: Tag,
    pub content: &'a [u8],
    /// The whole element, header included.
    pub encoding: &'a [u8],
}

/// Reads consecutive elements.
pub(super) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(super) const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Next element; `None` when the input is empty or malformed.
    pub(super) fn read(&mut self) -> Option<Element<'a>> {
        let (&tag, rest) = self.data.split_first()?;
        let tag = Tag(tag);

        let (&first, mut rest) = rest.split_first()?;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return None;
            }

            let (bytes, after) = rest.split_at_checked(count)?;
            rest = after;

            bytes.iter().try_fold(0usize, |length, &byte| {
                length.checked_mul(256)?.checked_add(usize::from(byte))
            })?
        };

        let content = rest.get(..length)?;
        let total = self.data.len() - rest.len() + length;
        let encoding = &self.data[..total];
        self.data = &self.data[total..];

        Some(Element {
            tag,
            content,
            encoding,
        })
    }

    /// Content of the next element, which must have `tag`.
    pub(super) fn expect(&mut self, tag: Tag) -> Option<&'a [u8]> {
        self.read()
            .filter(|element| element.tag == tag)
            .map(|element| element.content)
    }
}

/// Appends to a byte buffer; every method returns `None` when the buffer
/// is full.
pub(super) struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    pub(super) fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    pub(super) const fn position(&self) -> usize {
        self.position
    }

    pub(super) fn bytes(&mut self, data: &[u8]) -> Option<()> {
        let end = self.position.checked_add(data.len())?;
        self.output
            .get_mut(self.position..end)?
            .copy_from_slice(data);
        self.position = end;

        Some(())
    }

    pub(super) fn u16(&mut self, value: u16) -> Option<()> {
        self.bytes(&value.to_le_bytes())
    }

    pub(super) fn u32(&mut self, value: u32) -> Option<()> {
        self.bytes(&value.to_le_bytes())
    }

    /// Tag and length of an element whose content follows.
    pub(super) fn header(&mut self, tag: Tag, length: usize) -> Option<()> {
        self.bytes(&[tag.0])?;

        let size = length_size(length);
        if size == 1 {
            return self.bytes(&[length as u8]);
        }

        self.bytes(&[0x80 | (size - 1) as u8])?;
        let encoded = (length as u32).to_be_bytes();
        self.bytes(&encoded[encoded.len() - (size - 1)..])
    }

    /// A whole element.
    pub(super) fn element(&mut self, tag: Tag, content: &[u8]) -> Option<()> {
        self.header(tag, content.len())?;

        self.bytes(content)
    }
}

/// Bytes the encoding of an element with `content` bytes occupies.
pub(super) const fn encoded_length(content: usize) -> usize {
    1 + length_size(content) + content
}

const fn length_size(length: usize) -> usize {
    if length < 0x80 {
        1
    } else if length <= 0xff {
        2
    } else if length <= 0xffff {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use super::Tag;
    use super::Writer;
    use super::encoded_length;

    #[test]
    fn long_form_lengths_round_trip() {
        let content = [0x5a; 300];
        let mut buffer = [0u8; 310];
        let mut writer = Writer::new(&mut buffer);
        writer.element(Tag::OCTET_STRING, &content).unwrap();
        let written = writer.position();
        assert_eq!(written, encoded_length(300));
        assert_eq!(buffer[..4], [0x04, 0x82, 0x01, 0x2c]);
        let element = Reader::new(&buffer[..written]).read().unwrap();
        assert_eq!(element.tag, Tag::OCTET_STRING);
        assert_eq!(element.content, &content[..]);
        assert_eq!(element.encoding.len(), written);
    }

    #[test]
    fn rejects_truncated_and_indefinite_lengths() {
        assert!(Reader::new(&[0x30, 0x03, 0x01]).read().is_none());
        assert!(Reader::new(&[0x30, 0x80, 0x00, 0x00]).read().is_none());
        assert!(Reader::new(&[0x30, 0x82, 0x01]).read().is_none());
        assert!(Reader::new(&[0x30]).read().is_none());
    }
}
