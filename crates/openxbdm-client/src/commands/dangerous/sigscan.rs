//! Generic primitives for paginated xbdm memory reads + byte scans.

use crate::client::Client;
use crate::client::Connected;
use crate::commands::memory::GetMem;
use crate::error::Error;
use futures_util::io::AsyncRead;
use futures_util::io::AsyncWrite;

/// `getmem` chunk size. xbdm on Xenon cleanly serves 0x10000-byte reads
/// in a single response; larger requests split into additional response
/// lines which we'd rather not rely on.
pub const CHUNK: u32 = 0x10000;

/// Read `length` bytes starting at `address` from console memory,
/// paginating across `getmem` as needed. Unmapped pages inside the
/// requested range are returned as 0x00 (xbdm's `??` markers are
/// already decoded to zeros by our `GetMem` parser).
pub async fn read<T>(
    client: &mut Client<T, Connected>,
    address: u32,
    length: u32,
) -> Result<Vec<u8>, rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(length as usize);
    let mut cursor = 0u32;
    while cursor < length {
        let take = core::cmp::min(CHUNK, length - cursor);
        let snap = client
            .run(GetMem {
                address: address.wrapping_add(cursor),
                length: take,
            })
            .await?;
        out.extend_from_slice(&snap.data);
        cursor = cursor.wrapping_add(take);
    }
    Ok(out)
}

/// Read a u32 (big-endian, native for PowerPC) at `address`.
pub async fn read_u32_be<T>(
    client: &mut Client<T, Connected>,
    address: u32,
) -> Result<u32, rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = read(client, address, 4).await?;
    Ok(u32::from_be_bytes(
        bytes.try_into().expect("asked for 4 bytes"),
    ))
}

/// Write a u32 big-endian at `address` via `setmem`.
pub async fn write_u32_be<T>(
    client: &mut Client<T, Connected>,
    address: u32,
    value: u32,
) -> Result<(), rootcause::Report<Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    use crate::commands::memory::SetMem;
    client
        .run(SetMem {
            address,
            data: value.to_be_bytes().to_vec(),
        })
        .await?;
    Ok(())
}

/// Search `haystack` for the first occurrence of a null-terminated
/// C-style ASCII string `needle` on a 1-byte alignment. Returns the
/// byte offset into `haystack`, not a console address; caller adds the
/// search base. The null terminator is included in the match to avoid
/// substring false positives.
pub fn find_cstr(haystack: &[u8], needle: &str) -> Option<usize> {
    let mut pat = Vec::with_capacity(needle.len() + 1);
    pat.extend_from_slice(needle.as_bytes());
    pat.push(0);
    find_bytes(haystack, &pat, 1)
}

/// Search `haystack` for `needle`, stepping by `align` bytes at a time
/// (1 for arbitrary bytes, 4 for PPC-aligned instructions, etc.).
pub fn find_bytes(haystack: &[u8], needle: &[u8], align: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let last = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if haystack[i..i + needle.len()] == *needle {
            return Some(i);
        }
        i += align;
    }
    None
}

/// Iterate over every `align`-aligned occurrence of `needle` in
/// `haystack`. Useful for scanning dispatch tables where the target
/// pointer may appear many times.
pub fn find_bytes_all(haystack: &[u8], needle: &[u8], align: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > haystack.len() {
        return out;
    }
    let last = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if haystack[i..i + needle.len()] == *needle {
            out.push(i);
        }
        i += align;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_cstr_matches_exact_with_terminator() {
        let data = b"\x00altaddr\x00drivemap\x00";
        assert_eq!(find_cstr(data, "altaddr"), Some(1));
        assert_eq!(find_cstr(data, "drivemap"), Some(9));
        // Substring without the terminator shouldn't match.
        assert_eq!(find_cstr(data, "alta"), None);
    }

    #[test]
    fn find_bytes_respects_alignment() {
        let data = [0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        assert_eq!(find_bytes(&data, &[0xDE, 0xAD], 1), Some(1));
        // With alignment 2, the match at offset 1 is skipped.
        assert_eq!(find_bytes(&data, &[0xDE, 0xAD], 2), None);
    }

    #[test]
    fn find_bytes_all_collects_repeated_hits() {
        let data = b"abcabcabc";
        assert_eq!(find_bytes_all(data, b"abc", 1), vec![0, 3, 6]);
    }
}
