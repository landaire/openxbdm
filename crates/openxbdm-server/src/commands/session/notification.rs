//! Rules of notification texts and processor names (stock dmnotify).

/// Length of the kind in front of the `!` of a notification text (stock
/// export 36, 0x91f3b070). `None` when a space, a control character, or a
/// byte of 0x80 and above (a negative `char`) comes first.
pub fn notification_kind_length(text: &[u8]) -> Option<usize> {
    for (index, &byte) in text.iter().enumerate() {
        match byte {
            b'!' => return Some(index),
            _ if (byte as i8) <= 0x20 => return None,
            _ => {}
        }
    }
    None
}

/// The monitor's bounded case-insensitive name compare (stock 0x91f41148)
/// over NUL-terminated `first` and `second`; the end of a slice reads as
/// NUL. After `count` equal characters `first` must end as well, so a
/// zero result means `first` has at most `count` characters.
pub fn compare_names(first: &[u8], second: &[u8], count: usize) -> i32 {
    let at = |text: &[u8], index: usize| -> i8 { text.get(index).copied().unwrap_or(0) as i8 };
    let upper = |byte: i8| -> i32 {
        if (0x61..=0x7a).contains(&byte) {
            i32::from(byte - 0x20)
        } else {
            i32::from(byte)
        }
    };
    let mut index = 0;
    while index < count {
        let byte = at(first, index);
        if byte == 0 {
            return -i32::from(at(second, index));
        }
        let (left, right) = (upper(byte), upper(at(second, index)));
        if left != right {
            return left - right;
        }
        index += 1;
    }
    match at(first, index) {
        0 => 0,
        byte => i32::from(byte),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_needs_a_bang_before_any_separator() {
        assert_eq!(notification_kind_length(b"XBDMFE!Start 0x1"), Some(6));
        assert_eq!(notification_kind_length(b"!x"), Some(0));
        assert_eq!(notification_kind_length(b"no kind!"), None);
        assert_eq!(notification_kind_length(b"tab\t!"), None);
        assert_eq!(notification_kind_length(b"caf\xe9!"), None);
        assert_eq!(notification_kind_length(b"none"), None);
    }

    #[test]
    fn compare_requires_the_first_name_to_end_after_count() {
        assert_eq!(compare_names(b"xbdmfe", b"XBDMFE", 6), 0);
        // Export 36 passes the text first, which continues with `!`.
        assert_ne!(compare_names(b"XBDMFE!Start", b"XBDMFE", 6), 0);
        assert_ne!(compare_names(b"XBDMFE!Start", b"XBDMFE!Start", 6), 0);
        assert_eq!(compare_names(b"ab", b"AB", 5), 0);
        assert_ne!(compare_names(b"ab", b"abc", 5), 0);
        assert_eq!(compare_names(b"", b"", 0), 0);
        assert_ne!(compare_names(b"a", b"", 0), 0);
    }

    #[test]
    fn processor_removal_matches_whole_names_ignoring_case() {
        // Export 32 compares each processor name with the given name over
        // the given name's length.
        let matches =
            |processor: &[u8], name: &[u8]| compare_names(processor, name, name.len()) == 0;
        assert!(matches(b"XBDMFE", b"xbdmfe"));
        assert!(!matches(b"XBDMFE", b"XBDM"));
        assert!(!matches(b"XBDMFE", b"XBDMFE2"));
        assert!(matches(b"", b""));
        assert!(!matches(b"\xe9", b"\xc9"));
    }
}
