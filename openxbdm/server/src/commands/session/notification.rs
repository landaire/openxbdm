//! Notification channels and targets: `notify`, `notifyport`, and `notifyat`,
//! and the rules of notification texts and processor names (stock dmnotify).

use core::fmt::Write as _;

use crate::backend::Backend as AnyBackend;
use crate::commands::system;
use crate::commands::system::SettingsFile;
use crate::invocation::Invocation;
use crate::invocation::SessionRequest;
use crate::network::Endpoint;
use crate::network::Ipv4Address;
use crate::network::Network;
use crate::network::SocketId;
use crate::network::send_line;
use crate::notify::ExecutionState;
use crate::notify::MAX_NOTIFICATION_TARGETS;
use crate::notify::TargetFlags;
use crate::reply::CommandError;
use crate::reply::CommandResult;
use crate::reply::Reply;
use crate::state::ServerState;
use crate::text::Text;

/// Length of the kind in front of the `!` of a notification text (stock
/// export 36, 0x91f3b070). `None` when a space, a control character, or a
/// byte of 0x80 and above (a negative `char`) comes first.
pub fn notification_kind_length(text: &[u8]) -> Option<usize> {
    for (index, &byte) in text.iter().enumerate() {
        match byte {
            b'!' => return Some(index),
            _ if (byte as i8) <= 0x20 => return None,
            // Any other byte belongs to the kind.
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

/// Send the notification texts other threads have posted, in order.
pub fn send_posted_notifications(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    let notifications = &mut state.notifications;
    while backend.send_next_posted_notification(&mut |text| {
        notifications.send_text(text, network);
    }) {}
}

/// `notify` and `notifyport [reconnectport=<dword>] [debug] [reverse]`:
/// turn the connection into a notification channel. The channel receives
/// `205- now a notification channel` and the execution state line; no
/// status line follows.
pub(super) fn notify(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(socket) = invocation
        .session
        .as_deref()
        .map(|session| session.socket())
    else {
        return Err(CommandError::Fail);
    };

    let (endpoint, persist) = match invocation.line.dword("reconnectport") {
        None => (
            Endpoint {
                address: Ipv4Address::UNSPECIFIED,
                port: 0,
            },
            false,
        ),
        Some(port) => match invocation.network.peer(socket) {
            // The monitor ends the command without any reply.
            Err(_) => return Ok(Reply::Sent),
            Ok(peer) => (
                Endpoint {
                    address: peer.address,
                    port: port as u16,
                },
                port != 0,
            ),
        },
    };

    let flags = target_flags(invocation);
    let execution = invocation.backend.execution_state();
    let notifications = &mut invocation.state.notifications;
    let registered = if endpoint.port == 0 {
        notifications
            .attach_socket(socket, None, invocation.network)
            .is_some()
    } else {
        notifications.register_target(
            endpoint,
            flags,
            false,
            Some(socket),
            execution,
            invocation.network,
        )
    };

    let announced = registered
        && send_line(
            invocation.network,
            socket,
            b"205- now a notification channel",
        )
        .is_ok()
        && send_execution_line(invocation.network, socket, execution);
    if !announced {
        // The socket stays with the connection, so the channel must not
        // keep it.
        if registered {
            invocation.state.notifications.detach_socket(socket);
        }

        invocation.text.set_bytes(b"notification limit exceeded");
        return Err(CommandError::Fail);
    }

    if let Some(session) = invocation.session.as_deref_mut() {
        session.request(SessionRequest::ReleaseSocket);
    }

    if persist {
        invocation.state.settings_dirty = true;
    }

    Ok(Reply::Sent)
}

fn send_execution_line(
    network: &mut dyn Network,
    socket: SocketId,
    execution: ExecutionState,
) -> bool {
    let mut line = Text::<0x20>::new();
    let _ = write!(line, "execution {}", execution.name());

    send_line(network, socket, line.as_bytes()).is_ok()
}

fn target_flags(invocation: &Invocation<'_>) -> TargetFlags {
    let mut flags = TargetFlags::empty();
    if invocation.line.has("debug") {
        flags = flags.union(TargetFlags::DEBUG);
    }

    if invocation.line.has("reverse") {
        flags = flags.union(TargetFlags::REVERSE);
    }

    flags
}

/// `notifyat port=<dword> [addr=<a.b.c.d>] [drop] [debug] [reverse]`:
/// register a notification target (connected now unless `reverse`) or
/// drop every target with the endpoint.
pub(super) fn notify_at(invocation: &mut Invocation<'_>) -> CommandResult {
    let Some(socket) = invocation
        .session
        .as_deref()
        .map(|session| session.socket())
    else {
        return Err(CommandError::Fail);
    };

    if !register_from_line(invocation, Some(socket), false) {
        return Err(CommandError::Fail);
    }

    invocation.state.settings_dirty = true;

    Ok(Reply::Ok)
}

/// A settings-file `notifyat` line: the target is recorded without a
/// connection and `addr=` is required.
pub(crate) fn ini_notifyat(invocation: &mut Invocation<'_>) {
    register_from_line(invocation, None, true);
}

/// The `notifyat` worker. `socket` supplies the default address.
fn register_from_line(
    invocation: &mut Invocation<'_>,
    socket: Option<SocketId>,
    reverse: bool,
) -> bool {
    /// Buffer the monitor copies `addr=` into.
    const ADDRESS_TEXT_CAPACITY: usize = 0x14;

    let Some(port) = invocation.line.dword("port") else {
        return false;
    };

    let address = match invocation.line.param("addr") {
        Some(value) => {
            let mut buffer = [0u8; ADDRESS_TEXT_CAPACITY];
            parse_address(value.copy_into(&mut buffer))
        }
        None => match socket.map(|socket| invocation.network.peer(socket)) {
            Some(Ok(peer)) => peer.address,
            None | Some(Err(_)) => return false,
        },
    };

    let endpoint = Endpoint {
        address,
        port: port as u16,
    };

    if invocation.line.has("drop") {
        invocation
            .state
            .notifications
            .drop_targets(endpoint, invocation.network);
        return true;
    }

    let flags = target_flags(invocation);
    let reverse = reverse || flags.contains(TargetFlags::REVERSE);
    let execution = invocation.backend.execution_state();

    invocation.state.notifications.register_target(
        endpoint,
        flags,
        reverse,
        None,
        execution,
        invocation.network,
    )
}

/// Parse `a.b.c.d`: four groups of one to three decimal digits, each taken
/// modulo 256. The monitor stores the first group in the least significant
/// byte of a big-endian word that becomes `sin_addr` unchanged, so the
/// groups name the address bytes in reverse order. Malformed text gives the
/// unspecified address.
fn parse_address(text: &[u8]) -> Ipv4Address {
    let mut octets = [0u8; 4];
    let mut position = 0;

    for group in 0..4 {
        let mut value = 0u8;
        let mut digits = 0;

        while digits < 3 && text.get(position).is_some_and(u8::is_ascii_digit) {
            value = value.wrapping_mul(10).wrapping_add(text[position] - b'0');
            position += 1;
            digits += 1;
        }

        if digits == 0 {
            return Ipv4Address::UNSPECIFIED;
        }

        let separator = if group == 3 { None } else { Some(b'.') };
        if text.get(position).copied() != separator {
            return Ipv4Address::UNSPECIFIED;
        }

        position += 1;
        octets[3 - group] = value;
    }

    Ipv4Address(octets)
}

/// Settings-file lines for the notification targets.
pub(crate) fn notifyat_settings_lines(
    state: &ServerState,
    backend: &mut dyn AnyBackend,
    file: SettingsFile,
) {
    for target in state.notifications.targets() {
        let [a, b, c, d] = target.endpoint.address.octets();
        let reverse = if target.flags.contains(TargetFlags::REVERSE) {
            " reverse"
        } else {
            ""
        };

        system::write_line(
            backend,
            file,
            format_args!(
                "notifyat addr={d}.{c}.{b}.{a} port={}{reverse}",
                target.endpoint.port
            ),
        );
    }
}

/// Connect the targets loaded from the settings file. Each non-reverse
/// target is connected and sent `hello`; reverse targets wait for a
/// `notify reconnectport=` connection. Targets get 30 seconds; the
/// remaining reverse wait is finished by [`expire_reverse_targets`].
pub fn connect_persistent_targets(
    state: &mut ServerState,
    backend: &mut dyn AnyBackend,
    network: &mut dyn Network,
) {
    const FILETIME_PER_MILLISECOND: u64 = 10_000;
    /// Time persistent targets are given to connect, in FILETIME units.
    const PERSISTENT_CONNECT_WINDOW: u64 = 30_000 * FILETIME_PER_MILLISECOND;

    let deadline = backend
        .system_time()
        .saturating_add(PERSISTENT_CONNECT_WINDOW);
    let notifications = &mut state.notifications;
    let mut pending = [None::<SocketId>; MAX_NOTIFICATION_TARGETS];
    let mut reverse = false;

    for (index, socket) in pending.iter_mut().enumerate() {
        let Some(target) = notifications.target(index) else {
            continue;
        };

        if target.flags.contains(TargetFlags::REVERSE) {
            reverse = true;
        } else {
            match network.connect(target.endpoint, false) {
                Ok(connected) => {
                    *socket = Some(connected);
                }
                Err(_) => {
                    notifications.remove_target(index);
                }
            }
        }
    }

    let mut timed_out = false;

    for (index, socket) in pending.into_iter().enumerate() {
        let Some(socket) = socket else { continue };
        let now = backend.system_time();
        let ready = !timed_out
            && now < deadline
            && network
                .wait_writable(
                    socket,
                    (deadline - now).div_ceil(FILETIME_PER_MILLISECOND) as u32,
                )
                .is_ok();
        if !ready {
            // A timeout drops every target still connecting.
            timed_out = true;
            network.close(socket);
            notifications.remove_target(index);
            continue;
        }

        if network.set_blocking(socket, true).is_err() {
            // The monitor closes the socket but keeps the target.
            network.close(socket);
            continue;
        }

        if send_line(network, socket, b"hello").is_err()
            || notifications
                .attach_socket(socket, Some(index), network)
                .is_none()
        {
            network.close(socket);
            notifications.remove_target(index);
        }
    }

    if reverse {
        state.session.reverse_deadline = Some(deadline);
    } else {
        state.settings_dirty = true;
    }

    expire_reverse_targets(state, backend);
}

/// End the wait for reverse persistent targets once each has a connection
/// or the deadline has passed; targets still without one are dropped and
/// the settings file is rewritten.
pub fn expire_reverse_targets(state: &mut ServerState, backend: &mut dyn AnyBackend) {
    let Some(deadline) = state.session.reverse_deadline else {
        return;
    };

    let waiting = |index: usize, state: &ServerState| {
        state.notifications.target(index).is_some_and(|target| {
            target.flags.contains(TargetFlags::REVERSE) && target.socket_slot.is_none()
        })
    };

    let any_waiting = (0..MAX_NOTIFICATION_TARGETS).any(|index| waiting(index, state));
    if any_waiting && backend.system_time() < deadline {
        return;
    }

    for index in 0..MAX_NOTIFICATION_TARGETS {
        if waiting(index, state) {
            state.notifications.remove_target(index);
        }
    }

    state.session.reverse_deadline = None;
    state.settings_dirty = true;
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

    #[test]
    fn addresses_parse_in_reverse_group_order() {
        assert_eq!(parse_address(b"1.2.3.4"), Ipv4Address([4, 3, 2, 1]));
        assert_eq!(parse_address(b"300.0.0.1"), Ipv4Address([1, 0, 0, 44]));
        assert_eq!(parse_address(b"1.2.3"), Ipv4Address::UNSPECIFIED);
        assert_eq!(parse_address(b"1.2.3.4x"), Ipv4Address::UNSPECIFIED);
        assert_eq!(parse_address(b"1234.2.3.4"), Ipv4Address::UNSPECIFIED);
    }
}
