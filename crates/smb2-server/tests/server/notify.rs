//! CHANGE_NOTIFY (MS-SMB2 3.3.5.19): records of changes made through the
//! server, scans for changes made outside it, and the ways a waiting
//! notification ends.

use std::time::Duration;

use smb2_server::ServerConfig;
use smb2_server::fs::FileTime;
use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::backend::MemoryBackend;
use crate::backend::PASSWORD;
use crate::backend::USER;
use crate::client::Client;
use crate::client::Message;
use crate::client::access;
use crate::client::close_body;
use crate::client::command;
use crate::client::config;
use crate::client::context;
use crate::client::create_body;
use crate::client::dialect;
use crate::client::disposition;
use crate::client::flags;
use crate::client::notify_records;
use crate::client::options;
use crate::files::rename_information;

const FILE_NAME: u32 = 0x01;
const DIR_NAME: u32 = 0x02;
const SIZE: u32 = 0x08;
const LAST_WRITE: u32 = 0x10;
const NAMES: u32 = FILE_NAME | DIR_NAME;

const ADDED: u32 = 1;
const REMOVED: u32 = 2;
const MODIFIED: u32 = 3;
const RENAMED_OLD_NAME: u32 = 4;
const RENAMED_NEW_NAME: u32 = 5;

const INFO_FILE: u8 = 1;
const FILE_RENAME_INFORMATION: u8 = 10;
const SCAN_INTERVAL: Duration = Duration::from_secs(5);

/// A client connected with `config` and watching `watch`, which holds
/// the directory `sub`.
fn watching(config: ServerConfig) -> (Client, FileId) {
    let mut client = Client::negotiated(MemoryBackend::new(), config);
    client
        .logon(USER, PASSWORD, false)
        .expect(NtStatus::Success);
    client.tree_connect("Data").expect(NtStatus::Success);

    client.backend.add_directory(DATA, "watch");
    client.backend.add_directory(DATA, "watch\\sub");
    let directory = client.open_directory("watch");

    (client, directory)
}

/// Send a CHANGE_NOTIFY that waits; returns its interim reply.
fn wait_for_changes(client: &mut Client, directory: FileId, filter: u32, tree: bool) -> Message {
    let interim = client.change_notify(directory, filter, tree).single();
    interim.expect(NtStatus::Pending);
    assert_eq!(interim.command(), command::CHANGE_NOTIFY);
    assert_ne!(interim.flags() & flags::ASYNC_COMMAND, 0);

    interim
}

/// The completion of the notification `interim` started, from a poll.
fn completion(client: &mut Client, interim: &Message) -> Message {
    assert!(client.wants_poll());
    let reply = client.poll().single();
    assert_eq!(reply.command(), command::CHANGE_NOTIFY);
    assert_eq!(reply.message_id(), interim.message_id());
    assert_eq!(reply.async_id(), interim.async_id());

    reply
}

fn records(reply: &Message) -> Vec<(u32, String)> {
    reply.expect(NtStatus::Success);
    notify_records(reply.output())
}

fn create_file(client: &mut Client, path: &str) {
    let file = client.open(path, disposition::CREATE);
    client.close(file, 0).expect(NtStatus::Success);
}

fn advance(client: &mut Client, by: Duration) {
    client.backend.time = FileTime(client.backend.time.0 + (by.as_nanos() / 100) as u64);
}

#[test]
fn create_rename_and_delete_by_another_connection_are_reported() {
    let (mut client, directory) = watching(config(false));
    let mut peer = client.connected_peer("Data");

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    assert!(!client.wants_poll());
    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\new.txt"));
    let reply = completion(&mut client, &interim);
    assert_eq!(records(&reply), [(ADDED, "new.txt".to_owned())]);

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    client.with_peer(&mut peer, |peer| {
        let file = peer.open("watch\\new.txt", disposition::OPEN);
        peer.set_info(
            file,
            INFO_FILE,
            FILE_RENAME_INFORMATION,
            &rename_information("watch\\renamed.txt", false),
        )
        .expect(NtStatus::Success);
        peer.close(file, 0).expect(NtStatus::Success);
    });
    let reply = completion(&mut client, &interim);
    assert_eq!(
        records(&reply),
        [
            (RENAMED_OLD_NAME, "new.txt".to_owned()),
            (RENAMED_NEW_NAME, "renamed.txt".to_owned())
        ]
    );

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    client.with_peer(&mut peer, |peer| {
        let file = peer
            .create(
                "watch\\renamed.txt",
                access::DELETE | access::READ,
                disposition::OPEN,
                options::NON_DIRECTORY_FILE | options::DELETE_ON_CLOSE,
            )
            .file_id();
        peer.close(file, 0).expect(NtStatus::Success);
    });
    let reply = completion(&mut client, &interim);
    assert_eq!(records(&reply), [(REMOVED, "renamed.txt".to_owned())]);
}

#[test]
fn writes_are_reported_to_a_size_filter() {
    let (mut client, directory) = watching(config(false));
    client.backend.add_file(DATA, "watch\\log.txt", b"");
    let mut peer = client.connected_peer("Data");

    let interim = wait_for_changes(&mut client, directory, SIZE | LAST_WRITE, false);
    client.with_peer(&mut peer, |peer| {
        let file = peer.open("watch\\log.txt", disposition::OPEN);
        peer.write(file, 0, b"entry").expect(NtStatus::Success);
    });
    let reply = completion(&mut client, &interim);
    assert_eq!(records(&reply), [(MODIFIED, "log.txt".to_owned())]);
}

#[test]
fn filter_selects_the_reported_changes() {
    let (mut client, directory) = watching(config(false));
    let mut peer = client.connected_peer("Data");

    let interim = wait_for_changes(&mut client, directory, DIR_NAME, false);
    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\file.txt"));
    assert!(client.poll().is_nothing());

    client.with_peer(&mut peer, |peer| {
        peer.create(
            "watch\\folder",
            access::READ,
            disposition::CREATE,
            options::DIRECTORY_FILE,
        )
        .expect(NtStatus::Success);
    });
    let reply = completion(&mut client, &interim);
    assert_eq!(records(&reply), [(ADDED, "folder".to_owned())]);
}

#[test]
fn only_a_tree_watch_reports_changes_below_the_directory() {
    let (mut client, directory) = watching(config(false));
    let tree_directory = client.open_directory("watch");
    let mut peer = client.connected_peer("Data");

    let flat = wait_for_changes(&mut client, directory, NAMES, false);
    let tree = wait_for_changes(&mut client, tree_directory, NAMES, true);

    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\sub\\deep.txt"));
    let reply = completion(&mut client, &tree);
    assert_eq!(records(&reply), [(ADDED, "sub\\deep.txt".to_owned())]);

    // The flat watch still waits, and reports a change at its level.
    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\top.txt"));
    let reply = completion(&mut client, &flat);
    assert_eq!(records(&reply), [(ADDED, "top.txt".to_owned())]);
}

#[test]
fn changes_while_no_notification_waits_report_enum_dir() {
    let (mut client, directory) = watching(config(false));
    let mut peer = client.connected_peer("Data");

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\a.txt"));
    completion(&mut client, &interim);

    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\b.txt"));
    assert!(client.wants_poll());
    assert!(client.poll().is_nothing());
    let reply = client.change_notify(directory, NAMES, false).single();
    reply.expect(NtStatus::NotifyEnumDir);
    assert_eq!(reply.flags() & flags::ASYNC_COMMAND, 0);

    // The overflow is reported once.
    wait_for_changes(&mut client, directory, NAMES, false);
}

#[test]
fn own_change_completes_the_notification_in_the_same_reply() {
    let (mut client, directory) = watching(config(false));

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    let replies = client
        .call_all(
            command::CREATE,
            &create_body(
                "watch\\mine.txt",
                access::ALL,
                disposition::CREATE,
                options::NON_DIRECTORY_FILE,
                &[],
            ),
        )
        .replies();
    assert_eq!(replies.len(), 2);
    replies[0].expect(NtStatus::Success);
    assert_eq!(replies[1].async_id(), interim.async_id());
    assert_eq!(records(&replies[1]), [(ADDED, "mine.txt".to_owned())]);
}

#[test]
fn scans_find_changes_made_outside_the_server() {
    let (mut client, directory) = watching(ServerConfig {
        change_scan_interval: Some(SCAN_INTERVAL),
        ..config(false)
    });
    let interim = wait_for_changes(&mut client, directory, NAMES, false);

    // A scan of an unchanged directory reports nothing.
    advance(&mut client, SCAN_INTERVAL);
    assert!(client.poll().is_nothing());

    client.backend.add_file(DATA, "watch\\outside.txt", b"");
    // The next scan is not due yet.
    advance(&mut client, SCAN_INTERVAL / 2);
    assert!(client.poll().is_nothing());
    advance(&mut client, SCAN_INTERVAL / 2);
    let reply = client.poll().single();
    assert_eq!(reply.async_id(), interim.async_id());
    reply.expect(NtStatus::NotifyEnumDir);

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    client.backend.remove(DATA, "watch\\outside.txt");
    advance(&mut client, SCAN_INTERVAL);
    let reply = client.poll().single();
    assert_eq!(reply.async_id(), interim.async_id());
    reply.expect(NtStatus::NotifyEnumDir);
}

#[test]
fn scans_of_a_tree_watch_look_below_the_directory() {
    let (mut client, directory) = watching(ServerConfig {
        change_scan_interval: Some(SCAN_INTERVAL),
        ..config(false)
    });
    let tree_directory = client.open_directory("watch");
    let flat = wait_for_changes(&mut client, directory, NAMES, false);
    let tree = wait_for_changes(&mut client, tree_directory, NAMES, true);

    client
        .backend
        .add_file(DATA, "watch\\sub\\outside.txt", b"");
    advance(&mut client, SCAN_INTERVAL);

    // Each poll scans one due watch; the entries of `watch` itself are
    // unchanged, so only the tree watch completes.
    let mut replies = client.poll().replies_or_none();
    replies.extend(client.poll().replies_or_none());
    let [reply] = &replies[..] else {
        panic!("expected one reply, got {replies:?}");
    };
    assert_eq!(reply.async_id(), tree.async_id());
    reply.expect(NtStatus::NotifyEnumDir);

    advance(&mut client, SCAN_INTERVAL);
    assert!(client.poll().is_nothing());

    let reply = client.cancel(flat.message_id(), flat.async_id()).single();
    reply.expect(NtStatus::Cancelled);
}

#[test]
fn without_a_scan_interval_outside_changes_go_unreported() {
    let (mut client, directory) = watching(config(false));
    wait_for_changes(&mut client, directory, NAMES, false);

    client.backend.add_file(DATA, "watch\\outside.txt", b"");
    advance(&mut client, Duration::from_secs(3600));
    assert!(!client.wants_poll());
    assert!(client.poll().is_nothing());
}

#[test]
fn closing_the_watched_open_ends_the_notification_with_cleanup() {
    let (mut client, directory) = watching(config(false));
    let interim = wait_for_changes(&mut client, directory, NAMES, false);

    let replies = client
        .call_all(command::CLOSE, &close_body(directory, 0))
        .replies();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0].command(), command::CLOSE);
    replies[0].expect(NtStatus::Success);
    assert_eq!(replies[1].async_id(), interim.async_id());
    replies[1].expect(NtStatus::NotifyCleanup);
}

#[test]
fn cancel_ends_the_notification() {
    let (mut client, directory) = watching(config(false));
    let interim = wait_for_changes(&mut client, directory, NAMES, false);

    let reply = client
        .cancel(interim.message_id(), interim.async_id())
        .single();
    reply.expect(NtStatus::Cancelled);
    assert_eq!(reply.command(), command::CHANGE_NOTIFY);
    assert_eq!(reply.async_id(), interim.async_id());

    // A cancel of a request that already ended has no reply.
    assert!(
        client
            .cancel(interim.message_id(), interim.async_id())
            .is_nothing()
    );

    // The open accepts a new notification.
    wait_for_changes(&mut client, directory, NAMES, false);
}

#[test]
fn notifications_of_an_encrypted_session_are_encrypted() {
    let config = ServerConfig {
        encrypt_data: true,
        ..config(false)
    };

    let mut client = Client::smb3(config, dialect::SMB_3_1_1, &[context::AES_128_GCM], &[]);
    assert!(client.encrypt);
    client.tree_connect("Data").expect(NtStatus::Success);

    client.backend.add_directory(DATA, "watch");
    let directory = client.open_directory("watch");
    let mut peer = client.connected_peer("Data");

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\new.txt"));

    let before = *client.reply_nonces.last().unwrap();
    let frames = client.poll().frames();
    assert_eq!(frames.len(), 1);
    let nonce = frames[0].nonce.expect("notification is encrypted");
    assert!(nonce > before);
    let reply = &frames[0].messages[0];
    assert_eq!(reply.async_id(), interim.async_id());
    assert!(!reply.signed());
    assert_eq!(records(reply), [(ADDED, "new.txt".to_owned())]);

    // The cancelled reply of a later notification is encrypted as well.
    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    let frames = client
        .cancel(interim.message_id(), interim.async_id())
        .frames();
    assert!(frames[0].nonce.is_some());
    frames[0].messages[0].expect(NtStatus::Cancelled);
}

#[test]
fn notifications_with_full_size_buffers_complete_together() {
    let (mut client, directory) = watching(config(false));
    let second = client.open_directory("watch");
    let mut peer = client.connected_peer("Data");

    let mut interims = Vec::new();
    for watched in [directory, second] {
        let interim = client
            .change_notify_sized(watched, NAMES, false, 0x1_0000)
            .single();
        interim.expect(NtStatus::Pending);
        interims.push(interim);
    }

    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\new.txt"));
    let replies = client.poll().replies();
    assert_eq!(replies.len(), 2);
    for (reply, interim) in replies.iter().zip(&interims) {
        assert_eq!(reply.async_id(), interim.async_id());
        assert_eq!(records(reply), [(ADDED, "new.txt".to_owned())]);
    }

    assert!(!client.wants_poll());
}

#[test]
fn one_poll_runs_one_due_scan_oldest_first() {
    let (mut client, directory) = watching(ServerConfig {
        change_scan_interval: Some(SCAN_INTERVAL),
        ..config(false)
    });
    client.backend.add_directory(DATA, "other");
    let other = client.open_directory("other");

    let first = wait_for_changes(&mut client, directory, NAMES, false);
    advance(&mut client, Duration::from_secs(1));
    let second = wait_for_changes(&mut client, other, NAMES, false);

    client.backend.add_file(DATA, "watch\\outside.txt", b"");
    client.backend.add_file(DATA, "other\\outside.txt", b"");
    advance(&mut client, SCAN_INTERVAL);

    let reply = client.poll().single();
    assert_eq!(reply.async_id(), first.async_id());
    reply.expect(NtStatus::NotifyEnumDir);

    let reply = client.poll().single();
    assert_eq!(reply.async_id(), second.async_id());
    reply.expect(NtStatus::NotifyEnumDir);
}

#[test]
fn change_between_notifications_is_found_by_the_next_scan() {
    let (mut client, directory) = watching(ServerConfig {
        change_scan_interval: Some(SCAN_INTERVAL),
        ..config(false)
    });
    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    client
        .cancel(interim.message_id(), interim.async_id())
        .single()
        .expect(NtStatus::Cancelled);

    client.backend.add_file(DATA, "watch\\outside.txt", b"");
    // No notification waits, so nothing is scanned.
    advance(&mut client, SCAN_INTERVAL);
    assert!(client.poll().is_nothing());

    let interim = wait_for_changes(&mut client, directory, NAMES, false);
    let reply = client.poll().single();
    assert_eq!(reply.async_id(), interim.async_id());
    reply.expect(NtStatus::NotifyEnumDir);
}

#[test]
fn undefined_filter_bits_are_ignored() {
    let (mut client, directory) = watching(ServerConfig {
        change_scan_interval: Some(SCAN_INTERVAL),
        ..config(false)
    });
    let mut peer = client.connected_peer("Data");

    for filter in [0, 0x8000_1000] {
        // Nothing matches a filter without defined bits; the request waits
        // until it is cancelled.
        let interim = wait_for_changes(&mut client, directory, filter, false);
        client.with_peer(&mut peer, |peer| {
            create_file(peer, &format!("watch\\{filter}.txt"))
        });
        client
            .backend
            .add_file(DATA, &format!("watch\\outside{filter}.txt"), b"");
        advance(&mut client, SCAN_INTERVAL);
        assert!(client.poll().is_nothing());
        client
            .cancel(interim.message_id(), interim.async_id())
            .single()
            .expect(NtStatus::Cancelled);
    }

    // Defined bits next to undefined ones are reported.
    let (mut client, directory) = watching(config(false));
    let mut peer = client.connected_peer("Data");
    let interim = wait_for_changes(&mut client, directory, FILE_NAME | 0x8000_0000, false);
    client.with_peer(&mut peer, |peer| create_file(peer, "watch\\named.txt"));
    let reply = completion(&mut client, &interim);
    assert_eq!(records(&reply), [(ADDED, "named.txt".to_owned())]);
}
