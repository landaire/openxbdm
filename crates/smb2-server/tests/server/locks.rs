//! Byte-range locks (MS-SMB2 3.3.5.14) between opens on one connection and
//! on two connections to one server.

use smb2_server::server::FileId;
use smb2_server::status::NtStatus;

use crate::backend::DATA;
use crate::client::Client;
use crate::client::LockElement;
use crate::client::close_body;
use crate::client::command;
use crate::client::disposition;
use crate::client::flags;
use crate::client::lock;

const FILE: &str = "locked.bin";

fn element(offset: u64, length: u64, flags: u32) -> LockElement {
    LockElement {
        offset,
        length,
        flags,
    }
}

fn exclusive_now(offset: u64, length: u64) -> [LockElement; 1] {
    [element(
        offset,
        length,
        lock::EXCLUSIVE | lock::FAIL_IMMEDIATELY,
    )]
}

fn unlock(offset: u64, length: u64) -> [LockElement; 1] {
    [element(offset, length, lock::UNLOCK)]
}

/// A client and a peer on a second connection, each with an open of the
/// same 100-byte file.
fn two_connections() -> (Client, FileId, Client, FileId) {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, FILE, &[0x11; 100]);
    let file = client.open(FILE, disposition::OPEN);
    let mut peer = client.connected_peer("Data");
    let peer_file = client.with_peer(&mut peer, |peer| peer.open(FILE, disposition::OPEN));
    (client, file, peer, peer_file)
}

#[test]
fn conflicting_locks_across_connections_fail_immediately() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        peer.lock(peer_file, &exclusive_now(5, 10))
            .expect(NtStatus::LockNotGranted);
        peer.lock(
            peer_file,
            &[element(9, 1, lock::SHARED | lock::FAIL_IMMEDIATELY)],
        )
        .expect(NtStatus::LockNotGranted);
        // Adjacent ranges do not overlap.
        peer.lock(
            peer_file,
            &[element(10, 10, lock::SHARED | lock::FAIL_IMMEDIATELY)],
        )
        .expect(NtStatus::Success);
    });
    // Shared locks coexist; an exclusive one does not join them.
    client
        .lock(
            file,
            &[element(12, 4, lock::SHARED | lock::FAIL_IMMEDIATELY)],
        )
        .expect(NtStatus::Success);
    client
        .lock(file, &exclusive_now(15, 1))
        .expect(NtStatus::LockNotGranted);
}

#[test]
fn two_opens_on_one_connection_conflict() {
    let mut client = Client::connected("Data");
    client.backend.add_file(DATA, FILE, &[0; 100]);
    let first = client.open(FILE, disposition::OPEN);
    let second = client.open(FILE, disposition::OPEN);
    client
        .lock(first, &exclusive_now(0, 50))
        .expect(NtStatus::Success);
    client
        .lock(second, &exclusive_now(49, 2))
        .expect(NtStatus::LockNotGranted);
    client
        .lock(second, &exclusive_now(50, 50))
        .expect(NtStatus::Success);
}

#[test]
fn failed_multi_element_lock_releases_its_earlier_elements() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(50, 10))
        .expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        peer.lock(
            peer_file,
            &[
                element(0, 10, lock::EXCLUSIVE | lock::FAIL_IMMEDIATELY),
                element(55, 1, lock::EXCLUSIVE | lock::FAIL_IMMEDIATELY),
            ],
        )
        .expect(NtStatus::LockNotGranted);
    });
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
}

#[test]
fn read_and_write_over_another_opens_lock_conflict() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    client
        .lock(
            file,
            &[element(20, 10, lock::SHARED | lock::FAIL_IMMEDIATELY)],
        )
        .expect(NtStatus::Success);
    // The holder of the exclusive lock reads and writes through it.
    assert_eq!(client.read(file, 0, 4).data(), [0x11; 4]);
    client.write(file, 2, b"ab").expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        peer.read(peer_file, 8, 4)
            .expect(NtStatus::FileLockConflict);
        peer.write(peer_file, 9, b"x")
            .expect(NtStatus::FileLockConflict);
        peer.read(peer_file, 10, 10).expect(NtStatus::Success);
        // A shared lock admits reads only.
        peer.read(peer_file, 20, 10).expect(NtStatus::Success);
        peer.write(peer_file, 25, b"x")
            .expect(NtStatus::FileLockConflict);
        peer.write(peer_file, 30, b"x").expect(NtStatus::Success);
    });
}

#[test]
fn unlock_needs_the_exact_range_of_the_same_open() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &unlock(0, 10))
        .expect(NtStatus::RangeNotLocked);
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    client
        .lock(file, &unlock(0, 5))
        .expect(NtStatus::RangeNotLocked);
    client.with_peer(&mut peer, |peer| {
        peer.lock(peer_file, &unlock(0, 10))
            .expect(NtStatus::RangeNotLocked);
    });
    client.lock(file, &unlock(0, 10)).expect(NtStatus::Success);
    client
        .lock(file, &unlock(0, 10))
        .expect(NtStatus::RangeNotLocked);
    client.with_peer(&mut peer, |peer| {
        peer.lock(peer_file, &exclusive_now(0, 10))
            .expect(NtStatus::Success);
    });
}

#[test]
fn close_releases_the_opens_locks() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    client.close(file, 0).expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        peer.lock(peer_file, &exclusive_now(0, 10))
            .expect(NtStatus::Success);
        peer.write(peer_file, 0, b"mine").expect(NtStatus::Success);
    });
}

/// Start a blocking exclusive lock of `0..10` on the peer; returns the
/// interim reply.
fn blocked_lock(
    client: &mut Client,
    peer: &mut Client,
    peer_file: FileId,
) -> crate::client::Message {
    client.with_peer(peer, |peer| {
        let interim = peer.lock(peer_file, &[element(0, 10, lock::EXCLUSIVE)]);
        interim.expect(NtStatus::Pending);
        assert_ne!(interim.flags() & flags::ASYNC_COMMAND, 0);
        assert!(!peer.wants_poll());
        assert!(peer.poll().is_nothing());
        interim
    })
}

#[test]
fn blocking_lock_is_granted_after_unlock() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    let interim = blocked_lock(&mut client, &mut peer, peer_file);
    // Another range of the file does not release the waiter.
    client
        .lock(file, &exclusive_now(50, 1))
        .expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| assert!(peer.poll().is_nothing()));

    client.lock(file, &unlock(0, 10)).expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        assert!(peer.wants_poll());
        let granted = peer.poll().single();
        granted.expect(NtStatus::Success);
        assert_eq!(granted.command(), command::LOCK);
        assert_eq!(granted.message_id(), interim.message_id());
        assert_eq!(granted.async_id(), interim.async_id());
        assert!(!peer.wants_poll());
    });
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::LockNotGranted);
}

#[test]
fn blocking_lock_is_granted_when_the_holder_closes() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    blocked_lock(&mut client, &mut peer, peer_file);
    client.close(file, 0).expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        peer.poll().single().expect(NtStatus::Success);
    });
}

#[test]
fn cancel_ends_a_blocking_lock() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    let interim = blocked_lock(&mut client, &mut peer, peer_file);
    client.with_peer(&mut peer, |peer| {
        let cancelled = peer
            .cancel(interim.message_id(), interim.async_id())
            .single();
        cancelled.expect(NtStatus::Cancelled);
        assert_eq!(cancelled.command(), command::LOCK);
        assert_eq!(cancelled.async_id(), interim.async_id());
    });
    client.lock(file, &unlock(0, 10)).expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| assert!(peer.poll().is_nothing()));
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
}

#[test]
fn closing_the_waiting_open_cancels_its_lock() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    blocked_lock(&mut client, &mut peer, peer_file);
    client.with_peer(&mut peer, |peer| {
        let replies = peer
            .call_all(command::CLOSE, &close_body(peer_file, 0))
            .replies();
        let statuses: Vec<(u16, NtStatus)> = replies
            .iter()
            .map(|reply| (reply.command(), reply.status()))
            .collect();
        assert_eq!(
            statuses,
            [
                (command::CLOSE, NtStatus::Success),
                (command::LOCK, NtStatus::Cancelled)
            ]
        );
    });
}

#[test]
fn lock_in_a_compound_chain_does_not_wait() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        let replies = peer
            .compound(&[
                crate::client::Request {
                    command: command::LOCK,
                    body: crate::client::lock_body(peer_file, &[element(0, 10, lock::EXCLUSIVE)]),
                    related: false,
                },
                crate::client::Request {
                    command: command::ECHO,
                    body: crate::client::empty_body(),
                    related: false,
                },
            ])
            .replies();
        replies[0].expect(NtStatus::LockNotGranted);
    });
}

#[test]
fn failed_lock_keeps_an_earlier_lock_of_the_same_range() {
    let (mut client, file, mut peer, peer_file) = two_connections();
    client
        .lock(file, &exclusive_now(0, 10))
        .expect(NtStatus::Success);
    client.with_peer(&mut peer, |peer| {
        peer.lock(peer_file, &exclusive_now(50, 1))
            .expect(NtStatus::Success);
    });
    // A shared lock over the open's own exclusive lock is granted, then the
    // second element conflicts and the request is undone.
    client
        .lock(
            file,
            &[
                element(0, 10, lock::SHARED | lock::FAIL_IMMEDIATELY),
                element(50, 1, lock::EXCLUSIVE | lock::FAIL_IMMEDIATELY),
            ],
        )
        .expect(NtStatus::LockNotGranted);
    client.with_peer(&mut peer, |peer| {
        peer.read(peer_file, 0, 4)
            .expect(NtStatus::FileLockConflict);
    });
    client.lock(file, &unlock(0, 10)).expect(NtStatus::Success);
    client
        .lock(file, &unlock(0, 10))
        .expect(NtStatus::RangeNotLocked);
}
