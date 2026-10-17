//! `netcap` over TCP.

use std::io::Read;

use openxbdm_core::status::KernelError;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::netcap::BufferSizes;
use openxbdm_server::commands::network::netcap::capture_file;
use openxbdm_server::commands::network::netcap::capture_file::CaptureFileError;
use openxbdm_server::commands::network::netsim::NetsimError;
use openxbdm_server_host::backend::MockBackend;
use openxbdm_server_host::backend::network::netcap::Attachment;
use openxbdm_server_host::backend::network::netcap::LOCAL_TIME;
use openxbdm_server_host::backend::network::netcap::Mock;

use crate::common::RawSession;
use crate::common::TestServer;

/// Object name of `e:\cap.bin`.
const OBJECT_PATH: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\cap.bin";
/// Creates the simulator instance with an unshaped inbound queue.
const NETSIM_INSERT: &str = "netsim insertq in cfg=100100000000";
/// Removes every queue, which releases the idle instance.
const NETSIM_REMOVE: &str = "netsim removeq";

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");

    session
}

fn with_mock<T>(server: &TestServer, action: impl FnOnce(&mut Mock) -> T) -> T {
    action(&mut server.host.lock().backend.network.netcap)
}

fn with_backend<T>(server: &TestServer, action: impl FnOnce(&mut MockBackend) -> T) -> T {
    action(&mut server.host.lock().backend)
}

fn file_bytes(server: &TestServer, path: &str) -> Vec<u8> {
    with_backend(server, |backend| {
        backend.filesystem.read(path).unwrap().to_vec()
    })
}

fn capture_bytes(server: &TestServer) -> Vec<u8> {
    file_bytes(server, OBJECT_PATH)
}

/// Record bytes: time, length twice, frame, frame type.
fn record(microseconds: u64, frame: &[u8]) -> Vec<u8> {
    let mut bytes = microseconds.to_le_bytes().to_vec();
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    bytes.extend_from_slice(frame);
    bytes.extend_from_slice(&[1, 0]);

    bytes
}

fn header_with_table(offset: u32, length: u32) -> Vec<u8> {
    let mut header = capture_file::file_header(&LOCAL_TIME).to_vec();
    header[0x18..0x1c].copy_from_slice(&offset.to_le_bytes());
    header[0x1c..0x20].copy_from_slice(&length.to_le_bytes());

    header
}

#[test]
fn subcommand_and_file_are_required() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(session.command("netcap"), "423- bad parameter");
    assert_eq!(session.command("netcap start"), "412- filename is invalid");
    assert_eq!(session.command("netcap stop"), "435- ");
}

#[test]
fn capture_records_frames_and_the_frame_table() {
    /// Ticks of one millisecond at the simulated time base rate.
    const MILLISECOND: u64 = 50_000;

    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "200- started"
    );

    let transmitted = [0x00, 0x0d, 0x3a, 0x01, 0x02, 0x03, 0xaa, 0xbb];
    let received = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
    with_backend(&server, |backend| {
        let mock = &mut backend.network.netcap;
        let capture = mock.capture.as_ref().unwrap();
        assert_eq!(capture.object_path, OBJECT_PATH.as_bytes());
        assert_eq!(
            capture.sizes,
            BufferSizes {
                buffer: 0x20000,
                chunk: 0x4000
            }
        );
        assert_eq!(mock.attachment, Some(Attachment::Intercept));
        mock.timebase += 3 * MILLISECOND;
        backend.transmit_frame(&transmitted);
        backend.network.netcap.timebase += MILLISECOND / 2;
        backend.receive_frame(&received);
    });

    assert_eq!(session.command("netcap stop"), "200- stopped frames=2");
    assert_eq!(with_mock(&server, |mock| mock.attachment), None);

    let first = capture_file::HEADER_SIZE as u32;
    let second = first + 16 + transmitted.len() as u32 + 2;
    let table = second + 16 + received.len() as u32 + 2;
    let mut expected = header_with_table(table, 8);
    expected.extend(record(3000, &transmitted));
    expected.extend(record(3500, &received));
    expected.extend(first.to_le_bytes());
    expected.extend(second.to_le_bytes());
    assert_eq!(capture_bytes(&server), expected);
}

#[test]
fn empty_capture_has_no_frame_table() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "200- started"
    );
    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");
    assert_eq!(capture_bytes(&server), header_with_table(0, 0));
}

#[test]
fn second_start_and_existing_file_fail() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "200- started"
    );
    assert_eq!(
        session.command(r"netcap start file=e:\other.bin"),
        "408- err=0x82da0008"
    );
    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");

    // The file is created, never replaced.
    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "410- err=0x82da000a"
    );
    assert_eq!(session.command("netcap stop"), "435- ");
}

#[test]
fn untranslated_names_are_used_as_given() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(&format!("netcap start file={OBJECT_PATH}")),
        "200- started"
    );
    assert_eq!(
        with_mock(&server, |mock| mock
            .capture
            .as_ref()
            .unwrap()
            .object_path
            .clone()),
        OBJECT_PATH.as_bytes()
    );

    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");
    assert_eq!(capture_bytes(&server), header_with_table(0, 0));
}

#[test]
fn missing_directories_fail_the_start() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\absent\cap.bin"),
        "402- err=0x82da0002"
    );
    assert_eq!(session.command("netcap stop"), "435- ");
}

#[test]
fn getfile_reads_the_finished_capture() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "200- started"
    );
    with_backend(&server, |backend| backend.transmit_frame(&[0x5a; 6]));
    assert_eq!(session.command("netcap stop"), "200- stopped frames=1");

    let bytes = capture_bytes(&server);
    session.send(r"getfile name=e:\cap.bin");
    assert_eq!(session.line(), "203- binary response follows");

    let mut received = vec![0; 4 + bytes.len()];
    session.reader.read_exact(&mut received).unwrap();
    assert_eq!(received[..4], (bytes.len() as u32).to_le_bytes());
    assert_eq!(received[4..], bytes);
}

#[test]
fn captures_chain_into_the_network_simulator() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "200- started"
    );
    assert_eq!(
        with_mock(&server, |mock| mock.attachment),
        Some(Attachment::Intercept)
    );

    assert_eq!(session.command(NETSIM_INSERT), "200- index=0");
    assert_eq!(
        with_mock(&server, |mock| mock.attachment),
        Some(Attachment::Simulator)
    );

    with_backend(&server, |backend| {
        backend.transmit_frame(&[1; 8]);
        backend.receive_frame(&[2; 8]);
    });

    assert_eq!(
        session.command(NETSIM_REMOVE),
        "200- removed=1 inleft=0 outleft=0"
    );
    assert_eq!(
        with_mock(&server, |mock| mock.attachment),
        Some(Attachment::Intercept)
    );

    with_backend(&server, |backend| backend.transmit_frame(&[3; 8]));
    assert_eq!(session.command("netcap stop"), "200- stopped frames=3");

    // A capture started while the instance exists never installs its own
    // intercept, so an intercept failure does not apply.
    assert_eq!(session.command(NETSIM_INSERT), "200- index=0");
    with_mock(&server, |mock| {
        mock.intercept_error = Some(WsaError::ALREADY)
    });
    assert_eq!(
        session.command(r"netcap start file=e:\chained.bin"),
        "200- started"
    );
    assert_eq!(
        with_mock(&server, |mock| mock.attachment),
        Some(Attachment::Simulator)
    );
    with_backend(&server, |backend| backend.receive_frame(&[4; 8]));
    assert_eq!(session.command("netcap stop"), "200- stopped frames=1");
    assert_eq!(with_mock(&server, |mock| mock.attachment), None);
    assert_eq!(
        session.command(NETSIM_REMOVE),
        "200- removed=1 inleft=0 outleft=0"
    );
}

#[test]
fn failed_simulator_creation_leaves_the_capture_unrouted() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "200- started"
    );

    // ERROR_OUTOFMEMORY from the intercept registration.
    server.host.lock().backend.network.netsim.create_error =
        WsaError::new(14).map(NetsimError::Intercept);
    assert_eq!(session.command(NETSIM_INSERT), "400- err=0x8007000e");
    assert_eq!(
        with_mock(&server, |mock| mock.attachment),
        Some(Attachment::Unrouted)
    );

    with_backend(&server, |backend| backend.transmit_frame(&[1; 8]));
    assert_eq!(session.command(NETSIM_INSERT), "200- index=0");
    assert_eq!(
        with_mock(&server, |mock| mock.attachment),
        Some(Attachment::Simulator)
    );

    with_backend(&server, |backend| backend.transmit_frame(&[2; 8]));
    assert_eq!(session.command("netcap stop"), "200- stopped frames=1");
}

#[test]
fn buffer_sizes_follow_flags_and_buffersize() {
    let server = TestServer::start();
    let mut session = session(&server);

    let sizes =
        |server: &TestServer| with_mock(server, |mock| mock.capture.as_ref().unwrap().sizes);

    assert_eq!(
        session.command(r"netcap start file=e:\a.bin flags=8"),
        "200- started"
    );
    assert_eq!(
        sizes(&server),
        BufferSizes {
            buffer: 0x2000,
            chunk: 0x1000
        }
    );
    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");

    assert_eq!(
        session.command(r"netcap start file=e:\b.bin buffersize=0x3000"),
        "200- started"
    );
    assert_eq!(
        sizes(&server),
        BufferSizes {
            buffer: 0x3000,
            chunk: 0x1800
        }
    );
    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");

    assert_eq!(
        session.command(r"netcap start file=e:\c.bin buffersize=0x100000 flags=8"),
        "200- started"
    );
    assert_eq!(
        sizes(&server),
        BufferSizes {
            buffer: 0x10_0000,
            chunk: 0x4000
        }
    );
}

#[test]
fn receive_filters_skip_group_frames() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin flags=6"),
        "200- started"
    );

    let broadcast = [0xff; 8];
    let multicast = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01, 0x00];
    with_backend(&server, |backend| {
        backend.receive_frame(&broadcast);
        backend.receive_frame(&multicast);
        backend.transmit_frame(&broadcast);
        backend.transmit_frame(&multicast);
    });

    assert_eq!(session.command("netcap stop"), "200- stopped frames=2");
}

#[test]
fn promiscuous_mode_follows_the_capture() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\a.bin flags=1"),
        "200- started"
    );
    assert!(with_mock(&server, |mock| mock.promiscuous));
    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");
    assert!(!with_mock(&server, |mock| mock.promiscuous));

    // A refused request clears the flag, so stop leaves the mode alone.
    with_mock(&server, |mock| mock.promiscuous_error = true);
    assert_eq!(
        session.command(r"netcap start file=e:\b.bin flags=1"),
        "200- started"
    );
    with_mock(&server, |mock| mock.promiscuous = true);
    assert_eq!(session.command("netcap stop"), "200- stopped frames=0");
    assert!(with_mock(&server, |mock| mock.promiscuous));
}

#[test]
fn frame_errors_stop_recording_and_report_on_stop() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\a.bin maxframedata=100"),
        "200- started"
    );
    with_backend(&server, |backend| {
        backend.transmit_frame(&[0; 60]);
        backend.transmit_frame(&[0; 23]);
        backend.transmit_frame(&[0; 1]);
    });

    assert_eq!(
        session.command("netcap stop"),
        "200- stopped err=0x8007006f frames=1"
    );

    assert_eq!(
        session.command(r"netcap start file=e:\b.bin"),
        "200- started"
    );
    with_backend(&server, |backend| {
        backend.transmit_frame(&[0; capture_file::MAX_FRAME_LENGTH as usize + 1]);
        backend.transmit_frame(&[0; 4]);
    });
    assert_eq!(
        session.command("netcap stop"),
        "200- stopped err=0x80070018 frames=0"
    );
}

#[test]
fn lost_frames_report_438() {
    let server = TestServer::start();
    let mut session = session(&server);

    // A 0x40-byte buffer holds two records; the stalled writer never drains it.
    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin buffersize=0x40"),
        "200- started"
    );
    with_backend(&server, |backend| {
        backend.network.netcap.writer_stalled = true;
        backend.transmit_frame(&[1; 10]);
        backend.transmit_frame(&[2; 10]);
        backend.transmit_frame(&[3; 10]);
    });

    // The cut record leaves the frame table at the last record end the
    // writer flushed, the header end, so the finished file holds no frames.
    assert_eq!(
        session.command("netcap stop"),
        "438- stopped err=0x82da0026 frames=0"
    );
    assert_eq!(capture_bytes(&server), header_with_table(0, 0));
}

#[test]
fn file_write_failures_report_on_stop() {
    /// Bytes of one record holding a 10-byte frame.
    const RECORD_10: usize = 16 + 10 + 2;

    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin buffersize=0x40"),
        "200- started"
    );

    with_backend(&server, |backend| {
        // The writer fails on the drain the second record triggers and
        // exits; the records stay buffered and counted.
        backend.filesystem.write_limit = Some((capture_file::HEADER_SIZE + RECORD_10) as u64);
        backend.transmit_frame(&[1; 10]);
        backend.transmit_frame(&[2; 10]);
    });

    assert_eq!(
        session.command("netcap stop"),
        "200- stopped err=0x82da000f frames=2"
    );
    assert_eq!(capture_bytes(&server), header_with_table(0, 0));
}

#[test]
fn close_failures_map_kernel_status() {
    let server = TestServer::start();
    let mut session = session(&server);

    assert_eq!(
        session.command(r"netcap start file=e:\cap.bin"),
        "200- started"
    );

    with_mock(&server, |mock| {
        mock.finish_error = Some(CaptureFileError::Kernel(KernelError::DiskFull))
    });

    assert_eq!(
        session.command("netcap stop"),
        "200- stopped err=0x82da000f frames=0"
    );
}

#[test]
fn start_failures_report_the_result() {
    let server = TestServer::start();
    let mut session = session(&server);

    with_mock(&server, |mock| {
        mock.open_error = Some(CaptureFileError::OutOfMemory)
    });
    assert_eq!(
        session.command(r"netcap start file=e:\a.bin"),
        "400- err=0x8007000e"
    );

    with_mock(&server, |mock| {
        mock.intercept_error = Some(WsaError::ALREADY)
    });
    assert_eq!(
        session.command(r"netcap start file=e:\b.bin flags=1"),
        "416- err=0x82da0010"
    );

    // The file is finished and closed; promiscuous mode stays on.
    with_mock(&server, |mock| {
        assert!(mock.capture.is_none());
        assert!(mock.promiscuous);
    });
    assert_eq!(
        file_bytes(&server, "\\Device\\Harddisk0\\Partition1\\DEVKIT\\b.bin"),
        header_with_table(0, 0)
    );
    assert_eq!(session.command("netcap stop"), "435- ");

    with_mock(&server, |mock| {
        mock.intercept_error = Some(WsaError::NO_BUFFERS)
    });
    assert_eq!(
        session.command(r"netcap start file=e:\c.bin"),
        "400- err=0x80072747"
    );

    with_mock(&server, |mock| {
        mock.intercept_error = WsaError::new(-0x7ff8_fff2)
    });
    assert_eq!(
        session.command(r"netcap start file=e:\d.bin"),
        "400- err=0x8007000e"
    );
}
