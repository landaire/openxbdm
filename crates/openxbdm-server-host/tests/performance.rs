//! Performance counter, capture, profiler, PIX, and display commands over
//! TCP.

mod common;

use std::io::Read;

use common::RawSession;
use common::TestServer;
use common::run;
use openxbdm_client::commands::PerfCounterList;
use openxbdm_client::commands::QueryPerfCounter;
use openxbdm_core::status::Hresult;
use openxbdm_core::status::XbdmHresult;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::DisplayInformation;
use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::commands::performance::PixMessage;
use openxbdm_server::commands::performance::capture::CaptureFlags;
use openxbdm_server::commands::performance::profiler::ProfilerError;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;
use openxbdm_server_host::backend::performance::CaptureSession;
use openxbdm_server_host::backend::performance::Display;
use openxbdm_server_host::backend::performance::PAGES;
use openxbdm_server_host::backend::performance::THREADS;
use xbox360_sys::xboxkrnl::HardwareFlags;

fn session(server: &TestServer) -> RawSession {
    let mut session = server.raw();
    assert_eq!(session.line(), "201- connected");
    session
}

fn read_bytes(session: &mut RawSession, count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    session.reader.read_exact(&mut bytes).unwrap();
    bytes
}

#[test]
fn pclist_enumerates_the_counter_directory() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("pclist"), "202- multiline response follows");
    let lines = session.multiline();
    assert_eq!(lines.len(), 32);
    assert_eq!(lines[0], "name=\"%Thread5 DPC\" type=0x00000021");
    assert_eq!(lines[1], "name=\"Debugger Pages\" type=0x00000001");
    assert_eq!(lines[12], "name=\"Frames\" type=0x00000011");

    let counters = run(async {
        let mut client = server.client().await;
        client.run(PerfCounterList).await.unwrap()
    });
    assert_eq!(counters.len(), 32);
    assert_eq!(counters[4].name, "% GPU Frontend");
    assert_eq!(counters[4].kind, 0x21);
}

#[test]
fn pclist_without_a_directory_is_empty() {
    let server = TestServer::start();
    server.host.lock().backend.performance.counters.directory = false;
    let mut session = session(&server);
    assert_eq!(session.command("pclist"), "202- multiline response follows");
    assert!(session.multiline().is_empty());
}

#[test]
fn querypc_reads_instantaneous_values_and_keeps_the_previous_rate() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        let counters = &mut host.backend.performance.counters;
        counters.sources[PAGES + 7] = 0x1234;
        counters.sources[THREADS] = 0x500;
        counters.sources[THREADS + 1] = 0x2710;
        // Period-one counters are first due on the second tick.
        counters.tick(0);
        counters.tick(0x2710);
    }
    let mut session = session(&server);
    assert_eq!(
        session.command("querypc name=\"%Thread0 Idle\" type=0x21"),
        "202- counter data follows"
    );
    assert_eq!(
        session.multiline(),
        ["type=0x00000021 vallo=0x00000500 valhi=0x00000000 ratelo=0x00002710 ratehi=0x00000000"]
    );
    // The instantaneous path writes value and type only.
    assert_eq!(
        session.command("querypc name=\"Debugger Pages\" type=1"),
        "202- counter data follows"
    );
    assert_eq!(
        session.multiline(),
        ["type=0x00000000 vallo=0x00001234 valhi=0x00000000 ratelo=0x00002710 ratehi=0x00000000"]
    );

    let sample = run(async {
        let mut client = server.client().await;
        client
            .run(QueryPerfCounter {
                name: "Debugger Pages".to_owned(),
                kind: 1,
            })
            .await
            .unwrap()
    });
    assert_eq!((sample.kind, sample.value, sample.rate), (0, 0x1234, 0));
}

#[test]
fn querypc_history_uses_the_sampled_slot() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        let counters = &mut host.backend.performance.counters;
        counters.frame_counter = Some(40);
        counters.sources[PAGES] = 100;
        counters.tick(1000);
        counters.sources[PAGES] = 160;
        counters.tick(1100);
    }
    let mut session = session(&server);
    session.command("querypc name=Frames type=0x51");
    assert_eq!(
        session.multiline(),
        ["type=0x00000051 vallo=0x00009c40 valhi=0x00000000 ratelo=0x0000044c ratehi=0x00000000"]
    );
    session.command("querypc name=\"Free Pages\" type=0x43");
    assert_eq!(
        session.multiline(),
        ["type=0x00000001 vallo=0x000000a0 valhi=0x00000000 ratelo=0x00000003 ratehi=0x00000000"]
    );
}

#[test]
fn querypc_errors() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("querypc type=1"), "400- missing name");
    assert_eq!(session.command("querypc name=Frames"), "400- missing type");
    assert_eq!(
        session.command("querypc name=Nothing type=1"),
        "414- access denied"
    );
    assert_eq!(
        session.command("querypc name=Frames type=0x21"),
        "417- type invalid"
    );
    assert_eq!(
        session.command("querypc name=Frames type=0x11"),
        "418- data not available"
    );
    assert_eq!(
        session.command("querypc name=\"Free Pages\" type=0x41"),
        "418- data not available"
    );
    server.host.lock().backend.performance.counters.directory = false;
    assert_eq!(
        session.command("querypc name=Frames type=1"),
        "402- file not found"
    );
}

/// Pixel bytes of the simulated front buffer.
fn pixel(x: u32, y: u32) -> [u8; 4] {
    [x as u8, y as u8, (x >> 8) as u8 ^ 0x5a, (x ^ y) as u8]
}

#[test]
fn screenshot_sends_the_header_then_whole_tiles() {
    let server = TestServer::start();
    let display = DisplayInformation {
        surface_width: 150,
        colorspace: 1,
        left: 40,
        top: 3,
        right: 110,
        bottom: 70,
        scaled_width: 1280,
        scaled_height: 720,
    };
    server.host.lock().backend.performance.display = Display::new(display, 0x0a00_0000, pixel);

    let mut session = session(&server);
    assert_eq!(
        session.command("screenshot"),
        "203- binary response follows"
    );
    // Tiles 1..=3 of rows 0..=2; the surface is 5 tiles wide.
    assert_eq!(
        session.line(),
        "pitch=0x00000280 width=0x00000046 height=0x00000043 format=0x98280186 offsetx=0x00000008 \
         offsety=0x00000003, framebuffersize=0x00009000 sw=0x00000500 sh=0x000002d0 colorspace=0x1"
    );
    let body = read_bytes(&mut session, 0x9000);
    let reads = server.host.lock().backend.performance.display.reads.clone();
    let row = 0x280 * 32;
    let base = 0x0a00_0000u32;
    let expected: Vec<u32> = (0..3)
        .flat_map(|tile_row| (1..4).map(move |tile| base + tile_row * row + tile * 0x1000))
        .collect();
    assert_eq!(reads, expected);
    assert_eq!(session.command("dmversion").get(..4), Some("200-"));

    let shot = run(async {
        let mut client = server.client().await;
        client.screenshot().await.unwrap()
    });
    assert_eq!(shot.data, body);
    let rgba = shot.to_rgba8().unwrap();
    for y in 0..67 {
        for x in 0..70 {
            let [b, g, r, _] = pixel(x + 40, y + 3);
            let at = ((y * 70 + x) * 4) as usize;
            assert_eq!(rgba[at..at + 4], [r, g, b, 0xff], "pixel {x},{y}");
        }
    }
}

#[test]
fn screenshot_of_an_empty_display_sends_no_body() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("screenshot"),
        "203- binary response follows"
    );
    assert_eq!(session.command("perfstat"), "200- PerfFreq=0x2FAF080");
}

#[test]
fn fixed_replies() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("pixpreview anything"),
        "423- HRESULT 0x82da0017"
    );
    assert_eq!(session.command("gpucount enable"), "200- OK");
    assert_eq!(session.command("gpucount disable"), "200- OK");
    assert_eq!(session.command("gpucount"), "407- unknown command");
}

#[test]
fn autoprof_reads_and_writes_the_profile_setting() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("autoprof"), "200- xuid==0q0000000000000000");
    assert_eq!(
        session.command("autoprof xuid=0q0009000006f1b2c3"),
        "200- OK"
    );
    assert_eq!(
        session.command("autoprof xuid=12"),
        "200- xuid==0q0009000006f1b2c3"
    );
    server
        .host
        .lock()
        .backend
        .system
        .hardware_flags
        .remove(HardwareFlags::AUTO_PROFILE);
    assert_eq!(session.command("autoprof"), "407- unknown command");
}

const CAPTURE_PATH: &str = "\\Device\\Harddisk0\\Partition1\\DEVKIT\\cap.cap";

#[test]
fn capctrl_replies_with_the_result() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("capctrl"), "400- HRESULT 0x82da0000");
    assert_eq!(session.command("capctrl start"), "400- HRESULT 0x80070057");
    assert_eq!(
        session.command("capctrl start name=nodrive"),
        "413- HRESULT 0x82da000d"
    );
    assert_eq!(
        session.command("capctrl start name=e:\\cap.cap buffersize=12x"),
        "435- HRESULT 0x82da0023"
    );
    assert!(
        server
            .host
            .lock()
            .backend
            .filesystem
            .entry(CAPTURE_PATH)
            .is_none()
    );
    assert_eq!(
        session.command("capctrl fastcapenabled"),
        "427- HRESULT 0x82da001b"
    );
    assert_eq!(
        session.command("capctrl callcapenabled"),
        "433- HRESULT 0x82da0021"
    );
    server.host.lock().backend.performance.capture.fast_cap = true;
    assert_eq!(
        session.command("capctrl fastcapenabled"),
        "207- HRESULT 0x02da0007"
    );
    assert_eq!(
        session.command("capctrl flags=0x80000005"),
        "200- HRESULT 0x02da0000"
    );
    assert_eq!(
        server.host.lock().backend.performance.capture.flags,
        CaptureFlags(5)
    );
    assert_eq!(
        session.command("capctrl profilingstatus"),
        "424- HRESULT 0x82da0018"
    );
    assert_eq!(session.command("capctrl abort"), "424- HRESULT 0x82da0018");
    assert_eq!(
        server
            .host
            .lock()
            .backend
            .performance
            .capture
            .previous_flags,
        CaptureFlags(5)
    );

    assert_eq!(
        session.command("capctrl start name=e:\\cap.cap buffersize=12x"),
        "200- HRESULT 0x02da0000"
    );
    assert_eq!(
        session.command("capctrl start name=e:\\other.cap"),
        "425- HRESULT 0x82da0019"
    );
    assert_eq!(
        session.command("capctrl profilingstatus"),
        "200- HRESULT 0x02da0000"
    );
    {
        let host = server.host.lock();
        let capture = &host.backend.performance.capture;
        let expected = CaptureSession {
            name: b"e:\\cap.cap".to_vec(),
            buffer_size: 12,
            recording: true,
        };
        assert_eq!(capture.session, Some(expected));
        assert!(capture.kernel_call_cap.is_empty());
    }
    assert_eq!(session.command("capctrl stop"), "200- HRESULT 0x02da0000");
    assert_eq!(
        session.command("capctrl profilingstatus"),
        "424- HRESULT 0x82da0018"
    );
    assert_eq!(session.command("capctrl stop"), "424- HRESULT 0x82da0018");

    let host = server.host.lock();
    let capture = &host.backend.performance.capture;
    assert_eq!(capture.written, [CAPTURE_PATH.as_bytes().to_vec()]);
    assert_eq!(capture.flags, CaptureFlags::IDLE);
}

#[test]
fn capctrl_call_cap_and_full_buffers() {
    let server = TestServer::start();
    let mut session = session(&server);
    server.host.lock().backend.performance.capture.call_cap = true;
    assert_eq!(
        session.command("capctrl callcapenabled"),
        "208- HRESULT 0x02da0008"
    );
    assert_eq!(
        session.command("capctrl start name=e:\\cap.cap"),
        "200- HRESULT 0x02da0000"
    );
    server.host.lock().backend.performance.capture.full = true;
    assert_eq!(
        session.command("capctrl profilingstatus"),
        "438- HRESULT 0x82da0026"
    );
    assert_eq!(session.command("capctrl stop"), "438- HRESULT 0x82da0026");
    {
        let host = server.host.lock();
        let capture = &host.backend.performance.capture;
        assert_eq!(capture.kernel_call_cap, [true, false]);
        assert_eq!(capture.previous_flags, CaptureFlags(0x8002_0000));
        assert_eq!(capture.written, [CAPTURE_PATH.as_bytes().to_vec()]);
    }

    assert_eq!(
        session.command("capctrl start name=e:\\cap.cap"),
        "200- HRESULT 0x02da0000"
    );
    server.host.lock().backend.performance.capture.full = true;
    assert_eq!(session.command("capctrl abort"), "200- HRESULT 0x02da0000");
    assert_eq!(
        session.command("capctrl profilingstatus"),
        "424- HRESULT 0x82da0018"
    );
    assert_eq!(
        server.host.lock().backend.performance.capture.written.len(),
        1
    );
}

#[test]
fn capctrl_hands_bit_31_sizes_to_the_title() {
    let server = TestServer::start();
    let mut session = session(&server);
    server.host.lock().backend.performance.capture.fast_cap = true;
    assert_eq!(
        session.command("capctrl start name=e:\\cap.cap buffersize=0x80400000"),
        "429- HRESULT 0x82da001d"
    );
    server.host.lock().backend.performance.capture.title_capture = Some(Hresult::OK);
    assert_eq!(
        session.command("capctrl start name=e:\\cap.cap buffersize=0x80400000"),
        "200- HRESULT 0x02da0000"
    );
    // A title answering 0 leaves the command without a status line; the
    // start clears the title-terminated mark.
    {
        let mut host = server.host.lock();
        let capture = &mut host.backend.performance.capture;
        capture.title_capture = Some(Hresult::NO_REPLY);
        capture.title_terminated = true;
    }
    session.send("capctrl start name=e:\\cap.cap buffersize=0x80400000");
    server.wait_until(|host| !host.backend.performance.capture.title_terminated);
    assert_eq!(
        session.command("capctrl profilingstatus"),
        "424- HRESULT 0x82da0018"
    );
    server.host.lock().backend.performance.capture.title_capture = Some(Hresult(0x0000_0035));
    assert_eq!(
        session.command("capctrl start name=e:\\cap.cap buffersize=0x80400000"),
        "200- HRESULT 0x00000035"
    );
    assert_eq!(server.host.lock().backend.performance.capture.session, None);
}

#[test]
fn lopctrl_tracks_the_running_profiler() {
    let server = TestServer::start();
    server.host.lock().backend.performance.cpu_profiler.info = CpuProfilerInfo {
        elapsed_time: 0x10,
        total_samples: 0x20,
        overhead_interrupts: 3,
    };
    let mut session = session(&server);
    assert_eq!(session.command("lopctrl"), "400- HRESULT 0x82da0000");
    assert_eq!(session.command("lopctrl info"), "424- HRESULT 0x82da0018");
    assert_eq!(session.command("lopctrl stop"), "424- HRESULT 0x82da0018");
    assert_eq!(session.command("lopctrl start"), "400- HRESULT 0x80070057");
    assert_eq!(
        session.command("lopctrl start name=e:\\a.cpu interval=5 flags=0x41"),
        "200- HRESULT 0x02da0000"
    );
    assert_eq!(
        session.command("lopctrl start name=e:\\b.cpu"),
        "425- HRESULT 0x82da0019"
    );
    assert_eq!(
        session.command("lopctrl info"),
        "200- elapsedTime=0x00000010 totalSamp=0x00000020 overheadInt=0x00000003"
    );
    server
        .host
        .lock()
        .backend
        .performance
        .cpu_profiler
        .stop_result = Err(ProfilerError::NotCounterOwner);
    assert_eq!(session.command("lopctrl stop"), "445- HRESULT 0x82da002d");
    server
        .host
        .lock()
        .backend
        .performance
        .cpu_profiler
        .initialize_result = Err(ProfilerError::NoKernel);
    assert_eq!(
        session.command("lopctrl start name=e:\\c.cpu"),
        "403- HRESULT 0x82da0003"
    );
    assert_eq!(session.command("lopctrl info"), "424- HRESULT 0x82da0018");
    server
        .host
        .lock()
        .backend
        .performance
        .cpu_profiler
        .initialize_result = Ok(());
    // A name without a drive has no object path; the engine reports the
    // writer thread failure and stays initialized.
    assert_eq!(
        session.command("lopctrl start name=a.cpu"),
        "400- HRESULT 0x82da0000"
    );
    assert_eq!(session.command("lopctrl info"), "424- HRESULT 0x82da0018");
    assert_eq!(
        session.command("lopctrl start name=e:\\d.cpu interval=7"),
        "200- HRESULT 0x02da0000"
    );

    let host = server.host.lock();
    let profiler = &host.backend.performance.cpu_profiler;
    assert_eq!(
        profiler.initializations,
        [ProfilerFlags(0x41), ProfilerFlags(0), ProfilerFlags(0)]
    );
    assert_eq!(profiler.abandons, 1);
    let started = [
        (
            b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\a.cpu".to_vec(),
            5,
        ),
        (
            b"\\Device\\Harddisk0\\Partition1\\DEVKIT\\d.cpu".to_vec(),
            7,
        ),
    ];
    assert_eq!(profiler.starts, started);
    assert_eq!(profiler.directories, started.map(|(path, _)| path));
}

#[test]
fn vd_accesses_encoder_and_gpu_registers() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("vd"), "423- HRESULT 0x82da0017");
    assert_eq!(session.command("vd cmd=other"), "200- OK");
    assert_eq!(session.command("vd cmd=PEEK addr=0x10"), "200- 0x10101010");
    assert_eq!(session.command("vd cmd=peek addr=0x123"), "200- 0x23");
    assert_eq!(
        session.command("vd cmd=peek addr=0x300"),
        "423- HRESULT 0x82da0017"
    );
    assert_eq!(
        session.command("vd cmd=poke addr=0x10 data=0x12345678"),
        "200- OK"
    );
    assert_eq!(session.command("vd cmd=peek addr=0x10"), "200- 0x12345678");
    assert_eq!(
        session.command("vd cmd=poke addr=0x110 data=0x100"),
        "423- HRESULT 0x82da0017"
    );
    assert_eq!(
        session.command("vd cmd=poke addr=0x210 data=0x7f"),
        "200- OK"
    );
    assert_eq!(
        session.command("vd cmd=gpoke addr=0x1740 data=7"),
        "200- OK"
    );
    assert_eq!(
        session.command("vd cmd=gpeek addr=0x1740"),
        "200- 0x00000007"
    );
    assert_eq!(
        session.command("vd cmd=gpeek addr=0xfffd"),
        "423- HRESULT 0x82da0017"
    );
    server.host.lock().backend.performance.video.extended = false;
    assert_eq!(
        session.command("vd cmd=peek addr=0x100"),
        "404- HRESULT 0x82da0004"
    );
    assert_eq!(
        server.host.lock().backend.performance.video.extended_writes,
        [(0x210, 0x7f)]
    );
}

#[test]
fn vd_edid_sends_one_block() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(
        session.command("vd cmd=edid block=0"),
        "203- binary response follows"
    );
    let block = read_bytes(&mut session, 0x80);
    assert_eq!(block[..3], [0xa5, 0xa4, 0xa7]);
    assert_eq!(
        session.command("vd cmd=edid block=1"),
        "429- HRESULT 0x82da001d"
    );
    assert_eq!(
        session.command("vd cmd=edid block=0x100"),
        "423- HRESULT 0x82da0017"
    );
    server.host.lock().backend.performance.video.edid = None;
    assert_eq!(
        session.command("vd cmd=edid block=0"),
        "407- HRESULT 0x82da0007"
    );
}

#[test]
fn xstudio_requires_the_exact_token() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("xstudio DedicateSocket"), "200- OK 36626");
    assert_eq!(session.command("xstudio dedicatesocket"), "200- NO");
    assert_eq!(session.command("xstudio DedicateSocketX"), "200- NO");
    assert_eq!(session.command("xstudio"), "200- NO");
    server.host.lock().backend.performance.studio_port = None;
    assert_eq!(session.command("xstudio DedicateSocket"), "200- NO");
}

#[test]
fn pixcmd_without_a_session_refuses_posts() {
    let server = TestServer::start();
    let mut session = session(&server);
    assert_eq!(session.command("pixcmd a"), "200- NO");
    assert_eq!(session.command("pixcmd o 1 7 9"), "200- BUSY");
    assert_eq!(session.command("pixcmd b"), "200- OK");
    assert_eq!(session.command("pixcmd z"), "200- NO");
    assert_eq!(session.command("pixcmd f"), "200- NO");
}

#[test]
fn pixcmd_posts_engine_messages() {
    let server = TestServer::start();
    {
        let mut host = server.host.lock();
        let pix = &mut host.backend.performance.pix;
        pix.session = true;
        pix.frame_number = 50;
        pix.status = [0x5308, 1, 0x2100, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        pix.dogma = Some(PixDogma {
            handle: 0x10,
            procedure_1: 0x20,
            info: 0x30,
            procedure_3: 0x40,
        });
        pix.frame_statistics = Some([1, 2, 3]);
    }
    let mut session = session(&server);
    assert_eq!(session.command("pixcmd c"), "200- OK");
    assert_eq!(session.command("pixcmd d 3,5"), "200- OK");
    assert_eq!(session.command("pixcmd d 60"), "200- OK");
    assert_eq!(session.command("pixcmd v 2 4 7"), "200- NO");
    assert_eq!(session.command("pixcmd v 2 4 7 8"), "200- OK");
    assert_eq!(session.command("pixcmd v 1 1 7 9"), "200- OK");
    assert_eq!(session.command("pixcmd o 1 2 999999999 4"), "200- NO");
    assert_eq!(session.command("pixcmd o 1 2 999999999"), "200- OK");
    assert_eq!(session.command("pixcmd h"), "200- OK");
    assert_eq!(session.command("pixcmd m 3"), "200- OK 1 2 3");
    assert_eq!(session.command("pixcmd q 6500"), "200- NO");
    assert_eq!(
        session.command("pixcmd q 6500 1"),
        "200- OK 21256 1 8448 3 4 5 6 7 10 8 9"
    );
    assert_eq!(session.command("pixcmd u 99"), "200- OK 0");
    assert_eq!(session.command("pixcmd y 00010021"), "200- OK");

    let host = server.host.lock();
    let pix = &host.backend.performance.pix;
    let queue: Vec<(u32, Vec<u32>)> = pix
        .queue
        .iter()
        .map(|message| (message.code, message.payload().to_vec()))
        .collect();
    assert_eq!(
        queue,
        [
            (1, vec![1, 1, 0]),
            (7, vec![47, 3, 1]),
            (0xc, vec![1, 1, 7, 9]),
            (6, vec![1, 0, 2, 2, 0, u32::MAX, 0, 0, 0x140_0000, 0, 1, 0]),
            (5, vec![1, 0, 1, 0x10, 0x20, 0x30, 0x40]),
        ]
    );
    assert_eq!(pix.events, [6]);
    assert_eq!(pix.bitmap, [0, 2]);
    assert!(!pix.legacy);
    assert_eq!(host.server.state.performance.pix.version, 6500);
    assert_eq!(PixMessage::new(3, &[0]).payload(), [0]);
}

#[test]
fn pixcmd_r_sends_the_trace_ring() {
    let server = TestServer::start();
    server.host.lock().backend.performance.pix.ring =
        (0..0x1806u32).map(|index| index as u8).collect();
    let mut session = session(&server);
    assert_eq!(session.command("pixcmd r"), "203- OK 6148");
    let data = read_bytes(&mut session, 0x1804);
    assert_eq!(data[0x1803], 0x03);
    assert_eq!(session.command("pixcmd r"), "203- OK 0");
    assert_eq!(session.command("pixcmd g"), "200- NO");
}
