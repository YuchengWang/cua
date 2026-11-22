// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Milestone 3 real-Xvfb E2E adversarial tests for `VirtualScreenManager`:
//! 1. Dual virtual screen concurrency (`:99` / `:100`), `0600` XAUTHORITY & VNC passwdfile,
//!    `-nolisten tcp` / no `-ac`, `-localhost -viewonly`, isolated env injection, and zero cross-talk.
//! 2. `Xvfb` `SIGKILL` crash simulation + `reap_stale_runtime()` zero-residue recovery.
//!
//! Run:
//! `cargo test -p platform-linux --test virtual_screen_m3_e2e_xorg -- --test-threads=1 --nocapture`

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use platform_linux::capture::screenshot_display_bytes_with_context;
use platform_linux::x11::composite_capture::{capture_window_composite, CompositeCaptureOutcome};
use platform_linux::x11::context::{global_screen_pool, DisplayTarget, X11ScreenContext};
use platform_linux::x11::virtual_screen::{CreateVirtualScreenRequest, VirtualScreenManager};
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::{
    ConnectionExt as _, CreateWindowAux, EventMask, WindowClass,
};

fn pid_alive(pid: u32) -> bool {
    if !PathBuf::from(format!("/proc/{pid}")).exists() {
        return false;
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    !stat.contains(") Z ")
}

fn assert_no_proc_or_zombie(pid: u32, label: &str) {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    if proc_dir.exists() {
        let stat = fs::read_to_string(proc_dir.join("stat")).unwrap_or_default();
        panic!("{label} (pid {pid}) still exists in /proc (possible <defunct> zombie): {stat}");
    }
}

fn read_proc_cmdline(pid: u32) -> String {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn create_solid_window(
    ctx: &X11ScreenContext,
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    rgb_pixel: u32,
) -> u32 {
    let win = ctx.conn.generate_id().unwrap();
    let screen = &ctx.conn.setup().roots[ctx.screen_num];
    ctx.conn
        .create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            win,
            screen.root,
            x,
            y,
            w,
            h,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new()
                .background_pixel(rgb_pixel)
                .override_redirect(1)
                .event_mask(EventMask::EXPOSURE),
        )
        .unwrap();
    ctx.conn.map_window(win).unwrap();
    ctx.conn.flush().unwrap();
    let _ = ctx.conn.get_input_focus().unwrap().reply();
    win
}

#[test]
fn m3_dual_virtual_screen_concurrency_security_and_isolation() {
    let mgr = Arc::new(VirtualScreenManager::new());

    let m1 = Arc::clone(&mgr);
    let t1 = thread::spawn(move || {
        m1.create(CreateVirtualScreenRequest {
            width: Some(1024),
            height: Some(768),
            preferred_display: None,
            enable_vnc: false,
            session_id: Some("e2e-sess-a".to_owned()),
            ..Default::default()
        })
        .expect("create virtual screen A")
    });

    let m2 = Arc::clone(&mgr);
    let t2 = thread::spawn(move || {
        m2.create(CreateVirtualScreenRequest {
            width: Some(800),
            height: Some(600),
            preferred_display: None,
            enable_vnc: true,
            session_id: Some("e2e-sess-b".to_owned()),
            ..Default::default()
        })
        .expect("create virtual screen B")
    });

    let s1 = t1.join().unwrap();
    let s2 = t2.join().unwrap();
    assert_ne!(s1.display_id, s2.display_id);
    assert_eq!(mgr.list().len(), 2);

    // 1. Security gate checks: 0600 XAUTHORITY, -nolisten tcp, no -ac, x11vnc -localhost -viewonly.
    for s in [&s1, &s2] {
        let mode = fs::metadata(&s.xauth_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "XAUTHORITY must be 0600");

        let xvfb_cmd = read_proc_cmdline(s.pid_xvfb);
        assert!(xvfb_cmd.contains("-nolisten tcp"), "Xvfb missing -nolisten tcp: {xvfb_cmd}");
        assert!(
            !xvfb_cmd.split_whitespace().any(|tok| tok == "-ac"),
            "Xvfb must never use -ac: {xvfb_cmd}"
        );
    }

    if let Some(vnc_pid) = s2.pid_x11vnc {
        let vnc_cmd = read_proc_cmdline(vnc_pid);
        assert!(vnc_cmd.contains("-localhost"), "x11vnc missing -localhost: {vnc_cmd}");
        assert!(vnc_cmd.contains("-viewonly"), "x11vnc missing -viewonly: {vnc_cmd}");
        assert!(vnc_cmd.contains("-passwdfile"), "x11vnc missing -passwdfile: {vnc_cmd}");
        assert!(!vnc_cmd.contains("-nopw"), "x11vnc must never use -nopw: {vnc_cmd}");
        let pw_path = s2.xauth_path.parent().unwrap().join("vnc.passwd");
        let pw_mode = fs::metadata(&pw_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(pw_mode, 0o600, "vnc.passwd must be 0600");
    }

    // 2. Session display routing & env injection verification.
    assert_eq!(
        mgr.resolve_display_for_session(Some("e2e-sess-a"), None).as_deref(),
        Some(s1.display_id.as_str())
    );
    assert_eq!(
        mgr.resolve_display_for_session(Some("e2e-sess-b"), None).as_deref(),
        Some(s2.display_id.as_str())
    );

    let env_dump_a = std::env::temp_dir().join(format!("cua_m3_env_a_{}.txt", std::process::id()));
    let env_dump_b = std::env::temp_dir().join(format!("cua_m3_env_b_{}.txt", std::process::id()));
    let _ = fs::remove_file(&env_dump_a);
    let _ = fs::remove_file(&env_dump_b);

    let app_a = mgr
        .launch_app(
            &s1.display_id,
            "sh",
            &[
                "-c".to_owned(),
                format!("env > {}", env_dump_a.display()),
            ],
            &HashMap::new(),
        )
        .expect("launch_app on screen A");
    let app_b = mgr
        .launch_app(
            &s2.display_id,
            "sh",
            &[
                "-c".to_owned(),
                format!("env > {}", env_dump_b.display()),
            ],
            &HashMap::new(),
        )
        .expect("launch_app on screen B");
    let app_sleep = mgr
        .launch_app(
            &s1.display_id,
            "sleep",
            &["30".to_owned()],
            &HashMap::new(),
        )
        .expect("launch long-lived sleep app on screen A");

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && (!env_dump_a.exists() || !env_dump_b.exists()) {
        thread::sleep(Duration::from_millis(50));
    }
    let env_a = fs::read_to_string(&env_dump_a).unwrap_or_default();
    let env_b = fs::read_to_string(&env_dump_b).unwrap_or_default();
    let _ = fs::remove_file(&env_dump_a);
    let _ = fs::remove_file(&env_dump_b);

    assert!(env_a.contains(&format!("DISPLAY={}", s1.display_id)));
    assert!(env_a.contains(&format!("XAUTHORITY={}", s1.xauth_path.display())));
    assert!(env_a.contains("_JAVA_AWT_WM_NONREPARENTING=1"));
    assert!(env_a.contains("GTK_IM_MODULE=xim"));

    assert!(env_b.contains(&format!("DISPLAY={}", s2.display_id)));
    assert!(env_b.contains(&format!("XAUTHORITY={}", s2.xauth_path.display())));

    // 3. Cross-screen display capture & occluded XComposite capture isolation.
    let ctx1 = global_screen_pool()
        .get_or_connect_explicit(
            &DisplayTarget::Virtual(s1.display_id.clone()),
            Some(&s1.xauth_path),
            s1.dbus_address.as_deref(),
        )
        .unwrap();
    let ctx2 = global_screen_pool()
        .get_or_connect_explicit(
            &DisplayTarget::Virtual(s2.display_id.clone()),
            Some(&s2.xauth_path),
            s2.dbus_address.as_deref(),
        )
        .unwrap();

    let png1 = screenshot_display_bytes_with_context(&ctx1).expect("capture screen 1");
    let png2 = screenshot_display_bytes_with_context(&ctx2).expect("capture screen 2");
    let img1 = image::load_from_memory(&png1).unwrap();
    let img2 = image::load_from_memory(&png2).unwrap();
    assert_eq!((img1.width(), img1.height()), (1024, 768));
    assert_eq!((img2.width(), img2.height()), (800, 600));

    let win1_bg = create_solid_window(&ctx1, 10, 10, 100, 100, 0x0000_FF00);
    let _win1_fg = create_solid_window(&ctx1, 0, 0, 200, 200, 0x00FF_0000);
    let win2_bg = create_solid_window(&ctx2, 10, 10, 100, 100, 0x0000_00FF);
    let _win2_fg = create_solid_window(&ctx2, 0, 0, 200, 200, 0x00FF_0000);
    thread::sleep(Duration::from_millis(80));

    let cap1 = match capture_window_composite(&ctx1.conn, win1_bg).unwrap() {
        CompositeCaptureOutcome::Captured(b) => image::load_from_memory(&b).unwrap().to_rgba8(),
        other => panic!("unexpected fallback on screen 1: {other:?}"),
    };
    let cap2 = match capture_window_composite(&ctx2.conn, win2_bg).unwrap() {
        CompositeCaptureOutcome::Captured(b) => image::load_from_memory(&b).unwrap().to_rgba8(),
        other => panic!("unexpected fallback on screen 2: {other:?}"),
    };
    assert!(cap1.get_pixel(50, 50)[1] > 200);
    assert!(cap2.get_pixel(50, 50)[2] > 200);

    // 4. Clean teardown via SessionEndHook + destroy(), zero residue.
    mgr.destroy_for_session("e2e-sess-a");
    mgr.destroy(&s2.display_id).unwrap();
    assert!(mgr.list().is_empty());

    thread::sleep(Duration::from_millis(100));
    for s in [&s1, &s2] {
        assert_no_proc_or_zombie(s.pid_xvfb, "Xvfb");
        if let Some(pid) = s.pid_openbox {
            assert_no_proc_or_zombie(pid, "openbox");
        }
        if let Some(pid) = s.pid_dbus {
            assert_no_proc_or_zombie(pid, "dbus-daemon");
        }
        if let Some(pid) = s.pid_autocutsel {
            assert_no_proc_or_zombie(pid, "autocutsel");
        }
        if let Some(pid) = s.pid_x11vnc {
            assert_no_proc_or_zombie(pid, "x11vnc");
        }
        assert!(!PathBuf::from(format!("/tmp/.X11-unix/X{}", s.display_num)).exists());
        assert!(!PathBuf::from(format!("/tmp/.X{}-lock", s.display_num)).exists());
        assert!(!s.xauth_path.exists());
    }
    assert_no_proc_or_zombie(app_a.pid, "launched app A");
    assert_no_proc_or_zombie(app_b.pid, "launched app B");
    assert_no_proc_or_zombie(app_sleep.pid, "launched sleep app");
}

#[test]
fn m3_xvfb_sigkill_crash_reap_stale_runtime_zero_residue() {
    // Simulate a daemon crash where VirtualScreenManager is dropped via forget()
    // and Xvfb is killed with SIGKILL, leaving orphaned openbox/dbus/lock/socket.
    let mgr1 = VirtualScreenManager::new();
    let info = mgr1
        .create(CreateVirtualScreenRequest {
            width: Some(640),
            height: Some(480),
            preferred_display: None,
            enable_vnc: false,
            session_id: Some("crash-test".to_owned()),
            ..Default::default()
        })
        .expect("create screen for SIGKILL crash test");
    std::mem::forget(mgr1);

    unsafe {
        libc::kill(info.pid_xvfb as libc::pid_t, libc::SIGKILL);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && pid_alive(info.pid_xvfb) {
        thread::sleep(Duration::from_millis(30));
    }
    assert!(!pid_alive(info.pid_xvfb), "Xvfb should be dead after SIGKILL");

    let mgr2 = VirtualScreenManager::new();
    let reaped = mgr2.reap_stale_runtime();
    assert!(reaped >= 1, "reap_stale_runtime should reap crashed display");

    thread::sleep(Duration::from_millis(100));
    if let Some(pid) = info.pid_openbox {
        assert!(!pid_alive(pid), "orphan openbox should be reaped");
    }
    if let Some(pid) = info.pid_dbus {
        assert!(!pid_alive(pid), "orphan dbus-daemon should be reaped");
    }
    if let Some(pid) = info.pid_autocutsel {
        assert!(!pid_alive(pid), "orphan autocutsel should be reaped");
    }
    assert!(!PathBuf::from(format!("/tmp/.X11-unix/X{}", info.display_num)).exists());
    assert!(!PathBuf::from(format!("/tmp/.X{}-lock", info.display_num)).exists());
    assert!(!info.xauth_path.exists());

    // Confirm the same display number can be cleanly re-allocated after recovery.
    let recovered = mgr2
        .create(CreateVirtualScreenRequest {
            width: Some(640),
            height: Some(480),
            preferred_display: Some(info.display_num),
            enable_vnc: false,
            session_id: None,
            ..Default::default()
        })
        .expect("re-create screen after crash recovery");
    assert_eq!(recovered.display_num, info.display_num);
    mgr2.destroy(&recovered.display_id).unwrap();
}
