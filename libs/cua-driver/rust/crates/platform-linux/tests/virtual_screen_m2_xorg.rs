// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Milestone 2 real-Xvfb verification tests for `X11ScreenPool`, `X11ScreenContext`,
//! `xauth::resolve_for_display`, and `composite_capture::capture_window_composite`.
//!
//! Run:
//! `cargo test -p platform-linux --test virtual_screen_m2_xorg -- --test-threads=1 --nocapture`

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use platform_linux::x11::composite_capture::{capture_window_composite, CompositeCaptureOutcome};
use platform_linux::x11::context::{DisplayTarget, X11ScreenContext, X11ScreenPool};
use x11rb::connection::Connection as _;
use x11rb::protocol::res::ConnectionExt as _;
use x11rb::protocol::xproto::{
    ChangeWindowAttributesAux, ConnectionExt as _, CreateWindowAux, EventMask, WindowClass,
};

struct XvfbGuard {
    display_num: u16,
    display_id: String,
    xauth_path: PathBuf,
    temp_dir: PathBuf,
    child: Child,
}

impl XvfbGuard {
    fn spawn(preferred_start: u16) -> Self {
        let display_num = find_free_display(preferred_start)
            .expect("no free X11 display found in :99..:199");
        let display_id = format!(":{display_num}");

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "cua_m2_test_{}_{}_{}",
            std::process::id(),
            display_num,
            nonce
        ));
        fs::create_dir_all(&temp_dir).expect("create temp dir for Xvfb test");
        let xauth_path = temp_dir.join("Xauthority");
        fs::File::create(&xauth_path).expect("create Xauthority file");
        fs::set_permissions(&xauth_path, fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 Xauthority");

        let cookie = format!("{:032x}", nonce ^ ((display_num as u128) << 64));
        let status = Command::new("xauth")
            .arg("-f")
            .arg(&xauth_path)
            .arg("add")
            .arg(&display_id)
            .arg(".")
            .arg(&cookie)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run xauth add");
        assert!(status.success(), "xauth add failed for {display_id}");

        let child = Command::new("Xvfb")
            .arg(&display_id)
            .args([
                "-screen",
                "0",
                "640x480x24",
                "-auth",
            ])
            .arg(&xauth_path)
            .args([
                "+extension",
                "COMPOSITE",
                "+extension",
                "XTEST",
                "+extension",
                "MIT-SHM",
                "-nolisten",
                "tcp",
                "-s",
                "0",
                "-dpms",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn Xvfb");

        let guard = Self {
            display_num,
            display_id: display_id.clone(),
            xauth_path,
            temp_dir,
            child,
        };

        let sock = PathBuf::from(format!("/tmp/.X11-unix/X{display_num}"));
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if sock.exists()
                && X11ScreenContext::connect(&DisplayTarget::Virtual(display_id.clone())).is_ok()
            {
                return guard;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("Xvfb {display_id} did not become ready within 5s");
    }
}

impl Drop for XvfbGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn find_free_display(start: u16) -> Option<u16> {
    (start..=199).find(|n| {
        let sock = PathBuf::from(format!("/tmp/.X11-unix/X{n}"));
        let lock = PathBuf::from(format!("/tmp/.X{n}-lock"));
        !sock.exists() && !lock.exists()
    })
}

fn create_solid_window(
    ctx: &X11ScreenContext,
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    rgb_pixel: u32,
    map_now: bool,
) -> u32 {
    let win = ctx.conn.generate_id().unwrap();
    let screen = &ctx.conn.setup().roots[ctx.screen_num];
    let root = screen.root;
    let root_visual = screen.root_visual;
    ctx.conn
        .create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            win,
            root,
            x,
            y,
            w,
            h,
            0,
            WindowClass::INPUT_OUTPUT,
            root_visual,
            &CreateWindowAux::new()
                .background_pixel(rgb_pixel)
                .override_redirect(1)
                .event_mask(EventMask::EXPOSURE),
        )
        .unwrap();
    if map_now {
        ctx.conn.map_window(win).unwrap();
    }
    ctx.conn.flush().unwrap();
    let _ = ctx.conn.get_input_focus().unwrap().reply();
    win
}

#[test]
fn m2_dual_virtual_screen_pool_isolation_and_concurrency() {
    let g1 = XvfbGuard::spawn(99);
    let g2 = XvfbGuard::spawn(g1.display_num + 1);

    // Verify 0600 permissions on both XAUTHORITY files.
    for path in [&g1.xauth_path, &g2.xauth_path] {
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "XAUTHORITY must be 0600: {}", path.display());
    }

    let env_display_before = std::env::var_os("DISPLAY");
    let env_xauth_before = std::env::var_os("XAUTHORITY");

    let pool = Arc::new(X11ScreenPool::new());
    let d1 = g1.display_id.clone();
    let d2 = g2.display_id.clone();
    let x1 = g1.xauth_path.clone();
    let x2 = g2.xauth_path.clone();

    let p1 = Arc::clone(&pool);
    let p2 = Arc::clone(&pool);
    let t1 = thread::spawn(move || {
        let ctx = p1
            .get_or_connect(&DisplayTarget::Virtual(d1.clone()))
            .expect("connect virtual screen 1");
        assert_eq!(ctx.display_id, d1);
        assert_eq!(ctx.xauth_path.as_deref(), Some(x1.as_path()));
        assert!(ctx.shm_session.is_some());
    });
    let t2 = thread::spawn(move || {
        let ctx = p2
            .get_or_connect(&DisplayTarget::Virtual(d2.clone()))
            .expect("connect virtual screen 2");
        assert_eq!(ctx.display_id, d2);
        assert_eq!(ctx.xauth_path.as_deref(), Some(x2.as_path()));
        assert!(ctx.shm_session.is_some());
    });
    t1.join().unwrap();
    t2.join().unwrap();

    assert_eq!(std::env::var_os("DISPLAY"), env_display_before);
    assert_eq!(std::env::var_os("XAUTHORITY"), env_xauth_before);

    let cached = pool.cached_displays();
    assert!(cached.contains(&g1.display_id));
    assert!(cached.contains(&g2.display_id));

    pool.invalidate(&g1.display_id);
    assert!(!pool.cached_displays().contains(&g1.display_id));
    assert!(pool
        .get_or_connect(&DisplayTarget::Virtual(g1.display_id.clone()))
        .is_ok());
}

#[test]
fn m2_xcomposite_occluded_window_capture() {
    let g = XvfbGuard::spawn(99);
    let ctx = X11ScreenContext::connect(&DisplayTarget::Virtual(g.display_id.clone())).unwrap();

    // Bottom window: pure green (0x00FF00), 120x120 at (20, 20).
    let bg_win = create_solid_window(&ctx, 20, 20, 120, 120, 0x0000_FF00, true);
    // Top window: pure red (0xFF0000), 200x200 at (0, 0), completely occluding bg_win.
    let _fg_win = create_solid_window(&ctx, 0, 0, 200, 200, 0x00FF_0000, true);
    thread::sleep(Duration::from_millis(80));

    let outcome = capture_window_composite(&ctx.conn, bg_win).expect("composite capture");
    let png = match outcome {
        CompositeCaptureOutcome::Captured(bytes) => bytes,
        CompositeCaptureOutcome::UnmappedFallback { reason } => {
            panic!("expected Captured for mapped occluded window, got UnmappedFallback: {reason}");
        }
    };

    let img = image::load_from_memory(&png)
        .expect("decode PNG")
        .to_rgba8();
    assert_eq!(img.width(), 120);
    assert_eq!(img.height(), 120);
    let center = img.get_pixel(60, 60);
    assert!(
        center[1] > 200 && center[0] < 50 && center[2] < 50,
        "expected green occluded window pixel, got {:?}",
        center
    );
}

#[test]
fn m2_xcomposite_unmapped_window_graceful_fallback() {
    let g = XvfbGuard::spawn(99);
    let ctx = X11ScreenContext::connect(&DisplayTarget::Virtual(g.display_id.clone())).unwrap();

    let win = create_solid_window(&ctx, 10, 10, 100, 100, 0x0000_00FF, false);
    let outcome = capture_window_composite(&ctx.conn, win).expect("capture unmapped");
    assert!(
        matches!(outcome, CompositeCaptureOutcome::UnmappedFallback { .. }),
        "expected UnmappedFallback for unmapped window, got {outcome:?}"
    );

    ctx.conn.map_window(win).unwrap();
    ctx.conn.flush().unwrap();
    let _ = ctx.conn.get_input_focus().unwrap().reply();
    assert!(matches!(
        capture_window_composite(&ctx.conn, win).unwrap(),
        CompositeCaptureOutcome::Captured(_)
    ));

    ctx.conn.unmap_window(win).unwrap();
    ctx.conn
        .change_window_attributes(win, &ChangeWindowAttributesAux::new())
        .unwrap();
    ctx.conn.flush().unwrap();
    let _ = ctx.conn.get_input_focus().unwrap().reply();

    let outcome_after_unmap =
        capture_window_composite(&ctx.conn, win).expect("capture after unmap");
    assert!(
        matches!(
            outcome_after_unmap,
            CompositeCaptureOutcome::UnmappedFallback { .. }
        ),
        "expected UnmappedFallback after unmap, got {outcome_after_unmap:?}"
    );
}

#[test]
fn m2_xcomposite_pixmap_guard_no_leak() {
    let g = XvfbGuard::spawn(99);
    let ctx = X11ScreenContext::connect(&DisplayTarget::Virtual(g.display_id.clone())).unwrap();
    let win = create_solid_window(&ctx, 0, 0, 160, 120, 0x0011_2233, true);
    thread::sleep(Duration::from_millis(50));

    // Warm up once (CompositeRedirectWindow + backing pixmap allocation).
    assert!(matches!(
        capture_window_composite(&ctx.conn, win).unwrap(),
        CompositeCaptureOutcome::Captured(_)
    ));

    let client_id_base = ctx.conn.setup().resource_id_base;
    let baseline = ctx
        .conn
        .res_query_client_pixmap_bytes(client_id_base)
        .ok()
        .and_then(|c| c.reply().ok())
        .map(|r| r.bytes);

    for _ in 0..20 {
        let outcome = capture_window_composite(&ctx.conn, win).unwrap();
        assert!(matches!(outcome, CompositeCaptureOutcome::Captured(_)));
    }
    let _ = ctx.conn.get_input_focus().unwrap().reply();

    if let Some(base_bytes) = baseline {
        let after_bytes = ctx
            .conn
            .res_query_client_pixmap_bytes(client_id_base)
            .unwrap()
            .reply()
            .unwrap()
            .bytes;
        assert_eq!(
            after_bytes, base_bytes,
            "PixmapGuard leaked pixmaps: baseline={base_bytes}, after={after_bytes}"
        );
    }

    // Keep Path imported without warning if unused in some cfg.
    let _: &Path = &g.xauth_path;
}
