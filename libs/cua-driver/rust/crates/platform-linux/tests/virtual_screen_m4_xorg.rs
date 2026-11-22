// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Milestone 4 real-Xvfb E2E tests:
//! 1. Virtual-screen XTest click/key delivery + CJK `xtest_type_text` clipboard save/restore.
//! 2. Isolated `get/set/sync_clipboard` between two virtual screens (no auto-sync).
//! 3. `OverrideRedirect` viewable popup window enumeration via `list_windows_with_context`.
//!
//! Run:
//! `cargo test -p platform-linux --test virtual_screen_m4_xorg -- --test-threads=1 --nocapture`

#![cfg(target_os = "linux")]

use std::thread;
use std::time::{Duration, Instant};

use platform_linux::x11::context::{global_screen_pool, DisplayTarget};
use platform_linux::x11::list_windows_with_context;
use platform_linux::x11::virtual_input::{
    clipboard_get_for_context, clipboard_set_for_context, xtest_click, xtest_type_text,
};
use platform_linux::x11::virtual_screen::{CreateVirtualScreenRequest, VirtualScreenManager};
use serde_json::json;
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, WindowClass,
};
use x11rb::protocol::Event;

#[test]
fn m4_xtest_click_and_cjk_clipboard_roundtrip() {
    let mgr = VirtualScreenManager::new();
    let s1 = mgr
        .create(CreateVirtualScreenRequest {
            width: Some(800),
            height: Some(600),
            preferred_display: None,
            enable_vnc: false,
            session_id: Some("m4-xtest".to_owned()),
        })
        .expect("create virtual screen");

    let ctx = global_screen_pool()
        .get_or_connect_explicit(
            &DisplayTarget::Virtual(s1.display_id.clone()),
            Some(&s1.xauth_path),
            s1.dbus_address.as_deref(),
        )
        .unwrap();

    // Create a window listening for ButtonPress and KeyPress.
    let win = ctx.conn.generate_id().unwrap();
    let screen = &ctx.conn.setup().roots[ctx.screen_num];
    ctx.conn
        .create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            win,
            screen.root,
            50,
            50,
            300,
            200,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new()
                .background_pixel(0x0022_4466)
                .override_redirect(1)
                .event_mask(EventMask::BUTTON_PRESS | EventMask::KEY_PRESS),
        )
        .unwrap();
    ctx.conn.map_window(win).unwrap();
    ctx.conn
        .set_input_focus(x11rb::protocol::xproto::InputFocus::POINTER_ROOT, win, x11rb::CURRENT_TIME)
        .unwrap();
    ctx.conn.flush().unwrap();
    thread::sleep(Duration::from_millis(60));

    // Drain any initial events.
    while let Ok(Some(_)) = ctx.conn.poll_for_event() {}

    // 1. XTest click inside the window at (120, 120).
    xtest_click(&ctx, 120, 120, 1).expect("xtest_click");
    let mut got_button = false;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Ok(Some(Event::ButtonPress(bp))) = ctx.conn.poll_for_event() {
            assert_eq!(bp.detail, 1);
            assert_eq!(bp.root_x, 120);
            assert_eq!(bp.root_y, 120);
            got_button = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(got_button, "virtual screen window did not receive XTest ButtonPress");

    // 2. Non-ASCII & mixed ASCII+CJK text typing delivers Ctrl+V and preserves prior CLIPBOARD content.
    platform_linux::x11::virtual_input::xtest_focus_window(&ctx, u64::from(win))
        .expect("focus test window");
    clipboard_set_for_context(&ctx, "prev-clip-99").expect("seed prior clipboard");
    while let Ok(Some(_)) = ctx.conn.poll_for_event() {}
    xtest_type_text(&ctx, "AUDIT_测试_123").expect("xtest_type_text mixed ASCII+CJK");
    let mut key_presses = 0usize;
    let key_deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < key_deadline {
        match ctx.conn.poll_for_event() {
            Ok(Some(Event::KeyPress(_))) => key_presses += 1,
            Ok(Some(_)) => {}
            _ => {
                if key_presses >= 2 {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
        }
    }
    assert!(
        key_presses >= 2,
        "expected Ctrl+V KeyPress events for mixed ASCII+CJK paste, got {key_presses}"
    );
    let restored = clipboard_get_for_context(&ctx).expect("read restored clipboard");
    assert_eq!(
        restored, "prev-clip-99",
        "xtest_type_text must restore previous clipboard after Ctrl+V"
    );

    mgr.destroy(&s1.display_id).unwrap();
}

#[test]
fn m4_isolated_clipboard_tools_and_override_redirect_enumeration() {
    let mgr = VirtualScreenManager::new();
    let s1 = mgr
        .create(CreateVirtualScreenRequest {
            width: Some(640),
            height: Some(480),
            preferred_display: None,
            enable_vnc: false,
            session_id: Some("m4-cb-1".to_owned()),
        })
        .unwrap();
    let s2 = mgr
        .create(CreateVirtualScreenRequest {
            width: Some(640),
            height: Some(480),
            preferred_display: None,
            enable_vnc: false,
            session_id: Some("m4-cb-2".to_owned()),
        })
        .unwrap();

    let ctx1 = global_screen_pool()
        .get_or_connect_explicit(
            &DisplayTarget::Virtual(s1.display_id.clone()),
            Some(&s1.xauth_path),
            s1.dbus_address.as_deref(),
        )
        .unwrap();

    // 1. OverrideRedirect popup window enumeration.
    let popup = ctx1.conn.generate_id().unwrap();
    let screen = &ctx1.conn.setup().roots[ctx1.screen_num];
    ctx1.conn
        .create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            popup,
            screen.root,
            10,
            10,
            180,
            90,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new()
                .background_pixel(0x00FF_EEAA)
                .override_redirect(1),
        )
        .unwrap();
    ctx1.conn
        .change_property(
            PropMode::REPLACE,
            popup,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            8,
            b"cua-override-menu".len() as u32,
            b"cua-override-menu",
        )
        .unwrap();
    ctx1.conn.map_window(popup).unwrap();
    ctx1.conn.flush().unwrap();
    let _ = ctx1.conn.get_input_focus().unwrap().reply();

    let wins = list_windows_with_context(&ctx1, None);
    assert!(
        wins.iter().any(|w| w.xid == u64::from(popup)),
        "list_windows_with_context must include viewable OverrideRedirect popup: {wins:?}"
    );

    // 2. Isolated clipboard MCP tools (no automatic cross-screen sync).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let registry = platform_linux::register_tools();

        let r1 = registry
            .invoke(
                "set_clipboard",
                json!({ "display_id": s1.display_id, "text": "隔离剪贴板-S1" }),
            )
            .await;
        assert_ne!(r1.is_error, Some(true), "set_clipboard s1 failed: {:?}", r1);

        let r2 = registry
            .invoke(
                "set_clipboard",
                json!({ "display_id": s2.display_id, "text": "isolated-s2" }),
            )
            .await;
        assert_ne!(r2.is_error, Some(true), "set_clipboard s2 failed: {:?}", r2);

        let g2 = registry
            .invoke("get_clipboard", json!({ "display_id": s2.display_id }))
            .await;
        assert_eq!(g2.structured_content.as_ref().unwrap()["text"], "isolated-s2");

        let sync_res = registry
            .invoke(
                "sync_clipboard",
                json!({
                    "source_display_id": s1.display_id,
                    "target_display_id": s2.display_id
                }),
            )
            .await;
        assert_ne!(sync_res.is_error, Some(true), "sync_clipboard failed: {:?}", sync_res);

        let g2_after = registry
            .invoke("get_clipboard", json!({ "display_id": s2.display_id }))
            .await;
        assert_eq!(
            g2_after.structured_content.as_ref().unwrap()["text"],
            "隔离剪贴板-S1"
        );
    });

    mgr.destroy(&s1.display_id).unwrap();
    mgr.destroy(&s2.display_id).unwrap();
}
