// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Cua AI, Inc.

//! XTest-based input injection on an explicit [`X11ScreenContext`] (used for
//! isolated virtual X11 displays so Java/Swing, TWS, and Electron apps receive
//! real X11 events without touching the host's primary display).
//!
//! Non-ASCII / CJK text is typed via isolated CLIPBOARD save -> UTF-8 write ->
//! Ctrl+V -> CLIPBOARD restore, falling back gracefully when clipboard tools
//! are absent.

use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use x11rb::connection::Connection as _;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::wrapper::ConnectionExt as _;

use crate::x11::context::X11ScreenContext;

const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const MOTION_NOTIFY: u8 = 6;

/// Move the pointer to `(x, y)` on `ctx`.
pub fn xtest_move_cursor(ctx: &X11ScreenContext, x: i16, y: i16) -> Result<()> {
    let root = ctx.root_window();
    ctx.conn
        .xtest_fake_input(MOTION_NOTIFY, 0, 0, root, x, y, 0)?
        .check()?;
    ctx.conn.flush()?;
    Ok(())
}

/// Click mouse `button` (`1` = left, `2` = middle, `3` = right) at `(x, y)`.
pub fn xtest_click(ctx: &X11ScreenContext, x: i16, y: i16, button: u8) -> Result<()> {
    let root = ctx.root_window();
    ctx.conn
        .xtest_fake_input(MOTION_NOTIFY, 0, 0, root, x, y, 0)?;
    ctx.conn
        .xtest_fake_input(BUTTON_PRESS, button, 0, root, x, y, 0)?;
    ctx.conn
        .xtest_fake_input(BUTTON_RELEASE, button, 0, root, x, y, 0)?;
    ctx.conn.sync()?;
    Ok(())
}

/// Double-click mouse `button` at `(x, y)`.
pub fn xtest_double_click(ctx: &X11ScreenContext, x: i16, y: i16, button: u8) -> Result<()> {
    xtest_click(ctx, x, y, button)?;
    std::thread::sleep(Duration::from_millis(40));
    xtest_click(ctx, x, y, button)?;
    Ok(())
}

/// Drag mouse `button` from `(x1, y1)` to `(x2, y2)`.
pub fn xtest_drag(
    ctx: &X11ScreenContext,
    x1: i16,
    y1: i16,
    x2: i16,
    y2: i16,
    button: u8,
) -> Result<()> {
    let root = ctx.root_window();
    ctx.conn
        .xtest_fake_input(MOTION_NOTIFY, 0, 0, root, x1, y1, 0)?;
    ctx.conn
        .xtest_fake_input(BUTTON_PRESS, button, 0, root, x1, y1, 0)?;
    ctx.conn.flush()?;
    std::thread::sleep(Duration::from_millis(20));
    ctx.conn
        .xtest_fake_input(MOTION_NOTIFY, 0, 0, root, x2, y2, 0)?;
    ctx.conn
        .xtest_fake_input(BUTTON_RELEASE, button, 0, root, x2, y2, 0)?;
    ctx.conn.sync()?;
    Ok(())
}

/// Scroll vertically (`dy > 0` up / `< 0` down) or horizontally (`dx`) at `(x, y)`.
pub fn xtest_scroll(ctx: &X11ScreenContext, x: i16, y: i16, dx: i32, dy: i32) -> Result<()> {
    let root = ctx.root_window();
    ctx.conn
        .xtest_fake_input(MOTION_NOTIFY, 0, 0, root, x, y, 0)?;
    let emit_wheel = |button: u8, count: i32| -> Result<()> {
        for _ in 0..count.abs() {
            ctx.conn
                .xtest_fake_input(BUTTON_PRESS, button, 0, root, x, y, 0)?;
            ctx.conn
                .xtest_fake_input(BUTTON_RELEASE, button, 0, root, x, y, 0)?;
        }
        Ok(())
    };
    if dy > 0 {
        emit_wheel(4, dy)?;
    } else if dy < 0 {
        emit_wheel(5, dy)?;
    }
    if dx < 0 {
        emit_wheel(6, dx)?;
    } else if dx > 0 {
        emit_wheel(7, dx)?;
    }
    ctx.conn.sync()?;
    Ok(())
}

/// Press and release a key by X11 keyname (e.g. `"Return"`, `"Escape"`, `"Tab"`, `"a"`).
pub fn xtest_press_key(ctx: &X11ScreenContext, key: &str) -> Result<()> {
    let (keycode, shift) = resolve_key_to_keycode(ctx, key)?;
    let root = ctx.root_window();
    let shift_kc = if shift {
        find_keycode_for_keysym(ctx, 0xFFE1).map(|(kc, _)| kc)
    } else {
        None
    };

    if let Some(sk) = shift_kc {
        ctx.conn.xtest_fake_input(KEY_PRESS, sk, 0, root, 0, 0, 0)?;
    }
    ctx.conn
        .xtest_fake_input(KEY_PRESS, keycode, 0, root, 0, 0, 0)?;
    ctx.conn
        .xtest_fake_input(KEY_RELEASE, keycode, 0, root, 0, 0, 0)?;
    if let Some(sk) = shift_kc {
        ctx.conn
            .xtest_fake_input(KEY_RELEASE, sk, 0, root, 0, 0, 0)?;
    }
    ctx.conn.sync()?;
    Ok(())
}

/// Press a hotkey chord such as `["ctrl", "c"]` or `["alt", "F4"]`.
pub fn xtest_hotkey(ctx: &X11ScreenContext, keys: &[String]) -> Result<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let root = ctx.root_window();
    let mut keycodes = Vec::with_capacity(keys.len());
    for k in keys {
        let (kc, _) = resolve_key_to_keycode(ctx, k)?;
        keycodes.push(kc);
    }
    for &kc in &keycodes {
        ctx.conn.xtest_fake_input(KEY_PRESS, kc, 0, root, 0, 0, 0)?;
    }
    for &kc in keycodes.iter().rev() {
        ctx.conn
            .xtest_fake_input(KEY_RELEASE, kc, 0, root, 0, 0, 0)?;
    }
    ctx.conn.sync()?;
    Ok(())
}

/// Type UTF-8 text on `ctx`.
/// Pure ASCII uses XTest keystrokes; non-ASCII uses isolated clipboard
/// save -> write -> Ctrl+V -> restore so CJK/Unicode text works reliably.
pub fn xtest_type_text(ctx: &X11ScreenContext, text: &str) -> Result<()> {
    if text.is_ascii() {
        for ch in text.chars() {
            let key_str = match ch {
                '\n' | '\r' => "Return".to_owned(),
                '\t' => "Tab".to_owned(),
                ' ' => "space".to_owned(),
                _ => ch.to_string(),
            };
            xtest_press_key(ctx, &key_str)?;
        }
        return Ok(());
    }

    // Non-ASCII: save CLIPBOARD -> write target text -> Ctrl+V -> restore.
    let saved = clipboard_get_for_context(ctx).ok();
    clipboard_set_for_context(ctx, text)
        .context("failed to write non-ASCII text to virtual display clipboard")?;
    std::thread::sleep(Duration::from_millis(30));
    let paste_res = xtest_hotkey(ctx, &["ctrl".to_owned(), "v".to_owned()]);
    std::thread::sleep(Duration::from_millis(50));
    if let Some(prev) = saved {
        let _ = clipboard_set_for_context(ctx, &prev);
    }
    paste_res
}

/// Read `CLIPBOARD` text on `ctx` using `xclip` / `xsel` scoped to `ctx.display_id`
/// and `ctx.xauth_path` (never touches host clipboard).
pub fn clipboard_get_for_context(ctx: &X11ScreenContext) -> Result<String> {
    for (bin, args) in [
        ("xclip", &["-selection", "clipboard", "-o"][..]),
        ("xsel", &["--clipboard", "--output"][..]),
    ] {
        let mut cmd = Command::new(bin);
        cmd.args(args).env("DISPLAY", &ctx.display_id);
        if let Some(ref auth) = ctx.xauth_path {
            cmd.env("XAUTHORITY", auth);
        }
        if let Ok(out) = cmd.output() {
            if out.status.success() {
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
            }
        }
    }
    Err(anyhow!(
        "neither xclip nor xsel succeeded reading clipboard on {}",
        ctx.display_id
    ))
}

/// Write `CLIPBOARD` text on `ctx` using `xclip` / `xsel` scoped to `ctx.display_id`.
pub fn clipboard_set_for_context(ctx: &X11ScreenContext, text: &str) -> Result<()> {
    use std::io::Write as _;
    for (bin, args) in [
        ("xclip", &["-selection", "clipboard", "-i"][..]),
        ("xsel", &["--clipboard", "--input"][..]),
    ] {
        let mut cmd = Command::new(bin);
        cmd.args(args)
            .env("DISPLAY", &ctx.display_id)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(ref auth) = ctx.xauth_path {
            cmd.env("XAUTHORITY", auth);
        }
        if let Ok(mut child) = cmd.spawn() {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            if let Ok(status) = child.wait() {
                if status.success() {
                    return Ok(());
                }
            }
        }
    }
    Err(anyhow!(
        "neither xclip nor xsel succeeded writing clipboard on {}",
        ctx.display_id
    ))
}

fn resolve_key_to_keycode(ctx: &X11ScreenContext, key: &str) -> Result<(u8, bool)> {
    let keysym = key_name_to_keysym(key)
        .ok_or_else(|| anyhow!("unsupported X11 key name '{key}'"))?;
    find_keycode_for_keysym(ctx, keysym)
        .ok_or_else(|| anyhow!("no keycode mapped for key '{key}' (keysym 0x{keysym:x})"))
}

fn find_keycode_for_keysym(ctx: &X11ScreenContext, keysym: u32) -> Option<(u8, bool)> {
    let setup = ctx.conn.setup();
    let min_kc = setup.min_keycode;
    let count = setup.max_keycode.checked_sub(min_kc)?.saturating_add(1);
    let mapping = ctx.conn.get_keyboard_mapping(min_kc, count).ok()?.reply().ok()?;
    let per_kc = usize::from(mapping.keysyms_per_keycode);
    if per_kc == 0 {
        return None;
    }
    for (idx, chunk) in mapping.keysyms.chunks_exact(per_kc).enumerate() {
        let kc = min_kc.saturating_add(idx as u8);
        if chunk.first().copied() == Some(keysym) {
            return Some((kc, false));
        }
        if chunk.get(1).copied() == Some(keysym) {
            return Some((kc, true));
        }
    }
    None
}

fn key_name_to_keysym(key: &str) -> Option<u32> {
    let lower = key.to_ascii_lowercase();
    match lower.as_str() {
        "ctrl" | "control" | "control_l" => Some(0xFFE3),
        "alt" | "alt_l" => Some(0xFFE9),
        "shift" | "shift_l" => Some(0xFFE1),
        "super" | "meta" | "win" | "super_l" => Some(0xFFEB),
        "return" | "enter" => Some(0xFF0D),
        "tab" => Some(0xFF09),
        "escape" | "esc" => Some(0xFF1B),
        "backspace" => Some(0xFF08),
        "delete" | "del" => Some(0xFFFF),
        "space" => Some(0x0020),
        "up" => Some(0xFF52),
        "down" => Some(0xFF54),
        "left" => Some(0xFF51),
        "right" => Some(0xFF53),
        "home" => Some(0xFF50),
        "end" => Some(0xFF57),
        "pageup" | "page_up" => Some(0xFF55),
        "pagedown" | "page_down" => Some(0xFF56),
        "f1" => Some(0xFFBE),
        "f2" => Some(0xFFBF),
        "f3" => Some(0xFFC0),
        "f4" => Some(0xFFC1),
        "f5" => Some(0xFFC2),
        "f6" => Some(0xFFC3),
        "f7" => Some(0xFFC4),
        "f8" => Some(0xFFC5),
        "f9" => Some(0xFFC6),
        "f10" => Some(0xFFC7),
        "f11" => Some(0xFFC8),
        "f12" => Some(0xFFC9),
        _ if key.chars().count() == 1 => {
            let ch = key.chars().next()?;
            ch.is_ascii().then_some(u32::from(ch))
        }
        _ => None,
    }
}
