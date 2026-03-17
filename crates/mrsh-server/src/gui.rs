//! GUI automation — mouse, keyboard, and window management.
//! Windows-only in production; cross-platform types and stub handlers.

use mrsh_core::protocol::Response;
use serde::{Deserialize, Serialize};
use tracing::debug;

/// Window information returned by window list/find.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub hwnd: u64,
    pub title: String,
    pub pid: u32,
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
    pub visible: bool,
}

/// Handle an input/GUI command.
/// Format: command is "mouse|key|window", path holds the sub-action,
/// content holds arguments (JSON or space-separated).
pub fn handle_input(command: &str, action: &str, args: &str) -> Response {
    debug!("input: cmd={} action={} args={}", command, action, args);

    match command {
        "mouse" => handle_mouse(action, args),
        "key" => handle_key(action, args),
        "window" => handle_window(action, args),
        other => error_response(&format!("unknown input command: {}", other)),
    }
}

// ── Mouse ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn handle_mouse(action: &str, args: &str) -> Response {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    match action {
        "pos" => {
            let mut pt = POINT::default();
            unsafe { windows::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut pt).ok() };
            ok_response(&format!("{},{}", pt.x, pt.y))
        }
        "move" => {
            let (x, y) = parse_xy(args);
            unsafe { windows::Win32::UI::WindowsAndMessaging::SetCursorPos(x, y).ok() };
            ok_response("ok")
        }
        "click" => {
            let inputs = [
                INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dwFlags: MOUSEEVENTF_LEFTDOWN,
                            ..Default::default()
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_MOUSE,
                    Anonymous: INPUT_0 {
                        mi: MOUSEINPUT {
                            dwFlags: MOUSEEVENTF_LEFTUP,
                            ..Default::default()
                        },
                    },
                },
            ];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        "scroll" => {
            let delta: i32 = args.trim().parse().unwrap_or(120);
            let inputs = [INPUT {
                r#type: INPUT_MOUSE,
                Anonymous: INPUT_0 {
                    mi: MOUSEINPUT {
                        mouseData: delta as u32,
                        dwFlags: MOUSEEVENTF_WHEEL,
                        ..Default::default()
                    },
                },
            }];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        other => error_response(&format!("unknown mouse action: {}", other)),
    }
}

#[cfg(not(target_os = "windows"))]
fn handle_mouse(action: &str, _args: &str) -> Response {
    error_response(&format!("mouse {} not available on this platform", action))
}

// ── Keyboard ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn handle_key(action: &str, args: &str) -> Response {
    use windows::Win32::UI::Input::KeyboardAndMouse::*;

    match action {
        "type" => {
            // Type unicode string
            for ch in args.chars() {
                let scan = ch as u16;
                let inputs = [
                    INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wScan: scan,
                                dwFlags: KEYEVENTF_UNICODE,
                                ..Default::default()
                            },
                        },
                    },
                    INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wScan: scan,
                                dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                                ..Default::default()
                            },
                        },
                    },
                ];
                unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            }
            ok_response("ok")
        }
        "tap" => {
            let vk = named_key_to_vk(args.trim());
            let inputs = [
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(vk),
                            ..Default::default()
                        },
                    },
                },
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(vk),
                            dwFlags: KEYEVENTF_KEYUP,
                            ..Default::default()
                        },
                    },
                },
            ];
            unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            ok_response("ok")
        }
        other => error_response(&format!("unknown key action: {}", other)),
    }
}

#[cfg(not(target_os = "windows"))]
fn handle_key(action: &str, _args: &str) -> Response {
    error_response(&format!("key {} not available on this platform", action))
}

// ── Window management ──────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn handle_window(action: &str, args: &str) -> Response {
    use windows::Win32::Foundation::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    match action {
        "list" => {
            let mut windows = Vec::new();
            unsafe {
                EnumWindows(
                    Some(enum_windows_callback),
                    LPARAM(&mut windows as *mut Vec<WindowInfo> as isize),
                )
                .ok();
            }
            let json = serde_json::to_string(&windows).unwrap_or_default();
            ok_response(&json)
        }
        "find" => {
            let title_pattern = args.trim().to_lowercase();
            let mut windows: Vec<WindowInfo> = Vec::new();
            unsafe {
                EnumWindows(
                    Some(enum_windows_callback),
                    LPARAM(&mut windows as *mut Vec<WindowInfo> as isize),
                )
                .ok();
            }
            let matched: Vec<&WindowInfo> = windows
                .iter()
                .filter(|w| w.title.to_lowercase().contains(&title_pattern))
                .collect();
            let json = serde_json::to_string(&matched).unwrap_or_default();
            ok_response(&json)
        }
        "activate" => {
            let hwnd_val: u64 = args.trim().parse().unwrap_or(0);
            let hwnd = HWND(hwnd_val as *mut _);
            unsafe {
                let _ = SetForegroundWindow(hwnd);
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            ok_response("ok")
        }
        "close" => {
            let hwnd_val: u64 = args.trim().parse().unwrap_or(0);
            let hwnd = HWND(hwnd_val as *mut _);
            unsafe { PostMessageW(Some(hwnd), WM_CLOSE, WPARAM(0), LPARAM(0)).ok() };
            ok_response("ok")
        }
        other => error_response(&format!("unknown window action: {}", other)),
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn enum_windows_callback(
    hwnd: windows::Win32::Foundation::HWND,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::core::BOOL {
    use windows::Win32::Foundation::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    unsafe {
        if !IsWindowVisible(hwnd).as_bool() {
            return windows::core::BOOL(1); // TRUE
        }

        let mut title_buf = [0u16; 512];
        let len = GetWindowTextW(hwnd, &mut title_buf);
        if len == 0 {
            return windows::core::BOOL(1); // TRUE
        }
        let title = String::from_utf16_lossy(&title_buf[..len as usize]);

        let mut rect = RECT::default();
        let _ = GetWindowRect(hwnd, &mut rect);

        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));

        let windows = &mut *(lparam.0 as *mut Vec<WindowInfo>);
        windows.push(WindowInfo {
            hwnd: hwnd.0 as u64,
            title,
            pid,
            x: rect.left,
            y: rect.top,
            width: rect.right - rect.left,
            height: rect.bottom - rect.top,
            visible: true,
        });

        windows::core::BOOL(1) // TRUE
    }
}

#[cfg(not(target_os = "windows"))]
fn handle_window(action: &str, _args: &str) -> Response {
    error_response(&format!("window {} not available on this platform", action))
}

// ── Helpers ────────────────────────────────────────────────────────

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_xy(args: &str) -> (i32, i32) {
    let parts: Vec<&str> = args.split(',').collect();
    if parts.len() >= 2 {
        let x = parts[0].trim().parse().unwrap_or(0);
        let y = parts[1].trim().parse().unwrap_or(0);
        (x, y)
    } else {
        (0, 0)
    }
}

/// Map named key to Windows virtual key code.
#[cfg(target_os = "windows")]
fn named_key_to_vk(name: &str) -> u16 {
    match name.to_lowercase().as_str() {
        "enter" | "return" => 0x0D,
        "tab" => 0x09,
        "escape" | "esc" => 0x1B,
        "backspace" => 0x08,
        "delete" | "del" => 0x2E,
        "space" => 0x20,
        "up" => 0x26,
        "down" => 0x28,
        "left" => 0x25,
        "right" => 0x27,
        "home" => 0x24,
        "end" => 0x23,
        "pageup" => 0x21,
        "pagedown" => 0x22,
        "insert" => 0x2D,
        "ctrl" | "control" => 0x11,
        "alt" => 0x12,
        "shift" => 0x10,
        "win" | "windows" | "super" => 0x5B,
        "f1" => 0x70,
        "f2" => 0x71,
        "f3" => 0x72,
        "f4" => 0x73,
        "f5" => 0x74,
        "f6" => 0x75,
        "f7" => 0x76,
        "f8" => 0x77,
        "f9" => 0x78,
        "f10" => 0x79,
        "f11" => 0x7A,
        "f12" => 0x7B,
        _ => {
            // Single character → ASCII VK
            if let Some(c) = name.chars().next() {
                c.to_ascii_uppercase() as u16
            } else {
                0
            }
        }
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn ok_response(output: &str) -> Response {
    Response {
        success: true,
        output: Some(output.to_string()),
        error: None,
        size: None,
        binary: None,
        gzip: None,
    }
}

fn error_response(msg: &str) -> Response {
    Response {
        success: false,
        output: None,
        error: Some(msg.to_string()),
        size: None,
        binary: None,
        gzip: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xy_valid() {
        assert_eq!(parse_xy("100,200"), (100, 200));
        assert_eq!(parse_xy(" 50 , 75 "), (50, 75));
    }

    #[test]
    fn parse_xy_invalid() {
        assert_eq!(parse_xy("invalid"), (0, 0));
        assert_eq!(parse_xy(""), (0, 0));
    }

    #[test]
    fn window_info_serializes() {
        let info = WindowInfo {
            hwnd: 12345,
            title: "Test Window".to_string(),
            pid: 100,
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            visible: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("Test Window"));
        assert!(json.contains("12345"));
    }

    #[test]
    fn handle_input_unknown_command() {
        let resp = handle_input("unknown", "action", "args");
        assert!(!resp.success);
    }

    #[test]
    fn handle_input_mouse_stub() {
        // On non-Windows, all mouse actions return platform error
        #[cfg(not(target_os = "windows"))]
        {
            let resp = handle_input("mouse", "pos", "");
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }

    #[test]
    fn handle_input_window_stub() {
        #[cfg(not(target_os = "windows"))]
        {
            let resp = handle_input("window", "list", "");
            assert!(!resp.success);
            assert!(resp.error.unwrap().contains("not available"));
        }
    }
}
