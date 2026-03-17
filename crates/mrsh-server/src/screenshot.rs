//! Screen capture — GDI BitBlt on Windows, stub elsewhere.
//! Returns base64-encoded JPEG in the response.

use mrsh_core::protocol::Response;
use tracing::debug;

/// Handle a screenshot request.
/// Parameters: display (0-based), quality (1-100), scale (10-100%).
pub fn handle_screenshot(display_idx: u32, quality: u8, scale: u8) -> Response {
    debug!(
        "screenshot: display={} quality={} scale={}",
        display_idx, quality, scale
    );

    #[cfg(target_os = "windows")]
    {
        match capture_screen_windows(display_idx, quality, scale) {
            Ok(b64) => Response {
                success: true,
                output: Some(b64),
                error: None,
                size: None,
                binary: Some(true),
                gzip: None,
            },
            Err(e) => Response {
                success: false,
                output: None,
                error: Some(e.to_string()),
                size: None,
                binary: None,
                gzip: None,
            },
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        match capture_screen_linux(display_idx, quality, scale) {
            Ok(b64) => Response {
                success: true,
                output: Some(b64),
                error: None,
                size: None,
                binary: Some(true),
                gzip: None,
            },
            Err(e) => Response {
                success: false,
                output: None,
                error: Some(e.to_string()),
                size: None,
                binary: None,
                gzip: None,
            },
        }
    }
}

/// Check if an image buffer is likely all black (common on locked sessions).
/// Samples every ~100th pixel, returns true if all R/G/B values <= threshold.
pub fn is_black_image(rgba_data: &[u8], threshold: u8) -> bool {
    if rgba_data.is_empty() {
        return true;
    }
    // RGBA format: 4 bytes per pixel
    let pixel_count = rgba_data.len() / 4;
    let step = (pixel_count / 100).max(1);

    for i in (0..pixel_count).step_by(step) {
        let offset = i * 4;
        if offset + 2 >= rgba_data.len() {
            break;
        }
        let r = rgba_data[offset];
        let g = rgba_data[offset + 1];
        let b = rgba_data[offset + 2];
        if r > threshold || g > threshold || b > threshold {
            return false;
        }
    }
    true
}

/// Try running a screenshot command with a timeout.
/// Spawns the process and polls with try_wait to avoid indefinite blocking.
#[cfg(not(target_os = "windows"))]
fn try_screenshot_cmd(cmd: &str, args: &[&str], timeout_secs: u64) -> bool {
    use std::process::Command;
    let mut child = match Command::new(cmd).args(args).spawn() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => return false,
        }
    }
}

/// Capture screen on Linux using available tools (grim for Wayland, scrot/import for X11).
/// Returns base64-encoded JPEG.
#[cfg(not(target_os = "windows"))]
fn capture_screen_linux(_display: u32, quality: u8, _scale: u8) -> anyhow::Result<String> {
    use base64::Engine;

    // Check if a display server is available
    let has_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
    let has_x11 = std::env::var("DISPLAY").is_ok();
    if !has_wayland && !has_x11 {
        anyhow::bail!("no display server available (DISPLAY and WAYLAND_DISPLAY not set)");
    }

    let tmp_path = "/tmp/rsh-screenshot.png";

    // Try tools in order: grim (Wayland), scrot (X11), import (ImageMagick)
    // Each tool gets a 5-second timeout to avoid hanging
    let captured = try_screenshot_cmd("grim", &[tmp_path], 5)
        || try_screenshot_cmd("scrot", &["-o", tmp_path], 5)
        || try_screenshot_cmd("import", &["-window", "root", tmp_path], 5);

    if !captured {
        anyhow::bail!(
            "no screenshot tool available (install grim for Wayland, or scrot/imagemagick for X11)"
        );
    }

    // Read the PNG, convert to JPEG via image crate
    let png_data = std::fs::read(tmp_path)?;
    let _ = std::fs::remove_file(tmp_path);

    let img = image::load_from_memory(&png_data)?;
    let mut jpeg_buf = std::io::Cursor::new(Vec::new());
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
        &mut jpeg_buf,
        quality.clamp(1, 100),
    );
    img.write_with_encoder(encoder)?;

    let b64 = base64::engine::general_purpose::STANDARD.encode(jpeg_buf.into_inner());
    Ok(b64)
}

/// Capture screen on Windows using GDI BitBlt.
#[cfg(target_os = "windows")]
fn capture_screen_windows(_display: u32, quality: u8, scale: u8) -> anyhow::Result<String> {
    use base64::Engine;
    use windows::Win32::Graphics::Gdi::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    // Get screen dimensions
    let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };

    if width == 0 || height == 0 {
        anyhow::bail!("could not get screen dimensions");
    }

    // Scale
    let scale_f = scale.clamp(10, 100) as f64 / 100.0;
    let scaled_w = (width as f64 * scale_f) as i32;
    let scaled_h = (height as f64 * scale_f) as i32;

    // Create memory DC and bitmap
    let screen_dc = unsafe { GetDC(None) };
    let mem_dc = unsafe { CreateCompatibleDC(Some(screen_dc)) };
    let bitmap = unsafe { CreateCompatibleBitmap(screen_dc, scaled_w, scaled_h) };
    let _old = unsafe { SelectObject(mem_dc, bitmap.into()) };

    // StretchBlt from screen to memory DC
    unsafe {
        let _ = SetStretchBltMode(mem_dc, HALFTONE);
        let _ = StretchBlt(
            mem_dc,
            0,
            0,
            scaled_w,
            scaled_h,
            Some(screen_dc),
            0,
            0,
            width,
            height,
            SRCCOPY,
        );
    }

    // Read bitmap data
    let mut bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: scaled_w,
            biHeight: -scaled_h, // top-down
            biPlanes: 1,
            biBitCount: 32,
            biCompression: 0, // BI_RGB
            ..Default::default()
        },
        ..Default::default()
    };

    let mut rgba_data = vec![0u8; (scaled_w * scaled_h * 4) as usize];
    unsafe {
        GetDIBits(
            mem_dc,
            bitmap,
            0,
            scaled_h as u32,
            Some(rgba_data.as_mut_ptr() as *mut _),
            &mut bmi,
            DIB_RGB_COLORS,
        );
    }

    // Cleanup GDI
    unsafe {
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteDC(mem_dc);
        let _ = ReleaseDC(None, screen_dc);
    }

    // Check for black image
    if is_black_image(&rgba_data, 5) {
        anyhow::bail!("captured image is all black (display may be locked)");
    }

    // Convert BGRA → RGB
    let mut rgb_data = Vec::with_capacity((scaled_w * scaled_h * 3) as usize);
    for pixel in rgba_data.chunks_exact(4) {
        rgb_data.push(pixel[2]); // R (was at index 2 in BGRA)
        rgb_data.push(pixel[1]); // G
        rgb_data.push(pixel[0]); // B (was at index 0 in BGRA)
    }

    // Encode as JPEG
    let rgb_image = image::RgbImage::from_raw(scaled_w as u32, scaled_h as u32, rgb_data)
        .ok_or_else(|| anyhow::anyhow!("failed to create image from raw RGB data"))?;

    let mut jpeg_buf = std::io::Cursor::new(Vec::new());
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
        &mut jpeg_buf,
        quality.clamp(1, 100),
    );
    rgb_image.write_with_encoder(encoder)?;

    let b64 = base64::engine::general_purpose::STANDARD.encode(jpeg_buf.into_inner());
    Ok(b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_black_image_all_zeros() {
        let data = vec![0u8; 400]; // 100 black pixels
        assert!(is_black_image(&data, 5));
    }

    #[test]
    fn is_black_image_with_content() {
        let mut data = vec![0u8; 400];
        // Set pixel 50 to have color
        data[200] = 128; // R
        data[201] = 64; // G
        assert!(!is_black_image(&data, 5));
    }

    #[test]
    fn is_black_image_empty() {
        assert!(is_black_image(&[], 5));
    }

    /// Regression (orin-vi9): black-image detection must catch all-black frames
    /// from RDP/locked sessions where GetDIBits returns zeroed buffer.
    #[test]
    fn is_black_image_near_threshold() {
        // All pixels exactly at threshold → still black.
        let mut data = vec![0u8; 400];
        for pixel in data.chunks_exact_mut(4) {
            pixel[0] = 5; // R = threshold
            pixel[1] = 5; // G = threshold
            pixel[2] = 5; // B = threshold
        }
        assert!(is_black_image(&data, 5));

        // One pixel above threshold → not black.
        data[0] = 6;
        assert!(!is_black_image(&data, 5));
    }

    /// JPEG encoding of a synthetic frame — validates the encoding pipeline
    /// used after GDI capture (BGRA→RGB→JPEG→base64).
    #[test]
    fn jpeg_encode_synthetic_frame() {
        use base64::Engine;

        let w: u32 = 10;
        let h: u32 = 10;
        // Create BGRA data with a gradient pattern.
        let mut bgra = vec![0u8; (w * h * 4) as usize];
        for i in 0..(w * h) as usize {
            bgra[i * 4] = (i % 256) as u8;       // B
            bgra[i * 4 + 1] = ((i * 2) % 256) as u8; // G
            bgra[i * 4 + 2] = ((i * 3) % 256) as u8; // R
            bgra[i * 4 + 3] = 255;                     // A
        }

        // BGRA → RGB (same conversion as capture_screen_windows).
        let mut rgb = Vec::with_capacity((w * h * 3) as usize);
        for pixel in bgra.chunks_exact(4) {
            rgb.push(pixel[2]); // R
            rgb.push(pixel[1]); // G
            rgb.push(pixel[0]); // B
        }

        let img = image::RgbImage::from_raw(w, h, rgb).unwrap();
        let mut buf = std::io::Cursor::new(Vec::new());
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 80);
        img.write_with_encoder(encoder).unwrap();

        let b64 = base64::engine::general_purpose::STANDARD.encode(buf.into_inner());
        assert!(!b64.is_empty());
        // Decode to verify it's valid base64.
        let decoded = base64::engine::general_purpose::STANDARD.decode(&b64).unwrap();
        // JPEG magic bytes: FF D8 FF.
        assert_eq!(&decoded[..3], &[0xFF, 0xD8, 0xFF], "output must be valid JPEG");
    }

    #[test]
    fn screenshot_linux_no_display() {
        #[cfg(not(target_os = "windows"))]
        {
            let has_display = std::env::var("DISPLAY").is_ok()
                || std::env::var("WAYLAND_DISPLAY").is_ok();
            let resp = handle_screenshot(0, 80, 100);
            if has_display {
                // WSLg or real desktop — screenshot may succeed
            } else {
                assert!(!resp.success);
                assert!(resp.error.is_some());
            }
        }
    }
}
