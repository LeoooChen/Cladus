//! Process icons for the tree, as PNG.

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC,
    DeleteObject, GetDIBits, GetObjectW,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::Shell::{SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON, SHGetFileInfoW};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

/// Image path of a running process, as far as this user may see it.
pub fn image_path(pid: u32) -> Option<String> {
    // SAFETY: plain query; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    // SAFETY: the buffer holds `len` UTF-16 units.
    let ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut len)
    };
    // SAFETY: opened above.
    unsafe { CloseHandle(handle) };
    (ok != 0).then(|| String::from_utf16_lossy(&buffer[..len as usize]))
}

/// The 32-pixel shell icon of `path`, encoded as PNG.
pub fn png_for(path: &str) -> Option<Vec<u8>> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: SHFILEINFOW is plain data.
    let mut info: SHFILEINFOW = unsafe { std::mem::zeroed() };
    // SAFETY: valid path and out structure of the given size.
    let found = unsafe {
        SHGetFileInfoW(
            wide.as_ptr(),
            FILE_ATTRIBUTE_NORMAL,
            &mut info,
            size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON | SHGFI_LARGEICON,
        )
    };
    if found == 0 || info.hIcon.is_null() {
        return None;
    }
    let pixels = icon_pixels(info.hIcon);
    // SAFETY: the icon was returned to us and is destroyed once.
    unsafe { DestroyIcon(info.hIcon) };
    let (width, height, rgba) = pixels?;
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder.write_header().ok()?.write_image_data(&rgba).ok()?;
    }
    Some(out)
}

fn icon_pixels(
    icon: windows_sys::Win32::UI::WindowsAndMessaging::HICON,
) -> Option<(u32, u32, Vec<u8>)> {
    // SAFETY: ICONINFO is plain data; GetIconInfo fills it and we delete its bitmaps.
    let mut info: ICONINFO = unsafe { std::mem::zeroed() };
    // SAFETY: `info` is a valid out structure.
    if unsafe { GetIconInfo(icon, &mut info) } == 0 {
        return None;
    }
    let result = (|| {
        let color = read_bitmap(info.hbmColor)?;
        let mask = read_bitmap(info.hbmMask);
        let (width, height, mut bgra) = color;
        let has_alpha = bgra.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
        for (i, pixel) in bgra.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            pixel.swap(0, 2);
            if !has_alpha {
                // The AND mask is white where the icon is transparent.
                let transparent = mask
                    .as_ref()
                    .is_some_and(|(_, _, m)| m.get(i * 4).is_some_and(|&b| b != 0));
                pixel[3] = if transparent { 0 } else { 255 };
            }
        }
        Some((width, height, bgra))
    })();
    // SAFETY: GetIconInfo created these bitmaps for us.
    unsafe {
        if !info.hbmColor.is_null() {
            DeleteObject(info.hbmColor);
        }
        if !info.hbmMask.is_null() {
            DeleteObject(info.hbmMask);
        }
    }
    result
}

/// A bitmap's pixels as top-down 32-bit BGRA.
fn read_bitmap(bitmap: windows_sys::Win32::Graphics::Gdi::HBITMAP) -> Option<(u32, u32, Vec<u8>)> {
    if bitmap.is_null() {
        return None;
    }
    // SAFETY: BITMAP is plain data of the size passed.
    let mut header: BITMAP = unsafe { std::mem::zeroed() };
    // SAFETY: `header` is writable and as large as stated.
    if unsafe {
        GetObjectW(
            bitmap,
            size_of::<BITMAP>() as i32,
            (&mut header as *mut BITMAP).cast(),
        )
    } == 0
    {
        return None;
    }
    let (width, height) = (header.bmWidth, header.bmHeight);
    if width <= 0 || height <= 0 || width > 256 || height > 256 {
        return None;
    }
    // SAFETY: BITMAPINFO is plain data.
    let mut bmi: BITMAPINFO = unsafe { std::mem::zeroed() };
    bmi.bmiHeader = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width,
        biHeight: -height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB,
        // SAFETY: BITMAPINFOHEADER is plain data.
        ..unsafe { std::mem::zeroed() }
    };
    let mut pixels = vec![0u8; (width * height * 4) as usize];
    // SAFETY: a memory DC for GetDIBits; `pixels` fits the requested format.
    let lines = unsafe {
        let dc = CreateCompatibleDC(std::ptr::null_mut());
        let lines = GetDIBits(
            dc,
            bitmap,
            0,
            height as u32,
            pixels.as_mut_ptr().cast(),
            &mut bmi,
            DIB_RGB_COLORS,
        );
        DeleteDC(dc);
        lines
    };
    (lines == height).then_some((width as u32, height as u32, pixels))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_image_and_icon() {
        let path = image_path(std::process::id()).unwrap();
        assert!(path.to_ascii_lowercase().ends_with(".exe"));
        let notepad = std::env::var("SystemRoot").unwrap() + r"\System32\notepad.exe";
        let png = png_for(&notepad).unwrap();
        assert_eq!(&png[1..4], b"PNG");
    }
}
