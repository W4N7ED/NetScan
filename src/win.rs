//! Petites lectures de l'état de Windows : thème des applications, présence d'un écran.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            key: isize,
            sub_key: *const u16,
            value: *const u16,
            flags: u32,
            kind: *mut u32,
            data: *mut c_void,
            size: *mut u32,
        ) -> i32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn MonitorFromPoint(pt: Point, flags: u32) -> isize;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn system_prefers_dark() -> Option<bool> {
        const HKEY_CURRENT_USER: isize = 0x8000_0001_u32 as i32 as isize;
        const RRF_RT_REG_DWORD: u32 = 0x10;
        let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        let name = wide("AppsUseLightTheme");
        let mut light: u32 = 1;
        let mut size: u32 = 4;
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                &mut light as *mut u32 as *mut c_void,
                &mut size,
            )
        };
        (rc == 0).then_some(light == 0)
    }

    pub fn point_on_screen(x: i32, y: i32) -> bool {
        // MONITOR_DEFAULTTONULL = 0 : renvoie 0 si aucun écran ne contient le point.
        unsafe { MonitorFromPoint(Point { x, y }, 0) != 0 }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn system_prefers_dark() -> Option<bool> {
        None
    }
    pub fn point_on_screen(_x: i32, _y: i32) -> bool {
        true
    }
}

/// Windows est-il réglé sur le thème sombre pour les applications ?
pub fn system_prefers_dark() -> Option<bool> {
    imp::system_prefers_dark()
}

/// Le point (pixels physiques du bureau) est-il sur un écran branché ?
pub fn point_on_screen(x: i32, y: i32) -> bool {
    imp::point_on_screen(x, y)
}
