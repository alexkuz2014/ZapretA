//! Administrator check and self-elevation (Windows only; no-ops elsewhere).

#[cfg(target_os = "windows")]
mod imp {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
        UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
    };

    pub fn is_elevated() -> bool {
        // SAFETY: plain Win32 calls with valid out-pointers; the token handle is closed.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Relaunches this executable with the UAC prompt. Returns false if the user
    /// declined or the launch failed.
    pub fn relaunch_elevated(args: &str) -> bool {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let verb = wide(OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let params = wide(OsStr::new(args));
        // SAFETY: all pointers are valid NUL-terminated UTF-16 buffers that outlive the call.
        let result = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // ShellExecuteW returns a value greater than 32 on success.
        result as usize > 32
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    pub fn is_elevated() -> bool {
        true
    }
    pub fn relaunch_elevated(_args: &str) -> bool {
        false
    }
}

pub use imp::{is_elevated, relaunch_elevated};
