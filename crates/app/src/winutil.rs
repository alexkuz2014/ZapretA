//! Small Windows helpers for the GUI: single instance, console attach for
//! CLI use, window focus, hidden child processes and logon autostart.

use std::{
    ffi::OsStr,
    io,
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::Command,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE},
    System::{
        Console::{ATTACH_PARENT_PROCESS, AttachConsole},
        Threading::{CREATE_NO_WINDOW, CreateMutexW},
    },
    UI::WindowsAndMessaging::{
        FindWindowW, MB_ICONINFORMATION, MB_OK, MessageBoxW, SW_RESTORE, SW_SHOW,
        SetForegroundWindow, ShowWindow,
    },
};

pub const WINDOW_TITLE: &str = "ZapretA";
const TASK_NAME: &str = "ZapretA";

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Lets `println!` reach the terminal when the GUI-subsystem exe is run from a
/// console with CLI arguments. Harmless when there is no parent console.
pub fn attach_parent_console() {
    // SAFETY: plain Win32 call without pointers.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

/// Holds the named mutex for the life of the process.
pub struct SingleInstance(HANDLE);

impl Drop for SingleInstance {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateMutexW and is closed once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Returns `None` if another ZapretA instance already runs in this session.
pub fn single_instance() -> Option<SingleInstance> {
    let name = wide("Local\\ZapretA.SingleInstance");
    // SAFETY: valid NUL-terminated name; null security attributes are allowed.
    unsafe {
        let handle = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        if handle.is_null() {
            return None;
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            CloseHandle(handle);
            return None;
        }
        Some(SingleInstance(handle))
    }
}

/// Shows and focuses the ZapretA window (hidden to tray or minimized).
pub fn show_window() -> bool {
    let title = wide(WINDOW_TITLE);
    // SAFETY: valid NUL-terminated title; the HWND is only used for show/focus.
    unsafe {
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if hwnd.is_null() {
            return false;
        }
        ShowWindow(hwnd, SW_SHOW);
        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
        true
    }
}

pub fn message_box(text: &str) {
    let text = wide(text);
    let title = wide(WINDOW_TITLE);
    // SAFETY: valid NUL-terminated buffers outlive the call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

/// A child process that never opens a console window.
pub fn hidden(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

pub fn open_url(url: &str) {
    let _ = hidden("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn();
}

pub fn open_folder(path: &Path) {
    let _ = Command::new("explorer").arg(path).spawn();
}

/// Copies the running exe to a stable per-user location, so autostart keeps
/// working after the downloaded file is moved or deleted.
fn install_copy(app_dir: &Path) -> io::Result<PathBuf> {
    let current = std::env::current_exe()?;
    let target = app_dir.join("ZapretA.exe");
    let same = std::fs::canonicalize(&current).ok() == std::fs::canonicalize(&target).ok();
    if !same {
        std::fs::create_dir_all(app_dir)?;
        let temp = target.with_extension("exe.new");
        std::fs::copy(&current, &temp)?;
        if target.exists() {
            // A running copy cannot be replaced; keep using it in that case.
            if std::fs::remove_file(&target).is_err() {
                let _ = std::fs::remove_file(&temp);
                return Ok(target);
            }
        }
        std::fs::rename(&temp, &target)?;
    }
    Ok(target)
}

fn schtasks(args: &[&str]) -> io::Result<bool> {
    Ok(hidden("schtasks").args(args).status()?.success())
}

/// Elevated logon task: no UAC prompt at sign-in; starts hidden in the tray.
pub fn enable_autostart(app_dir: &Path) -> io::Result<()> {
    let exe = install_copy(app_dir)?;
    let action = format!("\"{}\" --tray", exe.display());
    let ok = schtasks(&[
        "/Create", "/TN", TASK_NAME, "/TR", &action, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
    ])?;
    if ok {
        Ok(())
    } else {
        Err(io::Error::other("schtasks /Create failed"))
    }
}

pub fn disable_autostart() -> io::Result<()> {
    schtasks(&["/Delete", "/TN", TASK_NAME, "/F"]).map(|_| ())
}

pub fn autostart_enabled() -> bool {
    schtasks(&["/Query", "/TN", TASK_NAME]).unwrap_or(false)
}
