//! Verified process lifecycle boundary for a future pinned engine bundle.

use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EngineState {
    #[default]
    Stopped,
    Starting,
    Running {
        process_id: u32,
        strategy_id: String,
    },
    Stopping,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError(pub String);

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EngineError {}

#[derive(Debug, Clone)]
pub struct EngineBundle {
    executable: PathBuf,
    expected_sha256: String,
}

impl EngineBundle {
    pub fn new(executable: impl Into<PathBuf>, expected_sha256: impl Into<String>) -> Self {
        Self {
            executable: executable.into(),
            expected_sha256: expected_sha256.into(),
        }
    }

    /// Reads and verifies the engine file before it can be launched.
    pub fn verify(&self) -> Result<VerifiedEngine, EngineError> {
        let expected = normalize_sha256(&self.expected_sha256)?;
        let mut file = File::open(&self.executable).map_err(|error| {
            EngineError(format!(
                "cannot open engine {}: {error}",
                self.executable.display()
            ))
        })?;
        let actual = hash_reader(&mut file).map_err(|error| {
            EngineError(format!(
                "cannot hash engine {}: {error}",
                self.executable.display()
            ))
        })?;
        if actual != expected {
            return Err(EngineError(format!(
                "engine SHA-256 mismatch for {}",
                self.executable.display()
            )));
        }
        Ok(VerifiedEngine {
            executable: self.executable.clone(),
            sha256: actual,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedEngine {
    executable: PathBuf,
    sha256: String,
}

impl VerifiedEngine {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn spawn(&self, args: &[String]) -> Result<EngineProcess, EngineError> {
        let parent = self
            .executable
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        #[cfg(target_os = "windows")]
        let job = create_kill_on_close_job()?;
        let mut child = Command::new(&self.executable)
            .args(args)
            .current_dir(parent)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                EngineError(format!(
                    "cannot start verified engine {}: {error}",
                    self.executable.display()
                ))
            })?;
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            // SAFETY: child is live and its process handle is borrowed for this call.
            let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as _) };
            if assigned == 0 {
                let error = io::Error::last_os_error();
                let _ = child.kill();
                let _ = child.wait();
                return Err(EngineError(format!(
                    "cannot assign engine to cleanup job: {error}"
                )));
            }
        }
        Ok(EngineProcess {
            child: Some(child),
            #[cfg(target_os = "windows")]
            _job: Some(job),
        })
    }
}

/// Dropping or explicitly stopping this guard terminates and reaps the child.
/// On Windows, the child also belongs to a kill-on-job-close Job Object, so
/// abrupt parent termination closes the last job handle and ends the engine.
pub struct EngineProcess {
    child: Option<Child>,
    #[cfg(target_os = "windows")]
    _job: Option<JobHandle>,
}

impl EngineProcess {
    pub fn process_id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    pub fn stop(&mut self) -> Result<(), EngineError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => {
                child
                    .kill()
                    .map_err(|error| EngineError(format!("cannot stop engine: {error}")))?;
                child
                    .wait()
                    .map(|_| ())
                    .map_err(|error| EngineError(format!("cannot reap engine: {error}")))
            }
            Err(error) => Err(EngineError(format!(
                "cannot inspect engine process: {error}"
            ))),
        }
    }
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(target_os = "windows")]
struct JobHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
impl Drop for JobHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this handle is created by CreateJobObjectW and owned here.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

#[cfg(target_os = "windows")]
fn create_kill_on_close_job() -> Result<JobHandle, EngineError> {
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };

    // SAFETY: null security attributes and name request a private unnamed job.
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if handle.is_null() {
        return Err(EngineError(format!(
            "CreateJobObjectW failed: {}",
            io::Error::last_os_error()
        )));
    }
    let job = JobHandle(handle);
    // SAFETY: zero is a valid initial state for the documented C structure.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: pointer and size describe the structure for the selected info class.
    let success = unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            &limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if success == 0 {
        return Err(EngineError(format!(
            "SetInformationJobObject failed: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(job)
}

fn normalize_sha256(value: &str) -> Result<String, EngineError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EngineError(
            "expected SHA-256 must be 64 hexadecimal characters".into(),
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn hash_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_sha256_before_launch() {
        let path = std::env::temp_dir().join(format!(
            "zapreta-engine-test-{}-{}.bin",
            std::process::id(),
            format_args!("{:?}", std::thread::current().id())
        ));
        std::fs::write(&path, b"verified payload").unwrap();
        let bundle = EngineBundle::new(
            &path,
            "3aac0a1146ffe55bac7c05f61401fb1e7e4e6a94110b91585c646fe8cf745f28",
        );
        let result = bundle.verify();
        let _ = std::fs::remove_file(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_malformed_or_mismatched_hashes() {
        let malformed = EngineBundle::new("not-present.exe", "bad-hash");
        assert!(malformed.verify().is_err());
        let mismatch = EngineBundle::new("not-present.exe", "0".repeat(64));
        assert!(mismatch.verify().is_err());
    }

    #[test]
    fn stopped_is_the_initial_engine_state() {
        assert_eq!(EngineState::default(), EngineState::Stopped);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn launches_only_after_verification_and_stops_child() {
        let executable = PathBuf::from(std::env::var_os("WINDIR").unwrap())
            .join("System32")
            .join("cmd.exe");
        let mut file = File::open(&executable).unwrap();
        let digest = hash_reader(&mut file).unwrap();
        let verified = EngineBundle::new(executable, digest).verify().unwrap();
        let mut process = verified
            .spawn(&["/C".into(), "exit".into(), "0".into()])
            .unwrap();
        assert!(process.process_id().is_some());
        process.stop().unwrap();
        assert!(process.process_id().is_none());
    }
}
