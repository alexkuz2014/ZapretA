//! Extraction of the embedded, hash-pinned engine files into a per-user folder.

use crate::embedded::{ENGINE_FILES, ENGINE_ID, EmbeddedFile};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Placeholder user lists, created only when absent and never overwritten so
/// the user's own entries survive updates. Content matches upstream defaults.
const USER_LISTS: &[(&str, &str)] = &[
    // The user's own IPs/subnets; the placeholder is upstream's "no ipset" value.
    ("lists/ipset-all.txt", "203.0.113.113/32\n"),
    ("lists/ipset-exclude-user.txt", "203.0.113.113/32\n"),
    (
        "lists/list-general-user.txt",
        "# Never leave this file empty\ndomain.example.abc\n",
    ),
    ("lists/list-exclude-user.txt", "domain.example.abc\n"),
];

pub fn default_root() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")?;
    Some(PathBuf::from(base).join("ZapretA").join(ENGINE_ID))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn needs_write(path: &Path, expected_sha256: &str) -> bool {
    match fs::read(path) {
        Ok(existing) => sha256_hex(&existing) != expected_sha256,
        Err(_) => true,
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension("zapreta-tmp");
    fs::write(&temp, bytes)?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temp, path)
}

/// Writes every embedded file whose on-disk copy is missing or has a different
/// SHA-256, then creates absent user lists. Returns the number of files written.
pub fn extract(files: &[EmbeddedFile], root: &Path) -> io::Result<usize> {
    let mut written = 0;
    for file in files {
        if sha256_hex(file.bytes) != file.sha256 {
            return Err(io::Error::other(format!(
                "embedded file {} does not match its pinned SHA-256",
                file.path
            )));
        }
        let target = root.join(file.path);
        if needs_write(&target, file.sha256) {
            write_atomic(&target, file.bytes)?;
            written += 1;
        }
    }
    for (path, content) in USER_LISTS {
        let target = root.join(path);
        if !target.exists() {
            write_atomic(&target, content.as_bytes())?;
            written += 1;
        }
    }
    Ok(written)
}

pub fn extract_default(root: &Path) -> io::Result<usize> {
    extract(ENGINE_FILES, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedded::WINWS_SHA256;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zapreta-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn embedded_files_match_pins_and_extract_repairs_tampering() {
        let root = temp_root("extract");
        let first = extract_default(&root).unwrap();
        assert!(first >= ENGINE_FILES.len());
        let winws = root.join("winws.exe");
        assert_eq!(sha256_hex(&fs::read(&winws).unwrap()), WINWS_SHA256);
        // Nothing to do the second time.
        assert_eq!(extract_default(&root).unwrap(), 0);
        // A tampered engine file is replaced; a user list is left alone.
        fs::write(&winws, b"tampered").unwrap();
        let user = root.join("lists/list-general-user.txt");
        fs::write(&user, "mine.example\n").unwrap();
        assert_eq!(extract_default(&root).unwrap(), 1);
        assert_eq!(sha256_hex(&fs::read(&winws).unwrap()), WINWS_SHA256);
        assert_eq!(fs::read_to_string(&user).unwrap(), "mine.example\n");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_embedded_bytes_that_do_not_match_their_pin() {
        let root = temp_root("badpin");
        let files = [EmbeddedFile {
            path: "x.bin",
            sha256: "0000",
            bytes: b"data",
        }];
        assert!(extract(&files, &root).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
