//! The user's own sites, IP addresses and exclusions, stored in the list files
//! the engine reads (`lists/*-user.txt`, `lists/ipset-all.txt`).

use std::{fs, io, net::IpAddr, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    Sites,
    Ips,
    ExcludeSites,
    ExcludeIps,
}

impl ListKind {
    pub const ALL: [ListKind; 4] = [
        ListKind::Sites,
        ListKind::Ips,
        ListKind::ExcludeSites,
        ListKind::ExcludeIps,
    ];

    pub fn file(self) -> &'static str {
        match self {
            ListKind::Sites => "lists/list-general-user.txt",
            ListKind::Ips => "lists/ipset-all.txt",
            ListKind::ExcludeSites => "lists/list-exclude-user.txt",
            ListKind::ExcludeIps => "lists/ipset-exclude-user.txt",
        }
    }

    /// The engine refuses empty list files, so an empty user list is written
    /// as a documentation-range placeholder that never matches real traffic.
    pub fn placeholder(self) -> &'static str {
        match self {
            ListKind::Sites | ListKind::ExcludeSites => "domain.example.abc",
            ListKind::Ips | ListKind::ExcludeIps => "203.0.113.113/32",
        }
    }

    fn is_ip(self) -> bool {
        matches!(self, ListKind::Ips | ListKind::ExcludeIps)
    }
}

/// Normalizes a pasted line: drops scheme, path, port and a leading `*.`/`.`.
/// zapret host lists already match every subdomain of a listed name.
fn normalize_domain(line: &str) -> String {
    let mut value = line.trim().to_ascii_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            value = rest.to_owned();
        }
    }
    if let Some(end) = value.find(['/', '?', '#']) {
        value.truncate(end);
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            value = host.to_owned();
        }
    }
    value
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_owned()
}

fn valid_ip_entry(value: &str) -> bool {
    match value.split_once('/') {
        None => value.parse::<IpAddr>().is_ok(),
        Some((addr, prefix)) => match (addr.parse::<IpAddr>(), prefix.parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(bits)) => bits <= 32,
            (Ok(IpAddr::V6(_)), Ok(bits)) => bits <= 128,
            _ => false,
        },
    }
}

/// Parses editor text into clean entries. Errors carry the 1-based line
/// number and the original text, so the UI can point at them.
pub fn parse(kind: ListKind, text: &str) -> Result<Vec<String>, Vec<(usize, String)>> {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value = if kind.is_ip() {
            line.to_owned()
        } else {
            normalize_domain(line)
        };
        let ok = if kind.is_ip() {
            valid_ip_entry(&value)
        } else {
            zapreta_net::validate_hostname(&value).is_ok() && value.contains('.')
        };
        if !ok {
            errors.push((index + 1, raw.to_owned()));
        } else if value != kind.placeholder() && !entries.contains(&value) {
            entries.push(value);
        }
    }
    if errors.is_empty() {
        Ok(entries)
    } else {
        Err(errors)
    }
}

pub fn read(root: &Path, kind: ListKind) -> Vec<String> {
    let text = fs::read_to_string(root.join(kind.file())).unwrap_or_default();
    // Tolerate hand-edited files: keep only lines that parse.
    text.lines()
        .filter_map(|line| parse(kind, line).ok())
        .flatten()
        .collect()
}

pub fn write(root: &Path, kind: ListKind, entries: &[String]) -> io::Result<()> {
    let path = root.join(kind.file());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = if entries.is_empty() {
        format!("{}\n", kind.placeholder())
    } else {
        entries.join("\n") + "\n"
    };
    let temp = path.with_extension("zapreta-tmp");
    fs::write(&temp, body)?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(temp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_normalized_and_deduplicated() {
        let text = "https://Rutracker.org/forum?x=1\n*.example.com\n# comment\n\nexample.com\nsite.net:8443\n";
        assert_eq!(
            parse(ListKind::Sites, text).unwrap(),
            vec!["rutracker.org", "example.com", "site.net"]
        );
    }

    #[test]
    fn invalid_lines_are_reported_with_line_numbers() {
        let errors = parse(ListKind::Sites, "good.com\nnot a domain\nlocalhost\n").unwrap_err();
        assert_eq!(errors.iter().map(|e| e.0).collect::<Vec<_>>(), vec![2, 3]);
        let errors = parse(ListKind::Ips, "10.0.0.0/8\n2001:db8::/129\n1.2.3\n").unwrap_err();
        assert_eq!(errors.iter().map(|e| e.0).collect::<Vec<_>>(), vec![2, 3]);
    }

    #[test]
    fn ip_entries_accept_addresses_and_cidr() {
        assert_eq!(
            parse(ListKind::Ips, "1.2.3.4\n10.0.0.0/8\n2001:db8::/32\n").unwrap(),
            vec!["1.2.3.4", "10.0.0.0/8", "2001:db8::/32"]
        );
    }

    #[test]
    fn empty_list_is_written_as_placeholder_and_read_back_empty() {
        let root = std::env::temp_dir().join(format!("zapreta-lists-{}", std::process::id()));
        for kind in ListKind::ALL {
            write(&root, kind, &[]).unwrap();
            let raw = fs::read_to_string(root.join(kind.file())).unwrap();
            assert_eq!(raw.trim(), kind.placeholder());
            assert!(read(&root, kind).is_empty());
        }
        write(&root, ListKind::Sites, &["a.com".into(), "b.org".into()]).unwrap();
        assert_eq!(read(&root, ListKind::Sites), vec!["a.com", "b.org"]);
        let _ = fs::remove_dir_all(&root);
    }
}
