//! DNS fix for the user's own sites. Many blocked sites are also blocked by
//! DNS spoofing, which no packet desync can repair: the browser connects to
//! the wrong address. For user sites whose system answer is missing, special
//! or disjoint from the DoH answer, ZapretA writes the DoH addresses into a
//! clearly marked block in the Windows `hosts` file and removes the block when
//! the bypass is turned off.

use std::net::IpAddr;

pub const BEGIN: &str = "# BEGIN ZapretA (added automatically, removed when the bypass is off)";
pub const END: &str = "# END ZapretA";
const MAX_V4: usize = 4;
const MAX_V6: usize = 2;

fn special(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
    }
}

/// Whether the DoH answer should replace the system answer for this name.
pub fn needs_override(system: Option<&[IpAddr]>, doh: &[IpAddr]) -> bool {
    if doh.is_empty() || doh.iter().any(special) {
        return false;
    }
    match system {
        None | Some([]) => true,
        Some(addresses) => {
            addresses.iter().any(special) || !addresses.iter().any(|ip| doh.contains(ip))
        }
    }
}

/// Addresses written for one name: IPv4 first (always reachable at home),
/// IPv6 only when there is no IPv4 answer.
pub fn pick(doh: &[IpAddr]) -> Vec<IpAddr> {
    let v4: Vec<IpAddr> = doh
        .iter()
        .filter(|ip| ip.is_ipv4())
        .take(MAX_V4)
        .copied()
        .collect();
    if !v4.is_empty() {
        return v4;
    }
    doh.iter()
        .filter(|ip| ip.is_ipv6())
        .take(MAX_V6)
        .copied()
        .collect()
}

/// Removes ZapretA's block, keeping every other line untouched.
pub fn strip_block(hosts: &str) -> String {
    let newline = if hosts.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = Vec::new();
    let mut inside = false;
    for line in hosts.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed == BEGIN {
            inside = true;
            continue;
        }
        if inside {
            if trimmed == END {
                inside = false;
            }
            continue;
        }
        out.push(trimmed);
    }
    while out.last().is_some_and(|line| line.trim().is_empty()) {
        out.pop();
    }
    let mut text = out.join(newline);
    if !text.is_empty() {
        text.push_str(newline);
    }
    text
}

/// Rewrites the hosts text with a fresh block for `entries` (none = no block).
pub fn render(hosts: &str, entries: &[(String, IpAddr)]) -> String {
    let newline = if hosts.contains("\r\n") || hosts.is_empty() {
        "\r\n"
    } else {
        "\n"
    };
    let mut text = strip_block(hosts);
    if entries.is_empty() {
        return text;
    }
    if !text.is_empty() {
        text.push_str(newline);
    }
    text.push_str(BEGIN);
    text.push_str(newline);
    for (name, ip) in entries {
        text.push_str(&format!("{ip} {name}{newline}"));
    }
    text.push_str(END);
    text.push_str(newline);
    text
}

#[cfg(windows)]
pub mod system {
    use super::*;
    use std::{fs, io, path::PathBuf};

    pub fn hosts_path() -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(root).join("System32\\drivers\\etc\\hosts")
    }

    fn write_if_changed(new_text: &str) -> io::Result<bool> {
        let path = hosts_path();
        let current = fs::read_to_string(&path).unwrap_or_default();
        if current == new_text {
            return Ok(false);
        }
        fs::write(&path, new_text)?;
        let _ = crate::winutil::hidden("ipconfig").arg("/flushdns").status();
        Ok(true)
    }

    pub fn apply(entries: &[(String, IpAddr)]) -> io::Result<bool> {
        let current = fs::read_to_string(hosts_path()).unwrap_or_default();
        write_if_changed(&render(&current, entries))
    }

    pub fn clear() -> io::Result<bool> {
        let current = fs::read_to_string(hosts_path()).unwrap_or_default();
        write_if_changed(&strip_block(&current))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn override_only_for_missing_special_or_disjoint_answers() {
        let doh = [ip("195.82.146.214")];
        assert!(needs_override(None, &doh));
        assert!(needs_override(Some(&[]), &doh));
        assert!(needs_override(Some(&[ip("10.10.34.36")]), &doh));
        assert!(needs_override(Some(&[ip("188.186.157.49")]), &doh));
        assert!(!needs_override(
            Some(&[ip("195.82.146.214"), ip("1.1.1.1")]),
            &doh
        ));
        assert!(!needs_override(None, &[]));
        assert!(!needs_override(None, &[ip("127.0.0.1")]));
    }

    #[test]
    fn block_is_added_replaced_and_removed_without_touching_other_lines() {
        let original = "# comment\r\n127.0.0.1 localhost\r\n";
        let one = render(original, &[("rutracker.org".into(), ip("195.82.146.214"))]);
        assert!(one.starts_with(original));
        assert!(one.contains("195.82.146.214 rutracker.org\r\n"));
        assert!(one.contains(BEGIN) && one.contains(END));
        let two = render(&one, &[("a.example".into(), ip("203.0.113.5"))]);
        assert!(!two.contains("rutracker.org"));
        assert_eq!(two.matches(BEGIN).count(), 1);
        assert_eq!(strip_block(&two), original);
        assert_eq!(render(&two, &[]), original);
    }

    #[test]
    fn pick_prefers_ipv4_and_caps_counts() {
        let all = [
            ip("2001:db8::1"),
            ip("1.1.1.1"),
            ip("1.1.1.2"),
            ip("1.1.1.3"),
            ip("1.1.1.4"),
            ip("1.1.1.5"),
        ];
        assert_eq!(pick(&all).len(), 4);
        assert!(pick(&all).iter().all(IpAddr::is_ipv4));
        assert_eq!(pick(&[ip("2001:db8::1")]), vec![ip("2001:db8::1")]);
    }
}
