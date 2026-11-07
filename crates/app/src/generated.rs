//! ZapretA's own TLS strategies, tried after the pinned Flowseal profiles.
//!
//! The families and their order follow `blockcheck.sh` from bol-van/zapret
//! v72.9 (the engine version embedded here): plain splits first, then
//! disorder, sequence-overlap splits, fakes with TTL / autottl / fooling, the
//! fake+split hybrids and finally window-size reduction. Fooling modes that
//! the upstream docs flag as unreliable on Windows clients or non-Linux
//! servers (`md5sig`, `datanoack`) are not used; `ts` is placed last because
//! TCP timestamps are disabled by default in Windows. Every flag is checked
//! against the embedded `winws.exe` option table in the tests below.

use crate::autoselect::Loaded;

/// Domain lists shared with the Flowseal profiles, plus the user's own lists.
const HOSTLISTS: &[&str] = &[
    "--hostlist=lists/list-general.txt",
    "--hostlist=lists/list-general-user.txt",
    "--hostlist=lists/list-google.txt",
];
const EXCLUDES: &[&str] = &[
    "--hostlist-exclude=lists/list-exclude.txt",
    "--hostlist-exclude=lists/list-exclude-user.txt",
    "--ipset-exclude=lists/ipset-exclude.txt",
    "--ipset-exclude=lists/ipset-exclude-user.txt",
];

/// (id suffix, short label, TLS desync arguments)
const TLS_VARIANTS: &[(&str, &str, &[&str])] = &[
    (
        "split-1",
        "multisplit 1",
        &["--dpi-desync=multisplit", "--dpi-desync-split-pos=1"],
    ),
    (
        "split-2",
        "multisplit 2",
        &["--dpi-desync=multisplit", "--dpi-desync-split-pos=2"],
    ),
    (
        "split-sniext",
        "multisplit sniext+1",
        &["--dpi-desync=multisplit", "--dpi-desync-split-pos=sniext+1"],
    ),
    (
        "split-midsld",
        "multisplit midsld",
        &["--dpi-desync=multisplit", "--dpi-desync-split-pos=midsld"],
    ),
    (
        "split-1-midsld",
        "multisplit 1,midsld",
        &["--dpi-desync=multisplit", "--dpi-desync-split-pos=1,midsld"],
    ),
    (
        "disorder-1",
        "multidisorder 1",
        &["--dpi-desync=multidisorder", "--dpi-desync-split-pos=1"],
    ),
    (
        "disorder-midsld",
        "multidisorder midsld",
        &[
            "--dpi-desync=multidisorder",
            "--dpi-desync-split-pos=midsld",
        ],
    ),
    (
        "disorder-1-midsld",
        "multidisorder 1,midsld",
        &[
            "--dpi-desync=multidisorder",
            "--dpi-desync-split-pos=1,midsld",
        ],
    ),
    (
        "seqovl-10",
        "multisplit seqovl 1",
        &[
            "--dpi-desync=multisplit",
            "--dpi-desync-split-pos=10,midsld",
            "--dpi-desync-split-seqovl=1",
        ],
    ),
    (
        "seqovl-pattern",
        "multisplit seqovl 336 + fake ClientHello",
        &[
            "--dpi-desync=multisplit",
            "--dpi-desync-split-pos=2",
            "--dpi-desync-split-seqovl=336",
            "--dpi-desync-split-seqovl-pattern=bin/tls_clienthello_www_google_com.bin",
        ],
    ),
    (
        "disorder-seqovl-2",
        "multidisorder seqovl 1/2",
        &[
            "--dpi-desync=multidisorder",
            "--dpi-desync-split-pos=2",
            "--dpi-desync-split-seqovl=1",
        ],
    ),
    (
        "disorder-seqovl-midsld",
        "multidisorder seqovl midsld",
        &[
            "--dpi-desync=multidisorder",
            "--dpi-desync-split-pos=midsld",
            "--dpi-desync-split-seqovl=midsld-1",
        ],
    ),
    (
        "fake-ttl4",
        "fake ttl 4",
        &["--dpi-desync=fake", "--dpi-desync-ttl=4"],
    ),
    (
        "fake-ttl6-mod",
        "fake ttl 6, rnd SNI",
        &[
            "--dpi-desync=fake",
            "--dpi-desync-ttl=6",
            "--dpi-desync-fake-tls-mod=rnd,rndsni,dupsid",
        ],
    ),
    (
        "fake-autottl",
        "fake autottl -2",
        &[
            "--dpi-desync=fake",
            "--dpi-desync-ttl=1",
            "--dpi-desync-autottl=-2",
        ],
    ),
    (
        "fake-badseq",
        "fake badseq",
        &["--dpi-desync=fake", "--dpi-desync-fooling=badseq"],
    ),
    (
        "fake-badseq0",
        "fake badseq inc 0",
        &[
            "--dpi-desync=fake",
            "--dpi-desync-fooling=badseq",
            "--dpi-desync-badseq-increment=0",
        ],
    ),
    (
        "fake-badsum",
        "fake badsum",
        &["--dpi-desync=fake", "--dpi-desync-fooling=badsum"],
    ),
    (
        "fake-split-badseq",
        "fake+multisplit badseq",
        &[
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-split-pos=1",
            "--dpi-desync-fooling=badseq",
        ],
    ),
    (
        "fake-split-ttl4",
        "fake+multisplit ttl 4, rnd SNI",
        &[
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-split-pos=midsld",
            "--dpi-desync-ttl=4",
            "--dpi-desync-fake-tls-mod=rnd,rndsni,dupsid",
        ],
    ),
    (
        "fake-disorder-badseq",
        "fake+multidisorder badseq",
        &[
            "--dpi-desync=fake,multidisorder",
            "--dpi-desync-split-pos=1,midsld",
            "--dpi-desync-fooling=badseq",
        ],
    ),
    (
        "fakedsplit-badseq",
        "fakedsplit badseq",
        &[
            "--dpi-desync=fakedsplit",
            "--dpi-desync-split-pos=1",
            "--dpi-desync-fooling=badseq",
        ],
    ),
    (
        "fakedsplit-ttl4",
        "fakedsplit ttl 4 altorder",
        &[
            "--dpi-desync=fakedsplit",
            "--dpi-desync-split-pos=midsld",
            "--dpi-desync-ttl=4",
            "--dpi-desync-fakedsplit-mod=altorder=1",
        ],
    ),
    (
        "fakeddisorder-badseq",
        "fakeddisorder badseq",
        &[
            "--dpi-desync=fakeddisorder",
            "--dpi-desync-split-pos=midsld",
            "--dpi-desync-fooling=badseq",
        ],
    ),
    (
        "hostfakesplit-badseq",
        "hostfakesplit badseq",
        &["--dpi-desync=hostfakesplit", "--dpi-desync-fooling=badseq"],
    ),
    (
        "hostfakesplit-ttl4",
        "hostfakesplit ttl 4 midhost",
        &[
            "--dpi-desync=hostfakesplit",
            "--dpi-desync-ttl=4",
            "--dpi-desync-hostfakesplit-midhost=midsld",
        ],
    ),
    (
        "fake-split-repeats",
        "fake+multisplit x6, Google ClientHello",
        &[
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-split-pos=1",
            "--dpi-desync-fooling=badseq",
            "--dpi-desync-repeats=6",
            "--dpi-desync-fake-tls=bin/tls_clienthello_www_google_com.bin",
        ],
    ),
    (
        "wssize",
        "wssize 1:6 + multisplit (медленнее)",
        &[
            "--wssize=1:6",
            "--dpi-desync=multisplit",
            "--dpi-desync-split-pos=1",
        ],
    ),
    (
        "fake-split-ts",
        "fake+multisplit ts",
        &[
            "--dpi-desync=fake,multisplit",
            "--dpi-desync-split-pos=1",
            "--dpi-desync-fooling=ts",
        ],
    ),
];

fn push_all(argv: &mut Vec<String>, items: &[&str]) {
    argv.extend(items.iter().map(|item| (*item).to_owned()));
}

fn build(suffix: &str, label: &str, tls: &[&str]) -> Loaded {
    let mut argv = Vec::new();
    push_all(&mut argv, &["--wf-tcp=80,443", "--wf-udp=443"]);
    // QUIC: same fake Initial approach as the Flowseal profiles.
    push_all(&mut argv, &["--filter-udp=443"]);
    push_all(&mut argv, HOSTLISTS);
    push_all(&mut argv, EXCLUDES);
    push_all(
        &mut argv,
        &[
            "--dpi-desync=fake",
            "--dpi-desync-repeats=6",
            "--dpi-desync-fake-quic=bin/quic_initial_www_google_com.bin",
            "--new",
        ],
    );
    // TLS for listed domains.
    push_all(&mut argv, &["--filter-tcp=443"]);
    push_all(&mut argv, HOSTLISTS);
    push_all(&mut argv, EXCLUDES);
    push_all(&mut argv, tls);
    push_all(&mut argv, &["--new"]);
    // TLS for the user's own IP addresses and subnets.
    push_all(
        &mut argv,
        &["--filter-tcp=443", "--ipset=lists/ipset-all.txt"],
    );
    push_all(&mut argv, EXCLUDES);
    push_all(&mut argv, tls);
    push_all(&mut argv, &["--new"]);
    // Plain HTTP for listed domains.
    push_all(&mut argv, &["--filter-tcp=80"]);
    push_all(&mut argv, HOSTLISTS);
    push_all(&mut argv, EXCLUDES);
    push_all(
        &mut argv,
        &["--dpi-desync=multisplit", "--dpi-desync-split-pos=method+2"],
    );
    Loaded {
        id: format!("zapreta-{suffix}"),
        label: format!("ZapretA: {label}"),
        argv,
        covers_tcp: true,
        covers_udp: true,
    }
}

pub fn strategies() -> Vec<Loaded> {
    TLS_VARIANTS
        .iter()
        .map(|(suffix, label, tls)| build(suffix, label, tls))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const WINWS: &[u8] = include_bytes!("../assets/engine/winws.exe");

    /// getopt long option names are stored as NUL-terminated strings.
    fn engine_knows(option: &str) -> bool {
        let needle = [b"\0", option.as_bytes(), b"\0"].concat();
        WINWS.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn every_flag_exists_in_the_embedded_engine() {
        for strategy in strategies() {
            for token in &strategy.argv {
                let name = token
                    .trim_start_matches("--")
                    .split('=')
                    .next()
                    .unwrap_or_default();
                assert!(
                    engine_knows(name),
                    "{}: unknown engine option {token}",
                    strategy.id
                );
            }
        }
    }

    #[test]
    fn referenced_files_are_embedded_or_user_lists() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/engine");
        for strategy in strategies() {
            for token in &strategy.argv {
                let Some((_, value)) = token.split_once('=') else {
                    continue;
                };
                if value.starts_with("lists/") || value.starts_with("bin/") {
                    let user_list = value.ends_with("-user.txt") || value == "lists/ipset-all.txt";
                    assert!(
                        user_list || root.join(value).is_file(),
                        "{}: missing {value}",
                        strategy.id
                    );
                }
            }
        }
    }

    #[test]
    fn ids_are_unique_and_do_not_collide_with_flowseal() {
        let ids: HashSet<_> = strategies().into_iter().map(|s| s.id).collect();
        assert_eq!(ids.len(), TLS_VARIANTS.len());
        assert!(ids.iter().all(|id| id.starts_with("zapreta-")));
    }

    #[test]
    fn engine_option_check_rejects_made_up_flags() {
        assert!(engine_knows("dpi-desync-split-pos"));
        assert!(!engine_knows("dpi-desync-made-up"));
    }
}
