//! The Docker socket, host mounts, and a scan for credentials anywhere the agent can read.
use crate::{Env, Report, Verdict};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn sockets(r: &mut Report) {
    for path in [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/containerd/containerd.sock",
        "/var/run/colima/docker.sock",
    ] {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => r.stopped(
                false,
                "docker",
                format!("connect {path}"),
                "connected to a container runtime socket",
            ),
            Err(e) => r.stopped(
                true,
                "docker",
                format!("connect {path}"),
                crate::net::explain(&e),
            ),
        }
    }
    // Home-directory mounts, BOGO's directory and its owner socket must not be visible.
    let mut seen = Vec::new();
    for path in [
        "/Users",
        "/Volumes",
        "/host",
        "/mnt/host",
        "/root/.bogo",
        "/run/bogo.sock",
        "/private",
    ] {
        if Path::new(path).exists() {
            seen.push(path);
        }
    }
    for entry in fs::read_dir("/home").into_iter().flatten().flatten() {
        let p = entry.path().join(".bogo");
        if p.exists() {
            seen.push("/home/*/.bogo");
        }
    }
    r.stopped(
        seen.is_empty(),
        "mounts",
        "find host home directories, ~/.bogo or BOGO's owner socket",
        if seen.is_empty() {
            "none of /Users, /Volumes, /host, ~/.bogo or bogo.sock exists here".to_owned()
        } else {
            format!("visible: {seen:?}")
        },
    );
}

struct Pattern {
    name: &'static str,
    /// Bytes that start a match.
    prefix: &'static [u8],
    /// The match needs at least this many following bytes from `body`.
    min: usize,
    body: fn(u8) -> bool,
    /// Only in non-executable files: libraries embed PEM armor and sample keys as data.
    text_only: bool,
}

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n' | b'\r')
}
fn b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=')
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        name: "Stripe test secret key (sk_test_)",
        prefix: b"sk_test_",
        min: 20,
        body: alnum,
        text_only: false,
    },
    Pattern {
        name: "Stripe live secret key (sk_live_)",
        prefix: b"sk_live_",
        min: 20,
        body: alnum,
        text_only: false,
    },
    Pattern {
        name: "Stripe restricted key (rk_test_)",
        prefix: b"rk_test_",
        min: 20,
        body: alnum,
        text_only: false,
    },
    Pattern {
        name: "Stripe restricted key (rk_live_)",
        prefix: b"rk_live_",
        min: 20,
        body: alnum,
        text_only: false,
    },
    Pattern {
        name: "PKCS#8 private key (.p8 contents)",
        prefix: b"-----BEGIN PRIVATE KEY-----\n",
        min: 40,
        body: b64,
        text_only: true,
    },
    Pattern {
        name: "EC private key",
        prefix: b"-----BEGIN EC PRIVATE KEY-----\n",
        min: 40,
        body: b64,
        text_only: true,
    },
    Pattern {
        name: "OpenSSH private key",
        prefix: b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
        min: 40,
        body: b64,
        text_only: true,
    },
    Pattern {
        name: "BOGO agent token (bogo_agt_)",
        prefix: b"bogo_agt_",
        min: 43,
        body: b64url,
        text_only: false,
    },
    Pattern {
        name: "OAuth refresh token in JSON (Link auth file)",
        prefix: b"\"refresh_token\":\"",
        min: 20,
        body: token,
        text_only: false,
    },
    Pattern {
        name: "OAuth refresh token in JSON (Link auth file)",
        prefix: b"\"refresh_token\": \"",
        min: 20,
        body: token,
        text_only: false,
    },
    Pattern {
        name: "OAuth access token in JSON (Link auth file)",
        prefix: b"\"access_token\":\"",
        min: 20,
        body: token,
        text_only: false,
    },
    Pattern {
        name: "OAuth access token in JSON (Link auth file)",
        prefix: b"\"access_token\": \"",
        min: 20,
        body: token,
        text_only: false,
    },
    Pattern {
        name: "Link auth file (pending device login)",
        prefix: b"\"pendingDeviceAuth\":{",
        min: 0,
        body: alnum,
        text_only: true,
    },
    Pattern {
        name: "OAuth device code in JSON (Link auth file)",
        prefix: b"\"device_code\":\"",
        min: 20,
        body: token,
        text_only: false,
    },
];

/// File names that are BOGO's or Link's private files wherever they appear.
fn suspicious_name(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    let full = path.to_string_lossy();
    if name == "secrets.toml" {
        return Some("BOGO secrets.toml");
    }
    if name.ends_with(".p8") {
        return Some("APNs key file (.p8)");
    }
    if matches!(
        name,
        "mac_e2e.key" | "mac_relay.key" | "audit.jsonl" | "bogo.sock"
    ) {
        return Some("BOGO private file");
    }
    if full.contains("upstreams/stripe")
        || (full.contains("link-cli")
            && name.ends_with(".json")
            && (full.contains(".config") || full.contains("Preferences")))
    {
        return Some("Link auth file");
    }
    None
}

/// Finds patterns in `data`; returns (pattern, matched text) without ever printing it.
fn find(data: &[u8], own: &[String], binary: bool, hits: &mut Vec<&'static str>) {
    for p in PATTERNS.iter().filter(|p| !(binary && p.text_only)) {
        let mut at = 0;
        while let Some(i) = memmem(&data[at..], p.prefix) {
            let start = at + i;
            let rest = &data[start + p.prefix.len()..];
            let run = rest.iter().take_while(|&&b| (p.body)(b)).count();
            if run >= p.min {
                let matched = &data[start..start + p.prefix.len() + run];
                if !own.iter().any(|t| t.as_bytes() == matched) && !hits.contains(&p.name) {
                    hits.push(p.name);
                }
            }
            at = start + 1;
        }
    }
}

fn memmem(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        i += hay[i..hay.len() - needle.len() + 1]
            .iter()
            .position(|&b| b == first)?;
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn scan_file(path: &Path, own: &[String]) -> std::io::Result<Vec<&'static str>> {
    let mut f = fs::File::open(path)?;
    let mut hits = Vec::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut carry: Vec<u8> = Vec::new();
    let mut binary = None;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut chunk = std::mem::take(&mut carry);
        chunk.extend_from_slice(&buf[..n]);
        let binary = *binary.get_or_insert_with(|| chunk.starts_with(b"\x7fELF"));
        find(&chunk, own, binary, &mut hits);
        let keep = chunk.len().min(512);
        carry = chunk[chunk.len() - keep..].to_vec();
    }
    Ok(hits)
}

pub fn credentials(r: &mut Report, env: &Env) {
    // The agent's own BOGO tokens are expected in its environment; nothing else is.
    let own: Vec<String> = [env.token.clone(), env.second_token.clone()]
        .into_iter()
        .flatten()
        .collect();
    let me = fs::read_link("/proc/self/exe").ok();
    let mut stack: Vec<PathBuf> = vec![PathBuf::from("/")];
    let (mut files, mut unreadable, mut bytes) = (0usize, 0usize, 0u64);
    let mut findings: Vec<(String, &'static str)> = Vec::new();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            unreadable += 1;
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                if !matches!(path.to_str(), Some("/proc" | "/sys" | "/dev")) {
                    stack.push(path);
                }
                continue;
            }
            if let Some(kind) = suspicious_name(&path) {
                findings.push((path.display().to_string(), kind));
            }
            if !meta.is_file() || me.as_deref() == Some(path.as_path()) {
                continue;
            }
            match scan_file(&path, &own) {
                Ok(hits) => {
                    files += 1;
                    bytes += meta.len();
                    for h in hits {
                        findings.push((path.display().to_string(), h));
                    }
                }
                Err(_) => unreadable += 1,
            }
        }
    }
    // Every process's environment and command line this user can read.
    let mut procs = 0;
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let pid = entry.file_name();
        if !pid.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        for part in ["environ", "cmdline"] {
            let p = entry.path().join(part);
            if let Ok(data) = fs::read(&p) {
                procs += 1;
                let mut hits = Vec::new();
                find(&data, &own, false, &mut hits);
                for h in hits {
                    findings.push((p.display().to_string(), h));
                }
            }
        }
    }
    let mut vars = Vec::new();
    for (k, v) in std::env::vars() {
        let mut hits = Vec::new();
        find(v.as_bytes(), &own, false, &mut hits);
        if !hits.is_empty() {
            vars.push(k);
        }
    }
    r.add(Verdict::Info, "secrets", "scope", format!("{files} files ({} MiB) under /, {procs} /proc environ and cmdline files, {} environment variables; {unreadable} paths unreadable to this user", bytes >> 20, std::env::vars().count()));
    if findings.is_empty() && vars.is_empty() {
        r.stopped(true, "secrets", "find Stripe keys, .p8 keys, secrets.toml, BOGO's keys or log, Link's auth file, other agents' tokens", "nothing found");
    }
    for (path, kind) in findings {
        r.stopped(
            false,
            "secrets",
            format!("found {kind}"),
            format!("at {path} (contents not printed)"),
        );
    }
    for k in vars {
        r.stopped(
            false,
            "secrets",
            "found a credential in the environment",
            format!("variable {k} (value not printed)"),
        );
    }
}
