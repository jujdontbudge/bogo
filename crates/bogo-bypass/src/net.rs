//! Network attempts: TCP, UDP, DNS, the forwarders, and changing the rules.
use crate::{Env, Report, Verdict};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_millis(700);

/// How one connection attempt ended.
pub enum Outcome {
    Connected,
    Stopped(String),
}

/// An error that shows the network refused the attempt. Anything else (out of file
/// descriptors or buffers, say) means the attempt never happened, so it is reported
/// as reached: a check that could not be made must not pass.
fn refused(e: &std::io::Error) -> Outcome {
    let network = matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) || matches!(e.raw_os_error(), Some(1 | 13 | 97 | 99 | 101 | 113));
    if network {
        Outcome::Stopped(explain(e))
    } else {
        Outcome::Connected
    }
}

/// Names an OS error and says what in the sandbox produced it.
pub fn explain(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::TimedOut || e.kind() == std::io::ErrorKind::WouldBlock {
        return "timed out: no packet came back (dropped)".into();
    }
    match e.raw_os_error() {
        Some(1) => "EPERM: dropped by the sandbox's nftables output rule".into(),
        Some(13) => "EACCES: refused by the sandbox".into(),
        Some(99) => "EADDRNOTAVAIL: no source address for it (IPv6 is disabled)".into(),
        Some(101) => "ENETUNREACH: no route out of the sandbox".into(),
        Some(113) => "EHOSTUNREACH: host unreachable from the sandbox".into(),
        Some(111) => "ECONNREFUSED: a reply came back (the packet got through)".into(),
        Some(2) => "ENOENT: does not exist in the sandbox".into(),
        Some(97) => "EAFNOSUPPORT: address family unavailable".into(),
        _ => format!("{e}"),
    }
}

pub fn tcp(addr: SocketAddr) -> Outcome {
    match TcpStream::connect_timeout(&addr, TIMEOUT) {
        Ok(_) => Outcome::Connected,
        // A refusal means a reply crossed the boundary, so it counts as reaching the target.
        Err(e) if e.raw_os_error() == Some(111) => Outcome::Connected,
        Err(e) => refused(&e),
    }
}

fn row_tcp(r: &mut Report, area: &'static str, what: &str, addr: SocketAddr) {
    match tcp(addr) {
        Outcome::Connected => r.stopped(
            false,
            area,
            format!("TCP {what} {addr}"),
            "connected: it got through",
        ),
        Outcome::Stopped(how) => r.stopped(true, area, format!("TCP {what} {addr}"), how),
    }
}

pub fn process(r: &mut Report) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| {
                l.strip_prefix(k)
                    .map(|v| v.split_whitespace().collect::<Vec<_>>().join(" "))
            })
            .unwrap_or_else(|| "?".into())
    };
    let (uid, cap_eff, cap_bnd, nnp) = (
        field("Uid:"),
        field("CapEff:"),
        field("CapBnd:"),
        field("NoNewPrivs:"),
    );
    r.add(
        Verdict::Info,
        "process",
        "identity",
        format!("Uid {uid}; CapEff {cap_eff}; CapBnd {cap_bnd}; NoNewPrivs {nnp}"),
    );
    let root = uid.split(' ').next() == Some("0");
    let caps = cap_eff.trim_start_matches('0').is_empty();
    r.stopped(
        !root && caps,
        "process",
        "run as root or hold any capability",
        if !root && caps {
            "non-root with no effective capabilities"
        } else {
            "the sandbox gave this process root or capabilities"
        },
    );
}

pub fn direct(r: &mut Report, env: &Env) {
    if env.targets.is_empty() {
        r.add(
            Verdict::Fail,
            "direct",
            "resolved upstream addresses",
            "BYPASS_TARGETS is empty; run through sandbox/bypass.sh",
        );
    }
    for (name, ips) in &env.targets {
        let mut ports = vec![443, 80];
        if name.contains("eilmer") && !ports.contains(&env.relay_port) {
            ports.push(env.relay_port);
        }
        for ip in ips {
            for port in &ports {
                row_tcp(r, "direct", name, SocketAddr::new(*ip, *port));
            }
        }
    }
    for (what, addr) in [
        ("public DNS", "1.1.1.1:443"),
        ("public DNS", "8.8.8.8:443"),
        ("public IP", "9.9.9.9:443"),
        ("cloud metadata", "169.254.169.254:80"),
        ("ECS metadata", "169.254.170.2:80"),
        ("Alibaba metadata", "100.100.100.200:80"),
        ("IPv6 public", "[2606:4700:4700::1111]:443"),
        ("IPv6 public", "[2001:4860:4860::8888]:443"),
        ("IPv6 metadata", "[fd00:ec2::254]:80"),
        ("IPv6 loopback", "[::1]:8790"),
        ("other loopback", "127.0.0.2:8790"),
    ] {
        row_tcp(r, "direct", what, addr.parse().unwrap());
    }
    // The namespace's own loopback is allowed; nothing of BOGO's is there.
    let how = match tcp("127.0.0.1:8790".parse().unwrap()) {
        Outcome::Connected => {
            "a local process in the sandbox answered (or refused): loopback is the namespace's own"
                .to_owned()
        }
        Outcome::Stopped(how) => how,
    };
    r.add(
        Verdict::Info,
        "direct",
        "TCP own loopback 127.0.0.1:8790",
        how,
    );
}

fn query(name: &str) -> Vec<u8> {
    let mut q = vec![
        rand::random::<u8>(),
        rand::random::<u8>(),
        1,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

fn udp_dns(server: SocketAddr, name: &str) -> Outcome {
    let bind = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => return refused(&e),
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1200)));
    if let Err(e) = sock.send_to(&query(name), server) {
        return refused(&e);
    }
    let mut buf = [0u8; 512];
    match sock.recv_from(&mut buf) {
        Ok(_) => Outcome::Connected,
        Err(e) => Outcome::Stopped(format!("sent, {}", explain(&e))),
    }
}

fn resolvers(env: &Env) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = [
        "127.0.0.11",
        "172.30.0.1",
        "1.1.1.1",
        "8.8.8.8",
        "192.168.5.3",
        "192.168.65.7",
        "2606:4700:4700::1111",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    for ip in &env.host_addrs {
        if !v.contains(&IpAddr::V4(*ip)) {
            v.push(IpAddr::V4(*ip));
        }
    }
    v.push(IpAddr::V4(*env.gate.ip()));
    v
}

pub fn dns(r: &mut Report, env: &Env) {
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    r.add(
        Verdict::Info,
        "dns",
        "/etc/resolv.conf nameservers",
        resolv
            .lines()
            .filter(|l| l.starts_with("nameserver"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    for name in [
        "api.stripe.com",
        "link.com",
        "api.link.com",
        "bogo.eilmer.si",
        "registry.npmjs.org",
        "example.com",
        "host.docker.internal",
        "gateway.docker.internal",
        "gate",
        "netpol",
        "agent",
        "metadata.google.internal",
    ] {
        let static_entry = hosts.lines().any(|l| {
            !l.trim_start().starts_with('#') && l.split_whitespace().skip(1).any(|h| h == name)
        });
        match (name, 443).to_socket_addrs() {
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.map(|a| a.ip().to_string()).collect();
                r.stopped(
                    false,
                    "dns",
                    format!("resolve {name}"),
                    format!(
                        "resolved to {}{}",
                        addrs.join(", "),
                        if static_entry {
                            " (from /etc/hosts)"
                        } else {
                            ""
                        }
                    ),
                );
            }
            Err(e) => r.stopped(
                true,
                "dns",
                format!("resolve {name}"),
                format!("lookup failed: {e}"),
            ),
        }
    }
    match (env.model_host.as_str(), 443).to_socket_addrs() {
        Ok(addrs) => r.add(Verdict::Info, "dns", format!("resolve {}", env.model_host), format!("{} from the static /etc/hosts entry for the model forwarder (§11 Q1); not a DNS answer", addrs.map(|a| a.ip().to_string()).collect::<Vec<_>>().join(", "))),
        Err(e) => r.add(Verdict::Info, "dns", format!("resolve {}", env.model_host), format!("lookup failed: {e}")),
    }
    for server in resolvers(env) {
        for name in ["api.stripe.com", "gate"] {
            let addr = SocketAddr::new(server, 53);
            match udp_dns(addr, name) {
                Outcome::Connected => r.stopped(
                    false,
                    "dns",
                    format!("UDP query {name} to {addr}"),
                    "an answer came back",
                ),
                Outcome::Stopped(how) => {
                    r.stopped(true, "dns", format!("UDP query {name} to {addr}"), how)
                }
            }
        }
        row_tcp(r, "dns", "DNS", SocketAddr::new(server, 53));
    }
    // Docker's resolver listens on random ports behind its own NAT rule; try them all.
    scan(r, "dns", Ipv4Addr::new(127, 0, 0, 11), &[]);
    let udp = udp_scan(Ipv4Addr::new(127, 0, 0, 11));
    r.stopped(
        udp.0 == 0,
        "dns",
        "UDP to 127.0.0.11 on every port 1-65535",
        udp.1,
    );
}

fn udp_scan(ip: Ipv4Addr) -> (usize, String) {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return (0, "could not open a UDP socket".into());
    };
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut sent = 0;
    for port in 1..=65535u16 {
        match sock.send_to(&query("gate"), (ip, port)) {
            Ok(_) => sent += 1,
            Err(e) => *kinds.entry(explain(&e)).or_default() += 1,
        }
    }
    let mut how: Vec<String> = kinds.iter().map(|(k, n)| format!("{n}× {k}")).collect();
    if sent > 0 {
        how.push(format!("{sent} datagrams left the socket"));
    }
    (sent, how.join("; "))
}

/// Tries many TCP destinations at once. Dropped SYNs only time out, so the attempts run
/// concurrently with a short timeout; every destination here is a hop or two away.
pub fn probe_many(addrs: Vec<SocketAddr>) -> Vec<(SocketAddr, Outcome)> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        let mut out = Vec::with_capacity(addrs.len());
        for batch in addrs.chunks(1024) {
            let mut set = tokio::task::JoinSet::new();
            for &addr in batch {
                set.spawn(async move {
                    let attempt =
                        tokio::time::timeout(SCAN_TIMEOUT, tokio::net::TcpStream::connect(addr))
                            .await;
                    let outcome = match attempt {
                        Ok(Ok(_)) => Outcome::Connected,
                        Ok(Err(e)) if e.raw_os_error() == Some(111) => Outcome::Connected,
                        Ok(Err(e)) => refused(&e),
                        Err(_) => {
                            Outcome::Stopped("timed out: no packet came back (dropped)".into())
                        }
                    };
                    (addr, outcome)
                });
            }
            while let Some(r) = set.join_next().await {
                out.push(r.expect("probe task"));
            }
        }
        out
    })
}

const SCAN_TIMEOUT: Duration = Duration::from_millis(400);

/// Counts outcomes; returns (reached destinations, "n× how" summary).
fn tally(results: Vec<(SocketAddr, Outcome)>) -> (Vec<SocketAddr>, String) {
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let mut reached = Vec::new();
    for (addr, o) in results {
        match o {
            Outcome::Connected => reached.push(addr),
            Outcome::Stopped(how) => *kinds.entry(how).or_default() += 1,
        }
    }
    reached.sort();
    (
        reached,
        kinds
            .iter()
            .map(|(k, c)| format!("{c}× {k}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Tries every TCP port on `ip` except `allowed`. One row per address.
pub fn scan(r: &mut Report, area: &'static str, ip: Ipv4Addr, allowed: &[u16]) {
    let addrs: Vec<SocketAddr> = (1..=65535u16)
        .filter(|p| !allowed.contains(p))
        .map(|p| SocketAddr::new(IpAddr::V4(ip), p))
        .collect();
    let n = addrs.len();
    let (reached, how) = tally(probe_many(addrs));
    let except = if allowed.is_empty() {
        String::new()
    } else {
        format!(
            " except {}",
            allowed
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let attempt = format!("TCP {ip} on all {n} ports{except}");
    if reached.is_empty() {
        r.stopped(true, area, attempt, how);
    } else {
        let ports: Vec<u16> = reached.iter().map(SocketAddr::port).collect();
        r.stopped(
            false,
            area,
            attempt,
            format!("reached ports {ports:?}; {how}"),
        );
    }
}

pub fn ports(r: &mut Report, env: &Env) {
    let gate = *env.gate.ip();
    scan(r, "ports", gate, &[env.gate.port()]);
    if let Some(model) = env.model_gate {
        scan(r, "ports", *model.ip(), &[model.port()]);
    }
    for ip in &env.host_addrs {
        scan(r, "ports", *ip, &[]);
    }
    // Every other address on bogo-net, on the ports a service would use.
    let me: Vec<Ipv4Addr> = local_v4();
    let mut addrs = Vec::new();
    for last in 1..=254u8 {
        let ip = Ipv4Addr::new(172, 30, 0, last);
        if ip == gate
            || Some(ip) == env.model_gate.map(|m| *m.ip())
            || me.contains(&ip)
            || env.host_addrs.contains(&ip)
        {
            continue;
        }
        for port in [22u16, 53, 80, 443, 2375, 8790] {
            addrs.push(SocketAddr::new(IpAddr::V4(ip), port));
        }
    }
    let tried = addrs.len();
    let (reached, how) = tally(probe_many(addrs));
    r.stopped(
        reached.is_empty(),
        "ports",
        format!("TCP other bogo-net addresses 172.30.0.1-254 ({tried} address:port pairs)"),
        if reached.is_empty() {
            how
        } else {
            format!("reached {reached:?}")
        },
    );
    // The only allowed path, as a control.
    match tcp(SocketAddr::V4(env.gate)) {
        Outcome::Connected => r.add(
            Verdict::Ok,
            "ports",
            format!("TCP BOGO's gate {}", env.gate),
            "connected (the one allowed path)",
        ),
        Outcome::Stopped(how) => r.add(
            Verdict::Fail,
            "ports",
            format!("TCP BOGO's gate {}", env.gate),
            format!("control failed: {how}"),
        ),
    }
}

fn local_v4() -> Vec<Ipv4Addr> {
    // The namespace's own address, learned from a route lookup to the gate.
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("172.30.0.2:9").map(|_| s))
        .and_then(|s| s.local_addr())
        .ok()
        .and_then(|a| match a.ip() {
            IpAddr::V4(v) => Some(vec![v]),
            IpAddr::V6(_) => None,
        })
        .unwrap_or_default()
}

pub fn forwarders(r: &mut Report, env: &Env) {
    // The gate parses nothing: a proxy request reaches BOGO, which refuses it.
    for (label, req) in [
        (
            "HTTP CONNECT api.stripe.com:443 through the gate",
            "CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n",
        ),
        (
            "absolute-URI proxy GET http://api.stripe.com/ through the gate",
            "GET http://api.stripe.com/v1/charges HTTP/1.1\r\nHost: api.stripe.com\r\nConnection: close\r\n\r\n",
        ),
    ] {
        match raw_http(SocketAddr::V4(env.gate), req) {
            Ok(status) => {
                let proxied = status.contains(" 200");
                r.stopped(
                    !proxied,
                    "proxy",
                    label,
                    format!("BOGO answered {status:?}: not a proxy"),
                );
            }
            Err(e) => r.stopped(true, "proxy", label, explain(&e)),
        }
    }
    let Some(model) = env.model_gate else {
        r.add(
            Verdict::Info,
            "proxy",
            "model forwarder",
            "BYPASS_MODEL_GATE not set: no model forwarder in this sandbox",
        );
        return;
    };
    match raw_http(
        SocketAddr::V4(model),
        "CONNECT api.stripe.com:443 HTTP/1.1\r\nHost: api.stripe.com:443\r\n\r\n",
    ) {
        Ok(status) => r.stopped(
            !status.contains(" 200"),
            "proxy",
            "HTTP CONNECT api.stripe.com through the model forwarder",
            format!("answered {status:?}: the forwarder only reaches the model host's TLS port"),
        ),
        Err(e) => r.stopped(
            true,
            "proxy",
            "HTTP CONNECT api.stripe.com through the model forwarder",
            explain(&e),
        ),
    }
    // TLS through the model forwarder with another name, in the SNI or only in the Host
    // header (domain fronting), must not reach that name. The forwarder's TCP endpoint is
    // fixed, so what answers is always the model host's edge.
    let edge = "refused by the model host's edge, not by the sandbox: the forwarder only ever reaches the model host (§11 Q1)";
    let mut attempts: Vec<(String, String, Option<String>)> = Vec::new();
    for name in [
        "api.stripe.com",
        "api.link.com",
        "link.com",
        "bogo.eilmer.si",
        "registry.npmjs.org",
    ] {
        attempts.push((
            format!("HTTPS {name} through the model forwarder (SNI {name})"),
            name.to_owned(),
            None,
        ));
    }
    for name in ["api.stripe.com", "bogo.eilmer.si", "registry.npmjs.org"] {
        attempts.push((
            format!(
                "domain fronting: SNI {} with Host {name} through the model forwarder",
                env.model_host
            ),
            env.model_host.clone(),
            Some(name.to_owned()),
        ));
    }
    for (label, sni, host) in attempts {
        match https_via(&sni, model, host.as_deref()) {
            Ok(a) if a.edge_refusal() => {
                r.stopped(true, "proxy", label, format!("{}: {edge}", a.describe()))
            }
            Ok(a) => r.stopped(false, "proxy", label, format!("answered {}", a.describe())),
            Err(e) => r.stopped(true, "proxy", label, e),
        }
    }
    match https_via(&env.model_host, model, None) {
        Ok(a) => r.add(
            Verdict::Ok,
            "proxy",
            format!("HTTPS {} through the model forwarder", env.model_host),
            format!(
                "{} (allowed by §11 Q1; the trust store works, so TLS failures above are real)",
                a.describe()
            ),
        ),
        Err(e) => r.add(
            Verdict::Info,
            "proxy",
            format!("HTTPS {} through the model forwarder", env.model_host),
            format!("failed: {e}"),
        ),
    }
}

fn raw_http(addr: SocketAddr, req: &str) -> std::io::Result<String> {
    let mut s = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(req.as_bytes())?;
    let mut buf = vec![0; 256];
    let n = s.read(&mut buf)?;
    let text = String::from_utf8_lossy(&buf[..n]);
    Ok(text
        .lines()
        .next()
        .unwrap_or("(connection closed without a reply)")
        .to_owned())
}

/// What a server said over TLS through the model forwarder.
struct Answer {
    status: u16,
    server: String,
    body: String,
}

impl Answer {
    /// The model host's edge (Cloudflare) refusing to route the request: error 1034
    /// (edge IP restricted) for another zone, or a plain 403 for an SNI/Host mismatch.
    fn edge_refusal(&self) -> bool {
        self.status == 403 && self.server.eq_ignore_ascii_case("cloudflare")
    }
    fn describe(&self) -> String {
        let body = self.body.split_whitespace().collect::<Vec<_>>().join(" ");
        let body: String = body.chars().take(60).collect();
        format!("HTTP {} server={} body {body:?}", self.status, self.server)
    }
}

fn https_via(
    name: &str,
    forwarder: std::net::SocketAddrV4,
    host: Option<&str>,
) -> Result<Answer, String> {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .resolve(name, SocketAddr::V4(forwarder))
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;
    let mut req = client.get(format!("https://{name}:{}/", forwarder.port()));
    if let Some(h) = host {
        req = req.header("Host", h);
    }
    match req.send() {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let server = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let body = resp.text().unwrap_or_default();
            Ok(Answer {
                status,
                server,
                body,
            })
        }
        Err(e) => {
            let mut msg = e.to_string();
            let mut src = std::error::Error::source(&e);
            while let Some(s) = src {
                msg = format!("{msg}: {s}");
                src = s.source();
            }
            Err(format!("TLS refused: {msg}"))
        }
    }
}

/// Sends nftables' "delete every table" batch over netlink, as `nft flush ruleset` does.
#[cfg(target_os = "linux")]
fn netlink_flush() -> Result<(), String> {
    use socket2::{Domain, Protocol, Socket, Type};
    const NETLINK_NETFILTER: i32 = 12;
    const NFNL_SUBSYS_NFTABLES: u16 = 10;
    let sock = Socket::new(
        Domain::from(16),
        Type::RAW,
        Some(Protocol::from(NETLINK_NETFILTER)),
    )
    .map_err(|e| explain(&e))?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
    let msg = |ty: u16, flags: u16, seq: u32, family: u8| {
        let mut m = Vec::with_capacity(20);
        m.extend_from_slice(&20u32.to_ne_bytes());
        m.extend_from_slice(&ty.to_ne_bytes());
        m.extend_from_slice(&flags.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.push(family);
        m.push(0);
        m.extend_from_slice(&NFNL_SUBSYS_NFTABLES.to_be_bytes());
        m
    };
    let mut batch = msg(16, 1, 1, 0); // NFNL_MSG_BATCH_BEGIN
    batch.extend(msg((NFNL_SUBSYS_NFTABLES << 8) | 2, 1 | 4, 2, 0)); // NFT_MSG_DELTABLE, all families, ack
    batch.extend(msg(17, 1, 3, 0)); // NFNL_MSG_BATCH_END
    sock.send(&batch).map_err(|e| explain(&e))?;
    let mut buf = vec![0u8; 8192];
    let n = (&sock)
        .read(&mut buf)
        .map_err(|e| format!("no reply: {}", explain(&e)))?;
    let mut at = 0;
    while at + 20 <= n {
        let len = u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[at + 4..at + 6].try_into().unwrap());
        if ty == 2 {
            let code = i32::from_ne_bytes(buf[at + 16..at + 20].try_into().unwrap());
            if code != 0 {
                return Err(explain(&std::io::Error::from_raw_os_error(-code)).replace(
                    "dropped by the sandbox's nftables output rule",
                    "the kernel requires CAP_NET_ADMIN",
                ));
            }
        }
        if len == 0 {
            break;
        }
        at += len.div_ceil(4) * 4;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn netlink_flush() -> Result<(), String> {
    Err("not Linux: no netlink here".into())
}

pub fn rules(r: &mut Report, env: &Env) {
    match netlink_flush() {
        Ok(()) => r.stopped(
            false,
            "rules",
            "netlink NFT_MSG_DELTABLE (flush every table)",
            "the kernel accepted it",
        ),
        Err(how) => r.stopped(
            true,
            "rules",
            "netlink NFT_MSG_DELTABLE (flush every table)",
            how,
        ),
    }
    match std::process::Command::new("nft")
        .args(["flush", "ruleset"])
        .output()
    {
        Ok(out) if out.status.success() => {
            r.stopped(false, "rules", "nft flush ruleset", "it succeeded")
        }
        Ok(out) => r.stopped(
            true,
            "rules",
            "nft flush ruleset",
            format!(
                "exit {}: {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
            ),
        ),
        Err(e) => r.stopped(
            true,
            "rules",
            "nft flush ruleset",
            format!("nft not runnable: {}", explain(&e)),
        ),
    }
    for (what, cmd) in [
        ("iptables -F", ["iptables", "-F"]),
        ("ip6tables -F", ["ip6tables", "-F"]),
    ] {
        match std::process::Command::new(cmd[0]).arg(cmd[1]).output() {
            Ok(out) if out.status.success() => r.stopped(false, "rules", what, "it succeeded"),
            Ok(out) => r.stopped(
                true,
                "rules",
                what,
                format!(
                    "exit {}: {}",
                    out.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                ),
            ),
            Err(e) => r.stopped(
                true,
                "rules",
                what,
                format!("not runnable: {}", explain(&e)),
            ),
        }
    }
    // The rules are still in force afterwards. 172.30.0.2:22 is on-link and closed: without
    // the rules it would answer with a reset at once; with them the SYN is dropped.
    let probe: SocketAddr = SocketAddr::new(IpAddr::V4(*env.gate.ip()), 22);
    match (tcp(probe), tcp(SocketAddr::V4(env.gate))) {
        (Outcome::Stopped(how), Outcome::Connected) => r.stopped(
            true,
            "rules",
            format!("after those attempts: TCP {probe} (on-link, closed)"),
            format!("{how}; the gate still connects, so the same rules hold"),
        ),
        (Outcome::Connected, _) => r.stopped(
            false,
            "rules",
            format!("after those attempts: TCP {probe}"),
            "a reply came back: the rules changed",
        ),
        (Outcome::Stopped(how), Outcome::Stopped(g)) => r.add(
            Verdict::Fail,
            "rules",
            "after those attempts",
            format!("{probe}: {how}; but the gate also failed: {g}"),
        ),
    }
}
