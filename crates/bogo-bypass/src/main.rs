//! BOGO's bypass suite (ARCHITECTURE §3.17). It runs inside the reference sandbox as the
//! agent would, tries every way around BOGO it knows, and prints how each attempt was
//! stopped. The sandbox's rules are the restriction; this program only observes them.
//!
//! Exit status 0 means every attempt was stopped and every control check held.
#![forbid(unsafe_code)]

mod mcp;
mod net;
mod scan;

use std::fmt::Write as _;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The attempt was stopped.
    Pass,
    /// The attempt got through, or a check could not be made.
    Fail,
    /// A control: something the sandbox is meant to allow worked.
    Ok,
    /// Context that is neither an attempt nor a control.
    Info,
}

pub struct Report {
    rows: Vec<(Verdict, &'static str, String, String)>,
}

impl Report {
    pub fn add(
        &mut self,
        v: Verdict,
        area: &'static str,
        attempt: impl Into<String>,
        how: impl Into<String>,
    ) {
        let (attempt, how) = (attempt.into(), how.into());
        let tag = match v {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Ok => " OK ",
            Verdict::Info => "INFO",
        };
        println!("[{tag}] {area:<7} {attempt}\n         -> {how}");
        self.rows.push((v, area, attempt, how));
    }
    pub fn stopped(
        &mut self,
        stopped: bool,
        area: &'static str,
        attempt: impl Into<String>,
        how: impl Into<String>,
    ) {
        self.add(
            if stopped {
                Verdict::Pass
            } else {
                Verdict::Fail
            },
            area,
            attempt,
            how,
        );
    }
    pub fn section(&self, title: &str) {
        println!("\n== {title} ==");
    }
}

fn main() {
    println!("BOGO bypass suite: every attempt below must be stopped (PASS).");
    println!("Controls (OK) show what the sandbox is meant to allow.");
    let mut r = Report { rows: Vec::new() };
    let env = Env::read();

    r.section("Process");
    net::process(&mut r);

    r.section("Direct network: upstreams, relay, internet, IPv6, metadata");
    net::direct(&mut r, &env);

    r.section("DNS");
    net::dns(&mut r, &env);

    r.section("Host, gateways and the forwarders' other ports");
    net::ports(&mut r, &env);

    r.section("Forwarders used as proxies");
    net::forwarders(&mut r, &env);

    r.section("Changing the rules");
    net::rules(&mut r, &env);

    r.section("Docker socket and host files");
    scan::sockets(&mut r);

    r.section("Credential scan (filesystem and environment)");
    scan::credentials(&mut r, &env);

    r.section("MCP: authentication, approvals, sessions");
    mcp::run(&mut r, &env);

    let count = |v| r.rows.iter().filter(|row| row.0 == v).count();
    let (pass, fail, ok) = (
        count(Verdict::Pass),
        count(Verdict::Fail),
        count(Verdict::Ok),
    );
    let mut summary =
        format!("\n== Summary ==\n{pass} attempts stopped, {fail} failed, {ok} controls held.");
    if fail > 0 {
        summary.push_str("\nFailures:");
        for (_, area, attempt, how) in r.rows.iter().filter(|row| row.0 == Verdict::Fail) {
            let _ = write!(summary, "\n  {area}: {attempt} -> {how}");
        }
    }
    println!("{summary}");
    std::process::exit(if fail == 0 { 0 } else { 1 });
}

/// Inputs from the sandbox. The runner resolves outside names on the host, because the
/// sandbox has no DNS, and passes their addresses in.
pub struct Env {
    pub url: Option<String>,
    pub token: Option<String>,
    pub second_token: Option<String>,
    /// `name=ip,ip;name=ip`
    pub targets: Vec<(String, Vec<std::net::IpAddr>)>,
    /// Addresses on the path to the host: gateways, the VM, Docker Desktop's host address.
    pub host_addrs: Vec<std::net::Ipv4Addr>,
    pub gate: std::net::SocketAddrV4,
    pub model_gate: Option<std::net::SocketAddrV4>,
    pub model_host: String,
    pub relay_port: u16,
    pub protected_tool: String,
    pub read_tool: String,
    pub deny_tool: String,
    pub replay_sig: Option<String>,
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

impl Env {
    fn read() -> Self {
        let url = var("BOGO_URL");
        let gate = url
            .as_deref()
            .and_then(|u| u.strip_prefix("http://"))
            .and_then(|u| u.split('/').next())
            .and_then(|a| a.parse().ok())
            .unwrap_or_else(|| "172.30.0.2:8790".parse().unwrap());
        let targets = var("BYPASS_TARGETS")
            .unwrap_or_default()
            .split(';')
            .filter_map(|t| {
                let (name, ips) = t.split_once('=')?;
                let ips = ips
                    .split(',')
                    .filter_map(|ip| ip.trim().parse().ok())
                    .collect();
                Some((name.trim().to_owned(), ips))
            })
            .collect();
        let mut host_addrs: Vec<std::net::Ipv4Addr> = [
            "172.30.0.1",     // bogo-net's gateway (the bridge itself)
            "172.17.0.1",     // Docker's default bridge
            "192.168.5.2",    // Lima/Colima: the Mac (host.docker.internal)
            "192.168.5.15",   // Lima/Colima: the VM
            "192.168.65.254", // Docker Desktop: host.docker.internal
            "192.168.65.1",   // Docker Desktop: the VM gateway
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        for extra in var("BYPASS_HOST_ADDRS")
            .unwrap_or_default()
            .split([',', ' '])
        {
            if let Ok(ip) = extra.parse()
                && !host_addrs.contains(&ip)
            {
                host_addrs.push(ip);
            }
        }
        Env {
            url,
            token: var("BOGO_AGENT_TOKEN"),
            second_token: var("BOGO_BYPASS_SECOND_TOKEN"),
            targets,
            host_addrs,
            gate,
            model_gate: var("BYPASS_MODEL_GATE").and_then(|s| s.parse().ok()),
            model_host: var("BYPASS_MODEL_HOST").unwrap_or_else(|| "api.anthropic.com".into()),
            relay_port: var("BYPASS_RELAY_PORT")
                .and_then(|s| s.parse().ok())
                .unwrap_or(443),
            protected_tool: var("BYPASS_PROTECTED_TOOL")
                .unwrap_or_else(|| "files__write_file".into()),
            read_tool: var("BYPASS_READ_TOOL").unwrap_or_else(|| "files__read_text_file".into()),
            deny_tool: var("BYPASS_DENY_TOOL").unwrap_or_else(|| "files__move_file".into()),
            replay_sig: var("BYPASS_REPLAY_SIG"),
        }
    }
}
