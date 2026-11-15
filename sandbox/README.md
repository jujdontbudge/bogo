# BOGO reference sandbox

BOGO's promise holds only for calls that go through BOGO. This sandbox is how
the owner makes sure an agent has no other way out: the agent runs in a Docker
network namespace whose nftables rules drop everything except TCP to BOGO's
gate and, per ARCHITECTURE §11 question 1, to one model API host.
`bogo-bypass` then tries every way around it and reports how each was stopped.

```
 bogo-net (internal, 172.30.0.0/24)                         egress bridge
┌───────────────────────────────────────────────┐
│ netpol 172.30.0.10  ── shares its netns ──► agent / bypass (uid 1000, no caps)
│   nftables: drop all, except                  │
│     tcp 172.30.0.2:8790  ─► gate (socat) ─────┼──► host.docker.internal:8790 = BOGO
│     tcp 172.30.0.3:443   ─► model-gate (socat)┼──► api.anthropic.com:443 (§11 Q1)
└───────────────────────────────────────────────┘
```

- `netpol` loads [policy.nft](policy.nft), writes a ready marker, then execs
  `setpriv` to `nobody` with an empty bounding set and `no_new_privs`, so no
  process in the namespace keeps `NET_ADMIN`. The agent starts only once that
  marker exists. IPv6 is disabled by sysctl and dropped by the `inet` table.
- `gate` and `model-gate` forward one fixed port to one fixed address. They
  parse nothing and offer no proxying. TLS to the model host runs end to end.
- The agent runs as uid 1000 with every capability dropped, `no-new-privileges`
  and a read-only root filesystem plus one work volume. Nothing mounts a home
  directory, `~/.bogo`, SSH keys, Link's auth file, BOGO's owner socket or the
  Docker socket. Its only BOGO credential is its agent token.

## Setup

1. In `~/.bogo/bogo.toml`, let BOGO accept the gate's address in the `Host`
   header (IPv4 literals only; names are refused):

   ```toml
   [server]
   allowed_hosts = ["172.30.0.2"]
   ```

2. Add two agents and put their tokens in `sandbox/.env` (mode 0600; see
   [.env.example](.env.example)). The second is used only by the bypass
   suite's session-reuse attempt.

   ```sh
   bogo agent add 'Sandbox agent'
   bogo agent add 'Bypass second'
   ```

3. Build and start. `build.sh` cross-compiles `bogo-shim` and `bogo-bypass`
   for Linux (`brew install zig`, `cargo install cargo-zigbuild`,
   `rustup target add aarch64-unknown-linux-musl`).

   ```sh
   sandbox/build.sh
   sandbox/up.sh
   ```

The gate reaches BOGO through `host.docker.internal` (`host-gateway`). On
Colima that is the Lima host address 192.168.5.2, which reaches the Mac's
loopback; on Docker Desktop it is its own host address.

## Running an agent inside

The agent image has Claude Code, and `/etc/bogo/mcp.json` points it at
`bogo-shim`, which reads `BOGO_URL` and `BOGO_AGENT_TOKEN` from the
environment. Give Claude Code its model credential at run time:

```sh
docker compose -f sandbox/compose.yml exec -T -e CLAUDE_CODE_OAUTH_TOKEN agent \
  claude -p "…" --mcp-config /etc/bogo/mcp.json --strict-mcp-config \
  --allowedTools 'mcp__bogo__*' --permission-mode dontAsk
```

## Bypass suite

```sh
sandbox/bypass.sh
```

It resolves the outside names on the host (the sandbox has no DNS), passes a
real approval signature from the audit log if there is one, and runs
`bogo-bypass` in the agent's namespace. Every line is an attempt and how it was
stopped; the exit status is 0 only if every attempt failed. How to read the
reasons:

| Reason | Meaning |
|---|---|
| `ENETUNREACH` | No route: the internal network has no default gateway. |
| `timed out … (dropped)` | An on-link destination (the gateway, the gate's other ports, other `bogo-net` addresses, Docker's resolver) that would otherwise answer; the namespace's rules dropped the packet. |
| `EPERM` | The kernel refused (netlink without `CAP_NET_ADMIN`). |
| `HTTP 401/403/400` | BOGO refused the request itself. |
| Cloudflare `403` | The model host's edge refused another name (error 1034) or an SNI/Host mismatch. |

Without the rules, a container on `bogo-net` reaches the gateway host's SSH
(the Colima VM at 172.30.0.1:22), gets RSTs from the gate's closed ports, and
gets answers from Docker's resolver. The rules are what stop those.

## Known limits

- **The model forwarder is an egress path to the model host's edge.** Its TCP
  endpoint is fixed, so it never reaches Stripe, Link or the relay directly, but
  what it reaches is whatever that edge serves. Today `api.anthropic.com` is a
  Cloudflare edge that refuses other names and SNI/Host fronting with 403; the
  suite checks both. If the owner chooses the other answer to §11 question 1
  (the model runs outside the container), remove the `model-gate` service and
  its rule in `policy.nft`, and the agent reaches only BOGO.
- The model credential lives in the agent's environment. It is the agent's own
  credential, not BOGO's, and it is not matched by the suite's credential scan.
- The suite observes the rules; it cannot prove the absence of kernel or Docker
  escapes.
