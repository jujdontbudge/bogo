# Reference sandbox, bypass suite, and BOGO on real upstreams

Ticket: [T11](../tickets/T11-sandbox-e2e.md). Branch `t3/sandbox-bypass-suite-e2e`.
Run on 2026-11-15 on the owner's Mac: Colima 0.10.3 (Docker 29.5.2, VM kernel
6.8.0), BOGO from this branch built with `test-approvers,test-registration`,
BOGO home `~/.bogo`, filesystem upstream
`@modelcontextprotocol/server-filesystem@2.3.0` on `~/bogo-test`, Link CLI
1.4.1 as `link-cli --mcp` with `LINK_AUTH_FILE` a path secret under
`~/.bogo/upstreams/stripe/`. No token, key or auth-file content appears here.

## Owner questions taken (ARCHITECTURE §11)

| Question | Option taken | Where |
|---|---|---|
| 1. The agent's model | One named model host through a second fixed forwarder (`model-gate`, 172.30.0.3:443 → `api.anthropic.com:443`, static `/etc/hosts` entry). | `sandbox/compose.yml`, `sandbox/policy.nft` |
| 9. Scenario 13 | Link's credential-returning read (`spend-request_retrieve` with card), with `number` and `cvc` redacted. | `~/.bogo/bogo.toml` `[tools.stripe__call_read_tool]` |
| 14. Link credentials | Link keeps its own auth file under `~/.bogo/upstreams/stripe/` (0600), named by path from `secrets.toml`. | `~/.bogo/secrets.toml` |

## 1. The sandbox: BOGO reachable, everything else refused

`sandbox/up.sh` started `gate`, `model-gate`, `netpol` and `agent`; `netpol`
logged `netpol: rules loaded` and turned healthy before the agent started.
Inside `netpol`, PID 1 is `sleep infinity` as `nobody` with `CapEff`,
`CapBnd` = 0 and `NoNewPrivs` = 1. The agent is uid 1000 with `CapEff` 0.

From inside the agent:

```text
BOGO via gate 172.30.0.2:8790 -> HTTP 200 data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25",...,"serverInfo":{"name":"bogo",...
172.30.0.2:22 no answer (dropped)
172.30.0.1:22 no answer (dropped)
192.168.5.2:8790 refused (ENETUNREACH)
198.137.150.175:443 refused (ENETUNREACH)      # api.stripe.com
1.1.1.1:443 refused (ENETUNREACH)
169.254.169.254:80 refused (ENETUNREACH)
127.0.0.11:53 no answer (dropped)
dns api.stripe.com -> EAI_AGAIN
```

Control without the rules: a container on `bogo-net` without `netpol`
connected to the Colima VM's SSH at 172.30.0.1:22, got RSTs from
172.30.0.2:22, and resolved `gate` through Docker's DNS. The rules are what
stop those.

Before BOGO accepted the gate's address, the same request got
`403 Forbidden: Host header is not allowed` from rmcp, which is why
`[server] allowed_hosts` exists (IPv4 literals only, applied to BOGO's own
edge check and to rmcp's).

## 2. Bypass suite

`sandbox/bypass.sh`: **145 attempts stopped, 0 failed, 3 controls held**,
exit 0, in 3m16s. The full report is
[sandbox-bypass-report.txt](sandbox-bypass-report.txt). Summary:

- Direct TCP to `api.stripe.com`, `link.com`, `api.link.com`, the relay
  `bogo.eilmer.si` (443, 80, 8443), npm, public IPs, IPv6 and metadata
  addresses: `ENETUNREACH` (IPv6: `EADDRNOTAVAIL`).
- Every TCP port on the gate except 8790, on the model forwarder except 443,
  and on the bogo-net gateway: 65534/65535 attempts each, all dropped. The
  host and VM addresses: all `ENETUNREACH`. 1500 other bogo-net
  address:port pairs: all dropped.
- DNS: every name fails to resolve; UDP and TCP 53 to every resolver,
  and all 65535 TCP and UDP ports of `127.0.0.11`, refused or dropped.
- Forwarders as proxies: `CONNECT` and absolute-URI requests through the
  gate reach BOGO, which answers 401. Through the model forwarder, TLS with
  another name's SNI fails the handshake (Stripe, Link) or gets Cloudflare's
  `403 error code: 1034`; SNI/Host fronting gets Cloudflare's 403. These last
  are refused by the model host's edge, not by the sandbox (see limits).
- Rules: netlink `NFT_MSG_DELTABLE` → `EPERM`; `nft flush ruleset` →
  `Operation not permitted`; afterwards 172.30.0.2:22 is still dropped and the
  gate still connects.
- Docker sockets absent; no `/Users`, `~/.bogo` or `bogo.sock`; credential
  scan of 5936 files (968 MiB) and process environments: nothing found.
- MCP: no token and a wrong token → 401; a browser `Origin` or foreign `Host`
  → 403; batches and duplicate keys → 400; resources, prompts and completions
  are answered by BOGO with empty results; un-namespaced or altered names →
  `Unknown tool.`; the deny tool is hidden and `This tool is denied by
  policy.`; a protected write with no approval, with a forged approval in
  `_meta` (including BOGO's internal call marker) or in the arguments, and
  with a **real approval proof replayed from the audit log**, is held each
  time and dropped after 4 s; the file is confirmed absent (`ENOENT`) each
  time; the same call in a fresh session is held again; reusing a session
  with another agent's token → 403 (and the session closes).
- `bogo request list` was `[]` afterwards: nothing was left pending.

## 3. Upstreams and the Link login

`bogo status`: `"upstreams": {"files": true, "stripe": true}`. `bogo tools`
(JSON, shown here as name and effective policy; `"unexposable": []`):

```text
files__append_file          Approve    files__read_file             Approve
files__copy_file            Approve    files__read_media_file       Approve
files__create_directory     Approve    files__read_multiple_files   Allow
files__directory_tree       Allow      files__read_text_file        Allow
files__edit_file            Approve    files__search_files          Allow
files__get_file_info        Allow      files__write_file            Approve
files__list_allowed_directories Allow  stripe__call_read_tool       Approve
files__list_directory       Allow      stripe__call_write_tool      Approve
files__list_directory_with_sizes Approve stripe__get_tool_details   Allow
files__move_file            Deny       stripe__search_tools         Allow
```

No tool is `unexposable` or `strict-client-risk`. Link CLI 1.4.1 exposes four
meta-tools; spend requests are `call_write_tool` with
`name = "spend-request_create"`.

**The Link device login waits for the device session.** `link-cli auth login
--auth ~/.bogo/upstreams/stripe/auth.json` produced a verification URL; Chrome
(already signed in to Link) showed "Confirm the phrase shown by your agent",
but the Mac's screen was locked for the rest of the run, so the cua driver
could not click Confirm, and Link's own instruction is to approve in the Link
app (the owner's phone). The auth file holds only an expired pending device
login. Until then Link answers every call with
`Not authenticated. Run "link-cli auth login" first.`

## 4. Scenarios from Claude Code inside the sandbox

Claude Code 2.1.325 ran `claude -p` inside the agent container, with BOGO as
its only MCP server through `bogo-shim`, `--allowedTools 'mcp__bogo__*'`,
`--permission-mode dontAsk`, and its model reached through the model
forwarder. Approvals came from the soft approver (`bogo soft 'Soft A' <id>`),
driven by a rule script that approved only a test-mode 4700-cent payment, once.

- **Filesystem read runs at once.** `files__read_text_file` →
  `{"content":"Itinerary: 6pm flight to SFO, seat 14C.\n"}` with no request.
- **Filesystem write needs approval.** `files__write_file` appeared in
  `bogo request list`; `booking-note.txt` did not exist. After `bogo soft`, the
  agent got `Successfully wrote to /Users/johansardar/bogo-test/booking-note.txt`
  and the file held exactly `Booked: 6pm flight to SFO, seat 14C.\n`.
- **Payment, approved, runs exactly once.** `stripe__call_write_tool`
  `spend-request_create` with `amount 4700, test true, requestApproval false`
  was held, approved, and forwarded once (log: `request_created` →
  `approval counted` → `authorized` → one `forwarded` → `result`). Link
  answered `Not authenticated…`; the Stripe dashboard check waits for the login.
- **Changed amount needs a new approval.** The same call with 4701 was a new
  request; the owner denied it; the agent got
  `The owner denied this action. wrong amount`; log `denial`,
  `request_ended why=denied`, no `forwarded`.
- **Denied payment.** 50000 cents ("business-class upgrade, $500") → denied →
  `The owner denied this action. wrong amount`; nothing forwarded. (Claude
  declined to send a call whose reason said "$5" for 50000 cents.)
- **The approved call sent again** needed its own approval and was denied
  (`already approved once`).
- **Output filtering (Scenario 13, Q9)** is configured on
  `stripe__call_read_tool` (`filter_output = ["number", "cvc"]`, redact) and
  waits for the Link login.

## 5. `bogo log verify`

```text
chain intact; Report { entries: 216, approvers_registered: 1, approvers_revoked: 0,
approvals_counted: 2, approvals_ignored: 0, denials_applied: 3, denials_ignored: 0 }
```

## 6. Checks

`cargo clippy --workspace --all-targets -- -D warnings` exit 0 and
`cargo test --workspace` exit 0 (full suite) on the final head.

## Found along the way

- A short value in `secrets.toml` breaks an upstream: BOGO's credential
  scrubber replaces every occurrence in the upstream's JSON-RPC, so
  `NO_UPDATE_NOTIFIER = "1"` as a secret made every `1` vanish, responses
  never correlated, and the daemon hung at startup with no message. As a
  plain `env` value it works. Worth a startup check on secret length.
- `bogo tools` fails with `invalid upstream configuration` before the first
  start, because there is no catalog yet.

## Device session, still to do

1. `NO_UPDATE_NOTIFIER=1 link-cli auth login --client-name BOGO --auth ~/.bogo/upstreams/stripe/auth.json --interval 5`,
   open the URL, Confirm, approve in the Link app.
2. `bogo stop && bogo start`, then rerun the payment prompt from inside the
   sandbox; check the test-mode spend request in Link/Stripe's test dashboard.
3. Retrieve that spend request with card through `stripe__call_read_tool`
   and confirm `number` and `cvc` arrive as `[removed by BOGO]` (or the block
   is withheld if Link returns non-JSON text).
4. `bogo log verify`.
