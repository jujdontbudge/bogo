# Configuration reference

This describes the current parser, not the illustrative TOML in the
[architecture](ARCHITECTURE.md). Sources:
[`raw.rs`](../crates/bogo-config/src/raw.rs),
[`lib.rs`](../crates/bogo-config/src/lib.rs),
[`secret.rs`](../crates/bogo-config/src/secret.rs), and the daemon's
[`load` / `serve`](../crates/bogo-daemon/src/owner.rs).

`bogo init` creates `~/.bogo/bogo.toml` and `secrets.toml`; every CLI command
accepts `--home DIRECTORY` for a different BOGO directory. This does not change
`HOME`. Edit while stopped, then restart. There is no live reload. Unknown keys
are refused in every fixed table, including nested secret references. Map keys
(upstream names, tool names, agent names, env/header names and secret names)
are data, subject to the rules below. TOML types matter: booleans are not
strings, integers are not duration strings, and duplicate TOML keys fail.

## Required skeleton

```toml
version = 1
[server]
port = 8790
[defaults]
max_pending = 4
```

`version`, `[server]`, `server.port`, and `[defaults]` are required.
`max_pending` deliberately ships unset; choose it before starting. `upstreams`,
`tools`, `agents` and `approvers` default to empty maps/tables. `relay`, `apns`
and `approvers.iphone` are optional. No `[approvers.soft]` table exists: register
software approvers with the CLI in a `test-approvers` build only.

## Server and defaults

| Key | Meaning and default | Refused values |
|---|---|---|
| `version` | File format, integer `1`. | Missing, any other integer, any other type. |
| `server.port` | Loopback HTTP MCP listener port. No default. | Outside `1..65535`, missing, non-integer. |
| `server.max_body` | Request body byte limit; default `"1MiB"`. | Invalid size syntax, zero, above `4294967295` bytes in parser; daemon additionally refuses anything over `1048576` bytes. |
| `server.allowed_hosts` | Extra IPv4 literals accepted in Host, besides localhost/127.0.0.1; default `[]`. Does not change the loopback bind address. Reference sandbox uses `["172.30.0.2"]`. | Hostnames, IPv6, malformed IPv4, `0.0.0.0`, `255.255.255.255`, non-string elements. |
| `defaults.policy` | Policy for unlisted tools and tool entries without `policy`; default `"approve"`. Can be `"deny"`. | `"allow"` and every other spelling. Use an explicit tool or agent override to allow. |
| `defaults.hide_denied` | Hide deny-policy tools from discovery; default `true`. A direct call is denied either way. | Non-boolean. |
| `defaults.max_pending` | Maximum live requests (pending **plus settled**) for each agent; required owner choice. Matching retries reuse a request before this check. | Missing, zero, negative, above `4294967295`, non-integer. |

Sizes are strings of decimal digits with optional suffix `B`, `KiB`, `MiB` or
`GiB` (binary units); bare `"1048576"` works. Spaces, signs, decimals, `MB`,
wrong case and arithmetic overflow fail.

Durations below are strings of unsigned decimal digits followed immediately by
`ms`, `s`, `m`, `h` or `d`. All duration fields require a positive value.
`"500ms"`, `"30s"`, `"10m"` work; `"0s"`, `"-1s"`, `"1.5s"`, `"1 s"`,
`"1w"`, bare `"10"`, and values overflowing a u64 millisecond count fail.

## Upstreams: `[upstreams.NAME]`

Names must be nonempty and contain only `a-z`, `0-9`, `-`. Uppercase and `_`
are refused, keeping `<upstream>__<tool>` unambiguous. Set exactly one of
`command` and `url`.

| Key | Meaning and default | Refused values |
|---|---|---|
| `command` | Local stdio executable. Prefer an absolute path for launchd. | Empty/whitespace-only, non-string; combined with `url`, or missing both. |
| `args` | Local command arguments; default `[]`. No shell expansion is performed. | Non-string elements; present on a remote upstream, even `[]`. |
| `env` | Local environment map; default `{}`. Each value is a string or `{ secret = "NAME" }`. | Other value types, malformed/unknown secret reference, or present on remote upstream, even `{}`. |
| `url` | Remote Streamable HTTP MCP endpoint. | Non-string, no `http://` or `https://` prefix; combined with `command`. Parser checks the prefix only; transport can reject a malformed URL later. |
| `headers` | Remote HTTP header map; default `{}`. Values have the same syntax as `env`. | Other value types, malformed/unknown secret reference; present on local upstream, even `{}`. Invalid HTTP names/values can also fail later at transport construction. |

```toml
[upstreams.files]
command = "/absolute/path/to/node"
args = ["/absolute/path/to/server-filesystem/dist/index.js", "/absolute/scratch"]
env = { NO_UPDATE_NOTIFIER = "1" }

[upstreams.remote]
url = "https://mcp.example.invalid/mcp"
headers = { Authorization = { secret = "remote_authorization" } }
```

Every reference must be a table containing only `secret`, with a string naming
an existing `secrets.toml` entry. BOGO supplies a value secret verbatim, or a
path secret as its path; it does not prepend `Bearer ` or read a path secret
into an HTTP header. Include any required prefix in the value secret itself.
Use plain env strings for noncredentials such as `"1"`.

At daemon load, local `command` and `args` that look like paths are normalized
through symlinks that successfully resolve. An argument's portion after `=` is
checked too. Local upstreams always run with working directory `/`, so a relative
argument means a path under `/`, whatever directory BOGO was started from. Paths into
BOGO home, or any parent of BOGO home, are refused. Path secrets are the
separate way to supply upstream credential paths. This startup check is not a
sandbox for arbitrary executable behavior: the owner must trust the upstream
and restrict its filesystem root. Do not give a filesystem upstream `/`, the
owner's home, or BOGO home.

## Tool policy: `[tools."UPSTREAM__TOOL"]`

The upstream must already be configured; the tool need not yet have been
discovered. The tool portion must be nonempty and use only ASCII letters,
digits, `_`, `.` or `-`. Missing `__`, unknown upstreams and other characters
are refused. Quote names containing dots in TOML.

| Key | Meaning and default | Refused values |
|---|---|---|
| `policy` | `"allow"`, `"approve"`, `"deny"`; omitted uses `defaults.policy`. | Other spellings/types. |
| `justification` | `"optional"` (default) or `"required"` for protected calls. Justification is signed but removed before forwarding. | Other spellings/types. |
| `highlight` | Map of argument paths to display formats, default `{}`. It changes presentation, not authorization or argument values. | Invalid paths, invalid formats, non-string formats. |
| `approvers` | Eligible registered approver names; default `[]` means all registered approvers. | Blank names, duplicate names, non-string elements. Unknown names are accepted in config but cannot approve. |
| `require` | `"any"` (default), or `{ k = N }` for N distinct approvers. | Other strings/types; missing `k`, extra keys, non-integer k, k outside `1..4294967295`. A tool entry with a nonempty `approvers` list and k greater than its length is refused. |
| `on_deny` | `"any"` (default): one pending denial ends it. `"when_unreachable"`: ends once remaining eligible approvers cannot reach the threshold. | Other spellings/types. A denial after settlement is ignored in both modes. |
| `expiry` | Optional positive duration from request creation. Omitted means no preset expiry; call/session ending still ends the request. | Invalid/zero duration. |
| `mode` | `"wait"` (default), or `"pending_retry"`. Retry requires identical arguments and justification in the same session; first approved retry consumes the request. | Other spellings/types. Direct stateless MCP connections cannot use pending/retry; use the shim. |
| `filter_output` | Field paths to remove from results; default `[]`. | Empty string, paths with empty dot segments (e.g. `a..b`, `.a`, `a.`), non-string elements. |
| `filter_action` | `"strip"` (default) removes matching fields; `"redact"` replaces them with `[removed by BOGO]`. | Other spellings/types. |
| `select` | Optional name of one top-level argument whose string value picks a per-action entry (below). The selected argument is also highlighted first, as text, unless `highlight` already names it. | Empty, or characters other than ASCII letters, digits, `_`, `.`, `-`. |

Highlight paths support object keys separated by dots and unsigned u32 array
indices: `amount`, `payment.amount`, `items[0].price`, `[2]`. Empty dot segments,
unmatched brackets, negative/nondigit/overflowing indices and stray `]` fail.
Formats are `text`, `usd_cents`, or three lowercase ASCII letters plus `_minor`
(e.g. `eur_minor`). The parser does **not** check those three letters against an
ISO currency registry: `zzz_minor` passes. Money display expects an integer
minor-unit value; unformattable values remain visible as raw values.

Output filter paths use a different grammar. A bare name such as `number`
matches that key recursively in nested objects/arrays. A dotted path such as
`cards.*.number` follows keys from the result root, with `*` traversing an array.
`items[0].number` has no array-index meaning here. The parser validates only
nonempty dot segments, not that the path will match anything. Filtering covers
structuredContent, metadata and supported content representations; JSON text
is parsed and filtered, non-JSON text/URIs are withheld when rules exist. This
is field filtering, not general content sanitization; arbitrary binary or
unanticipated representations are not a proved data-loss barrier. A filtered
result's output schema is omitted.

A missing or insufficient set of active approvers fails closed at call time.
`bogo tools` reports discovery, effective policies, schema risks and base-tool
approver availability. Check agent overrides separately: that availability
count is not recomputed for each override.

## Per-action policy: `[tools."UPSTREAM__TOOL[ARG=VALUE]"]`

Some upstreams put many actions behind one wrapper tool and name the action in
an argument. Link's `call_write_tool`, for example, takes `name =
"spend-request_create"`, `"spend-request_retrieve"`, `"ucp_catalog_search"` and
more. Set `select` on the tool, then give single values their own entry:

```toml
[tools.stripe__call_write_tool]
policy = "approve"
select = "name"

[tools."stripe__call_write_tool[name=spend-request_retrieve]"]
policy = "allow"
```

For each call, BOGO reads the selected top-level argument. If it is a JSON
string and an entry exists for exactly that value, the call is judged by that
entry, under the **policy key** `stripe__call_write_tool[name=spend-request_retrieve]`.
Otherwise it is judged by the tool's own entry: a value with no entry, a
different spelling, case or spacing, a missing argument, and a non-string value
(number, list, object, null) all fall back. Matching is exact string equality;
there are no patterns. The upstream always receives the real tool and exactly
the arguments the key was read from, and an approval covers that one request
only, so changing the value means a new request.

The agent chooses the argument, so **keep the strict policy on the base tool and
open single values**, as above. Never do the reverse (`policy = "allow"` on the
base and `"deny"` or `"approve"` on dangerous values): any spelling the upstream
accepts but the entry does not match would get the base's allow.

Rules:

- The base entry `[tools."UPSTREAM__TOOL"]` must exist with `select` naming the
  same argument. VALUE must be nonempty and have no control characters. Quote the
  whole TOML key.
- A per-action entry accepts `policy`, `justification`, `highlight`, `approvers`,
  `require`, `on_deny` and `expiry`. Each one it leaves out comes from the base
  entry (including `policy`), and each one it sets replaces the base's. A
  `highlight` it sets replaces the base's map; the selected argument is still shown
  first.
- `mode`, `filter_output`, `filter_action` and `select` belong to the base entry and
  apply to every action; setting them on a per-action entry is refused. Filter
  credential fields on the base when any action that returns them may run at once.
- The tool is listed once. `hide_denied` hides it only when the base and every
  per-action entry are denied for that agent. Its schema shows the justification
  field when any of them needs approval.
- An agent calling a policy key as if it were a tool name gets `Unknown tool.`
- The audit log's `call` entries, `bogo tools` (a row per key, with `action_of`
  naming the tool) and per-agent overrides use the policy key. The signed request
  keeps the real upstream and tool; the approver sees the action in the
  highlighted argument.

The core treats each policy key as one more tool name for the same upstream tool,
so every proved promise holds per key. Which key a call gets is computed by the
daemon from the same arguments the core signs and forwards.

### Recommended Link setup

Link's MCP server exposes `search_tools` and `get_tool_details` for discovery,
and runs every action through `call_read_tool` or `call_write_tool`, naming it in
`name` with its parameters in `arguments`. Agents do not reliably pick the
read tool for reads, so give both wrapper tools the same shape: approval by
default, with searches, status reads and retrieval opened by name. Anything that
creates or approves spending, checks out or logs in (`spend-request_create`,
`spend-request_request-approval`, `ucp_checkout_create`, `auth_login`, and any
action Link adds later) has no entry and waits for the phone.

```toml
[tools.stripe__search_tools]
policy = "allow"
[tools.stripe__get_tool_details]
policy = "allow"

[tools.stripe__call_write_tool]
policy = "approve"
select = "name"
justification = "required"
highlight = { name = "text", "arguments.amount" = "usd_cents", "arguments.currency" = "text", "arguments.test" = "text", "arguments.merchantName" = "text" }
expiry = "10m"
mode = "wait"
filter_output = ["number", "cvc"]   # retrieval can return card details

[tools.stripe__call_read_tool]
policy = "approve"
select = "name"
justification = "required"
highlight = { name = "text" }
expiry = "10m"
filter_output = ["number", "cvc"]

[tools."stripe__call_write_tool[name=ucp_catalog_search]"]
policy = "allow"
[tools."stripe__call_write_tool[name=spend-request_retrieve]"]
policy = "allow"
[tools."stripe__call_write_tool[name=auth_status]"]
policy = "allow"
[tools."stripe__call_read_tool[name=ucp_catalog_search]"]
policy = "allow"
[tools."stripe__call_read_tool[name=spend-request_retrieve]"]
policy = "allow"
[tools."stripe__call_read_tool[name=auth_status]"]
policy = "allow"
```

Check the action names against `get_tool_details` and `bogo tools` after
discovery; a name that does not match exactly just waits for approval.

## Per-agent overrides: `[agents."NAME".tools."UPSTREAM__TOOL"]`

This config does not register an agent or mint a token. Use `bogo agent add`.
Agent names may contain spaces but cannot be blank. Tools use the naming rules
above. Each override accepts **only**:

| Key | Meaning and default | Refused values |
|---|---|---|
| `policy` | Optional allow/approve/deny; otherwise inherit the tool. | Other spellings/types. |
| `approvers` | Optional eligible names; otherwise inherit. Explicit `[]` means all registered approvers. | Blank/duplicate/non-string names. |
| `require` | Optional `"any"` or `{ k = N }`; otherwise inherit. | Same requirement syntax/range errors as a tool. |

An override with none of these three fields is refused. The tool name may be a
policy key that has a `[tools."…"]` entry. An override on a base tool covers every
action of it: it is copied to each policy key, and an override on the key itself
wins field by field. Choosing an action therefore never escapes an agent's
override. Other settings stay
with the tool, including display hints and filtering. Unlike a tool entry, an
override's k/list-size mismatch is accepted by the parser; an unreachable
threshold still cannot execute. A tool's policy can therefore be opened or
restricted for one named agent without duplicating its display settings.

## iPhone configuration (implemented, hardware qualification pending)

| Key | Meaning | Refused values |
|---|---|---|
| `relay.url` | BOGO relay HTTPS base URL; no default. | Missing, non-string, lacks `https://`, or exactly `https://`. Parser checks prefix/length; iPhone route later parses and validates the URL/TLS. |
| `relay.max_message_age` | Positive retention duration, explicitly required if relay table exists. Not request expiry. | Missing/invalid/zero duration. |
| `relay.mailbox_capacity` | Positive TOML integer, explicitly required if relay table exists. | Missing, non-integer, zero, negative. Upper bound is TOML's signed 64-bit integer maximum. |
| `apns.key` | Required `{ secret = "NAME" }`; route needs a path secret naming the APNs `.p8` file. | Missing/malformed/unknown reference. Config parser accepts a value secret, but daemon rejects it when constructing the iPhone route. |
| `apns.key_id` | APNs signing key ID; required nonblank string. | Missing, blank, non-string. No ID-shape check in config parser. |
| `apns.team_id` | APNs team ID; required nonblank string. | Same as key_id. |
| `apns.topic` | App bundle ID used for push; required nonblank string. | Same as key_id. |
| `approvers.iphone.app_id` | Required App ID prefix + bundle ID for App Attest. Confirm the prefix from the provisioning profile; it need not equal the team ID. | Missing, blank, non-string. No App ID-shape check in config parser. |
| `approvers.iphone.app_attest` | Required nonempty list of `"production"` and/or `"development"`. Production accepts Apple's TestFlight/App Store categories. Enable development only deliberately. | Empty/missing list, duplicate environments, unknown spelling, non-string elements. |
| `approvers.iphone.approve_arm_delay` | Positive duration before Approve is enabled on review; explicit owner choice. | Missing/invalid/zero duration. |

An iPhone section requires relay and APNs sections. Only a build with
`test-registration` may omit APNs and register without App Attest. Present
attestation is still verified. `test-approvers` independently enables software
approval and its verifier; neither feature belongs in a production build.

The retention/capacity settings validate the owner's choices; they do not
configure the standalone relay remotely. Supply matching explicit
`--max-message-age SECONDS` and `--mailbox-capacity N` to `bogo-relay`.
Deployment and hardware/push checks are outstanding; see
[RELAY-PROTOCOL.md](RELAY-PROTOCOL.md) and [verification](verification/daemon-cli.md).

## `secrets.toml`

The top level is a map of arbitrary credential names, not a `[secrets]` table.
Names must be nonempty ASCII letters/digits/`_`/`-` (digits may come first).
Each entry is either:

```toml
# Illustrative paths only; replace before use. No credential belongs in docs.
auth_file = { path = "~/.bogo/upstreams/service/auth.json" }
```

Or `NAME = "VALUE"`, where VALUE is the actual credential. A value must contain
at least eight characters after trimming whitespace; empty/short values fail.
This minimum exists because BOGO scrubs known secrets from upstream traffic
and a short value would corrupt ordinary messages. It is not a password
strength check. Non-string values, tables without `path`, blank (`""`) paths,
non-string paths and extra table keys are refused. A whitespace-only path is
not rejected as blank by this parser; do not use one.

Only a leading `~/` expands to the process's home, **not** `--home`. `$VAR`,
`~other` and command substitution are not expanded. The daemon normalizes path
secrets and refuses paths resolving outside BOGO home. Existing resolvable
symlink escapes are refused, and so are dangling symlinks: a link whose target
does not exist yet is judged by where it points. The check runs at startup only,
so a link changed while BOGO runs is not re-checked.
Path secrets supply filenames; the owner/upstream is responsible
for the file's contents and permissions. Keep credential files private (0600).
The secrets file itself must be a regular file, not a symlink, with no group
or other permission bits (0600 or stricter). The config loader checks mode and
file type, not the file's numeric owner UID. The state layer checks private
directory modes and agreement between the lock file and root directory owners. Malformed secrets TOML errors omit values.

Keys and software seeds are private state, not policy knobs. Software approver
registration writes `soft_<sha256 of approver name>` value entries itself.
Do not copy them into a shared example. Agent tokens are printed once by
`agent add`; only their hashes enter the registry/log. Keep agent connection
configuration outside the agent's editable project when using a sandbox.

## Environment outside TOML

| Variable | Consumer and behavior |
|---|---|
| `BOGO_URL`, `BOGO_AGENT_TOKEN` | Required by the stdio shim: MCP URL and named agent token. |
| `BOGO_APP_BUNDLE_VERSIONS` | Optional comma-separated App Attest build numbers, trimmed. Real attestations carry no build number, so the list is used only if Apple includes one; unset means none would be accepted then. |
| `BOGO_RELAY_CA` | Optional PEM file adding trust for a private relay; normal TLS hostname checking stays enabled. |
| `BOGO_MAC_NAME` | Optional registration label; defaults to `BOGO Mac`. |
| `BOGO_LAKE`, `BOGO_LEAN` | Build-only overrides for the actual lake/lean executable paths. Normally use elan on PATH and the pinned toolchain. |

`bogo start` copies PATH and the three iPhone settings into its user LaunchAgent
plist. It does not copy upstream credentials or the shim's agent token. Set
those iPhone variables before starting. `--home` selects BOGO's state directory;
`HOME` continues to mean the account's real home.
