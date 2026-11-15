# Running BOGO on the Mac

Build the CLI, daemon and shim together:

```sh
cargo build -p bogo -p bogo-daemon -p bogo-shim
./target/debug/bogo init
```

`init` creates the private BOGO directory, keys, an owner-edited configuration,
an empty 0600 `secrets.toml`, and a concrete user LaunchAgent plist. It preserves
existing configuration. No system service, Keychain write, or password is used.
Use an absolute path to an installed binary; launchd must still find it at login.
`bogo-daemon --home DIRECTORY` is also available for foreground operation;
the user LaunchAgent runs `bogo --home DIRECTORY serve`.

Set `[defaults] max_pending` explicitly in `~/.bogo/bogo.toml`, then add an upstream:

```sh
bogo upstream add files -- npx -y @modelcontextprotocol/server-filesystem@2.3.0 /absolute/scratch/folder
bogo agent add 'Trip planner'
bogo start
bogo status
bogo tools
```

All commands accept `--home DIRECTORY` to select a separate BOGO directory
without overriding the process's home. The upstream add command requires BOGO
to be stopped. Config changes take effect on restart. Default policy `allow`,
unknown configuration keys, unsafe secrets permissions, path secrets outside
BOGO's directory, and upstream paths into that directory or its parents are
refused. Commands and arguments with path syntax are resolved through symlinks.
The strict body parser currently supports at most 1MiB; larger configured limits
are refused explicitly.

Copy the token printed by `agent add` once into the client's private connection
configuration. Only its SHA-256 enters BOGO's registry and log. For Claude Code,
use the stdio shim to bind the lifetime of pending calls to the client process:

```json
{"mcpServers":{"bogo":{"command":"/absolute/path/bogo-shim"}}}
```

Give that process `BOGO_URL=http://127.0.0.1:8790/mcp` and
`BOGO_AGENT_TOKEN` in its environment. HTTP MCP clients can use the same URL with
`Authorization: Bearer <agent token>`. The shim is preferred for clients that can
silently abandon otherwise live HTTP sessions; it keeps a separate liveness
stream and closes the BOGO session when the process dies.

Unlisted tools require approval. To open a particular read and protect writes,
edit `bogo.toml` and restart:

```toml
[tools.files__read_text_file]
policy = "allow"
[tools.files__write_file]
policy = "approve"
justification = "required"
# require = { k = 2 }
# approvers = ["Johan iPhone", "Second approver"]
[agents.Researcher.tools.files__write_file]
policy = "deny"
```

`bogo tools` reports effective policies, agent overrides, missing approvers,
thresholds and schema risks. Missing approvers do not open a tool. Disconnected
upstreams keep their cached tools discoverable; calls are not sent.

## Approvers

Configure `[relay]`, `[apns]` and `[approvers.iphone]` following the architecture.
`max_message_age`, `mailbox_capacity` and `approve_arm_delay` have no shipped
values. Set them deliberately. The standalone relay also requires explicit
`--max-message-age` and `--mailbox-capacity`; its values must match the owner's
deployment settings. The daemon does not administer the relay remotely.

Put the APNs key under BOGO's private directory and refer to it with a path
secret in `secrets.toml`. Set `BOGO_APP_BUNDLE_VERSIONS` to the comma-separated
accepted App Attest build numbers before `bogo start`. For a private test relay,
`BOGO_RELAY_CA` names its PEM certificate. `BOGO_MAC_NAME` sets the registration
label. These three non-secret settings are copied into the user LaunchAgent;
credentials are not copied into it.

```sh
bogo approver add 'Johan iPhone'
bogo approver list
bogo approver revoke 'Johan iPhone'
```

Compare the numeric code with the phone and confirm in the terminal. Reusing a
name registers a new key and revokes the old approver. Every completed registration
and revocation enters the audit log before it affects requests. Registry caches
are never used as authority by the daemon.

For a deliberately insecure verification build only:

```sh
cargo build -p bogo --features test-approvers,test-registration
bogo approver add 'Soft A' --kind soft
bogo request list
bogo soft 'Soft A' FULL_REQUEST_ID
bogo soft 'Soft A' FULL_REQUEST_ID --deny --note 'wrong amount'
```

`test-approvers` adds the software route and Ed25519 approval verifier; neither
is in the production daemon's dependency graph. Test seeds stay in
`secrets.toml`. `test-registration` allows the existing simulator registration
path without App Attest or APNs credentials; the production build requires both.
An arm delay and relay limits are still required whenever the iPhone route is
configured. A software route never counts as Face ID or hardware-backed approval.

## Owner operations and recovery

```sh
bogo agent list
bogo agent pause 'Trip planner'
bogo agent unpause 'Trip planner'
bogo agent revoke 'Trip planner'
bogo request list
bogo request cancel FULL_REQUEST_ID
bogo log
bogo log search denied
bogo log verify
bogo export --format jsonl
bogo log export --format csv
bogo stop
```

Mutations use the owner-only Unix socket while running. It checks the peer UID
and accepts bounded JSON lines. Stopped agent and revocation commands take the
same single-writer lock. Stopped log queries and exports are read-only.

The effects shell serializes lifecycle events, owner changes, approver decisions
and transport dispatch. It commits call, request, decision, authorization and
a dispatch-intent record before the final check, and result summaries before returning results.
After the intent is durable, dispatch is requeued behind lifecycle events observed
during that sync. An accepted core `forward` is returned without another await;
the forwarding record is queued before the gate reply and committed before any
result can be returned. A crash in between remains unknown from the already
durable call and authorization records. This ordering preserves the final gate
when durability and freshness would otherwise conflict.
It never stores upstream result bodies. The actual result is scrubbed by the
upstream manager and filtered before reaching the agent. Log verification checks
the hash chain, registered keys, canonical request bytes and approval signatures
through the compiled Lean decoder and verifier hook.

Every daemon boot starts a fresh core. Pending requests end; anything authorized
or forwarded without a terminal result is conservatively unknown. Nothing is
replayed. `stop` unloads KeepAlive, closes admission and sessions, and drains
those lifecycle events through a durability barrier. Startup refuses corruption;
only a torn final line is moved aside by the existing log recovery code.

The sandbox is a separate ticket. A host agent with built-in shell access can
bypass MCP; this daemon does not claim to sandbox that process.
