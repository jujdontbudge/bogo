<img src="assets/icon.svg" width="64" height="64" alt="">

# BOGO

BOGO puts approval between a named AI agent and protected MCP tools. Its Lean
core checks the exact call, signatures, session, expiry and single use before
permitting an upstream write. An explicitly allowed tool runs without approval;
a denied tool never runs through BOGO.

Start here: [configuration](docs/configuration.md),
[threat model](docs/threat-model.md), and
[What is proved / What is assumed](docs/proved-and-assumed.md).
The [spec](docs/SPEC.md) describes the intended product; the walkthrough below
uses the implemented Mac daemon and a **software test approver**. It does not
provide Face ID or protect a host agent from using its own shell to bypass MCP.
For agent isolation, follow the [reference sandbox](sandbox/README.md).

## Quick start on macOS

Use a terminal in this repository's root. Prerequisites: Xcode Command Line
Tools, [Rust via rustup](https://rustup.rs/),
[Lean via elan](https://github.com/leanprover/elan#installation), Node.js and npm,
Python 3, and an installed, authenticated [Claude Code](https://code.claude.com/docs/en/setup)
CLI (`claude`). Claude needs access to its model; this uses its existing login.
The repository pins Lean in `lean/lean-toolchain`. Put elan first: some Python
installations also ship an unrelated program called `lean`.

These commands create a fresh private demo directory, leaving `~/.bogo` alone.
Keep using the **same terminal**, including while Claude runs in the background.
Port 18790 must be free. No LaunchAgent is loaded in this walkthrough.

```sh
export PATH="$HOME/.elan/bin:$PATH"
cargo build -p bogo -p bogo-daemon -p bogo-shim --features bogo/test-approvers
export BOGO_BIN="$PWD/target/debug/bogo"
export BOGO_SHIM="$PWD/target/debug/bogo-shim"
export BOGO_DEMO="$(mktemp -d /tmp/bogo-quickstart.XXXXXX)"
export BOGO_DEMO_HOME="$BOGO_DEMO/home"
umask 077
mkdir -p "$BOGO_DEMO/scratch" "$BOGO_DEMO/client"
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" init
npm install --prefix "$BOGO_DEMO/upstream" --no-audit --no-fund \
  @modelcontextprotocol/server-filesystem@2.3.0
```

Configure a flood limit of four live requests per agent, an allowed read and a
protected write. These are demo choices, not shipped defaults. Every other
unlisted tool still needs approval. The filesystem upstream gets only the
scratch directory, a sibling of the private BOGO home.

```sh
cat > "$BOGO_DEMO_HOME/bogo.toml" <<'TOML'
version = 1
[server]
port = 18790
[defaults]
policy = "approve"
max_pending = 4
[tools.files__read_text_file]
policy = "allow"
[tools.files__write_file]
policy = "approve"
justification = "required"
TOML
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" upstream add files -- \
  "$(command -v node)" \
  "$BOGO_DEMO/upstream/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js" \
  "$BOGO_DEMO/scratch"
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" serve > "$BOGO_DEMO/daemon.log" 2>&1 &
BOGO_DAEMON_PID=$!
```

Run `status` once startup finishes; if it cannot connect yet, run it again.
Expect `running: true` and `upstreams: {files: true}`. If startup fails, inspect
`$BOGO_DEMO/daemon.log`. `tools` needs the catalog from a first successful start.
Register a software approver and a named agent. Capture the token without
printing it or putting it in the MCP JSON file:

```sh
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" status
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" approver add 'Demo approver' --kind soft
export BOGO_AGENT_TOKEN="$("$BOGO_BIN" --home "$BOGO_DEMO_HOME" agent add 'Demo agent' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
export BOGO_URL=http://127.0.0.1:18790/mcp
python3 - <<'PY'
import json, os
from pathlib import Path
p = Path(os.environ['BOGO_DEMO']) / 'client' / 'mcp.json'
p.write_text(json.dumps({'mcpServers': {'bogo': {'command': os.environ['BOGO_SHIM']}}}))
PY
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" tools
```

Claude inherits the token through its environment; the shim binds requests to
that Claude process's lifetime. Run Claude from the empty client directory so
repository instructions do not affect the demo. Its only enabled tools here
are BOGO's MCP tools. This CLI restriction is for reproducibility; it is not a
security sandbox.

```sh
printf 'Hello from BOGO\n' > "$BOGO_DEMO/scratch/hello.txt"
(
  cd "$BOGO_DEMO/client"
  claude -p "Use files__read_text_file to read $BOGO_DEMO/scratch/hello.txt. Then use files__write_file to write exactly BOGO APPROVED to $BOGO_DEMO/scratch/approved.txt, with justification 'Quick start protected write'. Report both tool results." \
    --mcp-config "$BOGO_DEMO/client/mcp.json" --strict-mcp-config \
    --tools '' --allowedTools 'mcp__bogo__*' --permission-mode dontAsk \
    > "$BOGO_DEMO/claude.out" 2>&1
) &
BOGO_CLAUDE_PID=$!
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" request list
```

Run `request list` again while Claude works until the write appears. The current
CLI lists IDs and hex request bytes, not a decoded review screen.
Use the call log to inspect `agent_name`, `tool`, and `arguments`; this fresh
demo should have exactly one pending request, for the write just requested.
Before approving, confirm that the file is absent:

```sh
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" log search files__write_file
test ! -e "$BOGO_DEMO/scratch/approved.txt" && printf 'Not written before approval\n'
```

Check the logged call is the intended demo write. From `request list`, copy its
full `id` (80 hex characters), replacing
`FULL_REQUEST_ID` below; approve only the intended demo write.

```sh
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" soft 'Demo approver' FULL_REQUEST_ID
wait "$BOGO_CLAUDE_PID"
cat "$BOGO_DEMO/claude.out"
cat "$BOGO_DEMO/scratch/approved.txt"
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" log verify
```

Expect `decision recorded`, Claude's real filesystem results, file content
`BOGO APPROVED`, and `chain intact` with one counted approval. The software
approver signs without user verification; anyone with this Mac account can
operate it. **Do not use this build/home to protect real actions.**

Stop the foreground daemon and check that its log remains verifiable:

```sh
kill -TERM "$BOGO_DAEMON_PID"
wait "$BOGO_DAEMON_PID"
"$BOGO_BIN" --home "$BOGO_DEMO_HOME" log verify
unset BOGO_AGENT_TOKEN
```

The demo directory retains arguments, audit records and the software key. Keep
it private; remove that specific temporary directory when finished.

## Running beyond the demo

Build production binaries without test features, into a separate target directory
so they cannot be confused with this demo:

```sh
CARGO_TARGET_DIR=target/production cargo build -p bogo -p bogo-daemon -p bogo-shim
```

Use an installed absolute binary path that survives login, `bogo init`, edit the
[configuration](docs/configuration.md), then `bogo start`. This loads the
`si.eilmer.bogo` **user** LaunchAgent with KeepAlive; `bogo stop` unloads it.
There is one service label per Mac account, regardless of `--home`. Never start
a second home under that label. Changes to TOML require a restart. See
[daemon operations and recovery](docs/daemon.md) for pause, revoke, cancel,
exports and crash outcomes. Never automatically retry an outcome reported as
unknown: the provider may already have acted.

The iPhone approver code exists inside the Apple Bridge iPhone app, with its
own registration, keys, encrypted relay channel and review screen. Production
registration requires App Attest and APNs configuration. **A real-device
session (Face ID, hardware App Attest and push), public relay deployment, and
completed Link login/payment checks remain outstanding** in the recorded
verification. This is not yet an end-to-end qualified phone setup guide.
[Verification records](docs/verification/daemon-cli.md) distinguish the working
software/local-relay paths from those remaining checks; the
[sandbox record](docs/verification/sandbox-e2e.md) explains the Link limitation.
No Apple Bridge Mac gateway, relay or credentials are needed for the demo.
The [quick-start verification record](docs/verification/user-docs.md) includes
the real Claude results, configuration probes and a reported path-validation bug.

Created in [T3 Code](https://t3.codes).
