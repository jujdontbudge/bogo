# MCP front and stdio shim verification

Implementation: `05e7a9c` on `t3/mcp-front-shim`. Run from the repository root.

The runnable fixture links `bogo-core` and the compiled Lean library, with real P-256
approvals through `bogo-verify`. It substitutes only the approver and upstream effects.
It is an example, not a production daemon or an authentication configuration for deployment.

```sh
cargo run -p bogo-front --example standin
cargo build -p bogo-shim
```

The fixture listens at `http://127.0.0.1:18763/mcp`. Its public dummy tokens are
`standin-trip` and `standin-research`. Researcher can see and execute only
`fixture__allow`; the other agent can see the outcome tools except
`fixture__forbidden`. Calling a hidden tool still reaches Lean policy enforcement
and is rejected. The fixture's log shows each core lifecycle input, decision,
original HTTP body in hex, and exact outgoing argument tree.

HTTP MCP config:

```json
{"mcpServers":{"bogo":{"type":"http","url":"http://127.0.0.1:18763/mcp","headers":{"Authorization":"Bearer standin-trip"}}}}
```

Stdio MCP config (replace the executable path):

```json
{"mcpServers":{"bogo":{"command":"/absolute/path/to/bogo-shim","env":{"BOGO_URL":"http://127.0.0.1:18763/mcp","BOGO_AGENT_TOKEN":"standin-trip"}}}}
```

## Actual client use

Used the unmodified `@modelcontextprotocol/sdk` 1.32.2 Client with its
StreamableHTTPClientTransport and StdioClientTransport. Only endpoint/token or
executable/environment configuration differed. Output:

```text
HTTP SDK <none> Error: Streamable HTTP error: Error POSTing to endpoint: 
HTTP SDK wrong Error: Streamable HTTP error: Error POSTing to endpoint: 
HTTP SDK standin-research fixture__allow
HTTP SDK standin-trip fixture__allow,fixture__approved,fixture__denied,fixture__ended,fixture__hold,fixture__not_sent,fixture__pending,fixture__unknown
HTTP SDK CALL {"content":[{"type":"text","text":"Stand-in result: {\"n\":47}"}],"isError":false}
STDIO SDK TOOLS fixture__allow,fixture__approved,fixture__denied,fixture__ended,fixture__hold,fixture__not_sent,fixture__pending,fixture__unknown
STDIO SDK CALL {"content":[{"type":"text","text":"Stand-in result: {\"n\":47}"}],"isError":false}
```

Also invoked Claude Code with the HTTP MCP config, `--bare`, `--strict-mcp-config`,
`--tools ''`, and `--permission-mode dontAsk`. It exited before model/API use:

```text
Not logged in · Please run /login
```

Its authenticated model-backed tools/list and call are therefore **not verified**.
No login, token changes, keychain writes, password prompts, or approval dialogs were used.

## Exact bytes and model-readable outcomes

A raw HTTP API client and a raw stdio process client sent this same message:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fixture__allow","arguments":{"z":4.7E3,"a":-0.00,"middle":9007199254740993}}}
```

Compared the complete sent body with the fixture's `Invocation.body` hex; identical
through both transports (the stdio newline is framing, not part of the message).
Lean receives `Input::Call` with the lexical argument tree; as specified by the
architecture, its binary codec sorts object keys and preserves number token text.
No claim is made that the core's binary wire format is the original JSON body.
The core's forward arguments were:

```text
{"a":-0.00,"middle":9007199254740993,"z":4.7E3}
```

HTTP usage output (all outcomes were obtained from the real front/linked core):

```text
TOOLS standin-trip 200 data: {"jsonrpc":"2.0","id":2,"result":{"ttlMs":0,"cacheScope":"private","tools":[{"name":"fixture__allow","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{},"type":"object"}},{"name":"fixture__approved","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{"justification":{"description":"Agent's reason (unverified)","type":"string"}},"type":"object"}},{"name":"fixture__denied","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{"justification":{"description":"Agent's reason (unverified)","type":"string"}},"type":"object"}},{"name":"fixture__ended","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{"justification":{"description":"Agent's reason (unverified)","type":"string"}},"type":"object"}},{"name":"fixture__hold","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{"justification":{"description":"Agent's reason (unverified)","type":"string"}},"type":"object"}},{"name":"fixture__not_sent","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{"justification":{"description":"Agent's reason (unverified)","type":"string"}},"type":"object"}},{"name":"fixture__pending","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{"justification":{"description":"Agent's reason (unverified)","type":"string"}},"type":"object"}},{"name":"fixture__unknown","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{"justification":{"description":"Agent's reason (unverified)","type":"string"}},"type":"object"}}]}}
id: 0/0
TOOLS standin-research 200 data: {"jsonrpc":"2.0","id":2,"result":{"ttlMs":0,"cacheScope":"private","tools":[{"name":"fixture__allow","description":"BOGO linked-core verification fixture","inputSchema":{"properties":{},"type":"object"}}]}}
id: 0/0
OUTCOME allow 200 data: {"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"Stand-in result: {\"a\":\"odd\",\"justification\":\"demo\",\"z\":4700}"}],"isError":false}}
id: 0/0
OUTCOME approved 200 data: {"jsonrpc":"2.0","id":11,"result":{"content":[{"type":"text","text":"Stand-in result: {\"a\":\"odd\",\"z\":4700}"}],"isError":false}}
id: 0/1
OUTCOME denied 200 data: {"jsonrpc":"2.0","id":12,"result":{"content":[{"type":"text","text":"The owner denied this action. wrong amount"}],"isError":true}}
id: 0/2
OUTCOME ended 200 data: {"jsonrpc":"2.0","id":13,"result":{"content":[{"type":"text","text":"Approval was not received in time; the action was not performed."}],"isError":true}}
id: 0/3
OUTCOME pending 200 data: {"jsonrpc":"2.0","id":14,"result":{"content":[{"type":"text","text":"Pending owner approval. Retry this exact call (same arguments and justification) in this session to run it once approved."}],"isError":true}}
id: 0/4
OUTCOME pending 200 data: {"jsonrpc":"2.0","id":15,"result":{"content":[{"type":"text","text":"Stand-in result: {\"a\":\"odd\",\"z\":4700}"}],"isError":false}}
id: 0/5
OUTCOME forbidden 200 data: {"jsonrpc":"2.0","id":16,"result":{"content":[{"type":"text","text":"This tool is denied by policy."}],"isError":true}}
id: 0/6
STATELESS allow 200 data: {"jsonrpc":"2.0","id":21,"result":{"resultType":"complete","content":[{"type":"text","text":"Stand-in result: {}"}],"isError":false}}
STATELESS pending 200 data: {"jsonrpc":"2.0","id":21,"result":{"resultType":"complete","content":[{"type":"text","text":"This tool needs a session-based MCP connection (protocol 2025-11-25) or the BOGO stdio shim."}],"isError":true}}
EXACT HTTP data: {"jsonrpc":"2.0","id":30,"result":{"content":[{"type":"text","text":"Stand-in result: {\"a\":-0.00,\"middle\":9007199254740993,\"z\":4.7E3}"}],"isError":false}}
id: 0/7
STRICT INVALID 400
STRICT INVALID 400
STRICT INVALID 400
STRICT INVALID 400
SESSION TOKEN SWAP 403
```

The protected approved result removed only the admitted justification key.
The pending response left a session-bound approval, and the exact retry consumed
it through Lean's dispatch gate. A direct 2026-07-28 call to that tool received
the specified session-required wording instead. Current-protocol requests used
per-request MCP metadata and mandatory HTTP method/name headers; the front derives
these transport headers for the shim without changing its bytes.

## Call/session liveness

The raw stdio client held a protected call, completed a second call concurrently,
then sent notifications/cancelled. Lean received CallEnded and emitted
EndedWithoutDecision. An explicitly cancelled MCP request need not return another
terminal response; owner cancellation was separately checked for the exact ended text.

Killed the shim with SIGKILL during another held call. Killed a direct stateless
HTTP curl client during a held call. Both cases ended the call and session in Lean.
For a legacy direct client, dropping its individual response stream ended the call;
the session remained until DELETE, as required by architecture §3.6.
A second call reusing an in-flight JSON-RPC ID received HTTP 409 and could not replace
the first waiter.

```text
SHIM INITIALIZE {'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2025-11-25', 'capabilities': {'tools': {'listChanged': True}}, 'serverInfo': {'name': 'bogo', 'version': '0.1.0'}}}
SHIM EXACT {'jsonrpc': '2.0', 'id': 2, 'result': {'content': [{'type': 'text', 'text': 'Stand-in result: {"a":-0.00,"middle":9007199254740993,"z":4.7E3}'}], 'isError': False}}
SHIM BODY MATCH true
SHIM CANCEL -> CallEnded, EndedWithoutDecision
SHIM SIGKILL: CORE INPUT CallEnded { call: [128, 174, 246, 141, 63, 56, 209, 206, 97, 161, 131, 243, 235, 182, 158, 163] } CORE OUTPUT [Reject { call: [128, 174, 246, 141, 63, 56, 209, 206, 97, 161, 131, 243, 235, 182, 158, 163], why: EndedWithoutDecision }, Ended { req: [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 1], why: CallEnded, to: [[102, 105, 120, 116, 117, 114, 101]] }] CORE INPUT SessionClosed { session: [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 111, 86, 79, 192, 209, 176, 52, 160, 200, 28, 48, 60, 157, 237, 74, 133] }
CURRENT SHIM PENDING/RETRY {'jsonrpc': '2.0', 'id': 2, 'result': {'resultType': 'complete', 'content': [{'type': 'text', 'text': 'Pending owner approval. Retry this exact call (same arguments and justification) in this session to run it once approved.'}], 'isError': True}}
CURRENT SHIM PENDING/RETRY {'jsonrpc': '2.0', 'id': 3, 'result': {'resultType': 'complete', 'content': [{'type': 'text', 'text': 'Stand-in result: {}'}], 'isError': False}}
HTTP CLIENT SIGKILL: CORE INPUT CallEnded { call: [84, 77, 166, 2, 157, 221, 45, 72, 129, 30, 71, 140, 170, 179, 162, 155] } CORE OUTPUT [Reject { call: [84, 77, 166, 2, 157, 221, 45, 72, 129, 30, 71, 140, 170, 179, 162, 155], why: EndedWithoutDecision }, Ended { req: [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0, 0, 3], why: CallEnded, to: [[102, 105, 120, 116, 117, 114, 101]] }] CORE INPUT SessionClosed { session: [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 32, 55, 251, 131, 4, 12, 46, 191, 45, 211, 203, 57, 235, 222, 203, 171] }
DUPLICATE ID 409 JSON-RPC ID is already in flight.
LEGACY STREAM DROP -> CallEnded; session remains until DELETE
LIVENESS CHECKS PASSED
```

Crashed and restarted the fixture daemon while a current-protocol shim call waited.
The pending request failed, the shim reopened liveness as a new session, and a new
call worked without replaying the old call:

```text
DAEMON CRASH PENDING REQUEST {'jsonrpc': '2.0', 'id': 1, 'error': {'code': -32000, 'message': 'BOGO is unreachable; the call was not retried.'}}
RECONNECTED SHIM {'jsonrpc': '2.0', 'id': 2, 'result': {'resultType': 'complete', 'content': [{'type': 'text', 'text': 'Stand-in result: {"unique":"restart"}'}], 'isError': False}}
RESTART CHECK PASSED: new SessionOpened after crash; no old call forwarded
```

## Guardrails and checks

No-token and wrong-token tools/call requests returned 401 with **no core input**.
Duplicate keys, lone surrogates, non-UTF-8, batches and excess depth were refused.
An oversized upload was refused while being written (the Python client observed
broken pipe/connection reset rather than receiving the server's 400 body).
Wrong-agent session reuse closed the BOGO session and returned 403; subsequent
use returned 404. Untrusted Host, browser Origin and stream-resumption attempts
were refused. Additional outcome output:

```text
AUTH '' 401
AUTH 'wrong' 401
NO UNAUTHENTICATED CORE INPUT true
OUTCOME not_sent 200 data: {"jsonrpc":"2.0","id":51,"result":{"content":[{"type":"text","text":"The upstream was unavailable; the action was not performed."}],"isError":true}}
id: 0/0
OUTCOME unknown 200 data: {"jsonrpc":"2.0","id":51,"result":{"content":[{"type":"text","text":"The upstream connection failed after the call was sent; the action may or may not have happened. BOGO will not retry it."}],"isError":true}}
id: 0/1
LIMIT 267 400
OVERSIZE upload refused: <urlopen error [Errno 32] Broken pipe>
HOST/ORIGIN/RESUMPTION {'Host': 'evil.example'} 403
HOST/ORIGIN/RESUMPTION {'Origin': 'https://evil.example'} 403
HOST/ORIGIN/RESUMPTION {'Last-Event-ID': '0/0'} 403
```

Commands completed successfully:

```sh
cargo check -p bogo-front -p bogo-shim
cargo clippy --workspace --all-targets
BOGO_REVIEW_STANDIN="$PWD/target/debug/examples/standin" cargo test -p bogo-front -p bogo-shim
cargo fmt --all --check
```

The test command ran the full test targets and doctests of both new crates
(no added tests before review); actual API/SDK/process use above is the feature evidence.
No CI workflow exists in this checkout. Existing packages were included in workspace
clippy; their unrelated test suites were not rerun.

## Boundaries and remaining integration

`bogo-front::Backend` is the narrow daemon effects-shell port: it looks up token hashes,
provides agent availability and the prepared per-agent catalog, accepts ordered lifecycle
inputs, supplies the daemon clock, and admits calls synchronously before returning a
result future. The final daemon must drive core outputs, durability, approval delivery,
and the gated upstream transport. Front never imports upstream internals or approver routes.
`bogo-shim` depends on no daemon crate or rmcp.

Not checked here: an authenticated Claude Code model run; actual upstream/approver
production wiring and audit durability (later ticket); real runtime registry mutation
and tool-list-change delivery; long idle sessions or suspended-Mac clock behavior.
Legacy MCP sessions are retained between requests until DELETE, revocation or shutdown;
a disappeared legacy client between requests cannot be detected, as documented in §3.6.

Sol round 1 (`gpt-6.1-sol`, medium) returned CHANGES with one finding:
S1 (should): a legacy stdio client could not call after daemon restart because
replacement liveness did not restore its MCP handshake. Accepted and fixed.
The shim now retains and replays only the original initialize/initialized bytes,
keeps replacement sessions unavailable to calls until that handshake completes,
and suppresses the duplicate initialize response. Tool calls are never replayed.

Applied Sol's regression test, reproduced its failure against the committed shim,
then ran the same test after the fix:

```text
   Compiling bogo-shim v0.1.0 (/Users/johansardar/.t3/worktrees/bogo/t3-307529f0-2e0c831ab81a251a/crates/bogo-shim)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.73s
     Running tests/reconnect.rs (target/debug/deps/reconnect-90e3227dde3ccbc7)

running 1 test
bogo-shim: notification stream: body error: error decoding response body
bogo-shim: BOGO returned HTTP 400 Bad Request

thread 'legacy_stdio_client_can_call_after_daemon_reconnect' (7846967) panicked at crates/bogo-shim/tests/reconnect.rs:96:5:
daemon is back and liveness reopened, but the legacy client cannot call: {"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"BOGO is unreachable; the call was not retried."}}
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test legacy_stdio_client_can_call_after_daemon_reconnect ... FAILED

failures:

failures:
    legacy_stdio_client_can_call_after_daemon_reconnect

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.01s

error: test failed, to rerun pass `-p bogo-shim --test reconnect`

   Compiling bogo-shim v0.1.0 (/Users/johansardar/.t3/worktrees/bogo/t3-307529f0-2e0c831ab81a251a/crates/bogo-shim)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.79s
     Running tests/reconnect.rs (target/debug/deps/reconnect-90e3227dde3ccbc7)

running 1 test
bogo-shim: notification stream: body error: error decoding response body
test legacy_stdio_client_can_call_after_daemon_reconnect ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.16s

```

The fixture path can be set with `BOGO_REVIEW_STANDIN`; otherwise the test uses
`target/debug/examples/standin`. Build the front example before running just the
shim's test suite. The full changed-package suite, workspace clippy and formatting
checks pass after the fix; the real SDK, concurrent call/cancel/crash checks, exact
stdio body match and current-protocol reconnect were also exercised again.

Sol round 2: fix review pending. No findings declined. No review token usage was
returned. Not pushed.

