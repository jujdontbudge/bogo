# Upstream transport boundary

`Manager::start` owns one rmcp connection per configured upstream. It discovers all
pages, keeps the catalog through outages, refreshes after tool-list notifications,
and restarts failed connections with capped exponential backoff. `health` and
`subscribe` expose current connection/catalog state. Save/load `Catalog` at the
daemon's `state/tools.json` path to retain first-seen times across daemon restarts.

The daemon must subscribe, configure the core with each changed catalog (including
its stable justification key), and only then admit calls against it. `tools_for`
projects policies and hidden denied tools for an agent. The core independently
resolves policy at admission and dispatch. Catalog views are never authorization.

Implement `Gate` using the daemon's core channel. `dispatch` must sample the daemon's
sleep-aware monotonic clock when the core processes it, durably record the result,
and consume a CallId at most once globally, including calls with policy allow.
Only `Forward` carries the authoritative upstream, tool and justification-free
`bogo_json::JVal`. Do not parse arguments into rmcp's map. `Manager::call` stages
only the CallId; the exact transports refuse unmarked calls and custom-message
attempts to bypass that check. They check the authoritative destination matches
the staged tool and connection. No call is queued for a later reconnect.

A child pipe lock, health check, HTTP headers and credentials are prepared before
dispatch. After dispatch the transport constructs the exact JSON-RPC frame and
starts one write in the same task. Numbers retain their original lexical spelling;
object key ordering and string escaping follow the approved exact writer in
ARCHITECTURE §3.2 and ADR 0001. Original whitespace and key order are not signed.
No justification or private call marker is sent upstream. HTTP redirects, request
retries and expired-session reinitialization are disabled.

`Gate::outcome` reports `not_sent` when the transport can establish that no bytes
left, or `unknown` after a partial write / lost reply. The daemon adapter must
resolve these through its durable effect shell. Never retry an unknown outcome.
Gate refusal is returned as a fixed error; the daemon resolves its waiter from the
core's rejection. Interactive upstream requests and InputRequiredResult are refused.

The child's environment starts empty, inherits only PATH, then receives its own
configured environment. Pass HOME explicitly only if an upstream requires it.
Remote credentials are sensitive HTTP headers; they never enter tool arguments.
All configured secret values, their base64 forms, and multiline components are
scrubbed before incoming messages reach rmcp; stderr is scrubbed before tracing.
Errors retain no SDK bodies, URLs or credentials. Scrubbing catches exact echoes,
not arbitrary transformations, encryption or encodings of credentials.

The crates remain independent as ARCHITECTURE §9 requires. `Manager::call` returns
credential-scrubbed results; the daemon must then call `bogo_filter::filter` on
the serialized MCP result **before** logging or returning it. Convert that value
back to rmcp's CallToolResult at the shell. Use the tool's configured paths/action,
and record Report counters without withheld content. Filters remove named fields;
they do not detect sensitive prose or binary data. Text/resource URI strings that
cannot be parsed as JSON are withheld when filters are enabled. Catalog output
schemas are conservatively omitted for every filtered tool, including redaction,
since a replacement string may also invalidate the original schema.

Justification is optional in the advertised schema; the core enforces any required
justification at admission. Keys are reserved across properties, branches and $defs,
including patternProperties. Schemas with complex whole-object constraints are
flagged `strict_client_risk`. An invalid/unsupported regex or no safe candidate
among the first 4096 names makes the tool unexposable rather than risking a collision.
An upstream that assigns undeclared meaning to the reserved name cannot receive
that name as a real argument; the chosen field always belongs to BOGO.

Run the real client verification with:

```sh
npm install --prefix /tmp/bogo-upstream-fs --no-audit --no-fund @modelcontextprotocol/server-filesystem@2.3.0
BOGO_FS_SERVER=/tmp/bogo-upstream-fs/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js cargo run -p bogo-upstream --example verify
```

This is an executable client and echo upstream for manual verification, not a daemon
or a replacement for its future durable Gate adapter. It uses synthetic credentials.
