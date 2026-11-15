# Critique of the competing architecture

The design gets several things right that matter: the lossless argument boundary, a final gated handoff before an upstream write, request IDs that bind the service generation, epoch-bound pause, settled decisions that can't change, the App Attest wording, phone-first build order, and an explicit sandbox policy. I have adopted most of those. What follows is where it is still wrong, unproved, missing part of the spec, or adds what the spec did not ask for.

## 1. It mostly describes properties, not mechanisms

The format asks each core piece for "a sketch of its interface". In most places this design gives requirements in place of the mechanism, so it can't be built or checked as written:

- **Lean interface (§3.1).** The whole kernel interface is three lines: `step : State × Event × VerifiedFacts -> Result(State × Effects)`, `finalHandoff`, `encodeRequest`. It never lists the events, the effects or the state. So the proof scope can't be checked against the spec. Does `Event` include agent-controlled session open and close? Malformed bridge bytes? Approver revocation? The adversary model in §3.18 ("any message at any time") is a claim about exactly that list, and the list isn't there.
- **Encoding (§3.1).** It says "tagged, length-prefixed … distinct constructor tags, specified integer widths". It gives no tags, field order, widths or layout. Both platforms need these bytes before anything else, and the Swift decoder must reject exactly what the Lean decoder rejects. A grammar is the interface. "Has a grammar" isn't one.
- **Justification field (§3.2).** It says "Closed schemas, references, compositions and pattern properties require a faithful transformation", but it gives no transformation, and then "an unrepresentable schema is reported as incompatible". It never says which schemas those are. The spec requires the field on every approve tool (§3.5), so this leaves an unbounded set of tools on which §3.5 silently doesn't hold.
- **Relay (§3.6).** It gives three verbs (`put`, `receive`, `ack`). It has no authentication protocol, no sender allowlist (any authenticated party could fill a mailbox), no rendezvous API for Add Mac (§3.5 says "BOGO's own rendezvous" and never defines it), no full-mailbox behaviour and no retract for undelivered requests that ended.
- **Envelope (§3.5).** It lists fields to bind, but has no layout, no HPKE `info`/`aad` split and no message-ID derivation. "Conflicting bytes under an ID are rejected" needs a defined ID.
- **Session observation (§3.2).** It says "Stdin EOF … and observed process/transport termination end the corresponding work". It doesn't say how BOGO, on the HTTP side, *observes* a shim that was `kill -9`ed between requests. With no open request there is no HTTP connection to drop. A shim-held liveness stream, or something like it, is needed, and none is described. In that window a pending-and-retry request sits behind a dead session, and the spec (§3.7) says it should have ended.

## 2. A dropped response stream is not treated as the end of the call

**§3.2:** "An SSE interruption alone is not universally a logical session ending", and "observed wait-call cancellation ends that call". SPEC §3.7 lists "a disconnect" as one of the events that end a request, and Scenario 6 has the client simply giving up. Many clients give up by closing the connection, not by sending `notifications/cancelled`.

MCP 2025-11-25 says a disconnect "SHOULD NOT be interpreted as the client cancelling its request" because the stream may be *resumed* ([transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)). That reason only applies if the server offers resumption, meaning event IDs and `Last-Event-ID` replay. If BOGO sends no event IDs (rmcp `SessionConfig.sse_retry = None`, [docs](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_server/session/local/struct.SessionConfig.html)), a dropped POST stream can never deliver its result. Ending the call is then both spec-compliant and fail-closed. The design never decides resumability, so a wait-mode request whose client hung up stays pending, and stays approvable, until some other signal arrives.

## 3. "Prepare exact bytes, then hand them to the single sender" doesn't fit rmcp, and the design doesn't say how it would

**§3.3 steps 1 and 5:** "Prepare the authenticated upstream connection and exact outbound bytes without sending … hand the already prepared bytes to the single sender."

In rmcp, the JSON-RPC request ID for a client `call_tool` is assigned inside the service loop, and responses are correlated by that ID. Bytes prepared outside rmcp either carry an ID rmcp didn't issue (so the response is orphaned), or they bypass rmcp's client entirely. Bypassing rmcp breaks the spec's "using the `rmcp` MCP SDK" for upstream calls. The design names the hazard ("Any upstream library retry/reconnect behavior … must be disabled at this boundary") but not the integration.

A workable integration exists: a custom rmcp `Transport` that serializes the outgoing `tools/call` itself, writing the arguments from a one-shot ticket that the final gate registers ([`Transport`](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport.rs), [`StreamableHttpClient::post_message`](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html)). rmcp keeps the ID, and BOGO keeps the bytes. Without something like that, step 5 is a wish.

Also, "Prepare the connection … do not consume authorization while waiting for connection setup or credential refresh" adds a waiting state for settled requests that the spec doesn't have. It is unclear whether a settled request waiting on a reconnecting upstream counts toward the pending limit, can be cancelled, or shows on the phone. Refusing with "upstream unavailable" at the gate is simpler, and it is just as fail-closed.

## 4. The lossless capture is correlated by JSON-RPC ID, which is weaker than needed

**§3.2:** "Server-minted call identity correlates this capture to the authenticated agent, session and typed JSON-RPC ID. Reusing an in-flight ID is rejected."

The correlation doesn't need a cross-request table at all. rmcp's Streamable HTTP server inserts the request's `http::request::Parts`, extensions included, into the JSON-RPC request's extensions, in both session and stateless modes ([`tower.rs`](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport/streamable_http_server/tower.rs): `req.request.extensions_mut().insert(part)`). An exact tree that an outer HTTP layer puts in the request's extensions therefore arrives with exactly that request's handler.

A table keyed by JSON-RPC ID adds a shared structure and a new rejection rule ("reusing an in-flight ID"), which is an agent-visible behaviour the spec doesn't define. It also needs cleanup on every exit path. The **shim** is also allowed to "adapt protocol envelopes", which means a second JSON parser that has to keep lexical number text. A shim that pumps bytes unparsed has no such obligation.

## 5. Things the spec didn't ask for

- **A "policy context" in the signed request (§3.1).** It binds eligible approver key generations, threshold, denial behaviour, mode and output filtering into the signed bytes. SPEC §3.6 lists what a request carries, and none of these are on it. Principle 4 says the owner sees what they sign, so every signed field must be rendered or it is signed unseen. The addition is also redundant: the design's own §3.2 says configuration is immutable until restart, and a restart ends every session and therefore every request. Policy can never change under a pending request. Re-registration and revocation are handled by the core's live registry check at dispatch, which doesn't need signing.
- **Retained consumed records that return a stored result (§3.3).** After a pending-and-retry request runs, later identical retries "return the recorded terminal outcome or stored filtered result, never execute again or silently create another request". Then §11 asks how a new identical action should be expressed. That adds result storage, a session-long tombstone and a new agent-visible behaviour, and it opens a spec question. The spec already answers it more simply: the retry "runs only once it has been approved" (§3.9). A later identical call is a new request that needs a new approval, which the owner sees and can deny. No approval ever covers two runs, which is all §3.8 requires. Storing filtered upstream results in BOGO is also new data at rest that the audit section (§3.11) never asked for.
- **"Tool-contract changes end affected pending requests" (§3.2, §5).** This is a new way for a request to end that isn't in SPEC §3.7's list. The signed bytes already fix exactly what will run, so a changed upstream description doesn't make the approved call any different.
- **"Old database restored" handling (§5).** Under this design's own threat model, restoring an old database is a Mac-compromise or owner action, which is out of scope (SPEC §3.19). The handling is extra.
- **An HTTP-aware sandbox forwarder that "accepts only BOGO MCP methods/path" (§3.8).** This puts a request parser between the agent and BOGO. BOGO already authenticates and judges every byte. A fixed-port TCP forwarder has no parsing surface, and the default-deny namespace policy (which I agree with) is what enforces "only BOGO".

## 6. Durable state for things that can't survive a restart

**§3.3 and §6:** sessions, exact pending requests, attempts and outboxes are all stored in SQLite, and each security event is a durable transaction. But the design's own recovery rule is "end every former service-generation session before accepting calls". So every pending request is dead after a restart anyway. Persisting each pending request, each delivery receipt and each settlement transactionally buys one thing: terminal notices to phones after a crash. A single post-restart "new generation" notice gives that too, since phones grey out every request from an older generation.

The durable state that actually has to survive is the registry (agents, tokens, pause epochs, approvers and key generations) and the audit record. An append-only, hash-chained log that is the source of truth for the registry gives one durable authority with one write per event, with snapshots carrying their replay position. That is the event-sourced recovery this design's critique allows as equivalent. Per-message durable receipts on the Mac are only needed for messages whose effect isn't idempotent, and with full request IDs, settled-once requests and epoch-bound pause, none of the phone→Mac messages are like that.

## 7. Parts of the spec that are thin or missing

- **Mismatch warning (§3.4).** It says "a deterministic small parser" but gives no patterns. The spec gives examples (`$47`, `47 USD`, `47 dollars`), and the phone must not "cry wolf" on `6pm` or flight numbers. Which forms are recognized is an interface that the review screen and its vectors depend on.
- **Display formats (§3.4).** "Exact decimal/integer-scale arithmetic". The design never says what `usd_cents` does with `4700.0` or `4.7e3`, both of which the spec says are distinct values. It needs a rule (for example, non-integer text is shown raw and marked) so the phone never formats something as `$47.00` that isn't integer text.
- **Pause and paused agents.** The CLI's `pause` (SPEC §7 draft) is mentioned, but how the phone learns the current pause epoch is only "through authenticated state", which is never defined.
- **APNs collapse and grouping (SPEC §3.8.1).** Grouping is described on the phone only. Banners aren't collapsed for duplicate requests, so a flood still produces a banner per request: the "reflex tap" surface §3.8.1 is meant to remove.
- **Config.** No `bogo.toml` sketch for the fields the spec requires per tool: denial rule, highlight formats, pending limit, hidden versus shown deny tools.
- **Owner cancel.** It is listed in the CLI, but no core event or flow is shown for it.
- **`bogo log verify` threshold check.** It says "checks protected consumption against eligible approvals at dispatch". It doesn't say how eligibility at dispatch is reconstructed from the record, which needs registry events and per-tool policy in the log.

## 8. Smaller points

- **Monotonic expiry (§3.3).** "A sleep-aware monotonic deadline derived at creation". The signed `expiresMs` is wall-clock time and the phone counts down to it. Two clocks can disagree about when a request ended. The rule "clock inconsistencies cannot extend lifetime" needs both checked, and the design says neither which wins nor how the phone shows it. The spec trusts the Mac's clock (assumptions list nothing else), so a single wall-clock check at the gate is simpler and matches what was signed.
- **Own App Attest verifier from CBOR/DER plus macOS Security (§9).** That is a reasonable option. But "a library wrapper is accepted only if it covers that procedure" is a condition, not a choice. The design never says which steps the chosen parsers perform and which BOGO code does. Apple's list now has eleven steps, including `apple_validation_category_01` and `apple_bundle_version_01` in the authenticator-data extensions ([Apple](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)).
- **Allowed calls and the audit (§3.3, §3.7).** "No general new audit requirement is imposed on allowed calls". But SPEC Scenario 15 says "Every scenario above appears in the log with its decision and reason", and that includes Scenario 4 (an allowed read). Allowed calls must be logged. They need not *wait* on the log before running.

## Remaining disagreements

| Point | My position | Best case for it |
|---|---|---|
| Durable authority | An append-only hash-chained log is the single source of truth. Registry checkpoints carry the `seq` they reflect and are rebuilt by replay at startup. Pending requests stay in memory and die with their sessions. | Every request dies at restart by rule, so persisting live request state and receipts transactionally adds durable writes on the hot path and buys only what a post-restart generation notice gives. The log has to exist anyway (SPEC §3.11), so making it the authority removes the second store instead of joining two. |
| Pending-and-retry after the run | A consumed request is removed. A later identical call is a new request with a new nonce and needs a new approval. No stored results. | It meets §3.8 (no approval covers two runs) and §3.9 ("runs only once it has been approved") with no new behaviour, no stored upstream results and no open spec question. A lost-result retry costs the owner one extra prompt they can deny. It never costs an unapproved run. |
| Policy context in signed bytes | Sign only what SPEC §3.6 lists. | Configuration can't change under a live request, because a restart ends them all. Revocation is checked live at the gate. Extra signed fields are signed unseen, against Principle 4. |
| Disconnect ends a call | With no stream resumption offered, a dropped response stream ends the call. | SPEC §3.7 names "a disconnect". MCP's caution exists only for resumable streams, and BOGO offers none. |
| Ingress correlation | Per-HTTP-request extensions carry the exact tree. The shim is an unparsed byte pump. | rmcp already delivers each request's `Parts` to its own handler, so there's no shared table and no new rejection rule. A byte pump can't lose number text. |
| Upstream not ready at dispatch | The gate refuses with "upstream unavailable", and the request is consumed. No waiting state for settled requests. | It is just as fail-closed, and it adds no state the spec lacks. |
| Tool-contract change ends requests | No. | Not in SPEC §3.7's list, and the signed bytes already fix what runs. |
| Sandbox forwarder | Fixed-port TCP forwarder plus a default-deny namespace policy. | No parser in front of BOGO. The namespace policy, not the forwarder, is what enforces "only BOGO". |
| Expiry clock | One check against the signed wall-clock `expiresMs` at approval and at the gate. | That is what the owner signed and what the phone counts down. The spec trusts the Mac's clock. |
