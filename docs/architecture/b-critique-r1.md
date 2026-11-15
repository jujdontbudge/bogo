# Critique of the other BOGO architecture

The design gets several things right: it is explicit about the proof boundary, it keeps a single serialized coordinator on one thread, it treats APNs as a hint and not a queue, and it does not reuse the old Approvals code. The problems below are where it is wrong, overbuilt, unproved, or too vague to build from.

## 1. It is mostly too vague to build from

The spec's format asks for "a sketch of its interface" for each core piece. Most pieces here are only prose with "must" statements, and an implementer would have to decide almost everything again:
- **Lean kernel (§3.1).** `step : State × Event × TrustedFacts → Result (State × Effects)` is the only signature. There is no `Event` type, no `Effects` type, no `Request` field list with encodings, no FFI symbol list and no ABI rule. "Lean defines the versioned tagged, length-prefixed binary format" is stated without the format: no tags, field order, length width or number-text grammar. The Swift decoder and the test vectors cannot be written from this.
- **Encrypted envelope (§3.5).** Header fields are named but not laid out. There is no message-type list for either direction.
- **Relay (§3.6).** The API is three lines (`put`, `receive`, `ack`). It does not say how mailboxes authenticate, how a sender is allowed to write to a mailbox, how registration rendezvous works, or what happens when a mailbox is full. "HTTP/WebSocket runtime" in §2 never commits to either one.
- **Registration (§3.5).** It describes the properties a SAS exchange needs (commit before reveal, unbiased digits) but not the message sequence: who commits, to what, and in which order. That order is exactly where these protocols break.
- **Config, CLI, state files.** There is no `bogo.toml` schema, no `~/.bogo` layout beyond three names, and no list of CLI subcommands.
- **Questions instead of decisions (§11).** Several questions push design decisions onto the owner. Q3 (App Attest meaning) and Q5 (default precedence) are reasonable to ask. Q4 (schema wrapping), Q6 (identical calls) and Q12 (app identity) are architecture choices that can be made from the spec and the repo. For example, the bundle ID `com.johansardar.applebridge.ios` and team `AX3C2B78YD` are in `ios/project.yml`.

## 2. The lossless argument path is right in principle but has no mechanism

The design correctly says that `rmcp`'s `CallToolRequestParams.arguments` is `Option<JsonObject>`, so the SDK's own decode/encode cannot be trusted with the exact number text. That point stands. serde_json even with `arbitrary_precision` rewrites exponents: `scan_exponent` always pushes a lowercase `e` and inserts `+` when there is no sign, so `4.7E3` and `4.7e3` both become `4.7e+3` ([serde_json `de.rs`](https://github.com/serde-rs/json/blob/master/src/de.rs)).

But the remedy in §3.2 is only a list of steps, and the hard parts are missing:
- **Ingress correlation is over-engineered.** It proposes correlating a raw capture with the SDK request "using server-generated internal correlation, session identity and typed JSON-RPC ID". This isn't needed. MCP 2025-11-25 requires that "the body of the POST request MUST be a single JSON-RPC request, notification, or response" ([transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)), so the raw body belongs to exactly one HTTP request. A tower layer can parse it and put the exact tree into that request's `http` extensions, which reach the rmcp handler. No ID matching is needed, so there is no ID-reuse attack to defend against.
- **Egress is not explained at all.** "The writer emits original number tokens" doesn't say how, when the rmcp client only accepts a `JsonObject`. The real points of control are a custom `Transport` for child processes and a custom `StreamableHttpClient` for remote upstreams. The latter's `post_message` receives the typed `ClientJsonRpcMessage` and serializes it itself ([trait](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html)). The design names neither.
- **The shim.** "The shim forwards raw JSON rather than decoding and reserializing" is right. But the design never says how a raw byte pump gets a session under 2026-07-28, which it calls unresolved in the very next subsection.

## 3. Transport encryption is a home-made construction that needs durable nonce state

§3.5 "Encrypted messages" derives directional ChaCha20-Poly1305 keys from static P-256 ECDH plus HKDF. It then has to reserve nonce counters durably, never reuse them after a crash, and reuse stored ciphertext for retransmits. §5 then needs a "restored old database or lost nonce state → require re-registration" failure mode. All of this comes from choosing static keys with a counter nonce.

HPKE (RFC 9180) in auth mode puts a fresh ephemeral key in every message, so there is no nonce state to lose and that failure mode disappears ([RFC 9180 §5](https://www.rfc-editor.org/rfc/rfc9180#section-5)). Auth mode still authenticates the sender's static key. CryptoKit ships HPKE with `authenticatedBy:` ([CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke)). The host app targets iOS 26 (`ios/project.yml`), so availability is not an issue. `rust-hpke` implements the same suites ([rozbb/rust-hpke](https://github.com/rozbb/rust-hpke)). A reviewed standard with no state beats a custom construction with persistent counters, on both fail-safety and proof burden.

## 4. Binding a "policy snapshot" into the signed request is beyond the spec and redundant

§3.1 adds "the resolved policy snapshot identity, including eligible approver identities and registration generations, threshold, denial behavior, output filtering and execution mode" to the signed bytes. Spec §3.6 lists exactly what a request carries, and this is not on the list. The design's own reason is that it stops signatures from "changing meaning across … policy revisions". But the same design says policy "is immutable for a service generation; restart applies edits and ends old sessions" (§3.2). A restart already kills every pending request and every session, so a signature can never outlive the policy it was made under. The extra field adds encoding surface and phone rendering ("the phone can expose this context") for no gain.

The same applies to the rule "a catalog/schema change while a protected request is pending ends that request" (§3.2). It is a lifecycle rule the spec doesn't have. The owner approved an exact call with exact arguments, and a changed description does not change those bytes.

## 5. The proof boundary trusts things the spec says are adversarial

§3.1 feeds the kernel `TrustedFacts`, which include "trusted time observations, observed connection state, and transport readiness". Spec §3.18 requires a model "in which the agent is fully adversarial and may send any message at any time". Connection state is exactly what the agent controls: it opens, closes, cancels and reconnects sessions. If session liveness is a trusted fact rather than an adversarial input, the theorems say nothing about an agent that plays games with session lifecycle. That is the scenario-3 "from another session" case. Session open/close and call end should be ordinary events in the adversarial trace, with no assumption attached.

The same goes for signatures. "Rust's verifier can construct evidence objects only after validation; the FFI converts those into the kernel's explicitly assumed facts." The design never says that the kernel itself checks that the evidence is over its own stored encoding of this request, with the key registered for this approver. If Rust chooses which bytes were verified, the "exact" theorem depends on Rust. Signature checking should be called from inside the Lean step over bytes Lean built, so the only assumption is "verify is a sound signature check". Lean supports this with `@[extern]` ([Lean FFI](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/)).

## 6. Two-phase dispatch adds state without closing the race

§3.3 "Dispatch boundary" runs a Lean check, commits consumption, and then runs a second "final freshness check through Lean" before the first upstream write. If that check fails, a "consumed but not sent" record results. The send is still asynchronous after the second check, so a cancel that arrives during the write is just as late as one that arrives during the commit. The race moves but does not close, and the design admits as much ("Transport buffering and provider execution are outside the kernel's linearization point"). The cost is a second kernel entry point (`checkDispatch` beside `step`), an extra lifecycle state, and an extra category of audit record. One serialized step that both decides and emits `forward`, followed by a durable log write and the send, gives the same guarantee with less to prove.

## 7. A durable SQLite journal of pending state buys nothing for authorization

§3.3 and §6 persist sessions, request bytes, attempts, delivery outboxes and consumption records in SQLite, with `synchronous=FULL` transactions on every event. Yet §5 says that after a crash "all former service-generation sessions are ended before reopening admission … No pending approval is resumed as executable." So every row of durable pending state is dead on restart. What actually needs to survive is the audit record and the agent/approver registry. An append-only, hash-chained, fsynced log written before every effect gives that with one file, and the spec's `bogo log verify` works on it directly. The "Mac outbox retains every live request until application acknowledgement" (§3.6) is also durable bookkeeping for requests that cannot be live after a restart.

## 8. Pending-and-retry refuses a legitimate second identical call forever

§3.3 says that after consumption, "further retries return a terminal already-consumed outcome or the stored result … one authorization per exact-match key for the session". Q6 then asks the owner how an agent can ever repeat the same action in that session. The spec already answers this. A retry "runs only once it has been approved" (§3.9), and each approval "authorizes at most one execution" (§3.8). Once the request is consumed it is gone, so the next identical call is simply a new request with a new nonce that needs a new approval. That is single-use by construction and needs no new interface bit. Returning a stored result instead is also not what the spec says the agent gets.

## 9. With no session end rule, sessions never end

§3.2 rejects any "heartbeat, guessed idle timeout or concealed default expiry". But for 2025-11-25 HTTP clients the spec defines no session end besides an explicit DELETE, which many clients never send ([transports, Session Management](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)). Under this design, a pending-and-retry request from an agent that has wandered off stays pending until BOGO restarts. It keeps a live entry on the phone that nobody will retry, and it counts against that agent's flood limit forever. Spec §3.7 says the request ends when "the agent's call or session ends (a disconnect, …)". A disconnect needs an observable signal. An open GET stream that closes is one such signal. For a session with no open stream at all, an owner-set idle end is the only one, and the value belongs in the owner's hands, not hidden.

The design also quotes 2025-11-25 as saying that "an SSE disconnection is not automatically a cancellation". That's accurate: "Disconnection SHOULD NOT be interpreted as the client cancelling its request" ([transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)). But the BOGO spec explicitly lists a disconnect as ending the request. If BOGO turns off SSE resumption (no event IDs), a dropped stream can never deliver the result anyway, so ending it is both what the BOGO spec says and fail-closed. The design never reconciles the two.

## 10. Allowed calls are missing from the audit

§4 scenario 4 says "No notification or approval persistence is placed on this path," and the audit event list in §3.7 begins with "Protected attempts". Spec scenario 15 says "Every scenario above appears in the log". That includes scenario 4 (an allowed call) and scenario 17. The design never says that allowed calls are logged.

## 11. The phone is built against a fake transport, so the riskiest parts come last

§3.4 says "a stand-in implements the module's transport interface during phone-first construction", and §8 connects the relay, registration and APNs only at step 6. The parts most likely to surprise are numeric-comparison registration, App Attest, HPKE interop between CryptoKit and Rust, the relay, background push wake, and Deny from the banner. All of them would be exercised only after the whole Mac core exists. The spec's "built against a stand-in for BOGO" is better served by a stand-in that speaks the real relay, real registration and real APNs, and only replaces the decision side.

## 12. The sandbox firewall step needs privileges the agent container must not have

§3.8 "Reference isolation" has a launcher "install default-deny rules in the agent network namespace before starting the untrusted agent". That needs `NET_ADMIN` in that namespace, either through an init step in the same container or a sidecar sharing its namespace. That is a privileged moving part next to the thing it isolates, and the design gives no sketch of it. Docker's `internal: true` network has no route out ([bridge driver](https://docs.docker.com/engine/network/drivers/bridge/)). Combined with a single-port forwarder and an agent container with all capabilities dropped, it gives the isolation the spec asks for. The spec's own proof of isolation is the bypass suite run from inside the container, which tries the host gateway, `host.docker.internal`, the relay and public addresses. The design's concern about published-port routing ([packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/)) is about inbound traffic to published ports, which this setup does not use.

## 13. Smaller points

- **Pause blocks tool discovery.** §3.1 says pause "forbids every subsequent agent request, including tool discovery". The spec says new requests are rejected. Rejecting `tools/list` too is harmless but goes beyond the spec, and it makes a paused agent fail in confusing ways rather than getting a clear "paused" rejection.
- **Two different software approvers are mixed up.** §7 says "the only software approver is the spec's separately built stand-in". The spec has two different things: a stand-in *for BOGO* used while the phone is built (§10), and a test-only *approver* for automated 2-of-2 (§7).
- **Signatures in two formats.** §6 says "DER signatures are strictly parsed and converted to one fixed wire representation". CryptoKit gives `rawRepresentation` (r‖s) directly, so the phone can send that one fixed format and DER never enters the path.

## What the other design gets right that I took

- serde_json `arbitrary_precision` is not enough on its own to keep exact number text (it rewrites exponents), and the shim must forward raw bytes rather than re-encode.
- The filesystem server lets client roots replace its command-line roots ([filesystem README](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)). BOGO's upstream client must declare no `roots` capability (and no sampling or elicitation).
- Tool discovery must follow pagination.
- Link CLI's `--test` is per command, not a login mode ([Link CLI README](https://github.com/stripe/link-cli/blob/main/README.md)). The agent therefore controls whether a spend request is testmode, and that field must be highlighted on the phone. Link auth lives in a file (`--auth` / `LINK_AUTH_FILE`), which BOGO should place under `~/.bogo`.
- Removing a Mac on the phone should tell the Mac, which then revokes that approver.
- Schema augmentation has edge cases with combinators and closed schemas.
- Spec §3.4 can be read two ways: default policy, or approve for newly discovered tools. That belongs with the owner.
- APNs keeps only the latest notification per app while a device is offline, so a shared bundle means an Apple Bridge push can displace a stored BOGO push ([sending notification requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns)). The relay inbox, not APNs, must be what the phone trusts.

## Remaining disagreements

1. **Session end for HTTP sessions with no open stream.**
   - *My position:* A legacy session ends on DELETE, or when its open GET stream closes. A session that never holds a stream ends after an owner-set idle period with no open request. A wait-mode call holds its stream, so idle never ends a call that is waiting.
   - *Best case:* Spec §3.7 ends requests on "a disconnect". Without an observable signal, sessions and their pending-and-retry requests live until restart. They clutter the phone and count against the flood limit forever. The value is the owner's and is listed as a question, not hidden.
2. **Policy snapshot in the signed bytes.**
   - *My position:* Leave it out. Sign exactly the §3.6 fields plus the BOGO installation ID.
   - *Best case:* Policy changes only on restart, and a restart ends every request and session (new boot ID in every nonce). A signature cannot outlive its policy, so binding the policy adds surface without adding safety.
3. **Transport encryption.**
   - *My position:* HPKE auth mode (RFC 9180), single-shot with an ephemeral key per message.
   - *Best case:* No nonce state to persist or lose. It is a standard construction available natively in CryptoKit and in `rust-hpke`, and it removes a whole failure mode the other design must handle.
4. **Durable pending state.**
   - *My position:* Pending requests live only in the core's memory. The durable record is the write-ahead, hash-chained log, and the registry is rebuilt from it.
   - *Best case:* Both designs end every request on restart, so durable pending rows are never used for authorization. One append-only file is simpler to verify, and it is exactly what `bogo log verify` checks.
5. **Pending-and-retry after consumption.**
   - *My position:* The consumed request is removed. The next identical call is a new request needing a new approval.
   - *Best case:* Single-use holds by construction, no new interface bit is needed, and the agent gets what §3.9 says (pending, then the real result) rather than a stored result.
6. **Two-phase dispatch.**
   - *My position:* One serialized core step decides and emits `forward`. The shell logs it durably, then sends.
   - *Best case:* A second "final check" doesn't close the race with an async send. It adds a kernel entry point and a "consumed, not sent" state.
7. **What the proof treats as trusted.**
   - *My position:* Session open/close and call end are adversarial trace inputs. Signature verification is an `extern` called by Lean over bytes Lean encoded, and its soundness is the only crypto assumption.
   - *Best case:* Spec §3.18 says the agent "may send any message at any time". Making connection state a trusted fact weakens the session-binding theorem the spec asks for.
8. **Stand-in for the phone-first build.**
   - *My position:* The stand-in uses the real relay, real registration and real APNs, and replaces only the decision side.
   - *Best case:* Registration, App Attest, HPKE interop and push wake are the riskiest parts. They get exercised first rather than last.
9. **Sandbox enforcement.**
   - *My position:* A Docker `internal` network, a single-port forwarder, and an agent with all capabilities dropped. The bypass suite proves it.
   - *Best case:* No privileged firewall step next to the untrusted process. The spec names the bypass suite as the check.
10. **Ending pending requests on a catalog change.**
    - *My position:* Don't. Only the endings listed in §3.7 apply.
    - *Best case:* The owner approved exact bytes, and a changed tool description doesn't change them. Adding endings the spec doesn't list is a behavior change.
