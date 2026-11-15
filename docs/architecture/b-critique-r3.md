# Critique of the competing BOGO architecture

The competing design gets the hard parts mostly right. It parses lexically, keeps the exact tree in request extensions, uses exact egress transports, runs Lean on one thread, has Lean pick the bytes and key for verification, uses epoch-bound pause, keeps settlement frozen, rechecks at handoff, uses a sleep-aware clock, and builds the phone first against a stand-in. My revised design takes several of its points: preparing the send before the final check, the monotonic clock, store-before-`seen` on the phone, attaching concurrent identical retries, rejecting reused in-flight JSON-RPC ids, filtering `_meta`, the App ID prefix caveat, and an explicit tagged trace model. What follows is where it is still wrong, overbuilt, underspecified or missing part of the spec.

## 1. A full SQLite commit in front of every allowed call (§3.6, §4 row 4)

§3.6 says: "A state-changing security event computes its Lean transition, then commits corresponding state facts, audit and outbox obligations before exposing effects." Row 4 of §4 says an allowed call will "record attempt, prepare/send … record outcome". With `synchronous=FULL` and `fullfsync=ON` (which §3.6 asks for), every allowed call therefore waits for an `F_FULLFSYNC` before its upstream sees a byte. That buys no safety. An allowed call has no approval to record first, so nothing is lost if the attempt row is written alongside the send, as long as the result is held until the row is durable. The goal is "as fast as possible", and on a Mac `F_FULLFSYNC` is the expensive call ([SQLite `fullfsync`](https://www.sqlite.org/pragma.html#pragma_fullfsync), [Apple `fsync(2)`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)). The same rule also puts an fsync in front of every inbound duplicate check, because §3.7 has the receiver "atomically record (registrationGeneration, messageId, payloadIdentity) … before acknowledging", even for messages whose effect is idempotent.

**Fix:** write the allowed call's record in the same group commit as the send, and hold the result until it is durable. Record inbound messages only through the log entry their effect causes.

## 2. The durable journal and outboxes buy nothing that the audit can't already give (§3.6, §3.8, §6)

The design journals pending requests, endpoint outboxes, receipts and registration transactions in SQLite. Yet §5 says "No executable pending request is resumed". A journaled pending request can't run after restart, so its only use is telling phones afterwards what happened. That information is already in the audit, which both designs write before every effect: request created, approvals, denial, authorized, forwarded or not sent, and result. A phone-driven `sync` that the Mac answers from the audit restores History after any loss: a Mac crash, a lost `outcome`, a relay that dropped a message. It needs no new tables and no second ledger to keep consistent with the audit. The design names six kinds of table and never states which one wins when the journal and the audit disagree.

**Fix:** one append-only record, written ahead of effects, plus read-only reconciliation from it.

## 3. The schema rule hides valid tools, and no algorithm for it is given (§3.5)

"A schema transformation is accepted only if removing that property yields exactly the original accepted argument domain … An unsupported transformation is reported incompatible rather than advertised as working." Two problems.

- **It is stricter than safety needs.** BOGO doesn't validate arguments against the advertised schema. The upstream validates what it receives, which is the agent's exact arguments with the field removed. So an advertised schema that accepts more than the original can't widen what runs. The only property that matters is one-way: everything the original accepted, plus the field as a string, is still accepted. The exact-domain equality the design demands is unnecessary, and deciding it for schemas with `$dynamicRef`, conditionals and shared references is not something the design gives any method for.
- **Its failure mode breaks the spec.** "Reported incompatible" means an approve tool on an unmodified upstream is not offered as working, against SPEC §3.2 ("the combined tool list of every upstream") and the "any MCP server, unmodified" promise. The risk it guards against is a client that validates its own inputs refusing the field, which is visible and runs nothing.

**Fix:** widen the schema one way (add the property, open closed branches, `maxProperties + 1`, `propertyNames` ∪ key). Where no simple widening exists, still expose the tool, flag it in `bogo tools`, and ask the owner. This is SPEC §3.5's stated behaviour.

## 4. Whether the input decoder is inside the proof is ambiguous (§3.2, §3.3)

`step : State -> ValidatedEvent`, and "The bridge decoder rejects malformed bytes without issuing effects." The "kernel bridge" unit is Rust/C. If structural validation runs in Rust before Lean, then theorem 6 ("unknown, malformed … inputs cannot dispatch") depends on unproved Rust, and SPEC §3.18's "the decision logic … that run[s] inside BOGO [is] the same Lean code the proof is about" is only partly true. The event list is also too loose to check: `Control(authenticatedOrigin, controlMessage)` and `OwnerChange(ownerOperation)` are placeholders, and `Journal(event)` makes the kernel emit storage-shaped effects, which ties the proved code to a database layout.

**Fix:** decode the byte input in Lean, so `stepFfi : State → ByteArray → State × ByteArray` is total over every byte string. Write every input and output variant out in full. Keep persistence entirely in the shell.

## 5. "No intervening asynchronous queue" is not achievable with stock rmcp, and the alternative isn't specified (§3.4, §3.6 step 4)

`handoff(prepared, oneShotPermit)` is meant to "initiate the first write without an intervening asynchronous queue". An rmcp client request goes from `Peer` through an in-process channel to the service task, which calls `Transport::send` ([rmcp `service.rs`](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/service.rs)). The design's fallback ("the adapter owns the scheduling rather than calling a generic delayed `call_tool`") means taking JSON-RPC id allocation and response correlation away from the SDK. That is unspecified, and it conflicts with the spec's choice of `rmcp`. It also isn't needed. The linearization point is the final Lean check, and an in-memory channel hop with no I/O, no reconnect and no credential work adds no window that matters. My design states that hop openly.

## 6. An HTTP-parsing forwarder adds trusted code in the agent's path for no gain (§3.11)

The forwarder is "a bounded HTTP forwarding process … [that] exposes only the BOGO MCP/liveness paths and necessary methods". That is a new HTTP parser sitting on untrusted bytes. It has to carry bodies byte-exact, keep SSE and long requests open, and pass DELETE and the liveness stream. It is named by no project or library. Restricting paths adds nothing, because BOGO's agent listener serves only those paths and checks the token on every request, and owner control is on a 0600 Unix socket the container can't reach. A fixed-destination TCP forwarder (`socat` to one address and port) parses nothing and can't change a byte.

## 7. The restored-state promise has no mechanism (§5, "Restored old state")

"If registration/control freshness cannot be established, require fresh registration rather than accepting uncertain authority." Nothing in the design can find out that `state.sqlite` was restored from a backup. A restored file looks like any other, so the condition can never fire. Either drop the claim or name the mechanism. (Both designs treat a compromised Mac as out of scope. The claim is the problem.)

## 8. Underspecified where an implementer needs exact answers

- **§3.5** "Choose a deterministic justification property that does not collide" gives no rule. The name is part of the agent-facing interface and of what the core strips.
- **§6** describes configuration only as a table of meanings, with no concrete TOML, field names or units. Expiry, highlight formats, `require`, denial behaviour and filter actions all have to be guessed.
- **§3.7** lists envelope "types" by name only, with no payload fields, so the phone and Mac sides can't be built from it.
- **§9** gives no versions ("pin resolved versions … at integration"), Lean included, and names "strict DER" and "macOS Security trust validation" without saying which crate does which App Attest step.
- **§8** is a list of phases, not a dependency order. Step 4 alone holds the whole Lean kernel, the proofs, the bridge, the store and the coordinator.

## 9. Smaller points

- **§3.4 shim.** Parsing "envelope/header fields needed for protocol version, IDs, error responses and SSE framing" is fine, but it should be named as read-only and limited to the top-level `id` and `method`, so the shim can't become a second interpreter of `params`.
- **§3.1 signature input.** Adding `approverId || keyGeneration` to the signed message is harmless but redundant: each registration has its own key, and Lean picks the key. It is a second domain tag that every route has to reproduce.
- **§3.9 phone store as raw SQLite C.** This adds a C dependency and hand-written bindings to the phone for a handful of records that a file written atomically would hold. Not wrong, but heavier than needed.

## Responses to the critique of my design

| Point | Resolution |
|---|---|
| 1. Counter replay, boot-local `reqId` | Already handled in the supplied design: every request-scoped message carries the full 40-byte `reqId` (boot ID ‖ seq), and duplicates are dropped by `msgId`. No counter accepts or refuses any message. Added: neither end acks to the relay until the effect is durable. |
| 2. Same-boot withheld pause | Already handled: `pause` carries the per-agent `pauseEpoch`, which `agent_unpaused` advances to its log `seq`. |
| 3. Settlement not frozen | Already handled: `settled` is its own state, and every later vote is `ignored(settled)` (theorem 3a). |
| 4. Forward before slow work; clock | Already split into `authorized` → durable → `dispatch` (final check) → `forward`. **Conceded and adopted:** prepare the upstream connection in parallel with the log write and before the final check, so an upstream restart no longer wastes an approval. **Conceded and adopted:** a sleep-aware monotonic core clock (`W0 + CLOCK_MONOTONIC − M0`), because `Instant` on macOS stops during sleep ([`Instant`](https://doc.rust-lang.org/std/time/struct.Instant.html)). |
| 5. Endpoint recovery | **Conceded:** the phone now stores the request before `seen` and before the relay ack. **Conceded:** a crash could leave History stale. Fixed with `sync`, answered from the log, not with a Mac outbox. Remove already waits for the Mac's `revokedAck`. A lost final registration reply is already recovered (the `registered` envelope plus an idempotent resend of `regSubmit`). Added: discarding an unconfirmed registration sends `removed`. |
| 6. Docker `internal` | Already handled: nftables default-deny in the shared namespace. **Adopted:** `netpol` now drops every capability (`setpriv`) after loading the rules, so no process with `NET_ADMIN` remains. |
| 7. Schema augmentation; absent args | **Partly conceded:** the widenings now cover `maxProperties`, `propertyNames` and closed `$ref` targets, and the rule is stated. **Defended:** exposure with a flag, not hiding (critique §3 above). **Conceded:** absent `arguments` is now `Option JVal` through ingress, encoding (0x04 `opt(value)`) and forwarding. |
| 8. App Attest | Already handled (A7, category and bundle-version checks, development kept separate). **Adopted:** the App ID is configurable, and the prefix is checked against the profile. |
| 9. Proof provenance | **Conceded:** a tagged trace model by origin, with explicit A8 (owner origin) and A9 (clock), and the `extern` given a logical contract (A1) and a faithful-implementation duty (A6). Denials and pauses need no authenticity for the promise, because they only remove authority. |
| 10. Exceeds or weakens the spec | No idle timer exists (already). Default `allow` is now refused, so new tools can't silently open (type-level `DefaultPolicy`). Grouped review already decides one request. `tools/list` already errors when paused. No new model runner exists; the existing Approvals checks in apple-bridge-iphone are only updated so they stop naming removed files. **Adopted:** filtering and the secret scan now cover `_meta`, and the docs say field filtering isn't prose detection. The torn-line rule already moves only a final line with no newline, which was never acknowledged. That is a committed boundary, and complete corrupt lines stop startup. |

## Remaining disagreements

1. **Durable state on the Mac: one hash-chained append-only log vs a SQLite journal with outboxes and receipts.**
   *Position:* the log (JSONL, group commit, `F_FULLFSYNC`) is the only durable authority. The registry and the outcome lookup are caches rebuilt from it. There is no pending-request journal and no Mac outbox.
   *Best case:* pending requests can't run after a restart in either design, so journaling them is only there to tell phones the outcome afterwards. The log already holds every outcome, because it is written before every effect. A read-only `sync` answered from the log gives exact reconciliation after a crash, a lost message or a relay loss, without a second ledger that can disagree with the audit. One structure means one recovery rule (§3.9) and one thing for `bogo log verify` to check.

2. **Durable per-message receipts on the Mac.**
   *Position:* none. Every phone→Mac message is idempotent (an approval set, a denial only of `pending`, `seen`, `removed`, epoch-checked `pause`, `sync`). Dedup by `msgId` is kept in memory, and the relay ack happens only after the message's log entry is durable.
   *Best case:* a receipt table puts an fsync in front of every duplicate check and adds nothing. A replay after a crash gives the same result, because each message is safe to apply twice.

3. **When an allowed call's record is written.**
   *Position:* in the same group commit as the upstream send, with the agent's result held until it is durable.
   *Best case:* no approval exists to record first, so nothing is lost. The result still never reaches the agent without its record, and the allowed path loses a full-fsync wait in front of the upstream. That serves the "fast" goal without weakening "fail-safe".

4. **Tools whose schema can't be widened simply.**
   *Position:* expose them with the field at the top level, flag them `strict-client-risk`, and ask the owner.
   *Best case:* BOGO never validates against the advertised schema, and the upstream validates the stripped exact arguments, so a looser advertised schema can't change what runs. Hiding or refusing such tools breaks SPEC §3.2 and the "any MCP server" promise to guard against a visible client-side refusal. No algorithm decides exact domain equality for general JSON Schema.

5. **Where input decoding happens.**
   *Position:* Lean decodes the raw input bytes (`stepFfi`), so "malformed input never forwards" is proved, not assumed.
   *Best case:* SPEC §3.18 requires the running decision logic to be the proved code. Rust-side validation before the kernel is unproved code on the authorization path, and the other design's "bridge decoder" leaves that open.

6. **The handoff boundary.**
   *Position:* use stock rmcp `call_tool` on a prepared, connected handle. The one in-process channel hop to rmcp's service task is stated openly. The linearization point is the Lean `dispatch` step.
   *Best case:* removing the hop means replacing rmcp's id allocation and response correlation with custom scheduling the spec didn't ask for. The hop has no I/O, no reconnect and no credential work, so it opens no window in which an observable event could be missed.

7. **The sandbox forwarder.**
   *Position:* a fixed-destination TCP forwarder (`socat`), with all policy in nftables and in BOGO itself.
   *Best case:* an HTTP-aware forwarder parses untrusted bytes, must preserve them exactly, and restricts nothing BOGO doesn't already refuse (token on every request; owner control is only on a Unix socket). Less parsing code in the agent's path means less to get wrong.
