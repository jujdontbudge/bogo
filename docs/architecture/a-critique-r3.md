# Final critique

This critique concerns the supplied `other-design.md`, not an earlier version. Its strongest improvements are exact ingress carried in HTTP extensions, a dedicated Lean thread, frozen settlement, a shim liveness stream, registry replay, epoch-bound pause, and explicit disclosure of App Attest's indirect key binding. Those are retained. The remaining issues below have concrete counterexamples or implementation consequences.

## 1. Crash recovery can falsely say an executed call was not sent

**Sections 3.5, 3.9 and 5.** The design durably records `authorized`, sends the upstream call, and writes `forwarded` in a concurrent/later group commit. Recovery then interprets `authorized` without `forwarded` as “not sent (BOGO stopped).” This is unsound:

1. `authorized` reaches durable storage.
2. The transport writes the tool call; the upstream may execute it.
3. BOGO crashes before `forwarded` becomes durable.
4. Recovery announces that the call was not sent.

No provider bug or Mac compromise is needed. The missing record proves only that the record is missing. Recovery must report **outcome unknown** for any consumed intent that could have reached the sender, unless durable evidence positively establishes no handoff. It must never retry that intent. This correction is required with either JSONL or SQLite; changing storage engines does not transact with an unmodified upstream.

The associated claim that every effect has its record is also too broad for allowed calls: their first attempt record is written concurrently with the effect. If Scenario 15 requires a complete record of those attempts, the attempt must be durable before sending. Recording only before the reply reaches the agent does not cover a crash after the upstream effect.

## 2. The claimed immediate rmcp send is not the implemented boundary

**Sections 3.5 steps 2–3, 3.7 and risk “Gate ordering.”** The shell checks `dispatch`, installs a ticket, then calls rmcp `call_tool`, claiming there is no queue or await before first write. The published rmcp 3.10.0 source contradicts that mechanism:

- [`Peer::send_request_with_option_and_subscription`](https://docs.rs/rmcp/3.10.0/src/rmcp/service.rs.html#889-956) allocates the request ID and awaits `self.tx.send(PeerSinkMessage::Request { ... })`.
- [`StreamableHttpClientTransport`](https://docs.rs/rmcp/3.10.0/src/rmcp/transport/streamable_http_client.rs.html#2016-2145) is a `WorkerTransport`, has POST concurrency/queueing, and has optional expired-session recovery that retries ordinary POSTs.
- [`post_message`](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html#tymethod.post_message) returns a future; a custom serializer alone does not remove downstream connection or writer scheduling.

A one-shot argument ticket protects exactness and duplicate sends. It does **not** make the earlier authorization fresh at a later transport handoff. The decisive trace is `dispatch(valid) → SDK queue → expiry/revocation/cancel → first write`.

The correction is to stage the message through rmcp first, retain its actual assigned JSON-RPC ID, and perform final Lean authorization at the prepared sender's irreversible handoff boundary. All asynchronous preparation must precede that final check. The ticket binds the whole dispatch, not just `CallId → JVal`. A not-ready upstream may be rejected immediately; I concede that no settled-request reconnection-wait feature is necessary. The issue is placement of the gate, not whether to wait through outages.

## 3. A boot notice does not replace durable endpoint recovery

**Sections 3.10–3.13.** Mac delivery state is memory-only; a restart sends a boot notice. That can grey old requests, but cannot reconstruct every promised acknowledgement or outcome:

- The Mac commits a registration and crashes before delivering `registered`. The relay subsequently loses the message or its allowed maximum age deletes it. The phone has a durable pending registration, but the design does not specify a post-restart route that authenticates/replays the same committed result once the in-memory lobby transaction is gone.
- The Mac records self-revocation and crashes before `revokedAck`. The phone keeps retrying `removed`; after revocation its channel is no longer active. A duplicate authenticated cleanup message needs a narrowly scoped acknowledgement path, not either indefinite waiting or restoration of authority.
- A request is acknowledged `seen`, then the phone crashes before its inbox write is durable. The Mac has stopped delivery. The text says `seen` follows every request but does not specify the necessary store-before-ack transaction.
- A terminal/outcome message is lost while the Mac remains running. There is no authenticated state synchronization API to recover the current state. A boot notice cannot repair a same-boot loss.

This is an availability/recovery defect, not a claim that old signatures execute after restart. My design persists state changes and their delivery obligations together, requires durable endpoint acceptance before acknowledgement, and provides authenticated reconciliation. It does not revive executable requests after restart. An event log can implement all of this, but then it must include these obligations, not just registry replay. SQLite is the chosen implementation because it supplies one existing transaction mechanism for registry, audit and outbox facts; it is not a second competing authority. [SQLite's atomic-commit documentation](https://www.sqlite.org/atomiccommit.html) states its recovery/storage assumptions explicitly.

The relay may expire transport copies only while endpoints can reconstruct/retransmit still-required data. A relay TTL must never silently become approval expiry.

## 4. Schema augmentation has terminating and semantic counterexamples

**Section 3.7, “Justification field.”** Searching for a name not matched by *any* `patternProperties` can run forever for `patternProperties: {".*": ...}`. Searching nested definitions is additionally unnecessary for a top-level field. Inserting a property into closed branches does not handle these ordinary valid constraints:

- `propertyNames: {"enum": ["amount"]}` still prohibits the new field.
- `maxProperties: 1` still prohibits `{amount: 4700, justification: "..."}`.
- An object-level `const`, `enum`, conditional or negated subschema may change validity when the field is inserted.
- A schema allowing arbitrary additional keys may already assign upstream meaning to the selected name even when it appears nowhere in `properties`. Stripping it is not proven collision-free.

These are consequences of [JSON Schema's property-name, size and composition rules](https://json-schema.org/understanding-json-schema/reference/object), not hypothetical validator quirks. Reporting only one `$ref` case while continuing to expose the others is not faithful universal support. Adding justification to `required` also differs from SPEC §3.5's optional advertised field plus explicit admission-time missing-justification error.

I specify a terminating, explicitly bounded supported transformation with the projection law `augmented(a) iff original(removeReservedField(a)) and reservedFieldIsOptionalString(a)`, without sacrificing any legitimate upstream field. Anything not covered is an explicit compatibility blocker. A wrapper/metadata alternative needs the owner's decision because it changes the stated interface. This does not solve the universal-compatibility gap by fiat; it makes the gap honest.

## 5. The sandbox's loopback exception contradicts its DNS prohibition

**Section 3.17.** “Allow loopback” precedes “nothing else: no DNS (Docker's embedded resolver at 127.0.0.11 included).” An unrestricted loopback acceptance also accepts that address. [Docker documents](https://docs.docker.com/engine/network/#dns-services) that the embedded resolver is at `127.0.0.11` and forwards external lookups to host-configured DNS. A broad allow followed by a prose prohibition is not a policy.

Block the resolver address and outside DNS explicitly before any local allow, account for Docker's resolver NAT/rule ordering, or avoid the broad loopback allow. Establish the resulting namespace behavior with the spec-required bypass executable. I accept the simpler **fixed-destination TCP forwarder**; an HTTP parser in the forwarder is unnecessary. BOGO itself validates Host, Origin, token and endpoint, and the owner socket is not on that listener. The remaining disagreement is the DNS rule, not TCP versus HTTP forwarding.

## 6. Audit verification checks the wrong authorization instant

**Section 3.9 step 4.** It checks registrations at `authorized`; the core promise requires them still active at final dispatch. A revocation ordered after authorization but before a recorded forwarding must be evaluated at that final boundary. The audit needs dispatch evidence identifying the ordered registry/control context and frozen policy, not only the earlier threshold event.

The verifier also cannot treat every retained `approval` entry as a valid counted approval: the log intentionally includes malformed, revoked and ignored signatures. It must distinguish “invalid evidence correctly rejected” from “invalid evidence used to authorize.” Exact bytes, historical key generations, counted identities and consumption are the authoritative record. This is part of the crash/audit correction in disagreement 1 below.

## 7. The proof statement needs explicit authority and observation boundaries

**Sections 3.1 and 3.3.** “The adversary is any `List Input`” includes `configure`, `approverSet`, `agentSet`, `agentUnpaused`, session identities and timestamps, but the explanation later limits some of those to owner/runtime sources. That distinction must be represented in the theorem's trace assumptions or event capabilities. Arbitrary session opening is appropriate; arbitrary binding of that session to another authenticated agent is not an operation the agent gets.

Similarly, proving `now < expiresMs` for an adversarially supplied `now` does not prove real-world freshness. Signature verification is also not enough to authenticate Deny, Pause or registry controls. The route must establish their origin, and the proof must state where that fact enters. My revision separates malformed agent bytes from trusted owner commands and authenticated transport observations, while quantifying over every adversarial ordering. It explicitly lists truthful time, observed liveness, faithful sender/storage and compiler/FFI assumptions. No additional proof framework is proposed.

There is also an immediate implementation error: §3.1 exports Lean symbols named `bogo_core_step`, `bogo_core_decode_request`, `bogo_core_check_approval`, and §3.4 gives the C wrapper those same names with different signatures. They cannot both define the same external symbol. Use distinct `bogo_lean_*` exports and public `bogo_*` byte-ABI wrappers. The [Lean FFI reference](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) is the relevant interface contract.

## 8. Two smaller mechanisms should not be claimed as stronger than they are

**The completely unparsed shim (§3.15).** Forwarding original message bodies without re-encoding is correct. But synthesizing an error for *each pending JSON-RPC request*, negotiating protocol-version headers, and handling concurrent cancellation requires envelope awareness somewhere. A zero-parser shim must instead terminate the transport on failure and delegate those responsibilities; it cannot simply assert both designs. I keep limited envelope inspection while preserving argument bytes unchanged. Diagnostics remain stderr-only.

**Expiry (§3.5 and §5).** A wall-clock rollback before the scheduled deadline fires can lengthen a finite approval lifetime. A trusted Mac is not a clock that never undergoes normal correction. I check both the signed wall deadline and a sleep-aware monotonic deadline derived from the same configured lifetime, accepting only before both. This adds no default expiry and no new timeout. The phone countdown is advisory and reconciles to the Mac's terminal state.

## 9. Spec conflicts must not be silently resolved inside configuration

**Sections 3.1, 3.7 and 6.** The implementation adopts default-allow inheritance for newly discovered tools and native Link auth files outside TOML, then asks about both afterward. Each is a real specification conflict. Until resolved, ship approve as the safe default, do not silently authorize new tools through an ambiguous default, and label Link's storage integration as blocked under the literal credential-storage rule.

The generic startup path prohibition in §3.16 also rejects the design's own `LINK_AUTH_FILE` under `~/.bogo/upstreams/stripe/`. An upstream legitimately needs private credential state; the agent and exposed filesystem roots must not reach it. Enforce that access boundary, not a blanket rejection of every credential path passed to every trusted child.

The same precision applies to App Attest: validating a category and bundle version is not yet a policy identifying which BOGO-capable build is accepted. Apple's [current validation procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) includes those checks and says the App ID uses the actual App ID prefix, which is *usually*, not invariably, the team ID. The host currently uses development signing in [project.yml](/Users/johansardar/apple-bridge-iphone/ios/project.yml:12). Retain the accepted distribution/version policy as an owner decision, verify the actual prefix, and keep the app-mediated biometric-key assumption explicit. Neither a development fallback nor a fictional completed distribution is justified.

## Response to the critique of my design

Several objections target details already absent from the supplied latest `your-design.md`: it already has a concrete encoding grammar and event/effect/state sketch; HTTP-request extensions rather than a raw-body correlation table; unsigned immutable policy context; new-nonce requests after terminal retry consumption; no termination merely for description changes; allowed-call audit; and explicit no-resumption/liveness handling. These are agreements, not issues to keep litigating.

I additionally concede the fixed TCP forwarder, reject an outage-wait feature for settled calls, remove restored-backup special handling, and make the sender gate, message IDs, phone acknowledgement ordering, attestation checks, schema support boundary and dual-clock rule more concrete. I retain durable transactional recovery because registration/revocation/outcome obligations survive even though executable sessions do not. Limited shim envelope parsing is necessary for the promised error/header behavior and does not mean re-encoding arguments.

## Remaining disagreements

Each row is an independently decidable point. These are the positions of the revised standalone design; the counterexamples and sources above are the supporting case.

| Point | My position | Best case |
|---|---|---|
| 1. Crash classification and audit boundary | Persist an irreversible intent before sending; unresolved intent means outcome unknown, never presumed not-sent. Record attempts before effects and verify eligible registrations at final dispatch, not just authorization. | The concrete send-before-`forwarded`-commit crash trace produces a false no-action report. Only positive evidence supports not-sent; no local database can infer a provider effect from a missing later record. |
| 2. Actual final gate | Stage through rmcp to obtain its real ID and transport slot, then run the final Lean gate at a ready, one-shot sender. Refuse an unavailable upstream instead of waiting through reconnection. | rmcp 3.10.0's source contains an awaited channel and HTTP worker queue. `call_tool` after an earlier gate is not an immediate write. Exactness tickets do not close the freshness gap. |
| 3. Durable authority and delivery recovery | Use one SQLite transaction authority for registry, audit, immutable request facts and endpoint outboxes; durable receipt-before-ack and authenticated synchronization. Never resurrect executable sessions. | A boot notice cannot repair lost registration confirmation, revocation acknowledgement, same-boot outcomes or an inbox acknowledged before durable storage. A log-only alternative is acceptable in principle only if it implements these same durable obligations; the competing memory-only hub does not. |
| 4. Justification schema compatibility | Admit only transformations with an explicit finite algorithm and projection guarantee; report unsupported schemas and seek an interface decision. Keep the advertised field optional and enforce required justification at admission. | Catch-all patterns defeat name search; propertyNames/maxProperties/const and arbitrary additional keys defeat insertion. It is safer and more honest to state the universal-compatibility blocker than expose a subtly altered tool contract. |
| 5. Sandbox DNS isolation | No broad loopback exception that admits Docker's resolver; explicitly enforce resolver/DNS blocking in actual namespace rule order. Use the agreed fixed TCP forwarder. | Docker's `127.0.0.11` resolver forwards external queries. “Allow loopback” and “no external DNS” are not simultaneously enforced without an explicit exception or narrower allow. |
| 6. Proof and ABI authority boundaries | Separate adversarial messages from authenticated owner/control/lifecycle facts, state clock/storage/sender/FFI assumptions, and use disjoint generated/public C symbol names. | Otherwise the universal trace claim grants adversaries owner operations or proves freshness only against a fabricated time; duplicate exported symbols also prevent the stated ABI from linking. |
| 7. Expiry clock | Require both the signed wall deadline and its derived sleep-aware monotonic bound; never add expiry to a request lacking it. | Ordinary rollback must not extend a finite approval's lifetime. The earlier of those two checks fails closed without inventing a timeout or trusting the phone clock. |
| 8. Shim mechanism | Preserve raw bodies, but permit limited envelope/header inspection for IDs, errors, protocol headers and concurrent cancellation. | A truly unparsed byte pump cannot generate the promised correctly correlated per-request errors or infer JSON-carried negotiation data. Parsing the envelope does not require normalizing arguments. |
| 9. Unresolved specification/trust choices | Do not operationally assume default-allow for new tools, alternate credential storage or accepted App Attest builds before the corresponding owner decision. Scope path isolation to agent reachability, not all upstream credential use. | Those choices affect the explicit safe-default, credential-location and modified-app threat promises. Asking at the end does not undo a contrary executable configuration, and the blanket path rule contradicts Link's proposed auth-file location. |
