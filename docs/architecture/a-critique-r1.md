# Critique of the competing architecture

The design has useful concrete boundaries: one Lean thread, a small byte-oriented FFI, independent approver routes, standard HPKE, and an explicit inventory of the iPhone host changes. Its recognition that the filesystem server has no sharing-link tool is also correct. The problems below are about the stated mechanisms, not whether those choices could be repaired.

## 1. Exact number text is not preserved by the selected SDK path

**Sections 3.2, 3.7, 3.15 and 9.** The claim that `serde_json` with `arbitrary_precision` preserves exact number text is false. In the current [serde_json 1.0.154 deserializer source](https://docs.rs/serde_json/1.0.154/src/serde_json/de.rs.html#1027-1058), `scan_exponent` consumes either `E` or `e`, writes `e`, and inserts `+` when no exponent sign was present. Consequently `4.7E3`, `4.7e3`, and `4.7e+3` collapse to the same exponent spelling. Preserving arbitrary precision is not preserving lexical identity.

The body guard rejects duplicate keys but does not retain argument tokens. Once `rmcp` has produced its ordinary argument object, the lost spelling cannot be recovered. The shim repeats the problem, and conversion from the Lean value back into an SDK number can repeat it on egress. This directly contradicts SPEC §3.6, which requires exact number text, not merely equal numerical values.

**Fix:** retain validated raw numeric spans before SDK decoding in both the HTTP endpoint and shim. Pass a lexical tree to Lean and serialize its exact numeric tokens on the upstream boundary. The raw representation must remain correlated to the authenticated session and one internal call identity. SDK numeric objects may be convenience views, never the authoritative approval or execution representation.

## 2. Authorization is checked before an arbitrarily delayed effect

**Sections 3.1, 3.5 and 3.7.** The core emits `forward`, then the shell waits for a durable log write and later invokes the upstream SDK. Between those operations, the request can expire, its session can close, or the approver or agent can be revoked. Serializing `step` calls does not serialize the delayed upstream effects. A previously returned `forward` is effectively a bearer permission in an effects queue.

There is a second expiry gap: an expiry timer is an event, not proof that an approval processed first has a current timestamp. The explicit approval checks do not require `now < expiresMs`; relying on the queued `tick` cannot establish theorem 4. The theorem's desired result must be implemented at the decision point.

**Fix:** prepare upstream transport first; durably reserve/consume the authorization; then make a final Lean freshness transition under the same dispatch gate that orders revocation, cancellation and session endings. The gate must cover handing the exact prepared bytes to the one-shot sender, without an intervening async queue or reconnect. Expiry is checked from trusted current time, not just timer delivery. State the linearization point as authorization to forward, not the provider's later physical effect. A crash after reservation sacrifices the action rather than replaying it.

## 3. Durable audit and mutable registry can disagree after a crash

**Sections 3.5, 3.9 and 6.** Writing an audit event before an effect does not make multiple durable files atomic. Example: `agentPaused` is logged and synced, then BOGO crashes before updating `agents.json`. Startup loads `paused=false`; the agent is accepted despite a durable pause. Registration/revocation has the same split-brain risk. The description does not replay registry events at startup, reconcile them with snapshots, or define a transaction joining the files.

Keeping live requests in memory is not itself unsafe if a restart ends every session. The missing piece is a complete, crash-consistent recovery authority for registry state, settlements, and acknowledgements. A boot notice can grey a phone's entries but does not reconcile partially applied Mac state changes.

**Fix:** one transactional state/audit/outbox store, or a fully specified event-sourced recovery process in which the append-only log is authoritative and snapshots carry replay positions. Separate atomic renames are not a substitute. [SQLite's atomic-commit documentation](https://www.sqlite.org/atomiccommit.html) describes the transaction boundary available without inventing a multi-file commit protocol.

## 4. Boot-local request IDs and global counters break message safety and recovery

**Sections 3.10–3.12.** Two concrete traces are missing:

1. An old authenticated denial `{reqId: 1, note: ...}` remains in a relay mailbox. BOGO restarts, its core sequence begins again, and a new request has `reqId: 1`. The envelope authenticates the installation and approver but not a boot/request generation, and the receive high-water counter resets each boot. The old denial can terminate a different new request. A valid approval cannot execute that new request because its signature binds request bytes, but a denial, acknowledgement or outcome must not be misassociated either.
2. The relay delivers phone message 12 before message 11. Accepting only counters greater than the last seen permanently discards 11, even if it was a distinct valid decision. Retrying the identical durable envelope never repairs this. The relay is explicitly allowed to reorder and delay traffic.

The stated boot ID on `pause` prevents cross-boot replays, but not a delayed, previously undelivered pause arriving after an owner unpause within the same boot. Unpause needs to invalidate older pause authority, not merely rely on an envelope's relative arrival order.

**Fix:** every request-scoped message binds installation, service generation and full request identity. Persist per-message receipts, deduplicate exact message IDs without discarding unseen lower IDs, and version request state. Pause binds the agent's current control epoch; unpause advances it. HPKE supplies neither general replay protection nor mailbox ordering: [RFC 9180 §9.7](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7) explicitly leaves these to the application.

## 5. A settled approval is still mutable, and retry identities disappear

**Sections 3.1 and 4 S3.** In pending-and-retry mode the request remains `approved`, additional approvals are explicitly accepted, and the denial rule has no settlement guard. A later denial can therefore undo a requirement already met, contrary to SPEC §3.8: once settled, later responses are ignored. Current registration and freshness still need checking before forwarding; those are different from accepting another decision.

After the first retry executes, the design deletes its matching record and says any later retry creates a fresh request. This does not reuse the original approval, but it makes a lost-result retry indistinguishable from a genuinely new identical business action and can solicit another approval for an accidental duplicate. The spec does not supply a retry discriminator.

**Fix:** retain session-lifetime consumed/ended matching records; return the recorded terminal outcome without another execution. Separate immutable decision settlement from subsequent dispatch eligibility. Ask how an intentional identical new action should be expressed rather than choosing implicit reapproval. My original design also needed a sharper statement that readiness is not final dispatch authority.

## 6. A new idle deadline contradicts the no-default-expiry contract

**Sections 3.6, 6 and 11.** `session_idle = "5m"` is an added lifetime rule. A pending-and-retry request has no open response stream after its initial pending response, so it can be ended while the phone is offline even though neither the agent nor owner ended the logical session. Asking the owner to confirm the timeout later does not make it valid to build it into the architecture now. The common rules explicitly prohibit invented time values.

The design is right that [MCP 2026-07-28 removes protocol sessions](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http). Call-scoped wait mode and a shim-owned session are sensible supported cases. Neither that fact nor an SDK default justifies silently adding a no-activity expiry. An unobservable client death must be a stated compatibility limitation or a spec decision.

## 7. Justification augmentation is neither collision-safe nor schema-safe

**Section 3.7.** Choosing `bogo_justification` when `justification` exists fails if the upstream already uses both names. Removing that second field would change the actual upstream call. Adding a property to an arbitrary schema also needs handling for composed schemas, references and closed objects, not just inserting `properties` and `required`. For example, an `allOf` branch with `additionalProperties:false` can reject a property added outside that branch. [JSON Schema's object documentation](https://json-schema.org/understanding-json-schema/reference/object#extending-closed-schemas) explains that boundary.

**Fix:** select an actually nonconflicting extension name and validate the original arguments after stripping only that field. Preserve all original constraints through a schema-aware transformation. If a universal extension cannot be represented faithfully, surface the spec conflict; do not silently replace an upstream field or promise compatibility with every schema.

## 8. App Attest and registration completion are overstated

**Sections 0, 3.11 and 5.** App Attest attests its own key and app evidence. It does not directly certify an arbitrary Secure Enclave approval public key's `biometryCurrentSet` ACL. The actual trust argument is that an accepted genuine app version creates the approval key internally, binds its evidence to a fresh challenge/transcript, and has no supplied-key registration path. That distinction belongs in the assumptions, not only an assertion that the ACL is "proven".

The current [Apple validation procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) also includes validation category and app version checks. A wrapper around `appattest` must establish coverage of all required fields instead of assuming its older list is sufficient. Development and production acceptance need explicit separation; the sample config accepts both without a normal-registration boundary.

Finally, "interruption at any step means nothing is registered" is impossible after the Mac commits registration but its final acknowledgement is lost. The stated sequence also sends `registered` before describing the durable write. Final messages must be sent after commit; retransmission of the same transaction must recover a one-sided commit idempotently.

## 9. The reference network policy is not established by an internal bridge

**Section 3.17.** A Docker internal network plus a dual-homed `socat` container restricts routing but is not a complete policy covering host-local addresses, DNS forwarding, IPv6 and privileges. A bypass executable describes desired observations; it does not install the restrictions that make them true. [Docker's bridge documentation](https://docs.docker.com/engine/network/drivers/bridge/) explicitly describes host access and the difference between same-network connectivity and external routing.

**Fix:** specify default-deny rules in the agent namespace, permit only the fixed MCP forwarder address/port and established responses, and drop network-admin/raw capabilities before running the agent. No Docker socket or credential-bearing mounts. Also explicitly constrain the filesystem upstream's allowed roots so an allowed read cannot retrieve BOGO's credentials on the agent's behalf. The [filesystem documentation](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) describes legacy client roots replacing command-line roots.

## 10. Scope, completeness and factual corrections

- **Section 3.13:** Deny on a group denies every member, whereas review presents only its oldest member. This is an unrequested bulk action; the spec says the owner decides one exact request. Keep grouping visual and both decisions scoped to the reviewed member. Pause already supplies the specified broader control.
- **Section 3.13:** Macs includes remove, but no removal message or offline acknowledgement semantics are defined. Removal must at least disable local signing immediately; any remote revocation claim needs authenticated delivery and acknowledgement.
- **Section 3.14:** Adding a new `bogo-model` check entry and vector runner is a verification-plan addition forbidden by the common rules. Cross-language protocol vectors themselves are legitimate interface artifacts; a prescribed check lane is not.
- **Section 3.9 / S4:** Logging and synchronizing every allowed call adds an unrequested blocking cost and data collection. The spec requires every protected attempt to be audited. Do not force unrelated allowed calls through durable approval bookkeeping.
- **Section 3.9:** Automatically treating any invalid final JSON line as a torn write can label corruption as benign recovery. A known incomplete transactional append and an unexplained malformed committed event must be distinguished. Never repair authoritative history by silently discarding a complete corrupted record.
- **Section 3.9:** A `Secret` type cannot alone prevent a credential reflected into an upstream error, result or plain string from reaching logs. Keep credential-boundary sanitization and explicit result/error handling.
- **Section 8:** Requiring deployed relay, full real registration and APNs before beginning BogoKit is unnecessary and conflicts with the specified phone-first work against a stand-in. Begin the pure module and host edge after the encoding/port contract; attach real transport later.
- **Sections 4 S1 and 10:** A Link SpendRequest is not automatically a completed $47 payment. Current [Link source documentation](https://github.com/stripe/link-cli/blob/main/README.md) makes `--test` a SpendRequest mode, says Link Pay Tokens do not support it, and describes live-only checkout commands. Keep real result semantics and establish the actual testmode tool rather than relying on the illustrative `create_payment_link` name.
- **Section 10, Scenario 13:** Correctly identifies a gap I missed: the official filesystem server has no public-link sharing tool. I carry this question into the revised design rather than pretending that scenario is already realizable with the selected upstream.

## Remaining disagreements

| Point | My position | Best case |
|---|---|---|
| Exact argument transport | Retain lexical JSON through ingress, shim, Lean and upstream serialization. | The actual `serde_json` source demonstrably rewrites exponent text. This is a correctness boundary, not stylistic caution. |
| Dispatch authorization | Prepare transport, durably consume, then perform a final serialized Lean freshness/handoff check. | A queued `forward` can outlive cancellation, revocation or expiry while its log write waits. |
| Durable authority | Use one transaction for registry/state, audit and delivery work. | Otherwise a logged pause or revocation can be lost from the state loaded after a crash; a specified event-sourced replay could also solve it, but the submitted design has none. |
| Message identity and replay | Bind full generation/request IDs, deduplicate durably, allow out-of-order unique delivery, and epoch-bind pause. | Boot-local IDs can target the wrong call, and high-water rejection can make a retried decision permanently undeliverable. |
| Retry settlement | Freeze decision settlement and retain consumed matching records for the session. | Late responses must not alter a settled requirement; retrying a lost result must not silently become another business action. The new-identical-call distinction needs a spec decision. |
| Session lifetime | No invented idle timeout. | Phone offline plus pending-and-retry must not acquire a preset expiry merely because the response has already returned. |
| Registration evidence | Genuine-app-bound key creation is an explicit assumption, not direct attestation of the approval key's ACL; final registration is idempotently recoverable. | Apple's API exposes app/key evidence, and a lost final acknowledgement cannot undo a completed durable write. |
| Group actions and allowed-call audit | Decide only the reviewed member; do not impose protected-call audit synchronization on allowed tools. | Both avoid unrequested behavior and keep the smallest implementation satisfying the spec. |
| Sandbox | Enforce an explicit namespace policy and safe filesystem roots in addition to Docker topology. | The agent is adversarial, and a desired bypass-check result is not a network enforcement mechanism. |

HPKE itself is no longer a disagreement: the revised design adopts authenticated HPKE with independent per-message contexts and application-level replay handling. The filesystem scenario gap, dedicated Lean thread and byte-oriented FFI are also accepted. No critique-of-yours.md was present in this first round.
