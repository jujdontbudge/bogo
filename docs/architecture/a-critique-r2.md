# Critique of the competing BOGO architecture

The architecture has useful concrete boundaries: a lexical JSON path, SDK transport adapters, a single Lean thread, an approval-verification hook called with Lean-selected bytes, and a phone-first stand-in using real delivery. Those are worth retaining. The problems below concern the actual supplied document, not an earlier version.

## 1. Replay handling loses valid messages and can target the wrong request

**Sections 3.11, 3.13 and 5.** Accepting only a counter greater than the last counter seen is not reliable mailbox delivery. Suppose a phone queues approval A with counter 10 and denial B with counter 11. The relay delivers B first. A is now permanently rejected even though it was never received. Retransmitting the stored A cannot fix this. An adversarial relay can force the problem, but ordinary reordering suffices.

Request-scoped messages also carry only a boot-local `reqId`. The receiver counter resets each boot. An old, previously undelivered denial can then target a newly allocated request with the same sequence number. Approval signatures resist this because the signed request contains the boot nonce; denials, `seen`, and `ended` do not have that protection. The phone says it deduplicates `(bogoId, bootSeq, reqId)`, but `bootSeq` is absent from these message payloads. A separate boot notification cannot safely assign a generation to a reordered request.

**Fix:** Bind installation, registration generation and full request identity into every relevant envelope/payload. Deduplicate by durable message ID, accepting unseen out-of-order messages. Use terminal state versions and reconciliation, not a global high-water counter. [RFC 9180 §9.7.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.3) explicitly leaves replay protection to the application; single-shot HPKE does not solve this.

## 2. A boot ID does not prevent a delayed pause from undoing unpause

**Section 3.11, Replay.** The claim that binding `pause` to the current `bootId` prevents re-pausing an agent after Mac unpause is false within one boot:

1. The phone sends pause P; the relay withholds it.
2. The owner pauses/unpauses the agent on the Mac.
3. The relay delivers previously unseen P during that same boot.
4. P has the current boot ID and a counter greater than the receiver's last value, so it pauses the agent again.

**Fix:** Mac unpause advances a per-agent control epoch. A pause is authenticated over agent ID and the epoch the phone reviewed. A stale epoch cannot override the later owner action. Counter deduplication alone also cannot reject first delivery of stale authority.

## 3. Settlement is not frozen in pending-and-retry mode

**Section 3.1, Approval and Denial.** The approval handler explicitly accepts both `pending` and `approved`, while the denial handler has no settled-state guard. This contradicts SPEC §3.8: once the requirement is met, the request is settled and later responses are ignored. In pending-and-retry, an approval can meet the threshold, then a late denial can change the result before a retry. This is not equivalent to revocation: revocation changes current registration eligibility, while a late vote must not reopen the settled decision.

**Fix:** Separate collecting votes from settled approval. After settlement, ignore further votes; at dispatch still check that enough of the settled evidence comes from currently active eligible registrations. A registration change may invalidate authority without reopening voting.

## 4. `forward` is decided before arbitrarily slow work

**Sections 3.5 and 3.7.** The sequence is Lean `forward`, durable group-commit logging, creation of an SDK ticket, then asynchronous `call_tool`. A request can be valid when Lean emits `forward` and expired by the time disk synchronization or connection preparation finishes. An already-observed cancel/revoke can similarly be logged as late even though no upstream byte has yet been handed off. This is not only the unavoidable race after network transmission begins; the design creates an avoidable, unbounded pre-send gap.

**Fix:** Prepare the transport first, durably consume authority, then perform the final Lean freshness/lifecycle check and non-queued handoff. The second check does not claim to undo a provider action or detect an unobservable disconnect. It prevents disk stalls, connection setup and observed earlier cancellations from extending usable authority. The same `step` function can implement this event; no second authorization implementation is needed. If the transport cannot take the handoff, authority stays consumed and the call is not sent.

The clock failure row also says a clock jump simply moves expiries. A wall-clock rollback must not lengthen a configured approval lifetime. Use a sleep-aware monotonic deadline and reject uncertainty; expiry must be checked at handoff even if the timer event was delayed.

## 5. Durable endpoint recovery is incomplete

**Sections 3.10–3.13 and 5.** Persisting the audit and rebuilding registries is a sound alternative to SQLite for authorization history. It is not yet a complete replacement for durable endpoint work:

- Request delivery stops after `seen`, but the phone section does not specify storing the inbound request before sending `seen` and acknowledging the relay. A crash can lose the phone's only copy while the Mac has stopped delivery.
- The phone retries until `outcome`; the Mac has no durable outcome outbox/reconciliation API. A crash after consuming a decision can strand a locally signed decision or leave History stale.
- Remove deletes channel keys once the **relay** accepts the message, while the UI claims to wait for the **Mac**. The relay is not the trust boundary. If it loses that message, the phone can no longer authenticate a retry to revoke itself.
- Registration claims interruption at any step means nothing registered, but the Mac writes the registry before the phone necessarily receives the final reply. This is a standard lost-final-ack ambiguity, not an all-or-nothing exchange.

**Fix:** Durable application receipts, retriable final registration acknowledgements, endpoint outboxes and authenticated synchronization. Pending rows need not resume as executable to be useful: they identify exactly which phone entries must end after restart. SQLite can keep registry history, audit and delivery obligations in one transaction without implementing separate checkpoint/replay protocols for each.

## 6. Docker `internal` is not BOGO-only isolation

**Section 3.17 and critique §12.** The claim that an internal network plus a fixed forwarder gives the complete restriction is contradicted by [Docker's own `--internal` documentation](https://docs.docker.com/reference/cli/docker/network/create/#internal): communication with the gateway IP and appropriately configured host services remains possible. That is precisely one of the destinations the document's bypass checker expects to be unreachable. A successful check on a host with no listening service is not proof the topology forbids that route.

**Fix:** Retain the internal network and fixed forwarder, but install an explicit default-deny policy in the agent network namespace before untrusted execution. A trusted setup container may hold `NET_ADMIN` briefly; it exits before the non-root, all-capabilities-dropped agent starts in that namespace. No privileged helper remains reachable by the agent. Block DNS forwarding and IPv6 too. The bypass executable observes the resulting restriction; it does not create the restriction.

## 7. Schema augmentation does not work for arbitrary MCP tools

**Section 3.7.** The two-name fallback collides if both `justification` and `bogo_justification` exist. Adding a property inside closed combinator branches does not account for `maxProperties`, `propertyNames`, overlapping `patternProperties`, whole-object `const`/`enum`, conditionals or dynamic references. A top-level sibling of `$ref` does not make a referenced closed object admit the new field. These are ordinary JSON Schema semantics, not exotic SDK behavior; [the official object reference](https://json-schema.org/understanding-json-schema/reference/object) describes the scope of `additionalProperties` and property-name/cardinality constraints.

**Fix:** Define the transformation invariant: removing the chosen BOGO property must yield exactly the original accepted argument domain. Use a deterministic collision-free name only where that invariant can be maintained. Otherwise report the incompatibility and ask whether a wrapper/metadata representation is permitted. Do not present a known-invalid schema as supported. Keep the advertised justification field optional as SPEC §3.5 says; enforce the per-tool requirement on admission.

The request type also replaces optional MCP arguments with a mandatory `JVal`, without explaining how absence differs from an explicit empty object. Preserve that distinction through ingress, encoding and forwarding.

## 8. App Attest validation and its claim are overstated

**Sections 0 and 3.11.** App Attest attests its own key and app-originated data; it does not directly attest the access-control flags of a separately supplied Secure Enclave approval key. The valid argument is that an accepted genuine app creates that key internally with the required ACL, then binds it into attested registration evidence. This assumption must be visible.

The validation checklist is also behind [Apple's current procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server), which includes `validationCategory` and `appVersion` in addition to certificate, nonce, App ID, AAGUID and key checks. Merely accepting both development and production AAGUIDs is not an accepted-build policy. The repository currently uses a development identity; that discoverable fact is not a decision to trust development registrations in normal BOGO.

**Fix:** Validate the complete supported Apple procedure and the accepted distribution/version evidence; separate development from normal registrations. State the genuine-app/key-enforcement assumption. The bundle/team values are already discoverable in [project.yml](/Users/johansardar/apple-bridge-iphone/ios/project.yml:3); the owner question is the acceptable distribution/trust policy, not those identifiers.

## 9. The pure-core proof still requires a faithful boundary

**Sections 3.1 and 3.3.** Moving approval verification inside Lean is a worthwhile simplification: Lean selects the exact registered key and its own request bytes. However, `any List Input` is not a sufficient provenance model. `configure`, `approverSet`, `agentUnpaused`, and authenticated denial/pause are not arbitrary agent authority. In the listed input type, denial and pause contain no evidence; their authenticity is supplied by the shell. Likewise, time and observed transport end events still come from the shell.

**Fix:** State a tagged trace model: agent input is arbitrary, network input is arbitrary until authenticated, and owner/transport/clock events have explicit origin assumptions. Include session open/close/cancel in adversarial lifecycle traces without claiming Lean detects real socket state. An opaque Lean `extern` needs a logical specification and a faithful runtime implementation; the attribute alone does not prove soundness. [Lean's FFI documentation](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) describes the code boundary, not its verification.

## 10. Several choices silently exceed or weaken the spec

- **Sections 3.6 and 6:** the concrete five-minute `session_idle` is an additional pending-and-retry lifetime, even though the owner has not chosen it. Keep the session-observability gap explicit; do not install an idle expiry while asking permission for it elsewhere. MCP permits server session termination, but does not mandate this value; [2025-11-25 transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) also warns that SSE disconnect is not normally cancellation. A fail-closed, non-resuming BOGO profile is defensible, but is a documented profile, not universal compatibility.
- **Sections 3.1 and 11:** default allow is applied to newly discovered tools even while precedence is an open question. That selects the weaker interpretation of SPEC's explicit safe-by-default rule before the owner answers.
- **Section 3.13:** Deny on a review of the oldest grouped request denies the entire group. SPEC says the owner decides a call as-is. Use one concrete request for both Approve and Deny; Pause is the specified agent-wide action.
- **Section 3.1:** `tools/list` continues after pause although SPEC §3.8.1 and the glossary say every request is rejected. Returning a clear paused error is neither an empty list nor confusing behavior.
- **Section 3.14:** adding a `bogo-model` runner to existing model checks is a new verification-plan artifact forbidden by the round rules. Encoding vectors as protocol artifacts and the explicitly specified bypass executable are enough here.
- **Sections 3.8 and 3.9:** a `Secret` type cannot stop an upstream from returning a credential inside a normal string. Also filter result metadata and duplicate representations, and omit/adjust output schemas when stripping required fields. Field filtering must not claim universal prose/binary secret detection.
- **Section 3.9:** moving any final invalid-JSON line aside and treating it as benign recovery can conceal corruption of committed history. Use a committed boundary or a transactional store; do not relabel arbitrary damaged history as an incomplete write.

## 11. Responses to the critique of my design

| Critique | Resolution |
|---|---|
| Interfaces too vague | Concede. The revision specifies event/effect variants, wire primitives, C ABI ownership, exact transport tickets, relay operations, durable receipts, config fields and registration phases. These are interface sketches, not a claim the implementation exists. |
| Raw ingress correlation overbuilt; SDK egress missing | Concede. Use the exact tree in HTTP request extensions, carried by rmcp's request parts. Use `ExactChildTransport` and `ExactHttpClient::post_message`; bind each one-shot ticket to the complete call, not arguments alone. [rmcp source](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport/streamable_http_server/tower.rs) and [client trait](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html) support these seams. |
| Static-key counter encryption | No current disagreement: the supplied `your-design.md` already uses single-shot authenticated HPKE. Retain it, with application replay handling. |
| Signed policy snapshot redundant | Concede under immutable per-boot policy. Remove it from the signed format; retain an immutable local request context for threshold/filter/mode and historical audit. |
| Session lifecycle excluded from proof; crypto evidence chosen by Rust | Clarify lifecycle provenance and adopt Lean-called verification over Lean-owned bytes. Truthful transport observation is still an explicit implementation assumption; adversarial lifecycle ordering is proved. |
| Second dispatch check is pointless | Disagree for the concrete pre-send expiry/cancel counterexample above. Keep it as an event in the same transition function and state its exact linearization limit. |
| SQLite pending durability buys nothing | Disagree for endpoint reconciliation and atomic audit/registry/outbox work, not because sessions can resume execution. Keep the store small and do not fsync pure duplicate reads. |
| Retry tombstones forbid a legitimate new identical call | Concede. While one logical request is pending/dispatching, retries attach. Once it is terminal, a later identical call may create a new nonce and requires a new approval. Lost-result retries may therefore ask again; no old approval can execute twice. Do not claim business-level deduplication. |
| No session end mechanism | Add a real shim liveness channel and a documented non-resuming wait profile. Do not invent direct-HTTP idle expiry. Keep silent abandonment/stateless retry compatibility as genuine spec questions. |
| Allowed calls absent from audit | Concede the scenario-15 reading. Record allowed attempts/outcomes too, without approval fan-out. |
| Phone stand-in postpones real delivery | Concede. Build the phone against a stand-in using real registration, HPKE, relay and direct APNs before the full decision daemon. |
| Firewall requires privilege | Concede the missing setup mechanism; specify a short-lived trusted namespace initializer and no agent capabilities. Do not discard enforcement, since Docker documents reachable gateway-host services. |
| Automatic ending on catalog changes | Concede for descriptions/presentation changes. Pin each admitted request's extraction and routing context; do not cancel it merely for metadata changes. A missing/unusable actual upstream fails closed at dispatch. |
| Software approver and stand-in conflated; DER signatures | The supplied design already separates the two development artifacts. Keep that separation and use CryptoKit raw 64-byte P-256 signatures directly. |

## Remaining disagreements

1. **Final authorization point.** My position: durably consume before sending, then recheck current lifecycle and expiry immediately at a prepared handoff. Best case: an expiry during fsync is observable and avoidable; emitting `forward` earlier does not make a later send fresh.
2. **Durable endpoint state.** My position: one SQLite transaction boundary for registry, audit and endpoint delivery/receipt obligations. Best case: recovery must reconcile phone state, self-revocation and registration even when old sessions cannot execute; a replayable log alone needs additional mechanisms to do that.
3. **Mailbox replay and control freshness.** My position: full generation-scoped identities, durable per-message receipts, terminal versions and per-agent unpause epochs. Best case: counters discard valid reordered messages, and a boot ID cannot reject a withheld same-boot pause.
4. **Reference isolation.** My position: explicit namespace default-deny rules in addition to an internal network/forwarder, installed before untrusted execution. Best case: Docker expressly allows gateway-host communication on an internal network.
5. **HTTP lifetimes.** My position: observable end signals and an explicit shim contract, with no unapproved idle timer. Best case: a guessed idle expiry changes the no-preset-expiry promise; no protocol mechanism can reveal a silent remote abandonment instant.
6. **Universal schema/interactive compatibility.** My position: fail closed on unsupported transformations/interactions and keep the necessary interface decision visible. Best case: simple property insertion is demonstrably not equivalent for all JSON Schemas, and silently excluding valid upstream tools does not fulfill “any MCP server.”
7. **App Attest trust boundary.** My position: validate current accepted-build evidence and describe the app-mediated key-protection assumption explicitly. Best case: attesting the App Attest key is not direct attestation of an independent approval key's biometric ACL.
8. **Default policy, pause and grouped denial.** My position: no new tools silently become allow while precedence is unresolved; pause rejects every agent request; a review decides one concrete grouped member. Best case: these preserve the spec's safe-by-default, every-request and exact-call wording without adding batch decisions.
