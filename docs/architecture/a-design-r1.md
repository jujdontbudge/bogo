# BOGO: Architecture

Status: 2026-11-14. Built from SPEC.md.

## 0. The shape

BOGO is one Rust service on the owner's Mac, exposing an authenticated MCP HTTP endpoint to named agents and holding private MCP connections to unmodified upstreams. A small executable Lean 4 kernel owns effective policy, exact request encoding, approval settlement and authorization consumption; Rust supplies validated transport, cryptography, durable storage and one-shot effects. The iPhone approver is an independent Swift package mounted as the BOGO tab inside Apple Bridge, with its own Secure Enclave keys, registration, review, storage and encrypted mailbox connection. BOGO's separate relay carries opaque messages, and the Mac sends APNs directly. State, the append-only audit and delivery work share a local transaction boundary. Crashes end old sessions, delivery resumes from durable outboxes, and possibly sent upstream calls are never replayed. The Docker reference environment permits only BOGO and contains no upstream credentials. The design distinguishes what can be guaranteed from unavoidable boundaries: unmodified upstreams do not offer atomic commit with BOGO, silent client abandonment is not always observable, and App Attest authenticates app-originated evidence rather than directly certifying a separate key's biometric ACL.

## 1. Runtime picture

```text
Reference Docker environment                    Owner's Mac
  untrusted named agent
     | HTTP, or stdio -> bogo-shim
     v
  fixed-destination MCP forwarder ------------> BOGO MCP edge
  namespace default-deny network policy             |
                                                   v
  owner terminal -> bogo CLI -> owner-only socket -> coordinator
                                                   |       |
                                              Lean kernel  transactional store
                                                   |       state + audit + outboxes
                                             one-shot sender
                                              /          \
                                      local processes   remote MCP upstreams
                                      credentials only on BOGO's side

  BOGO encrypted delivery <----> bogo.eilmer.si:<own port> <----> BOGO Swift package
                                 own relay/service/state        inside Apple Bridge
  BOGO direct APNs sender --------------------> Apple APNs ----> host notification edge
                                                               |
                                                   BOGO Inbox / History / Macs
                                                   exact review + Face ID key
```

The Mac units are modules in one service, not separately deployed services. Local upstreams, the optional shim, the relay and the existing iPhone app run separately. The forwarder is neither an approval service nor a general proxy. Apple Bridge's Mac gateway, relay, registration and APNs path are absent from every BOGO dependency.

## 2. Units

| Unit | Language | Owns | May depend on | Must never depend on |
|---|---|---|---|---|
| Authorization and encoding kernel | Lean 4 | Canonical values, request encoding, policy resolution, lifecycle, threshold counting, consumption, proofs | Lean standard library and explicitly modeled facts | Network, database, MCP SDK, UI |
| Kernel bridge | Rust and small C ABI | Runtime initialization, buffer ownership, one dedicated Lean thread | Compiled Lean library | A second authorization implementation |
| MCP edge and shim | Rust | Agent authentication, raw JSON capture, discovery views, call/session lifecycle | rmcp, HTTP runtime, coordinator ports | Credentials, direct upstream dispatch |
| Catalog and configuration | Rust | Discovery, names, schema augmentation, typed TOML snapshots | MCP discovery port, domain values | Agent-authored policy or identity |
| Coordinator | Rust | Ordering security events, durable transitions, dispatch gate | Kernel bridge, store, crypto verifier, effect ports | UI summaries as authority |
| Store and audit | Rust and SQL | State, registry history, attempts, hash chain, outboxes and receipts | SQLite and canonical event encoding | Network execution authority |
| Upstream adapter | Rust | Processes, remote transport, credential injection, lexical serialization, filtering | rmcp, secrets provider, private one-shot dispatch input | Agent-selected URLs or phone rendering |
| Cryptography and registration | Rust | Signature verification, numeric comparison, App Attest validation, key bindings, HPKE | Crypto libraries, Apple trust anchor | Relay claims of identity |
| Approver delivery and APNs | Rust | Route fan-out, reconciliation, opaque delivery, direct push | Registry, encrypted outboxes, HTTP | Authorization rules or upstream calls |
| Relay | Rust | Opaque mailbox persistence and rendezvous | Its own TLS, HTTP and SQLite | Decryption, upstream/APNs credentials, Lean |
| BOGO iPhone package | Swift | Exact decoding, review, keys, registration, Inbox/History/Macs, outboxes | Apple frameworks, independent local storage | Host identity, pairing, approval jobs or relay |
| iPhone host edge | Swift | Tab mounting, push-token fan-out, notification routing, old-feature retirement | BOGO facade and unrelated host features | Constructing approval bytes or accessing BOGO keys |
| Owner CLI and launcher | Rust | Setup, lifecycle, agent/approver commands, cancellation, logs | Owner-only local control socket | Agent HTTP or remote owner-control API |
| Reference sandbox | Container configuration and Rust | Network restriction, fixed forwarder, prescribed bypass checker | Docker and fixed BOGO endpoint | Docker socket, credential mounts, arbitrary egress |

## 3.1 Exact values and the executable Lean kernel

### Immutable request

The signed request contains encoding version; installation identity; stable upstream identity and exact tool name; complete arguments; optional justification; display hints; stable agent identity and owner-assigned name; unverified client name; session and service generation; unique nonce; creation time and optional expiry; and a policy-context identity binding the eligible approver key generations, threshold, denial behavior, mode and output filtering. The added identifiers prevent reinterpretation across installations, restarts and registrations; they add no new approval feature.

```text
Json = Null | Bool | String(unicodeScalars) | Number(validJsonNumberToken)
     | Array(ordered values) | Object(sorted unique key/value pairs)
```

Object keys use UTF-8 byte ordering, not locale order. Duplicate decoded keys, invalid UTF-8, lone surrogates, malformed numbers, overflowing lengths and unsupported structural bounds are rejected before ordinary maps erase information. Strings are not Unicode-normalized. Number tokens retain every character: `4700`, `4700.0`, `4.7e3`, `4.7E3`, `4.7e+3` and signed zero remain distinct as applicable. Equivalent string escapes and object-member order describe the same canonical value; injectivity is over that defined value domain, not every textual JSON document. Missing MCP arguments remain distinct from an explicit empty object, and absent justification from an empty string.

Lean defines a tagged, length-prefixed binary encoding with a magic value, version, fixed field order, distinct constructor tags, specified integer widths/byte order and explicit optional-field tags. Decoders consume all input and reject noncanonical forms. The theorem `decode(encode(r)) = r` establishes injectivity on valid representable requests. Size limits produce rejection, never truncation.

Only compiled Lean produces production approval-request bytes. Rust passes the lexical tree through a bounded ABI; Swift strictly decodes the received bytes and signs those original bytes. Lean-generated vectors are interface artifacts covering canonical values and rejected representations, not a second format definition.

### Interface and state

```text
encodeRequest : ValidRequest -> EncodedRequest
step          : State × Event × VerifiedFacts -> Result(State × Effects)
finalHandoff  : State × ReservedRequest × CurrentFacts -> Reject | Dispatch
```

The executable functions in the proof are the ones compiled to C and linked into BOGO. Lean validates the bridge input codec before applying transitions. The Rust crypto boundary constructs verified facts tied to exact bytes, public keys and registration generations; an agent cannot supply an `approved=true` flag. The core owns the rules for interpreting and counting those facts. A separate local owner input type cannot be constructed through the MCP or relay edge.

```text
Pending -> SettledApproved -> Reserved -> Sent -> Completed
   |              |              |         \-> OutcomeUnknown
   |              |              \-> NotSent
   +--------------+-> Ended
   \-> Denied

Invalid admission -> Rejected
```

`SettledApproved` freezes the decision: subsequent approval/denial responses are late and cannot change it. It is not ongoing permission to execute. Dispatch still requires an open session/call, unexpired request, unpaused/unrevoked agent and sufficient currently registered eligible keys. Revocation may end a settled request; it never reopens voting or transfers its authority to a replacement key.

The kernel resolves per-agent policy, strips only the catalog-designated justification field, enforces required justification, admits within the per-agent pending limit, binds request identity, counts distinct approvers, settles any-of/k-of-n, applies denial behavior, and orders cancellation, pause, revocation, expiry and consumption. It rejects impossible thresholds before waiting. Default veto means a valid denial while pending settles immediately; without veto, denied approvers cannot contribute, and an unreachable threshold ends without forwarding. Repeated responses from one registered approver count once. Re-registration changes key generation and never validates an old signature.

Pause denies pending requests and prevents every agent request, including discovery, until the owner unpauses on the Mac. Agent revocation is independent of pause and cannot be undone by unpause. Catalog or policy changes cannot reinterpret an immutable pending request.

### What is proved / What is assumed

For arbitrary adversarial agent inputs and arbitrary delivery order, the Lean statements establish:

- Protected dispatch requires enough distinct, eligible and currently registered approvals over that exact request.
- Arguments, justification, agent, session, nonce and policy context cannot change under an approval.
- Each request authorizes at most one dispatch.
- No dispatch follows an observed ending, denial, pause, relevant revocation or expiry already ordered before its final handoff.
- Any-of, k-of-n, denial policy and per-agent overrides obey their definitions.
- Malformed inputs and unsupported encodings cannot authorize execution.
- Allowed dispatch corresponds to effective allow policy, not a Rust bypass.
- Encoding is deterministic and injective on its defined domain.

Explicit assumptions are signature unforgeability, collision resistance, secure HPKE/randomness, faithful signature verification, correct biometric key enforcement, genuine accepted app behavior, truthful transport/time observations, correct storage and effect delivery, compiler/runtime/FFI correctness, an uncompromised Mac and phone OS, sandbox isolation and upstream access controls. Cryptographic hooks are narrow assumptions, not axioms asserting the desired complete result. The proof does not establish delivery, human judgment, provider behavior, exact-once external completion or instant detection of a silent client timeout.

The bridge has a small byte-buffer API for initialization, stepping, encoding/decoding and freeing results, plus an ABI version. One thread initializes Lean and owns all its objects. Only the bridge handles Lean reference ownership and unsafe runtime calls. This follows the [Lean FFI requirements](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/); toolchain and library are built together.

## 3.2 MCP, identity, catalog and credentials

### Lossless MCP boundary

BOGO uses `rmcp` for required MCP framing, discovery and transport integration, but raw tool-call bytes are authoritative. The endpoint captures the body before SDK decoding, rejects ambiguous envelopes and duplicate keys at every depth, and produces a lossless lexical tree. Server-minted call identity correlates this capture to the authenticated agent, session and typed JSON-RPC ID. Reusing an in-flight ID is rejected rather than overwriting another capture.

The shim has the same lexical-preservation rule. It may adapt protocol envelopes but cannot round-trip tool arguments through ordinary number objects. Upstream serialization emits the immutable kernel-selected argument tree and original number tokens, excluding only BOGO's justification. Both ingress and egress sit behind one custom transport boundary; no other SDK `call_tool` path may bypass it.

This is required by actual library behavior: [`serde_json::scan_exponent`](https://docs.rs/serde_json/1.0.154/src/serde_json/de.rs.html#1027-1058) lowercases exponent markers and inserts a missing positive sign even with `arbitrary_precision`. [`RawValue`](https://docs.rs/serde_json/1.0.154/serde_json/value/struct.RawValue.html) can retain source syntax, but does not validate duplicate keys by itself. [`rmcp` transport adapters](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport.rs) confine the required integration without modifying upstream servers.

Only defined execution inputs are forwarded. Unknown tool-call extensions that could change execution are rejected or included in the exact request format before support is added. Transport IDs and progress correlation are generated/mapped by BOGO, not alternate unsigned action inputs. Non-tool resources, prompts and arbitrary upstream URLs are not exposed as policy bypasses. Owner-controlled filesystem roots cannot be replaced by agent roots. A required upstream interaction that changes execution inputs needs a newly complete protected request; unsupported interaction is rejected, not silently performed. Universal compatibility with interactive MCP tools remains a stated spec question.

### Agent authentication and sessions

`bogo agent add` creates a stable identity, owner name and random bearer token. BOGO stores only its verifier hash and prints the token once. Every HTTP request is authenticated, even when it carries an existing session ID. The session is bound to that agent; MCP `clientInfo` is always unverified display data. The endpoint validates Host and Origin and binds only to required local interfaces. Owner control is a separate permission- and peer-checked Unix socket, never an HTTP or relay route.

A session is an observable authorization connection, not merely an agent token. Restart creates a new service generation and ends all old sessions before admission reopens. Supported lifecycle forms are explicit:

- With the BOGO stdio shim, one shim process owns one authorization session. Stdin EOF, explicit cancellation and observed process/transport termination end the corresponding work. The shim keeps diagnostics on stderr and closes its HTTP-side session on normal exit.
- Initialization-era direct HTTP binds a server-issued MCP session to one agent. Explicit deletion and observed supported session termination end it; observed wait-call cancellation ends that call. An SSE interruption alone is not universally a logical session ending.
- [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) removed protocol sessions. Direct wait calls can use request-scoped authorization sessions. Pending-and-retry cannot use an agent token or pooled TCP connection as a substitute for cross-request session identity; it requires the shim or an agreed explicit session contract.

No idle timer supplies an undisclosed default expiry. If a client silently abandons a call without closing/cancelling, BOGO cannot infer that fact from silence. Unsupported session combinations fail closed with a model-readable explanation; they are not represented as complete fulfillment of universal compatibility. Network loss ends work when the chosen transport contract observes it, not at an unknowable remote instant.

### Policy and discovery

The owner configures arbitrary local/remote upstreams in `~/.bogo/bogo.toml`; secrets are references. Discovery follows pagination, retains original descriptions and schemas, and handles supported tool-list changes. Aliases cannot contain `__`; an explicit mapping resolves `<upstream>__<tool>` without guessing splits. Collisions, invalid names or protocol length limits produce visible incompatibility, never routing to a different tool.

Per-agent overrides replace policy and eligible approvers; other values inherit the tool record, then defaults. Validate thresholds, unique identities, field paths, formats and secret references. Broken configuration cannot fall back to allow. Configuration is immutable until restart; no live reload is needed. Newly encountered tools are approve by default. The relationship between that rule and an owner-set default of allow is unresolved; until clarified, discovery cannot silently allow a new identity. Tool-contract changes end affected pending requests.

Denied tools are hidden by default for that agent; an owner setting may expose them, but calls remain rejected. Approve tools advertise an optional BOGO justification property with a deterministic genuinely nonconflicting name. A required-justification policy is enforced on calls with the requested explanatory error. Only that chosen property is removed, and remaining arguments must satisfy the original schema. Closed schemas, references, compositions and pattern properties require a faithful transformation. A wrapper or metadata fallback would change the specified interface and needs a spec decision; an unrepresentable schema is reported as incompatible, not falsely supported.

### Private upstream connections

Local upstreams are supervised unmodified child processes with explicitly constructed minimal environments and private stdio. Remote upstreams use configured URLs and credentials. The agent controls neither launch commands nor URLs, headers or redirects. Credentials never follow a redirect to a different authority without an owner-configured rule. Reconnect retries initialization/discovery, not possibly sent tool calls. An unavailable upstream is prepared before authorization is consumed; failures cannot trigger hidden re-execution.

`~/.bogo` is owner-only. `secrets.toml` is an owner-owned regular file with owner-only read/write access, checked against symlink/ownership surprises and excluded from agent mounts and filesystem-upstream roots. No upstream credential is written to Mac Keychain. Credential-consuming child processes necessarily receive private credentials on BOGO's side; the agent does not. Secret wrappers suppress accidental formatting, and errors/results are separately prevented from reflecting known connection credentials into logs or agent output. Arbitrary native rotating credential formats need explicit handling rather than pretending that any CLI auth cache is TOML.

## 3.3 Durable coordination and dispatch

One coordinator orders security events; parsing, crypto, network preparation and push delivery run outside it. Results carry their registration/session generations so stale work is rejected. No phone wait holds a database transaction or blocks another upstream's transport.

SQLite stores authoritative state, audit and delivery outboxes together. One writer uses transactions, foreign keys, WAL and deliberately configured durable synchronization, including appropriate macOS full-fsync/checkpoint settings. [SQLite's atomic-commit account](https://www.sqlite.org/atomiccommit.html) and [pragmas](https://www.sqlite.org/pragma.html) define the storage assumptions. A process lock prevents a second dispatcher against the same installation.

For one security event, registry updates, request state, audit append and required delivery work commit together. The kernel's proposed transition becomes externally visible only after commit; failure stops effects and restores the committed state or terminates the service. A network acknowledgement means durable acceptance, not merely receipt in memory. Recovery derives from the committed store, not potentially inconsistent JSON snapshots.

### One-shot forwarding

1. Prepare the authenticated upstream connection and exact outbound bytes without sending. Do not consume authorization while waiting for connection setup or credential refresh.
2. Through Lean, check current policy, threshold, registration, agent status, session/call state and expiry.
3. Atomically record irreversible consumption/reservation, immutable dispatch intent and audit evidence. Remove settled delivery work. Commit durably before a protected send.
4. After that commit, process relevant already-observed ending/revocation events and obtain fresh trusted time. Under the shared dispatch gate, Lean rechecks the reserved request and orders the final handoff against cancellation, revocation, pause and session end.
5. In that same gated turn, hand the already prepared bytes to the single sender. There is no delayed generic `forward` queue, connection establishment or reconnect between the final check and first-write initiation. If the transport cannot accept that handoff without preparation, retain consumption and record not-sent; never restore the approval.
6. The non-cloneable dispatch object can be used once. Persist the actual outcome, filter the result, then answer the waiting agent if it remains connected.

Expiry is checked during the final transition even if a timer event is delayed. Optional expiry uses a sleep-aware monotonic deadline derived at creation; clock inconsistencies cannot extend lifetime. Timers notify endings but are not the authority for freshness. Mac resume revalidates or ends affected transport lifetimes before dispatch.

The linearization point is BOGO's authorization to hand bytes to an upstream transport. After that point, cancellation cannot undo bytes already buffered or a provider action. A crash after reservation but before durable completion leaves known-not-sent or outcome-unknown. Neither is replayed. Any upstream library retry/reconnect behavior for `tools/call` must be disabled at this boundary. Generic unmodified upstreams cannot participate in a transaction with BOGO: at-most-once forwarding is achievable, lossless exactly-once external effects are not.

Allowed tools still receive a Lean allow decision and ordinary current-agent/session checks. They do not enter approval delivery, protected-attempt persistence or synchronous approval-audit work merely to mimic a protected call. Durable configuration/identity state already governs them.

### Waiting, retry matching, grouping and flood resistance

Wait mode keeps the call pending without a preset expiry. Only the specified decision, cancellation, observed call/session end, owner action or configured expiry ends it. Phone/relay unavailability alone does not.

Pending-and-retry persists an exact matching key over session, upstream, tool, lexical arguments, justification and policy context. Repeated pending calls attach to the same request. Settlement sends nothing upstream until an identical retry; that retry performs the final dispatch procedure. Concurrent retries contend for one consumption record. Consumed and ended matching records remain for the session so later retries return the recorded terminal outcome or stored filtered result, never execute again or silently create another request. How to express a genuinely new identical action in that session remains a spec question.

In wait mode, repeated calls are distinct requests with distinct nonces. The phone groups identical pending actions by agent, upstream, tool, arguments, justification, hints and policy context; grouping changes presentation, not authority. Opening a group selects one concrete member and shows its session. Both Approve and Deny decide that member only. No approval covers the group. Pause provides the specified agent-wide action.

The per-agent pending limit counts outstanding logical requests, including settled-but-unconsumed work. Lean checks it before allocation and notification. Excess attempts are rejected quietly and audited. Matching retries do not invent additional execution authority. Bounded ingress/parser work and backpressure prevent unbounded in-memory queues; storage exhaustion closes admission rather than skipping audit or authorization. No invented rate or duration is introduced.

## 3.4 Independent iPhone feature

The host edge exposes only:

```text
BOGOFeature.rootView()
BOGOFeature.updatePushToken(token, environment)
BOGOFeature.receiveNotification(payload, action)
BOGOFeature.sceneBecameActive()
```

The package separates exact protocol/model, cryptography, transport, storage and views. A stand-in for BOGO implements the transport port during phone-first construction; rendering does not require a deployed relay. The host never accesses keys or constructs signed requests.

Replace the Approvals tab and old review presentation with BOGO. Remove old approval capability entry points and pending old approval notifications. Incoming Apple Bridge approval jobs are ignored without a decision so they expire on the unchanged Apple Bridge Mac. Photo/audio requests return the host protocol's explicit denied/rejected result, independent of capability toggles; they never reach camera, microphone or legacy approval code. The current dependency is concrete in [CaptureCapability.swift](/Users/johansardar/apple-bridge-iphone/ios/Capabilities/Capture/CaptureCapability.swift:6), and selection happens in [CommandHandlers.swift](/Users/johansardar/apple-bridge-iphone/ios/Delivery/CommandHandlers.swift:5). Avoid a thrown error that the host might translate into an indeterminate result.

Notification routing recognizes BOGO categories first and fans the shared APNs token to independent consumers. BOGO categories are merged with unrelated host categories. BOGO storage, relay, registration and push handling never pass through Apple Bridge's identity, pairing, delivery jobs or Mac services. BOGO works without any Apple Bridge Mac registration.

### Review and controls

Inbox persists original request bytes and validated decoding, shows grouped pending requests and greys ended entries. History distinguishes local decisions, Mac acceptance and actual/unknown execution outcomes. Macs supports registered setups, Add Mac, remove and re-registration when required.

The review model derives exclusively from received canonical bytes. Unknown versions, malformed values and unsupported critical display rules disable approval. "Will execute (exact)" shows upstream, tool, every argument and the trusted agent name. Highlighted values resolve signed structural paths; raw numeric tokens remain inspectable beside formatted values. All arguments remain accessible through scrolling/tree navigation, never silent truncation. Control characters, direction overrides, zero-width characters and significant whitespace are visibly inspectable; strings are not interpreted as instructions or markup.

Currency uses exact decimal/integer-scale arithmetic, not floating point. Invalid hints retain the raw value and a clear formatting failure. "Agent's reason (unverified)" shows justification, self-reported client name, session tag and the mismatch warning. A deterministic small parser recognizes explicit amounts such as `$47`, `47 USD` and `47 dollars` and compares currency/value pairs against all successfully formatted currency fields. An unmatched recognized amount warns; ordinary numbers such as `6pm` or flight numbers do not match. No money mention produces no warning. This is not a promise to understand arbitrary prose.

Approve exists only on full review, after the specified short delay for that particular request, and requires Face ID. Changing the reviewed request resets the delay. Ended entries cannot approve. The exact delay is an owner decision, not a new performance target. Deny can include a note. Pause is one tap and cannot unpause remotely. Local cached pending state is not proof of Mac freshness: the Mac always rechecks, and a late signature may be rejected.

Removing a Mac immediately disables local signing. An authenticated self-revocation message is retained until acknowledged; offline removal is explicitly not confirmation that the Mac already revoked the approver. It touches no Apple Bridge registration.

### Keys

Each Mac registration uses its own Secure Enclave P-256 approval key with `privateKeyUsage`, `biometryCurrentSet` and device-only protection. Require Face ID, not Touch ID or passcode fallback. Each approval signing operation uses a fresh authentication context without a reuse window. UI-only biometric checking followed by signing with an unrestricted key is forbidden. [Apple documents nonexportable Secure Enclave keys](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) and [current-enrollment access control](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset).

An approval signature covers a domain-separated approve envelope containing the full original request bytes, approver identity and key generation. P-256 ECDSA/SHA-256 uses a fixed wire signature representation; alternate encodings cannot become different approvers. Persist the signed decision before sending; retransmit that same decision without another signing ceremony.

Separate BOGO transport and control keys permit background delivery, notification Deny, pause and self-revocation without approval authority. Those keys are bound at registration. Control messages use disjoint signature domains and cannot produce Lean approval evidence. Key loss, app reinstall or biometric enrollment change requires fresh registration; no automatic software-key replacement is trusted.

## 3.5 Registration and encrypted approver routes

### Route interface

```text
register(ownerInteraction) -> VerifiedRegistration
sendRequest(registration, immutableRequestBytes) -> DeliveryReceipt
sendSettlement(registration, requestIdentity, stateVersion) -> DeliveryReceipt
receiveDecision() -> AuthenticatedDecision
reconcile(registration, knownState) -> StateUpdates
revoke(registration) -> Settlement
```

The kernel knows registered approver IDs, eligible generations and verified evidence, not route implementation. Adding a route supplies trusted registration, rendering/user-verification behavior and cryptographic evidence through the same port; it cannot bypass the kernel. Only the iPhone route is built for normal use now.

### Add Mac

`bogo approver add "Johan iPhone"` starts an owner-initiated transaction. Phone Add Mac uses BOGO's own rendezvous. If several offers exist, labels/age help choose a candidate but confer no trust. There is no QR code, typed pairing code or Apple Bridge discovery dependency.

Use a versioned commitment-based short-authentication-string exchange. The transcript binds roles, transaction identity, installation identity, public-key encodings, nonces and all protocol choices. The Mac commits to its ephemeral contribution before learning the phone's; the phone sends its contribution; the Mac reveals its committed contribution; both reject invalid commitments/keys. Derive the six displayed digits from the shared secret and complete transcript with unbiased extraction. The reviewed structure follows the commitment rationale in the [Matrix SAS protocol](https://spec.matrix.org/v1.16/client-server-api/#short-authentication-string-sas-verification), not a bare hash of freely replaceable public keys. One displayed attempt belongs to one local transaction; a mismatch/abort needs explicit owner restart, never relay-driven invisible retries. The BOGO adaptation is a crypto integration risk, not part of the Lean authorization proof.

The owner confirms on the Mac first. That confirmation is authenticated under the exchange key. The phone then confirms with Face ID, creates its approval key internally, proves possession and binds all long-term approval/control/encryption/mailbox identities to the compared transcript and a fresh Mac challenge. Key creation after numeric comparison is therefore still bound to that comparison. The Mac identity and final key set are authenticated in the same confirmed channel.

### App Attest

The phone uses a BOGO-specific App Attest key to attest challenge-bound registration evidence. The Mac validates CBOR, certificate chain against Apple's App Attest root, certificate nonce, App ID, attested key identity, counter, environment and required validation-category/app-version fields according to [Apple's current validation procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server). A library wrapper is accepted only if it covers that procedure; an opaque success boolean is insufficient. Challenges are single-use, and evidence and extracted keys are retained for the registration record.

The attested key is not the approval key. App Attest does not directly certify a supplied approval public key's biometric ACL. The accepted genuine app creates that key internally, never accepts an external replacement, and attests the bound evidence after Face ID possession proof. This is an explicit genuine-app/OS/key-enforcement trust argument. Production registration requires the accepted distribution identity/environment/version evidence; development registrations are explicitly separated and cannot silently substitute for production proof. Unsupported or unavailable attestation refuses registration; no graceful bypass is allowed.

Each side persists its prepared/final registration state before acknowledging the corresponding phase. The Mac marks trust active only after both confirmations and valid attestation. If its final acknowledgement is lost, retransmitting the same transaction retrieves the same result, not a second registration. The phone does not offer approval until it has the authenticated committed result. Re-registration revokes the previous generation atomically with activating the new one; historical keys remain in audit. An interruption before commit creates no trusted registration; after one side commits it is recovered idempotently rather than claimed to have never happened.

### HPKE envelopes and replay

Use authenticated HPKE, suite DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, through Rust `hpke` and [CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke). Long-term channel keys are distinct from approval keys and bound at registration. Every mailbox message has an independent fresh HPKE encapsulation/context and exactly one sealed plaintext; do not reuse a stream context across reordered mailbox deliveries. The original ciphertext is stored before send and retransmitted byte-for-byte.

Authenticated context/header data bind protocol version, installation, sender/recipient registration generation, direction, message kind and unique message ID. Request-scoped plaintext binds the full service-generation/request identity, never just a boot-local sequence. Types include request, settlement, signed approval/denial, pause, self-revocation, durable receipt, push-token update and synchronization.

Receivers authenticate and validate before accepting. A transaction records each unique message ID, payload identity and resulting state change before acknowledging it. Identical duplicate delivery receives the same acknowledgement; conflicting bytes under an ID are rejected. Unseen lower-numbered messages are not discarded simply because a newer message arrived. Per-request state versions and terminal tombstones prevent old pending messages from resurrecting ended entries. Settlements and requests arriving out of order reconcile against the Mac's authoritative state.

Pause additionally binds a per-agent control epoch. The owner unpause increments that epoch; any queued pause from before unpause is rejected even if it is being delivered for the first time. The phone obtains fresh epochs through authenticated state and invalidates old pause actions on updates. This is authority freshness, not just transport replay detection.

[HPKE explicitly does not provide general replay protection](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7). Durable receipts, scoped identities and reconciliation supply it. Request content, justifications, identities, decisions and push-token updates are encrypted; mailbox routing, sizes, endpoints and timing remain observable. No claim of traffic-analysis resistance is made.

## 3.6 Relay, APNs and delivery

The relay runs at `bogo.eilmer.si` on its own configured non-443 port, service account, service definition and state directory on the specified VPS. It shares no application state or code path with Apple Bridge. TLS uses a valid public certificate; DNS-01 renewal uses a Cloudflare credential scoped to the required zone and kept outside relay application state. The port is a deployment value, not an invented product requirement.

```text
put(mailbox, messageId, ciphertext) -> durable receipt
receive(mailbox, cursor) -> opaque messages
ack(mailbox, messageIds) -> removal
```

Mailbox identities authenticate using endpoint-held keys; the relay stores public authentication material, not endpoint secrets. The relay necessarily has TLS material, but no upstream/APNs credential, approval key or content-decryption key. A compromised relay may omit, replay, reorder or delete traffic, but cannot authorize calls or read their contents. Bounded storage returns explicit admission failure instead of pretending to retain a message.

Endpoint outboxes are authoritative. Mac request delivery persists until durable phone receipt or request ending; phone decisions persist until durable Mac acknowledgement. Request receipt means the phone stored the bytes, not merely displayed a notification. Reconciliation on foreground/reconnect restores current pending state and terminal markers even after relay loss. No retry count or relay retention policy becomes request expiry. Retry/backoff and long-polling conserve resources without introducing time goals.

The Mac sends APNs directly with the owner's existing provider key. Generic time-sensitive alerts contain opaque BOGO routing, never arguments or justification. Notification actions contain Deny only; the default tap opens full review. Deny targets the exact persisted request identity and queues its signed control decision if offline. Push-token changes travel through BOGO's authenticated encrypted channel, not Apple Bridge registration.

APNs is a best-effort wake/alert hint, not a durable queue or authorization channel. [Apple documents its delivery limits](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns). Shared bundle delivery can collapse/omit alerts, force-quit can prevent background work, and OS notification preferences can suppress time-sensitive presentation. Inbox reconciliation maintains correctness without assuming any push arrived.

## 3.7 Output filtering and audit

Output filtering is a deterministic projection over the whole returned MCP result. Configuration compiles field selectors into unambiguous structural paths and removal/redaction operations. Apply to structured content and duplicate JSON text representations before releasing any bytes. Resource links, metadata and embedded content cannot remain as unchecked copies of a removed field. If a configured filter cannot safely transform a representation, withhold it or return an output-delivery error, while preserving the real execution outcome. Never repeat the action to obtain a different result. Exposed optional output schemas must reflect the projection or be omitted rather than promise fields that were removed.

Without filters, return the upstream's real result. Field filtering is not a semantic detector for every secret in arbitrary prose or binary attachments. Owner-selected filters, constrained upstream access and the sandbox remain distinct boundaries. Known BOGO connection credentials must not be reflected through diagnostic or result handling.

The authoritative audit is an append-only table in the state database, with immutable event payloads, monotonically ordered sequences and each event's previous hash. The API only appends; derived query indexes are not historical authority. Events record protected attempts, complete canonical requests and justification, policy context, decisions/reasons/timestamps, responding approvers, original signed evidence, registration/revocation history, endings, consumption and actual or uncertain outcomes. Flood/paused/denied-policy rejections reaching authenticated admission are included. Unsigned hostile input is rendered safely, never executed as terminal control text.

Argument values are logged as specified; credential material obtained from the secret provider is not. A forbidden credential reflection is rejected/redacted at that boundary and recorded without copying the credential. A typed `Secret` alone is not treated as a solution to arbitrary reflected strings. No general new audit requirement is imposed on allowed calls.

`bogo log verify` checks chain continuity/canonical encoding, rebuilds historical registries, verifies signatures against exact bytes and key generations, and checks protected consumption against eligible approvals at dispatch. Later revocation does not invalidate historically valid evidence; already revoked or late responses are recorded as rejected evidence. Search/export operate on the same authoritative events. Export includes a verifiable chain/head.

A hash chain detects internal deletion/alteration, but cannot detect replacement by an earlier valid prefix without a separately retained head. Owner-retained export supplies an optional comparison point; no transparency service is added. Compromised Mac storage is outside the threat model. Malformed committed history is corruption, not silently repaired as a torn tail. On unavailable/full storage, stop protected admission/dispatch rather than claim unlimited auditing. A received packet is durable only after its transaction commits.

## 3.8 Owner operation, isolation and actual upstreams

`bogo init` creates protected directories, an approve-by-default configuration and service identity. `start` validates state/configuration before serving; a macOS LaunchAgent restarts unexpected exits. `stop` closes admission, commits pending endings and stops dispatch before shutting transports. The owner-only CLI supplies approver register/list/revoke/re-register; agent add/list/revoke/pause/unpause; discovered tool/effective-policy inspection; pending-request cancellation; and log view/search/export/verify. No web dashboard or remote owner API is added. Historical registration identity is never overwritten in place.

The reference agent container is on a dedicated internal network with a minimal fixed-destination HTTP forwarder. The forwarder accepts only BOGO MCP methods/path and cannot CONNECT, choose arbitrary URLs or follow redirects to other destinations. Before the untrusted agent starts, namespace rules default-deny traffic except the fixed forwarder address/port and established responses. Deny host-gateway routes, DNS forwarding, IPv6 bypasses and link-local/private/public destinations. Drop network administration/raw capabilities, run unprivileged, and expose no Docker socket or writable network configuration. [Docker bridge topology alone](https://docs.docker.com/engine/network/drivers/bridge/) is not the full enforcement mechanism.

Only the agent's BOGO token enters the container. No Mac home, BOGO state, APNs material, Link auth cache or owner socket is mounted. Filesystem upstream roots are explicitly owner-selected nonsecret paths and cannot be broadened by the agent. The reference setup must not let an allowed filesystem read become a secret-extraction path.

The spec-prescribed bypass checker is a shipped executable whose contract is to report forbidden direct upstream/relay/host access, credential discovery and unapproved protected calls from inside this environment. It is the required isolation artifact, not a new general verification framework or a timed run. A conventional cloud-backed agent's inference route conflicts with the literal BOGO-only egress rule; that is an owner/spec decision, not a hidden allowlist exception.

Use the unmodified Link CLI in MCP mode and the official filesystem server, with pinned installed executables and actual discovered schemas. [Link's current documentation](https://github.com/stripe/link-cli/blob/main/README.md) establishes `link-cli --mcp`, device-flow login and testmode SpendRequests. It does not establish that a test login makes all tools test-only: Link Pay Tokens do not support `--test`, and some checkout paths are live-only. The payment scenario uses only a confirmed testmode operation and test payment credentials; no real-money demonstration is performed. A SpendRequest/credential result is not falsely reported as a completed merchant charge. Rotating credentials remain private to BOGO; whether a native CLI cache is allowed instead of all state physically residing in `secrets.toml` needs resolution.

The [official filesystem server's tool inventory](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) contains no public sharing-link operation. Its file operations still satisfy the non-commerce upstream requirement, but the specific sharing-link filtering scenario needs an owner-selected real tool/result. No fabricated filesystem sharing tool is added.

## 4. Data flows

| Scenario | Flow through the units |
|---|---|
| 1. Payment approved | Authenticate Trip planner; capture lexical testmode arguments and justification; Lean creates the immutable request; transaction commits state/audit/outbox; relay delivers and Mac pushes; exact review shows $47.00 and trusted agent name; Face ID signs original bytes; verification and Lean settle; prepare/reserve/final-check/handoff once; persist/filter/return the real Link result. |
| 2. Lie in justification | Signed amount 50000 cents renders $500.00; recognized $5 text warns; Deny with "wrong amount" is durably delivered; Lean denies with no upstream send; agent receives "The owner denied this action. wrong amount". |
| 3. Changed call/session/replay | Changed lexical number, justification or session cannot match the approved bytes. A fresh admissible request needs fresh approval. Duplicate decision delivery is idempotent; consumed authorization never dispatches again. |
| 4. Allowed tool | Lean resolves allow for the authenticated active agent; adapter sends exact arguments immediately without approval fan-out or protected-call journaling; returns the real result. |
| 5. Denied tool | Per-agent discovery hides the tool unless configured visible; directly calling its name still produces rejection, never upstream traffic. |
| 6. No answer | Observed call cancellation/session end or configured expiry is ordered and durably ends the request; phone receives terminal state; late approval rejects. The not-performed outcome is used only if nothing could have been sent. |
| 7. Phone offline | Live request stays pending without default expiry; endpoint delivery retries; reconnect reconciles current state; only still-live requests can dispatch after approval. |
| 8. Add phone | Mac command and Add Mac perform committed numeric comparison; Mac confirms first; Face ID creates/proves the approval key; App Attest binds fresh evidence; both sides durably finalize the same registration. |
| 9. Add agent | CLI commits registry identity/token hash and prints token; later requests use that trusted name; missing/invalid/revoked tokens are refused. |
| 10. Stolen phone | No Face ID means no approval-key use; Mac revoke invalidates the route/key generation and pending eligibility; later signatures reject. Other registrations remain independent. |
| 11. Face ID changed | Current-enrollment key becomes unusable; phone requests Add Mac again; no fallback key or automatic trust transfer; old evidence remains auditable. |
| 12. Two approvers | Same request bytes go to all eligible approvers; one approver counts once; the second distinct valid approval meets 2-of-2; default denial veto applies while pending; final dispatch rechecks current registration. |
| 13. Output filtering | The chosen actual upstream runs once; result representations are filtered together or withheld; real execution status remains recorded. The selected filesystem server cannot supply the illustrative public-link result without a spec clarification. |
| 14. Escape attempt | Namespace/forwarder rules block direct upstream/relay/host access; credential files are absent and excluded from filesystem roots; valid BOGO token still cannot replace approval. |
| 15. Verify record | CLI checks chain and historical registration/signatures, reconstructs consumption eligibility, and reports the verified head, corruption and unknown outcomes without contacting upstreams. |
| 16. Flood and pause | Grouped entries retain separate nonces; pending-limit rejection creates no push; epoch-bound pause denies pending work and rejects further requests; Mac unpause advances epoch so delayed old pauses cannot override it. |
| 17. Two upstreams | Independent namespace/connection state keeps Stripe and filesystem discovery/execution separate; a payment waiting on a phone does not occupy another upstream's transport. |
| Pending-and-retry | First call commits one logical request and returns pending; identical retries attach; approval settles without sending; matching retry consumes once; subsequent retries observe retained terminal state/result. |
| Owner cancel/remove | Local cancel durably ends unsent work; phone removal disables local approval and reliably requests self-revocation, distinguishing local removal from Mac acknowledgement. |
| Old iPhone requests | Old Apple Bridge approval job is ignored; photo/audio receives explicit denied/rejected; BOGO notifications route independently even without Apple Bridge Mac registration. |

## 5. Failure

| Failure | Safe result and recovery |
|---|---|
| Bad config, permissions, signatures, duplicate keys or unknown protocol version | Reject without dispatch; report the precise error. No fallback allow, repaired JSON or alternative signing key. |
| Mac crash while pending | Recover committed journal; end every former service-generation session before accepting calls; send durable terminal updates. Old approvals never become executable after restart. |
| Crash after reservation or possible send | Keep consumption. Never replay. Report known-not-sent only with evidence; otherwise outcome unknown. |
| Lost result or agent response connection | Action may have happened; retain durable outcome when available and return it to a supported retry. Never say "not performed" merely because delivery failed. |
| Cancellation/revocation during preparation or commit | Final gated Lean handoff rejects if the event was ordered before send. Consumed authority is not restored. |
| Upstream crash/disconnect | Reconnect and discover independently; never retry an uncertain tool call. Changed contracts end affected pending requests. |
| Relay deletion, outage or reordering | Endpoints retry/reconcile; durable exact-message receipts accept out-of-order unique messages safely. Persistent omission harms availability, not authorization. |
| APNs omitted, app force-quit or token invalid | Keep encrypted state and outboxes; reconcile on next available execution. Do not promise background delivery that iOS may prevent. |
| Phone process termination | Reload independent store, resend durable decisions, reconcile pending/ended state; local decision is not fabricated execution success. |
| Signing/attestation unavailable or enrollment changed | No approval/registration bypass. Retry transient failure; fresh registration for invalid keys. |
| Final registration acknowledgement lost | Resume the same committed transaction idempotently; no false claim that both sides stayed unregistered. |
| Late denial/approval or stale generation | Log appropriate rejected evidence; do not alter settled decision or target a recycled request ID. |
| Denial and threshold race | Coordinator order determines settlement; late responses do not reopen it. |
| Clock rollback or sleep | Optional deadlines cannot gain lifetime; revalidate transport on resume; no automatic send based on stale liveness. |
| Full/corrupt storage | Stop affected admission and dispatch. Preserve committed evidence; never silently discard corrupt history as benign recovery. |
| Filter failure | Withhold unsafe result representation, preserve execution status, never execute again. |
| Old database restored | End old sessions and reject uncertain registration/message generations; require fresh registration where replay/key safety cannot be established. |
| Forwarder failure | Agent loses its only route; observed session/call endings reject late authority. No direct-route fallback. |

Automatic recovery means durable local recovery and retryable delivery, not restoration of destroyed copies, resurrection of a dead session or replay of an uncertain external effect. There is no architectural way to make arbitrary provider side effects disappear after a lost connection.

## 6. Data and versions

- `~/.bogo/bogo.toml`: schema version, upstreams/secret references, defaults, per-tool/per-agent policy, display hints, optional expiry, approvers/threshold/denial mode, retry mode, filtering and pending limit.
- `~/.bogo/secrets.toml`: owner-only credential source; changes use protected same-directory write/flush/atomic replacement. No agent access or credential logging.
- `~/.bogo/state.sqlite`: installation and service generations, registries/key history, agent control epochs/token verifiers, immutable policy/catalog snapshots, sessions, exact requests, attempts, response evidence, consumption/outcomes, audit, outboxes and durable receipts.
- Owner-only lock/socket and launch configuration; no agent-facing owner API.
- Phone BOGO-only application-support database/files and device-only Keychain namespace: per-Mac identity/key references, received exact bytes, terminal state versions, decisions, outbox/receipts and registration transactions. Background transport protection is distinct from biometric approval-key protection.
- Relay's own SQLite state: opaque messages, routing/public authentication material and durable acknowledgements; no decrypted requests.

Unique constraints enforce one consumption per request and one counted response per eligible approver generation. Immutable request bytes and historical events are never re-encoded in place. Pending retry tombstones remain for the session. Durable message acceptance is scoped by installation/registration generation and message identity, not a counter reset on restart.

Request format, bridge ABI, registration transcript, HPKE envelope, control messages, audit and database each have explicit versions. Unknown security-critical fields, tags and trailing bytes reject. Approval, denial, pause, self-revocation and settlement have distinct domains. One request uses one encoding understood by every approver needed for its requirement; signatures over different format versions are never combined as if they covered identical bytes.

Database migration is transactional before traffic begins. Supported historical audit formats remain verifiable; unsupported authorization formats cannot execute. Policy restart and key-generation changes do not reinterpret old evidence. Pin Lean toolchain, Rust lockfile, Swift package settings and upstream versions; select the supported MCP eras explicitly rather than inheriting changing SDK defaults.

The phone-development stand-in simulates BOGO behind its transport port. The separate test-only software approver demonstrates threshold behavior when no second real approver exists. These are different artifacts. The software approver's registrar/keys are absent from normal BOGO, not activated by a runtime TOML flag; no development proof or feature selection silently weakens production registration.

## 7. Repo layout

```text
bogo/
  crates/
    bogo-cli/          CLI and service entry
    bogo-domain/       opaque IDs and bridge values
    bogo-lean/         safe wrapper and small C ABI
    bogo-mcp/          rmcp edge, lossless boundary, shim
    bogo-policy/       TOML and catalog transformation
    bogo-runtime/      coordinator and one-shot effect wiring
    bogo-store/        transactional state, audit, outboxes
    bogo-upstream/     process/HTTP adapters and filtering
    bogo-crypto/       signatures, registration, HPKE
    bogo-delivery/     approver ports, reconciliation, direct APNs
    bogo-relay/        independent VPS executable
    bogo-sandbox/      fixed forwarder and required bypass checker
  lean/Bogo/
    Domain.lean Encoding.lean Policy.lean Transition.lean
    Properties.lean Exports.lean
  protocol/
    encoding.md registration.md transport.md vectors/
  development/
    phone-standin/     BOGO stand-in, not a normal service dependency
    software-approver/ isolated threshold-demonstration build
  sandbox/            container configuration and namespace policy
  deploy/macos/       LaunchAgent
  deploy/relay/       independent service, certificate and firewall setup
  docs/
    configuration.md threat-model.md proof-boundary.md
  README.md

apple-bridge-iphone/
  Packages/BOGOFeature/Sources/
    BOGOProtocol/ BOGOCrypto/ BOGOTransport/ BOGOStore/ BOGOFeature/
  ios/App/            host facade mounting
  ios/Delivery/       category routing and token fan-out
  ios/Capabilities/Capture/  explicit denied behavior
```

Domain/Lean knows no SDK or UI types. MCP and delivery cannot import a concrete upstream sender. Only coordinator wiring constructs the one-shot dispatch input. The relay imports framing/routing, not decryption, policy or secrets. The production graph excludes development artifacts and the software registrar.

On iPhone, the host imports only the facade. Protocol/model has no SwiftUI or host dependency; crypto/store do not import screens; transport cannot manufacture approval signatures. No BOGO target imports Apple Bridge identity, pairing, approval jobs or Mac service paths. Old approvals are retired, not hidden as an alternate signing path.

## 8. Build order

1. Define exact value/request/control formats and ports, with Lean encoding and emitted interface vectors. This is the shared prerequisite, not a full Mac daemon.
2. Build the iPhone package against a BOGO stand-in: exact review, Inbox/History/Macs, grouping, delay, denial and pause. Mount the host facade, retire old approvals and make capture denied. No live relay or full registration service blocks this work.
3. Connect real Face ID key use, App Attest and numeric comparison through the same phone ports. Define the full versioned registration transcript and trust evidence before enabling real approval.
4. Implement the Lean transitions/proofs and dedicated runtime bridge; define durable event/state transitions and the final dispatch interface together.
5. Build Mac configuration, registries, transactional store, owner CLI, supervision and coordinator. Registration and agent state now have their durable authority.
6. Connect the independent relay, HPKE envelopes, receipts/reconciliation and direct APNs; swap phone transport from stand-in to actual BOGO without changing rendering/signing.
7. Connect lossless rmcp discovery/calls, session adapters, upstream preparation and gated one-shot dispatch; add complete-result filtering and historical audit verification.
8. Assemble threshold settlement, retry matching, expiry, revocation, flood/pause and crash recovery through those existing boundaries. Keep the software approver confined to its separate build.
9. Assemble Docker isolation and its prescribed checker, configure actual Link testmode/filesystem operations, and publish quick start, configuration, threat model and proved/assumed documentation from the actual interfaces.

No interim production path uses old iPhone keys, an unproved Rust authorization placeholder or Apple Bridge Mac services.

## 9. Libraries

| Choice | Why | Source |
|---|---|---|
| Lean 4 and Lake | Required executable encoding/authorization and proofs; C output links into Rust | [Lean](https://github.com/leanprover/lean4), [FFI](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) |
| rmcp | Required Rust MCP lifecycle/discovery/transport SDK behind a lossless tool-call adapter | [Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) |
| Serde/serde_json RawValue | Typed ancillary data and retained source spans; not lexical number authority | [RawValue](https://docs.rs/serde_json/1.0.154/serde_json/value/struct.RawValue.html), [deserializer](https://docs.rs/serde_json/1.0.154/src/serde_json/de.rs.html) |
| Tokio, Axum/Hyper, Reqwest | Async processes/HTTP outside the coordinator, streaming and direct HTTP/2 APNs | [Tokio](https://github.com/tokio-rs/tokio), [Axum](https://github.com/tokio-rs/axum), [Reqwest](https://github.com/seanmonstar/reqwest) |
| rusqlite/SQLite | Local atomic state/audit/outbox and opaque relay persistence | [rusqlite](https://github.com/rusqlite/rusqlite), [SQLite](https://www.sqlite.org/atomiccommit.html) |
| Rust hpke and CryptoKit HPKE | Standard authenticated encryption construction with native iOS support; application handles replay | [rust-hpke](https://github.com/rozbb/rust-hpke), [CryptoKit](https://developer.apple.com/documentation/cryptokit/hpke), [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) |
| RustCrypto p256, sha2, hkdf and curve primitives | Approval verification, hashing and registration key agreement; explicit crypto assumptions | [elliptic-curves](https://github.com/RustCrypto/elliptic-curves), [hashes](https://github.com/RustCrypto/hashes), [KDFs](https://github.com/RustCrypto/KDFs) |
| macOS Security trust validation plus strict CBOR/DER parsing | Apple anchor verification and complete App Attest evidence validation; no Mac Keychain credential writes | [security-framework](https://docs.rs/security-framework/latest/security_framework/), [Apple procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server), [Ciborium](https://github.com/enarx/ciborium), [DER](https://github.com/RustCrypto/formats/tree/master/der) |
| TOML and Clap | Owner configuration and CLI, with explicit domain validation | [toml](https://github.com/toml-rs/toml), [Clap](https://github.com/clap-rs/clap) |
| Swift Security, LocalAuthentication, CryptoKit, DeviceCheck | Enclave access controls, Face ID, crypto and App Attest | [Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [DeviceCheck](https://developer.apple.com/documentation/devicecheck) |
| SwiftUI, UserNotifications, URLSession, SQLite C API | Existing native stack with independent BOGO views, notifications, transport and persistence | [SwiftUI](https://developer.apple.com/documentation/swiftui), [UserNotifications](https://developer.apple.com/documentation/usernotifications), [SQLite C](https://www.sqlite.org/cintro.html) |
| Rustls and a DNS-01 ACME client | Relay TLS and independent certificate lifecycle | [Rustls](https://github.com/rustls/rustls), [lego Cloudflare](https://go-acme.github.io/lego/dns/cloudflare/) |
| Docker, Link CLI, official filesystem server | Specified reference environment and unmodified upstreams | [Docker](https://docs.docker.com/engine/network/drivers/bridge/), [Link CLI](https://github.com/stripe/link-cli), [filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) |

Library selection is not a claim that the dependencies are formally verified. The Lean theorem explicitly stops at crypto, parsers outside the kernel, runtime/FFI, persistence and transport assumptions. Versions must be pinned to the implementations actually integrated, with their source behavior checked at the lossless and security boundaries.

## 10. Risks and open questions

| Risk | Consequence | How to establish the boundary |
|---|---|---|
| SDK normalization or argument escape path | Signed bytes differ from forwarded arguments | Follow actual bytes through shim, ingress, Lean and egress; inspect every upstream send caller. |
| Gated dispatch implemented as an async queue | Expired/revoked authority is sent later | Trace reservation, current facts and first-write initiation; transport preparation must precede the final ordered check. |
| Universal MCP/session/schema promises | Some clients or interactive tools cannot fit the specified interface | Inspect real negotiated versions and discovered schemas; publish supported lifecycle/interaction contracts and surface remaining spec decisions. |
| Registration SAS adaptation | Transcript omissions or rerolls weaken numeric comparison | Review all roles, commitments, keys, challenges and final acknowledgements against the source protocol. |
| App Attest mistaken for approval-key ACL attestation | Unsupported security claim or acceptance of an old app build | Validate current evidence fields and trace the accepted app's internal key-creation/signing path. |
| Out-of-order/replayed control messages | Wrong request denied, lost valid decision or stale pause | Trace full generation IDs, durable receipts, request versions and unpause epochs through reconciliation. |
| Residual legacy iPhone routes | Old unrestricted key or capture flow remains reachable | Trace host tab, notification, job dispatch and persisted old approval entry points. |
| Sandbox or filesystem roots too broad | Agent reaches providers or retrieves private credentials | Inspect effective namespace rules, mounts and upstream roots from the reference environment; use the required bypass checker. |
| Link and filesystem examples do not match actual tools | Live operation mistaken for testmode, or invented demonstration | Read pinned CLI schemas and real results; keep the unsupported sharing-link example an owner question. |
| Persistence, exhaustion and valid-prefix truncation | Record guarantees are overstated | Trace transaction failure/recovery and verified-head semantics; keep the external-copy limitation explicit. |
| APNs/OS delivery limits | Phone does not alert despite pending work | Treat push as a hint and reconcile authoritative encrypted state independently. |

This document specifies mechanisms and proof obligations, not completed proofs or runtime results. No biometric operation, upstream execution or sandbox bypass run is claimed here.

## 11. Questions for the user

1. **Unknown upstream outcome:** May BOGO report "execution outcome unknown; not retried" after a send might have occurred? At-most-once forwarding cannot also guarantee "silence means nothing happened" and lossless automatic completion for arbitrary unmodified upstreams.
2. **Session compatibility:** Which direct MCP client/version combinations must support pending-and-retry? Options include the supplied shim, an explicit BOGO session contract, or limiting that mode to session-capable connections. Silent abandonment without a protocol signal cannot be reliably detected without changing the lifetime promise.
3. **Exact interface compatibility:** For schemas that cannot faithfully accept an added justification field, or tools needing execution-changing interactive exchanges, may BOGO use a wrapper/metadata/new approval exchange, or should they be reported incompatible? Universal unmodified-tool support is not solved by hiding those cases.
4. **Default precedence:** If the owner sets default allow, do newly discovered tools still remain approve until explicitly configured, or inherit allow immediately?
5. **Identical new actions in retry mode:** How should the agent distinguish a new identical business action from retrying a lost result within the same session? Retaining consumed matching records prevents accidental duplicate execution but needs a defined new-action mechanism if both are required.
6. **Registration evidence and distribution:** Is genuine-app-attested internal key creation the intended App Attest guarantee? Which distribution identity/environment and accepted version evidence identify the BOGO-capable build? Public App Attest is not direct biometric-ACL attestation of an arbitrary approval key.
7. **Unspecified behavior values:** What short Approve delay and default pending limit should configuration use? Neither is assigned a value here; no idle timeout or preset request expiry is added.
8. **Reference inference route:** Does inference run outside the container, or may the spec permit an additional constrained model-provider route? The literal BOGO-only egress rule excludes ordinary cloud model access from inside it.
9. **Actual Link operation:** Which discovered Link tools should be protected, and which supported testmode SpendRequest/credential operation realizes the $47 scenario without implying a completed merchant charge?
10. **Credential storage:** Must rotating native CLI session state physically live entirely in `secrets.toml`, or may an unmodified upstream use an isolated owner-only auth file on BOGO's side?
11. **Filtering scenario:** Which real tool/result should demonstrate public-link removal? The selected official filesystem server has no sharing-link operation; no replacement tool is invented here.
12. **Second approver:** Is another Face ID-capable iPhone/iPad available for real 2-of-2 use? The software approver remains confined to the specified separate demonstration build.
13. **Unconfirmed speed/setup aspirations:** Should the earlier allowed-call overhead, notification latency and setup-time aspirations become requirements? They are not performance promises in this architecture; no benchmark count, soak or timed trial is added.
