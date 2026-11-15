# BOGO: Architecture

Status: 2026-11-14. Built from SPEC.md.

## 0. The shape

BOGO is one Rust service on the owner's Mac, exposing authenticated MCP HTTP through rmcp and a raw-body-preserving stdio shim. Only BOGO holds upstream credentials or connects to unmodified upstreams. Compiled Lean 4 owns exact request encoding, policy, approval settlement, lifecycle and single-use authorization; Rust supplies authenticated observations, cryptography, durable storage and effects. One SQLite transaction authority joins registry history, audit, immutable request facts and endpoint delivery obligations. Every upstream call goes through an exact transport; protected calls receive their final Lean authorization at a prepared, non-replayable sender, after SDK queueing and durable consumption. A separate Swift package replaces Approvals inside the existing Apple Bridge iPhone app, with its own Face ID–locked keys, screens, storage, registration and relay connection. BOGO's independent relay carries end-to-end encrypted messages; the Mac sends APNs directly. Restart ends old sessions rather than reviving approvals, and uncertain upstream sends are never replayed. A default-deny Docker namespace exposes only a fixed route to BOGO. The remaining universal-compatibility and external-effect limits are explicit specification questions, not silently weakened guarantees.

## 1. Runtime picture

```text
Docker reference environment                     Owner's Mac
  inert namespace holder
  trusted initializer -> installs policy -> exits
  non-root agent, no capabilities
    | direct MCP HTTP or stdio -> bogo-shim
    v
  default-deny namespace -> fixed TCP forwarder -> BOGO authenticated MCP edge
                                                       |
  owner terminal -> bogo -> owner-only Unix socket -> coordinator
                                                   /      |        \
                                             Lean thread SQLite   exact rmcp adapters
                                                         audit     staged sender
                                                        + outbox    /       \
                                                                local     remote
                                                              upstreams upstreams

BOGO encrypted delivery <----> bogo.eilmer.si:<own port> <----> BOGO Swift package
                                own relay/service/state        in Apple Bridge app
BOGO direct APNs sender ------> Apple APNs -------------------> notification edge
                                                               Inbox / History / Macs
                                                               exact review + Face ID
```

Mac modules run in one supervised service. The shim, local upstreams, forwarder, relay and existing iPhone app are separate processes. No BOGO component uses any Apple Bridge Mac gateway, relay, registration or APNs path. The relay shares only the VPS. The phone host mounts the BOGO facade, routes BOGO notifications and shares its push token; it supplies no BOGO signing authority or registration identity.

## 2. Units

| Unit | Language | Owns | May depend on | Must never depend on |
|---|---|---|---|---|
| Kernel | Lean 4 | Exact value/request codec, effective policy, lifecycle, thresholds, consumption, proofs | Lean standard library, specified crypto primitive | Filesystem, sockets, UI, SDK |
| Kernel bridge | Rust / C | Dedicated thread, runtime initialization, byte ABI, ownership | Compiled Lean, verifier callback | Independent Rust authorization logic |
| Exact JSON | Rust | Strict lexical parser/writer | Standard library | SDK-normalized argument values |
| MCP edge / shim | Rust | Authenticated requests, exact extensions, discovery, call/session observations; stdio framing | rmcp, HTTP, coordinator port | Credentials, concrete upstream sender |
| Configuration/catalog | Rust | TOML validation, policy compilation, tool mapping, schema augmentation | Exact domain types, discovery port | Agent-selected policy or launch destinations |
| Coordinator | Rust | Ordered security events, commits, final sender gate | Kernel bridge, store, effect ports | UI summaries as execution authority |
| Store/audit | Rust / SQL | Registry/history, immutable requests, intent/outcome, hash chain, outboxes/receipts | SQLite, canonical event encoding | Sending upstream calls |
| Upstream adapter | Rust | Private child/HTTP connections, rmcp staging, exact writer, output filtering | Credential provider, rmcp, private gate port | Agent-chosen credentials, URLs, executable authority |
| Crypto/registration | Rust | Signature checks, SAS, App Attest validation, HPKE | Crypto libraries, Apple trust anchor | Relay assertions of trust |
| Approver delivery | Rust | Route fan-out, reconciliation, retries, direct APNs | Registry/outbox, crypto, HTTP | Deciding execution |
| Relay | Rust | Opaque mailboxes, public-key mailbox auth, rendezvous | Independent TLS/HTTP/SQLite | Decryption, APNs/upstream secrets, kernel |
| Phone package | Swift | Canonical decoding, review, keys, inbox/history/Macs, durable delivery | Apple frameworks, own SQLite | Apple Bridge identity, jobs, registration or relay |
| Phone host edge | Swift | Tab, push-token fan-out, category routing, old-feature retirement | Public BOGO facade | BOGO key access or signed-request construction |
| Owner CLI | Rust | Setup, service lifecycle, registries, tools, cancel, logs | Owner-only control socket | Remote owner-control API |
| Reference isolation | Container configuration | Namespace policy, fixed forwarder, prescribed bypass executable | Docker, fixed BOGO destination | Arbitrary egress or credential mounts |

## 3. Core pieces

### 3.1 Exact values and request encoding

The authoritative parser rejects duplicate decoded object keys, invalid UTF-8, lone surrogate escapes, malformed numbers, trailing input and unsupported sizes/depths. Strings are Unicode scalar sequences without normalization. Equivalent JSON string escape spellings are the same value. Object keys sort by UTF-8 bytes; arrays retain order. Numbers retain the complete ASCII token: `4700`, `4700.0`, `4.7e3`, `4.7E3`, `4.7e+3` and `-0` remain distinct. Absent arguments differ from an explicit empty object; absent justification differs from an empty string.

```text
JVal = Null | Bool | Number(JsonNumberText) | String(UnicodeScalars)
     | Array(List JVal) | Object(StrictlySortedUniqueKeys JVal)
JsonNumberText = -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?

All integers: unsigned big-endian. Length/count: u32. Time: u64 Unix milliseconds.
bytes(x) = u32(length(x)) || x
str(s)   = bytes(UTF8(s))
opt(T)   = 0x00 | 0x01 T
list(T)  = u32(count) || T*

value = 0x00                              -- null
      | 0x01 | 0x02                       -- false | true
      | 0x03 bytes(valid-number-ASCII)
      | 0x04 str(string)
      | 0x05 list(value)
      | 0x06 list(str(key) || value)       -- unique, ascending keys
PathSegment = 0x00 str(objectKey) | 0x01 u32(arrayIndex)
Hint = list(PathSegment) || format
format = 0x00 | 0x01 str(ISO-currency) u8(minor-unit-scale)
         -- text | money in integer minor units

Request = "BOGOREQ\0" || u16(1) || these fields in exactly this order:
  0x01 bytes(installationId)
  0x02 str(upstreamId)             0x03 str(toolName)
  0x04 opt(value)                 -- complete stripped arguments
  0x05 opt(str(justification))     0x06 list(Hint)
  0x07 bytes(agentId)             0x08 str(ownerAssignedAgentName)
  0x09 opt(str(clientReportedName))
  0x0A bytes(sessionId)            0x0B bytes(nonce)
  0x0C u64(createdMs)              0x0D opt(u64(expiresMs))
```

Installation identity and each boot generation are random 32-byte values. Agent/approver identities are installation-scoped random 16-byte values. A session is the 32-byte boot generation plus a server-minted random 16-byte identifier. The nonce is the boot generation plus a non-reused u64 sequence; exhaustion closes admission. Full request identity is installation plus nonce, never an unscoped integer. Domain types validate each width, time range, hint format and canonical ordering; overflow rejects.

Lean defines and executes both the encoder and decoder. Decode consumes all input and rejects unknown versions/tags, unsupported critical hints, invalid domains and noncanonical ordering. Prove `decode(encode(r)) = some r`, hence injectivity, over the explicitly bounded canonical domain. Rust encodes bridge events, not the authoritative approval request. Swift decodes and signs the original received request bytes rather than re-encoding its view. Lean-generated protocol vectors include lexical JSON, canonical values, request bytes and expected exact-writer output for platform interoperability.

Approval input is `"BOGO-APPROVAL\0v1" || bytes(approverId) || u64(keyGeneration) || bytes(requestBytes)`. P-256 ECDSA uses SHA-256 and CryptoKit's raw 64-byte `r || s` wire representation. Distinct approvers mean registered identities, not distinct ECDSA encodings.

Effective policy, eligible registration generations, threshold, denial behavior, filtering, extraction key and mode are immutable local request context, recorded for audit but not extra phone-signed request fields. Configuration changes require restart and therefore end old sessions. No dynamic catalog change can reinterpret an admitted request's route or reserved justification property.

### 3.2 Executable Lean kernel and ABI

The kernel is a total transition function with no I/O. Its state contains immutable configuration, registries and key generations, agent pause/control epochs, sessions/calls, live requests, response sets, settled decisions, reservations and consumption. Every allow, approve and deny decision passes through it.

```text
Event = SessionOpened(serverSession, authenticatedAgent, clientInfo)
      | SessionClosed(session) | CallEnded(callId)
      | Admit(session, callId, exactName, optionalArguments, observedTime)
      | Decision(approver, requestId, signedEvidence, observedTime)
      | Control(authenticatedOrigin, controlMessage)
      | OwnerChange(ownerOperation)
      | Deadline(observedTime)
      | Reserve(requestIdOrAllowedCall, preparedSendId, observedTime)
      | Handoff(reservationId, preparedSendId, observedTime)
      | EffectOutcome(reservationId, outcome)

Effect = Ask(requestId, requestBytes, eligibleApprovers)
       | Reply(callId, pending | denied(note) | ended | rejected(reason))
       | Journal(event) | DeliverState(requestId, version, state)
       | ReserveSend(reservationId, immutableDispatch)
       | DispatchOnce(reservationId, preparedSendId, immutableDispatch)
       | NextDeadline(optionalDeadline)

step : State -> ValidatedEvent -> State × List Effect
verify : Algorithm × PublicKey × ExactMessage × Signature -> Bool
```

`ValidatedEvent` means structurally validated, not agent-trusted. Owner operations arrive only from the owner socket. Agent bytes cannot construct registration, unpause or authenticated identity facts. Cryptographic evidence remains arbitrary until verified. The route authenticates control origins before constructing control events. The core selects the registered verification key, generation, algorithm and exact bytes; one Rust callback supplies the specified crypto primitive.

```text
Collecting -> SettledApproved -> Reserved -> HandedOff -> Completed | OutcomeUnknown
     |               |             |
     |               +-> Ended     +-> NotSent (consumption retained)
     +-> Denied | Ended
```

Rules:

- Resolve per-agent override, then explicit tool policy, then valid defaults. Unknown agents/tools, malformed inputs, paused/revoked agents and closed sessions reject. Allow dispatch has no approval state; deny never dispatches.
- Approve strips only the catalog-reserved justification property. Present justification must be a string. Missing required justification gives an explanatory rejection. Stored stripped arguments, not a subsequent retry's copy, are authoritative.
- Match an existing pending-and-retry request before allocating or checking a new-request limit. Count every outstanding logical request, including settled-but-unconsumed requests, against its agent's configured pending limit. Excess rejects quietly and is audited.
- Encode one immutable request and send identical bytes to all eligible approvers. No preset expiry exists. An impossible threshold rejects rather than waiting for nonexistent eligible keys.
- Verify approvals against the exact stored bytes and currently active eligible key generations. Distinct identities count once. Any-of needs one; k-of-n needs k. While collecting, default denial veto ends the request. Configured non-veto denial excludes that identity from usable votes and denies when k becomes unreachable; contradictory later evidence cannot restore a denied identity.
- Reaching threshold freezes the counted vote set and settles the decision. Later votes are ignored. Pending-and-retry settlement alone does not execute. Revocation never transfers old votes to replacement keys or reopens voting.
- Reservation and final handoff check sufficient currently active counted keys, active/unpaused agent, live session and executing call, immutable dispatch identity and freshness. Reservation consumes authority irreversibly. Only one matching handoff can emit `DispatchOnce`.
- Call/session end, owner cancellation, agent revocation and configured expiry end unsent authority. Relevant approver loss either makes collecting authority unreachable or invalidates settled authority. Pause denies outstanding requests and rejects every subsequent agent request, including discovery. Only the Mac owner unpauses.
- Mac unpause increments a durable per-agent control epoch. Phone pause carries the current epoch; an older pause cannot reapply after unpause, including its first delayed delivery.

One thread initializes Lean and owns all Lean objects. The public C ABI uses byte buffers and a distinct namespace from generated exports:

```c
uint32_t bogo_abi_version(void);
int bogo_kernel_open(const uint8_t *init, size_t n, void **handle);
int bogo_kernel_step(void *handle, const uint8_t *event, size_t n,
                     uint8_t **result, size_t *result_n);
int bogo_request_decode(const uint8_t *bytes, size_t n,
                        uint8_t **result, size_t *result_n);
void bogo_buffer_free(uint8_t *buffer);
void bogo_kernel_close(void *handle);
```

Generated Lean exports use `bogo_lean_*`, never these wrapper symbols. Inputs are borrowed only during a call. Returned buffers are owned by the wrapper and released only through its free function. Runtime/module initialization occurs once; ABI mismatch refuses startup. Pin Lean code, runtime and headers together. No panic/exception crosses the ABI. The [Lean FFI reference](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) governs generated object ownership and calling conventions.

### 3.3 What is proved / What is assumed

The trace model quantifies over arbitrary agent messages, malformed bytes, arguments, justifications, client names, signatures, cancellations, connections and adversarial network ordering/replay. Opening and ending sessions are modeled, not assumed away. Identity attribution comes from authenticated transport observations; arbitrary agent behavior is not permission to invent another agent's token verification or an owner command.

Prove that every protected `DispatchOnce` has sufficient distinct active eligible approvals; each binds the exact request and lexical arguments; each request/reservation dispatches at most once; no ordered end, pause, relevant revocation or expiry preceding handoff can be bypassed; sessions and per-agent policy remain bound; settlement is final; malformed or unauthorized messages cannot dispatch; allowed calls require effective allow and active identity/session; and encoding is deterministic and injective.

List assumptions explicitly: signature soundness and user-verification-bound keys; hash collision resistance; secure randomness and HPKE; accepted genuine app behavior; secure OS/enclave/Face ID; truthful clock/liveness observations; correct storage durability and one-shot sender refinement; compiler/runtime/FFI correctness; uncompromised Mac and phone OS; actual sandbox isolation; and upstream access controls. Distinguish cryptographic soundness hypotheses from axioms of Lean's logic. An `extern` declaration alone does not prove that its Rust implementation satisfies the assumed relation.

The theorem does not prove human judgment, notification availability, universal schema compatibility, instant detection of silent client abandonment, or exactly-once external completion. The implementation must faithfully refine the final handoff event, not merely prove a predicate at an earlier SDK call.

### 3.4 MCP edge, shim and sessions

Pin rmcp 3.10.0 as the integration baseline. An outer HTTP layer authenticates each bearer token, reads one message with the strict lexical parser and puts `ExactCall { internalCallId, name, optionalArguments, envelopeIdentity }` in that request's extensions. rmcp carries HTTP request parts to its handler; the handler requires this exact tree and ignores the SDK-normalized argument map. Method/name/ID must agree between envelopes. Duplicate keys reject before SDK processing. Active JSON-RPC IDs remain unambiguous within a session so cancellation cannot overwrite another waiter.

Authenticate every HTTP request, not just session creation. A server-minted session is bound to one authenticated agent. `bogo agent add` prints a random token once; persist only its verifier hash, stable agent identity and owner name. A token never authorizes a protected call. Validate Host and Origin. Bind only to loopback or the narrowly required sandbox-reachable interface; the owner-control Unix socket is separate and owner-permission/peer checked.

The stdio shim preserves original JSON bodies byte-for-byte. It may inspect envelope fields for IDs, client negotiation, protocol headers, cancellation and correctly correlated error replies, but never reserializes arguments. It forwards requests concurrently so a waiting tool call cannot block a following cancellation. Diagnostics go to stderr; stdout carries only MCP messages. SSE framing is decoded without modifying payload values.

At startup the shim authenticates a BOGO-only liveness endpoint and obtains a server session handle. It holds that stream open and attaches the handle to forwarded POSTs. Stdin EOF, DELETE, explicit cancellation or observed liveness termination closes the corresponding authority. Reconnection obtains a new handle; it never rebinds old approvals. An observed shim crash closes its stream; silent network failure detection remains subject to transport/OS observation.

Direct session-capable HTTP binds `Mcp-Session-Id` to the agent and client information. DELETE, revocation and restart end the session. Protected wait calls keep their response body open. Observed body cancellation or MCP cancellation ends that call. BOGO offers no approval-request resumption or event replay capable of reviving an ended call. This is a documented stricter, non-resuming profile: the [2025-11-25 MCP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) ordinarily distinguishes an SSE interruption from cancellation. A direct session without a persistent liveness stream cannot reveal silent abandonment between calls; no idle expiry is invented.

The [2026-07-28 protocol](https://modelcontextprotocol.io/specification/2026-07-28/changelog) is stateless. Direct wait calls use call-scoped authorization sessions and per-request client information. Pending-and-retry requires a session-capable connection or the shim's explicit session contract; reject incompatible stateless use with a clear message. Negotiated headers, metadata, initialization/discovery and private cache fields follow the supported protocol era.

Upstream roots, sampling, elicitation, resources, prompts and execution-changing continuations are not unsigned alternate paths. Advertise only supported tools behavior. Reject interactions that need additional execution-changing input rather than silently forwarding it outside the approved bytes; universal interactive MCP compatibility remains an owner question.

### 3.5 Catalog, schema projection and secrets

Discover every page of `tools/list`, refresh on supported list-change notifications, and retain explicit routing from `<upstream>__<tool>` to configured upstream identity/original name. Upstream aliases cannot contain `__`. Reject ambiguous collisions; report unexposable protocol names/lengths rather than silently aliasing them. Preserve descriptions and original argument constraints except the specified justification addition. Hide denied tools per agent by default; an optionally visible denied tool still rejects.

Configuration is immutable until restart. It contains per-tool allow/approve/deny, justification requirement, display hints, optional expiry, eligible approvers, any-of/k-of-n, denial rule, output filters, wait/pending-retry and per-agent policy/approver overrides. Validate references and effective thresholds before using them. Ship approve as default. Do not silently apply an ambiguous default-allow rule to new tools; the precedence question must be resolved before such configuration is enabled.

Schema augmentation is a finite, explicit compiler, not an unbounded search for a name. Its contract is:

```text
augmented(a) iff original(removeReservedField(a))
                and reservedFieldIsOptionalString(a)
```

It must also preserve all legitimate upstream fields: the reserved top-level name cannot already carry upstream meaning. For the initial supported subset, the argument root is an object with a finite declared property set closed by `additionalProperties: false`; nested value schemas are unchanged. Allow ordinary `properties` and `required`, plus annotations. Reject root-wide constraints not handled by the compiler, including pattern/property-name rules, cardinality, object constants/enums, conditionals, negation, references and combinators. Choose the first available `bogo_justification`/numbered candidate from that finite closed namespace, insert its optional string schema, and preserve original required properties. A future compiler may accept additional constructs only with the same projection contract; unsupported schemas are reported incompatible, never transformed approximately. Open additional-key namespaces cannot be called collision-free merely because the selected name is absent from `properties`.

Even when policy requires justification, its advertised schema property stays optional; admission produces the specified explanatory error when absent. The chosen extraction key is frozen in each admitted request. Descriptions or unrelated catalog additions do not end existing requests. Existing retry matching uses the stored extraction context. [JSON Schema's object constraints](https://json-schema.org/understanding-json-schema/reference/object) explain why arbitrary insertion is insufficient. A universal wrapper/metadata interface requires an owner decision rather than silently narrowing the spec's promise.

Local upstreams are supervised unmodified child processes with private stdio, an explicit minimal environment and BOGO-only private state. Remote upstreams use only owner-configured URLs/credential references; disable automatic credential-bearing redirects. The agent cannot choose destinations, launch commands, headers or credential paths.

`~/.bogo` is owner-only. `secrets.toml` is an owner-owned regular file with mode 0600 and validated path ownership. Credentials/private child state never enter agent mounts or allowed filesystem-upstream roots. Upstream processes legitimately receive their own credentials; that is not permission for an agent-accessible tool to read them. No Mac Keychain writes are used for upstream credentials. Secret wrappers prevent accidental formatting, and diagnostic/results handling withholds known credential reflection rather than assuming a string cannot contain a secret. Request argument values are logged as required; injected connection credentials are not.

### 3.6 Durable coordination and the actual sender gate

Use one SQLite database, one writer and one installation process lock. WAL, foreign keys, `synchronous=FULL` and macOS `fullfsync=ON` are deliberate settings; read back effective settings. [SQLite documents full-sync behavior](https://www.sqlite.org/pragma.html#pragma_fullfsync) separately from normal synchronization. Registry state, request facts, audit and endpoint delivery obligations commit in the same transaction. There is no independent registry file competing with an audit log.

Compute a Lean transition, commit its facts/audit/outbox effects, then publish effects or acknowledge acceptance. On failed commit, publish nothing and restore the committed view or terminate. Pure reads and already-applied duplicates do not create unnecessary durable transitions. The database stores security facts and recovery obligations, not an executable snapshot that can revive old sessions.

rmcp retains JSON-RPC ID allocation and response correlation. Exact child/HTTP adapters intercept outbound `tools/call` messages **after** SDK allocation/queueing and before transport submission. A private marker identifies a staged call; agent-supplied metadata cannot register one. The staged record binds call, reservation, upstream connection generation, original tool name, argument presence, full exact tree and rmcp's assigned JSON-RPC ID. The marker is stripped from the wire. All other protocol messages use SDK serialization.

```text
stage(rmcpAssignedMessage, immutableDispatch) -> PreparedSend | Unavailable
reserve(preparedId) -> durable irreversible consumption
tryHandoff(preparedId, permit) -> Started | NotStarted
```

The concrete order is:

1. Maintain upstream health/credentials independently. Stage the SDK-assigned envelope and exact bytes behind a closed transport gate. No tool request bytes can leave during staging. If the connection or writer cannot be prepared, reject without holding a settled request for future reconnection.
2. Run Lean `Reserve`; commit consumption, request/policy/approval evidence and dispatch intent. Allowed attempts also get a durable intent before their effects, but have no approval request or approver traffic.
3. At the ready sender, serialize a final gate with lifecycle/control events, sample current time, and run Lean `Handoff`. Drain security events already observed ahead of that handoff. Sender and coordinator share an ordering boundary; waiting for the Lean thread occurs before the final handoff linearization, not as an unobserved delayed permit queue.
4. Initiate the prepared transport's irreversible send in that same gate turn. There is no SDK queue, credential refresh, reconnect or asynchronously awaited connection setup after final authorization. If readiness was lost and zero bytes were handed off, return NotStarted and retain consumption. A permit cannot be stored and used later.
5. Complete the already-started frame without replay, receive the result, record outcome, filter and return it. Losing the result does not recreate authority.

A custom `StreamableHttpClient::post_message` serializer is an integration seam, not proof of this boundary. rmcp's [request channel](https://docs.rs/rmcp/3.10.0/src/rmcp/service.rs.html#889-956) and [HTTP worker](https://docs.rs/rmcp/3.10.0/src/rmcp/transport/streamable_http_client.rs.html#2016-2145) queue and may recover sessions. All such queues must precede the final sender gate; disable `reinit_on_expired_session` for tool-call dispatch and prevent retries at every lower layer. If a stock HTTP adapter cannot expose the prepared boundary, BOGO owns that transport implementation while retaining rmcp protocol/response handling. A typed ticket alone is insufficient.

The linearization point is authorization plus immediate irreversible transport handoff, not completion inside the provider. Once bytes are handed off, later expiry/cancellation cannot recall them. Partial writes and HTTP buffering may leave an unknown outcome; no transport reconnect may resend that call.

At creation, derive both signed wall-clock times and a sleep-aware monotonic deadline from the configured lifetime. When an expiry exists, acceptance requires `wallNow < expiresMs` and `continuousElapsed < expiresMs-createdMs`; equality rejects. Check on approval, reservation and final handoff, not only timer firing. A rollback cannot extend lifetime; a forward jump may end it earlier. Without configured expiry, neither bound exists. The phone countdown is advisory and terminal synchronization overrides it. Resume revalidates liveness/readiness. Uncertain time or liveness refuses handoff.

Crash classification is conservative. A committed consumed intent without a durable definitive outcome is **outcome unknown** if it could have reached handoff. Only positive evidence supports not-sent. A missing later `forwarded` entry is not such evidence. Never replay either unknown or consumed-not-sent work. SQLite cannot transact with arbitrary providers: at-most-once forwarding is achievable, guaranteed exactly-once completion and universal “silence means nothing happened” after a possible send are not.

### 3.7 Wait, retry, grouping and ending

Wait mode holds one tool call until approval, denial or ending. Pending-and-retry creates a logical request that remains alive after the initial pending response while its session lives. Match session, upstream, tool, exact arguments and justification. Matching retries attach before the flood-limit allocation check. Approval settles without sending; the first matching live retry consumes and dispatches. Concurrent retries cannot independently execute. Once terminal, a later identical call may create a new nonce and needs fresh approval. There is no session-long result cache or business-operation deduplication; a lost-result retry can cause a fresh prompt, never an automatic second execution.

Wait-mode duplicates remain separate requests/nonces. Group display by agent, upstream, tool, exact arguments, justification and display hints. Opening a group selects one live member and its session. Approve/Deny decide only that member; the count is never a batch grant. Pause is the specified agent-wide denial mechanism. Collapse APNs alerts using an opaque keyed group digest; a notification always identifies one concrete request for Deny.

Ending invalidates unsent authority, persists its terminal version and schedules notices/retraction. A late signature is rejected even if the relay withheld the ending from the phone. Phone offline does not end a request; delivery continues while the request remains live. Restart terminates every old generation's sessions before admission and creates terminal reconciliation work, never runnable recovered requests.

### 3.8 Approver route, encryption and registration

```text
ApproverRoute:
  register(transaction, ownerInteraction) -> VerifiedRegistration
  deliver(registration, messageId, payload) -> RelayReceipt
  receive() -> UnverifiedEnvelope
  reconcile(registration, cursor) -> AuthenticatedStateUpdates
```

A transport receipt does not establish approval or endpoint acceptance. Route registration must establish the exact-rendering and user-verification contract. The core receives identity/generation and signed evidence, not relay details. Normal BOGO includes only the iPhone route; the software approver exists only in a separate development build and cannot be registered in normal BOGO.

The Mac stores independent installation identity, X25519 channel and Ed25519 mailbox-auth keys in protected files. Each phone/Mac registration has its own Secure Enclave P-256 approval key, X25519 channel key and Ed25519 mailbox key. Phone channel keys use BOGO-only device-local Keychain protection usable after first unlock; they cannot produce approval signatures. Re-registration creates a new generation and retains historical public evidence.

Use authenticated HPKE with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305. Each envelope uses one fresh encapsulation and one sealed plaintext. Persist ciphertext before send and retransmit identical bytes; never recreate different ciphertext under a retained message identity.

```text
Header = "BOGOE2E\0" || u16(1) || u16(kind)
       || installationId[32] || senderId[16] || recipientId[16]
       || u64(registrationGeneration) || u8(direction) || messageId[32]
Envelope = Header || bytes(encapsulation) || bytes(ciphertext)
HPKE info = "BOGO-CHANNEL\0v1" || installationId || senderId || recipientId
            || u64(registrationGeneration)
HPKE aad = Header
messageId = random 32 bytes allocated once per persistent outbound record
```

Header kinds/identifiers reveal routing metadata, never arguments or justification. The payload kinds are request, state/terminal update, approval, denial, pause, self-revocation, application receipt, push-token update and synchronization. Every request-scoped payload carries full installation/boot/sequence identity. Approval contains the raw signature; Deny/Pause/remove use the separate authenticated channel, not an approval signature. No control message can count as approval.

Receivers authenticate before registering a message ID as seen. Atomically persist `(generation, messageId, payloadIdentity)`, the state change and acknowledgement obligation. Exact duplicates reissue the prior receipt; conflicting payload identities reject. Accept unseen out-of-order messages. Terminal versions/tombstones stop a delayed request from resurrecting. Push-token updates have a persistent sequence; pause carries the agent's current control epoch delivered in authenticated request/state envelopes. [HPKE does not provide replay protection by itself](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.3).

**Add Mac** uses a commitment-based short-authentication-string exchange through BOGO's own rendezvous:

1. The owner runs `bogo approver add`; the Mac creates a transaction, ephemeral X25519 contribution and random nonce, and publishes a commitment to that role-tagged contribution, transaction and offered protocol choices. Its committed secret contribution is not revealed early.
2. Add Mac lists offers with untrusted labels. The phone selects one and fixes its ephemeral contribution/nonce and selected protocol. The Mac accepts one peer for that transaction; neither endpoint silently replaces participants or restarts an attempt.
3. The Mac reveals its commitment. The phone checks it; both validate keys, roles, transaction and protocol and reject an all-zero shared secret. Derive transcript-bound SAS material from the ephemeral shared secret through HKDF. Rejection sampling produces six decimal digits without modulo bias.
4. Both display those digits for this attempt. The owner confirms on the Mac first. Its transcript-authenticated confirmation enables phone confirmation. A mismatch or abort requires explicit owner restart. The commitment discipline follows the [SAS rationale](https://spec.matrix.org/v1.16/client-server-api/#short-authentication-string-sas-verification); the six-digit adaptation is a crypto integration assumption, not a Lean theorem.
5. Face ID confirms on the phone. The app internally creates its protected approval key and proves possession over the registration transcript/fresh challenge. It generates channel/mailbox keys and obtains App Attest evidence binding the challenge, full transcript, approval key, channel/mailbox keys and version. Registration phases after comparison use authenticated single-shot HPKE with transcript-bound context and unique phase IDs.
6. The Mac verifies all evidence and commits the registration plus its confirmation outbox atomically. Re-registration atomically revokes the prior generation and installs the new one. The phone activates only after receiving the authenticated committed result and durably storing it.
7. Lost confirmation is recovered by the same transaction ID and a durable committed-result lookup authenticated by the established registration/transcript. Neither endpoint relies on an in-memory lobby surviving. Before commit no trust exists; after commit retries return that one result, not a second registration.

Persist local transaction state before externally acknowledging each phase. Resume with exact stored messages/key material or abort explicitly, never reconstruct an interrupted encryption state by reusing nonces. Registration confirmation and self-revocation acknowledgement remain recoverable after restart. A revoked generation may authenticate only its narrowly scoped duplicate cleanup acknowledgement request; it never regains decision authority.

**App Attest validation** is one BOGO function with named responsibilities. Ciborium parses the attestation/authenticator CBOR with duplicate/shape bounds. macOS Security validates certificate signatures/chain against the pinned Apple App Attest root, not arbitrary system trust. Strict DER parsing extracts the credential-certificate nonce extension. BOGO computes the challenge/transcript client-data hash, nonce, public-key identifier and RP ID; checks the counter, credential ID, encoded key, AAGUID/environment and attested `apple_validation_category_01` and `apple_bundle_version_01` against the configured accepted distribution/build policy. Retain verified key, evidence and receipt as Apple's [current procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) requires. No opaque library success boolean substitutes for those checks; no attestation-unavailable fallback exists.

App Attest attests its own key and app-generated evidence, not the ACL on a separate supplied key. The accepted genuine build creates the approval key internally and accepts no replacement key. Genuine app behavior and OS/enclave enforcement are explicit assumptions. The actual host uses iOS 26, team `AX3C2B78YD`, bundle `com.johansardar.applebridge.ios` and development signing in [project.yml](/Users/johansardar/apple-bridge-iphone/ios/project.yml:4). Confirm the provisioned App ID prefix rather than universally equating it to the team. Accepted BOGO-capable distribution/version is an owner decision; development evidence is not silently equivalent to production trust.

### 3.9 Independent relay, reconciliation and direct APNs

The relay has its own selected port, service account, service definition and SQLite database at `bogo.eilmer.si`. It has no Apple Bridge application dependency. Public TLS uses a DNS-01 certificate and a scoped Cloudflare credential outside relay application state. The relay necessarily has TLS material but no approval, channel-decryption, upstream or APNs secret.

```text
POST /v1/auth/challenge {mailboxPublicKey} -> one-use challenge
POST /v1/auth/verify {challengeId, signature} -> bounded bearer
POST /v1/allow {senderMailboxIds} -> receipt
POST /v1/send {to, messageId, ciphertext} -> durable receipt | full | conflict
POST /v1/fetch {cursor, wait} -> opaque messages
POST /v1/ack {messageIds} -> receipt
POST /v1/retract {to, messageIds} -> receipt
POST /v1/lobby/offer; GET /v1/lobby
POST /v1/lobby/{transaction}/message; POST /v1/lobby/{transaction}/fetch
```

Mailbox identity derives from its public authentication key. Challenges bind the service and mailbox. Only the mailbox owner fetches, acknowledges or changes its sender allowlist; retract is sender-scoped. Persist ciphertext before success. Full storage explicitly refuses; no false durable receipt. Operational mailbox bounds never define request expiry. Lobby offers require the active local owner transaction; stale offers are not trusted identity. A hostile relay can delay/drop/reorder/replay, but cannot forge endpoint authority.

Endpoints retain delivery obligations until an application acknowledgement or authoritative ending. A phone persists inbound request bytes before `seen` or relay deletion, and persists decisions before sending. Mac acceptance, audit and receipt/outbox commit together. After foreground/reconnect, authenticated synchronization returns current pending entries, terminal versions, agent epochs and committed registration/removal status. It repairs lost messages independently of their order. A boot-generation update helps grey stale requests but is not the only recovery mechanism. Relay retention limits can delete copies only without discarding the endpoint's still-live obligation to retransmit/reconcile.

Self-revocation immediately destroys local signing capability; an authenticated removal outbox and channel keys remain until Mac acknowledgement. Mac revocation commits first. Duplicate cleanup messages can retrieve that stored acknowledgement even after authority is revoked. The phone says “Removed locally; awaiting Mac acknowledgement” while offline, not “revoked everywhere.”

The Mac sends time-sensitive APNs alerts directly with the owner's existing provider key and app topic. Payloads contain opaque BOGO routing plus generic “Approval requested,” never argument/justification content. The category has Deny only; tapping opens full review. Push token/environment updates use BOGO's authenticated encrypted channel. Use opaque keyed group digests for collapse/thread identities.

APNs is a best-effort alert/wake hint, not a durable inbox. [Apple's delivery documentation](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns) allows notification coalescing and delayed/lost delivery; shared-app alerts may displace one another. Notification permissions, force-quit and OS scheduling can prevent background work. Deny is queued whenever iOS grants execution and reconciled later; do not promise immediate background handling or interpret APNs acceptance as phone receipt.

### 3.10 iPhone feature and host replacement

The local Swift package has independent protocol/model, crypto, store, transport and view/facade targets. Its host-facing API is deliberately narrow:

```swift
@MainActor public final class BOGOFeature {
    public var rootView: AnyView { get }
    public static var notificationCategories: Set<UNNotificationCategory> { get }
    public func ownsNotification(_ payload: [AnyHashable: Any]) -> Bool
    public func receiveNotification(_ payload: [AnyHashable: Any], action: String?) async
    public func updatePushToken(_ token: Data, environment: APNsEnvironment) async
    public func sceneBecameActive() async
}
```

The host mounts BOGO instead of Approvals, routes its categories before legacy handling and fans out the shared push token. BOGO works on a phone never registered with Apple Bridge's Mac. Its keys and application-support SQLite are independent of host identity/storage. Keychain namespace and protection classes separate approval keys from background transport keys.

Remove the old Approvals feature and notification actions, not merely its tab label. Incoming Apple Bridge approval jobs are ignored without a decision so they expire on the unchanged Mac. Photo/audio calls always return the existing protocol's explicit denied/rejected outcome and cannot reach capture UI or legacy approval code. Existing coupling is present in [CaptureCapability.swift](/Users/johansardar/apple-bridge-iphone/ios/Capabilities/Capture/CaptureCapability.swift:6) and [CommandHandlers.swift](/Users/johansardar/apple-bridge-iphone/ios/Delivery/CommandHandlers.swift:5). Preserve unrelated capabilities and host registration behavior. Merge notification categories rather than replacing unrelated ones.

**Inbox, History, Macs:** store exact request bytes, decoded view and state version; group duplicates without merging nonces. Ended/settled entries are grey and non-approvable. History distinguishes local signing, Mac acceptance and known/unknown execution. Macs lists registrations, Add Mac, removal and re-registration state. A receipt is not successful execution.

**Review:** render from the exact received bytes being signed. “Will execute (exact)” contains upstream/tool, every argument, highlighted values and “Requested by” the trusted owner-assigned name. Full raw values remain inspectable; no summary or truncation hides data. Make control, bidirectional and zero-width characters visible; expose significant whitespace. Never interpret agent text as markup or instructions.

“Agent's reason (unverified)” contains justification, self-reported name, a session tag derived from the session's random suffix rather than its shared boot prefix, and mismatch warnings. Money formats accept integer token text within supported bounds and apply integer-scale arithmetic; noninteger/exponent/out-of-range tokens remain raw with a formatting warning. Display the original token alongside a formatted highlight. No binary floating point is used.

The mismatch recognizer accepts explicitly currency-marked forms such as `$47`, `$47.00`, `47 USD`, `USD 47` and `47 dollars`. Compare exact currency/value pairs against all successfully rendered currency fields; warn for an amount matching none. Bare numbers, times and flight numbers are ignored. No recognized amount means no warning. This is deliberately a heuristic, not a claim to understand prose.

Approve exists only on full review after the required short delay for that exact request; changing the group member resets it. Each approval uses a fresh authentication context without a biometric reuse window. The per-registration Secure Enclave P-256 key has `privateKeyUsage`, `biometryCurrentSet` and device-only passcode-protected accessibility. Require Face ID; no passcode-only, Touch ID or software-key fallback. The signing operation itself enforces biometrics, not merely an earlier UI check. [Secure Enclave guidance](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) and [biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) define the mechanism. Enrollment change/key loss/reinstall requires registration again.

Deny has an optional note and can run through the separately authenticated control channel from the notification. Pause is one tap and uses the authenticated current control epoch; only the Mac unpauses. A phone clock/countdown cannot authorize the Mac. Persist a signature before transmission, allowing transport retry without a second signing ceremony.

The phone-first stand-in supplies real protocol vectors, registration, App Attest, encryption, relay and direct APNs, but has no production upstream execution. It is separate from the development-only software approver used for k-of-n without a second phone.

### 3.11 Output filtering and audit

`filter(rules, CallToolResult) -> FilteredResult | WithheldRepresentation` is a deterministic projection outside Lean. Compile selectors into unambiguous structural paths with explicit strip/redact actions. Apply them to structured content, JSON text copies, metadata, resource links and embedded resources. Withhold any representation a configured rule cannot safely process, rather than returning an unfiltered copy or rerunning the tool. Without filters, return the real upstream result. Omit an output schema that cannot truthfully describe the filtered result; simply deleting a property does not handle every JSON Schema constraint. Field filtering is not universal secret detection in prose/binary data.

The audit is an append-only SQLite table with canonical immutable event bytes, monotonic sequence and predecessor hash. Query/search indexes are derived. Record every protected attempt and its exact request, justification, decision/reason/times, responding identities and original evidence. Record registration/revocation generations, pause epochs, frozen local policy, consumption, dispatch ordering evidence and known/unknown outcomes. Record allowed and denied attempts too, as required by Scenario 15. Flood/paused/deny rejections create no push. Do not store successful result bodies as a retry cache.

`bogo log verify` checks canonical hash continuity, reconstructs historical registries and request policy, verifies original signed bytes and counted identities, and evaluates authority at final dispatch—not only at the earlier threshold event. Retained invalid/late evidence is reported as rejected evidence, not falsely counted or confused with a corrupt valid approval. Later revocation does not invalidate earlier valid execution. Export includes immutable event bytes and chain/head; human/CSV views are derived. Escape terminal control characters.

A hash chain detects changes relative to retained history, not replacement by a valid earlier prefix without a retained head. Owner-kept exports can anchor comparison; no transparency service is added. Corrupt committed history stops affected operation. SQLite handles incomplete transactions under its storage assumptions. Do not infer not-sent from missing post-send evidence.

### 3.12 Owner operation, isolation and selected upstreams

```text
bogo init
bogo start | stop
bogo approver add "<name>" | list | revoke <name>
bogo agent add "<name>" | list | revoke <name> | pause <name> | unpause <name>
bogo tools
bogo request list | cancel <id>
bogo log [search ...] | export | verify
```

Adding an existing approver name performs explicit re-registration with retained history. Initialization creates protected config/state and a launchd LaunchAgent. Start validates before serving. Unexpected exit is supervised; stop closes admission and commits unsent endings. Mutating commands use the owner socket while running, or acquire the same writer lock and use the same library while offline. No dashboard or remote owner API exists.

**Sandbox:** a dedicated internal Docker network and fixed-destination TCP forwarder expose only BOGO. [`--internal` still permits gateway-host communication](https://docs.docker.com/reference/cli/docker/network/create/#internal), so namespace policy is the actual boundary. A trusted short-lived initializer enters the agent namespace before untrusted code, installs default-deny rules for both directions/families, allows only the fixed forwarder address/port and established replies, and exits. An inert holder retains the namespace. The agent starts only after successful setup, runs non-root with all capabilities dropped/no-new-privileges and cannot alter that policy.

Do not broadly allow loopback: [Docker's embedded resolver is 127.0.0.11 and forwards external lookups](https://docs.docker.com/engine/network/#dns-services). Block that destination and outside DNS explicitly in the effective rule order, accounting for Docker's resolver NAT; any needed loopback service gets only its exact allow. Drop IPv6 bypasses. Namespace recreation requires initialization again. The forwarder connects to one configured address/port, parses no HTTP, exposes no CONNECT/SOCKS or general IP route, and cannot choose an agent-provided destination. BOGO itself rejects unsupported paths/methods and validates authentication/Host/Origin.

No Docker socket, host home, secrets, owner socket or private upstream state enters the container. Only the agent's own BOGO token does. The specified bypass executable runs inside that actual environment and observes direct upstream/relay/host reachability, DNS/IPv6, credential discovery, policy modification and unauthenticated/forged protected calls. No additional verification framework or timed run is introduced.

Filesystem roots are owner-selected nonsecret directories. BOGO advertises no roots capability, because the [official filesystem server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) can let client roots replace command-line roots. An allowed read must not expose credentials.

Use pinned installed `link-cli --mcp` and the official filesystem server unmodified. [Link's documentation](https://github.com/stripe/link-cli/blob/main/README.md) describes `--test` as testmode SpendRequest/payment-credential behavior, not a universal test login. Some flows lack testmode. Discover actual names/fields, highlight testmode beside money and use only confirmed testmode operations with test credentials. A SpendRequest/credential is not a completed merchant charge. No live purchase is authorized by this architecture.

Link's rotating private auth file conflicts with literal credential storage in TOML and remains a specification decision. The official filesystem server has no public-sharing-link tool; select a real returned field/tool for filtering instead of inventing one. Literal BOGO-only egress also excludes an in-container conventional cloud model connection; inference placement or a permitted exception requires an owner decision.

## 4. Data flows

| Scenario | Flow |
|---|---|
| 1. Payment approved | Authenticate Trip planner; exact-parse confirmed testmode arguments; Lean strips justification and encodes request; commit audit/outbox; encrypted delivery and direct APNs; phone renders real amount and trusted name; Face ID signs original bytes; verify/settle; stage SDK envelope, durably consume, final-check/handoff once; filter/log/return Link's real result. |
| 2. Lie in reason | Signed 50000 minor units renders $500.00; recognized $5 claim warns; authenticated durable Deny carries “wrong amount”; Lean ends authority; return “The owner denied this action. wrong amount”; no upstream send. |
| 3. Changed call/session/replay | Changed number text, justification or session is a different request needing new approval; old signature cannot authorize it. Duplicate votes count once; consumed identity never dispatches again. |
| 4. Allowed read | Lean resolves allow; durable attempt and prepared one-shot send; no phone request; record/filter/return actual result. |
| 5. Denied tool | Per-agent catalog hides it by default; direct call still rejects/logs without upstream execution. |
| 6. No answer | Observed cancellation/disconnection or configured expiry ends unsent authority; persist terminal state and notify/reconcile phone. Late approval rejects. Use “action was not performed” only with no-send evidence. |
| 7. Phone offline | Request remains pending while its session/call is live; delivery/reconciliation retries with no default expiry; only still-live requests can dispatch after reconnection. |
| 8. Add phone | Commitment SAS and six digits; Mac confirmation first; Face ID creates/proves protected key; App Attest binds accepted app evidence; atomic registration/confirmation outbox; recover by the same transaction ID. |
| 9. Add agent | Persist named identity and token verifier; print token once; authenticate each request and bind session; missing/wrong token refuses connection. |
| 10. Stolen phone | Without Face ID no approval-key operation. Owner revokes one generation; late votes reject; other approvers remain independent. |
| 11. Face ID changed | Approval key becomes unusable; phone requires registration again. Replacement generation inherits no approval evidence. |
| 12. Two approvers | Send identical bytes to each eligible approver; count distinct identities; 2-of-2 settles at second valid identity; default denial veto applies while collecting; final gate rechecks registrations. |
| 13. Filter result | Run the actual selected tool once; strip/redact across all output copies or withhold unsafe representations; never retry because filtering failed. |
| 14. Escape | Namespace permits only fixed BOGO route; credentials absent and filesystem roots constrained; token alone cannot authorize a protected call. |
| 15. Verify record | Recompute chain, reconstruct historical keys/policy/control order, verify original signatures and dispatch evidence; distinguish rejected evidence, not-sent and unknown outcomes. |
| 16. Flood | Group exact duplicates without combining nonces; collapse alerts; pending-limit excess rejects/logs quietly; epoch-bound pause denies pending and rejects every new request; Mac unpause advances epoch. |
| 17. Two upstreams | Independent mapping/connections/preparation keep Stripe and filesystem separate; phone waits hold neither a DB transaction nor another upstream's connection. |
| Pending-and-retry | Initial pending response; identical same-session retries attach; approval settles; first live matching retry consumes once; later terminal-following call needs a new nonce and approval. |
| Owner cancel/remove | Mac cancel ends unsent authority. Phone removal destroys local signing and retains self-revocation delivery until durable Mac acknowledgement. |
| Legacy phone requests | Ignore old approval jobs; explicitly deny capture; unrelated host behavior remains; BOGO registration/notifications work without Apple Bridge Mac registration. |

Model-readable outcomes are the actual filtered upstream result; specified owner-denial text plus note; “Approval was not received in time; the action was not performed” for unsent ending; pending instructions for identical same-session retry; precise rejection reasons; and truthful “execution outcome unknown; not retried” after possible send, subject to the explicit specification decision.

## 5. Failure

| Failure | Safe behavior and recovery |
|---|---|
| Malformed input/config/unsupported schema | Reject affected admission/startup explicitly; never repair ambiguity into an authorized call. |
| Crash while collecting/settled | Recover durable facts; close all old-generation sessions before traffic; generate terminal reconciliation work; never resume executable authority. |
| Crash after consumption/possible send | Keep consumption spent; unresolved handoff is unknown unless positively proved not-sent; never replay. |
| Cancel/expiry during commit or SDK scheduling | Final gate runs after those waits and honors ordered lifecycle/current time; refusal retains consumption. |
| Upstream unavailable before handoff | Reject not-sent; no settled-call reconnect queue. Health recovery applies only to future calls. |
| Upstream lost result/partial write | Preserve unknown outcome and evidence; no repeated execution. |
| Phone crash after signing | Reload persisted exact decision/outbox and retry transport without signing again. |
| Phone crash after receipt | Receipt was issued only after durable inbox write; synchronization repairs state. |
| Lost/reordered relay data | Durable endpoint obligations, exact IDs, receipts and reconciliation repair delivery; terminal versions prevent resurrection. |
| Dropped APNs or unavailable background execution | Inbox/outbox remain authoritative; reconcile when iOS runs; no notification-timing promise. |
| Registration/revocation reply lost | Recover committed result/ack by transaction or generation with narrowly scoped authentication; never restore revoked authority. |
| Late vote/replaced key | Ignore/log or reject; do not reopen settlement or transfer signatures to new generations. |
| Delayed pause after unpause | Epoch mismatch refuses it, even on first delivery. |
| Biometric key invalid/attestation unavailable | No fallback; require registration when needed, retry transient transport separately. |
| Disk full/corrupt/unavailable | Stop affected admission/effects; no acknowledgement of uncommitted acceptance; report corruption. |
| Clock adjustment/sleep | Enforce both wall and derived continuous bound; revalidate transports after resume; uncertainty cannot authorize. |
| Filter error | Withhold unsafe output while retaining actual execution status; never rerun. |
| Sandbox/forwarder failure | Agent loses its only route; no direct fallback; observed call/session termination ends authority. |

Automatic recovery means durable local repair and idempotent message delivery, not resurrection of dead sessions, replay of uncertain provider effects or recovery from destroyed storage.

## 6. Data and versions

```text
~/.bogo/                     0700
  bogo.toml                 owner policy, explicit format version
  secrets.toml              0600, upstream/APNs credential values
  state.sqlite              registry, audit, requests, intents, outboxes, receipts
  keys/                     independent Mac private key files, 0600
  run/bogo.sock             owner-only control socket
  run/writer.lock           single installation writer
```

Tables include installation/boot generation, agents/token verifiers/control epochs, approver generations and attestation evidence, immutable request bytes/resolved policy, attempts/reservations/outcomes, canonical audit, endpoint messages/receipts and registration transactions. Unique constraints enforce one consumption per request, one counted identity per request and one consistent payload per message identity. Historical records support verification/reconciliation, never reusable grants. No upstream result cache is required.

| Configuration | Contents |
|---|---|
| `version` | Explicit schema; unknown keys/versions reject. |
| `server` | Local binding and body/structural bounds; no hidden session expiry. |
| `relay` | Independent HTTPS URL/port and operational mailbox bounds. |
| `apns` | Key reference, key ID, topic, environment. |
| `upstreams.<id>` | One local command/args or remote URL, credential env/header references, private state contract. |
| `defaults` | Approve default, hidden/show-denied behavior, owner-chosen pending limit. |
| `tools.<name>` | Policy, required/optional justification, typed highlight paths/formats, optional expiry, approvers, any/k requirement, denial rule, wait/pending_retry, strip/redact selectors. |
| `agents.<name>.tools.<tool>` | Per-agent policy/approver overrides with validated effective threshold. |
| `iphone` | Approved distribution/build evidence, supported wire versions and owner-chosen short review delay. |

The phone stores exact requests, versions/tombstones, decisions, message obligations, per-Mac registrations and interrupted transactions. The relay stores only routing/public-auth data and ciphertext. Operator values absent from the spec remain explicit setup choices, not fabricated defaults. Alternate native credential files are not silently admitted by calling them TOML references.

Version request encoding, bridge ABI, registration transcript, channel envelope/control messages, audit, database and configuration independently. Unknown critical tags, invalid domains and trailing bytes reject. One request has one encoding and all counted approvers sign exactly those bytes. Migrations run transactionally before admission; historical bytes are never rewritten. Pin Lean/Cargo/Swift/upstream dependencies against actual integration behavior.

## 7. Repo layout

```text
bogo/
  crates/
    bogo-domain/      bogo-lean/        bogo-json/
    bogo-mcp/         bogo-config/      bogo-runtime/
    bogo-store/       bogo-upstream/    bogo-crypto/
    bogo-delivery/    bogo-relay/       bogo-cli/
    bogo-shim/        bogo-sandbox/
  lean/Bogo/
    Domain.lean Encoding.lean Policy.lean Transition.lean
    Properties.lean Exports.lean
  protocol/          wire documentation and Lean-generated vectors
  development/
    phone-standin/   independent real registration/delivery, no upstream execution
    software-approver/  separate nonproduction threshold demonstration
  sandbox/           namespace initialization, container topology, bypass executable
  deploy/macos/      LaunchAgent
  deploy/relay/      independent service, TLS and firewall configuration
  docs/              configuration, threat model, proved-and-assumed
  README.md

apple-bridge-iphone/
  Packages/BOGOFeature/Sources/
    BOGOProtocol/ BOGOCrypto/ BOGOStore/ BOGOTransport/ BOGOFeature/
  ios/App/           tab and facade edge
  ios/Delivery/      category routing/token fan-out, legacy-job retirement
  ios/Capabilities/Capture/  explicit denied behavior
```

Domain/kernel imports no SDK/UI types. Only the bridge handles Lean ownership. MCP/delivery cannot import the concrete sender; runtime constructs private dispatch identities and the final gate. The store cannot execute. Relay imports framing/routing, not policy/decryption. Normal BOGO excludes development registration authority and the software approver.

Phone protocol/model imports no SwiftUI/host code; crypto/store import no views; transport cannot manufacture approval signatures. The host imports only the facade. BOGO targets never import Apple Bridge identity, registration, approval jobs or Mac service paths. Host integration changes do not touch any Apple Bridge Mac repository.

## 8. Build order

1. Define exact values/request/control contracts, Lean encoder/decoder and vectors, phone facade and transport ports. These shared prerequisites are not a production Mac service.
2. Build the phone model/store/review and host replacement against the stand-in; no real upstream effect is available.
3. Add real independent HPKE, SAS/App Attest, relay and direct APNs to the stand-in; complete Inbox/History/Macs, protected key operations, durable delivery and reconciliation.
4. Implement Lean policy/lifecycle/threshold/consumption proofs, then its dedicated-thread ABI and transaction/coordinator interfaces.
5. Connect Mac registries, owner configuration, CLI, supervision and production approver delivery through those interfaces.
6. Integrate exact rmcp ingress/shim and SDK-assigned staged transports; establish the final sender boundary, output filtering and historical audit verification.
7. Assemble mode, threshold, expiry, revocation, pause and flood behavior through the proved transitions; keep the software approver in its separate development build.
8. Assemble actual Docker namespace isolation and its specified bypass executable; configure confirmed Link testmode/filesystem operations after relevant owner decisions; write the quick start, config reference, threat model and proved/assumed documentation from the implemented contracts.

No interim normal-use path relies on old unrestricted phone keys, Rust authorization substitutes or Apple Bridge Mac services.

## 9. Libraries

| Choice | Why | Source |
|---|---|---|
| Lean 4 / Lake | Required executable decision/encoding code compiled to C with proofs | [Lean](https://github.com/leanprover/lean4), [FFI](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) |
| rmcp 3.10.0 baseline | Required SDK; request extensions and custom transport seams, with explicit staging | [SDK](https://github.com/modelcontextprotocol/rust-sdk), [published service source](https://docs.rs/rmcp/3.10.0/src/rmcp/service.rs.html), [HTTP seam](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html) |
| BOGO lexical parser/writer | Exact number tokens and duplicate-key rejection, without SDK normalization | [JSON grammar](https://www.rfc-editor.org/rfc/rfc8259) |
| Serde / serde_json | Ancillary envelopes/config views and nonsigned results, never authoritative arguments | [serde_json](https://github.com/serde-rs/json) |
| Tokio, Axum/Hyper, Reqwest | Async IO, controlled transport integration, relay and direct APNs HTTP/2 | [Tokio](https://github.com/tokio-rs/tokio), [Axum](https://github.com/tokio-rs/axum), [Reqwest](https://github.com/seanmonstar/reqwest) |
| rusqlite / SQLite | One transactional local authority; separate relay and phone stores | [rusqlite](https://github.com/rusqlite/rusqlite), [atomic commit](https://www.sqlite.org/atomiccommit.html), [pragmas](https://www.sqlite.org/pragma.html) |
| Rust hpke / CryptoKit HPKE | Standard authenticated single-shot envelopes across Rust/Swift | [rust-hpke](https://github.com/rozbb/rust-hpke), [CryptoKit](https://developer.apple.com/documentation/cryptokit/hpke), [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) |
| RustCrypto p256, sha2, hkdf; ed25519-dalek | Approval verification, hashing/KDF and separate mailbox authentication | [curves](https://github.com/RustCrypto/elliptic-curves), [hashes](https://github.com/RustCrypto/hashes), [KDFs](https://github.com/RustCrypto/KDFs), [dalek](https://github.com/dalek-cryptography/curve25519-dalek) |
| macOS Security, Ciborium, strict DER | Named App Attest chain, CBOR and extension parsing with explicit BOGO validation | [security-framework](https://docs.rs/security-framework/latest/security_framework/), [Ciborium](https://github.com/enarx/ciborium), [DER](https://github.com/RustCrypto/formats/tree/master/der), [Apple](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) |
| TOML, Clap | Owner config and CLI | [TOML](https://github.com/toml-rs/toml), [Clap](https://github.com/clap-rs/clap) |
| Swift CryptoKit, Security, LocalAuthentication, DeviceCheck | Secure Enclave/Face ID, HPKE and App Attest | [Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [DeviceCheck](https://developer.apple.com/documentation/devicecheck) |
| SwiftUI, UserNotifications, URLSession, SQLite C | Native independent phone UI, notification edge and persistent delivery | [SwiftUI](https://developer.apple.com/documentation/swiftui), [notifications](https://developer.apple.com/documentation/usernotifications), [SQLite C](https://www.sqlite.org/cintro.html) |
| Rustls / lego DNS-01 | Independent relay TLS and scoped Cloudflare certificate issuance | [Rustls](https://github.com/rustls/rustls), [lego](https://go-acme.github.io/lego/dns/cloudflare/) |
| Docker, fixed TCP forwarder, Link CLI, official filesystem server | Required isolation and unmodified upstreams | [Docker networking](https://docs.docker.com/engine/network/), [Link](https://github.com/stripe/link-cli), [filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) |

Resolve/pin compatible versions rather than claiming every newest library is already integrated. None of these dependencies is formally verified by the Lean theorem. Transport scheduling, mailbox recovery, Swift decoding and app-key creation remain concrete implementation obligations.

## 10. Risks and open questions

| Risk | Consequence | How to establish the boundary |
|---|---|---|
| SDK normalization/send bypass | Approved bytes differ from forwarded call | Follow lexical tokens through shim, request extensions, Lean and exact transport; inspect every tool write entry. |
| Queue after final authorization | Expired/revoked authority reaches sender late | Trace the SDK-assigned message through preparation, durable intent, final ordered gate and irreversible submission. |
| Universal schema/MCP promise | Valid unmodified tools cannot express justification or interactive execution | Inspect actual schemas/protocol interactions, identify unsupported transformations and resolve the interface decision. |
| SAS integration | Comparison does not bind intended peer/transcript | Examine commitment/reveal ordering, role/key/version binding, owner confirmations and interrupted exchange recovery. |
| App Attest overclaim | A wrong build or supplied unprotected key registers | Validate Apple's current fields, provisioned App ID and accepted build policy; trace internal key generation and keep assumptions explicit. |
| Lost endpoint control/outcome | Stale Inbox or registration/removal stuck after crash | Trace atomic outboxes/receipts and authenticated same-boot/post-restart reconciliation. |
| Legacy phone escape path | Old approvals/capture still reachable | Trace host tabs, notifications, delivery and capability dispatch to explicit retirement behavior. |
| Sandbox DNS/host/roots | Agent reaches credentials or upstreams directly | Inspect effective namespace/NAT rules, mounts and roots; run the prescribed bypass executable in that environment. |
| External outcome ambiguity | A real effect is falsely labeled not performed | Preserve consumed intent, positive no-send evidence and unknown outcome distinctly; never retry uncertain sends. |
| Storage failure/hash-chain limits | Lost evidence or overstated tamper detection | Establish actual transaction/sync settings and receipt boundaries; expose valid-prefix limitations. |
| iOS/APNs limits | No notification/fetch despite pending work | Keep durable inbox/outbox synchronization independent from best-effort wake. |
| Real upstream mismatch | Live operation or invented tool used as demonstration | Discover actual Link testmode and filesystem behavior; return truthful tool results. |

These are architecture and proof obligations, not claims of completed Lean proofs, deployed infrastructure, successful real-phone biometrics or observed isolation.

## 11. Questions for the user

1. **Unknown outcomes:** May BOGO say “execution outcome unknown; not retried” after a possible send? Arbitrary unmodified upstreams cannot provide both at-most-once forwarding and guaranteed completion/no-effect certainty across a lost reply.
2. **Sessions:** Which direct clients/protocols must support pending-and-retry? The shim supplies explicit liveness; stateless direct HTTP does not. Silent abandonment without a signal is unobservable, and no idle expiry is added.
3. **Universal interface:** For schemas that cannot faithfully reserve a justification field, or tools needing execution-changing interactive input, may BOGO use a wrapper/metadata/additional approval contract, or must it report incompatibility? The stated universal promise cannot be claimed under the bounded interface without resolving this.
4. **New-tool defaults:** Does newly discovered always mean approve until explicitly configured, even when the owner chooses a different unlisted-tool default? Do not silently choose default-allow precedence.
5. **Registration trust:** Is genuine-app-attested internal biometric-key creation the intended guarantee, and which distribution/version identifies an accepted BOGO-capable build? App Attest does not directly attest a separately supplied key's biometric ACL.
6. **Behavior values:** What short Approve delay and default per-agent pending limit should setup use? Operational message/body bounds require values without becoming approval expiry. No performance goal is added.
7. **Reference inference:** Does the model run outside the container, or may the spec permit a constrained model-provider route? Literal BOGO-only egress excludes ordinary in-container cloud inference.
8. **Link policies/operation:** Which discovered tools require protection, and which actual testmode SpendRequest/credential operation realizes the example without claiming a merchant charge?
9. **Credential storage:** May an unmodified CLI maintain rotating credentials in its own owner-only private file referenced from TOML, or must they physically live in `secrets.toml`?
10. **Filtering example:** Which real tool/result should demonstrate public-link removal? The selected official filesystem server has no sharing-link operation.
11. **Second approver:** Is another Face ID-capable iPhone available? The specified software approver remains a separate nonproduction demonstration.
12. **Unconfirmed speed/setup aspirations:** Should earlier allowed-call overhead, notification-latency or setup-time aspirations become requirements? They are not goals here, and no benchmark, soak, timed trial or fixed run count is added.
