# BOGO: Architecture

Status: 2026-11-14. Built from SPEC.md.

## 0. The shape

BOGO is one Rust service on the owner's Mac. Named agents reach its authenticated MCP HTTP endpoint directly or through a small stdio shim; BOGO alone connects to unmodified upstreams and holds their credentials. Compiled Lean 4 owns exact request encoding, effective policy, approval settlement and single-use authorization. Rust owns transport, cryptography, durable storage and effects, with one serialized coordinator and one prepared, one-shot upstream handoff. A separate Swift package inside Apple Bridge replaces the old Approvals feature with BOGO's Inbox, History and Macs, using its own Face ID–locked Secure Enclave approval keys and independent registration, storage and delivery. BOGO's own relay carries authenticated end-to-end encrypted messages; the Mac sends APNs directly. Durable requests, audit and endpoint delivery obligations share a transaction boundary. Restart ends old sessions rather than resurrecting approvals; possibly sent upstream calls are never replayed. The Docker reference environment permits only the fixed BOGO route. The architecture states the limits of generic upstream execution, observable session liveness, schema compatibility and app-mediated key attestation rather than treating these as already solved.

## 1. Runtime picture

```text
Docker reference environment                         Owner's Mac
  trusted namespace initialization, then exits
  untrusted agent (non-root, no capabilities)
       | direct MCP HTTP or stdio -> bogo-shim
       v
  default-deny namespace -> fixed forwarder ------> BOGO MCP edge
                                                       |
  owner terminal -> bogo -> owner-only Unix socket -> coordinator
                                                    /      |       \
                                             Lean thread  SQLite  prepared sender
                                                         journal    /       \
                                                         + audit  local     remote
                                                         + outbox upstreams upstreams

BOGO encrypted delivery <------> bogo.eilmer.si:<own port> <------> BOGO Swift package
                                  separate relay/state            in Apple Bridge
BOGO direct APNs sender --------> Apple APNs --------------------> notification edge
                                                                  |
                                                           Inbox / History / Macs
                                                           exact review + Face ID
```

The Mac units are modules of one service. Upstream processes, the shim, fixed forwarder, relay and existing iPhone app are separate processes. No BOGO component imports or calls an Apple Bridge Mac gateway, relay, registration or APNs path. The relay shares only its VPS with Apple Bridge. The phone host shares its push token and mounts/routes the feature through a narrow facade; it does not supply BOGO identity or signing authority.

## 2. Units

| Unit | Language | Owns | May depend on | Must never depend on |
|---|---|---|---|---|
| Kernel | Lean 4 | Exact value types, encoding, policy, lifecycle, thresholds, consumption and proofs | Lean standard library, specified verification primitive | Network, database, SDK, UI |
| Kernel bridge | Rust / C | Lean initialization, object ownership, byte ABI, dedicated thread | Compiled kernel and crypto callback | A Rust authorization implementation |
| Exact JSON | Rust | Strict lexical parser and writer | Standard library | SDK numeric values as authority |
| MCP edge | Rust | Token authentication, raw-body extensions, per-agent discovery, lifecycle | rmcp, HTTP, coordinator port | Secrets or an upstream sender |
| Shim | Rust | Stdio framing, raw HTTP forwarding and session liveness | HTTP runtime, envelope inspection | Request re-encoding or approval logic |
| Configuration/catalog | Rust | Validated TOML, tool mapping, schema augmentation | Exact values, discovery port | Agent-provided policy or launch URLs |
| Coordinator | Rust | Ordered events, persistence boundary, one-shot effect wiring | Kernel bridge, store, effect ports | UI summaries as authority |
| Store/audit | Rust / SQL | Registry history, request journal, audit, receipts/outboxes | SQLite, canonical event encoding | Direct upstream effects |
| Upstream adapter | Rust | Private processes/HTTP, lexical sends, result filtering | rmcp, credential provider, prepared-send port | Agent-selected credentials or URLs |
| Crypto/registration | Rust | Verification, SAS exchange, App Attest validation, HPKE | Crypto libraries, Apple trust anchor | Relay assertions of trust |
| Approver delivery | Rust | Route fan-out, reconciliation, retries, direct APNs | Registry/outbox, crypto, HTTP | Decisions to execute |
| Relay | Rust | Opaque durable mailbox, authentication and rendezvous | Own HTTP/TLS/SQLite | Decryption, APNs/upstream credentials, kernel |
| Phone package | Swift | Exact decoding, screens, keys, independent state/delivery | Apple frameworks, own SQLite storage | Host registration, identity or delivery jobs |
| Phone host edge | Swift | BOGO tab, shared token, category routing, old-feature retirement | BOGO facade | BOGO key access or request construction |
| Owner CLI | Rust | Setup, lifecycle, registries, tools, cancellation, logs | Local owner control port | Agent HTTP or relay control API |
| Reference isolation | Container configuration / Rust | Namespace restriction, fixed forwarder, specified bypass executable | Docker, fixed BOGO endpoint | Credential mounts or arbitrary egress |

## 3. Core pieces

### 3.1 Exact values and signed request format

BOGO preserves JSON value semantics, except that number lexemes are deliberately part of identity. The parser rejects duplicate decoded object keys, invalid UTF-8, lone surrogate escapes, invalid number syntax, trailing input and unsupported structural sizes. Strings are Unicode scalar sequences without normalization; different spellings of the same JSON string escape represent the same value. Object member order is canonicalized by UTF-8 byte ordering. Arrays retain order. Numbers keep their entire original ASCII token: `4700`, `4700.0`, `4.7e3`, `4.7E3`, `4.7e+3` and `-0` are not normalized. Absent arguments differ from an explicit empty object; absent justification differs from an empty string.

```text
JVal = Null | Bool | Number(JsonNumberText) | String(UnicodeScalars)
     | Array(List JVal) | Object(StrictlySortedUniqueKeys JVal)
JsonNumberText grammar:
  -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
```

Lean defines and produces the signed encoding. Version 1 uses the following wire grammar; every integer is unsigned big-endian, every length/count is u32, times are u64 Unix milliseconds, and overflow rejects rather than truncates.

```text
bytes(x) = u32(length(x)) || x
str(s)   = bytes(UTF8(s))
opt(T)   = 0x00 | 0x01 T
list(T)  = u32(count) || T*

value = 0x00                         -- null
      | 0x01 | 0x02                  -- false | true
      | 0x03 bytes(valid-number-ASCII)
      | 0x04 str(string)
      | 0x05 list(value)
      | 0x06 list(str(key) || value)  -- strictly ascending UTF-8 keys

PathSegment = 0x00 str(objectKey) | 0x01 u32(arrayIndex)
Hint = list(PathSegment) || (0x00 | 0x01 str(ISO-currency) u8(minor-unit-scale))
       -- format 0=text, 1=money in integer minor units

Request = "BOGOREQ\0" || u16(1) || the following fields in this exact order:
  0x01 bytes(installationId)
  0x02 str(upstreamId)       0x03 str(toolName)
  0x04 opt(value)           -- complete arguments after removing BOGO field
  0x05 opt(str(justification))
  0x06 list(Hint)
  0x07 bytes(agentId)       0x08 str(ownerAssignedAgentName)
  0x09 opt(str(clientReportedName))
  0x0A bytes(sessionId)     0x0B bytes(nonce)
  0x0C u64(createdMs)       0x0D opt(u64(expiresMs))
```

IDs have validated role-specific widths in the domain model. An installation has a random 32-byte identity. Each service boot has a fresh 32-byte generation; sessions include that generation and a server-minted random identifier. A request nonce is that generation plus a non-reused u64 sequence; exhaustion closes admission. Request identity is the full installation/generation/sequence tuple, never the sequence alone.

A canonical request has valid domains, strictly ordered unique object keys and hint paths, and no redundant or unknown fields. Decode consumes the entire input. Unknown versions, noncanonical values and unsupported critical hints reject. Lean proves `decode(encode(r)) = some r`, and therefore encoding injectivity, over representable canonical requests. Boundedness is explicit in that theorem; an overflowing value is not silently mapped into another request.

The signature input is `"BOGO-APPROVAL\0v1" || bytes(approverId) || u64(keyGeneration) || bytes(requestBytes)`. The phone signs the received original request bytes, not a re-encoded view. P-256 ECDSA with SHA-256 uses CryptoKit's raw 64-byte `r || s` representation on the wire. A distinct approver means a registered identity, not a distinct signature encoding.

Policy, eligible registration generations, threshold, denial behavior, output filtering and mode are immutable local context attached to the request, not extra phone-signed fields. Configuration changes require restart, which ends every old session. New votes cannot change that context; historical audit retains it. Catalog presentation changes cannot reinterpret an admitted request's extraction or routing.

Lean-generated vectors describe encoding/decoding and exact JSON writer interoperability for Rust and Swift. They are protocol artifacts, not an independent encoding implementation or a general testing framework.

### 3.2 Executable Lean authorization kernel

The kernel is a total state transition function. It has no filesystem, sockets, timers or UI. One dedicated thread owns all Lean objects. A Rust callback implements the specified cryptographic verification primitive; Lean selects the registered key, algorithm, generation and message bytes.

```text
Event = Admit(session, callId, exactName, optionalArguments, observedTime)
      | SessionOpened(serverSession, authenticatedAgent, clientInfo)
      | SessionClosed(session) | CallEnded(callId)
      | Decision(approver, requestId, signedEvidence, observedTime)
      | Control(authenticatedOrigin, controlMessage)
      | OwnerChange(ownerOperation)
      | Deadline(observedTime)
      | Reserve(requestId, preparedSendId, observedTime)
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

`ValidatedEvent` means structurally validated, not automatically trusted. Owner events, transport observations and authenticated control events carry separately established origins. Raw agent requests can never construct an owner registration or an unpause event. Network-supplied signatures remain arbitrary inputs until verified. The bridge decoder rejects malformed bytes without issuing effects.

State contains immutable boot configuration, registries/generations, agent status/control epochs, live sessions/calls, pending requests, distinct response sets, settled decisions and consumed reservations. The important lifecycle is:

```text
Collecting -> SettledApproved -> Reserved -> HandedOff -> Completed | OutcomeUnknown
     |               |            |
     |               |            +-> NotSent (consumption retained)
     +-> Denied      +-> Ended
     +-> Ended
```

Rules:

- Resolve per-agent override, then tool policy, then valid defaults. `allow` and `deny` also go through Lean; there is no Rust fast-path authorization bypass. Unknown agents/tools and malformed calls reject.
- An approve tool strips only its catalog-designated BOGO justification property. If present it must be a string; if required but absent, reject with a message telling the agent to include it. Forwarding always uses the stored stripped arguments, never the retry's independently constructed copy.
- Count outstanding logical requests, including settled-but-unconsumed ones, against the configured per-agent pending limit before allocation/notification. Matching retries do not add a request. Excess new requests reject quietly and are audited.
- Build and encode one immutable request, with an optional expiry and no default expiry. Send the same bytes to all eligible registered approvers. An impossible threshold rejects rather than waits indefinitely.
- During `Collecting`, verify every approval over the kernel's own bytes and the current registered key. Count each eligible identity once. Any-of needs one; k-of-n needs k distinct identities. Default denial veto ends the request. The configurable non-veto behavior excludes deniers and denies when the threshold becomes unreachable.
- On reaching the threshold, freeze the settled vote set. Later approvals/denials are ignored as late. In pending-and-retry, settlement does not dispatch by itself. Revocation may subsequently invalidate usable authority but never reopens voting or transfers an old vote to a replacement key.
- At reservation and handoff, sufficient counted approvals must still come from active eligible generations. The agent must remain active/unpaused, the session and relevant call must remain live, and any expiry must not have passed.
- Observed cancel, call/session end, owner cancellation, agent revocation, configured expiry or relevant eligibility failure ends unsent authority. No terminal request is reopened by late delivery.
- Pause denies pending requests and rejects every subsequent agent request, including discovery, with a clear paused outcome. Only the owner on the Mac can unpause. Unpause advances a per-agent control epoch, invalidating withheld older pause messages.
- A reservation is irreversible consumption. Only one `Handoff` for it can emit `DispatchOnce`. Failure after reservation does not restore authority.

The C wrapper uses distinct names for Lean exports and the public ABI, avoiding linker-symbol collisions:

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

The wrapper owns the opaque Lean state and returns separately allocated byte buffers freed only by `bogo_buffer_free`. Inputs are borrowed only for the duration of a call. All calls run on the initializing thread. The wrapper initializes generated modules/runtime once, checks the ABI version, handles Lean reference ownership, and prevents exceptions/panics crossing the ABI. Its internal generated exports use a `bogo_lean_` prefix. Lean code, headers and runtime come from one pinned toolchain, following the [Lean FFI reference](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/).

### 3.3 What is proved / What is assumed

The adversary can supply arbitrary malformed bytes, tool arguments, justifications, names, response order, duplicate signatures and cancellation/connection schedules. The trace model explicitly permits session open/close and call end in any order; session binding is not assumed away. It distinguishes those events from owner commands and from the runtime observation that a particular authenticated transport actually ended.

The Lean proofs establish:

1. Each protected handoff has sufficient distinct currently registered eligible approval evidence.
2. Every counted approval binds exactly the request, including lexical arguments, justification, agent, session, nonce and times.
3. Each request/reservation emits at most one upstream dispatch.
4. No dispatch occurs after an ending, pause, relevant revocation or expiry ordered before the final handoff.
5. Any-of, k-of-n, per-agent overrides, duplicate handling and denial behavior obey their definitions, including frozen settlement.
6. Unknown, malformed, denied or otherwise unauthorized inputs cannot dispatch.
7. Allowed dispatch requires effective allow policy and a valid active agent/session.
8. Encoding is deterministic and injective over its stated canonical domain.

Explicit assumptions are cryptographic verification soundness/unforgeability, hash collision resistance, secure randomness and HPKE, genuine accepted app behavior, Secure Enclave/Face ID enforcement, faithful HTTP/JSON/transport observations, truthful time, correct durable storage and one-shot effects, compiler/runtime/FFI correctness, an uncompromised Mac and phone OS, sandbox isolation and upstream access controls. The verifier primitive has a logical contract connected to its Rust implementation; an `extern` annotation alone is not a proof.

The proof does not prove human judgment, delivery availability, universal schema support, exact-once provider completion, or instant detection of silent client abandonment. The Rust sender must faithfully refine `DispatchOnce`; it is not justified merely because a theorem about an earlier abstract `forward` exists.

### 3.4 MCP edge, exact transports and session lifecycle

BOGO uses pinned `rmcp` for MCP protocol handling and discovery. Raw arguments remain authoritative before and after SDK processing. [`serde_json`'s exponent scanner](https://github.com/serde-rs/json/blob/master/src/de.rs) lowercases exponent notation and inserts a positive sign even with `arbitrary_precision`; that option is not an exact-token solution.

**Ingress:** an HTTP layer authenticates the bearer token, parses one JSON-RPC message with the strict lexical parser and adds `ExactCall { name, optionalArguments, metadataClass, internalCallId }` to that HTTP request's extensions. rmcp carries request parts into the handler's extensions, as shown in its [server source](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport/streamable_http_server/tower.rs). The handler uses this exact tree, not the SDK `arguments` map. No cross-request raw-body lookup by agent-controlled ID is needed. Track active JSON-RPC IDs for cancellation separately, rejecting concurrent reuse within a session rather than overwriting a waiter.

The lexical tree and SDK envelope must agree on method/name/ID. Duplicate keys anywhere reject before SDK decoding. Unknown execution-affecting extension inputs, MRTR continuations or agent-supplied authorization/transport headers are never silently forwarded outside the signed action. Known protocol bookkeeping is regenerated by BOGO. Unsupported execution-changing interactions reject and remain a compatibility question.

**Egress:** use an `ExactChildTransport` implementing rmcp's `Transport` for private process stdio and an `ExactHttpClient` implementing [`StreamableHttpClient::post_message`](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html) for remote HTTP. Other protocol messages use SDK serialization. A `tools/call` requires a private one-shot dispatch ticket binding reservation, call, upstream connection generation, tool name, argument presence and exact tree. An internal `_meta` marker can carry its opaque reference through rmcp; the transport strips the marker and writes the full call from the ticket, including every number token. It checks the complete binding, not only an arguments lookup. Agent metadata cannot register tickets. A send without a ticket fails closed.

`prepare(dispatch) -> PreparedSend` establishes credentials/connection and constructs exact outbound bytes without writing them. `handoff(prepared, oneShotPermit) -> Started | NotStarted` initiates the first transport write without reconnecting or queueing behind future preparation. The SDK adapters must implement that boundary; if a stock adapter cannot, the adapter owns the scheduling rather than calling a generic delayed `call_tool` after authorization. HTTP transport retries, redirects and SDK reconnect replays cannot re-emit a consumed call. Initialization/discovery may retry independently.

**Authentication:** `bogo agent add` prints a random connection token once; store only its verifier hash with stable agent ID and owner-assigned name. Authenticate every HTTP request, not just session creation. Bind sessions to that identity; a token mismatch cannot borrow another session. Validate Host/Origin. Bind to loopback or the narrowly required sandbox interface, never all interfaces by default. The owner control socket is separate and owner-permission/peer checked.

**Session contracts:**

- The stdio shim owns one BOGO authorization session per process/liveness connection. It obtains a server-minted session handle with its agent token through the BOGO-only liveness endpoint and includes it on raw forwarded POSTs. Stdin EOF, explicit cancellation or observed liveness closure ends the appropriate work. Reconnection obtains a new handle; old approvals cannot migrate.
- The shim preserves each original JSON message body. It parses only envelope/header fields needed for protocol version, IDs, error responses and SSE framing; it never serializes the arguments again. It handles concurrent requests so a held call cannot block a following cancellation. Diagnostics go to stderr, JSON-RPC only to stdout.
- Direct 2025-era HTTP binds `Mcp-Session-Id` to one agent. Explicit DELETE, observed connection termination under the documented BOGO non-resuming profile, revocation and restart end the session. A protected wait response remains open; observed response-body cancellation or MCP cancellation ends its call. If the client opens the profile's session liveness stream, its closure ends the session. BOGO provides no request resumption that could revive ended authority.
- The [2025-11-25 transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) normally distinguishes SSE disconnection from cancellation. BOGO's stricter non-resuming profile must be documented as such. A direct session with no persistent stream and no explicit end signal cannot reveal remote abandonment merely through silence.
- [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog) removes protocol sessions and initialization. Direct wait calls use request-scoped authorization sessions and per-request client information. Pending-and-retry requires the shim's explicit session contract or a session-capable connection; a stateless direct call gets a clear incompatibility rejection rather than silently binding approvals to an agent token or pooled TCP connection. Required discovery, metadata, headers and cache fields follow the negotiated protocol era.

There is no invented idle timeout or hidden default expiry. Transport detection can be delayed by the OS/network; an unobservable silent client timeout cannot be acted on. Mac restart invalidates all old generation/session handles before serving traffic.

### 3.5 Catalog, policy and credential isolation

Discovery follows every `tools/list` page and supported list-change notifications. Maintain an explicit mapping of `<upstream>__<tool>` to configured upstream identity and original tool name. Upstream aliases cannot contain the delimiter. Preserve original descriptions and input constraints except the specified justification addition. Invalid names, collisions and protocol length limits are visible incompatibilities, never ambiguous routing.

The immutable boot policy includes tool allow/approve/deny, justification requirement, signed display hints, optional expiry, eligible approvers, any-of/k-of-n, denial behavior, output filters, wait/pending-retry mode and per-agent policy/approver overrides. Validate all values and references before use. Denied tools are hidden for that agent by default; optionally show them, but calls still reject. Paused agents receive a paused error on every request.

The shipped default is approve. Newly discovered tools cannot silently become allow. The conflict between owner-set default allow and the new-tool safety rule is an owner question; configuration combinations depending on that unresolved precedence are reported rather than guessed. Explicit configured tool policies work normally.

For approve tools, choose a deterministic justification property that does not collide with upstream fields. The advertised field remains optional as specified; required justification is enforced on admission with the explanatory outcome. A schema transformation is accepted only if removing that property yields exactly the original accepted argument domain and does not drop or alter any original argument. This requires accounting for references, compositions, additional/unevaluated properties, property-name/pattern constraints, cardinality, conditionals and whole-object constants. A supported transformation and chosen field are frozen in each request's local context. An unsupported transformation is reported incompatible rather than advertised as working. A wrapper/metadata alternative would change the specified interface and needs an owner decision. [JSON Schema's object rules](https://json-schema.org/understanding-json-schema/reference/object) explain why simple property insertion is insufficient.

Catalog descriptions or unrelated additions do not automatically end admitted requests. Pending requests retain their exact tool/argument extraction and routing context. A genuinely unavailable or unusable upstream fails closed during preparation. Agent retries matching an existing request use that request's extraction context, not a changed catalog key.

Local upstreams are unmodified supervised child processes with private stdio and an explicit minimal environment. Remote upstreams use only owner-configured URLs and credential references. Disable automatic credential-bearing redirects. The agent cannot select launch commands, headers, arbitrary destinations or credential sources. Advertise no upstream roots/sampling/elicitation capability; there is no unsigned alternate execution path. Resources/prompts are not exposed as substitute tools. Interactive MCP operations that cannot fit this contract remain an explicit universal-compatibility gap.

`~/.bogo` is owner-only. `secrets.toml` must be an owner-owned regular file with mode 0600, with safe path/ownership checks. It and all private child state are absent from agent mounts and excluded from filesystem-upstream roots. Mac Keychain is not used for upstream credentials. Secret wrappers prevent routine formatting, but diagnostics and returned strings are also checked for known connection-credential reflection; arbitrary strings do not become safe by lacking the `Secret` type. Malformed reflected credential material is withheld rather than logged.

### 3.6 Durable coordinator and prepared dispatch

SQLite is the local transaction boundary for registry/history, request journal, audit and delivery work. Use one writer, foreign keys, WAL and deliberate durability settings: `synchronous=FULL`, macOS `fullfsync=ON` where supported, and matching checkpoint synchronization. Check actual settings rather than relying on defaults. [SQLite documents these separately](https://www.sqlite.org/pragma.html#pragma_fullfsync). A process lock prevents a second dispatcher using the installation.

A state-changing security event computes its Lean transition, then commits corresponding state facts, audit and outbox obligations before exposing effects or acknowledging acceptance. A failed commit emits nothing; the coordinator restores the committed view or terminates. Pending in-memory Lean state is not treated as more authoritative than the committed journal. Pure reads and already-acknowledged duplicate messages do not invent new durable transitions.

Dispatch order:

1. Prepare the authenticated upstream connection, exact request bytes and local non-replayable writer slot. Phone waits and upstream setup occur outside the coordinator and outside database transactions.
2. Run Lean `Reserve`, checking policy, threshold, active registrations, agent/session/call state and expiry. Commit irreversible consumption, the full dispatch intent and audit evidence durably.
3. After the commit, process relevant already-observed ending/control events and obtain current time. In the same serialized dispatch-gate turn, run Lean `Handoff` for that reservation.
4. If still valid, pass its unique permit to the prepared adapter and initiate the first write without an intervening asynchronous queue or connection setup. If preparation is no longer valid, record not-sent and retain consumption.
5. Persist known send/result status, filter the result, and answer the agent if its waiter remains reachable. Never resubmit a possibly sent call.

The linearization point is the final authorization and immediate handoff to a prepared transport. Events ordered before it take effect; events after it cannot undo bytes already buffered or provider work. This does not promise that cancellation at a remote client instant is synchronously observable. The final check exists to catch expiry/cancellation during durable commit and preparation, not to claim control over the provider.

Expiry uses a sleep-aware monotonic deadline derived when the signed wall-clock creation/expiry values are made. Clock rollback cannot extend lifetime. Deadline events keep UI/delivery current, but the final handoff compares current time even if the timer was delayed. Mac resume revalidates affected transports before dispatch. Uncertain clock/liveness state cannot authorize a call.

Generic unmodified upstreams do not transact with SQLite. A crash between consumption and outcome can leave not-sent or unknown. Neither is replayed. At-most-once forwarding is achievable; guaranteed exactly-once external completion and “silence means nothing happened” after a possible send are not. The agent receives “execution outcome unknown; not retried” for that case, subject to the explicit spec question.

**Wait and retry:** wait mode holds one call until settlement/end. In pending-and-retry, the logical request outlives the initial pending response while its session lives. Match session, upstream, tool, exact arguments and justification; identical retries attach to that logical request. Approval settles without sending. The first identical retry after settlement consumes it. Concurrent retries cannot each dispatch; while the request is dispatching, they observe/attach to the same terminal operation. Once terminal, a later identical call may start a new nonce and requires a new approval. An old approval cannot authorize the new request. This is not business-operation deduplication: a retry after a lost final result may ask for fresh approval rather than return a cached success or execute automatically.

**Grouping:** wait-mode duplicates remain distinct requests/nonces. The phone groups by agent, upstream, tool, exact arguments, justification and display hints. Opening a group selects one concrete live member and its session. Approve and Deny decide that member only. The count is presentation, not a batch authorization. Pause is the specified agent-wide denial control.

### 3.7 Approver routes, encryption and registration

```text
ApproverRoute:
  register(transaction, ownerInteraction) -> VerifiedRegistration
  deliver(registration, messageId, requestBytes) -> TransportReceipt
  sendState(registration, requestId, stateVersion, state) -> TransportReceipt
  receive() -> UnverifiedEnvelope
  reconcile(registration, cursor) -> AuthenticatedStateUpdates
```

Only a route's validated registration can establish an eligible key. Route transport receipts do not authorize execution or prove endpoint acceptance. The kernel sees identity/generation, cryptographic evidence and lifecycle, not relay implementation. New routes supply the same registration, exact-rendering and user-verification contract. Normal BOGO builds contain only the iPhone route; the software approver is confined to its separate development build and cannot be registered through production configuration.

**Keys:** the Mac has BOGO-only installation identity, X25519 HPKE key and Ed25519 mailbox-auth key in protected files. Each phone/Mac registration has its own Secure Enclave P-256 approval key, X25519 channel key and Ed25519 mailbox/control key. Phone transport keys use BOGO-only device-local Keychain storage usable after first unlock; they cannot sign approvals. Approval-key use requires Face ID. Re-registration creates a new key generation and never overwrites historical identity.

**Normal envelopes:** authenticated HPKE with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, using one fresh encapsulation and one sealed plaintext per message. Rust `hpke` and CryptoKit HPKE implement this standard. Store ciphertext before send and retransmit identical bytes. No long-lived AEAD nonce counter is needed.

```text
Header = "BOGOE2E\0" || u16(version) || u16(kind)
       || installationId || senderRegistration || recipientRegistration
       || u64(keyGeneration) || u8(direction) || messageId
Envelope = Header || bytes(encapsulation) || bytes(ciphertext)
HPKE info = domain-separated canonical registration identities and version
HPKE AAD  = Header
```

Opaque envelope kind and identifiers reveal routing/size metadata but no arguments or justifications. Sensitive application details remain in plaintext inside the encryption. Types are request, terminal/state update, approval, denial, pause, self-revocation, application receipt, push-token update and synchronization. All request-scoped payloads contain full installation/boot/sequence identity. Approvals include the raw approval signature. Denial/pause/removal are authenticated under disjoint control domains, not the Face ID approval domain. A valid control message cannot become approval evidence.

Receivers authenticate/decode, then atomically record `(registrationGeneration, messageId, payloadIdentity)` and its state change before acknowledging. An exact duplicate receives the previous receipt; conflicting content under the same ID rejects. Unseen lower-order messages remain valid. Terminal request versions/tombstones prevent late request delivery from resurrecting an ended entry. Synchronization reconciles current pending and terminal state independently of delivery order. Pause additionally carries the current per-agent control epoch, which Mac unpause increments. [HPKE does not itself supply replay protection](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.3).

**Add Mac:** numeric comparison is a commitment-based SAS exchange, not a hash of freely replaceable public keys. The [Matrix SAS rationale](https://spec.matrix.org/v1.16/client-server-api/#short-authentication-string-sas-verification) explains the commit-before-reveal requirement. BOGO's six-digit adaptation remains a cryptographic integration boundary, separate from the Lean decision proof.

1. The Mac owner command creates a fresh registration transaction, ephemeral X25519 contribution and random nonce. It offers a label, transaction ID, supported version/suite and a commitment to its full role-tagged contribution. The relay does not receive the committed secret contribution in advance. Add Mac lists candidates; labels are untrusted convenience, not identity.
2. The phone selects one transaction, fixes its own ephemeral key/nonce and sends that contribution plus the fixed protocol selection. The Mac fixes this peer for the transaction; neither endpoint accepts relay-driven participant replacement or hidden retries.
3. The Mac reveals its committed contribution. The phone verifies the commitment, key validity, roles, transaction and protocol choices. Both reject an invalid/all-zero shared-secret result. The full transcript includes both contributions, roles, selected suite/version and transaction identity.
4. Derive SAS material with HKDF from the ephemeral shared secret and transcript. Extract six decimal digits without modulo bias using rejection sampling from domain-separated derived bytes. Both display the same digits for this one attempt. Mismatch/abort requires explicit owner restart.
5. The owner confirms on the Mac first. Its transcript-bound confirmation is authenticated through the ephemeral exchange. Remaining registration messages use fresh single-shot authenticated HPKE between the exchange keys with transcript-bound context; each phase has a unique ID.
6. Only then the phone enables confirmation. Face ID confirms; the phone creates its approval key internally with the required ACL and proves possession. It generates its long-term channel/mailbox keys and requests App Attest evidence over the fresh challenge, complete transcript, approval public key, channel/mailbox public keys and registration version. The Mac's long-term keys are bound by the same confirmed exchange.
7. The Mac validates the complete attestation and possession evidence and durably commits the new registration. Re-registration atomically revokes the previous generation and installs the new one. It sends an authenticated committed result. The phone stores the committed registration and sends its application receipt.
8. A lost final reply is retried by the same transaction ID and returns the same committed result. It does not create a second registration. Before commit there is no trust; after commit, recovery must acknowledge that one side may already be registered. The phone does not offer approval until it receives the committed result.

Each phase persists the necessary local transaction state before its externally visible acknowledgement. Interrupted ephemeral exchanges are either resumed with stored exact messages/key material or explicitly aborted into a new transaction, never reconstructed with reused encryption state.

**App Attest boundary:** validate CBOR shape, certificate chain to Apple's App Attest root, nonce from fresh challenge and authenticator data, App ID hash, attested-key identity, credential ID, counter, AAGUID/environment, and supported `validationCategory`/`appVersion` evidence according to [Apple's current procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server). Store the validated evidence, attested public key and receipt with the registration. Validate/store the receipt as Apple specifies; do not substitute an opaque library success boolean for required checks.

App Attest attests its own key and app-originated evidence; it does not directly certify a separate supplied approval key's biometric ACL. The accepted genuine app creates that key internally, accepts no externally supplied replacement, then attests the binding. Genuine app behavior and OS/enclave enforcement are explicit assumptions. Production trust requires accepted distribution/version evidence; development records are separated and cannot silently stand in for normal trust. No attestation-unavailable fallback exists.

The existing app's team, bundle and iOS target are `AX3C2B78YD`, `com.johansardar.applebridge.ios` and iOS 26 in [project.yml](/Users/johansardar/apple-bridge-iphone/ios/project.yml:3). The App ID prefix must be confirmed against the actual provisioning identity, since it need not universally equal the team ID. The remaining owner decision is accepted distribution/build policy, not a request to rediscover these repository values.

### 3.8 Relay, application receipts and direct APNs

The relay runs at `bogo.eilmer.si` on its own selected port, service account, service definition and SQLite database. It has no Apple Bridge application dependency. Public TLS uses a DNS-01 certificate and a Cloudflare token scoped to the necessary zone; the ACME credential stays outside relay application state. The relay necessarily holds TLS material, but no upstream/APNs credential, approval key or content decryption key.

Use HTTPS JSON requests and long-polling, with bounded bodies and explicit errors:

```text
POST /v1/auth/challenge {mailboxPublicKey} -> challenge
POST /v1/auth/verify {challengeId, signature} -> short-lived bearer
POST /v1/allow {senderMailboxIds} -> receipt
POST /v1/send {to, messageId, ciphertext} -> durable receipt | full | conflict
POST /v1/fetch {cursor, wait} -> opaque messages
POST /v1/ack {messageIds} -> receipt
POST /v1/retract {to, messageIds} -> receipt
POST /v1/lobby/offer; GET /v1/lobby
POST /v1/lobby/{transaction}/message; POST /v1/lobby/{transaction}/fetch
```

Mailbox identity is derived from its endpoint-held public authentication key. Auth challenges are one-use and bind mailbox/service purpose. Only the mailbox owner changes its sender allowlist, fetches or acknowledges its contents. Retract is sender-scoped. Relay-side identity checks are anti-abuse/routing, never authorization evidence. A compromised relay may drop, delay, replay, reorder or delete messages; endpoint cryptography remains authoritative.

Persist messages before relay receipt. Full storage rejects admission explicitly; it never claims to retain data it discarded. Registration offers exist only while the local owner transaction remains active; a stale offer does not establish trust. Storage caps and retry/backoff are operational bounds, not request expiry. No new duration is assigned here.

Endpoints retain delivery obligations until **application** acknowledgement or authoritative ending. The phone persists inbound bytes before sending `seen` and relay acknowledgement. It persists signed decisions before transmission. Mac decision acceptance, audit and response outbox commit together. On reconnect/foreground, authenticated synchronization returns current pending state and terminal updates, restoring consistency after relay loss. Delivery does not stop permanently merely because a volatile receiver once saw a packet.

The Mac sends time-sensitive APNs alerts directly using the owner's provider key and app topic. The payload contains only opaque BOGO routing and generic “Approval requested” text, not arguments/justification. The category has Deny only; tapping opens full review. Push token/environment updates travel over BOGO's own encrypted authenticated channel. Collapse/grouping identifiers are opaque keyed digests rather than plaintext business data.

APNs is a best-effort alert/wake hint. Apple's [delivery documentation](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns) does not make it a durable inbox. Shared-app notifications may displace one another; permissions, force-quit and OS background scheduling may prevent timely fetches. No architecture can promise background Deny execution when iOS does not run the app. Persist the action when execution is granted and reconcile on the next available opportunity. Never use APNs success as proof of phone receipt or approval.

### 3.9 Independent iPhone approver

Use a local Swift package with separate protocol/model, crypto, store, transport and facade/view targets. Its host API is limited to:

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

The host mounts the BOGO tab, routes matching categories before legacy handling and fans out its APNs token. It never reads BOGO keys or builds a signed request. BOGO works when the phone has never registered with the Apple Bridge Mac.

**Host replacement:** remove the old Approvals tab/screens/capability entry points and stale approval notification actions. Ignore incoming Apple Bridge approval jobs without returning a decision so they expire on the unchanged Mac. Photo/audio requests always return the existing protocol's explicit rejected/denied result, independent of capability toggles, and cannot reach capture UI or legacy approvals. The current coupling is visible in [CaptureCapability.swift](/Users/johansardar/apple-bridge-iphone/ios/Capabilities/Capture/CaptureCapability.swift:6) and [CommandHandlers.swift](/Users/johansardar/apple-bridge-iphone/ios/Delivery/CommandHandlers.swift:5). Preserve unrelated phone capabilities and registration paths. BOGO's notification categories are merged, not substituted for unrelated categories.

**Inbox/History/Macs:** persist exact request bytes and canonical decoded state. Group duplicates with a count but preserve each request identity. Ended entries are greyed and cannot approve. History distinguishes local signature, Mac acceptance and completed/unknown execution; a locally signed decision is not execution success. Macs supports Add Mac, list, remove and re-registration. The store is BOGO-only application-support SQLite, with device-local Keychain namespaces for its keys.

**Review:** derive all content from the exact request bytes being signed. “Will execute (exact)” contains upstream/tool, trusted owner-assigned agent name and every argument; signed hints highlight values without hiding raw values. The full tree remains inspectable, not silently truncated. Escape control/bidirectional/zero-width characters and expose significant whitespace. Never interpret agent text as markup or instructions.

“Agent's reason (unverified)” contains justification, self-reported client name, session tag and mismatch warnings. Money uses exact integer/decimal arithmetic, never binary floating point. The money-minor format accepts valid integer tokens within supported bounds; otherwise show the raw token and a formatting warning. The simple mismatch recognizer identifies explicit currency forms such as `$47`, `47 USD`, `USD 47` and `47 dollars`, compares currency/value pairs with every successfully displayed currency field, and warns for an amount matching none. Times/flight numbers without a currency marker are ignored. No money mention means no warning. This remains a heuristic warning, not prose comprehension.

Approve exists only on full review after the specified short delay for that exact request. Changing the selected request resets the delay. Deny may include a note. Both target one concrete request. Pause is one tap and carries the current agent control epoch; unpause exists only on the Mac. The phone countdown is presentation; Mac freshness remains authoritative.

Each approval uses a fresh authentication context without a reuse window and a per-registration Secure Enclave P-256 key with `privateKeyUsage`, `biometryCurrentSet` and device-only passcode-protected accessibility. Require Face ID, no passcode-only or Touch ID fallback. The key operation itself is constrained; a UI-only biometric check followed by an unrestricted key is forbidden. [Apple's enclave guidance](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) and [`biometryCurrentSet`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset) define the underlying mechanism. Enrollment change, key loss or reinstall requires registration again, not a software fallback.

Deny, pause and self-revocation use separately authenticated control authority so notification Deny does not require the approval key. Removing a Mac immediately disables/deletes local approval capability, then retains an authenticated self-revocation outbox and channel material until the **Mac** acknowledges revocation. “Removed locally; awaiting Mac acknowledgement” is truthful while offline. Relay receipt alone cannot complete removal.

The phone-first stand-in for BOGO uses real encoding vectors, registration, App Attest, HPKE, the independent relay and direct APNs, but no production authorization or upstream calls. It is distinct from the separately compiled software approver used to demonstrate k-of-n without another real phone.

### 3.10 Output filtering and audit

`filter(rules, CallToolResult) -> FilteredResult | WithheldRepresentation` is a deterministic projection outside Lean. Compile selectors into unambiguous structural paths with explicit strip/redact actions. Cover structured content, JSON text copies, metadata, embedded resources and resource links before releasing any result. If a configured rule cannot safely process a representation, withhold that representation or return an output-delivery error; do not repeat the tool call. Filtered tools omit an incompatible output schema rather than promising a required field that was removed. Without filters, return the upstream's real result.

Field filtering is not universal detection of secrets in prose or binary data. Known connection-credential reflection is withheld separately. Owner-selected filtering, correct upstream access controls and the sandbox are distinct boundaries.

The authoritative audit is an append-only SQLite table with canonical immutable event bytes, monotonic sequence and previous-entry hash. The API appends only; query indexes are derived. Record every protected attempt and its exact request/justification, decision/reason/time, responses and original signatures, registration/revocation evidence, consumption and known/unknown outcome. Record allowed attempts/outcomes too so the spec's audit scenario includes them. Denied-policy, paused and flood rejections are recorded without sending a notification. Allowed calls incur no approver traffic or approval state.

Requests and argument values are logged; credentials from the secret provider are not. Diagnostic errors cannot freely reflect child environment/header values. Distinguish invalid/late evidence from counted approvals so retaining an invalid signature does not make the entire log falsely look valid.

`bogo log verify` checks canonical hash continuity, reconstructs historical registrations/generations and local request policy context, verifies signed bytes, and checks threshold/freshness/consumption evidence at dispatch. Later revocation does not retroactively invalidate an earlier valid approval. Search/export read the same authoritative events; exports include the chain/head. Terminal control characters are escaped in CLI output.

A hash chain detects internal deletion/alteration relative to retained history, not replacement with a valid earlier prefix unless a head was retained separately. Owner-retained exports can provide that comparison; no transparency service is added. Corrupt committed history stops affected operation and is reported, not silently reclassified as a torn final line. SQLite recovery handles uncommitted transactions under its documented storage assumptions.

### 3.11 Owner operation, sandbox and selected upstreams

```text
bogo init
bogo start | stop
bogo approver add "<name>" | list | revoke <name>
bogo agent add "<name>" | list | revoke <name> | pause <name> | unpause <name>
bogo tools
bogo request list | cancel <id>
bogo log [search ...] | export | verify
```

`approver add` on an existing name performs explicit re-registration, retaining historical keys. `init` creates protected state/configuration and a LaunchAgent definition; `start` validates before serving; unexpected service exit is restarted by launchd. `stop` closes admission and commits unsent endings before stopping transports. Mutations use the owner-only socket when running; offline commands take the same writer lock and use the same store code. No remote owner API or web dashboard exists.

**Reference sandbox:** use a dedicated internal Docker network plus a fixed-destination forwarder to the Mac's BOGO endpoint. Docker documents that [`--internal` still permits gateway-host communication](https://docs.docker.com/reference/cli/docker/network/create/#internal); it is not the full security boundary.

A trusted, short-lived initializer enters the agent's network namespace before any untrusted executable, installs default-deny output/input rules allowing only the fixed forwarder address/port and established responses, blocks outside DNS and IPv6 bypasses, then exits. The namespace can be held by a minimal inert container; an initializer shares only its network namespace and briefly has `NET_ADMIN`. The agent starts only after successful setup, with no namespace-administration process/API left accessible to it. Recreated namespaces require initialization again. The agent runs non-root with all capabilities dropped and no-new-privileges; it cannot change network policy. Failure to establish the policy prevents startup.

The forwarder is a bounded HTTP forwarding process pinned to one destination, not CONNECT/SOCKS or an agent-selected URL proxy. It exposes only the BOGO MCP/liveness paths and necessary methods, has no general IP forwarding path, and follows no redirects. No Docker socket, home directory, credentials, owner control socket or private upstream state enters the agent container. Only the named agent's BOGO connection token does.

The spec-required bypass executable runs from the reference container and reports forbidden direct upstream/relay/host access, DNS/IPv6 routes, credential discovery and unapproved/forged protected calls. Its purpose is observing the actual isolation contract, not asserting that an absent listening host service proves isolation. No additional benchmark, timed run or verification framework is introduced.

Filesystem upstream roots are owner-selected nonsecret directories; agent roots cannot replace them. The [official filesystem server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) permits roots replacement for compatible older clients, so BOGO advertises no roots capability. Do not allow a nominally harmless filesystem read to expose BOGO credentials.

Use installed, pinned `link-cli --mcp` and the official filesystem server unmodified. [Link's source documentation](https://github.com/stripe/link-cli/blob/main/README.md) says `--test` creates testmode SpendRequests and test payment credentials; it is not a universal test-login setting. Link Pay Tokens lack testmode and checkout paths can be live-only. Discover real tool/field names, display the testmode field alongside money, and perform only confirmed testmode operations with test credentials. A SpendRequest or credential is not a completed merchant charge. No real-money demonstration is authorized by this architecture.

Link uses a rotating private auth file; whether that may live under BOGO's protected directory with a `secrets.toml` reference, rather than physically inside TOML, is a spec decision. The official filesystem server has no public-sharing-link tool, so the illustrative filtering scenario needs an actual selected result/tool rather than an invented operation. Finally, BOGO-only container egress excludes a conventional cloud model connection from inside the container; inference placement or an exception needs an owner decision.

## 4. Data flows

| Scenario | Flow |
|---|---|
| 1. Payment approved | Authenticate Trip planner; parse exact confirmed testmode arguments; Lean strips justification and encodes request; commit journal/audit/outbox; encrypted delivery plus direct APNs; phone renders $47.00 and trusted agent name; Face ID signs original bytes; Lean verifies/settles; prepare, durably reserve, final-check and hand off once; filter/persist/return real Link result. |
| 2. Lie in reason | Signed 50000 minor units renders $500.00; recognized $5 text warns; Deny with “wrong amount” is persisted/authenticated; Lean denies; no upstream send; reply “The owner denied this action. wrong amount”. |
| 3. Mutation/session/replay | Changed argument token, justification or session is a different request needing fresh approval. Old signatures cannot match it. Repeated evidence is idempotent; consumed request never dispatches again. |
| 4. Allowed tool | Lean resolves allow; record attempt, prepare/send without phone activity, record outcome, return real result. |
| 5. Denied tool | Per-agent discovery hides it by default; calling the known name still rejects and audits without upstream contact. |
| 6. No answer | Observed cancel/session end or configured expiry ends unsent work, persists terminal state and updates phone. Late approval rejects. “Action was not performed” is used only when nothing could have been sent. |
| 7. Phone offline | Request remains pending while call/session lives; delivery retries without a default expiry. Foreground/reconnect synchronization retrieves current state and only still-live authority can dispatch. |
| 8. Add phone | Owner command and Add Mac run committed SAS comparison; Mac confirms first; Face ID creates/proves key; App Attest binds registration; both persist and recover final acknowledgement idempotently. |
| 9. Add agent | Commit owner name/identity/token verifier; print token once; authenticate each call; missing/invalid token refuses connection. |
| 10. Stolen phone | No Face ID means no approval-key use. Mac revoke invalidates one registration/generation; late signatures reject. Other approvers stay independent. |
| 11. Face ID changed | Key becomes unusable; phone asks for registration again. New key generation never inherits old approvals. |
| 12. Two approvers | Same request bytes reach every eligible approver. Distinct identities count once; second valid response meets 2-of-2; default denial veto applies while collecting. Later votes are ignored; handoff still checks current registrations. |
| 13. Output filtering | One actual selected tool runs once; all relevant returned representations are filtered/withheld consistently. Missing filesystem sharing-link example remains an explicit tool-selection question. |
| 14. Escape | Namespace policy restricts traffic to the fixed BOGO forwarder, credentials are absent and upstream roots constrained. An agent token does not replace approval. |
| 15. Verify record | CLI verifies chain, historical keys, exact signatures and dispatch evidence, reporting corruption, invalid evidence and unknown outcomes accurately. |
| 16. Flood/pause | Duplicate display groups preserve nonces; pending-limit excess is rejected/logged without push; authenticated epoch-bound pause denies pending and rejects all new requests; Mac unpause invalidates delayed old pauses. |
| 17. Two upstreams | Separate mappings, connections and preparation keep Stripe and filesystem independent; waiting for phone approval holds neither another upstream's transport nor a database transaction. |
| Pending-and-retry | First call creates request and returns pending; same-session identical retries attach; approval settles; first matching live retry reserves/sends once; a later terminal-following identical action needs a new nonce and approval. |
| Owner cancel/remove | Mac cancellation ends unsent authority. Phone removal disables signing locally and reliably requests self-revocation until Mac acknowledgement. |
| Old phone requests | Ignore Apple Bridge approval jobs; explicitly reject photo/audio; independent BOGO notifications and registration work without Apple Bridge Mac pairing. |

Outcomes are model-readable: approved returns the real filtered upstream result; denied returns the specified owner-denial text and optional note; unsent ending returns “Approval was not received in time; the action was not performed”; pending explains identical same-session retry; other rejections identify missing justification, pause, flood, policy, incompatibility or invalid input. Unknown execution is never mislabeled as an unsent ending.

## 5. Failure

| Failure | Safe behavior and recovery |
|---|---|
| Bad config, permissions, schema transform or malformed bytes | Reject affected admission/startup with precise error; no fallback allow, repaired JSON or invented interface. |
| Mac crash while collecting/settled | Recover committed journal; end every old service-generation session before admission; enqueue terminal updates. No executable pending request is resumed. |
| Crash after reservation or possible send | Preserve consumption; never replay. Report not-sent only with evidence, otherwise outcome unknown. |
| Cancellation/expiry during storage commit | Final Lean handoff rejects using current observations/time; consumed authority stays spent. |
| Lost upstream result | Record unknown if necessary; reconnect for future work without retrying the call. Never claim the provider did nothing. |
| Phone termination after signing | Reload durable original decision/outbox and resend without another biometric signing ceremony. Mac deduplicates. |
| Phone termination after inbound receipt | Request already stored before `seen`; reconcile state before allowing stale cached UI to imply freshness. |
| Relay loss/reorder/replay | Outboxes and full scoped IDs retry/reconcile; accept unseen out-of-order messages; terminal versions prevent resurrection. Omission affects availability only. |
| APNs dropped/force-quit/background denied | Inbox remains independent; reconcile when iOS next runs the feature. No guaranteed wake or notification timing. |
| Registration final reply lost | Resume same transaction and return committed result; do not falsely assert neither side registered. |
| Late decision/stale key generation | Reject or log ignored evidence; never target recycled sequence IDs or reopen settled voting. |
| Revocation after threshold but before send | Handoff checks active eligible generations and refuses invalid authority. |
| Stale pause after unpause | Control epoch mismatch rejects it, including first delivery during the same boot. |
| Key invalidation/attestation unavailable | No fallback approval/registration. Prompt re-registration when necessary; retry transient delivery separately. |
| Disk full/unavailable/corrupt | Stop affected admission/effects; preserve committed evidence. Do not acknowledge uncommitted acceptance. |
| Clock rollback/sleep | Monotonic lifetime does not grow; revalidate transports on resume; uncertainty rejects handoff. |
| Filter failure | Withhold unsafe output while retaining actual execution status; never rerun. |
| Restored old state | Start a fresh service generation, invalidate old sessions and reconcile. If registration/control freshness cannot be established, require fresh registration rather than accepting uncertain authority. |
| Sandbox/forwarder failure | Agent loses its only route; setup fails closed and observed session/call loss ends authority. No direct fallback. |

Automatic recovery means durable local recovery and retryable message delivery, not restoration of destroyed storage, revival of dead sessions or replay of uncertain provider side effects.

## 6. Data and versions

```text
~/.bogo/                         0700
  bogo.toml                     owner-edited policy, format version
  secrets.toml                  0600, credential values/references
  state.sqlite                  authoritative registry/journal/audit/outboxes
  keys/                         BOGO-only Mac key material, 0600 files
  run/bogo.sock                 owner-only control socket
  run/writer.lock               one installation writer
```

Core tables include installation/boot records, agents/token verifiers/control epochs, approver generations/history/evidence, immutable request bytes/local context, attempts/reservations/outcomes, audit events, endpoint outboxes/receipts and registration transactions. Derived catalog/query indexes are not authorization history. Constraints enforce one consumption per request and one counted identity per request. Old request records support audit/phone reconciliation, never a reusable execution grant.

Configuration schema:

| Table/field | Meaning |
|---|---|
| `version` | Explicit configuration version; unknown versions/keys reject. |
| `server` | Local bind and explicit bounded body/structural settings; no hidden session/request expiry. |
| `relay.url` | Independent public HTTPS endpoint and selected port. |
| `apns` | Key reference, key ID, topic and environment configuration. |
| `upstreams.<id>` | Exactly one local command/args or remote URL; secret references for required env/headers; private process state. |
| `defaults` | Approve default, denied-tool visibility, owner-selected pending limit. |
| `tools.<namespaced-name>` | Policy, justification required/optional, highlight paths/formats, eligible names, any/k threshold, denial behavior, optional expiry, wait/pending_retry, strip/redact paths. |
| `agents.<owner-name>.tools.<name>` | Per-agent policy/eligible-approver overrides, validated against effective threshold. |
| `iphone` | Accepted registration distribution/version policy and supported protocol versions. |

Required behavior values left unspecified by the spec remain explicit setup decisions, not fabricated defaults. A native rotating upstream credential file is not silently allowed by a type alias; the credential-storage question must be resolved before claiming that integration satisfies the literal TOML requirement.

The phone store holds exact request bytes, state versions, local decisions, endpoint receipts/outboxes, per-Mac registrations and in-progress registration state. Approval keys and channel keys have distinct protection classes. The relay stores only opaque ciphertext, routing/public-auth material and mailbox state.

Version the request format, Rust–Lean ABI, registration transcript, HPKE envelope, control payloads, audit and database independently. Unknown critical versions/tags/trailing bytes reject. All approvers counted for one request sign the same version and original bytes; do not encode different per-approver requests and combine the signatures. Migrations run transactionally before traffic. Historical bytes are not rewritten and historical verification remains available. Pin Lean, Cargo and Swift dependencies and installed upstream versions to the implementations actually integrated.

## 7. Repo layout

```text
bogo/
  crates/
    bogo-domain/        opaque IDs and bridge values
    bogo-lean/          dedicated thread, Rust/C ABI
    bogo-json/          lexical JSON parser/writer
    bogo-mcp/           HTTP edge, exact extension/lifecycle integration
    bogo-config/        TOML, policy/catalog transformations
    bogo-runtime/       coordinator and one-shot dispatch wiring
    bogo-store/         SQLite, audit, outboxes and receipts
    bogo-upstream/      private processes/HTTP adapters and filtering
    bogo-crypto/        signatures, registration, App Attest, HPKE
    bogo-delivery/      approver routes, reconciliation, direct APNs
    bogo-relay/         independent relay executable
    bogo-cli/           CLI and service entry
    bogo-shim/          stdio/raw HTTP and liveness
    bogo-sandbox/       fixed forwarder and specified bypass executable
  lean/Bogo/
    Domain.lean Encoding.lean Policy.lean Transition.lean
    Properties.lean Exports.lean
  protocol/             wire documentation and Lean-generated vectors
  development/
    phone-standin/       real delivery, no production execution
    software-approver/   separate threshold demonstration build
  sandbox/              container topology and namespace initialization
  deploy/macos/         LaunchAgent
  deploy/relay/         independent service/TLS/firewall configuration
  docs/                 configuration, threat-model, proved-and-assumed
  README.md

apple-bridge-iphone/
  Packages/BOGOFeature/Sources/
    BOGOProtocol/ BOGOCrypto/ BOGOStore/ BOGOTransport/ BOGOFeature/
  ios/App/              tab mounting and facade edge
  ios/Delivery/         BOGO category routing/token fan-out, old-job handling
  ios/Capabilities/Capture/   explicit denied behavior
```

Domain/Lean imports no SDK or UI types. Only the ABI bridge touches Lean runtime ownership. MCP and delivery cannot import the concrete upstream sender; only runtime wiring constructs private dispatch tickets. The store cannot initiate execution. The relay imports routing/framing, not decryption or policy. Normal BOGO excludes both development executables and software registration authority.

On iPhone, protocol/model knows no SwiftUI or host code; crypto/store do not import views; transport cannot manufacture approval signatures. The host imports only the public facade. No BOGO target imports Apple Bridge identity, registration, approval jobs or Mac service paths. Retiring old approvals removes the alternate path, not merely its tab label.

## 8. Build order

1. Define the exact value/request/control contracts, Lean encoding/decoding and emitted vectors; define the phone facade and transport ports. These are shared prerequisites, not a full Mac daemon.
2. Build phone protocol/model/store/review and host replacement against the BOGO stand-in. Build real HPKE, SAS/App Attest, relay and APNs paths into that stand-in so registration and delivery are exercised before production authorization exists. No real upstream effect is available through it.
3. Complete the iPhone Inbox/History/Macs, key enforcement, durable decision delivery, synchronization and old-feature retirement through those ports.
4. Implement Lean lifecycle/policy/settlement/consumption proofs and the dedicated runtime bridge, then the store/coordinator transaction and prepared-handoff interfaces.
5. Connect Mac owner configuration, registries, CLI, launch supervision and the production approver route, reusing the independent delivery mechanisms rather than the stand-in's decision behavior.
6. Connect lossless rmcp ingress/discovery, shim/liveness, exact upstream transports, complete-result filtering and historical audit verification.
7. Assemble all existing mode/threshold/expiry/revocation/flood controls through the proved transitions; keep the software approver separate from normal registration.
8. Assemble Docker namespace isolation and its prescribed bypass executable; configure actual Link testmode/filesystem operations after the relevant spec decisions; publish quick start, configuration reference, threat model and proved/assumed documentation from the actual contracts.

No interim normal-use path uses an unrestricted old phone key, a Rust authorization substitute or any Apple Bridge Mac service.

## 9. Libraries

| Choice | Why | Source |
|---|---|---|
| Lean 4 / Lake | Required executable decision/encoding functions and proofs, compiled to C | [Lean](https://github.com/leanprover/lean4), [FFI](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) |
| rmcp, pinned 3.10.0 integration baseline | Required MCP SDK with custom transport seams and both documented protocol eras | [Rust SDK](https://github.com/modelcontextprotocol/rust-sdk), [HTTP transport trait](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html) |
| BOGO lexical parser/writer | Retain numeric tokens and reject duplicate decoded keys; SDK number objects are not authoritative | [JSON grammar, RFC 8259](https://www.rfc-editor.org/rfc/rfc8259), [serde_json behavior](https://github.com/serde-rs/json/blob/master/src/de.rs) |
| Serde/serde_json | Ancillary framing, config views and nonsigned results; never authoritative argument normalization | [serde_json](https://github.com/serde-rs/json) |
| Tokio, Axum/Hyper, Reqwest | Async processes/HTTP, request extensions, controlled transport and direct APNs HTTP/2 | [Tokio](https://github.com/tokio-rs/tokio), [Axum](https://github.com/tokio-rs/axum), [Reqwest](https://github.com/seanmonstar/reqwest) |
| rusqlite / SQLite | Atomic registry/journal/audit/outbox, plus independent relay storage | [rusqlite](https://github.com/rusqlite/rusqlite), [atomic commit](https://www.sqlite.org/atomiccommit.html), [pragmas](https://www.sqlite.org/pragma.html) |
| Rust hpke / CryptoKit HPKE | Standard authenticated single-shot envelopes with native iOS support | [rust-hpke](https://github.com/rozbb/rust-hpke), [CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke), [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) |
| RustCrypto p256, sha2, hkdf; ed25519-dalek | Approval verification, hashes/KDF and separate mailbox/control authentication | [elliptic curves](https://github.com/RustCrypto/elliptic-curves), [hashes](https://github.com/RustCrypto/hashes), [KDFs](https://github.com/RustCrypto/KDFs), [dalek](https://github.com/dalek-cryptography/curve25519-dalek) |
| macOS Security trust validation, Ciborium, strict DER | Complete current App Attest validation against Apple anchor; no upstream Keychain writes | [security-framework](https://docs.rs/security-framework/latest/security_framework/), [Ciborium](https://github.com/enarx/ciborium), [DER](https://github.com/RustCrypto/formats/tree/master/der), [Apple validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) |
| TOML, Clap | Typed owner configuration and command interface | [TOML](https://github.com/toml-rs/toml), [Clap](https://github.com/clap-rs/clap) |
| Swift CryptoKit, Security, LocalAuthentication, DeviceCheck | Enclave keys, Face ID, HPKE and App Attest | [Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave), [DeviceCheck](https://developer.apple.com/documentation/devicecheck) |
| SwiftUI, UserNotifications, URLSession, SQLite C | Native screens, notification integration, transport and independent durable phone state | [SwiftUI](https://developer.apple.com/documentation/swiftui), [UserNotifications](https://developer.apple.com/documentation/usernotifications), [SQLite C](https://www.sqlite.org/cintro.html) |
| Rustls / lego DNS-01 | Independent public relay TLS and scoped Cloudflare certificate lifecycle | [Rustls](https://github.com/rustls/rustls), [lego Cloudflare](https://go-acme.github.io/lego/dns/cloudflare/) |
| Docker, Link CLI, official filesystem server | Specified isolation environment and unmodified upstreams | [Docker internal networks](https://docs.docker.com/reference/cli/docker/network/create/#internal), [Link](https://github.com/stripe/link-cli), [filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) |

Pin resolved versions and source behavior at integration rather than asserting that every newest dependency is already compatible. Dependencies are not formally verified by the Lean theorem. Request-extension propagation, metadata tickets and first-write scheduling are explicit adapter contracts to establish against the pinned rmcp source.

## 10. Risks and open questions

| Risk | Consequence | How to establish the boundary |
|---|---|---|
| SDK decode or send bypass | Approved arguments differ from forwarded bytes | Follow original tokens through shim, extensions, Lean and exact writer; inspect every upstream write entry. |
| Async work after final check | Expired/revoked authority is sent late | Trace commit, lifecycle ordering and actual first-write handoff; eliminate connection setup/queues after final authorization. |
| Universal MCP/schema promise | Valid upstream tools or direct stateless modes cannot fit exact current interface | Inspect negotiated protocols and real schemas; report unsupported transformations/interactions and resolve owner decisions. |
| SAS adaptation | Transcript/commitment mistakes weaken numeric comparison | Review role/key/nonce/version binding and final acknowledgement against the commitment protocol and actual crypto APIs. |
| Attestation overclaim | Wrong app/build or unprotected external key becomes trusted | Validate current Apple fields and the accepted app's internal key-creation path; state app-mediated assumption explicitly. |
| Reordered controls | Wrong request denied, valid response lost or stale pause applied | Trace full IDs, durable receipts, terminal versions and per-agent epochs through reconnect/restart. |
| Legacy phone entry points | Old unrestricted approvals/capture remain reachable | Trace tab, notification and delivery/capability edges; ensure explicit capture rejection and ignored approval jobs. |
| Isolation topology | Gateway/DNS/IPv6 or broad filesystem roots bypass BOGO | Inspect effective namespace rules/mounts/roots and run the required bypass executable inside the actual reference environment. |
| Provider outcome ambiguity | A lost reply is misreported as no action | Keep not-sent distinct from outcome unknown; never replay uncertain calls. |
| Storage corruption/exhaustion | Lost audit or falsely acknowledged decisions | Trace atomic commit/receipt boundaries, startup verification and full-disk refusal; expose valid-prefix limitations. |
| APNs/iOS execution limits | No alert/background fetch despite pending work | Keep endpoint inbox/outbox reconciliation independent of push delivery. |
| Real upstream mismatch | Live purchase or fictional tool used as demonstration | Use actual Link testmode schemas/results; select a real filtering result; do not infer test-only login. |

This is an architectural design and set of proof obligations, not a claim of completed Lean proofs, successful biometric operations, a deployed relay or observed sandbox isolation.

## 11. Questions for the user

1. **Unknown execution outcome:** May BOGO report “execution outcome unknown; not retried” after a send might have occurred? Arbitrary unmodified upstreams cannot simultaneously provide at-most-once forwarding, lossless automatic completion and a universal “silence means nothing happened” guarantee.
2. **Session compatibility:** Which direct MCP clients/protocols must support pending-and-retry? The supplied shim provides an explicit lifetime; stateless direct HTTP cannot provide same-session retry without an additional contract. Silent abandonment without a protocol signal remains unobservable; no idle expiry is added here.
3. **Exact schema/interaction interface:** For tools that cannot faithfully accept the added justification property, or need execution-changing interactive exchanges, may the interface use a wrapper/metadata/new approval exchange, or must those tools be reported incompatible? The universal compatibility promise needs this boundary resolved.
4. **Default policy precedence:** If the owner sets default allow, do newly discovered tools still require approval until explicitly configured, or inherit allow immediately? No weaker interpretation is silently selected.
5. **Accepted registration trust:** Is genuine-app-attested internal creation of the biometric key the intended App Attest guarantee, and which distribution/version evidence identifies an accepted BOGO build? Public App Attest is not direct ACL attestation of an arbitrary approval key.
6. **Behavior values:** What short Approve delay and default per-agent pending limit should setup use? Operational mailbox/body bounds also need chosen values, without becoming request-expiry rules. No performance target or timed trial is introduced.
7. **Reference inference route:** Does inference run outside the container, or may the spec permit a constrained model-provider route? Literal BOGO-only egress excludes ordinary cloud inference from inside it.
8. **Link operation and policies:** Which discovered Link tools should be protected, and which supported testmode SpendRequest/credential operation realizes the payment scenario without claiming a completed merchant charge?
9. **Credential storage:** Must rotating native CLI session state physically live inside `secrets.toml`, or may an unmodified upstream maintain a private owner-only auth file on BOGO's side referenced from TOML?
10. **Filtering scenario:** Which actual tool/result should demonstrate public-link removal? The selected official filesystem server has no sharing-link operation.
11. **Second approver:** Is another Face ID-capable iPhone available for real 2-of-2 use? The software approver remains confined to the separate specified development build.
12. **Unconfirmed speed/setup aspirations:** Should the earlier allowed-call overhead, notification-latency and setup-time aspirations become requirements? They are not goals of this architecture and no benchmark/soak/count/duration is added.
