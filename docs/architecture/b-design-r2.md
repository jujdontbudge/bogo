# BOGO: Architecture

Status: 2026-11-14. Built from SPEC.md.

## 0. The shape

BOGO is one Rust daemon on the owner's Mac. Agents see it as a single MCP server over Streamable HTTP (`rmcp`). Stdio-only clients reach it through a small shim. Every tool call, allowed or protected, goes through one pure decision function. That function is written in Lean 4 and compiled to C, and the daemon links the exact compiled code the proofs are about. It runs on one dedicated thread and takes bytes in and gives bytes out. Policy resolution, the stripping of the justification field, request encoding, single-use, session binding, k-of-n counting, revocation, pause and the flood limit all live inside it. Signature checks also run inside it, through one `extern` hook into Rust, which is the stated cryptographic assumption. Everything else is a thin effects shell around that core: the MCP front, the upstream manager, the hash-chained audit log, output filtering, the approver hub and the owner CLI. The shell only carries out what the core outputs. It forwards exactly the arguments the core emits, and only when the core says `forward`. A protected call passes two core steps. The step that settles the request outputs `authorized`. The shell makes that durable in the log, then sends `dispatch`. The core rechecks session, call, expiry, agent and approver registration against everything it has seen so far, and only then outputs `forward`, which the shell writes to the upstream at once. Tool arguments never pass through a lossy JSON parse. One strict lexical parser (`bogo-json`) reads each request body once, keeping every number's exact text and rejecting duplicate keys. One exact writer emits the forwarded arguments. The upstream transports refuse any `tools/call` that does not come from a `forward` output. Approvers are plug-in routes behind one trait. The first route is the iPhone section, a separate Swift package (`BogoKit`) inside apple-bridge-iphone. It holds a Face ID–bound Secure Enclave P-256 key (`.biometryCurrentSet`), proven at registration with App Attest. It talks to BOGO only through HPKE-auth-sealed messages that pass through BOGO's own store-and-forward relay at `bogo.eilmer.si`, and it is woken by APNs pushes that the Mac sends itself. Pending requests live only in memory and die with their session, so a crash or restart ends every request, which fails closed. Every request-scoped message carries the full request ID, which includes the random boot ID, so nothing from an earlier boot can touch a later request. The audit log is written ahead of every protected effect, so a crash loses no record. The log is also the single source of truth for the agent and approver registry, including pause epochs, which is rebuilt from it at startup. Every link that can drop is retried idempotently: relay mailboxes, the phone's outbox and BOGO's delivery loop. Duplicates are recognized by message ID, never by counters that a reordering relay could defeat.

## 1. Runtime picture

```
 Docker (reference sandbox)                      owner's Mac
┌───────────────────────────┐          ┌───────────────────────────────────────────────────────────┐
│ agent harness             │          │ bogo daemon (launchd user agent, KeepAlive)               │
│  └ MCP client ──HTTP──────┼─► gate ──┼─► 127.0.0.1:<port>/mcp                                  │
│    (or stdio → bogo-shim) │ (socat,  │   ┌──────────────┐ Input bytes  ┌──────────────────────┐  │
│ netns: default-deny       │  only    │   │ front (rmcp  │─────────────►│ core thread          │  │
└───────────────────────────┘  BOGO)   │   │ server, auth,│◄─────────────│  Lean BogoCore.step  │  │
                                       │   │ liveness)    │ Output bytes │  (+ extern verify)   │  │
                                       │   └──────┬───────┘              └──────────┬───────────┘  │
                                       │          │ forward(exact args)             │ ask/ended    │
                                       │   ┌──────▼───────┐   ┌─────────┐   ┌───────▼──────────┐   │
                                       │   │ upstream mgr │   │ audit   │◄──│ approver hub     │   │
                                       │   │ (rmcp client)│   │ log     │   │  └ iphone route  │   │
                                       │   └──┬────────┬──┘   │ (WAL)   │   │  └ soft (tests)  │   │
                                       │      │stdio   │HTTPS └─────────┘   └──┬────────────┬──┘   │
                                       │  link-cli  remote MCP             APNs (HTTP/2)  relay  │
                                       │  fs server  (secrets from ~/.bogo/secrets.toml)  client │
                                       │   ▲ unix socket ~/.bogo/run/bogo.sock ◄── `bogo` CLI     │
                                       └───┼───────────────────────────────────────┼───────┼─────┘
                                           │                                       │       │ HTTPS long-poll
                                   owner terminal                                  │       ▼
                                                                    ┌──────────────┼───────────────┐
                                                                    │ VPS: bogo-relay (own port,   │
                                                                    │ own systemd unit, own SQLite)│
                                                                    │ mailboxes of ciphertext only │
                                                                    └──────────────┬───────────────┘
                                                                       APNs push   │ HTTPS
                                                                           ▼       ▼
                                                     ┌──────────────────────────────────────────┐
                                                     │ iPhone: Apple Bridge app                 │
                                                     │  host shell ──narrow edge──► BogoKit     │
                                                     │  (tabs, push token, notif.   ├ BogoModel │
                                                     │   delegate routing)          ├ BogoCrypto│
                                                     │                              ├ BogoRelay │
                                                     │                              └ BogoSect. │
                                                     └──────────────────────────────────────────┘
```

How the parts talk:
- Agent to BOGO: MCP Streamable HTTP with `Authorization: Bearer <agent token>`. The stdio shim is a byte pump. It passes each stdio line as one POST body, unparsed. It carries its own BOGO session in a header and holds a liveness stream open (§3.15).
- Front to core: an in-process channel to the core thread. Each step passes one encoded `Input` and gets back the encoded `Output`s.
- Daemon to upstreams: `rmcp` clients over a child process's stdio (local) or Streamable HTTP (remote). Both go through BOGO's exact transports, which write `tools/call` arguments byte-exact (§3.7).
- Daemon to phone: HPKE-auth-sealed envelopes go into the phone's relay mailbox, plus an APNs alert push sent straight from the Mac.
- Phone to daemon: HPKE-auth-sealed envelopes go into BOGO's relay mailbox. BOGO holds a long-poll open on its mailbox.
- CLI to daemon: JSON lines over a Unix socket that only the owner can open (mode 0600).

## 2. Units

| Unit | Language | Owns | May depend on | Must never depend on |
|---|---|---|---|---|
| `lean/BogoCore` | Lean 4 | JSON value tree, request encoding and decoding, policy resolution, the decision state machine (`step`), the Rust↔Lean wire codec, the FFI exports | Lean `Init` and `Std` only | Lean compiler (`Lean`) package, Mathlib, any I/O |
| `lean/BogoProofs` | Lean 4 | Specification of the promise and all proofs, including encoding injectivity | `BogoCore`, `Std` | Being linked into any binary |
| `lean/BogoVectors` | Lean 4 | Executable that writes test vectors (`vectors/*.json`) | `BogoCore` | Anything in Rust or Swift |
| `bogo-core-sys` | Rust + C | Building the Lean static library, the C shim (`shim.c`) around `lean.h`, raw `extern "C"` | `cc`, the Lean toolchain at build time | Every other BOGO crate |
| `bogo-json` | Rust | Strict lexical JSON parser (exact number text, duplicate-key and lone-surrogate rejection, depth and size limits) into `JVal`; exact writer from `JVal` | nothing beyond `std` | Everything else |
| `bogo-core` | Rust | Safe `Core` handle, the dedicated core thread, typed `Input`/`Output`, the Rust wire encoder/decoder | `bogo-core-sys`, `bogo-json` | rmcp, I/O, approver routes |
| `bogo-verify` | Rust | `bogo_verify` export that the Lean `extern` calls: dispatch by algorithm tag (P-256 ECDSA; soft Ed25519 only with the `test-approvers` feature) | `p256`, `ed25519-dalek` (feature-gated) | Anything else |
| `bogo-config` | Rust | Parsing and validating `bogo.toml` and `secrets.toml` into typed values; the `Secret` type (no `Serialize`, no `Debug` contents) | `toml`, `serde` | core, rmcp, network |
| `bogo-state` | Rust | The `~/.bogo` layout and permissions, the single-writer `flock`, atomic checkpoint files (agents with pause epochs, approvers, tool catalog, boot counter) and their rebuild by replaying the log, BOGO's own keys | `bogo-config`, `bogo-log` (reader), `fs4` | core, rmcp, network |
| `bogo-log` | Rust | The append-only hash-chained audit log: group-commit writer, reader, search, export, `verify` | `sha2`, `serde_json`, `bogo-core` (decode and verify through Lean) | front, upstreams, approver routes |
| `bogo-filter` | Rust | Output filtering (strip or redact field paths in tool results) | `serde_json` | Everything else |
| `bogo-upstream` | Rust | Upstream connections, the exact transports (child stdio and HTTP client), the namespaced tool catalog with pagination, the justification field in schemas, exact-argument forwarding, redaction of known secret values from results and errors, restart and backoff | `rmcp` (client), `bogo-json`, `bogo-config` | core, front, log, approvers |
| `bogo-front` | Rust | MCP server: agent-token auth, the exact-body layer, call and session liveness, BOGO sessions, the per-agent `tools/list`, mapping tool calls to core `Input`s and outcomes to model-readable results | `rmcp` (server), `axum`, `bogo-json`, `bogo-core` types | upstream internals, approver routes, log internals |
| `bogo-approver` | Rust | The `ApproverRoute` trait, the approver hub (fan-out, delivery retry, inbound decisions), the registration driver | `bogo-core` types | rmcp, the front, the upstreams |
| `bogo-relay-proto` | Rust | Relay wire types, mailbox auth, the async relay client (long-poll, send, ack, retract, lobby) | `reqwest`, `ed25519-dalek` | Any daemon crate |
| `bogo-e2e` | Rust | Envelope format, HPKE auth mode seal and open, message IDs | `hpke` | Network |
| `bogo-apns` | Rust | APNs token-auth HTTP/2 client (ES256 JWT, alert pushes, collapse IDs) | `reqwest`, `jsonwebtoken` | Everything else |
| `bogo-approver-iphone` | Rust | iPhone route: SAS registration, the App Attest check (all of Apple's steps), request delivery, decision intake, ended notices, push | `bogo-approver`, `bogo-relay-proto`, `bogo-e2e`, `bogo-apns`, `appattest`, `ciborium`, `p256` | core internals, front, upstreams, anything from Apple Bridge |
| `bogo-approver-soft` | Rust | Software approver for automated 2-of-2 checks; compiled only with `--features test-approvers` | `bogo-approver`, `ed25519-dalek` | Being present in a release build |
| `bogo-daemon` | Rust | Wiring: the effects shell (output → log → effect, and the `authorized` → `dispatch` → `forward` gate), the control socket, startup and shutdown | all daemon crates above | Apple Bridge anything |
| `bogo` (bin) | Rust | The CLI and `bogo serve` (the daemon entry point launchd runs) | `bogo-daemon`, `clap` | n/a |
| `bogo-shim` (bin) | Rust | stdio ↔ Streamable HTTP byte pump (no JSON re-encoding), one BOGO session per shim process, the liveness stream | `reqwest`, `tokio` | rmcp, every BOGO internal crate |
| `bogo-relay` (bin) | Rust | The relay service: mailboxes, allowlists, lobby, SQLite storage, TLS | `bogo-relay-proto`, `axum`, `rusqlite`, `rustls` | Every daemon crate, the Apple Bridge relay |
| `bogo-standin` (bin) | Rust | Stand-in for BOGO while the phone is built: real registration, real relay, real push; sends requests from Lean vectors and prints verified decisions | `bogo-approver-iphone`, `bogo-state`, `bogo-verify` | front, upstreams, core thread |
| `bogo-bypass` (bin) | Rust (Linux target) | The bypass test suite the spec asks for, run inside the sandbox container | `rmcp` (client), `reqwest` | Every BOGO internal crate |
| `sandbox/` | Docker Compose + nftables | The reference setup: internal network, `netpol` namespace holder with default-deny rules, `gate` TCP forwarder, agent service | Docker | Host home directory mounts, the Docker socket |
| `BogoKit/BogoModel` | Swift | Request decoding (canonical checks), the render model, mismatch rule, duplicate grouping, inbox state machine | Foundation | UIKit, SwiftUI, Security, host app code |
| `BogoKit/BogoCrypto` | Swift | Secure Enclave approval key, HPKE auth, relay auth key, App Attest, Keychain items under BOGO's own service names | CryptoKit, Security, LocalAuthentication, DeviceCheck | Host app code, BogoSection |
| `BogoKit/BogoRelay` | Swift | The `MacLink` port, its relay implementation and a local stand-in implementation, persistent outbox, message pump | BogoModel, BogoCrypto, Foundation | Host app code |
| `BogoKit/BogoSection` | Swift | SwiftUI (Inbox, History, Macs, review, Add Mac), the `BogoSection` facade, notification category, push handling | All BogoKit modules, SwiftUI, UserNotifications | Apple Bridge `PairingClient`, `DeviceIdentity`, `PushDelivery`, `PhoneJob`, the gateway |
| Host edge (`ios/App/*`) | Swift | The BOGO tab in place of Approvals, notification routing, the shared push token, removing the old Approvals feature, capture always denied | `BogoSection` facade only | BogoKit internals |

## 3. Core pieces

### 3.1 The decision core (Lean 4: `BogoCore`)

**What it does.** It is a deterministic state machine. Every event that can affect a decision is an `Input`. Every decision is an `Output`. It does no I/O. It reads the time only from inputs. It mints request sequence numbers itself.

**Interface sketch (Lean):**

```lean
-- Values: exact JSON tree. Numbers keep their source text.
inductive JVal
  | null | bool (b : Bool) | num (text : String) | str (s : String)
  | arr (xs : List JVal) | obj (kvs : List (String × JVal))   -- canonical: keys strictly ascending by UTF-8 bytes

inductive PolicyKind | allow | approve | deny
inductive Requirement | anyOf | kOfN (k : Nat)
inductive DenyRule | anyDenial | whenUnreachable         -- k-of-n: default anyDenial
inductive Mode | wait | pendingRetry
inductive Format | text | moneyMinor (iso4217 : String)  -- "usd_cents" = moneyMinor "USD"

structure ToolPolicy where
  kind : PolicyKind;  justificationRequired : Bool
  hints : List (List String × Format)                     -- field path, format
  expiryMs : Option Nat;  approvers : List ApproverId
  requirement : Requirement;  denyRule : DenyRule;  mode : Mode

structure AgentOverride where                              -- per agent, per tool
  kind : Option PolicyKind; approvers : Option (List ApproverId); requirement : Option Requirement

structure Request where                                    -- exactly what is signed (SPEC §3.6, nothing more)
  bogoId : ByteArray; upstream : String; tool : String; args : JVal
  justification : Option String; hints : List (List String × Format)
  agentId : AgentId; agentName : String; clientName : Option String
  session : SessionId; nonce : ReqId
  createdMs : Nat; expiresMs : Option Nat

abbrev ReqId := ByteArray      -- 40 bytes: bootId (32) ‖ u64 seq. The request's nonce and its ID everywhere.

inductive Input
  | configure (cfg : PolicyConfig) (catalog : List CatalogEntry)
  | approverSet (a : Approver)            | approverRevoked (id : ApproverId)
  | agentSet (a : Agent)                  | agentRevoked (id : AgentId)   -- Agent carries paused, pauseEpoch
  | ownerPause (agent : AgentId)          | agentUnpaused (id : AgentId) (newEpoch : Nat)
  | sessionOpened (s : SessionId) (agent : AgentId) (client : Option String)
  | sessionClosed (s : SessionId)
  | call (s : SessionId) (c : CallId) (name : String) (args : JVal) (nowMs : Nat)
  | callEnded (c : CallId)                                 -- cancel, disconnect, client gave up
  | approval (a : ApproverId) (r : ReqId) (alg : UInt16) (proof : ByteArray) (nowMs : Nat)
  | denial (a : ApproverId) (r : ReqId) (note : Option String)
  | pauseAgent (a : ApproverId) (agent : AgentId) (epoch : Nat)
  | ownerCancel (r : ReqId)
  | dispatch (c : CallId) (nowMs : Nat)                    -- shell: the `authorized` log entry is durable
  | tick (nowMs : Nat)

inductive Output
  | forward (c : CallId) (upstream tool : String) (args : JVal)   -- justification already removed
  | authorized (c : CallId) (r : ReqId)                    -- requirement met (wait) or matching retry (pending-and-retry)
  | reject (c : CallId) (why : Rejection)                  -- denied note, ended, deny policy, paused, flood, malformed, …
  | pendingApproval (c : CallId)
  | ask (r : ReqId) (bytes : ByteArray) (to : List ApproverId) (groupKey : ByteArray) (pauseEpoch : Nat)
  | settled (r : ReqId) (to : List ApproverId)             -- tells approvers that later responses are ignored
  | ended (r : ReqId) (why : EndReason) (to : List ApproverId)
  | counted (r : ReqId) (a : ApproverId) | ignored (r : ReqId) (a : ApproverId) (why : IgnoreReason)
  | floodDropped (c : CallId) | agentPaused (agent : AgentId)

def step : State → Input → State × List Output

-- Signature or approval-proof check. Outside the proof, an assumption. Implemented in Rust.
@[extern "bogo_lean_verify"]
opaque verify (alg : UInt16) (pk : @& ByteArray) (msg : @& ByteArray) (proof : @& ByteArray) : Bool

-- FFI surface, bytes only:
@[export bogo_core_init] def initFfi (bogoId bootId : @& ByteArray) : State
@[export bogo_core_step] def stepFfi (s : State) (input : @& ByteArray) : State × ByteArray
@[export bogo_core_decode_request] def decodeRequestFfi (b : @& ByteArray) : ByteArray  -- JSON view for the CLI
@[export bogo_core_check_approval] def checkApprovalFfi (pk req proof : @& ByteArray) (alg : UInt16) : Bool  -- for `bogo log verify`
@[export bogo_core_abi] def abiVersion : UInt32
```

`stepFfi` decodes the input bytes with the Lean wire codec. If decoding fails, it returns the state unchanged plus `reject(callIdIfAny, malformed)`. If decoding succeeds, it runs `step` and encodes the outputs. Decoding is part of the proved code, so the promise holds for every byte string Rust could pass, not just well-formed ones.

**Request lifecycle inside the core:**

```
pending ──requirement met──► settled ──dispatch passes──► (forward; removed)
   │                            │  └──dispatch fails──────► (reject; removed)
   ├──denial / end──────────────┴──end──────────────────► (ended; removed)
```

**Decision rules the core keeps:**
- **Resolve policy.** The effective policy is the per-agent override, else the tool's entry, else the default. A tool that is in the catalog but not listed in the config gets the default. The shipped default is `approve`. A name that is not in the catalog is rejected as an unknown tool. Paused agents and revoked agents are rejected for every call.
- **allow** produces `forward` with the arguments unchanged, in the same step. **deny** produces `reject(denyPolicy)`.
- **approve** goes through these checks in order:
  1. The value at the tool's justification key, if present, must be a string. Otherwise the call is rejected as malformed.
  2. If a justification is required and missing, the call is rejected with a message telling the agent to include one.
  3. The core removes the justification key from the arguments.
  4. If the agent's live request count (pending plus settled) is at or over `maxPending`, the call produces `floodDropped` and nothing goes to approvers.
  5. The core builds a `Request`, encodes it, stores it as `pending`, and outputs `ask` to the eligible approvers that are registered and active. If fewer than the requirement are eligible, the call is rejected with `noEligibleApprover` before anyone is asked.
- **Settlement.** The step in which the requirement is met moves the request to `settled` and outputs `settled` to its approvers. From then on, every approval and denial for it is `ignored(settled)`. Settlement is final as a decision. It is not yet permission to run.
- **Wait mode.** The call is held. The settling step also outputs `authorized(c, r)`.
- **Pending-and-retry mode.** If no identical live request exists, the core creates one and returns `pendingApproval`. A retry is identical when it has the same session, upstream, tool, arguments and justification. A retry of a pending request returns `pendingApproval` again. A retry of a settled request outputs `authorized` for the retry's own call ID and binds the request to that call. Only one call can hold that binding, so concurrent identical retries get `pendingApproval` (the request is no longer free) and never a second run. When the request is forwarded or fails its dispatch, it is removed. A later identical call finds no request, so it starts a new one with a new nonce that needs a new approval. An agent can therefore repeat a real action, and no approval ever covers two runs.
- **Dispatch (the final gate).** `dispatch c now` is accepted only for a request in `settled` that is bound to call `c`, and only once. It outputs `forward` with the stored arguments only if all of these still hold. Otherwise it outputs `reject` and an `ended` notice:
  - the call `c` is live and its session is open,
  - `expiresMs`, if set, is greater than `now`,
  - the agent is neither paused nor revoked,
  - the counted approvers that are still registered, active and eligible still meet the requirement.

  Either way the request is removed, so it can never be dispatched again.
- **Approval.** The approval is accepted only if all of these hold:
  - the request exists and is `pending`,
  - `now < expiresMs`, if the request has an expiry (checked here, not only by `tick`),
  - the approver is registered and active,
  - the approver is eligible for this agent and tool,
  - `verify alg pk ("BOGO-APPROVAL\x00v1" ++ bytes) proof` is true.

  Accepted approvals form a set, so the same approver counts once.
- **Denial.** Only a `pending` request can be denied. Under `anyDenial`, one valid denial from an eligible, active approver ends the request, and the call gets `reject(denied note)`. Under `whenUnreachable`, a denial removes that approver from the ones that can still approve, and ends the request only when k can no longer be reached.
- **Ending.** These all produce `ended` (to the approvers) and `reject(endedWithoutDecision)` (to a waiting call):
  - `callEnded`,
  - `sessionClosed`,
  - `ownerCancel`,
  - agent revocation,
  - approver revocation that leaves k unreachable for a pending request,
  - `tick` past `expiresMs`.

  They apply to `pending` and `settled` requests alike. The request is then removed. A late approval finds no request and is `ignored(unknown)`.
- **Pause.** `pauseAgent a agent epoch` is accepted only from a registered, active approver, and only if `epoch` equals the agent's current `pauseEpoch`. `ownerPause` comes from the Mac CLI and needs no epoch. Both deny all of that agent's live requests, mark the agent paused and output `agentPaused`. Only `agentUnpaused`, which comes from the Mac CLI, clears the pause. It also sets the agent's `pauseEpoch` to `newEpoch`, which the shell takes from the log sequence number of the `agent_unpaused` entry. That number is durable and only grows, so a pause message composed before an unpause can never apply after it, even if this is its first delivery.
- **Request IDs.** `ReqId` is the request's nonce: the random boot ID followed by the core's own `seq`, which only grows within a boot. Every request-scoped input carries the full `ReqId`. One that names another boot finds no request and is `ignored(unknown)`. No "seen" set is needed.
- **Grouping key.** `groupKey` is the encoding of (agentId, upstream, tool, args, justification), using the same value grammar as the request. Lean needs no hash function for this. Rust hashes it for the APNs collapse ID. The phone computes the same tuple from the decoded request and groups duplicates by it.
- **Agent pause and revocation scope.** These reject every new `call` from that agent, whatever the policy, with the reason "paused" or "revoked". The front also refuses every other request from a paused or revoked agent, `tools/list` included, with a JSON-RPC error giving the same reason. It reads that from the registry view the shell keeps. The core stays the authority for calls.

**Rules it always keeps:**
- It is total and deterministic, with no `partial` definitions and no `panic!`. The proofs require this.
- The only `forward` sources are an allow decision, or a `dispatch` that passes the final gate for a request bound to that call.
- The `forward` arguments are the request's own arguments, never a value from the current input. In pending-and-retry, the retry only has to match. The stored copy is what gets forwarded.

### 3.2 Request encoding (Lean, mirrored in Swift)

This implements ADR 0001. It is a tagged, length-prefixed binary format. All lengths and counts are `u32` big-endian. A request that would exceed that limit is rejected as malformed.

```
Request  := "BOGOREQ" 0x00 | u16 version=1 | field*        (fields in fixed order, each: u8 field-tag | payload)
  0x01 bogoId   bytes      0x02 upstream str     0x03 tool str          0x04 args value
  0x05 justif   opt(str)   0x06 hints list(path,fmt)                    0x07 agentId bytes
  0x08 agentName str       0x09 clientName opt(str)                     0x0A session bytes
  0x0B nonce    bytes      0x0C createdMs u64    0x0D expiresMs opt(u64)
value    := 0x00 null | 0x01 false | 0x02 true
          | 0x03 u32 len ascii-number-text   (must match the JSON number grammar; text kept exactly)
          | 0x04 u32 len utf8-string
          | 0x05 u32 count value*
          | 0x06 u32 count (u32 len utf8-key value)*        (keys strictly ascending by bytes; duplicates impossible)
opt(x)   := 0x00 | 0x01 x        str := u32 len utf8      bytes := u32 len raw
```

- **Proved.** `decode (encode r) = some r` for every canonical `r`. That gives `encode_injective`: two different requests never encode the same. `decode` also rejects every non-canonical byte string: unsorted keys, a bad number grammar, trailing bytes, or an unknown tag or version.
- **Numbers.** `4700`, `4700.0`, `4.7e3`, `4.7E3` and `4.7e+3` are five different `num` texts, and the encoding never reads them as numbers. Rust gets the exact text only from `bogo-json`, BOGO's own lexical parser, which stores each number token byte for byte. `serde_json` is not used for arguments: even with `arbitrary_precision` it rewrites exponents. Its `scan_exponent` always pushes a lowercase `e` and adds `+` when the sign is missing ([serde_json `de.rs`](https://github.com/serde-rs/json/blob/master/src/de.rs)).
- **Strings** are Unicode scalar sequences after JSON unescaping, so `"A"` and `"A"` are the same string. Escape spelling is syntax, not a different value. `bogo-json` rejects lone surrogate escapes, invalid UTF-8 and control characters that are not escaped, so none of them reach the core.
- **Who encodes what.** The signed bytes are produced only by the Lean encoder inside the core. Swift only decodes, renders and signs the exact received bytes. Rust has an encoder only for the Rust→Lean wire format, which shares the `value` grammar, and a decoder for `Output`. Its exact writer turns a `forward` `JVal` back into JSON text, emitting each number's text unchanged. Rust and Swift are both checked against `vectors/` generated by `BogoVectors`. The vectors include JSON source text, the expected `JVal`, request bytes, and the exact text the writer must produce.
- **Signed message.** The approval signature covers `"BOGO-APPROVAL\x00v1" ‖ requestBytes`. The domain tag means a request signature can never be mistaken for any other signed object.

### 3.3 Proof (`BogoProofs`)

**Model.** The adversary is any `List Input`. The agent controls every `call`, `callEnded`, `sessionOpened` and `sessionClosed`, and can send malformed bytes through `stepFfi`. Session and call lifecycle are adversarial inputs, not trusted facts. The theorems hold whatever order the agent opens, closes, cancels or reuses sessions in. The relay and the network control the order and duplication of every `approval`, `denial` and `pauseAgent`, and can inject arbitrary ones. `dispatch` and `tick` are also arbitrary in the model: the theorems hold even if the shell sent them at any time, any number of times. The theorems hold for all such lists, run from `initFfi`.

**Assumptions, each listed in "What is proved / What is assumed":**
- **A1 Unforgeable approvals.** For every algorithm tag in use, `verify alg (pk a) m p = true` implies `OwnerApproved a m`. This is stated as a hypothesis on the trace, not as a global `axiom`, so it cannot make the logic inconsistent. It covers spec assumptions 1 and 3: the signature can't be forged, and the key is usable only after user verification.
- **A2 Hash collision resistance.** This is used inside ECDSA-SHA-256 and for the log chain. The core's matching uses full byte equality, not hashes.
- **A3 Distinct boots.** `bootId` is 32 random bytes, so two boots never share one. Approvals, denials and every other request-scoped message from an earlier boot can therefore never match a request of a later boot.
- **A7 Genuine app.** App Attest shows that the registering app is the genuine, unmodified BOGO-capable build on a real device. It does not attest the approval key's access control directly. That build creates the approval key only inside the Secure Enclave with `.biometryCurrentSet` and has no path that accepts a supplied key, so the key's Face ID protection rests on this assumption plus spec assumption 3.
- **A4, A5.** These are spec assumptions 4 and 5 (the sandbox, and upstreams rejecting unauthenticated requests). They are listed, but nothing in Lean uses them.
- **A6 Faithful shell.** The Rust shell sends upstream exactly the `forward` outputs and nothing else, writes each one at once, and delivers each agent's own exact argument text to the core. This is the one link the proof cannot see, so it is kept narrow:
  - `bogo-json` parses the body once,
  - the exact transports refuse any `tools/call` that lacks a live forward ticket (§3.7),
  - the writer is checked against Lean vectors.

**Theorems** (where `forward c u t args` appears in the outputs of step i of `run init inputs`):
1. **Approved.** Either the effective policy at step i was `allow`, or there is a request `r` with `r.upstream = u`, `r.tool = t`, `r.args = args`, and a set `S` of distinct approver IDs. Every `a ∈ S` was registered, active and eligible for `(r.agentId, tool)` at step i, and `OwnerApproved a (sigMsg (encode r))` holds. `|S| ≥ 1` for any-of and `|S| ≥ k` for k-of-n.
2. **Exact.** By (1) and `encode_injective`, the owner approved exactly `r`: its upstream, tool, arguments, justification, agent, session, nonce and times.
3. **Single-use.** For every request, at most one `forward` is emitted over the whole trace, and at most one `dispatch` is ever accepted for it.
3a. **Settled is final.** Once a request is `settled`, no later approval or denial changes its state.
4. **Fresh.** At step i, which is the `dispatch` step, `r.session` is open, the call `c` belongs to `r.session` and is still live, the agent is neither paused nor revoked, and if `r.expiresMs = some e` then `now < e` for that step's `now`. Every ending, revocation and pause that the core saw before step i is honoured. The linearization point is BOGO's decision to hand the bytes to the upstream transport. A provider's physical effect comes later and is outside the model.
5. **Session binding.** `c`'s session equals `r.session`. A call from another session never matches.
6. **Fail-closed.** No `forward` is ever emitted for a call that is:
   - under a `deny` policy,
   - from a paused, revoked or unknown agent,
   - for an unknown tool,
   - from a closed session,
   - from a malformed input (any bytes that `decode` rejects),
   - for a request that has ended,
   - for a settled request whose call or session ended, whose agent was paused or revoked, whose expiry passed, or whose counted approvers fell below the requirement before its `dispatch`,
   - for a `pauseAgent` carrying a stale epoch (it can't pause, and it can't unpause either).
7. **Encoding.** `encode_injective` and `decode_encode`.

The proofs cover any number of approvers, any-of and k-of-n with both deny rules, revocation at any point, per-agent overrides and both modes.

### 3.4 Core host (`bogo-core-sys`, `bogo-core`, `bogo-verify`)

- **Build.** `build.rs` runs `lake build BogoCore:static` against the toolchain pinned in `lean/lean-toolchain` (v4.35.0, the current stable release). It compiles `shim.c` with `cc` against that toolchain's `lean.h`, then links the static library plus the runtime flags reported by `leanc --print-ldflags`. It does not use the `lean-sys` crate. That crate was last released in 2025, while `lean.h` is an internal, unstable interface, so BOGO's own six-function C shim is the only code that touches it ([Lean FFI](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/)).
- **Shim C ABI** (stable, owned by BOGO):

  ```c
  int  bogo_core_start(const uint8_t* bogo_id, size_t n1, const uint8_t* boot_id, size_t n2); // runtime + module init + lean_io_mark_end_initialization
  int  bogo_core_step(const uint8_t* in, size_t n, uint8_t** out, size_t* out_n);            // holds the State object internally
  void bogo_core_free(uint8_t* p);
  int  bogo_core_decode_request(const uint8_t* in, size_t n, uint8_t** out, size_t* out_n);
  int  bogo_core_check_approval(uint16_t alg, const uint8_t* pk, size_t, const uint8_t* req, size_t, const uint8_t* proof, size_t);
  uint32_t bogo_core_abi(void);
  // implemented in Rust (bogo-verify), called from Lean through the extern hook:
  uint8_t bogo_verify(uint16_t alg, const uint8_t* pk, size_t, const uint8_t* msg, size_t, const uint8_t* proof, size_t);
  ```

- **One core thread.** `bogo-core` starts one OS thread. That thread initializes the Lean runtime and holds the `State` object. It serves steps from an `mpsc` channel: `Core::step(Input) -> Vec<Output>`. All decisions are therefore serialized and linearizable, and no other thread ever touches Lean. That rules out the multi-thread rules around `lean_initialize_thread`. At startup it checks `bogo_core_abi()` against the Rust constant and refuses to run on a mismatch.
- **`bogo-verify`.**
  - Tag `1`, P-256 ECDSA: raw `r‖s` over SHA-256 of the message, as CryptoKit produces it. Verified with `p256`.
  - Tag `0xFF00`, Ed25519 for the soft test approver: only exists with `--features test-approvers`. In a release binary the tag returns `false`, so a software approver can't approve anything in a normal BOGO, even if its record is injected.
  - Any other tag returns `false`. A new approver route adds a tag here and its registration module. The Lean core does not change (Principle 7).

### 3.5 Effects shell (`bogo-daemon`)

This is the only consumer of core outputs. Each output is handled as: write the log entry durably, then do the effect. The one exception is `forward`, whose entry is written alongside the upstream call, because the decision it carries out is already on disk (`authorized`) or needs no approval (allow).

| Output | Effect (after the log entry is durable) |
|---|---|
| `authorized c r` | Then send `dispatch c now` to the core (the final gate, below). |
| `forward c u t args` | Send the exact `args` to upstream `u`'s tool `t` through `bogo-upstream` at once, apply `bogo-filter`, resolve waiter `c`. Never retried. It doesn't wait on the log. For a protected call the `authorized` entry is already durable, and for an allowed call there is no approval to record first. The `forwarded` entry goes into the next group commit alongside the send, and the agent's result waits for it. |
| `reject c why` | Resolve waiter `c` with the model-readable text (§3.6). |
| `pendingApproval c` | Resolve `c` with the pending text. |
| `ask r bytes to groupKey epoch` | Hub delivers to each approver in `to`. Delivery retries until `seen` or the request ends. |
| `settled r to` | Hub sends `settled` notices, so phones grey the entry as decided. |
| `ended r why to` | Hub sends ended notices and retracts undelivered messages. |
| `agentPaused a` | The `agent_paused` entry is the record. The checkpoint in `agents.json` is updated after it, and replay rebuilds it after a crash (§3.9). The front's registry view marks the agent paused. |
| `counted` / `ignored` / `floodDropped` | Log only. Flood drops never notify anyone. |

- **Waiters.** Waiters are keyed by `CallId`, a 128-bit value Rust mints per call and passes in the `call` input. The shell never builds upstream arguments itself. The `forward` output is the only source.
- **Forward tickets.** For each `forward`, the shell registers a one-shot ticket `(CallId → JVal)` with that upstream's exact transport, then calls rmcp `call_tool` with the ticket ID in `_meta`. The transport takes the ticket, strips the marker and writes the arguments from the ticket (§3.7). The ticket is removed on use, and a `tools/call` with no live ticket is never written. So a second send of the same forward is impossible, and so is a send from anywhere else.
- **The final gate.** For a protected call, the shell handles `authorized c r` like this:
  1. Append `authorized` to the log and wait until it is durable. The decision, and the signed approvals it rests on, are on disk before anything can run.
  2. Send `dispatch c now` to the core. Every input that arrived during the write (a `callEnded`, a revocation, a pause, a cancel) is queued on the same core channel ahead of it, so the core sees it first.
  3. On `forward`, register the forward ticket and call the exact transport straight away. There is no other `await` between the core's answer and the first write, and no queue, reconnect or credential refresh. If the upstream connection is not up at that moment, the transport refuses, the shell logs `not_sent`, and the agent gets "upstream unavailable; the action was not performed". The request is already consumed and is never retried.
  4. On `reject`, resolve the waiter with the reason and send the `ended` notices.

  This narrows the gap between the last check and the write to one channel hop with no I/O in it. Any event the core has ordered before the gate is honoured. An event that arrives after the gate finds no request and is logged as late.
- **Allowed calls.** `forward` from an allow decision is sent at once. Its `call` and `forwarded` entries go into the same group commit, concurrently with the upstream call. The agent's response waits until they are durable. So an allowed call costs no extra wait before the upstream, and still never returns a result without its record.
- **Time.** `tick` comes from one timer that wakes at the earliest `expiresMs` among live requests. The core reports that value in a `nextDeadline` field of every step's result. There is no polling. The timer only ends requests promptly. Freshness itself is decided from the `now` carried by `approval` and `dispatch`, so a late timer can never let an expired request run.

### 3.6 MCP front (`bogo-front`)

- **Server.** `rmcp` `StreamableHttpService` bound to `127.0.0.1:<port>`. It uses rmcp's loopback `allowed_hosts` and enforces Origin validation.
  - **Legacy session mode on.** Protocol 2025-11-25 and earlier gives real `Mcp-Session-Id` sessions. The session manager's `keep_alive` is `None`, so no idle timer ends a session. BOGO ends sessions only on the events listed below. `sse_retry` is `None`, so BOGO sends no priming event IDs and offers no stream resumption ([`SessionConfig`](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_server/session/local/struct.SessionConfig.html)).
  - **Disconnect.** MCP 2025-11-25 says that disconnection "SHOULD NOT be interpreted as the client cancelling its request", because a stream may be resumed ([transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)). BOGO offers no resumption, so a dropped response stream can never deliver its result. BOGO's spec lists a disconnect as ending the call, so BOGO ends it, which is also fail-closed.
  - **2026-07-28.** Requests that negotiate 2026-07-28 are stateless under that spec ([MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)), and rmcp serves them that way.
- **Layers, outermost first:**
  1. **Agent auth.** The bearer token is hashed with SHA-256 and looked up among non-revoked agents. Without a match the request gets 401 and never reaches rmcp. The `AgentId` goes into the request extensions. rmcp copies `http::request::Parts` into the handler's `RequestContext.extensions`.
  2. **Exact-body layer.** It reads the POST body once and parses it with `bogo-json`. It rejects these with 400:
     - JSON-RPC batches (2025-11-25 allows one message per POST),
     - duplicate object keys at any depth,
     - invalid UTF-8 or lone surrogates,
     - bodies over the configured size or depth.

     For a `tools/call`, it puts `ExactCall { name, args: JVal }` into this HTTP request's extensions. rmcp inserts the HTTP request's `Parts` into the JSON-RPC request's extensions in both session and stateless modes ([`tower.rs`](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport/streamable_http_server/tower.rs)), so the handler gets the exact tree for exactly this request. No ID matching is involved. The handler uses only `ExactCall`, and the `arguments` rmcp parsed for itself are ignored. If `ExactCall` is missing, the call is rejected. "Ambiguous → reject" is true before rmcp parses anything. The agent's `_meta` and progress token on a `tools/call` are never forwarded upstream. The exact transport writes only BOGO's own request.
  3. **Call liveness.** For a `tools/call`, it registers a `Liveness` token keyed by the JSON-RPC id and session, and wraps the response body in a drop guard. If the body is dropped before the final message (the client disconnected), the token fires `callEnded`. rmcp's handler `ct`, which fires on `notifications/cancelled` and on rmcp's own stateless-disconnect handling (rust-sdk #857), fires `callEnded` too. For protected wait-mode calls, BOGO sends no intermediate messages, so the first message is the final one.
- **BOGO sessions.** The core's `SessionId` is `bootId ‖ random 16 bytes`. Three kinds of connection map onto it:
  - **Shim session (any protocol).** Every request carries `Bogo-Session: <128-bit random>`, which the shim mints once per process. The session is bound to the agent of its first request. A `Bogo-Session` request is accepted only while that session's liveness stream (`GET /mcp/bogo-liveness`, same header and token) is open. The session ends when that stream closes (shim exit or crash), on DELETE, on agent revocation, or on daemon stop. This is how a stdio client gets one session per connection whatever MCP version it negotiates. The header is a channel between BOGO's own two parts, never a tool argument. An agent that sends it directly only gets a session it must keep alive itself, bound to its own token.
  - **Legacy protocol, direct.** One BOGO session per `Mcp-Session-Id`, bound to the agent of its first request. A later request on that session with a different agent token is rejected, and the session is closed. The client's self-reported name comes from `initialize.clientInfo`. The session ends on HTTP DELETE, agent revocation or daemon stop. No idle timer ends it, because that would be a preset expiry the spec doesn't have. A wait-mode call still ends the moment its own response stream drops (layer 3). The limit: if a direct client vanishes between requests without sending DELETE, BOGO cannot see that. Its pending-and-retry requests then stay pending until the owner denies or cancels them, the agent is revoked, or BOGO restarts. They can never run, because running needs a retry in that session. This is stated in the docs and raised in §11. The shim has no such gap.
  - **2026-07-28 stateless, direct.** Each `tools/call` is its own session, opened and closed around the call ([MCP 2026-07-28 transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)). The client name comes from `_meta` `io.modelcontextprotocol/clientInfo`. Wait mode works unchanged. A pending-and-retry tool has no session to retry in, so it is rejected with the text "This tool needs a session-based MCP connection (protocol 2025-11-25) or the BOGO stdio shim." That is fail-closed.
- **`tools/list`.** The combined catalog for this agent. A paused or revoked agent gets a JSON-RPC error instead (§3.1). Deny tools are hidden when `hide_denied`. Approve tools get the justification property. For tools with output filters, filtered fields are also removed from the advertised `outputSchema`, including its `required` list, so a client that validates results never expects a field BOGO strips. Order is deterministic: by upstream, then by tool. `cacheScope: "private"`. When an upstream sends `list_changed`, legacy sessions are notified.
- **`tools/call`.** The handler sends `call(session, callId, name, args, now)` to the core and awaits its waiter. It then maps the outcome:
  - forwarded → the upstream's real `CallToolResult` after filtering,
  - denied → `isError: true`, text `"The owner denied this action."` plus `" " + note` if there is a note,
  - ended → `isError: true`, `"Approval was not received in time; the action was not performed."`,
  - pending → `isError: true`, `"Pending owner approval. Retry this exact call (same arguments and justification) in this session to run it once approved."`,
  - not sent at the gate → `isError: true`, `"The upstream was unavailable; the action was not performed."`,
  - other rejections → `isError: true` with the reason (deny policy, paused, flood, missing justification, unknown tool).
- **Not proxied.** Upstream resources, prompts, completions, sampling, elicitation and roots are not exposed. Exposing them would open paths around the gate. BOGO advertises only the `tools` capability.

### 3.7 Upstream manager (`bogo-upstream`)

- **One shared connection per upstream.**
  - Local upstreams: an rmcp client over `ExactChildTransport`, BOGO's own `Transport` impl around the child's stdin/stdout. The child is started with `command`, `args` and a minimal environment built from `secrets.toml` references. Credentials exist only in that child's environment.
  - Remote upstreams: `StreamableHttpClientTransport` over `ExactHttpClient`, BOGO's own `StreamableHttpClient` impl on `reqwest`. Its `post_message` receives the typed message and serializes it itself ([trait](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html)). Headers come from secrets, and redirects are not followed.
- **Exact transports.** Both serialize every outgoing message with serde_json, except `tools/call`:
  - A `tools/call` must carry `_meta["si.eilmer.bogo/fwd"] = <CallId>` matching a live forward ticket (§3.5).
  - The transport removes that key, then writes the JSON-RPC line with `arguments` emitted by the `bogo-json` exact writer from the ticket's `JVal`.
  - A `tools/call` without a live ticket is dropped with an error and logged. This holds whoever inside the daemon tried to send it.
- **Client capabilities.** BOGO's client to each upstream declares no capabilities: no `roots`, `sampling` or `elicitation`. That matters for the filesystem server, whose client-supplied roots would replace the directories given on its command line ([filesystem server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)).
- **Discovery** follows `tools/list` pagination to the end (rmcp `list_all_tools`). It does so again on `notifications/tools/list_changed`.
- **Naming.** Upstream names match `[a-z0-9-]+`, with no `__`, so splitting `<upstream>__<tool>` at the first `__` is unambiguous. A namespaced name over MCP's 128-character limit, or with characters outside `[A-Za-z0-9_.-]`, is not exposed. It is reported in `bogo tools` as `unexposable`.
- **Justification field.** For approve tools, the property name is the first of `justification`, `bogo_justification`, `bogo_justification_2`, `bogo_justification_3`, … that doesn't occur as a property name anywhere in the tool's schema (top level, any combinator branch, any `$defs` entry) and isn't matched by any `patternProperties` pattern in it. So it never collides with a real field, and no upstream field is ever removed. The chosen key is recorded per tool in the catalog, so the core strips exactly that key and nothing else. It is added to `required` when the policy requires it.
  - It is inserted as `{"type":"string","description":"Why you are making this call (shown to the owner as your unverified claim)."}` into the top-level `properties`. Every other part of the schema is left as it is.
  - If the top level closes the object through a combinator (`allOf`/`anyOf`/`oneOf` branch with `additionalProperties: false` or `unevaluatedProperties: false`), a client that validates could refuse the field. BOGO then adds the property to each such branch's `properties` as well. That is the smallest change that keeps the schema valid.
  - A tool whose top level is a `$ref` gets the field at the top level, and also in the referenced definition if that definition closes the object and is referenced nowhere else. Otherwise it is reported as `justification: schema-ref` in `bogo tools`, because a strict client could refuse the field. BOGO itself doesn't validate arguments against schemas. The upstream does that, on the arguments with the field already removed.
- **Catalog.** Catalog changes are persisted to `state/tools.json` with first-seen times, so `bogo tools` works while BOGO is stopped. A new catalog goes to the core as a `configure` input. New tools get the default policy (`approve`).
- **Forwarding.** `call_tool` with the forward ticket in `_meta`, written byte-exact by the exact transport. A tool call is never retried after it has been sent.
- **Results.** Results are parsed by rmcp. `serde_json` is built with `arbitrary_precision`, so large integers and long decimals in results keep their digits rather than going through `f64`. Results are not signed, so exponent spelling in a result doesn't matter. An upstream that crashes mid-call gives the agent `isError: true` "upstream failed; the action may or may not have happened", and the log records outcome unknown.
- **Upstream health.** A child process that exits is restarted with exponential backoff. While an upstream is down, its tools stay in the catalog. A call that reaches the gate while its upstream is down is refused by the transport and logged `not_sent` (§3.5). It is never queued and never retried.
- **Secrets in results.** Before a result or error reaches the agent or the log, `bogo-upstream` replaces every exact occurrence of a configured secret value (and its base64 form) with `[credential removed by BOGO]`, and logs that it did. The `Secret` type stops accidental formatting. This scan catches an upstream that echoes a credential back. It can't catch a credential the upstream transforms in some other way, and the docs say so.
- **Rejected result types.** An upstream `InputRequiredResult` (MRTR) or server→client request is answered as an error. The agent gets `isError: true` "upstream asked for interactive input, which BOGO does not pass through".

### 3.8 Output filter (`bogo-filter`)

- **Rules.** Per tool, `filter_output = ["url", "data.share.link", …]`. A bare name matches that key at any depth. A dotted path matches exactly, and `*` matches every element of an array. The action is `strip` (the default) or `redact`, which replaces the value with `"[removed by BOGO]"`.
- **Where it applies.** To `structuredContent` and to every `text` content block that parses as JSON. For resource-link and embedded-resource blocks, `uri` and `text` are subject to the same key rules.
- **Fail-closed.** If a tool has filters and a text block is not JSON, the block is replaced with `"[output withheld by BOGO: not filterable]"`. The log records the fact, but not the content.
- It is a pure function, `filter(&Rules, CallToolResult) -> (CallToolResult, Report)`, outside Lean.

### 3.9 Audit log (`bogo-log`)

- **File.** `~/.bogo/log/audit.jsonl`, one JSON object per line:

  ```json
  {"v":1,"seq":1042,"prev":"<hex sha256 of line 1041's bytes incl. newline>","ts":"2026-11-14T18:02:11.204Z",
   "kind":"request_created","agent":{"id":"…","name":"Trip planner"},"session":"…","tool":"stripe__<spend tool>",
   "req":1042,"request_b64":"…","justification":"booking the 6pm flight…","policy":"approve"}
  ```

- **Entry kinds.**
  - Lifecycle: `boot` (boot_seq, bootId, bogo.toml SHA-256), `tail_recovered`.
  - Agents: `agent_added`, `agent_revoked`, `agent_paused` (by owner or by approver), `agent_unpaused` (its own `seq` becomes the agent's new pause epoch).
  - Approvers: `approver_registered`, which stores the registration transaction ID, the public keys, algorithm, App Attest key ID, environment, validation category and bundle version, and the attestation SHA-256. Also `approver_revoked`, with `by: "owner"` or `by: "self"` (removed on the phone).
  - Calls: `call` (every attempt, any policy, as Scenario 15 needs allowed and denied calls in the record too), `rejected` (with reason), `request_created`, `approval` (approver ID, algorithm, proof, `counted` or `ignored`+why), `denial` (+note), `request_settled`, `authorized`, `request_ended` (+why), `forwarded`, `not_sent`, `result` (`ok`, `is_error`, `upstream_failed` or `unknown`, filtered fields, credentials removed). Result content is not logged.
- **Credentials never appear.** `Secret` values have no `Serialize`, and the log writer only accepts `LogEvent` values, which can't hold one.
- **Writer.** One task with group commit. Every entry that is waiting is written, then one `sync_data` runs (F_FULLFSYNC on macOS), then all those waiters are released. Protected effects wait for their entry. An allowed call's entry is written alongside its upstream call, and its result waits for it (§3.5). A crash therefore never leaves a protected effect without its record, and never returns any result without one.
- **Registry source of truth.** The log is the only durable authority. Every change to agents, approvers, pause state or pause epoch is a log entry first. The checkpoint files in `state/` are caches. Each is written atomically only after its entry is durable, and records the `seq` of the last entry it reflects. At startup `bogo-state` replays every agent and approver entry after that `seq` (`agent_added`, `agent_revoked`, `agent_paused`, `agent_unpaused`, `approver_registered`, `approver_revoked`), rewrites the checkpoint, and only then feeds the registry to the core. Example: if `agent_paused` is durable and BOGO crashes before `agents.json` is rewritten, replay finds the entry and the agent starts paused. A crash between the log write and the file write therefore loses nothing, and the registry and the log can never disagree. That property is also what `bogo log verify` relies on. A checkpoint that is missing or unreadable is rebuilt from the whole log. Agent entries carry the token's SHA-256, never the token.
- **Recovery.** Only one shape counts as a torn write: a final line with no trailing newline. A record is committed only when its newline is synced, so a line without one was never acknowledged to anything. It is moved to `audit.torn.<ts>`, and a `tail_recovered` entry carrying its hash is appended. `verify` reports this as a recovery, not as tampering. A complete line (newline present) that fails to parse, or whose `prev` hash doesn't match, is corruption. BOGO refuses to start, names the line, and leaves the file untouched. It never repairs authoritative history by dropping a complete record. An `authorized` entry with no `forwarded` or `not_sent` before the next `boot` is reported as "not sent (BOGO stopped)". A `forwarded` entry with no `result` is reported as "outcome unknown (BOGO stopped)". Neither is ever replayed.
- **`bogo log verify`.**
  1. Recompute the chain.
  2. Replay `approver_registered`/`approver_revoked` in order to know who was registered at each point.
  3. For every `approval` entry, check `bogo_core_check_approval` (the same Lean code) against the key registered at that moment, over the logged request bytes.
  4. Check that every `forwarded` protected request has enough counted approvals from approvers that were registered at its `authorized` entry. The threshold and eligible approvers come from the `bogo.toml` SHA-256 in the preceding `boot` entry together with a copy of the resolved per-tool policy that `request_created` carries.

  It reports the first break with its line number.
- **`bogo log [search]`** prints a filtered, decoded view (filters: agent, tool, decision, time range, text). Request bytes are decoded by the Lean decoder export. **`bogo log export`** writes JSON Lines or CSV.

### 3.10 Approver hub and route interface (`bogo-approver`)

```rust
#[async_trait]
pub trait ApproverRoute: Send + Sync + 'static {
    fn kind(&self) -> &'static str;                                   // "iphone", "soft"
    async fn register(&self, name: &str, owner: &dyn OwnerPrompt) -> Result<NewApprover, RegError>;
    async fn deliver(&self, a: &ApproverRecord, r: &Outbound) -> Result<(), DeliveryError>; // idempotent per (a, r.id)
    async fn notice(&self, a: &ApproverRecord, r: &ReqId, n: &Notice) -> Result<(), DeliveryError>;   // settled | ended | outcome
    async fn boot(&self, a: &ApproverRecord, boot: &BootNotice) -> Result<(), DeliveryError>;
    async fn revoked_ack(&self, a: &ApproverRecord) -> Result<(), DeliveryError>;
    fn inbound(&self) -> BoxStream<'static, Inbound>;                 // already channel-authenticated
}
pub struct NewApprover { pub alg: u16, pub sig_pk: Vec<u8>, pub route_data: serde_json::Value }
pub enum Inbound { Approval { approver: ApproverId, req: ReqId, alg: u16, proof: Vec<u8> },
                   Denial { approver: ApproverId, req: ReqId, note: Option<String> },
                   Pause { approver: ApproverId, agent: AgentId, epoch: u64 }, Seen { approver: ApproverId, req: ReqId },
                   Removed { approver: ApproverId } }
// ReqId is the full 40-byte request ID (bootId ‖ seq) everywhere; there is no short form.
```

- **Hub.**
  - For `ask` it fans out to each listed approver's route.
  - It retries `deliver` with backoff until `Seen` arrives or the request ends. This is how "delivery keeps being retried" is met.
  - It turns `Inbound` into core inputs. `Removed` becomes `approverRevoked`, logged with `by: "self"`, and is answered with `revoked_ack` once that entry is durable.
  - Its delivery state lives in memory. A restart ends every request, so there is nothing to resume except the `boot` notice, which goes to every approver first.
- **The core knows nothing about routes.** It knows each approver only as `(id, name, alg, sig_pk, active)`.
- **Re-registering.** `bogo approver add` with an existing name runs a new registration. On success it revokes the old record and registers the new one in a single `approverSet` step.

### 3.11 iPhone route (`bogo-approver-iphone`) and its protocol

**Keys.**

| Holder | Key | Purpose |
|---|---|---|
| Mac (`~/.bogo/keys/`, 0600) | X25519 `macE2E` | HPKE key for the phone↔Mac channel. `bogoId = SHA-256(macE2E.pub)`. |
| Mac | Ed25519 `macRelay` | Relay mailbox auth |
| Mac | the owner's APNs `.p8`, referenced in `secrets.toml` | Pushes |
| Phone, per registered Mac | Secure Enclave P-256 `approve` | Approval signatures. `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` plus `[.privateKeyUsage, .biometryCurrentSet]`. Never exportable. Unusable after a Face ID change. |
| Phone, per registered Mac | X25519 `phoneE2E`, Ed25519 `phoneRelay` | Channel and mailbox. Keychain, `AfterFirstUnlockThisDeviceOnly`, BOGO's own service name `si.eilmer.bogo.*`. |
| Phone | App Attest key (`DCAppAttestService`) | Proves the genuine app at registration |

**Envelope (both directions).**

```
Envelope := "BOGOE2E" 0x00 | u8 version=1 | u8 direction | u8 type | 16 bytes msgId | bytes enc | bytes ciphertext
  HPKE mode_auth, suite DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (RFC 9180)
  info = "bogo/e2e/v1" ‖ bogoId ‖ approverId,  aad = header bytes (magic..msgId)
  msgId: random, chosen once when the message enters the sender's outbox; every resend is the same bytes
```

- **Mac→phone types:**
  - `request {reqId, bootSeq, bytes, pauseEpoch, armDelay}` (the phone derives the group itself)
  - `settled {reqId}`
  - `ended {reqId, why}`
  - `boot {bootSeq, bootId}`
  - `outcome {reqId, executed|notSent|rejected(why)}`
  - `registered {txId, approverId}`
  - `revokedAck {}`
- **Phone→Mac types:**
  - `approval {reqId, alg=1, sig}`
  - `denial {reqId, note}`
  - `pause {agentId, epoch}`
  - `seen {reqId}`
  - `pushToken {tokenSeq, token, env}`
  - `removed {}`: the owner removed this Mac on the phone. The Mac treats it as `approverRevoked` for that approver and logs `approver_revoked by=self`. Like Deny, it can only take authority away.
- **Why HPKE single-shot.** Every envelope carries a fresh ephemeral key (`enc`), so no nonce counter has to be stored, reserved or recovered after a crash, and a restored backup cannot cause nonce reuse ([RFC 9180 §5–6](https://www.rfc-editor.org/rfc/rfc9180#section-5)). Auth mode still binds each message to the sender's static key. `msgId` is for deduplication only, never for the AEAD nonce.
- **Auth mode.** The relay can neither read nor forge either direction.
- **Replay and reordering.** HPKE gives no replay protection of its own ([RFC 9180 §9.7](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7)), and the relay may delay, reorder or repeat anything. So no message is accepted or refused by its position. Each type is safe to apply late, early or twice:
  - Every request-scoped message carries the full 40-byte `reqId`. One from another boot names no live request and is ignored. No boot-local number can point at the wrong request.
  - `approval` is idempotent (a set). `denial` acts only on a `pending` request. `seen` and `removed` are idempotent. Out-of-order arrival loses nothing, because nothing is discarded for being "older".
  - `pause` must carry the agent's current `pauseEpoch`. An unpause moves the epoch on, so a pause composed before it never applies after it, even on first delivery.
  - `pushToken` carries the phone's `tokenSeq`, which it persists and increments on each token change. The Mac applies only a greater one. A newer token replaces an older one, so dropping a stale update loses nothing.
  - On the phone, each request has one state record per `(bogoId, reqId)`, with terminal states kept as tombstones. A `settled`, `ended` or `outcome` that arrives before its `request` is kept, and the late `request` shows greyed. A `boot` whose `bootSeq` is greater than the last seen ends every request whose `reqId` names another boot. A `request` whose `bootSeq` is below the latest known is shown ended at once.
  - Duplicate envelopes (same `msgId`) are dropped before decryption work on both sides. The Mac keeps that set in memory only, because every phone message is idempotent anyway.

**Delivery.**
- For each `ask`, the route does two things concurrently:
  - puts a `request` envelope in the phone's mailbox (`msgId = H(reqId‖approverId)[0..16]`, so resends are idempotent at the relay),
  - sends one APNs alert:

    ```
    apns-push-type: alert, apns-priority: 10, apns-topic: com.johansardar.applebridge.ios
    apns-collapse-id: hex(HMAC(macE2E-derived key, groupKey))[:32]
    {"aps":{"alert":{"title":"BOGO","body":"Approval requested"},"interruption-level":"time-sensitive",
            "category":"bogo.request","thread-id":"bogo","content-available":1,"sound":"default"},
     "bogo":{"v":1,"mac":"<bogoId prefix>","rid":"<reqId hex>"}}
    ```

- The push carries no request content. The collapse ID makes duplicate requests collapse into one banner. The phone counts duplicates.
- APNs is only a wake-up, never the queue. While a device is offline, APNs keeps only the latest notification for the app ([sending notification requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns)), and Apple Bridge shares the bundle, so an Apple Bridge push can displace a BOGO one. The relay mailbox is what the phone trusts. It fetches on launch, on foreground and on any push.
- A push is retried until APNs accepts it. The relay copy is retried until `seen`.
- The APNs host is sandbox or production, according to the environment the phone reported. JWT provider tokens are ES256, cached, and refreshed within Apple's limits ([APNs token auth](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns), [sending requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns)).

**Registration (numeric comparison).** This follows the commitment scheme of Bluetooth LE Secure Connections numeric comparison, so a man in the middle has one guess at a 6-digit code ([Bluetooth pairing, numeric comparison](https://www.bluetooth.com/blog/bluetooth-pairing-part-4/)).

1. The Mac (`bogo approver add "Johan iPhone"`) creates an ephemeral X25519 `eM` and posts a lobby offer `{offerId, ePubM, macLabel}` to the relay. It refreshes the offer while the command runs.
2. The phone (BOGO → Macs → Add Mac) lists the open offers. It usually finds one, and shows several by label and age if there are more. It creates `eP` and sends `ePubP` to the offer.
3. The Mac sends the commitment `Cm = SHA-256("bogo-reg-commit" ‖ ePubM ‖ ePubP ‖ Nm)`, with `Nm` 16 random bytes.
4. The phone sends `Np`. Then the Mac reveals `Nm`, and the phone checks `Cm`.
5. Both sides compute `code = u32be(SHA-256("bogo-reg-code" ‖ ePubM ‖ ePubP ‖ Nm ‖ Np)[0..4]) mod 10^6` and show it as `382 917`. From then on, all registration traffic is sealed under `K = HKDF(X25519(eM,eP), transcript)`.
6. The owner confirms on the Mac. Sealed under `K`, the Mac sends `macConfirmed {macE2E.pub, macRelay.pub, bogoId, macName, challenge}`, where `challenge` is 32 fresh random bytes. Only after that does the phone enable its Confirm button. The transaction ID is `txId = SHA-256(transcriptHash)`.
7. The owner confirms on the phone with Face ID. That single `LAContext` evaluation is used to create the SE key and to sign `"BOGO-REG\x00v1" ‖ transcriptHash ‖ challenge` as proof of possession. The phone then:
   - creates `phoneE2E` and `phoneRelay`,
   - runs App Attest `generateKey` and `attestKey(keyId, clientDataHash = SHA-256(transcriptHash ‖ challenge ‖ sePub ‖ phoneE2E.pub ‖ phoneRelay.pub))`,
   - adds the Mac's mailbox to its own allowlist,
   - writes the pending registration (`txId`, keys, Mac identity) to its store, marked "waiting for the Mac", and never offers approval on it yet,
   - sends `regSubmit` (everything, plus its push token and environment) over the lobby channel, and resends the same bytes until it gets an answer.
8. The Mac checks everything below. Any failure aborts, and nothing is registered:
   - the attestation, against all eleven steps of [Apple's procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server): certificate chain to the pinned Apple App Attestation root, nonce, key ID, RP ID for `AX3C2B78YD.com.johansardar.applebridge.ios`, counter 0, credential ID, the AAGUID environment, and the `apple_validation_category_01` and `apple_bundle_version_01` values in the authenticator data's extensions. BOGO's own `attest` function parses those two extension values with `ciborium` itself rather than trusting that the crate covers them,
   - environment and category against `[approvers.iphone] app_attest`. The default is `["production"]`, which accepts AAGUID `appattest` with category 2 (TestFlight) or 4 (App Store). `"development"` (AAGUID `appattestdevelop`, category 3) is accepted only if the owner lists it. The record and `bogo approver list` show which one was used,
   - the proof-of-possession signature over the transcript and `challenge`.

   On success the Mac appends `approver_registered` and waits until it is durable. It sets its mailbox allowlist to include the phone. Only then does it answer `registered {txId, approverId}`, both on the lobby channel and as an envelope in the phone's mailbox, which is durable at the relay and retried until `seen`.
9. The phone marks the registration active only when `registered` arrives with its `txId`. The lobby offer is then deleted.

**Interrupted registration.** Before the Mac's commit, nothing is registered on the Mac. The phone's pending entry shows "Not confirmed by the Mac" and the owner can discard it, which deletes its keys. After the commit, the phone always recovers: the `registered` envelope waits in its mailbox, and a resent `regSubmit` with the same `txId` gets the same `registered` answer, never a second registration. A different `txId` for the same name is a new registration, which re-registers (§3.10).

**What App Attest shows.** It shows that the genuine, unmodified BOGO-capable build produced this evidence on a real device, bound to this transcript and challenge. It does not attest the approval key's access control directly. That build creates the approval key only inside the Secure Enclave with `.biometryCurrentSet` and has no path that registers a supplied key. That is why the key's Face ID protection is something BOGO checks indirectly rather than hopes for, and it is listed as assumption A7 (§3.3).

### 3.12 Relay (`bogo-relay`)

- **Deployment.**
  - Its own systemd unit `bogo-relay.service` and port (`[listen] port`). The default is 8443, and the owner confirms it (§11).
  - Its own SQLite file `/var/lib/bogo-relay/relay.db` (WAL, `synchronous=FULL`).
  - Its own nftables rule.
  - TLS with `rustls`, using a Let's Encrypt certificate that `lego` obtains through Cloudflare DNS-01 with a token scoped to `eilmer.si`. The cert is reloaded on a renew hook (SIGHUP).
  - DNS `bogo.eilmer.si` is A/AAAA to the VPS, DNS only (not proxied).
  - Nothing is shared with Apple Bridge's relay.
- **API (JSON over HTTPS):**

  ```
  POST /v1/auth/challenge {pub}            → {challenge}
  POST /v1/auth/verify {pub, sig}          → {token}        (bearer, in memory; mailbox = SHA-256(pub))
  POST /v1/allow {senders:[mailbox]}       (owner of mailbox sets who may write to it)
  POST /v1/send {to, msg_id, body}         → 200 once durable; idempotent on (to,msg_id); 409 full
  POST /v1/fetch {wait:true}               → [{msg_id, from, body}] (long-poll; returns at once when mail arrives)
  POST /v1/ack {msg_ids}                   (recipient deletes)
  POST /v1/retract {to, msg_ids}           (sender deletes undelivered)
  POST /v1/lobby/offer | GET /v1/lobby | POST /v1/lobby/{id}/msg | POST /v1/lobby/{id}/fetch   (registration only; in memory; offers vanish when not refreshed)
  ```

- **Rules it keeps:**
  - It stores only ciphertext and the metadata it needs to route.
  - A message is never dropped silently. A full mailbox returns 409, and the sender retries.
  - Messages are deleted only on ack, retract, or the configured maximum age.
  - It holds no application secrets. It cannot forge (approvals are signed and envelopes are auth-mode HPKE), and it cannot read.

### 3.13 iPhone approver (`BogoKit` inside apple-bridge-iphone)

**Narrow edge.** This is the only API the host app sees:

```swift
@MainActor public protocol BogoHost: AnyObject {
    var pushToken: Data? { get }                 // the one thing shared with the host
    var apnsEnvironment: BogoAPNsEnvironment { get }
}
@MainActor public final class BogoSection {
    public init(host: BogoHost, storageDirectory: URL, relayURL: URL)
    public var tab: some View { get }                         // Inbox | History | Macs
    public static var notificationCategories: Set<UNNotificationCategory> { get }  // "bogo.request": [Deny]
    public func owns(_ userInfo: [AnyHashable: Any]) -> Bool  // payload has "bogo"
    public func remoteNotification(_ userInfo: [AnyHashable: Any]) async -> UIBackgroundFetchResult
    public func notificationResponse(_ response: UNNotificationResponse) async
    public func pushTokenChanged(_ token: Data)
    public func sceneBecameActive() async
}
```

**Modules.**
- **BogoModel** (pure, so it can be checked without the app):
  - `RequestBytes.decode(_:) -> Result<ApprovalRequest, DecodeError>`. It enforces canonical form exactly as the Lean decoder does and is checked against `vectors/`.
  - `ReviewModel(request:)` builds the two sections:
    - "Will execute (exact)": upstream, tool, "Requested by \<agentName\>", highlighted fields in their formats (`moneyMinor`: integer text → `$47.00`; a non-integer or out-of-range value is shown raw with a "can't format" mark), then every argument as a full tree, and an expiry countdown.
    - "Agent's reason (unverified)": justification, client name, session tag (the first 8 hex characters of the session ID), and any warning.

    Control, bidi-override and zero-width characters in any string are shown as visible escapes, so the screen can't be made to show something other than the bytes.
  - `MismatchRule.warnings(justification:moneyFields:)`:
    - It finds amounts in the forms `$47`, `$47.00`, `47 USD`, `USD 47` and `47 dollars`.
    - Each amount is compared against every field shown as currency, in major units. It warns for each amount that matches no such field: "Reason says $5, but this will charge $500.00".
    - A bare number, a time ("6pm") or a flight number never matches, because each pattern needs a currency marker.
    - A justification with no amount gets no warning.
  - `Grouping.key(request)` is built from the same tuple as the core's `groupKey`, (agentId, upstream, tool, args, justification), so duplicates show as one entry with a count.
  - `Inbox` state machine, per request:
    - `pending → approving → sent → outcome(executed|notSent|rejected)`,
    - `pending → denying → sent → outcome`,
    - `pending → settled` from `settled` (decided, possibly by another approver; no further actions),
    - `pending → ended` from `ended`, from a newer `boot`, or from an expiry that has passed.

    Ended and settled entries are greyed and offer no actions. Terminal states are kept as tombstones, so a late `request` envelope for them never shows as pending.
- **BogoCrypto.**
  - `ApprovalKey` wraps `SecureEnclave.P256.Signing.PrivateKey(accessControl:authenticationContext:)` ([CryptoKit SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave), [biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)).
  - `Channel` wraps `HPKE.Sender/Recipient(…, authenticatedBy:)` with `.Curve25519_SHA256_ChachaPoly`. CryptoKit has offered auth mode since iOS 17 ([CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke)).
  - `Attest` wraps `DCAppAttestService` ([DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice)).
  - A signing failure with the key-invalidated error marks that Mac's registration as `needsReRegistration`. A changed `LAContext.evaluatedPolicyDomainState`, checked when the tab opens, does the same. The Macs screen then asks the owner to add the Mac again.
- **BogoRelay.**
  - `MacLink` is the port the rest of BogoKit talks to: send an envelope, receive envelopes, and the registration lobby. It has two implementations. `RelayMacLink` is the real one. `StandInMacLink` replays requests from `vectors/` in-process and prints decisions, so the review, grouping, delay, Deny, Pause and the Face ID signing can all be built before the relay or the Mac side exist.
  - URLSession client: auth, long-poll while the app is active, a single fetch on push wake, send and ack.
  - The outbox is a file written atomically before any send. Signed approvals and denials are retried until BOGO's `outcome` arrives or the request is known to have ended. Every inbound `request` is answered with `seen`.
- **BogoSection.**
  - Screens: Inbox (grouped, with counts), History (decisions and outcomes), Macs (list, Add Mac, remove, re-register prompt), Review, and the registration flow.
  - **Remove.** It deletes that Mac's SE approval key at once, so no approval can be made from this phone after that point. It then queues a `removed` envelope in the outbox. The Mac logs `approver_revoked by=self` and answers `revokedAck`. The channel keys are kept until that ack arrives, then deleted. Until then the Macs list shows "Removed here; the Mac hasn't confirmed yet", because the phone can't know the Mac has revoked it. The owner can also run `bogo approver revoke` on the Mac.
  - Review shows **Approve** and **Deny** (with an optional note) and **Pause agent**. Approve becomes tappable only after `approveArmDelay` once the screen is shown, and pressing it triggers Face ID through the SE key's signing.
  - A grouped entry reviews its oldest live request, and shows that request's session tag. Approve and Deny both decide that one request only. Grouping changes how entries look, never what a decision covers. The broader control is **Pause agent**.

**Storage.**
- `Application Support/BOGO/` with `completeUntilFirstUserAuthentication`, so a background push wake can write. Pending entries are readable while the phone is locked, as the spec allows.
- The keys are Keychain items owned by BogoCrypto only.
- Nothing is shared with Apple Bridge storage or identity.

**Notification.**
- Category `bogo.request` has one action, `Deny`, with options `.destructive` and without `.foreground`. Tapping Deny runs `notificationResponse` in the background: it seals the denial and sends it, or queues it in the outbox.
- Tapping the banner opens the Review screen. That screen is the only place Approve exists.

### 3.14 Host app changes (apple-bridge-iphone)

- **Tab.** `ShellTab.approvals` becomes `.bogo` (title "BOGO"), rendering `BogoSection.tab`.
- **Removed:** `ApprovalsCapability`, `ApprovalInbox`, `ApprovalReview`, `ApprovalReviewScreen`, `ShellApprovalsScreen`, and the `approvals` entry in `Capabilities.all`.
- **Old approval jobs.** In `PushDelivery.drain`, `bridge.approval` jobs are skipped with `continue`, with no delivery and no result, so they expire on the Mac.
- **Capture.** `CaptureCapability`'s `deferredHandlers` are removed. `CommandHandlers.handler(for:)` then returns `nil` for `iphone.capture.*`, and `PushDelivery` answers `state: "rejected"`. Capture now always comes back denied. The descriptor stays with `available: false` and permission "Replaced by BOGO".
- **`BridgeAppDelegate`.**
  - `didRegisterForRemoteNotifications` also calls `bogo.pushTokenChanged`.
  - `didReceiveRemoteNotification` and `didReceive response` ask `bogo.owns(userInfo)` first. BOGO payloads go to BogoSection. Everything else follows the existing path.
  - BOGO's category is merged into the registered categories.
- **Project.**
  - `project.yml` adds the local Swift package `BogoKit` to the AppleBridge target.
  - The entitlements add `com.apple.developer.devicecheck.appattest-environment`. Without it, development builds use the sandbox; TestFlight and the App Store always use production ([entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment)).
  - `NSFaceIDUsageDescription` gets BOGO wording.
- **Existing model checks.** The repo's existing checks that reference the Approvals tab (`lab/ios/ShellProof.swift` and the `shell` entry in `packaging/dev/check-models.py`) are updated so they describe the BOGO tab instead. Nothing new is added to them.
- **Untouched.** The Apple Bridge pairing, gateway client, Apple Bridge relay and its APNs registration path.

### 3.15 Stdio shim (`bogo-shim`)

- `bogo-shim` reads `BOGO_URL` and `BOGO_AGENT_TOKEN` from its environment.
- **Byte pump.** It never parses or re-encodes JSON.
  - Each line from stdin is POSTed unchanged as one body, with `Authorization`, `Bogo-Session`, and `Mcp-Session-Id` / `MCP-Protocol-Version` when BOGO has given them.
  - Each JSON-RPC message in the response is written to stdout as one line. That means the JSON body itself, or each SSE `data` payload. BOGO's own output never contains raw newlines, so this is always one line.
  - Whatever the client negotiates passes through untouched, including its `clientInfo` and its `notifications/cancelled`.
- **Session.** At start it mints `Bogo-Session` (128 random bits) and opens `GET /mcp/bogo-liveness` with it. That stream stays open for the life of the process, so BOGO ends the session the moment the shim dies, even on `kill -9`.
- **Stdin closes.** It sends DELETE for the session and exits, which ends the session's requests.
- **BOGO unreachable.** It answers each pending request with a JSON-RPC error and keeps trying to reopen the liveness stream. A new liveness stream means a new session, since the old one has ended.
- It holds only the agent token and contains no BOGO logic, so exactness can't be lost here.

### 3.16 Owner CLI and control (`bogo`)

```
bogo init                                   # ~/.bogo (0700), bogo.toml template, secrets.toml (0600), keys, LaunchAgent plist, prints MCP config + shim snippet
bogo start | stop                           # launchctl bootstrap/bootout gui/$UID ~/Library/LaunchAgents/si.eilmer.bogo.plist (KeepAlive)
bogo approver add "<name>" | list | revoke <name>       # add with existing name = re-register
bogo agent add "<name>" | list | revoke <name> | pause <name> | unpause <name>
bogo tools                                  # every discovered tool, effective policy (and per-agent overrides), flags
bogo request list | cancel <id>             # the owner ending a pending request
bogo log [search …] | export [--format jsonl|csv] | verify
bogo serve                                  # daemon entry point (launchd runs this)
```

- **Pause from the Mac.** `bogo agent pause` sends `ownerPause` and logs `agent_paused by=owner`. `bogo agent unpause` logs `agent_unpaused` first, then sends `agentUnpaused` with that entry's `seq`.
- **Writer lock.** `~/.bogo/run/lock` (`flock`) allows one writer. When the daemon runs, mutating commands go over the control socket. When it doesn't, the CLI takes the lock and uses the same library code. `approver add` while the daemon is down runs registration in the CLI process.
- **Agent tokens.** `bogo_agt_` plus 32 random bytes in base64url. The token is printed once, and only its SHA-256 is stored.
- **Startup checks.** These fail closed and refuse to start:
  - `bogo.toml` has unknown keys (`deny_unknown_fields`),
  - `secrets.toml` is readable by group or others,
  - a policy names an approver that is not registered (the tool is reported as having no eligible approver, and its calls are rejected),
  - k is larger than the number of eligible approvers (same report),
  - any absolute path in an upstream's `command`, `args` or path secret is `~/.bogo`, inside it, or an ancestor of it. This stops an allowed filesystem read from reaching BOGO's credentials on the agent's behalf.

### 3.17 Reference sandbox and bypass suite

- **`sandbox/compose.yml`.** Docker's network topology alone is not the enforcement ([bridge networks](https://docs.docker.com/engine/network/drivers/bridge/)). An explicit default-deny policy in the agent's own network namespace is.
  - Network `bogo-net`, `internal: true`, with a fixed subnet `172.30.0.0/24`.
  - Service `gate` (`alpine/socat`) at the fixed address `172.30.0.2` on `bogo-net`, and also on the default bridge. It forwards only `172.30.0.2:8790 → host.docker.internal:<bogo port>` ([Docker Desktop networking](https://docs.docker.com/desktop/features/networking/)). It has `cap_drop: [ALL]`. `socat` forwards one fixed port to one fixed address and parses nothing, because BOGO itself judges every byte.
  - Service `netpol` holds the agent's network namespace. It sits at `172.30.0.10` on `bogo-net`, has `cap_add: [NET_ADMIN]`, loads `sandbox/policy.nft`, then sleeps. Its healthcheck passes only once the rules are loaded. The rules, for both `inet` families:
    - output policy drop, input policy drop,
    - allow loopback,
    - allow TCP to `172.30.0.2` port 8790 and its established replies,
    - nothing else: no DNS (Docker's embedded resolver at `127.0.0.11` included), no other `bogo-net` address, no gateway, no link-local, private or public range,
    - IPv6 is disabled with `sysctls: net.ipv6.conf.all.disable_ipv6=1`, and the `ip6` side drops everything anyway.
  - Service `agent` has `network_mode: "service:netpol"`, so it shares that namespace and its rules ([`network_mode`](https://docs.docker.com/reference/compose-file/services/#network_mode)). It has `depends_on: netpol: condition: service_healthy`, so it never starts before the rules exist. `BOGO_URL=http://172.30.0.2:8790/mcp` uses an address, so no DNS is needed. `BOGO_AGENT_TOKEN` comes from `sandbox/.env`. It runs as a non-root user with `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, and a read-only root filesystem with a writable work volume. Without `NET_ADMIN` it can't change the rules it shares.
  - No container mounts the home directory, `~/.bogo`, SSH keys, Link's auth file or the Docker socket, and none holds `secrets.toml`.
- **`bogo-bypass`.** Runs inside `agent` and prints one PASS or FAIL per attempt. Every attempt must fail:
  - TCP and DNS to `api.stripe.com`, `link.com`, the relay `bogo.eilmer.si`, a public IP, IPv6 and cloud metadata addresses;
  - `host.docker.internal` on any port, the `bogo-net` gateway address on any port, and `gate` on any port other than 8790;
  - Docker's embedded DNS resolving any outside name, and any UDP or TCP to port 53;
  - changing the namespace's rules (`nft flush ruleset`), which must fail for lack of `NET_ADMIN`;
  - a scan of the filesystem and environment for credential patterns: `sk_test_`, `sk_live_`, `.p8`, `secrets.toml`, Link CLI auth files;
  - MCP with no token or a wrong token;
  - a protected tool called without approval, using cancel-after-send so nothing is left pending;
  - a fake approval smuggled in `_meta` or the arguments;
  - a call to the un-namespaced upstream name;
  - a deny-policy tool;
  - the same session ID reused with another agent's token;
  - the Docker socket.

## 4. Data flows

**S1. Payment approved.** The tool is Link's testmode spend-request tool as `bogo tools` lists it after discovery (written `stripe__<spend tool>` here). The name in the spec's sketch is illustrative.
1. The agent POSTs `tools/call stripe__<spend tool> {amount:4700, test:true, …, justification:"booking the 6pm flight…, $47"}`. The front authenticates "Trip planner". The exact-body layer parses the body with `bogo-json`, keeping `4700` as the text `4700`, and liveness registers.
2. The core resolves the policy: approve, wait. It strips the justification, builds and encodes the request, and outputs `ask`.
3. The `request_created` entry is written durably. Then the hub sends the relay envelope and APNs.
4. The banner (Deny only) appears on the phone. The owner taps it, the app fetches the envelope and decodes it, and Review shows "$47.00", "Requested by Trip planner" and the reason.
5. After the arm delay, the owner taps Approve, Face ID runs, and the SE signs. The outbox stores the approval, then sends it to the relay.
6. BOGO's long-poll returns the approval. It is opened, and it goes into the core as `approval` with the full `reqId`. The core checks the expiry against `now`, verifies through `bogo_verify` and counts it (1 of any-of). The request is `settled`, and the core outputs `settled` and `authorized`.
7. The `authorized` entry is written durably. The shell sends `dispatch`. The core finds the call live, the session open and the approver still registered, and outputs `forward` with the stored arguments.
8. The shell registers the forward ticket and calls the Link upstream at once. `ExactChildTransport` writes the stored arguments byte-exact, without the justification. The result is filtered and logged, and the agent gets Link's real result. In testmode that is a spend request with a test card, not a merchant charge, and BOGO reports it as exactly what Link returned. The phone gets `outcome executed`.

**S2. A lie in the reason.** Same path. The phone shows $500.00 and the mismatch warning "Reason says $5, but this will charge $500.00". The owner taps Deny with the note "wrong amount". The phone sends a `denial`, the core outputs `reject(denied "wrong amount")`, and the agent gets "The owner denied this action. wrong amount". There is no `forward`, so nothing reaches Stripe.

**S3. Changing the call after approval.**
- **`amount:4701`, or a new justification.** This is a different request with a new `seq`, and the old signature doesn't verify over its bytes. In wait mode, the first call has already run once and been removed.
- **Another session.** Session binding means it never matches.
- **A replay of the approval.** The request has been removed (`ignored(unknown)`), it is settled (`ignored(settled)`), or the approver is already counted. A replay from an earlier boot names no live request.
- **Pending-and-retry.** The settled request runs once, on the first identical retry, through the same gate. Two identical retries at once can't both run: only one is bound. Any later identical call creates a new request that needs a new approval.
- **`4.7e3` in place of `4700`.** This is a different `num` text, so it is a different request. The phone shows `4.7e3` raw with a "can't format" mark, because it is not integer text.

**S4. Allowed tool.** Core `forward` → upstream at once, with the `call` and `forwarded` entries written in the same group commit alongside. The result goes back once they are durable. There is no approver traffic.

**S5. Denied tool for Researcher.** The per-agent override is deny, so `tools/list` omits the tool. A direct call gives `reject(denyPolicy)`, which is logged, and there is no upstream contact.

**S6. No answer.**
- **The client gives up.** It sends `notifications/cancelled`, or the response stream drops, or (through the shim) the client exits and the liveness stream closes. Each of these leads to `callEnded` or `sessionClosed`. The core outputs `ended` and `reject(ended)`, and the phone greys the entry out. A late Approve finds no request, is logged as `ignored(unknown)`, and BOGO answers `outcome rejected(not live)`, which the phone shows. If the client gives up while the `authorized` entry is being written, the core sees the `callEnded` before the `dispatch`, so nothing is sent.
- **A 10-minute expiry.** The deadline timer leads to `tick`, with the same result. The phone's countdown has already reached zero. An approval that arrives after the deadline but before the timer fires is refused, because the core checks its `now` against `expiresMs`.

**S7. Phone offline.** The envelope waits in the relay. APNs stores the alert. The hub keeps retrying until `seen`. When the phone comes back, it fetches from the relay, the request appears in the Inbox, and it can still be decided while the session is alive.

**S8. Adding the phone.** This follows §3.11. The Mac commits the registration before it answers, and a lost answer is recovered from the phone's mailbox. `bogo approver list` shows "Johan iPhone (iphone, App Attest: production, TestFlight, bundle 1.4 (212), registered …)".

**S9. Adding an agent.** `bogo agent add "Trip planner"` stores a token hash, logs `agent_added` and prints the token. Requests then carry agentName "Trip planner". A connection with no token, or a wrong one, gets 401 at the auth layer.

**S10. Stolen phone.** The Inbox is visible. Approve needs the SE key, which needs Face ID. `bogo approver revoke "Johan iPhone"` causes `approverRevoked`: any later approval is `ignored(revoked)`, pending requests that relied on that approver end if k is now unreachable, and a settled request that counted it fails the gate if the remaining approvers no longer meet k. A Deny or Pause from the thief only refuses things, which is fail-closed.

**S11. Face ID changed.** Signing fails with the key-invalidated error, or a domain-state change is seen, so the Mac is marked `needsReRegistration`. The BOGO tab asks the owner to add the Mac again, and the new registration replaces the old approver.

**S12. Two approvers (2-of-2).** One soft approver plus the iPhone, or two iPhones. The first approval is `counted`. A second approval from the same approver is not counted again. The second distinct approver settles the request, and it runs through the gate. Any denial while the request is pending gives `reject(denied)` under the default `anyDenial`. A denial after settlement is `ignored(settled)`.

**S13. Output filtering.** The official filesystem server has no tool that returns a sharing link, so the tool for this scenario is the owner's choice (§11). Whatever tool is chosen, the flow is the same. Say its result contains `share_url`. With `filter_output=["share_url"]`, the filter strips it from the structured content and the JSON text before the agent sees it. The log records `filtered: ["share_url"]`.

**S14. Escape attempts.** `bogo-bypass` inside the container fails at every attempt. The only route is through `gate` to BOGO, and there the agent token gives no authority.

**S15. Checking the record.** `bogo log verify` checks the chain, replays the approver registry, re-verifies every approval with the Lean check, and confirms every protected `forwarded` request has its threshold. It prints a summary per decision type.

**S16. A flood.**
1. Identical requests share a `groupKey`. APNs collapses their banners, and the Inbox shows one entry with a count.
2. At `max_pending`, the core outputs `floodDropped` for each new call. That is logged, no approver is notified, and the agent gets the flood rejection.
3. The owner taps Pause agent on the review screen. The phone sends `pause {agentId, epoch}` with the epoch from that request's envelope. The core denies all of that agent's live requests and outputs `agentPaused`, whose log entry is the durable record. Every new request from the agent is rejected, `tools/list` included.
4. `bogo agent unpause` logs `agent_unpaused` and causes `agentUnpaused` with that entry's `seq` as the new epoch. A pause message still in flight from before is refused.

**S17. Two upstreams.** Stripe (`link-cli --mcp`) and the filesystem server are separate rmcp clients with separate namespaces, policies and restart state. A crash in one doesn't touch the other.

## 5. Failure

| Part | Crash / disconnect | Bad input | Recovery |
|---|---|---|---|
| **Core thread** (Lean) | The daemon process dies with it, because Lean is in-process. Every session drops, so no protected call runs. | Any malformed `Input` bytes give `reject(malformed)`, which is proved. | launchd KeepAlive restarts it. There is a new bootId and an empty state, so earlier approvals can never match (A3). |
| **Daemon** | All live requests end, because their sessions are gone. An `authorized` request that never reached `forwarded` was not sent. The log is durable up to the last protected effect. | — | On restart it moves aside a torn final line (refusing to start on real corruption), replays the registry from the log, logs `boot`, and sends `boot{bootSeq, bootId}` to every approver so phones grey out every older request. Old-boot messages still in mailboxes name no live request. Upstreams reconnect. |
| **Front** | A dropped response stream leads to `callEnded`. A closed shim liveness stream leads to `sessionClosed`. No idle timer ends sessions. | Batches, duplicate keys, oversize bodies, bad tokens, requests from paused or revoked agents, and a session reused by another agent are all rejected before the core. | Clients reconnect and re-list tools. |
| **Upstream** | A child exiting mid-call returns "may or may not have happened" and logs `unknown`. It is never retried. The child is restarted with backoff. | A malformed result, or an MRTR/server request, is returned to the agent as an error. A result that echoes a known credential has it removed. | The tools stay listed. A call that reaches the gate during an outage is `not_sent` and consumed. |
| **Log** | A protected effect waits for its entry, and every result waits for its entry, so a crash means no effect without its record. | A final line with no newline is moved aside and logged. A complete line that fails to parse or chain stops startup and is reported, never dropped. | If the disk is full or the write fails, the daemon refuses every call that needs logging, which is every call. Fail-closed. |
| **Approver hub** | If the relay is unreachable, delivery keeps retrying until the request ends, and requests wait. If APNs fails, pushes are retried. | An envelope that fails to open is dropped and counted in diagnostics. A duplicate `msgId` is dropped. A message for an unknown `reqId`, a stale pause epoch or an unknown approver is ignored and logged. Reordering loses nothing. | Long-poll reconnects with backoff. |
| **Relay** | If down, both sides retry. Messages are durable in SQLite. | Bad auth gives 401. A non-allowlisted sender gives 403. A full mailbox gives 409, and the sender retries. | systemd `Restart=always`. A relay restart drops in-memory tokens, and clients re-authenticate. |
| **Phone app** | A crash after signing is safe, because the outbox is written before sending and resent at the next launch or wake. If it is killed, the APNs alert still shows, and Deny works in the background. | An undecodable or non-canonical request, the wrong `bogoId`, or an unknown encoding version is shown as "Unreadable request" with Deny only. A failed signature check on an envelope means it is dropped. | Fetch on launch, foreground and push wake. |
| **SE key / Face ID** | Face ID failure or cancel means nothing is sent, and the request stays pending. | An invalidated key leads to `needsReRegistration`. | Re-register. |
| **Registration** | Before the Mac commits, nothing is registered, and the phone's pending entry can be discarded. After the commit, a lost answer is recovered: the `registered` envelope waits in the phone's mailbox, and a resent `regSubmit` with the same `txId` gets the same answer. | A commitment, SAS, attestation (any of Apple's steps, or a disallowed environment or category) or proof-of-possession failure aborts the registration. | Run `bogo approver add` again. |
| **Shim** | Stdin closing sends DELETE and ends the session. A shim crash closes the liveness stream, which ends the session. If BOGO is unreachable, the shim returns JSON-RPC errors to the client. | It never parses bodies, so it has no bad-input path of its own. BOGO's exact-body layer judges every byte. | It reopens the liveness stream, which gives a new session. |
| **Exact transports** | A `tools/call` without a live forward ticket is never written, and the attempt is logged as `internal_send_refused`. A child that dies mid-write leaves the result unknown. | — | The ticket is spent, so nothing can resend it. |
| **Config** | — | Unknown keys, bad permissions on secrets, or an unexposable tool name: the daemon refuses to start or the tool is not exposed. | The owner fixes the file and restarts. |
| **Clock** | — | A Mac clock jump only moves expiries (the Mac's clock is trusted, and the gate checks `now` against the signed `expiresMs`). A phone clock jump only changes the countdown shown. | — |
| **Gate** | A `callEnded`, revocation, pause or cancel that arrives while the `authorized` entry is being written is seen before `dispatch`, so nothing is sent. | A `dispatch` for an unknown or already-dispatched call is ignored (proved). | — |

## 6. Data and versions

**`~/.bogo/` (directory 0700):**

```
bogo.toml               owner-edited policy (format below)
secrets.toml            0600; refused otherwise
keys/mac_e2e.key        X25519, 0600
keys/mac_relay.key      Ed25519, 0600
state/agents.json       {"v":1,"log_seq":N,"agents":[{"id","name","token_sha256","created","revoked","paused","pause_epoch"}]}   cache, rebuilt from log
state/approvers.json    {"v":1,"log_seq":N,"approvers":[{"id","name","kind","alg","sig_pk","route":{…},"tx_id","attest":{"env","category","bundle_version"},"registered","revoked"}]}   cache, rebuilt from log
upstreams/<name>/       0700, per-upstream private state BOGO points a child at (e.g. Link's auth file)
state/tools.json        {"v":1,"tools":[{"name","upstream","tool","first_seen","justification_key","exposable"}]}
state/boot              {"v":1,"boot_seq":N}  (incremented and synced at every start)
log/audit.jsonl         hash-chained log
run/bogo.sock, run/lock
```

The state files are written atomically: write to a temp file, `sync`, then rename. The daemon or the lock holder is the only writer. `agents.json` and `approvers.json` are caches of the log (§3.9). `tools.json` and `boot` are not security state: the catalog is rediscovered at every start, and `boot_seq` only orders boot notices for phones (the random `bootId` is what keeps boots apart).

**`bogo.toml`** (`version = 1`, `deny_unknown_fields` everywhere):

```toml
version = 1
[server]
port = 8790
max_body = "1MiB"                  # parser limit; owner may change
[relay]
url = "https://bogo.eilmer.si:8443"
[apns]
key = { secret = "apns_p8" }       # secrets.toml: apns_p8 = { path = "/Users/…/AuthKey_XXXX.p8" }
key_id = "XXXXXXXXXX"; team_id = "AX3C2B78YD"; topic = "com.johansardar.applebridge.ios"
[approvers.iphone]
app_attest = ["production"]        # add "development" only for development builds; it is never implied
approve_arm_delay = <owner sets>   # the review screen's "short delay"; sent to the phone with each request
[upstreams.stripe]
command = "npx"; args = ["-y", "@stripe/link-cli@<pinned>", "--mcp"]
env = { LINK_AUTH_FILE = { secret = "link_auth" } }   # secrets.toml: link_auth = { path = "~/.bogo/upstreams/stripe/auth.json" }
[upstreams.files]
command = "npx"; args = ["-y", "@modelcontextprotocol/server-filesystem@<pinned>", "/Users/johansardar/bogo-test"]
# remote: url = "https://…/mcp", headers = { Authorization = { secret = "tok" } }
[defaults]
policy = "approve"; hide_denied = true
max_pending = <owner sets>         # the spec gives no value; startup refuses until it is set
[tools."stripe__<spend tool>"]        # name as `bogo tools` lists it after discovery
policy = "approve"; justification = "required"
highlight = { amount = "usd_cents", currency = "text", test = "text" }
approvers = ["Johan iPhone"]; require = "any"   # or { k = 2 }
on_deny = "any"                                  # or "when_unreachable"
expiry = "10m"; mode = "wait"                    # or "pending_retry"
filter_output = ["url"]; filter_action = "strip" # or "redact"
[agents."Researcher".tools."stripe__<spend tool>"]
policy = "deny"
```

`max_pending` and `approve_arm_delay` have no value in the spec. The template ships both lines unset, and `bogo start` names them until the owner sets them. That is the fail-closed choice.

**Secrets.** A secret is either a value or `{ path = "…" }`. A path secret is passed to the child as that path, which is how Link CLI's own auth file works: it reads and refreshes `LINK_AUTH_FILE`, and `--auth` does the same ([Link CLI README](https://github.com/stripe/link-cli/blob/main/README.md)). The file lives under `~/.bogo/upstreams/stripe/` (0600), outside anything the agent can reach. Link refreshes its token in place, so rotated tokens never need to be written back into TOML.

**Link testmode.** `--test` is a per-call option of spend-request creation, not a login mode. So whether a spend request is in testmode is an argument the agent chooses. The template therefore highlights that field for the Link spend-request tool, next to `amount`. The owner sees "test: true" under Will execute and signs it. The tool and field names come from `bogo tools` after discovery, not from the sketch.

**Formats and how they change:**

| Format | Version marker | Change rule |
|---|---|---|
| Request encoding | `"BOGOREQ\0"` + u16 | A new version is a new Lean encoder with its own injectivity proof. Each approver advertises the versions it supports at registration and in `pushToken` messages. One request has one encoding: BOGO uses the highest version that every eligible approver for it supports, so signatures under k-of-n always cover identical bytes. An unknown version on the phone shows as unreadable, with Deny only. |
| Rust↔Lean wire | `bogo_core_abi()` | Built together. A mismatch refuses to start. |
| E2E envelope | `"BOGOE2E\0"` + u8, HPKE info `bogo/e2e/v1` | New types are added. An unknown type is ignored after a successful open, unless it is marked critical (high bit of `type`), in which case the whole envelope is refused. A new suite gets a new version. |
| Relay API | `/v1/` path | Additive fields only. A breaking change means `/v2` alongside `/v1`. |
| `bogo.toml` | `version` | An unknown version refuses to start. `bogo` prints the migration. |
| State files | `"v"` | Read old, write new, on start. |
| Audit log | per-entry `"v"` | The verifier keeps every past version. Old lines are never rewritten. |
| Test vectors | `vectors/manifest.json` (Lean toolchain + `BogoCore` commit) | Regenerated by `BogoVectors`. Rust and Swift read the same files. |

## 7. Repo layout

**BOGO repo:**

```
bogo/
  lean/
    lakefile.toml  lean-toolchain            (pinned v4.35.0)
    BogoCore/   Json.lean Encoding.lean Policy.lean Core.lean Wire.lean Ffi.lean
    BogoProofs/ Spec.lean Encoding.lean Core.lean Promise.lean
    BogoVectors/Main.lean
  vectors/                                   generated, checked in
  crates/
    bogo-json/  bogo-core-sys/ (build.rs, shim.c)  bogo-core/  bogo-verify/
    bogo-config/  bogo-state/  bogo-log/  bogo-filter/
    bogo-upstream/  bogo-front/
    bogo-approver/  bogo-approver-iphone/  bogo-approver-soft/
    bogo-relay-proto/  bogo-e2e/  bogo-apns/
    bogo-daemon/
  bins/
    bogo/  bogo-shim/  bogo-relay/  bogo-standin/  bogo-bypass/
  sandbox/      compose.yml  policy.nft  .env.example  README.md
  deploy/relay/ bogo-relay.service  lego-renew.sh  nftables-bogo.conf
  docs/         README.md  configuration.md  threat-model.md  proved-and-assumed.md  SPEC.md  adr/
  Cargo.toml (workspace; serde_json features = ["arbitrary_precision"] for results only; rmcp pinned "=3.10.0")
```

**apple-bridge-iphone:**

```
ios/BogoKit/  Package.swift
  Sources/BogoModel/  Sources/BogoCrypto/  Sources/BogoRelay/  Sources/BogoSection/
ios/App/…     (edge edits only)
```

**Import rules:**
- `BogoCore` imports `Init` and `Std` only. `BogoProofs` and `BogoVectors` may import `BogoCore`. Nothing imports `BogoProofs`.
- Only `bogo-core-sys` contains `unsafe` or touches `lean.h`.
- `bogo-core` has no async runtime and no I/O beyond its thread and channel.
- `bogo-front`, `bogo-upstream`, `bogo-log`, `bogo-filter` and `bogo-approver*` never depend on each other. Only `bogo-daemon` wires them.
- Only `bogo-daemon`'s gate sends `dispatch` to the core, and only after the `authorized` entry is durable.
- `bogo-approver-iphone` must not depend on `bogo-core` internals, only on the shared ID and request types re-exported by `bogo-approver`.
- `bogo-approver-soft` is listed under `[features] test-approvers` and is absent from the default build.
- `bogo-shim`, `bogo-bypass` and `bogo-relay` depend on no daemon crate. `bogo-shim` does not depend on rmcp or any JSON parser.
- Only `bogo-upstream`'s exact transports write a `tools/call` to an upstream. Nothing else in the workspace calls `call_tool` except the shell's one forward function.
- Tool arguments are parsed only by `bogo-json`. Nothing reads `CallToolRequestParams.arguments`.
- Nothing in either repo references Apple Bridge Mac code, its gateway paths (`/v1/iphone/*`), relay or pairing.
- In BogoKit, the direction is BogoModel ← BogoCrypto ← BogoRelay ← BogoSection. The host app imports only `BogoSection`. BogoKit never imports host code.

## 8. Build order

The spec puts the iPhone section first, built against a stand-in, with the Mac side after. The order follows that.

1. **`BogoCore` encoding** (`Json`, `Encoding`) with `decode_encode` and `encode_injective`, then `BogoVectors` → `vectors/`, and the envelope and message formats of §3.11. Both platforms need these bytes before anything else. `bogo-json` follows straight away, checked against the same vectors, because every Rust path into the core goes through it.
2. **`BogoKit` against `StandInMacLink`:** BogoModel (decoding, review model, mismatch rule, grouping, inbox states), BogoCrypto's approval key with Face ID, and the BogoSection screens, plus the host-app edge edits in apple-bridge-iphone (tab, notification routing, old Approvals removed, capture denied). Nothing here waits on a relay or a Mac.
3. **Crypto and transport building blocks:** `bogo-e2e`, `bogo-relay-proto`, `bogo-apns`, `bogo-verify` (P-256), then the `bogo-relay` service deployed on the VPS (DNS, certificate, port rule). BogoKit's `RelayMacLink` and HPKE `Channel` follow.
4. **`bogo-approver`** (trait and hub) and **`bogo-approver-iphone`** (registration with SAS and App Attest, delivery, intake), with `bogo-state` for keys and the approver registry, and BogoKit's registration flow and App Attest.
5. **`bogo-standin`**: registers a real phone over the real relay, sends requests taken from `vectors/`, prints each decision verified with `bogo-verify`, and sends `settled`, `ended`, `boot` and `outcome` on command. The phone now runs end to end without the daemon.
6. **`BogoCore` decision logic** (`Policy`, `Core`, `Wire`, `Ffi`) and **`BogoProofs`**. This can run in parallel with steps 2–5, because it depends only on step 1.
7. **`bogo-core-sys`** and **`bogo-core`**: link the Lean static library and run the core thread.
8. **`bogo-config`**, **`bogo-log`**, **`bogo-filter`**, **`bogo-upstream`**, **`bogo-front`**. These are independent of each other.
9. **`bogo-daemon`** and the **`bogo` CLI** (init, start and stop with launchd, agents, approvers, tools, request, log). Then **`bogo-approver-soft`** for 2-of-2.
10. **`bogo-shim`**.
11. **Sandbox** and **`bogo-bypass`**, then the Link CLI test login (owner device flow) and the filesystem upstream.
12. **Docs**: README quick start, configuration reference, threat model and assumptions, and "What is proved / What is assumed", written from the theorem statements in `BogoProofs/Promise.lean`.

## 9. Libraries

| Choice | Why | Source |
|---|---|---|
| `rmcp` =3.10.0 (features `server`, `transport-streamable-http-server`, `client`, `transport-child-process`, `transport-streamable-http-client-reqwest`, `transport-io`) | Required by the spec. It does Streamable HTTP with legacy sessions plus 2026-07-28 stateless, puts `http::request::Parts` in handler extensions, cancels a stateless request's handler on client disconnect, and supports `arbitrary_precision`. It is pinned exactly because it moves fast. | [github.com/modelcontextprotocol/rust-sdk](https://github.com/modelcontextprotocol/rust-sdk) |
| `serde_json` 1.0 + `arbitrary_precision` | MCP framing, results (big numbers keep their digits) and config views. Never used for tool arguments, because it rewrites exponent text (`4.7E3` → `4.7e+3`). | [github.com/serde-rs/json](https://github.com/serde-rs/json), [`de.rs` `scan_exponent`](https://github.com/serde-rs/json/blob/master/src/de.rs) |
| `bogo-json` (BOGO's own, no dependencies) | Exact lexical JSON for arguments: number text kept byte for byte, duplicate keys rejected, writer emits the same text. It is small enough to check against Lean vectors, and no existing crate offers both exact number text and duplicate rejection on a tree it hands back. | this repo |
| `tokio` 1.54, `axum` 0.8, `tower` | The runtime and the HTTP layers around rmcp, including the relay server | [tokio](https://github.com/tokio-rs/tokio), [axum](https://github.com/tokio-rs/axum) |
| Lean 4 v4.35.0 + Lake (`:static` facet) | Required by the spec. The decision code is compiled to C and statically linked. | [lean4 releases](https://github.com/leanprover/lean4/releases), [Lake README](https://github.com/leanprover/lean4/blob/master/src/lake/README.md), [FFI reference](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) |
| `cc` | Compiles BOGO's own C shim against the pinned `lean.h`. `lean-sys` was rejected: last release 2025-09, bound to older headers. | [github.com/rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) |
| `hpke` 0.15 (x25519, chacha) | RFC 9180 auth mode. Interoperates with CryptoKit HPKE `.Curve25519_SHA256_ChachaPoly`. | [github.com/rozbb/rust-hpke](https://github.com/rozbb/rust-hpke), [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) |
| `p256` 0.14 / `ecdsa` 0.17 | Verifies Secure Enclave P-256 signatures | [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves) |
| `ed25519-dalek` 3 | Relay mailbox auth, and the soft test approver | [curve25519-dalek repo](https://github.com/dalek-cryptography/curve25519-dalek) |
| `sha2` 0.11 | Log chain, token hashes, collapse IDs | [RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `appattest` 0.1.1 + `ciborium` 0.2 | `appattest` does the chain, nonce, RP ID, counter, AAGUID and key ID checks. BOGO's own `attest` function wraps it with a pinned root, and itself parses the authenticator data's extensions with `ciborium` to check `apple_validation_category_01` and `apple_bundle_version_01`, so all eleven of Apple's steps are covered by named code. If the crate turns out to miss any step, that step moves into BOGO's function too. | [appattest](https://github.com/PrismaPhonic/appattest), [ciborium](https://github.com/enarx/ciborium), [Apple's procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) |
| `reqwest` 0.13 (rustls, http2) | Relay client and APNs HTTP/2 | [github.com/seanmonstar/reqwest](https://github.com/seanmonstar/reqwest) |
| `jsonwebtoken` 12 | APNs ES256 provider tokens. BOGO's own client was chosen over `a2`, whose last release is 2024-05. | [github.com/Keats/jsonwebtoken](https://github.com/Keats/jsonwebtoken) |
| `rusqlite` 0.42 (bundled) | Durable relay mailboxes (WAL) | [github.com/rusqlite/rusqlite](https://github.com/rusqlite/rusqlite) |
| `rustls` 0.23 | Relay TLS | [github.com/rustls/rustls](https://github.com/rustls/rustls) |
| `toml` 1.x + `serde` | Parses `bogo.toml` and `secrets.toml` with `deny_unknown_fields` | [github.com/toml-rs/toml](https://github.com/toml-rs/toml) |
| `clap` 4 | CLI | [github.com/clap-rs/clap](https://github.com/clap-rs/clap) |
| `fs4` 1 | `flock` single-writer lock | [github.com/al8n/fs4](https://github.com/al8n/fs4) |
| `tracing` | Diagnostics, never the audit record | [github.com/tokio-rs/tracing](https://github.com/tokio-rs/tracing) |
| CryptoKit (`SecureEnclave.P256`, `HPKE`), Security (`SecAccessControl` `.biometryCurrentSet`), LocalAuthentication, DeviceCheck (`DCAppAttestService`), UserNotifications, SwiftUI, URLSession | Native, with no third-party code on the phone | [SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave), [HPKE](https://developer.apple.com/documentation/cryptokit/hpke), [biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset), [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice), [UNNotificationAction](https://developer.apple.com/documentation/usernotifications/unnotificationaction) |
| `lego` | Let's Encrypt DNS-01 through Cloudflare with a scoped token | [go-acme.github.io/lego/dns/cloudflare](https://go-acme.github.io/lego/dns/cloudflare/) |
| Docker Compose + `alpine/socat` + nftables | Reference sandbox: internal network, single-port TCP gate, default-deny rules in a namespace the agent shares but can't change | [Docker bridge networks](https://docs.docker.com/engine/network/drivers/bridge/), [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/), [Compose `network_mode`](https://docs.docker.com/reference/compose-file/services/#network_mode), [nftables](https://wiki.nftables.org/) |
| `@stripe/link-cli --mcp`, `@modelcontextprotocol/server-filesystem` | The upstreams the spec uses for proof. Link CLI exposes spend-request tools over MCP and can return card details on request, which is a natural output-filter target. | [github.com/stripe/link-cli](https://github.com/stripe/link-cli), [servers/filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) |

## 10. Risks and open questions

| Risk | Why it matters | How to find out |
|---|---|---|
| **MCP 2026-07-28 removed sessions** | "Session = one MCP connection" now only exists in legacy versions. Stateless clients get call-scoped sessions, which makes pending-and-retry unavailable to them. If clients drop legacy versions, session semantics shrink further. | Check which protocol Claude Code, Cursor and Claude Desktop negotiate against BOGO. Watch rmcp's `legacy_session_mode` across releases. |
| **Disconnect detection in legacy sessions** | The liveness layer depends on hyper dropping the response body when the client goes away, and on `sse_retry: None` really suppressing priming events in rmcp 3.10. | Run a protected wait-mode call, kill the client, and confirm `callEnded` shows in the log. Inspect the first SSE bytes for an event ID. |
| **Exact transports vs rmcp internals** | They rely on rmcp passing `_meta` through to the `Transport` / `StreamableHttpClient` unchanged, and on BOGO's serializer producing JSON-RPC that rmcp still correlates by `id`. The ingress side relies on rmcp handing each request's `Parts` to its handler, which its server source does today. | Send a vector with `4.7E3` and `-0` to a stub upstream that echoes its raw stdin, and compare bytes. Re-read `tower.rs` on every rmcp bump, since the version is pinned. |
| **Gate ordering** | Fresh-at-dispatch holds only if every security input reaches the core channel before the shell's `dispatch`, and nothing awaits between `forward` and the first write | Read the gate function: it must be one task that awaits the log, sends `dispatch`, and on `forward` calls the transport without any other `await`. |
| **Silently abandoned direct sessions** | With no idle timer, a direct legacy client that vanishes without DELETE leaves its pending-and-retry requests pending (never runnable) until owner action, revocation or restart | Owner decision (§11). The shim has no such gap. |
| **Schema augmentation edge cases** | Some upstream schemas use top-level combinators or `$ref`, and a strict client might reject the added field | `bogo tools` reports how each tool's field was added. Check the Link and filesystem schemas after discovery. |
| **Lean static link on macOS** | `lean.h` is unstable, and the link line (`leanc --print-ldflags`, libc++, gmp) can change between toolchains | Pin the toolchain. The ABI check runs at startup. Build the shim against the pinned header on each toolchain bump. |
| **Proof boundary (A6)** | The Rust shell could forward something other than the `forward` output | Keep the shell's forward path one function from output to rmcp `call_tool`, with no other caller of `call_tool` in the workspace. Check it with a grep-able rule: `call_tool` is used in only one place. |
| **`appattest` crate maturity** | It is young, it pulls in `openssl` and `aws-lc-rs`, and it predates Apple's validation-category and bundle-version steps | Feed it real attestations from development and TestFlight builds, and read which of Apple's eleven steps it performs. It is wrapped behind one function, so a self-written verifier using `x509-parser`, `p384` and `p256` could replace it. |
| **Docker Desktop `host.docker.internal` reaching host loopback** | The gate depends on it. BOGO listens on 127.0.0.1 only. | Run `bogo-bypass` and a real agent call from the container. |
| **nftables inside Docker Desktop's VM** | `netpol` needs nftables support in the Linux VM's kernel | Load `policy.nft` in `netpol` and list the ruleset from inside it. |
| **Agent harness needs its model API** | A sandbox that allows only BOGO also cuts off the agent's LLM | Owner decision (§11) |
| **iOS background Deny and push wake** | A force-quit app gets no background wake. Deny from the banner still launches it, but the timing is up to iOS. | Try Deny from a locked phone with the app force-quit. The outbox makes a late send safe. |
| **Link CLI behaviour** | It may use elicitation or MRTR, which BOGO refuses, or need its device-flow login on the Mac side. Testmode is a per-call argument the agent controls, and some Link flows (Link Pay Tokens) have no testmode at all. | List its tools, log in once with `LINK_AUTH_FILE` pointing under `~/.bogo`, and run a testmode spend request through BOGO with the test field highlighted. |
| **Scenario 13 tool** | The official filesystem server has no "share" tool that returns a public link | Owner decision (§11) |
| **Relay lobby is global** | Anyone can post offers. Numeric comparison keeps registration secure, but junk offers could clutter Add Mac. | Watch the lobby. A per-offer label and age is shown. |
| **Log chain without an anchor** | Someone with file access could rewrite the whole chain. Mac compromise is out of scope, but that is the limit of what the chain shows. | State it in the threat-model doc. |
| **Number formats on the phone** | `moneyMinor` on a non-integer number text must not mislead | The vectors include `4700`, `4700.0`, `4.7e3` and `-0`. Non-integers show raw and are marked. |

## 11. Questions for the user

1. **Sandbox egress for the agent's model.** The spec says the container has no network except BOGO, but an agent harness such as Claude Code must reach its model API. Should the namespace policy also allow one named model API host (through a second fixed forwarder), or must the agent's model run outside the container?
2. **Protocol 2026-07-28 clients.** That protocol has no sessions. Is this acceptable?
   - Pending-and-retry tools need either a session-capable connection or the stdio shim, which carries its own BOGO session.
   - They are rejected for stateless direct HTTP clients.
3. **Owner cancel.** The spec lists "the owner cancels it" as a way a request ends, but no command is drafted for it. Is `bogo request list | cancel <id>` acceptable, or should cancel live on the phone?
4. **Silently abandoned direct sessions.** No idle timer ends a session, because that would be a preset expiry. So when a direct (not shim) client on protocol 2025-11-25 disappears between requests without sending DELETE, BOGO can't see it. Its pending-and-retry requests stay pending until the owner denies or cancels them, the agent is revoked, or BOGO restarts. They can never run in the meantime, and wait-mode calls are unaffected. Is that acceptable, or does the owner want an idle end, with a value they choose?
5. **Numbers the spec leaves open.** These are behaviour values, not performance goals. Each ships unset, and BOGO won't start until it is set:
   - the Approve arm delay ("a short delay"),
   - the default `max_pending` flood limit,
   - the relay's maximum message age and mailbox caps.
6. **Relay port.** 8443 is assumed. Is it free on the VPS?
7. **Banner text.** The push carries no content ("BOGO: Approval requested"). Showing the agent or tool name on the banner would need an encrypted payload plus a Notification Service Extension. Is the generic banner fine?
8. **Upstream resources and prompts.** These are not exposed, so they can't be used to go around the gate. Is that OK, given that the spec only talks about tools?
9. **Scenario 13.** The official filesystem server returns no public sharing link. Which tool should show output filtering? Stripe Link's card-details retrieval is one option, or a small test upstream.
10. **A lost result in pending-and-retry.** After a settled request runs, it is removed. If the agent never received the result and retries the identical call, that is a new request, which the owner sees and must approve again. It never runs twice on one approval. Is that the intended behaviour, or should BOGO keep the result for identical retries in the session (which would then need a way to express a genuinely new identical action)?
11. **Default policy and new tools.** §3.4 says unlisted tools get the default policy, and also that newly discovered tools default to approve. This design reads it as "the shipped default policy is approve, and every unlisted tool follows `[defaults] policy`". If the owner sets the default to allow, should newly discovered tools still need approval until they are listed?
12. **Link credentials.** Link CLI keeps and refreshes its own auth file. Is a file under `~/.bogo/upstreams/stripe/` (0600), named from `secrets.toml` by path, acceptable instead of the token itself living in `secrets.toml`?
13. **Spec §9 open questions carried over:**
    - whether the PRD's speed goals apply (overhead on allowed calls, notification latency, setup time),
    - whether a second real device exists for 2-of-2,
    - which Link tools are protected (all of them, or only the ones that create spend requests or credentials).
