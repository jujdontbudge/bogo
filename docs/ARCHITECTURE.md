# BOGO: Architecture

Status: 2026-11-14. Built from SPEC.md.

## 0. The shape

BOGO is one Rust daemon on the owner's Mac. Agents see it as one MCP server over Streamable HTTP (`rmcp`), and stdio-only clients reach it through a small shim. Every tool call goes through one pure decision function: allowed calls, protected calls and denied calls alike. That function is written in Lean 4 and compiled to C, and the daemon links the exact compiled code the proofs are about. It runs on one dedicated thread, takes bytes in and gives bytes out. Lean decodes those bytes itself, so malformed input is covered by the proof. Policy resolution, stripping the justification, request encoding, single-use, session binding, k-of-n counting, revocation, pause and the flood limit all live inside it. Signature checks run inside it too, through one `extern` hook into Rust, which is a stated assumption. Everything else is a thin shell that carries out what the core outputs: the MCP front, the upstream manager, the hash-chained audit log, output filtering, the approver hub and the owner CLI.

The core's final check runs at the last possible moment. BOGO's own exact upstream transport asks the core for `dispatch` at the moment it is about to write the `tools/call` to the upstream. That happens after every SDK queue, and the transport writes the core's own `forward` arguments in the same turn, byte for byte, without waiting on anything else first. Tool arguments never go through a lossy JSON parse: one strict lexical parser keeps each number's exact text, and one exact writer emits it. Time reaches the core from one clock that keeps counting through sleep and never runs backwards.

The append-only hash-chained audit log is BOGO's only durable authority. The agent and approver registry, pause epochs and every outcome a phone may still be waiting on are all derived from it. No effect happens, and no reply reaches an agent, before its log entry is durable. Pending requests live only in memory and die with their session, so a crash or restart ends every request, which fails closed. A request that might have been sent when BOGO stopped is reported as "outcome unknown" and is never replayed.

Approvers are plug-in routes behind one trait. The first is the iPhone section: a separate Swift package (`BogoKit`) inside apple-bridge-iphone. It holds a Face ID–bound Secure Enclave P-256 key, proven at registration with App Attest. It talks to BOGO only through HPKE-sealed messages that pass through BOGO's own store-and-forward relay at `bogo.eilmer.si`, and it is woken by APNs pushes that the Mac sends itself. Every message that crosses the relay is safe to apply late, early or twice, and neither end acknowledges one until its effect is durable. A reference Docker sandbox gives the agent a default-deny network namespace whose only route leads to BOGO.

## 1. Runtime picture

```
 Docker (reference sandbox)                     owner's Mac
┌───────────────────────────┐          ┌──────────────────────────────────────────────────────────┐
│ agent harness             │          │ bogo daemon (launchd user agent, KeepAlive)              │
│  └ MCP client ──HTTP──────┼─► gate ──┼─► 127.0.0.1:<port>/mcp                                 │
│    (or stdio → bogo-shim) │ (socat,  │   ┌─────────────┐  Input bytes  ┌──────────────────────┐  │
│ netns: default-deny       │  fixed   │   │ front (rmcp │──────────────►│ core thread          │  │
└───────────────────────────┘  dest.)  │   │ server,auth,│◄──────────────│  Lean step (+extern  │  │
                                       │   │ liveness)   │  Output bytes │  verify)             │  │
                                       │   └─────┬───────┘               └──▲───────────┬───────┘  │
                                       │         │ authorized              dispatch│      │ ask/ended│
                                       │   ┌─────▼──────────────────────────────┴─┐  ┌──▼───────┐  │
                                       │   │ upstream mgr: rmcp clients over      │  │ approver │  │
                                       │   │ BOGO exact transports (final gate)   │  │ hub      │  │
                                       │   └──┬──────────────┬────────────────────┘  │ └ iphone │  │
                                       │      │stdio         │HTTPS   ┌──────────┐   │ └ soft*  │  │
                                       │  link-cli       remote MCP  │audit log │◄──┴──┬────┬──┘  │
                                       │  fs server                  │(only     │  APNs│    │relay │
                                       │  (creds from secrets.toml)  │authority)│      │    │client│
                                       │   ▲ unix socket ~/.bogo/run/bogo.sock ◄── `bogo` CLI      │
                                       └───┼──────────────────────────────────────────┼────┼──────┘
                                     owner terminal                                   │    │ HTTPS long-poll
                                                                                      │    ▼
                                                                    ┌─────────────────┼───────────────┐
                                                                    │ VPS: bogo-relay (own port, own  │
                                                                    │ systemd unit, own SQLite, own   │
                                                                    │ firewall rule): ciphertext only │
                                                                    └─────────────────┬───────────────┘
                                                                         APNs push    │ HTTPS
                                                                             ▼        ▼
                                                     ┌─────────────────────────────────────────────┐
                                                     │ iPhone: Apple Bridge app                    │
                                                     │  host shell ──narrow edge──► BogoKit        │
                                                     │  (BOGO tab, push token,     ├ BogoModel     │
                                                     │   notification routing)     ├ BogoCrypto    │
                                                     │                             ├ BogoRelay     │
                                                     │                             └ BogoSection   │
                                                     └─────────────────────────────────────────────┘
   * soft approver exists only in a build with the `test-approvers` feature
```

How the parts talk:
- **Agent to BOGO:** MCP Streamable HTTP with `Authorization: Bearer <agent token>`. The stdio shim forwards each stdio message as one POST body, byte for byte. It carries its own BOGO session in a header and holds a liveness stream open (§3.15).
- **Front to core:** an in-process channel to the core thread. Each step passes one encoded `Input` and gets back the encoded `Output`s.
- **Exact transport to core:** at the moment of writing a `tools/call`, the transport sends `dispatch` on the same channel and writes only if the answer is `forward`.
- **Daemon to upstreams:** `rmcp` clients over a child process's stdio (local upstreams) or Streamable HTTP (remote ones), always through BOGO's exact transports.
- **Daemon and phone:** HPKE-sealed envelopes in each side's relay mailbox, plus an APNs alert that the Mac sends directly.
- **CLI to daemon:** JSON lines over a Unix socket that only the owner can open.

## 2. Units

| Unit | Language | Owns | May depend on | Must never depend on |
|---|---|---|---|---|
| `lean/BogoCore` | Lean 4 | JSON value tree, request encoding and decoding, policy resolution, the decision state machine (`step`), the Rust↔Lean wire codec, FFI exports | Lean `Init`, `Std` | The `Lean` compiler package, Mathlib, any I/O |
| `lean/BogoProofs` | Lean 4 | The promise's specification and every proof, including encoding injectivity | `BogoCore`, `Std` | Being linked into any binary |
| `lean/BogoVectors` | Lean 4 | Executable that writes `vectors/*.json` | `BogoCore` | Rust, Swift |
| `bogo-core-sys` | Rust + C | Building the Lean static library, the C shim around `lean.h`, raw `extern "C"` | `cc`, the Lean toolchain at build time | Every other BOGO crate |
| `bogo-json` | Rust | Strict lexical JSON parser into `JVal` (exact number text, rejects duplicate keys and lone surrogates, has limits) and the exact writer | `std` only | Everything else |
| `bogo-core` | Rust | Safe `Core` handle, the core thread, typed `Input`/`Output`, the Rust side of the wire codec | `bogo-core-sys`, `bogo-json` | rmcp, I/O, approver routes |
| `bogo-verify` | Rust | `bogo_rs_verify`, called from the core's extern hook: P-256 ECDSA, plus soft Ed25519 only with `test-approvers` | `p256`, `ed25519-dalek` (behind a feature) | Anything else |
| `bogo-config` | Rust | Parsing and validating `bogo.toml` and `secrets.toml`; the `Secret` type (not serializable, no `Debug` contents) | `toml`, `serde` | Core, rmcp, network |
| `bogo-log` | Rust | The hash-chained audit log: group-commit writer, reader, search, export, `verify`, registry replay, outcome lookup | `sha2`, `serde_json`, `bogo-core` (decoding and checks through Lean) | Front, upstreams, approver routes |
| `bogo-state` | Rust | `~/.bogo` layout and permissions, the single-writer lock, BOGO's own keys, registry checkpoint caches rebuilt from the log | `bogo-config`, `bogo-log` | Core, rmcp, network |
| `bogo-filter` | Rust | Output filtering (strip or redact field paths in results) | `serde_json` | Everything else |
| `bogo-upstream` | Rust | Upstream connections, the exact transports and their final gate, the namespaced catalog, justification schema widening, removing secrets from results, restart | `rmcp` (client), `bogo-json`, `bogo-config`, a `Gate` port | Front, log internals, approvers |
| `bogo-front` | Rust | MCP server: agent-token auth, the exact-body layer, call and session liveness, BOGO sessions, per-agent `tools/list`, model-readable results | `rmcp` (server), `axum`, `bogo-json`, `bogo-core` types | Upstream internals, approver routes |
| `bogo-approver` | Rust | `ApproverRoute` trait, the approver hub (fan-out, delivery retry, inbound decisions, sync answers), the registration driver | `bogo-core` types | rmcp, front, upstreams |
| `bogo-relay-proto` | Rust | Relay wire types, mailbox auth, the async relay client | `reqwest`, `ed25519-dalek` | Any daemon crate |
| `bogo-e2e` | Rust | Envelope format, HPKE auth-mode seal and open, message IDs | `hpke` | Network |
| `bogo-apns` | Rust | APNs token-auth HTTP/2 client | `reqwest`, `jsonwebtoken` | Everything else |
| `bogo-attest` | Rust | App Attest verification as named steps against a pinned Apple root | `ciborium`, `x509-cert`, `der`, `p256`, `p384`, `sha2` | Network, the system trust store |
| `bogo-approver-iphone` | Rust | iPhone route: SAS registration, delivery, decision intake, notices, push | `bogo-approver`, `bogo-relay-proto`, `bogo-e2e`, `bogo-apns`, `bogo-attest` | Core internals, front, upstreams, anything from Apple Bridge |
| `bogo-approver-soft` | Rust | Software approver for automated 2-of-2 checks | `bogo-approver`, `ed25519-dalek` | Being present in a default build |
| `bogo-daemon` | Rust | Wiring: the effects shell (output → log → effect), the core clock, the control socket, startup and shutdown | All daemon crates | Apple Bridge anything |
| `bogo` (bin) | Rust | The CLI and `bogo serve` | `bogo-daemon`, `clap` | — |
| `bogo-shim` (bin) | Rust | stdio ↔ Streamable HTTP forwarder that never re-encodes, one BOGO session per process, the liveness stream | `reqwest`, `tokio`, `bogo-json` (read-only) | rmcp, every other BOGO crate |
| `bogo-relay` (bin) | Rust | Relay service: mailboxes, allowlists, registration lobby, SQLite, TLS | `bogo-relay-proto`, `axum`, `rusqlite`, `rustls` | Every daemon crate, the Apple Bridge relay |
| `bogo-standin` (bin) | Rust | Stand-in for BOGO while the phone is built: real registration, relay and push; sends requests from Lean vectors; prints verified decisions | `bogo-approver-iphone`, `bogo-state`, `bogo-verify` | Front, upstreams, the core thread |
| `bogo-bypass` (bin) | Rust (Linux) | The bypass test suite the spec asks for, run inside the sandbox | `rmcp` (client), `reqwest` | Every BOGO internal crate |
| `sandbox/` | Compose + nftables | The reference setup: internal network, namespace holder with default-deny rules, fixed TCP forwarder, agent service | Docker | Home-directory mounts, the Docker socket |
| `BogoKit/BogoModel` | Swift | Request decoding with canonical checks, the render model, mismatch rule, grouping, inbox state machine | Foundation | UIKit, SwiftUI, Security, host code |
| `BogoKit/BogoCrypto` | Swift | Secure Enclave approval key, HPKE, relay auth key, App Attest, BOGO-only Keychain items | CryptoKit, Security, LocalAuthentication, DeviceCheck | Host code, BogoSection |
| `BogoKit/BogoRelay` | Swift | The `MacLink` port with relay and stand-in implementations, the SQLite store and outbox, the message pump | BogoModel, BogoCrypto, Foundation, system SQLite | Host code |
| `BogoKit/BogoSection` | Swift | Screens (Inbox, History, Macs, Review, Add Mac), the facade, notification category, push handling | All BogoKit modules, SwiftUI, UserNotifications | Apple Bridge pairing, identity, push delivery, jobs, gateway |
| Host edge (`ios/App`, `ios/Delivery`, `ios/Capabilities`) | Swift | The BOGO tab in place of Approvals, notification routing, the shared push token, removing old Approvals, capture always denied | The `BogoSection` facade only | BogoKit internals |

## 3. Core pieces

### 3.1 The decision core (Lean 4: `BogoCore`)

**What it does.** It is a deterministic state machine. Every event that can affect a decision is an `Input`, and every decision is an `Output`. It does no I/O, reads the time only from its inputs, and mints request sequence numbers itself.

**Interface sketch:**

```lean
inductive JVal                                        -- exact JSON tree; numbers keep their source text
  | null | bool (b : Bool) | num (text : String) | str (s : String)
  | arr (xs : List JVal) | obj (kvs : List (String × JVal))   -- keys strictly ascending by UTF-8 bytes

inductive PolicyKind | allow | approve | deny
inductive DefaultPolicy | approve | deny               -- the default can never be allow (§3.16, §11)
inductive Requirement | anyOf | kOfN (k : Nat)
inductive DenyRule | anyDenial | whenUnreachable      -- k-of-n; default anyDenial
inductive Mode | wait | pendingRetry
inductive Format | text | moneyMinor (iso4217 : String) -- "usd_cents" = moneyMinor "USD"

structure ToolPolicy where
  kind : PolicyKind; justificationRequired : Bool; hints : List (List String × Format)
  expiryMs : Option Nat; approvers : List ApproverId; requirement : Requirement
  denyRule : DenyRule; mode : Mode

structure AgentOverride where
  kind : Option PolicyKind; approvers : Option (List ApproverId); requirement : Option Requirement

structure Request where                               -- exactly the SPEC §3.6 fields, nothing more
  bogoId : ByteArray; upstream : String; tool : String; args : Option JVal
  justification : Option String; hints : List (List String × Format)
  agentId : AgentId; agentName : String; clientName : Option String
  session : SessionId; nonce : ReqId; createdMs : Nat; expiresMs : Option Nat

abbrev ReqId := ByteArray   -- 40 bytes: bootId (32) ‖ u64 seq; the nonce and the ID everywhere

inductive Input
  | configure (seq : Nat) (cfg : PolicyConfig) (catalog : List CatalogEntry)
  | approverSet (seq : Nat) (a : Approver)       | approverRevoked (seq : Nat) (id : ApproverId)
  | agentSet (seq : Nat) (a : Agent)             | agentRevoked (seq : Nat) (id : AgentId)
  | ownerPause (seq : Nat) (agent : AgentId)     | agentUnpaused (seq : Nat) (id : AgentId)
  | ownerCancel (r : ReqId)
  | sessionOpened (s : SessionId) (agent : AgentId) (client : Option String)
  | sessionClosed (s : SessionId)
  | call (s : SessionId) (c : CallId) (name : String) (args : Option JVal) (nowMs : Nat)
  | callEnded (c : CallId)                        -- cancel, disconnect, client gave up
  | approval (a : ApproverId) (r : ReqId) (alg : UInt16) (proof : ByteArray) (nowMs : Nat)
  | denial (a : ApproverId) (r : ReqId) (note : Option String)
  | pauseAgent (a : ApproverId) (agent : AgentId) (epoch : Nat)
  | dispatch (c : CallId) (nowMs : Nat)           -- only from an exact transport, at the write
  | notSent (c : CallId)                          -- shell: the send could not be staged
  | tick (nowMs : Nat)

inductive Output
  | authorized (c : CallId) (r : Option ReqId)    -- allow (none) or requirement met (some r): record, then stage
  | forward (c : CallId) (upstream tool : String) (args : Option JVal) (registrySeq : Nat)
  | attach (c : CallId) (primary : CallId)        -- identical retry while primary holds the request
  | reject (c : CallId) (why : Rejection)
  | pendingApproval (c : CallId)
  | ask (r : ReqId) (bytes : ByteArray) (to : List ApproverId) (groupKey : ByteArray) (pauseEpoch : Nat)
  | settled (r : ReqId) (to : List ApproverId)
  | ended (r : ReqId) (why : EndReason) (to : List ApproverId)
  | counted (r : ReqId) (a : ApproverId) | ignored (r : ReqId) (a : ApproverId) (why : IgnoreReason)
  | floodDropped (c : CallId) | agentPaused (agent : AgentId)

def step : State → Input → State × List Output × Option Nat   -- Option Nat = next deadline

@[extern "bogo_shim_verify"]                      -- C shim → Rust bogo_rs_verify; an assumption (A1, A6)
opaque verify (alg : UInt16) (pk : @& ByteArray) (msg : @& ByteArray) (proof : @& ByteArray) : Bool

@[export bogo_lean_init]   def initFfi (bogoId bootId : @& ByteArray) : State
@[export bogo_lean_step]   def stepFfi (s : State) (input : @& ByteArray) : State × ByteArray
@[export bogo_lean_decode_request] def decodeRequestFfi (b : @& ByteArray) : ByteArray
@[export bogo_lean_check_approval] def checkApprovalFfi (alg : UInt16) (pk req proof : @& ByteArray) : Bool
@[export bogo_lean_abi]    def abiVersion : UInt32
```

`stepFfi` decodes the input bytes with the Lean wire codec. If decoding fails, it returns the state unchanged plus `reject(callIdIfAny, malformed)`. Otherwise it runs `step` and encodes the outputs. Decoding is part of the proved code, so the promise holds for every byte string Rust could pass. No Rust code validates or interprets an `Input` on the core's behalf.

**Request record.** Next to each `Request` the core keeps the context it was admitted with: the resolved `ToolPolicy`, the eligible approvers, the justification key the catalog named, and the bound `CallId` if there is one. This context is fixed for the life of the request. A later `configure` never changes how an admitted request is matched, stripped or routed.

**Lifecycle inside the core:**

```
allow:     call ──► allowed(c) ──dispatch passes──► forward (removed)
                         └──dispatch fails / notSent / callEnded──► reject (removed)

approve:   pending ──requirement met──► settled ──dispatch passes──► forward (removed)
              │                            ├──dispatch fails / notSent──► reject + ended (removed)
              └──denial / end──────────────┴──end──────────────────────► ended (removed)
```

**Decision rules:**
- **Resolve policy.** The effective policy is the per-agent override, else the tool's entry, else the default. The default has type `DefaultPolicy`, which has no `allow`, so a tool the owner never listed can never run without approval (Principle 5). The shipped default is `approve`. A name that isn't in the catalog is rejected as an unknown tool. Calls from paused or revoked agents are rejected.
- **allow** outputs `authorized(c, none)` and holds the call as `allowed`. **deny** outputs `reject(denyPolicy)`.
- **approve** checks these in order:
  1. The value at the tool's justification key, if present, must be a string; otherwise the call is rejected as malformed.
  2. If a justification is required and missing, the call is rejected with a message telling the agent to include one.
  3. The core removes the justification key. Absent arguments stay absent. An object that held only the justification becomes `{}`.
  4. A pending-and-retry call that matches an existing live request is handled by the mode rule below, before the flood check.
  5. If the agent's live requests (pending plus settled) are at or over `max_pending`, the core outputs `floodDropped`, and nothing goes to approvers.
  6. If fewer eligible, active approvers exist than the requirement needs, the call is rejected with `noEligibleApprover`.
  7. Otherwise the core builds, encodes and stores a `Request` as `pending`, and outputs `ask` with identical bytes for every eligible approver.
- **Approval** is accepted only if all of these hold: the request exists and is `pending`; `now < expiresMs` when there is an expiry; the approver is registered, active and eligible for this agent and tool; and `verify alg pk ("BOGO-APPROVAL\x00v1" ++ bytes) proof` is true. Accepted approvals form a set, so the same approver counts once.
- **Denial** applies only to a `pending` request, from a registered, active, eligible approver. Under `anyDenial`, one denial ends the request with `reject(denied note)`. Under `whenUnreachable`, a denial removes that approver from those who can still approve, and ends the request once k can't be reached.
- **Settlement.** The step that meets the requirement moves the request to `settled` and outputs `settled` to its approvers. Every later approval or denial is `ignored(settled)`. Settlement is a final decision, but it isn't yet permission to run.
- **Wait mode.** The settling step also outputs `authorized(c, some r)`.
- **Pending-and-retry mode.** If no identical live request exists, the core creates one and returns `pendingApproval`. A retry is identical when session, upstream, tool, stripped arguments and justification all match. A retry of a pending request gets `pendingApproval` again. The first retry of a settled request gets `authorized` for its own call ID and binds the request to it. An identical retry that arrives while it is bound gets `attach(c, primary)`: it receives the primary's outcome, and nothing runs twice. Once the request is forwarded or fails its dispatch, it is removed. A later identical call starts a new request with a new nonce, which needs a new approval.
- **Dispatch (the final gate).** `dispatch c now` is accepted only for a call that is `allowed`, or that is bound to a `settled` request, and only once. It outputs `forward` with the stored arguments, plus the current `registrySeq`, only if all of these still hold:
  - the call is live and its session is open,
  - the agent is neither paused nor revoked,
  - for a protected call: `now < expiresMs` if there is an expiry, and the counted approvers that are still registered, active and eligible still meet the requirement.

  Otherwise it outputs `reject` (and `ended` to approvers). Either way the call's authority is removed, so it can never be dispatched again. `notSent c` removes it the same way, with the reason "upstream unavailable".
- **Ending.** These produce `ended` to approvers and `reject(endedWithoutDecision)` to a waiting call, for `pending` and `settled` requests alike: `callEnded`, `sessionClosed`, `ownerCancel`, agent revocation, an approver revocation that leaves k unreachable for a pending request, and `tick` past `expiresMs`. A late approval finds no request and is `ignored(unknown)`.
- **Pause.** `pauseAgent a agent epoch` is accepted only from a registered, active approver, and only if `epoch` equals the agent's current pause epoch. `ownerPause` from the Mac CLI needs no epoch. Both deny all of that agent's live requests and output `agentPaused`. Only `agentUnpaused` from the Mac clears the pause. It sets the agent's pause epoch to that input's `seq`, which is the log sequence number of the `agent_unpaused` entry: durable and always growing. So a pause composed before an unpause can never apply after it, even on its first delivery.
- **Request IDs.** `ReqId` is the random boot ID followed by the core's `seq`, which only grows within a boot. Every request-scoped input carries the full `ReqId`. An input naming another boot finds no request.
- **Grouping key.** `groupKey` is the encoding of (agentId, upstream, tool, stripped args, justification), using the request's value grammar. Rust hashes it for the APNs collapse ID, and the phone computes the same tuple from the decoded request.
- **Registry sequence.** Each owner input carries the `seq` of the log entry it came from. The core remembers the highest one applied as `registrySeq` and includes it in `forward`, so the verifier knows exactly which registry the gate saw.

**Rules it always keeps:**
- It is total and deterministic, with no `partial` definitions and no `panic!`.
- The only source of `forward` is an accepted `dispatch`.
- `forward` arguments are the stored stripped arguments, never a value from the current input.

### 3.2 Request encoding (Lean, decoded in Swift)

This is ADR 0001: a tagged, length-prefixed binary format. All lengths and counts are `u32` big-endian. Anything over the limit is rejected as malformed.

```
Request  := "BOGOREQ" 0x00 | u16 version=1 | field*          (fixed order; each: u8 tag | payload)
  0x01 bogoId bytes      0x02 upstream str    0x03 tool str        0x04 args opt(value)
  0x05 justification opt(str)                 0x06 hints list(path, fmt)
  0x07 agentId bytes     0x08 agentName str   0x09 clientName opt(str)
  0x0A session bytes     0x0B nonce bytes     0x0C createdMs u64   0x0D expiresMs opt(u64)
value    := 0x00 null | 0x01 false | 0x02 true
          | 0x03 u32 len ascii-number-text   (must match the JSON number grammar; kept exactly)
          | 0x04 u32 len utf8-string
          | 0x05 u32 count value*
          | 0x06 u32 count (u32 len utf8-key value)*   (keys strictly ascending by bytes)
path     := list(0x00 str key | 0x01 u32 index)
fmt      := 0x00 text | 0x01 str iso4217
opt(x)   := 0x00 | 0x01 x       str := u32 len utf8       bytes := u32 len raw
```

- **Proved.** `decode (encode r) = some r` for every canonical `r`, which gives `encode_injective`: two different requests never encode the same. `decode` rejects every non-canonical byte string: unsorted or duplicate keys, a bad number grammar, trailing bytes, an unknown tag or version.
- **Absence.** Absent `arguments` and `{}` are different requests, and the writer reproduces whichever the agent sent. An absent justification and an empty one are also different.
- **Numbers.** `4700`, `4700.0`, `4.7e3`, `4.7E3`, `4.7e+3` and `-0` are all different `num` texts, and the encoding never treats them as numbers. Rust gets the exact text only from `bogo-json`. `serde_json` is never used for arguments: even with `arbitrary_precision` it rewrites exponents (its `scan_exponent` always emits lowercase `e` and adds `+`; [serde_json `de.rs`](https://github.com/serde-rs/json/blob/master/src/de.rs)).
- **Strings** are Unicode scalar sequences after JSON unescaping, so escape spelling is syntax, not a different value. `bogo-json` rejects lone surrogates, invalid UTF-8 and unescaped control characters.
- **Who encodes what.** Only the Lean encoder inside the core produces signed bytes. Swift decodes, renders and signs the exact bytes it received, and never re-encodes. Rust and Swift are both checked against `vectors/` from `BogoVectors`: JSON source text, the expected `JVal`, request bytes, and the exact text the writer must produce.
- **Signed message.** An approval signs `"BOGO-APPROVAL\x00v1" ‖ requestBytes`. The domain tag keeps a request signature from being mistaken for any other signed object. The key is per registration, so no approver ID is needed inside.

### 3.3 Proof (`BogoProofs`) — What is proved / What is assumed

**Model: a tagged trace.** A trace is any `List Input`, run from `initFfi`. Each input has an origin:

| Origin | Inputs | What the model allows |
|---|---|---|
| Agent | `call`, `callEnded`, `sessionOpened`, `sessionClosed`, and any byte string through `stepFfi` | Anything, in any order, at any rate, including any session lifecycle |
| Network | `approval`, `denial`, `pauseAgent` | Anything: forgeries, replays, reordering, duplicates. An approval counts only if `verify` accepts it over the core's own bytes and the registered key. Denial and pause only take authority away, so no theorem about `forward` depends on them being genuine. |
| Shell scheduling | `dispatch`, `notSent`, `tick` | Any time, any number of times |
| Owner | `configure`, `approverSet`, `approverRevoked`, `agentSet`, `agentRevoked`, `ownerPause`, `agentUnpaused`, `ownerCancel` | Arbitrary values in any order. The theorems are stated relative to the registry and policy these inputs define at each step. |

`nowMs` values are arbitrary numbers in the model. "Fresh" is stated against the `now` of the dispatch step, so its meaning in real time rests on A9.

**Assumptions** (each one listed in the docs):
- **A1 Unforgeable, user-verified approvals.** For every algorithm tag in use, `verify alg (pk a) m p = true` implies `OwnerApproved a m`. In Lean it is the one axiom beyond the standard three, `Bogo.Proofs.A1_unforgeable`, so `#print axioms` shows every theorem that rests on it. `OwnerApproved` is opaque and A1 is its only source, so the axiom can't make the logic inconsistent (it holds when `OwnerApproved` is read as `True`). It covers spec assumptions 1 and 3.
- **A2 Hash collision resistance**, inside ECDSA-SHA-256 and for the log chain. The core matches by full byte equality, never by hash.
- **A3 Distinct boots.** `bootId` is 32 random bytes, so no two boots share one.
- **A4, A5.** Spec assumptions 4 and 5 (the sandbox, and upstreams rejecting unauthenticated requests). Listed, but unused in Lean.
- **A6 Faithful shell.** The proof can't see this link, so it is kept narrow. The Rust shell writes upstream exactly the `forward` outputs, and only at the write that requested them. It reports real transport events as the inputs they are. `bogo-json` delivers the agent's exact text. `bogo_rs_verify` is a faithful P-256 verifier. The Lean compiler, its runtime, the C shim and the FFI are correct.
- **A7 Genuine app.** App Attest shows that the registering app is the genuine BOGO-capable build on a real device. It doesn't attest the approval key's access control directly. That build creates the approval key only inside the Secure Enclave with `.biometryCurrentSet` and has no path that accepts a key supplied from outside.
- **A8 Owner and identity origin.** Owner inputs come only from the CLI over the owner-only control socket, from startup config, or from replaying earlier owner entries in the log. The `agent` in `sessionOpened` is the one whose token the front verified. No agent request or relay message becomes an owner input, except `removed` from a registered approver, which becomes `approverRevoked` and only takes authority away.
- **A9 Clock.** `nowMs` is the core clock of §3.5: within a boot it never decreases, and it keeps counting while the Mac sleeps.
- **A10 Storage.** A log entry reported durable survives a crash (F_FULLFSYNC on macOS behaves as documented).

**Theorems.** Here `forward c u t args _` appears in the outputs of step i of `run init inputs`:
1. **Approved.** Either the effective policy at step i was `allow`, or there is a request `r` with `r.upstream = u`, `r.tool = t`, `r.args = args`, and a set `S` of distinct approver IDs. Every member of `S` was registered, active and eligible at step i and satisfies `OwnerApproved a (sigMsg (encode r))`. `|S| ≥ 1` for any-of, and `|S| ≥ k` for k-of-n.
2. **Exact.** By (1) and `encode_injective`, the owner approved exactly `r`: its upstream, tool, arguments, justification, agent, session, nonce and times.
3. **Single-use.** For every request, and every allowed call, at most one `forward` is emitted over the whole trace.
4. **Settled is final.** Once a request is settled, no later approval or denial changes it.
5. **Fresh.** At step i, which is the `dispatch` step: the session `r.session` is open, the call `c` belongs to it and is live, the agent isn't paused or revoked, and `now < e` if `r.expiresMs = some e`. Every ending, revocation and pause the core saw before step i is honoured.
6. **Session binding.** The session of `c` equals `r.session`.
7. **Fail-closed.** No `forward` is ever emitted for: a deny policy; a paused, revoked or unknown agent; an unknown tool; a closed session; malformed input (any bytes `decode` rejects); an ended request; a settled request whose call or session ended, whose agent was paused or revoked, whose expiry passed, or whose counted approvers fell below the requirement before `dispatch`; or a pause with a stale epoch.
8. **Safe default.** A tool with no config entry and no per-agent override never produces `forward` without an approval, whatever the default.
9. **Attach never runs.** An attached call never gets its own `forward`.
10. **Encoding.** `encode_injective` and `decode_encode`.

The proofs cover any number of approvers, any-of and k-of-n under both deny rules, revocation at any point, per-agent overrides, and both modes.

**In Lean** (`BogoProofs`, each pinned by `#guard_msgs` on `#print axioms` in `BogoProofs/Axioms.lean`): (1) `approved`, (2) `exact`, (3) `single_use`, (4) `settled_final`, (5, 6) `fresh`, (7) `fail_closed` and `malformed_never_runs`, (8) `safe_default` and `unlisted_never_allow`, (9) `attach_never_runs`, (10) `encode_injective`, `decode_encode`, `encode_decode` and `decode_injective`. Also `asks_admitted` and `flood_limit` (the owner is asked only about an admitted call, under the flood limit), `blocked_after` and `blocked_agent_not_asked` (pause and revocation), and `revoked_approver_gone`. `bytes_lift`, `single_use_bytes` and `approved_bytes` carry the theorems to the raw byte strings Rust passes to `bogo_lean_step`. The gate checks the requirement and eligibility under both the policy a request was admitted with and the policy in force at `dispatch`, so (1) holds even if `configure` changes the policy while a request is live.

**Not proved:** human judgment, notification delivery, schema compatibility, detecting a client that vanishes silently, and what a provider does after BOGO handed it bytes. The linearization point is the accepted `dispatch` at the transport write.

### 3.4 Core host (`bogo-core-sys`, `bogo-core`, `bogo-verify`)

- **Build.** `build.rs` runs `lake build BogoCore:static` against the toolchain pinned in `lean/lean-toolchain`. It compiles `shim.c` against that toolchain's `lean.h` and links the flags that `leanc --print-ldflags` reports. BOGO's own small C shim is the only code that touches `lean.h`, because the [Lean FFI](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) is documented as unstable.
- **Symbols in three separate namespaces.** `@[export]` emits exactly the name it is given, so the three sets are kept apart:
  - Lean exports are `bogo_lean_*`.
  - The shim's public ABI is `bogo_core_*`.
  - The Rust verifier is `bogo_rs_verify`.

  ```c
  int  bogo_core_start(const uint8_t* bogo_id, size_t n1, const uint8_t* boot_id, size_t n2);
       // lean_initialize_runtime_module, initialize_BogoCore, lean_io_mark_end_initialization
  int  bogo_core_step(const uint8_t* in, size_t n, uint8_t** out, size_t* out_n);  // holds State inside
  int  bogo_core_decode_request(const uint8_t* in, size_t n, uint8_t** out, size_t* out_n);
  int  bogo_core_check_approval(uint16_t alg, const uint8_t* pk, size_t, const uint8_t* req, size_t,
                                const uint8_t* proof, size_t);
  void bogo_core_free(uint8_t* p);
  uint32_t bogo_core_abi(void);
  // the Lean extern target; it reads the borrowed ByteArray objects and calls into Rust:
  uint8_t bogo_shim_verify(uint16_t alg, b_lean_obj_arg pk, b_lean_obj_arg msg, b_lean_obj_arg proof);
  // implemented in Rust (bogo-verify):
  uint8_t bogo_rs_verify(uint16_t alg, const uint8_t* pk, size_t, const uint8_t* msg, size_t,
                         const uint8_t* proof, size_t);
  ```

  Inputs are borrowed only for the duration of a call. Buffers that are returned belong to the shim and are released only through `bogo_core_free`. No panic or exception crosses the ABI.
- **One core thread.** That thread initializes the Lean runtime and holds the `State`. No other thread touches Lean, so the rules around `lean_initialize_thread` never apply. It serves steps from a channel: `Core::step(Input) -> (Vec<Output>, Option<Deadline>)`. All decisions are serialized. At startup it compares `bogo_core_abi()` with the Rust constant and refuses to run if they differ. `bogo log verify` runs a second instance of the same code in its own process.
- **`bogo_rs_verify`.** Tag `1` is P-256 ECDSA with raw `r‖s` over SHA-256, as CryptoKit produces it. Tag `0xFF00` is Ed25519 for the soft approver, compiled only with `test-approvers`; in a default build the tag returns `false`, so a soft approver can't approve anything even if its record were injected. Every other tag returns `false`. A new approver route adds a tag here and a registration module, and the Lean core doesn't change (Principle 7).

### 3.5 Effects shell (`bogo-daemon`)

It is the only consumer of core outputs. **The rule: an effect, or a reply to an agent, happens only after its log entry is durable.** The `forwarded` and `result` entries necessarily come after the write. The agent's result still waits for them.

| Output | Effect (after its entry is durable) |
|---|---|
| `authorized c r` | Stage the send (below). |
| `forward c u t args seq` | Handled inside the exact transport that asked for it (§3.7); logged as `forwarded` with `registry_seq`. |
| `attach c primary` | Make `c` an extra waiter on `primary`. |
| `reject c why`, `pendingApproval c` | Reply to the waiter with the model-readable text (§3.6). |
| `ask r bytes to groupKey epoch` | The hub delivers to each listed approver and retries until `seen` or the request ends. |
| `settled r to`, `ended r why to` | The hub sends notices and retracts undelivered messages. |
| `agentPaused a` | The front's registry view marks the agent paused. |
| `counted`, `ignored`, `floodDropped` | Log only. A flood drop notifies nobody. |

- **Waiters** are keyed by `CallId`, a 128-bit value Rust mints for each call. The shell never builds upstream arguments.
- **Staging the send.** For `authorized c _`:
  1. The shell checks that upstream `u` is connected and initialized. If it isn't, it sends `notSent c`, logs `not_sent(upstream unavailable)`, and the agent gets "The upstream was unavailable; the action was not performed." Nothing waits for a reconnect: a broken upstream fails closed, and the owner is never left with an approved action that might run much later.
  2. Otherwise it calls rmcp `call_tool` on that upstream with the marker `_meta["si.eilmer.bogo/call"] = <CallId>` and empty arguments. rmcp allocates the JSON-RPC ID and correlates the response as usual.
  3. The exact transport runs the final gate when the message reaches it (§3.7).
- **Why the gate is in the transport.** In rmcp 3.10.0, `call_tool` puts the request on an mpsc channel. The service loop builds the transport's `send` future and runs it in a spawned task ([service.rs](https://docs.rs/rmcp/3.10.0/src/rmcp/service.rs.html)). On top of that, the HTTP client worker can queue a POST and resend it after re-initializing an expired session ([streamable_http_client.rs](https://docs.rs/rmcp/3.10.0/src/rmcp/transport/streamable_http_client.rs.html)). A check made before `call_tool` would therefore not be the last moment. Running `dispatch` inside the transport's write puts every SDK queue before the gate, without replacing rmcp's ID allocation or response correlation.
- **Ordering.** The transport's `dispatch` goes on the same core channel as every other input. Any `callEnded`, revocation, pause, cancel or expiry tick that the front or hub observed earlier is therefore applied first. An expiry that passed while BOGO waited is caught too, because `dispatch` carries the current `now`.
- **Attached calls** get the primary's filtered result when it arrives. If an attached call ends first, only its own waiter is dropped.
- **Inbound decisions.** Each approver message goes to the core, and its log entry (`approval`, `denial`, `agent_paused`, `approver_revoked` or `ignored`) becomes durable before the hub acknowledges the message to the relay.
- **Core clock.** Every `nowMs` comes from one function. At boot it reads the wall clock once (`W0`) and `clock_gettime(CLOCK_MONOTONIC)` once (`M0`). After that, `now = W0 + (CLOCK_MONOTONIC − M0)`. On macOS, `CLOCK_MONOTONIC` "will continue to increment while the system is asleep" (`man clock_gettime`). Rust's `Instant` uses `CLOCK_UPTIME_RAW` on Darwin, which doesn't count sleep ([Instant](https://doc.rust-lang.org/std/time/struct.Instant.html)), so it isn't used. The signed `createdMs` and `expiresMs` come from this same function. Setting the wall clock back during a boot can't lengthen an expiry, and no request survives a boot. A request without an expiry never gets one.
- **Timer.** One timer wakes at the core's reported next deadline and sends `tick`. It only ends requests promptly. Freshness itself is decided by the `now` carried in `approval` and `dispatch`, so a late timer can never let an expired request run.

### 3.6 MCP front (`bogo-front`)

- **Server.** `rmcp` `StreamableHttpService`, bound to `127.0.0.1:<port>`, with loopback `allowed_hosts` and Origin validation.
  - **Session mode on**, for protocol 2025-11-25 and earlier. The session manager's `keep_alive` is `None`, so no idle timer ends a session. `sse_retry` is `None`, so BOGO sends no priming event IDs and offers no stream resumption ([SessionConfig](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_server/session/local/struct.SessionConfig.html)).
  - **Disconnect.** MCP 2025-11-25 says a disconnect "SHOULD NOT be interpreted as the client cancelling its request", because a stream may be resumed ([transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)). BOGO offers no resumption, so a dropped stream can never deliver its result. The BOGO spec counts a disconnect as ending the call, so BOGO ends it. That is a documented, stricter profile.
  - **2026-07-28** requests are stateless ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)), and rmcp serves them that way.
- **Layers, outermost first:**
  1. **Agent auth on every request.** The bearer token is hashed with SHA-256 and looked up among agents that aren't revoked. Without a match the response is 401, and rmcp never sees the request. The `AgentId` goes into the request extensions.
  2. **Exact body.** The layer reads the POST body once and parses it with `bogo-json`. It rejects these with 400: JSON-RPC batches, duplicate keys at any depth, invalid UTF-8 or lone surrogates, and bodies over the size or depth limits. For a `tools/call`, it puts `ExactCall { name, args: Option<JVal> }` into the HTTP request's extensions and checks that `method`, `id` and `name` agree with the envelope rmcp will decode. rmcp copies the HTTP `Parts` into the handler's request context ([tower.rs](https://github.com/modelcontextprotocol/rust-sdk/blob/main/crates/rmcp/src/transport/streamable_http_server/tower.rs)). The handler uses only `ExactCall`. rmcp's own parsed `arguments` are ignored, and a call without `ExactCall` is rejected. The agent's `_meta` is never forwarded upstream.
  3. **Call liveness.** Each `tools/call` registers a token keyed by JSON-RPC ID and session, and its response body is wrapped in a drop guard. A `tools/call` whose ID is already in flight in the same session is rejected, so a reused ID can never take over or cancel another call's waiter. If the body is dropped before the final message, or rmcp's cancellation token fires (on `notifications/cancelled` or a stateless disconnect), the front sends `callEnded`. Protected wait-mode calls get no intermediate messages.
- **BOGO sessions.** The core's `SessionId` is `bootId ‖ 16 random bytes`. Three kinds of connection map onto it:
  - **Shim session (any protocol).** Every request carries `Bogo-Session: <128-bit random>`, which the shim mints once per process. The session is bound to the agent of its first request, and it is accepted only while its liveness stream (`GET /mcp/bogo-liveness`, same header and token) stays open. It ends when that stream closes, on DELETE, on agent revocation, or when the daemon stops.
  - **Session protocol, direct.** One BOGO session per `Mcp-Session-Id`, bound to the agent of its first request. A request on it with another agent's token is rejected, and the session closes. The client's self-reported name comes from `initialize.clientInfo`. The session ends on DELETE, agent revocation or daemon stop. A wait-mode call still ends the moment its own stream drops. If a direct client vanishes between requests without sending DELETE, BOGO can't see it. Its pending-and-retry requests then stay pending, but they can never run, because running needs a retry in that session (§11).
  - **2026-07-28 stateless, direct.** Each `tools/call` is its own session, opened and closed around the call. The client name comes from `_meta` `io.modelcontextprotocol/clientInfo`. Wait mode works unchanged. A pending-and-retry tool is rejected with "This tool needs a session-based MCP connection (protocol 2025-11-25) or the BOGO stdio shim."
- **`tools/list`** returns this agent's combined catalog. A paused or revoked agent gets a JSON-RPC error instead, for every request it sends. Deny tools are hidden when `hide_denied` is set. Approve tools get the justification property. Filtered output fields are removed from `outputSchema`, or the `outputSchema` is left out when it can't be adjusted simply (§3.8). Order is deterministic, and `cacheScope` is private. Legacy sessions are notified when an upstream sends `list_changed`.
- **Model-readable results:**
  - forwarded → the upstream's real `CallToolResult`, after filtering
  - denied → `isError`, "The owner denied this action." plus " " and the note, if there is one
  - ended → `isError`, "Approval was not received in time; the action was not performed."
  - pending → `isError`, "Pending owner approval. Retry this exact call (same arguments and justification) in this session to run it once approved."
  - not sent → `isError`, "The upstream was unavailable; the action was not performed."
  - unknown → `isError`, "The upstream connection failed after the call was sent; the action may or may not have happened. BOGO will not retry it."
  - other rejections → `isError` with the reason: deny policy, paused, revoked, flood limit, missing justification, unknown tool, malformed
- **Not proxied.** Resources, prompts, completions, sampling, elicitation and roots are not exposed, because each would open a path around the gate. BOGO advertises only `tools`.

### 3.7 Upstream manager and the final gate (`bogo-upstream`)

- **One shared connection per upstream.**
  - Local upstreams: rmcp client over `ExactChildTransport`, BOGO's own `Transport` around the child's stdin and stdout. The child gets `command`, `args` and a minimal environment built from `secrets.toml` references. Credentials exist only in that child's environment.
  - Remote upstreams: `StreamableHttpClientTransport` over `ExactHttpClient`, BOGO's own `StreamableHttpClient` on `reqwest`, which serializes each message itself ([trait](https://docs.rs/rmcp/3.10.0/rmcp/transport/streamable_http_client/trait.StreamableHttpClient.html)). Headers come from secrets. Redirects are not followed. `reinit_on_expired_session` is off, so the worker never resends a message.
- **Exact transports.** They serialize every other message with serde_json. For a `tools/call`:
  1. If the marker `_meta["si.eilmer.bogo/call"]` is missing, the transport refuses, logs `internal_send_refused` and writes nothing. That holds whoever inside the daemon tried to send it.
  2. It sends `dispatch(callId, now)` to the core and waits for the answer. Because this happens inside the transport's own send, every SDK queue lies before it.
  3. On `forward`, in the same task and with nothing awaited in between, it removes the marker and starts the write: the JSON-RPC line, or the HTTP POST, with `arguments` emitted by the `bogo-json` exact writer from the `forward` output. On anything else, it writes nothing and returns an error to rmcp, and the shell resolves the waiter from the core's `reject`.
  4. The gate accepts a `CallId` once. A second `send` for the same marker, from any retry layer, gets no `forward` and writes nothing.
- **Linearization.** The point is the accepted `dispatch`, immediately followed by the start of one write. Nothing that can wait sits after it: no SDK queue, no reconnect, no session re-init, no credential work and no retry. The only thing after it is the transport's own single attempt to put that one message on the wire.
- **Write outcomes:**
  - The write fails before any byte leaves: a closed pipe on the child's stdin, or a `reqwest` connect error, which happens before the request is sent. That is positive evidence, logged `not_sent`.
  - The write fails after it has started, or the child dies before replying: logged `unknown`.
  - Neither is ever retried.
- **Client capabilities.** BOGO's client to each upstream declares none: no `roots`, `sampling` or `elicitation`. That matters for the filesystem server, where client-supplied roots would replace its command-line roots ([filesystem server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)).
- **Discovery** follows `tools/list` pagination to the end, and again on `notifications/tools/list_changed`.
- **Naming.** Upstream names match `[a-z0-9-]+` and contain no `__`, so splitting `<upstream>__<tool>` at the first `__` is unambiguous. A name over MCP's length limit, or with characters outside `[A-Za-z0-9_.-]`, is not exposed and is reported as `unexposable` in `bogo tools`.
- **Justification field.** For approve tools, the property name is the first of `justification`, `bogo_justification`, `bogo_justification_2`, … that doesn't occur as a property name anywhere in the tool's schema (top level, any combinator branch, any `$defs`) and isn't matched by any `patternProperties` pattern. The chosen key is recorded per tool and copied into each request at admission, and it is the only key the core strips. The advertised field stays optional. A required justification is enforced at admission, with its own message.
  - **The rule.** Every argument object the original schema accepts must still be accepted once the field is added as a string. The advertised schema may accept more than the original, never less. That is enough, because BOGO never validates against the advertised schema: the upstream validates what it actually receives, which is the agent's exact arguments with only the field removed.
  - **How it's kept.** `{"type":"string","description":"Why you are making this call (shown to the owner as your unverified claim)."}` goes into the top-level `properties`. Wherever the schema constrains the object as a whole, the smallest widening is applied:
    - a top-level or combinator-branch object closed by `additionalProperties: false` or `unevaluatedProperties: false` gets the property in that branch too,
    - `maxProperties: n` becomes `n + 1`,
    - `propertyNames: S` becomes `{"anyOf": [S, {"const": "<key>"}]}`,
    - a top-level `$ref` whose target closes the object and is referenced nowhere else gets the property in that target.
  - **What can't be kept simply:** whole-object `const` or `enum`, a closing `if`/`then`/`else`, `$dynamicRef`, a closed `$ref` target that is shared, and `dependentSchemas` that close the object. Such a tool is still exposed with the field at the top level and marked `justification: strict-client-risk` in `bogo tools`. A client that validates inputs refuses the field on that tool, visibly, and nothing runs (§11).
  - **Known limit.** If a schema leaves extra keys open and an upstream gives undeclared meaning to a key with the chosen name, the agent can't pass that key, because it is always taken as the justification. Exactness is unaffected, since what runs is exactly what was signed. The docs state this.
- **Catalog.** Persisted to `state/tools.json` with first-seen times, so `bogo tools` works while BOGO is stopped. A new catalog reaches the core as `configure`. New tools get the default (`approve`).
- **Results** are parsed by rmcp with serde_json `arbitrary_precision`, so big numbers keep their digits. An upstream `InputRequiredResult` or a server→client request is answered as an error: "upstream asked for interactive input, which BOGO does not pass through."
- **Health.** A child that exits is restarted with exponential backoff, and its tools stay listed. A call staged while the upstream is down is `not_sent` (§3.5).
- **Secrets in results.** Before a result or error reaches the agent or the log, every exact occurrence of a configured secret value, and of its base64 form, is replaced with `[credential removed by BOGO]`. That covers content blocks, `structuredContent`, resource URIs and text, `_meta`, and error messages. Child stderr is scanned the same way before it reaches `tracing`. This catches an upstream that echoes a credential back, not one that transforms it, and the docs say so.

### 3.8 Output filter (`bogo-filter`)

- **Rules.** Per tool, `filter_output = ["url", "data.share.link", …]`. A bare name matches that key at any depth. A dotted path matches exactly, and `*` matches every array element. The action is `strip` (the default) or `redact`, which replaces the value with `"[removed by BOGO]"`.
- **Where it applies:** `structuredContent`, every `text` block that parses as JSON, the result's `_meta`, and the `uri` and `text` of resource-link and embedded-resource blocks. A field filtered in one representation is filtered in all of them.
- **Fail-closed.** If a tool has filters and a text block isn't JSON, the block is replaced with `"[output withheld by BOGO: not filterable]"`. The log records that this happened, without the content. The tool is never rerun.
- **Advertised output schema.** A stripped property is also removed from the tool's `properties` and `required`. If anything else in the schema refers to it, the `outputSchema` is left out entirely.
- **Scope.** It removes named fields. It doesn't detect secrets in prose or binary data, and the docs say so.
- `filter(&Rules, CallToolResult) -> (CallToolResult, Report)` is a pure function outside Lean.

### 3.9 Audit log (`bogo-log`): the only durable authority

- **File.** `~/.bogo/log/audit.jsonl`, one JSON object per line:

  ```json
  {"v":1,"seq":1042,"prev":"<hex sha256 of line 1041 incl. newline>","ts":"2026-11-14T18:02:11.204Z",
   "kind":"request_created","agent":{"id":"…","name":"Trip planner"},"session":"…",
   "tool":"stripe__<spend tool>","req":"<reqId hex>","request_b64":"…","justification":"booking…",
   "policy":{…resolved ToolPolicy…}}
  ```

- **Entry kinds.**
  - Lifecycle: `boot` (boot_seq, bootId, SHA-256 of `bogo.toml`), `tail_recovered`.
  - Agents: `agent_added`, `agent_revoked`, `agent_paused` (by owner or by approver), `agent_unpaused` (its `seq` is the new pause epoch).
  - Approvers: `approver_registered` (transaction ID, public keys, algorithm, App Attest key ID, environment, validation category, bundle version, attestation hash, and `replaces` on re-registration), `approver_revoked` (`by: owner | self`).
  - Calls: `call` (every attempt, any policy), `rejected` (with reason), `request_created`, `approval` (counted, or ignored with why), `denial` (with note), `request_settled`, `authorized`, `request_ended` (with why), `forwarded` (with `registry_seq`), `not_sent`, `result` (`ok`, `is_error`, `unknown`, filtered fields, credentials removed).
  - Request bytes and argument values are logged. Result bodies are not.
- **Credentials never appear.** `Secret` has no `Serialize`, and the writer accepts only `LogEvent` values, which can't hold one. Agent entries carry the token's SHA-256, never the token.
- **Writer.** One task with group commit: write every waiting entry, run one `F_FULLFSYNC`, then release those waiters. With the shell's rule (§3.5), this means:
  - no approver hears of a request before `request_created` is durable,
  - no send is staged before `authorized` (or the allowed call's `call` entry) is durable,
  - no relay message is acknowledged before its effect is durable,
  - no reply reaches an agent before its record is durable.
- **Registry.** Every change to agents, approvers, pause state or epochs is written to the log first. `state/agents.json` and `state/approvers.json` are caches. Each records the `seq` it reflects and is rewritten atomically after its entry is durable. At startup, the entries after that `seq` are replayed, and only then is the registry fed to the core. A checkpoint that is missing or unreadable is rebuilt from the whole log. The registry and the log can never disagree.
- **Recovery.**
  - Only a final line without a trailing newline counts as torn. It was never acknowledged to anything. It is moved to `audit.torn.<ts>`, and a `tail_recovered` entry with its hash is appended.
  - A complete line that fails to parse or to chain is corruption. BOGO refuses to start, names the line, and never repairs history by dropping a record.
  - Outcomes left open by a stop are classified conservatively. Only positive evidence counts as "not sent":
    - an `authorized` (or allowed `call`) with neither `forwarded` nor `not_sent` before the next `boot` is reported as **outcome unknown (BOGO stopped after authorizing; it may have been sent)**,
    - a `forwarded` with no `result` is **outcome unknown**.

    Neither is ever replayed.
- **Outcome lookup.** `outcome(reqId) -> Live | Executed | NotSent | Denied | Ended(why) | Unknown | NoRecord`. It reads only that request's boot segment, found through `log/boots.idx` (bootId → byte offset), a cache rebuilt whenever it is missing or behind. It answers a phone's `sync` (§3.11). Every outcome a phone can wait for is already in the log, so the Mac needs no separate outbox.
- **`bogo log verify`:**
  1. Recompute the chain.
  2. Replay registration and revocation entries in order.
  3. Check every `approval` with `bogo_core_check_approval` (the same Lean code) against the key registered at that moment, over the logged request bytes.
  4. For every protected `forwarded`, rebuild the registry as of its `registry_seq` (the registry the gate actually saw) and confirm enough distinct counted approvals from approvers that were registered, active and eligible there. Thresholds and eligibility come from the resolved policy copied into `request_created`.
  5. Report evidence that was ignored (late, revoked, settled) as ignored, never as counted, and never as corruption.

  It reports the first break with its line number. A later revocation doesn't invalidate an earlier valid execution.
- **Limit.** The chain shows any change relative to the history it holds. It can't detect replacement of the whole file with a valid shorter chain. Exports the owner keeps can anchor a comparison. The docs say this.
- **`bogo log [search]`** prints a filtered view (agent, tool, decision, time range, text) with request bytes decoded by the Lean decoder export and terminal control characters escaped. **`bogo log export`** writes JSON Lines (raw entries) or CSV.

### 3.10 Approver hub and route interface (`bogo-approver`)

```rust
#[async_trait]
pub trait ApproverRoute: Send + Sync + 'static {
    fn kind(&self) -> &'static str;                                        // "iphone", "soft"
    async fn register(&self, name: &str, owner: &dyn OwnerPrompt) -> Result<NewApprover, RegError>;
    async fn deliver(&self, a: &ApproverRecord, r: &Outbound) -> Result<(), DeliveryError>; // idempotent per (a, r.id)
    async fn notice(&self, a: &ApproverRecord, r: &ReqId, n: &Notice) -> Result<(), DeliveryError>; // settled|ended|outcome
    async fn boot(&self, a: &ApproverRecord, b: &BootNotice) -> Result<(), DeliveryError>;
    async fn revoked_ack(&self, a: &ApproverRecord) -> Result<(), DeliveryError>;
    fn inbound(&self) -> BoxStream<'static, Inbound>;                      // channel-authenticated
}
pub struct NewApprover { pub alg: u16, pub sig_pk: Vec<u8>, pub tx_id: [u8; 32], pub route_data: serde_json::Value }
pub enum Inbound {
    Approval { approver: ApproverId, req: ReqId, alg: u16, proof: Vec<u8> },
    Denial { approver: ApproverId, req: ReqId, note: Option<String> },
    Pause { approver: ApproverId, agent: AgentId, epoch: u64 },
    Seen { approver: ApproverId, req: ReqId },
    Removed { approver: ApproverId },
    Sync { approver: ApproverId, reqs: Vec<ReqId> },
    RegResend { approver: ApproverId, tx_id: [u8; 32] },
}
// Every Inbound carries an ack handle, acked to the relay only after its log entry is durable.
```

- **Fan-out.** For `ask`, the hub sends to each listed approver's route and retries `deliver` with backoff until `Seen` or the request ends. That is how "delivery keeps being retried" is met.
- **Inbound.** The hub turns `Inbound` into core inputs.
  - `Removed` becomes `approverRevoked` (logged `by: self`) and is answered with `revoked_ack` once durable. A `Removed` from an approver that is already revoked gets `revoked_ack` again.
  - `Sync` is answered with one `outcome` notice per listed request, from the log's lookup.
  - `RegResend` is answered with the stored `registered` result for that transaction.

  All three answers are read-only and idempotent.
- **State in memory only.** Delivery state and the set of seen message IDs live in memory. Every phone message is idempotent (an approval set, a denial only of `pending`, `seen`, `removed`, an epoch-checked pause, `sync`), so a duplicate after a crash gives the same result.
- **On every boot**, before admitting any agent traffic, the hub:
  - re-applies its relay mailbox allowlist from the registry,
  - sends `boot` to every approver,
  - sends each active approver its `registered{txId}` again (idempotent; the phone ignores it if already active).

  A registration whose confirmation was lost in a crash is therefore repaired without a Mac outbox.
- **The core knows nothing about routes.** It sees each approver only as `(id, name, alg, sig_pk, active)`.
- **Re-registering.** `bogo approver add` with an existing name runs a new registration. On success, one `approver_registered{replaces}` entry revokes the old ID and registers the new one, and the core receives that as one `approverSet` step. Old votes never transfer.

### 3.11 iPhone route (`bogo-approver-iphone`) and its protocol

**Keys.**

| Holder | Key | Purpose |
|---|---|---|
| Mac (`~/.bogo/keys/`, 0600) | X25519 `macE2E` | HPKE channel; `bogoId = SHA-256(macE2E.pub)` |
| Mac | Ed25519 `macRelay` | Relay mailbox auth |
| Mac | the owner's APNs `.p8`, referenced from `secrets.toml` | Pushes |
| Phone, per registered Mac | Secure Enclave P-256 `approve` | Approval signatures. `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` with `[.privateKeyUsage, .biometryCurrentSet]`. Can't be exported; unusable after a Face ID change. |
| Phone, per registered Mac | X25519 `phoneE2E`, Ed25519 `phoneRelay` | Channel and mailbox; Keychain, `AfterFirstUnlockThisDeviceOnly`, BOGO's own service names. They can't produce approvals. |
| Phone | App Attest key | Proves the genuine app at registration |

**Envelope (both directions).**

```
Envelope := "BOGOE2E" 0x00 | u8 version=1 | u8 direction | u8 type | 16 bytes msgId | bytes enc | bytes ciphertext
  HPKE mode_auth: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (RFC 9180)
  info = "bogo/e2e/v1" ‖ bogoId ‖ approverId      aad = header bytes (magic..msgId)
  msgId: random, chosen once when the message enters the sender's outbox; every resend is the same bytes
```

- **Mac→phone:**
  - `request {reqId, bootSeq, bytes, pauseEpoch, armDelay}`
  - `settled {reqId}`
  - `ended {reqId, why}`
  - `boot {bootSeq, bootId}`
  - `outcome {reqId, live|executed|notSent|denied|ended(why)|unknown|noRecord}`
  - `registered {txId, approverId}`
  - `revokedAck {}`
- **Phone→Mac:**
  - `approval {reqId, alg=1, sig}`
  - `denial {reqId, note}`
  - `pause {agentId, epoch}`
  - `seen {reqId}`
  - `pushToken {tokenSeq, token, env, encodingVersions}`
  - `sync {reqIds}`
  - `regResend {txId}`
  - `removed {}`
- **Single-shot HPKE.** Every envelope has a fresh ephemeral `enc`, so there is no nonce counter to store or recover, and restoring a backup can't cause nonce reuse ([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)). Auth mode binds each message to the sender's static key, so the relay can neither read nor forge in either direction. `msgId` is used only for deduplication.
- **Replay and reordering.** HPKE has no replay protection of its own ([RFC 9180 §9.7](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7)), and the relay can delay, reorder or repeat anything. No message is accepted or refused by its position:
  - Request-scoped messages carry the full 40-byte `reqId`. One from another boot names no live request.
  - `approval` is a set member. `denial` acts only on `pending`. `seen`, `removed`, `sync` and `regResend` are idempotent.
  - `pause` carries the current epoch.
  - `pushToken` applies only if its `tokenSeq` is higher than the last one seen. It is stored with the approver in a `route_updated` log entry.
  - The phone keeps one record per `(bogoId, reqId)`, with terminal states kept as tombstones. A `settled`, `ended` or `outcome` that arrives before its `request` is kept, and the late `request` shows greyed. A `boot` with a higher `bootSeq` ends every request from other boots. A `request` whose `bootSeq` is below the latest one known shows as ended.
  - Duplicate `msgId`s are dropped before decryption.
  - **Acknowledge after effect.** Each end acks a message to the relay only once its effect is durable there: on the Mac, after its log entry; on the phone, after its store write. A crash before that leaves the message in the mailbox to be fetched again.
  - **Reconciliation.** The phone sends `sync` on launch, on foreground, after each `boot`, and with each outbox resend of a decision that has no `outcome` yet. A lost `outcome`, a Mac crash after it accepted a decision, or a relay that dropped a message only delays History; it can't leave it wrong.

**Delivery.** For each `ask`, the route does two things concurrently:
- It puts a `request` envelope in the phone's mailbox, with `msgId = H(reqId‖approverId)[0..16]` so resends are idempotent at the relay.
- It sends one APNs alert:

  ```
  apns-push-type: alert   apns-priority: 10   apns-topic: com.johansardar.applebridge.ios
  apns-collapse-id: hex(HMAC(key derived from macE2E, groupKey))[:32]
  {"aps":{"alert":{"title":"BOGO","body":"Approval requested"},"interruption-level":"time-sensitive",
          "category":"bogo.request","thread-id":"bogo","content-available":1,"sound":"default"},
   "bogo":{"v":1,"mac":"<bogoId prefix>","rid":"<reqId hex>"}}
  ```

- The push carries no request content. Duplicates collapse into one banner, and the phone counts them.
- APNs is only a wake-up, never the queue. Apple can coalesce or drop notifications, and Apple Bridge shares the bundle, so its pushes can displace BOGO's ([sending notification requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns)). The relay mailbox is what the phone trusts. It fetches on launch, on foreground and on any push.
- Pushes are retried until APNs accepts them. The mailbox copy is retried until `seen`. The APNs host follows the environment the phone reported. Provider tokens are ES256, cached and refreshed within Apple's limits ([token auth](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns)).

**Registration (numeric comparison).** This follows the commitment scheme of Bluetooth LE Secure Connections numeric comparison, so a man in the middle gets one guess at a 6-digit code ([Bluetooth numeric comparison](https://www.bluetooth.com/blog/bluetooth-pairing-part-4/)).
1. `bogo approver add "Johan iPhone"` creates an ephemeral X25519 `eM`, posts a lobby offer `{offerId, ePubM, macLabel}` to the relay, and refreshes it while the command runs.
2. BOGO → Macs → Add Mac lists the open offers by label and age. The phone picks one, creates `eP` and sends `ePubP`. The Mac accepts exactly one peer per offer.
3. The Mac sends the commitment `Cm = SHA-256("bogo-reg-commit" ‖ ePubM ‖ ePubP ‖ Nm)`, where `Nm` is 16 random bytes.
4. The phone sends `Np`, a fresh 16 random bytes. The Mac reveals `Nm`, and the phone checks `Cm`. Both reject an all-zero shared secret.
5. Both compute `code = u64be(SHA-256("bogo-reg-code" ‖ ePubM ‖ ePubP ‖ Nm ‖ Np)[0..8]) mod 10^6` (bias below 2^-44) and show it as `382 917`. After that, all registration traffic is sealed under `K = HKDF(X25519(eM, eP), transcriptHash)`, with a unique ID for each phase.
6. The owner confirms on the Mac. Sealed under `K`, the Mac sends `macConfirmed {macE2E.pub, macRelay.pub, bogoId, macName, challenge}`, where `challenge` is 32 fresh bytes. Only then does the phone enable Confirm. `txId = SHA-256(transcriptHash)`. A mismatch or an abort on either side ends the attempt, and the owner starts again.
7. The owner confirms on the phone with Face ID. That one `LAContext` evaluation creates the Secure Enclave key and signs `"BOGO-REG\x00v1" ‖ transcriptHash ‖ challenge` as proof of possession. The phone then:
   - creates `phoneE2E` and `phoneRelay`,
   - runs App Attest `generateKey` and `attestKey(keyId, clientDataHash = SHA-256(transcriptHash ‖ challenge ‖ sePub ‖ phoneE2E.pub ‖ phoneRelay.pub))`,
   - adds the Mac's mailbox to its allowlist,
   - stores the pending registration, marked "waiting for the Mac" and not yet usable,
   - sends `regSubmit` (everything, plus push token, environment and supported encoding versions), resending the same bytes until it gets an answer.
8. The Mac checks the following. Any failure aborts, and nothing is registered.
   - **The attestation**, in `bogo-attest`, against every step of [Apple's procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server):
     - the certificate chain to the pinned Apple App Attestation root, never the system trust store,
     - the nonce in the credential certificate's extension, computed by BOGO,
     - the key ID,
     - the RP ID hash for the App ID in `[approvers.iphone] app_id` (default `AX3C2B78YD.com.johansardar.applebridge.ios`, from `project.yml`'s team and bundle; the App ID prefix is checked once against the provisioning profile, since it need not equal the team ID),
     - counter 0, the credential ID, and the AAGUID environment,
     - the COSE credential key, which must equal the certified key and end the authenticator data. *Correction (2026-11-16, first real iPhone):* real App Attest data is 164 bytes with flags `0x40` and carries no extension map, so there is no `apple_validation_category_01` or `apple_bundle_version_01` to read. BOGO checks them only if Apple ever sends the map (flag ED set); otherwise the registration records them as null.
   - **Environment** (from the AAGUID) against `[approvers.iphone] app_attest`. The default `["production"]` accepts TestFlight or App Store builds; the two can't be told apart without the extension map. `"development"` is accepted only if the owner lists it.
   - **The proof-of-possession signature.**

   On success the Mac appends `approver_registered` and waits until it is durable, then updates its mailbox allowlist. Only then does it answer `registered {txId, approverId}`, on the lobby channel and as an envelope in the phone's mailbox.
9. The phone marks the registration active only when `registered` with its `txId` arrives. The lobby offer is then deleted.

**Interrupted registration.**
- Before the Mac commits, nothing is registered. The phone's pending entry shows "Not confirmed by the Mac", and the owner can discard it. Discarding deletes the approval key at once and queues `removed` under the pending channel keys, in case the Mac did commit. A Mac that never committed can't open it. One that did revokes the record.
- After the commit, the phone always recovers. The `registered` envelope waits in its mailbox. A `regResend {txId}` gets the same answer. On boot, the Mac resends `registered` to every active approver. The same `txId` is never registered twice. A different `txId` for the same name is a re-registration.

### 3.12 Relay (`bogo-relay`)

- **Deployment.** On the VPS, completely separate from Apple Bridge's relay:
  - its own systemd unit `bogo-relay.service` and its own port, chosen by the owner (§11),
  - its own SQLite file (WAL, `synchronous=FULL`) and its own firewall rule,
  - TLS with `rustls`, using a Let's Encrypt certificate that `lego` obtains through Cloudflare DNS-01 with a token scoped to `eilmer.si`. The token lives outside the relay's application state, and the certificate reloads on a renew hook.
  - `bogo.eilmer.si` resolves to the VPS (DNS only, not proxied).
- **API (JSON over HTTPS):**

  ```
  POST /v1/auth/challenge {pub}        → {challenge}        (one use; binds service and mailbox)
  POST /v1/auth/verify {pub, sig}      → {token}            (bearer in memory; mailbox = SHA-256(pub))
  POST /v1/allow {senders:[mailbox]}   (only the mailbox owner sets who may write to it)
  POST /v1/send {to, msg_id, body}     → 200 once durable | 409 full | idempotent on (to, msg_id)
  POST /v1/fetch {wait:true}           → [{msg_id, from, body}]   (long-poll)
  POST /v1/ack {msg_ids}               (recipient deletes)
  POST /v1/retract {to, msg_ids}       (sender deletes its own undelivered messages)
  POST /v1/lobby/offer | GET /v1/lobby | POST /v1/lobby/{id}/msg | POST /v1/lobby/{id}/fetch
                                       (registration only; in memory; offers vanish unless refreshed)
  ```

- **Rules it keeps:**
  - It stores only ciphertext and routing metadata, and holds no application secret.
  - It never drops a message silently: a full mailbox answers 409, and the sender retries.
  - Messages are deleted only on ack, on retract, or at the owner-set maximum age. That age never defines request expiry: an endpoint still holding a live obligation re-sends.

### 3.13 iPhone approver (`BogoKit` inside apple-bridge-iphone)

**Narrow edge.** This is the only API the host app sees:

```swift
@MainActor public protocol BogoHost: AnyObject {
    var pushToken: Data? { get }                     // the one thing shared with the host
    var apnsEnvironment: BogoAPNsEnvironment { get }
}
@MainActor public final class BogoSection {
    public init(host: BogoHost, storageDirectory: URL, relayURL: URL)
    public var tab: some View { get }                                  // Inbox | History | Macs
    public static var notificationCategories: Set<UNNotificationCategory> { get } // "bogo.request": [Deny]
    public func owns(_ userInfo: [AnyHashable: Any]) -> Bool           // payload has "bogo"
    public func remoteNotification(_ userInfo: [AnyHashable: Any]) async -> UIBackgroundFetchResult
    public func notificationResponse(_ response: UNNotificationResponse) async
    public func pushTokenChanged(_ token: Data)
    public func sceneBecameActive() async
}
```

**Modules.**
- **BogoModel** (pure):
  - `RequestBytes.decode` enforces canonical form exactly as the Lean decoder does, and is checked against `vectors/`.
  - `ReviewModel` builds the two sections:
    - **"Will execute (exact)":** upstream, tool, "Requested by \<agentName\>", highlighted fields in their formats, every argument as a full tree with raw values inspectable (nothing truncated or summarized), and the expiry countdown if there is one. `moneyMinor` accepts only integer number text within bounds and uses integer arithmetic (`4700` → `$47.00`), showing the original token beside it. Any other text is shown raw with a "can't format" mark. No floating point is used.
    - **"Agent's reason (unverified)":** the justification, the client's self-reported name, the session tag (8 hex characters from the session's random part, not its boot prefix), and any warning.

    Control, bidirectional-override and zero-width characters show as visible escapes, and significant whitespace is made visible. Agent text is never interpreted as markup.
  - `MismatchRule` finds amounts marked as currency: `$47`, `$47.00`, `47 USD`, `USD 47`, `47 dollars`. Each is compared in major units with every field shown as currency. It warns for each amount that matches none: "Reason says $5, but this will charge $500.00". A bare number, a time or a flight number never matches, because each pattern needs a currency marker. No amount means no warning.
  - `Grouping.key` uses the same tuple as the core's `groupKey`.
  - `Inbox` states, per request:
    - `pending → approving → sent → outcome(executed|notSent|denied|ended|unknown)`
    - `pending → denying → sent → outcome`
    - `pending → settled`
    - `pending → ended`

    Ended and settled entries are greyed and offer no actions. Terminal states are kept as tombstones.
- **BogoCrypto.**
  - `ApprovalKey` wraps `SecureEnclave.P256.Signing.PrivateKey(accessControl:authenticationContext:)` ([SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave), [biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)).
  - Each approval uses a fresh `LAContext` with `touchIDAuthenticationAllowableReuseDuration = 0`, and there is no passcode fallback. The signing operation itself enforces Face ID.
  - `Channel` wraps CryptoKit `HPKE` in auth mode, `.Curve25519_SHA256_ChachaPoly` ([HPKE](https://developer.apple.com/documentation/cryptokit/hpke)).
  - `Attest` wraps `DCAppAttestService` ([DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice)).
  - A key-invalidated error on signing, or a changed `evaluatedPolicyDomainState` when the tab opens, marks that Mac `needsReRegistration`.
- **BogoRelay.**
  - `MacLink` is the port the rest of BogoKit uses. `RelayMacLink` is the real implementation. `StandInMacLink` replays requests from `vectors/` in-process, so review, grouping, the arm delay, Deny, Pause and Face ID signing all work before the relay or the Mac exist.
  - **Store.** One SQLite database (the system library) in `Application Support/BOGO/`, with file protection `completeUntilFirstUserAuthentication` so a push wake can write. It holds exact request bytes, state records, tombstones, the outbox and registrations. A state change and its outbox row commit together.
  - **Order for every inbound `request`:** write it to the store, send `seen`, then ack it to the relay. A crash can never lose the phone's only copy.
  - **Decisions.** Signed approvals and denials are stored before they are sent, and resent until an `outcome` arrives or the request is known to have ended. A resend never needs a second Face ID.
- **BogoSection.**
  - Screens: Inbox (grouped, with counts), History (decisions and outcomes; a receipt is never shown as execution), Macs (list, Add Mac, remove, re-register prompt), Review, registration.
  - Review shows **Approve**, **Deny** (with an optional note) and **Pause agent**. Approve becomes tappable only after `armDelay` once the screen is shown, and the delay restarts when the screen switches request or returns from the background.
  - A grouped entry reviews its oldest live request and shows that request's session tag. Approve and Deny decide that one request only. The agent-wide control is Pause.
  - **Remove** deletes that Mac's approval key at once, then queues `removed`. The channel keys are kept until `revokedAck` arrives. Until then the Macs list shows "Removed here; the Mac hasn't confirmed yet".
- **Notification.** Category `bogo.request` has one action, `Deny` (`.destructive`, not `.foreground`), handled in the background: it seals and sends the denial, or queues it. Tapping the banner opens Review, which is the only place Approve exists.
- **Storage isolation.** Nothing is shared with Apple Bridge storage, identity or Keychain items. BOGO works on a phone that was never paired with the Apple Bridge Mac gateway.

### 3.14 Host app changes (apple-bridge-iphone)

- **Tab.** `ShellTab.approvals` ([ShellModel.swift](/Users/johansardar/apple-bridge-iphone/ios/App/ShellModel.swift:10)) becomes `.bogo`, titled "BOGO", and renders `BogoSection.tab`.
- **Removed.** The Approvals capability ([ApprovalsCapability.swift](/Users/johansardar/apple-bridge-iphone/ios/Capabilities/Approvals/ApprovalsCapability.swift), [ApprovalInbox.swift](/Users/johansardar/apple-bridge-iphone/ios/Capabilities/Approvals/ApprovalInbox.swift)), its screens and notification actions, and its entry in `Capabilities`.
- **Old approval jobs.** In `PushDelivery`, the `bridge.approval` branch ([PushDelivery.swift](/Users/johansardar/apple-bridge-iphone/ios/Delivery/PushDelivery.swift:125)) just `continue`s, with no delivery and no result, so those jobs expire on the unchanged Mac.
- **Capture.** `CaptureCapability`'s deferred handlers ([CaptureCapability.swift](/Users/johansardar/apple-bridge-iphone/ios/Capabilities/Capture/CaptureCapability.swift:6)) are removed. `CommandHandlers.handler(for:)` ([CommandHandlers.swift](/Users/johansardar/apple-bridge-iphone/ios/Delivery/CommandHandlers.swift:7)) then returns `nil` for `iphone.capture.*`, and the existing path answers rejected, so capture always comes back denied. The descriptor stays, with `available: false`.
- **`BridgeAppDelegate`:**
  - token registration also calls `bogo.pushTokenChanged`,
  - remote notifications and notification responses ask `bogo.owns` first, and everything else follows the existing path,
  - BOGO's category is merged into the registered categories, never replacing unrelated ones.
- **Project.** `project.yml` adds the local package `BogoKit`. The entitlements gain `com.apple.developer.devicecheck.appattest-environment` ([entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.devicecheck.appattest-environment)). `NSFaceIDUsageDescription` gets BOGO wording.
- **Existing checks that name the Approvals tab** (`lab/ios/ShellProof.swift`, `packaging/dev/check-models.py`) are updated to describe the BOGO tab. Nothing new is added to them.
- **Untouched:** Apple Bridge pairing, the gateway client, the Apple Bridge relay and its APNs path, and every other capability.

### 3.15 Stdio shim (`bogo-shim`)

- It reads `BOGO_URL` and `BOGO_AGENT_TOKEN` from its environment.
- **Never re-encodes.** It reads each message once with `bogo-json`, only for envelope fields: the top-level `id` and `method`, and in the `initialize` response, `result.protocolVersion`. It then sends the original bytes. It never touches or rewrites `params`.
- Each request is POSTed on its own task, so a held protected call never blocks a later `notifications/cancelled` or another call. Each POST carries `Authorization`, `Bogo-Session`, and `Mcp-Session-Id` and `MCP-Protocol-Version` once they are known.
- Each JSON-RPC message in a response (the JSON body, or each SSE `data` payload) is written to stdout as one line. Diagnostics go to stderr only.
- **Session.** At start it mints `Bogo-Session` and opens `GET /mcp/bogo-liveness`, which stays open for the life of the process. BOGO ends the session the moment the shim dies, even on `kill -9`. When stdin closes, it sends DELETE and exits.
- **BOGO unreachable.** It answers each pending request with a JSON-RPC error carrying that request's `id`, and keeps trying to reopen liveness. A new liveness stream is a new session, and it never inherits old approvals.

### 3.16 Owner CLI and control (`bogo`)

```
bogo init                                  # ~/.bogo (0700), bogo.toml template, secrets.toml (0600), keys,
                                           # LaunchAgent plist; prints the MCP config and shim snippet
bogo start | stop                          # load/unload the user LaunchAgent (KeepAlive)
bogo approver add "<name>" | list | revoke <name>       # add with an existing name = re-register
bogo agent add "<name>" | list | revoke <name> | pause <name> | unpause <name>
bogo tools                                 # every discovered tool, effective policy, per-agent overrides, flags
bogo request list | cancel <id>            # the owner ending a request
bogo log [search …] | export [--format jsonl|csv] | verify
bogo serve                                 # daemon entry point that launchd runs
```

- **Pause and unpause on the Mac.** `bogo agent pause` logs `agent_paused by=owner`, then sends `ownerPause`. `bogo agent unpause` logs `agent_unpaused`, then sends `agentUnpaused` with that entry's `seq`.
- **One writer.** `~/.bogo/run/lock` (`flock`) allows a single writer. While the daemon runs, mutating commands go over the control socket, which is owner-only and checks the peer's UID. While it is stopped, the CLI takes the lock and uses the same library code.
- **Agent tokens** are `bogo_agt_` plus 32 random bytes in base64url. Each is printed once, and only its SHA-256 is stored.
- **Stop** closes admission, ends every session (each pending request ends and is logged), and then exits.
- **Startup checks.** Each fails closed and refuses to start:
  - `bogo.toml` has unknown keys or an unknown version,
  - `[defaults] policy` is `allow`; a tool runs without approval only when it is listed by name (§11),
  - `secrets.toml` is not an owner-owned regular file with mode 0600,
  - `max_pending` or `approve_arm_delay` is unset,
  - an upstream's `command` or `args` names `~/.bogo`, anything inside it, or a parent of it, so an allowed filesystem read can never reach BOGO's credentials,
  - a path secret lies outside `~/.bogo`.
- **Reported, not fatal.** A policy that names an unregistered approver, or a k larger than the number of eligible approvers, is reported in `bogo tools`. Calls to that tool are rejected with `noEligibleApprover`.

### 3.17 Reference sandbox and bypass suite

- **`sandbox/compose.yml`.** Docker's network topology alone doesn't enforce anything: `--internal` still allows talking to the gateway host ([network create](https://docs.docker.com/reference/cli/docker/network/create/#internal)). An explicit default-deny policy in the agent's own network namespace does.
  - Network `bogo-net`: `internal: true`, fixed subnet `172.30.0.0/24`.
  - **`gate`** (`alpine/socat`) sits at `172.30.0.2` on `bogo-net` and on the default bridge. It forwards only `172.30.0.2:8790 → host.docker.internal:<bogo port>` ([Docker Desktop networking](https://docs.docker.com/desktop/features/networking/)), with `cap_drop: [ALL]`. It forwards one fixed port to one fixed address, parses nothing, and offers no CONNECT or proxying. BOGO itself judges every byte.
  - **`netpol`** holds the agent's network namespace, at `172.30.0.10` on `bogo-net` only, with `cap_add: [NET_ADMIN]`. Its entrypoint loads `sandbox/policy.nft` and writes a ready marker. Then it `exec`s `setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs sleep infinity`, so no process in the namespace keeps `NET_ADMIN`. Its healthcheck passes only once the marker exists. If loading fails, it exits.
  - **The rules (`inet` family), in this order:**
    1. Input and output policy: drop.
    2. Drop everything to `127.0.0.11`, any port, before any loopback accept. Docker's embedded resolver lives at that loopback address and forwards outside lookups ([Docker DNS](https://docs.docker.com/engine/network/#dns-services)). Current Moby skips forwarding for containers attached only to internal networks (CVE-2024-29018), but the rule doesn't depend on that.
    3. Accept loopback only between `127.0.0.1` and itself.
    4. Accept TCP to `172.30.0.2:8790` and its established replies.
    5. Nothing else: no UDP or TCP port 53 anywhere, no other `bogo-net` address, no gateway, no link-local, private or public range.

    IPv6 is disabled with `net.ipv6.conf.all.disable_ipv6=1`, and the IPv6 side drops everything anyway.
  - **`agent`** has `network_mode: "service:netpol"` ([network_mode](https://docs.docker.com/reference/compose-file/services/#network_mode)) and `depends_on: netpol: condition: service_healthy`, so it never starts before the rules exist. `BOGO_URL=http://172.30.0.2:8790/mcp` uses an address, so no DNS is needed. `BOGO_AGENT_TOKEN` comes from `sandbox/.env`. It runs as a non-root user with `cap_drop: [ALL]`, `no-new-privileges` and a read-only root filesystem plus one work volume. Without `NET_ADMIN` it can't change the rules it shares.
  - No container mounts the home directory, `~/.bogo`, SSH keys, Link's auth file, the owner socket or the Docker socket.
- **`bogo-bypass`** runs inside `agent` and prints PASS or FAIL for each attempt. Every attempt must fail:
  - TCP and DNS to `api.stripe.com`, `link.com`, the relay `bogo.eilmer.si`, a public IP, IPv6, and cloud metadata addresses,
  - `host.docker.internal` on any port, the `bogo-net` gateway on any port, and `gate` on any port but 8790,
  - Docker's resolver at `127.0.0.11` answering any name, and any UDP or TCP to port 53,
  - `nft flush ruleset` (it must fail for lack of `NET_ADMIN`),
  - a scan of the filesystem and environment for credential patterns (`sk_test_`, `sk_live_`, `.p8`, `secrets.toml`, Link auth files),
  - MCP with no token or a wrong token,
  - a protected tool called without approval (cancelled after sending, so nothing is left pending),
  - a fake approval smuggled in `_meta` or the arguments,
  - the un-namespaced upstream tool name,
  - a deny-policy tool,
  - a session ID reused with another agent's token,
  - the Docker socket.

  The rules are the restriction; the suite only observes them from inside.

## 4. Data flows

**S1. Payment approved.** The tool is Link's testmode spend-request tool as `bogo tools` lists it after discovery, written `stripe__<spend tool>` here.
1. The agent POSTs `tools/call stripe__<spend tool>` with `{amount:4700, …, justification:"booking the 6pm flight you asked for, $47"}`. The front authenticates "Trip planner", `bogo-json` keeps `4700` as the text `4700`, and liveness registers.
2. `call` → core: approve, wait. The core strips the justification, encodes the request and outputs `ask`.
3. Once `request_created` is durable, the hub sends the relay envelope and the APNs alert.
4. The phone shows the banner, with Deny only. The owner taps it. The app fetches and stores the envelope, sends `seen`, and Review shows "$47.00", "Requested by Trip planner" and the reason.
5. After the arm delay, the owner taps Approve. Face ID runs, and the Secure Enclave signs the received bytes. The outbox stores the approval, then sends it.
6. BOGO's long-poll returns it. Opened, it becomes `approval` with the full `reqId`. The core checks the expiry, verifies the signature and counts it. The request settles, and the core outputs `settled` and `authorized`. The `approval` entry is durable before the relay ack.
7. Once `authorized` is durable, the shell checks that Link is connected and calls `call_tool` with the marker.
8. `ExactChildTransport` receives the message and sends `dispatch`. The core finds the call live, the session open, the agent active and the approver registered, and outputs `forward` with the stored arguments. The transport writes them byte for byte, without the justification.
9. Link's result is filtered. `forwarded` and `result` are durable. The agent gets Link's real result, which in testmode is a spend request with test credentials, not a merchant charge. The phone gets `outcome executed`.

**S2. A lie in the reason.** Same path. The phone shows $500.00 and "Reason says $5, but this will charge $500.00". The owner taps Deny with the note "wrong amount". The core outputs `reject(denied "wrong amount")`, and the agent gets "The owner denied this action. wrong amount". There is no `authorized`, so no `dispatch` and nothing sent.

**S3. Changing the call after approval.**
- `amount:4701`, `4.7e3`, or a new justification: a different request with a new nonce, and the old signature doesn't verify over its bytes.
- Another session: the session binding never matches.
- Replaying the approval: the request has been removed, or is settled, or the approver is already counted. A replay from an earlier boot names no request.
- Pending-and-retry: the settled request runs once, on the first identical retry, through the same gate. A concurrent identical retry is attached and gets the same result. A later identical call needs a new approval.

**S4. Allowed tool.** `call` → `authorized(c, none)` → the `call` entry is durable → stage → the transport's `dispatch` → `forward` → write → `forwarded` and `result` are durable → reply. There is no approver traffic.

**S5. Denied tool for Researcher.** The per-agent override is deny, so `tools/list` omits the tool. A direct call gets `reject(denyPolicy)`, which is logged, and there is no upstream contact.

**S6. No answer.**
- The client gives up: `notifications/cancelled`, a dropped stream, or a shim exit that closes liveness. That leads to `callEnded` or `sessionClosed`. The core outputs `ended` and `reject(ended)`, and the phone greys the entry. A late Approve is `ignored(unknown)`, and the phone gets `outcome ended`.
- If the client gives up while `authorized` is being written, or while the message waits in rmcp's queue, the core sees `callEnded` before `dispatch`, so nothing is written.
- With a 10-minute expiry, the timer sends `tick`, with the same result. An approval or a `dispatch` after the deadline is refused on its own `now`.

**S7. Phone offline.** The envelope waits in the relay, and the hub keeps retrying until `seen`. When the phone reconnects, it fetches, stores, and shows the request in the Inbox. The owner can still decide it while the session is alive.

**S8. Adding the phone.** As in §3.11: commitment, the six digits, Mac confirmation first, then Face ID creating and proving the key, then App Attest. The Mac commits before it answers, and a lost answer is recovered. `bogo approver list` shows the approver with its App Attest environment, category and bundle version.

**S9. Adding an agent.** `bogo agent add "Trip planner"` logs `agent_added` with the token's hash and prints the token once. Requests then carry agentName "Trip planner". A request without a valid token gets 401.

**S10. Stolen phone.** The Inbox is visible, but Approve needs the Secure Enclave key, which needs Face ID. `bogo approver revoke "Johan iPhone"` logs `approver_revoked`, then applies `approverRevoked`. Later approvals are `ignored(revoked)`. Pending requests that can no longer reach k end. A settled request that counted that approver fails the gate if the rest no longer meet k. A Deny or Pause from the thief only refuses things.

**S11. Face ID changed.** Signing fails with the key-invalidated error, or a domain-state change is seen. The Mac entry becomes `needsReRegistration`, and the tab asks the owner to add the Mac again. The new registration replaces the old approver ID, and no old votes carry over.

**S12. Two approvers (2-of-2).** The soft approver (test build) plus the iPhone, or two iPhones. The first approval is counted, and a second from the same approver counts once. The second distinct approver settles the request, and it runs through the gate, which rechecks both registrations. Any denial while pending gives `reject(denied)` under `anyDenial`. A denial after settlement is `ignored(settled)`.

**S13. Output filtering.** For the tool the owner picks (§11), say its result contains `share_url` and `filter_output=["share_url"]` is set. The field is stripped from `structuredContent` and from the JSON text copies before the agent sees them, and the log records `filtered: ["share_url"]`.

**S14. Escape attempts.** `bogo-bypass` fails at every attempt. The only route is `gate` to BOGO, and the agent token there authorizes nothing protected.

**S15. Checking the record.** `bogo log verify` checks the chain, replays the registry, re-verifies every approval with the Lean check, and confirms every protected `forwarded` met its threshold against the registry at its `registry_seq`. It prints a summary per decision type, with not-sent and unknown outcomes kept apart.

**S16. A flood.**
1. Identical requests share a `groupKey`, so their banners collapse and the Inbox shows one entry with a count.
2. At `max_pending`, new calls get `floodDropped`: logged, nobody notified, and the agent gets the flood rejection.
3. The owner taps Pause agent. `pause {agentId, epoch}` carries the epoch from that request's envelope. The core denies the agent's live requests, and every new request from it is rejected, `tools/list` included.
4. `bogo agent unpause` moves the epoch on, so a pause still in flight is refused.

**S17. Two upstreams.** Link and the filesystem server have separate rmcp clients, exact transports, namespaces, policies and restart state. A crash or wait in one never holds the other.

**Owner cancel.** `bogo request cancel <id>` sends `ownerCancel`. The request ends, the waiter gets the ended text, and the phone greys the entry.

**Phone remove.** The approval key is deleted at once, and `removed` is queued. The Mac logs `approver_revoked by=self` and acknowledges. Duplicates are acknowledged again.

**Legacy phone traffic.** Old approval jobs are skipped and expire on the Mac. Capture is always rejected. BOGO registration and notifications work on a phone never paired with the Apple Bridge gateway.

## 5. Failure

| Part | Crash / disconnect | Bad input | Recovery |
|---|---|---|---|
| **Core thread** | It is in-process, so the daemon dies with it. Every session drops, and nothing protected runs. | Any malformed `Input` bytes get `reject(malformed)` (proved). | launchd restarts it with a new bootId and an empty state. Old approvals can never match (A3). |
| **Daemon** | Every live request ends with its session. The log is durable up to the last effect. | — | Restart: set aside a torn tail (refuse on real corruption); replay the registry; log `boot`; classify open outcomes conservatively (§3.9); re-apply the relay allowlist; send `boot` and `registered` to approvers; only then admit agents. Phones `sync` and get answers from the log. Old-boot messages in mailboxes name no request, so they are logged as ignored and acked. |
| **Front** | A dropped response stream → `callEnded`. A closed shim liveness → `sessionClosed`. No idle timer. | Batches, duplicate keys, oversize bodies, bad tokens, paused or revoked agents, and a session reused by another agent are refused before the core. | Clients reconnect and list tools again. |
| **Staging and gate** | An upstream that is down at staging → `notSent`, consumed. An ending that arrives while `authorized` is written or the message is queued → seen before `dispatch`, so nothing is written. | A `tools/call` without the marker, or a second `send` for a spent marker, writes nothing (`internal_send_refused`). | Health recovery applies only to future calls. Nothing is queued for a reconnect. |
| **Upstream** | Dies before any byte → `not_sent`. Dies after the write started or before replying → `unknown`, never retried. The child is restarted with backoff. | A malformed result, or a request for interactive input, goes back to the agent as an error. An echoed known credential is removed. | Tools stay listed. |
| **Log** | Every effect and every reply waits for its entry, so no crash leaves an effect without its record. | A torn tail is moved aside and recorded. A complete bad line stops startup and is named, never dropped. | Disk full or write failure: every call is refused (fail-closed) until it is fixed. |
| **Approver hub** | Relay unreachable: delivery retries until the request ends, and the request waits. APNs failure: pushes retry. | An envelope that fails to open, or a duplicate `msgId`, is dropped. An unknown `reqId`, stale epoch or unknown approver is ignored and logged. | Long-poll reconnects with backoff. |
| **Relay** | Down: both sides retry, and messages are durable in SQLite. Restart: bearer tokens are lost, and clients authenticate again. | Bad auth → 401. A sender not on the allowlist → 403. Full mailbox → 409, and the sender retries. | systemd `Restart=always`. |
| **Phone app** | After signing: the store already holds the decision, and it is resent. After receiving: the request was stored before `seen` and before the relay ack. Killed: the APNs alert still shows, and Deny runs in the background. | A request that is undecodable, non-canonical, for the wrong `bogoId` or in an unknown version shows "Unreadable request" with Deny only. A failed envelope open is dropped. | Fetch and `sync` on launch, foreground and push wake. |
| **Secure Enclave / Face ID** | Face ID failure or cancel: nothing is sent, and the request stays pending. | An invalidated key → `needsReRegistration`. No fallback of any kind. | Register again. |
| **Registration** | Before the Mac commits, nothing is trusted. After it, a lost answer is recovered (mailbox, `regResend`, resend on boot). | A failure in the commitment, the SAS, any App Attest step, a disallowed environment or category, or proof of possession aborts. | Run `bogo approver add` again. |
| **Shim** | Stdin closes → DELETE. A crash closes liveness. Both end the session. BOGO unreachable → JSON-RPC errors to the client. | It reads only envelope fields. BOGO's exact-body layer judges every byte. | Reopens liveness, which gives a new session. |
| **Config** | — | Unknown keys or versions, bad secret permissions, `allow` as the default, unset behaviour values, or a path into `~/.bogo` → refuses to start. An unexposable tool name → that tool is not exposed. | The owner fixes the file and restarts. |
| **Clock** | Sleep: the core clock keeps counting, an expiry that passed is enforced at the next `approval` or `dispatch`, and the timer fires on wake. | A wall-clock change during a boot changes nothing. A phone clock change only moves the countdown shown. | Each boot reads the wall clock again, and every earlier request has already ended. |
| **Sandbox** | The forwarder fails: the agent loses its only route, and there is no fallback. The calls and sessions involved end. | — | Recreating the namespace runs `netpol` again before the agent starts. |

Recovering automatically means repairing durable state locally and delivering messages idempotently. It never means bringing a dead session back, or replaying a send whose outcome is uncertain.

## 6. Data and versions

**`~/.bogo/` (0700):**

```
bogo.toml               owner-edited policy
secrets.toml            0600, owner-owned regular file; refused otherwise
keys/mac_e2e.key        X25519, 0600
keys/mac_relay.key      Ed25519, 0600
upstreams/<name>/       0700, private state an upstream is pointed at (e.g. Link's auth file)
log/audit.jsonl         hash-chained log: the only durable authority
log/boots.idx           cache: bootId → offset, rebuilt from the log
state/agents.json       cache: {"v":1,"log_seq":N,"agents":[{id,name,token_sha256,revoked,paused,pause_epoch}]}
state/approvers.json    cache: {"v":1,"log_seq":N,"approvers":[{id,name,kind,alg,sig_pk,route,tx_id,attest,revoked}]}
state/tools.json        catalog with first-seen times and chosen justification keys (rediscovered at start)
state/boot              {"v":1,"boot_seq":N}, incremented and synced at each start; orders boot notices only
run/bogo.sock, run/lock
```

State files are written atomically (temp file, sync, rename) by the single writer. None of them is security state the log can't rebuild.

**`bogo.toml`** (`version = 1`, unknown fields refused everywhere):

```toml
version = 1
[server]
port = 8790
max_body = "1MiB"                    # parser limit
[relay]
url = "https://bogo.eilmer.si:<port>"
max_message_age = <owner sets>       # relay retention; never a request expiry
[apns]
key = { secret = "apns_p8" }         # secrets.toml: apns_p8 = { path = "…/AuthKey_XXXX.p8" }
key_id = "XXXXXXXXXX"; team_id = "AX3C2B78YD"; topic = "com.johansardar.applebridge.ios"
[approvers.iphone]
app_id = "AX3C2B78YD.com.johansardar.applebridge.ios"
app_attest = ["production"]          # add "development" only for development builds
approve_arm_delay = <owner sets>     # the review screen's short delay
[upstreams.stripe]
command = "link-cli"; args = ["--mcp"]
env = { LINK_AUTH_FILE = { secret = "link_auth" } }   # secrets.toml: link_auth = { path = "~/.bogo/upstreams/stripe/auth.json" }
[upstreams.files]
command = "npx"; args = ["-y", "@modelcontextprotocol/server-filesystem@<pinned>", "/Users/johansardar/bogo-test"]
# remote: url = "https://…/mcp", headers = { Authorization = { secret = "tok" } }
[defaults]
policy = "approve"; hide_denied = true   # "approve" or "deny"
max_pending = <owner sets>               # per-agent flood limit
[tools."stripe__<spend tool>"]
policy = "approve"; justification = "required"
highlight = { amount = "usd_cents", currency = "text", test = "text" }
approvers = ["Johan iPhone"]; require = "any"    # or { k = 2 }
on_deny = "any"                                  # or "when_unreachable"
expiry = "10m"; mode = "wait"                    # or "pending_retry"
filter_output = ["url"]; filter_action = "strip" # or "redact"
[agents."Researcher".tools."stripe__<spend tool>"]
policy = "deny"
# Link puts its actions behind two wrapper tools, named by the `name` argument.
# Both wait for the phone by default; searches, status reads and retrieval run at once.
[tools.stripe__call_write_tool]
policy = "approve"; justification = "required"; select = "name"
highlight = { name = "text", "arguments.amount" = "usd_cents", "arguments.currency" = "text", "arguments.test" = "text" }
expiry = "10m"; mode = "wait"
filter_output = ["number", "cvc"]                # retrieval can return card details
[tools."stripe__call_write_tool[name=ucp_catalog_search]"]
policy = "allow"
[tools."stripe__call_write_tool[name=spend-request_retrieve]"]
policy = "allow"
[tools."stripe__call_write_tool[name=auth_status]"]
policy = "allow"
# call_read_tool: the same shape (approve + select = "name", the same three allowed names)
```

- **Secrets.** A secret is either a value or `{ path = "…" }`. A path secret is handed to the child as a path, which is how Link CLI keeps and refreshes its own auth file (`LINK_AUTH_FILE` or `--auth`; [Link CLI README](https://github.com/stripe/link-cli/blob/main/README.md)). That file lives under `~/.bogo/upstreams/stripe/`, outside anything the agent can reach (§11).
- **Per-action policy.** `select` names one top-level argument; `[tools."T[arg=value]"]` gives one exact string value its own entry, starting from T's settings. The daemon hands the core the policy key `T[arg=value]` as the tool name, or T itself for any other value, a missing argument or a non-string. The core treats it as one more catalog name for the same upstream tool, so the proofs hold per key and the forward still names the real tool and the signed arguments. Strict policy belongs on T: the agent picks the value. Full rules: [configuration](configuration.md#per-action-policy-toolsupstream__toolargvalue).
- **Link testmode.** `--test` is a per-call option for creating a spend request, not a login mode. Whether a request is in testmode is therefore an argument, so the template highlights it next to `amount`. Tool and field names come from `bogo tools` after discovery. Link is for US and Canadian accounts only.

**Formats and how they change:**

| Format | Version marker | Change rule |
|---|---|---|
| Request encoding | `"BOGOREQ\0"` + u16 | A new version is a new Lean encoder with its own injectivity proof. Each phone reports the versions it supports at registration and in `pushToken`. A request uses the highest version every eligible approver supports, so k-of-n signatures always cover identical bytes. A phone shows an unknown version as unreadable, with Deny only. |
| Rust↔Lean wire and C ABI | `bogo_core_abi()` | Built together. A mismatch refuses to start. |
| E2E envelope | `"BOGOE2E\0"` + u8, HPKE info `bogo/e2e/v1` | New types are added. An unknown type is ignored after a successful open, unless its high bit marks it critical, in which case it is refused. A new suite means a new version. |
| Registration transcript | domain tags `bogo-reg-*` | A new tag per version. |
| Relay API | `/v1/` | Additive fields only. A breaking change means `/v2` beside `/v1`. |
| `bogo.toml` | `version` | An unknown version refuses to start, and `bogo` prints the migration. |
| State caches | `"v"` | Read the old version, write the new one, or rebuild from the log. |
| Audit log | per-entry `"v"` | The verifier keeps every past version. Old lines are never rewritten. |
| Phone store | SQLite `user_version` | Migrated in one transaction before use. |
| Test vectors | `vectors/manifest.json` (toolchain + `BogoCore` commit) | Regenerated by `BogoVectors`. Rust and Swift read the same files. |

## 7. Repo layout

**BOGO repo:**

```
bogo/
  lean/
    lakefile.toml  lean-toolchain
    BogoCore/    Json.lean Encoding.lean Policy.lean Core.lean Wire.lean Ffi.lean
    BogoProofs/  Spec.lean Encoding.lean Core.lean Promise.lean
    BogoVectors/ Main.lean
  vectors/                       generated, checked in
  crates/
    bogo-json/ bogo-core-sys/ (build.rs, shim.c) bogo-core/ bogo-verify/
    bogo-config/ bogo-log/ bogo-state/ bogo-filter/
    bogo-upstream/ bogo-front/
    bogo-approver/ bogo-approver-iphone/ bogo-approver-soft/ bogo-attest/
    bogo-relay-proto/ bogo-e2e/ bogo-apns/
    bogo-daemon/
  bins/
    bogo/ bogo-shim/ bogo-relay/ bogo-standin/ bogo-bypass/
  sandbox/       compose.yml policy.nft .env.example README.md
  deploy/macos/  si.eilmer.bogo.plist
  deploy/relay/  bogo-relay.service lego-renew.sh nftables-bogo.conf
  docs/          README.md configuration.md threat-model.md proved-and-assumed.md SPEC.md adr/
  Cargo.toml     workspace; rmcp pinned "=3.10.0"; serde_json arbitrary_precision (results only)
```

**apple-bridge-iphone:**

```
ios/BogoKit/   Package.swift
  Sources/BogoModel/ Sources/BogoCrypto/ Sources/BogoRelay/ Sources/BogoSection/
ios/App/, ios/Delivery/, ios/Capabilities/   edge edits only
```

**Import rules:**
- `BogoCore` imports `Init` and `Std` only. `BogoProofs` and `BogoVectors` may import `BogoCore`. Nothing imports `BogoProofs`.
- Only `bogo-core-sys` contains `unsafe` FFI or touches `lean.h`.
- `bogo-core` has no async runtime and no I/O beyond its thread and channel.
- `bogo-front`, `bogo-upstream`, `bogo-log`, `bogo-filter` and `bogo-approver*` never depend on each other. Only `bogo-daemon` wires them together.
- `bogo-upstream` reaches the core only through the `Gate` port (`dispatch`), which `bogo-daemon` provides.
- Only `bogo-upstream`'s exact transports write a `tools/call`. Only the shell's one staging function calls `call_tool`.
- Tool arguments are parsed only by `bogo-json`. Nothing reads rmcp's `CallToolRequestParams.arguments`.
- `bogo-approver-iphone` uses only the shared ID and request types that `bogo-approver` re-exports.
- `bogo-approver-soft` sits behind the `test-approvers` feature and is absent from the default build.
- `bogo-shim`, `bogo-bypass` and `bogo-relay` depend on no daemon crate. `bogo-shim` uses `bogo-json` only to read envelope fields, and never writes JSON it parsed.
- Nothing in either repo references Apple Bridge Mac code, its gateway, relay, pairing or APNs path.
- In BogoKit: BogoModel ← BogoCrypto ← BogoRelay ← BogoSection. The host imports only `BogoSection`, and BogoKit never imports host code.

## 8. Build order

The spec puts the iPhone section first, built against a stand-in, with the Mac side after.

1. **Bytes first.** `BogoCore` `Json` and `Encoding` with `decode_encode` and `encode_injective`; `BogoVectors` → `vectors/`; the envelope and message formats of §3.11. Then `bogo-json`, checked against the same vectors.
2. **`BogoKit` against `StandInMacLink`.** BogoModel, the approval key with Face ID, the BogoSection screens and the SQLite store, plus the host-app edge edits (tab, routing, Approvals removed, capture denied). Nothing here waits on a relay or a Mac.
3. **Crypto and transport pieces.** `bogo-e2e`, `bogo-relay-proto`, `bogo-apns`, `bogo-verify`, `bogo-attest`; the `bogo-relay` service on the VPS (DNS, certificate, port rule); BogoKit's `RelayMacLink` and HPKE channel.
4. **Approvers.** `bogo-approver` (trait and hub), `bogo-approver-iphone` (registration, delivery, intake), the registry parts of `bogo-log` and `bogo-state`, and BogoKit's registration flow with App Attest.
5. **`bogo-standin`.** Registers a real phone over the real relay, sends vector requests, prints verified decisions, and sends `settled`, `ended`, `boot` and `outcome` on command. The phone now runs end to end without the daemon.
6. **Decision logic and proofs.** `BogoCore` (`Policy`, `Core`, `Wire`, `Ffi`) and `BogoProofs`. These depend only on step 1, so they can proceed alongside steps 2–5.
7. **Linking.** `bogo-core-sys` and `bogo-core`: link the Lean library and run the core thread.
8. **Mac pieces.** `bogo-config`, the rest of `bogo-log`, `bogo-filter`, `bogo-upstream` with the exact transports and the gate port, and `bogo-front`. They are independent of each other.
9. **Assembly.** `bogo-daemon` and the `bogo` CLI. Then `bogo-approver-soft` in its feature build.
10. **`bogo-shim`.**
11. **Sandbox.** `sandbox/` and `bogo-bypass`. Then the Link CLI test login (the owner's device flow, with `LINK_AUTH_FILE` under `~/.bogo`) and the filesystem upstream.
12. **Docs.** README quick start, configuration reference, threat model and assumptions, and "What is proved / What is assumed", written from the theorem statements in `BogoProofs/Promise.lean`.

## 9. Libraries

| Choice | Why | Source |
|---|---|---|
| Lean 4 + Lake (`:static`), toolchain pinned in `lean-toolchain` | Required. The decision code is compiled to C and linked statically. | [lean4](https://github.com/leanprover/lean4), [FFI reference](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) |
| `cc` | Compiles BOGO's own C shim against the pinned `lean.h`. No third-party Lean binding. | [cc-rs](https://github.com/rust-lang/cc-rs) |
| `rmcp` =3.10.0 | Required SDK. Streamable HTTP server and client, HTTP `Parts` in handler extensions, a custom `Transport` and `StreamableHttpClient`, `reinit_on_expired_session` configurable. Pinned exactly because the gate depends on its internals. | [rust-sdk](https://github.com/modelcontextprotocol/rust-sdk), [service.rs](https://docs.rs/rmcp/3.10.0/src/rmcp/service.rs.html), [streamable_http_client.rs](https://docs.rs/rmcp/3.10.0/src/rmcp/transport/streamable_http_client.rs.html) |
| `bogo-json` (BOGO's own) | Exact number text, duplicate-key rejection, an exact writer; small enough to check against Lean vectors. | [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) |
| `serde_json` + `arbitrary_precision` | MCP framing, results and config views; never tool arguments. | [serde_json](https://github.com/serde-rs/json) |
| `tokio`, `axum`, `tower`, `reqwest` (rustls, http2) | Runtime, HTTP layers, relay client and server, APNs HTTP/2. | [tokio](https://github.com/tokio-rs/tokio), [axum](https://github.com/tokio-rs/axum), [reqwest](https://github.com/seanmonstar/reqwest) |
| `hpke` | RFC 9180 auth mode; interoperates with CryptoKit HPKE. | [rust-hpke](https://github.com/rozbb/rust-hpke), [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) |
| `p256`, `p384`, `sha2`, `hkdf` | Approval verification, the App Attest chain (Apple's root is P-384), hashing and KDF. | [elliptic-curves](https://github.com/RustCrypto/elliptic-curves), [hashes](https://github.com/RustCrypto/hashes), [KDFs](https://github.com/RustCrypto/KDFs) |
| `ed25519-dalek` | Relay mailbox auth, and the soft test approver. | [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) |
| `ciborium`, `x509-cert`, `der` | App Attest's CBOR and certificates, parsed by BOGO's own named steps with no system trust store. | [ciborium](https://github.com/enarx/ciborium), [RustCrypto formats](https://github.com/RustCrypto/formats), [Apple's procedure](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server) |
| `jsonwebtoken` | APNs ES256 provider tokens. | [jsonwebtoken](https://github.com/Keats/jsonwebtoken) |
| `rusqlite` (bundled) | The relay's durable mailboxes. | [rusqlite](https://github.com/rusqlite/rusqlite) |
| `rustls`, `lego` | Relay TLS; Let's Encrypt DNS-01 through a scoped Cloudflare token. | [rustls](https://github.com/rustls/rustls), [lego Cloudflare](https://go-acme.github.io/lego/dns/cloudflare/) |
| `toml` + `serde`, `clap`, `fs4`, `tracing` | Config with unknown fields refused, the CLI, the writer lock, diagnostics (never the audit record). | [toml](https://github.com/toml-rs/toml), [clap](https://github.com/clap-rs/clap), [fs4](https://github.com/al8n/fs4), [tracing](https://github.com/tokio-rs/tracing) |
| CryptoKit, Security, LocalAuthentication, DeviceCheck, UserNotifications, SwiftUI, URLSession, system SQLite | Native phone code with no third-party dependencies. | [SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave), [HPKE](https://developer.apple.com/documentation/cryptokit/hpke), [DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice), [UserNotifications](https://developer.apple.com/documentation/usernotifications), [SQLite C](https://www.sqlite.org/cintro.html) |
| Docker Compose, `alpine/socat`, nftables | Reference sandbox: internal network, a fixed single-port forwarder, default-deny rules in a namespace the agent shares but can't change. | [Docker networking](https://docs.docker.com/engine/network/), [network_mode](https://docs.docker.com/reference/compose-file/services/#network_mode), [nftables](https://wiki.nftables.org/) |
| `link-cli --mcp`, `@modelcontextprotocol/server-filesystem` | The upstreams the spec uses, run unmodified at pinned versions. | [link-cli](https://github.com/stripe/link-cli), [filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) |

Crate versions other than rmcp are pinned in `Cargo.lock` when work starts. None of these libraries is covered by the Lean proof; each sits under A6 or A7.

## 10. Risks and open questions

| Risk | Why it matters | How to find out |
|---|---|---|
| **rmcp internals under the gate** | The gate relies on rmcp passing `_meta` through to BOGO's `Transport` and `StreamableHttpClient`, on `reinit_on_expired_session` being off, and on BOGO's serializer producing JSON-RPC that rmcp still correlates. | Send a vector containing `4.7E3` and `-0` to a stub upstream that echoes its raw input, and compare bytes. Re-read `service.rs`, `streamable_http_client.rs` and `tower.rs` on every rmcp bump. |
| **Gate ordering** | Freshness at dispatch holds only if every security input reaches the core channel before the transport's `dispatch`, and nothing that can wait follows a `forward`. | Read the transport's send: one `dispatch` await, then the write's first call, with no other await between them. |
| **Disconnect detection** | The liveness layer depends on hyper dropping the response body when the client leaves, and on `sse_retry: None` suppressing priming events. | Kill a client during a held call and look for `callEnded` in the log. Inspect the first SSE bytes for an event ID. |
| **MCP 2026-07-28 is stateless** | Stateless direct clients get call-scoped sessions, so pending-and-retry isn't available to them. | Check which protocol Claude Code, Cursor and Claude Desktop negotiate. Watch rmcp's session mode across releases. |
| **Silently abandoned direct sessions** | Pending-and-retry requests from a vanished direct client stay pending (never runnable) until owner action, revocation or restart. | Owner decision (§11). The shim has no such gap. |
| **Schema widening edge cases** | A strict validating client refuses the field on `strict-client-risk` tools. | Look at the Link and filesystem schemas after discovery. |
| **Lean static link on macOS** | `lean.h` is unstable, and the link line can change between toolchains. | Pin the toolchain; the ABI check runs at start. Rebuild the shim on every bump. |
| **Proof boundary (A6)** | The shell could forward something other than a `forward` output. | Keep `call_tool` in one place and `tools/call` writes in the exact transports only; both rules can be checked with grep. |
| **App Attest details** | A wrong build, or a misread field, could register. | Feed real attestations from a development build and a TestFlight build through `bogo-attest`, one named step at a time. Confirm the App ID prefix against the provisioning profile. |
| **Docker Desktop specifics** | The gate depends on `host.docker.internal` reaching the host's loopback, and `netpol` depends on nftables in Docker Desktop's VM kernel. | Load `policy.nft` and list the ruleset from inside. Run `bogo-bypass` and a real agent call. |
| **iOS background limits** | A force-quit app gets no background wake, and banner Deny timing is up to iOS. | Try Deny from a locked phone with the app force-quit. The outbox makes a late send safe. |
| **Link CLI behaviour** | It may ask for interactive input (refused), and some flows have no testmode. | List its tools, log in once with `LINK_AUTH_FILE` under `~/.bogo`, and run a testmode spend request through BOGO. |
| **Outcome classification** | A crash right after `authorized` shows as "unknown" even if nothing was sent. That is honest, but imprecise. | Inspect History after a forced daemon kill. |
| **Log anchor** | Someone with file access could replace the whole chain. Mac compromise is out of scope. | State this in the threat model; owner exports can anchor a comparison. |
| **Global relay lobby** | Junk offers could clutter Add Mac. Numeric comparison keeps it secure. | Watch the lobby. Each offer shows a label and age. |

## 11. Questions for the user

1. **The agent's model in the sandbox.** The container may reach only BOGO, but a harness like Claude Code needs its model API. Should the namespace also allow one named model host (through a second fixed forwarder), or does the model run outside the container?
2. **Stateless 2026-07-28 clients.** Pending-and-retry tools need a session-capable connection or the stdio shim, and they are rejected for stateless direct clients. Is that acceptable?
3. **Silently abandoned direct sessions.** No idle timer ends a session, because that would be a preset expiry the spec doesn't have. A direct client that vanishes without DELETE leaves its pending-and-retry requests pending, though never runnable. Is that acceptable, or do you want an idle end with a value you choose?
4. **Owner cancel.** The spec lets the owner cancel a request but drafts no command. Is `bogo request list | cancel <id>` right?
5. **Values the spec leaves open.** These are behaviour values, not performance goals. Each ships unset, and BOGO won't start until it is set: the Approve arm delay, the per-agent `max_pending`, and the relay's maximum message age and mailbox size.
6. **Relay port.** Which port on the VPS is free for BOGO's relay?
7. **Banner text.** The push says only "BOGO: Approval requested". Showing the agent or tool would need an encrypted payload and a Notification Service Extension. Is the generic banner fine?
8. **Resources, prompts and interactive input.** These aren't passed through, so they can't route around the gate. An upstream that asks for interactive input gets an error. Is that fine, since the spec speaks only of tools?
9. **Scenario 13.** The official filesystem server has no tool that returns a public sharing link. Which tool should show output filtering: Link's credential-returning tool, or a small test upstream?
10. **A lost result in pending-and-retry.** After a request runs, it is removed. If the agent never got the result and retries, that is a new request needing a new approval. It never runs twice on one approval. Is that intended?
11. **Default policy.** SPEC §3.4 says unlisted tools get the default, and also that new tools default to approve. Principle 5 says a forgotten tool should never be open. BOGO therefore accepts only `approve` or `deny` as the default, and refuses `allow`. Is that right, or do you want a default of `allow` with newly discovered tools still held at approve until listed?
12. **Strict-client schemas.** A few schema shapes can't be widened simply, so those tools are exposed with the field at the top level and flagged. Is that acceptable, or should they take the justification another way (for example in `_meta`), which would change the interface the spec describes?
13. **Outcome unknown.** After BOGO hands a call to an upstream and then loses the connection, nobody can know whether it acted. BOGO says "the action may or may not have happened", never retries, and the log and phone say "unknown". A crash right after authorizing is reported the same way. Is that wording right? "Silence means nothing happened" holds for everything BOGO didn't send.
14. **Link credentials.** Link CLI keeps and refreshes its own auth file. Is a file under `~/.bogo/upstreams/stripe/` (0600), named by path from `secrets.toml`, acceptable instead of the token itself living in `secrets.toml`?
15. **Accepted App Attest builds.** The current app is development-signed. Registration accepts production (TestFlight, App Store) attestations by default. Should development attestations be accepted too, or will the BOGO-capable build ship through TestFlight?
16. **Allowed-call overhead.** Every allowed call waits for one durable log write before it goes upstream, so a crash can never lose the record of a call that ran. If the PRD's "negligible overhead on allowed calls" becomes a goal, that record could instead be written alongside the call, at the cost of possibly losing an allowed call's record in a crash. Which do you prefer?
17. **Carried over from SPEC §9:** whether the PRD's speed and setup goals apply (allowed-call overhead, notification latency, setup time); whether a second real device exists for 2-of-2 (until then the soft approver shows it); and which Link tools are protected (all of them, or only those that create spend requests or credentials).
