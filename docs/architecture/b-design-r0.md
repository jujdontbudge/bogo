# BOGO: Architecture

Status: 2026-11-14. Built from SPEC.md.

## 0. The shape

BOGO is one Rust daemon on the owner's Mac. Agents see it as a single MCP server over Streamable HTTP (`rmcp`). Stdio-only clients reach it through a small shim. Every tool call, allowed or protected, goes through one pure decision function. That function is written in Lean 4 and compiled to C, and the daemon links the exact compiled code the proofs are about. It runs on one dedicated thread and takes bytes in and gives bytes out. Policy resolution, the stripping of the justification field, request encoding, single-use, session binding, k-of-n counting, revocation, pause and the flood limit all live inside it. Signature checks also run inside it, through one `extern` hook into Rust, which is the stated cryptographic assumption. Everything else is a thin effects shell around that core: the MCP front, the upstream manager, the hash-chained audit log, output filtering, the approver hub and the owner CLI. The shell only carries out what the core outputs. It forwards exactly the arguments the core emits, and only when the core says `forward`. Approvers are plug-in routes behind one trait. The first route is the iPhone section, a separate Swift package (`BogoKit`) inside apple-bridge-iphone. It holds a Face ID–bound Secure Enclave P-256 key (`.biometryCurrentSet`), proven at registration with App Attest. It talks to BOGO only through HPKE-auth-sealed messages that pass through BOGO's own store-and-forward relay at `bogo.eilmer.si`, and it is woken by APNs pushes that the Mac sends itself. Pending requests live only in memory and die with their session, so a crash or restart ends every request, which fails closed. The audit log is written ahead of every effect, so a crash loses no record. Every link that can drop is retried idempotently: relay mailboxes, the phone's outbox and BOGO's delivery loop.

## 1. Runtime picture

```
 Docker (reference sandbox)                      owner's Mac
┌───────────────────────────┐          ┌───────────────────────────────────────────────────────────┐
│ agent harness             │          │ bogo daemon (launchd user agent, KeepAlive)               │
│  └ MCP client ──HTTP──────┼─► gate ──┼─► 127.0.0.1:<port>/mcp                                  │
│    (or stdio → bogo-shim) │ (socat,  │   ┌──────────────┐ Input bytes  ┌──────────────────────┐  │
│ network: internal only    │  only    │   │ front (rmcp  │─────────────►│ core thread          │  │
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
                                                     │                              └ BogoUI    │
                                                     └──────────────────────────────────────────┘
```

How the parts talk:
- Agent to BOGO: MCP Streamable HTTP with `Authorization: Bearer <agent token>`. The stdio shim speaks stdio to the client and Streamable HTTP to BOGO.
- Front to core: an in-process channel to the core thread. Each step passes one encoded `Input` and gets back the encoded `Output`s.
- Daemon to upstreams: `rmcp` clients over a child process's stdio (local) or Streamable HTTP (remote).
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
| `bogo-core` | Rust | Safe `Core` handle, the dedicated core thread, typed `Input`/`Output`, the Rust wire encoder/decoder | `bogo-core-sys`, `serde_json` | rmcp, I/O, approver routes |
| `bogo-verify` | Rust | `bogo_verify` export that the Lean `extern` calls: dispatch by algorithm tag (P-256 ECDSA; soft Ed25519 only with the `test-approvers` feature) | `p256`, `ed25519-dalek` (feature-gated) | Anything else |
| `bogo-config` | Rust | Parsing and validating `bogo.toml` and `secrets.toml` into typed values; the `Secret` type (no `Serialize`, no `Debug` contents) | `toml`, `serde` | core, rmcp, network |
| `bogo-state` | Rust | The `~/.bogo` layout and permissions, the single-writer `flock`, atomic JSON files (agents, approvers, tool catalog, boot counter), BOGO's own keys | `bogo-config`, `fs4` | core, rmcp, network |
| `bogo-log` | Rust | The append-only hash-chained audit log: group-commit writer, reader, search, export, `verify` | `sha2`, `serde_json`, `bogo-core` (decode and verify through Lean) | front, upstreams, approver routes |
| `bogo-filter` | Rust | Output filtering (strip or redact field paths in tool results) | `serde_json` | Everything else |
| `bogo-upstream` | Rust | Upstream connections, the namespaced tool catalog, the justification field in schemas, exact-argument forwarding, restart and backoff | `rmcp` (client), `bogo-config` | core, front, log, approvers |
| `bogo-front` | Rust | MCP server: agent-token auth, body guard, call liveness, BOGO sessions, the per-agent `tools/list`, mapping tool calls to core `Input`s and outcomes to model-readable results | `rmcp` (server), `axum`, `bogo-core` types | upstream internals, approver routes, log internals |
| `bogo-approver` | Rust | The `ApproverRoute` trait, the approver hub (fan-out, delivery retry, inbound decisions), the registration driver | `bogo-core` types | rmcp, the front, the upstreams |
| `bogo-relay-proto` | Rust | Relay wire types, mailbox auth, the async relay client (long-poll, send, ack, retract, lobby) | `reqwest`, `ed25519-dalek` | Any daemon crate |
| `bogo-e2e` | Rust | Envelope format, HPKE auth mode seal and open, per-direction counters | `hpke` | Network |
| `bogo-apns` | Rust | APNs token-auth HTTP/2 client (ES256 JWT, alert pushes, collapse IDs) | `reqwest`, `jsonwebtoken` | Everything else |
| `bogo-approver-iphone` | Rust | iPhone route: SAS registration, App Attest check, request delivery, decision intake, ended notices, push | `bogo-approver`, `bogo-relay-proto`, `bogo-e2e`, `bogo-apns`, `appattest`, `p256` | core internals, front, upstreams, anything from Apple Bridge |
| `bogo-approver-soft` | Rust | Software approver for automated 2-of-2 checks; compiled only with `--features test-approvers` | `bogo-approver`, `ed25519-dalek` | Being present in a release build |
| `bogo-daemon` | Rust | Wiring: the effects shell (output → log → effect), the control socket, startup and shutdown | all daemon crates above | Apple Bridge anything |
| `bogo` (bin) | Rust | The CLI and `bogo serve` (the daemon entry point launchd runs) | `bogo-daemon`, `clap` | n/a |
| `bogo-shim` (bin) | Rust | stdio ↔ Streamable HTTP pass-through, one BOGO session per shim process | `rmcp` (server + client) | Every BOGO internal crate |
| `bogo-relay` (bin) | Rust | The relay service: mailboxes, allowlists, lobby, SQLite storage, TLS | `bogo-relay-proto`, `axum`, `rusqlite`, `rustls` | Every daemon crate, the Apple Bridge relay |
| `bogo-standin` (bin) | Rust | Stand-in for BOGO while the phone is built: real registration, real relay, real push; sends requests from Lean vectors and prints verified decisions | `bogo-approver-iphone`, `bogo-state`, `bogo-verify` | front, upstreams, core thread |
| `bogo-bypass` (bin) | Rust (Linux target) | The bypass test suite that runs inside the sandbox container | `rmcp` (client), `reqwest` | Every BOGO internal crate |
| `sandbox/` | Docker Compose | The reference setup: internal network, `gate` forwarder, agent service | Docker | Host home directory mounts |
| `BogoKit/BogoModel` | Swift | Request decoding (canonical checks), the render model, mismatch rule, duplicate grouping, inbox state machine | Foundation | UIKit, SwiftUI, Security, host app code |
| `BogoKit/BogoCrypto` | Swift | Secure Enclave approval key, HPKE auth, relay auth key, App Attest, Keychain items under BOGO's own service names | CryptoKit, Security, LocalAuthentication, DeviceCheck | Host app code, BogoUI |
| `BogoKit/BogoRelay` | Swift | Relay client, persistent outbox, message pump | BogoModel, BogoCrypto, Foundation | Host app code |
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

structure Request where                                    -- exactly what is signed
  bogoId : ByteArray; upstream : String; tool : String; args : JVal
  justification : Option String; hints : List (List String × Format)
  agentId : AgentId; agentName : String; clientName : Option String
  session : SessionId; nonce : ByteArray                   -- nonce = bootId ‖ seq
  createdMs : Nat; expiresMs : Option Nat

inductive Input
  | configure (cfg : PolicyConfig) (catalog : List CatalogEntry)
  | approverSet (a : Approver)            | approverRevoked (id : ApproverId)
  | agentSet (a : Agent)                  | agentRevoked (id : AgentId)
  | agentUnpaused (id : AgentId)
  | sessionOpened (s : SessionId) (agent : AgentId) (client : Option String)
  | sessionClosed (s : SessionId)
  | call (s : SessionId) (c : CallId) (name : String) (args : JVal) (nowMs : Nat)
  | callEnded (c : CallId)                                 -- cancel, disconnect, client gave up
  | approval (a : ApproverId) (r : ReqId) (alg : UInt16) (proof : ByteArray) (nowMs : Nat)
  | denial (a : ApproverId) (r : ReqId) (note : Option String)
  | pauseAgent (a : ApproverId) (agent : AgentId)
  | ownerCancel (r : ReqId)
  | tick (nowMs : Nat)

inductive Output
  | forward (c : CallId) (upstream tool : String) (args : JVal)   -- justification already removed
  | reject (c : CallId) (why : Rejection)                  -- denied note, ended, deny policy, paused, flood, malformed, …
  | pendingApproval (c : CallId)
  | ask (r : ReqId) (bytes : ByteArray) (to : List ApproverId) (group : ByteArray)
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

**Decision rules the core keeps:**
- **Resolve policy.** The effective policy is the per-agent override, else the tool's entry, else the default. A tool that is in the catalog but not listed in the config gets the default. The shipped default is `approve`. A name that is not in the catalog is rejected as an unknown tool. Paused agents and revoked agents are rejected for every call.
- **allow** produces `forward` with the arguments unchanged. **deny** produces `reject(denyPolicy)`.
- **approve** goes through these checks in order:
  1. The value at the tool's justification key, if present, must be a string. Otherwise the call is rejected as malformed.
  2. If a justification is required and missing, the call is rejected with a message telling the agent to include one.
  3. The core removes the justification key from the arguments.
  4. If the agent's pending count is at or over `maxPending`, the call produces `floodDropped` and nothing goes to approvers.
  5. The core builds a `Request`, encodes it, stores it as `pending`, and outputs `ask` to the eligible approvers that are registered and active. If there are none, the call is rejected with `noEligibleApprover`.
- **Wait mode.** The call is held. `forward` happens in the same step that meets the requirement.
- **Pending-and-retry mode.** If no identical request exists, the core creates one and returns `pendingApproval`. A retry is identical when it has the same session, tool, arguments and justification. A retry of a pending request returns `pendingApproval` again. A retry of an approved request produces `forward`, consumes the request, and removes it.
- **Approval.** The approval is accepted only if all of these hold:
  - the request is still `pending` or `approved` (approved only matters in pending-and-retry mode),
  - the approver is registered and active,
  - the approver is eligible for this agent and tool,
  - `verify alg pk ("BOGO-APPROVAL\x00v1" ++ bytes) proof` is true.

  Accepted approvals form a set, so the same approver counts once. When the approval is counted, the core recounts using only approvers that are still active and eligible. Revocation removes earlier counts.
- **Denial.** Under `anyDenial`, one denial ends the request and the call gets `reject(denied note)`. Under `whenUnreachable`, a denial ends the request only when k can no longer be reached.
- **Ending.** These all produce `ended` (to the approvers) and `reject(endedWithoutDecision)` (to a waiting call):
  - `callEnded`,
  - `sessionClosed`,
  - `ownerCancel`,
  - agent revocation,
  - approver revocation that makes k unreachable,
  - `tick` past `expiresMs`.

  The request is then removed. A late approval finds no request and is `ignored(ended)`.
- **Pause.** `pauseAgent` denies all of that agent's pending requests, marks the agent paused and outputs `agentPaused`. Only `agentUnpaused`, which comes from the Mac CLI, clears the pause.
- **Request IDs.** `ReqId` is the core's own `seq`, which only grows. A request that has been consumed or ended is removed, and its `seq` is never reissued. No "seen" set is needed.
- **Grouping key.** `group` is the hash of (agent, upstream, tool, args, justification). The phone groups duplicates by this key and BOGO derives the APNs collapse ID from it.

**Rules it always keeps:**
- It is total and deterministic, with no `partial` definitions and no `panic!`. The proofs require this.
- The only `forward` sources are an allow decision, or a request whose requirement was met in this step (wait mode) or earlier (pending-and-retry).
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
- **Numbers.** `4700`, `4700.0` and `4.7e3` are three different `num` texts, and the encoding never reads them as numbers. Rust gets the exact text because `serde_json` is built with `arbitrary_precision`. rmcp 3.10 supports and tests that feature (`tests/test_deserialization.rs`, module `arbitrary_precision`). Strings are Unicode scalar sequences after JSON unescaping. `serde_json` refuses lone surrogates, so they never reach the core.
- **Who encodes what.** The signed bytes are produced only by the Lean encoder inside the core. Swift only decodes, renders and signs the exact received bytes. Rust has an encoder only for the Rust→Lean wire format, which shares the `value` grammar, and a decoder for `Output`. Rust and Swift are both checked against `vectors/` generated by `BogoVectors`.
- **Signed message.** The approval signature covers `"BOGO-APPROVAL\x00v1" ‖ requestBytes`. The domain tag means a request signature can never be mistaken for any other signed object.

### 3.3 Proof (`BogoProofs`)

**Model.** The adversary is any `List Input`. The agent controls every `call`, `callEnded`, `sessionOpened` and `sessionClosed`, and can send malformed bytes through `stepFfi`. The relay and the network control the order and duplication of every `approval`, `denial` and `pauseAgent`, and can inject arbitrary ones. The theorems hold for all such lists, run from `initFfi`.

**Assumptions, each listed in "What is proved / What is assumed":**
- **A1 Unforgeable approvals.** For every algorithm tag in use, `verify alg (pk a) m p = true` implies `OwnerApproved a m`. This is stated as a hypothesis on the trace, not as a global `axiom`, so it cannot make the logic inconsistent. It covers spec assumptions 1 and 3: the signature can't be forged, and the key is usable only after user verification.
- **A2 Hash collision resistance.** This is used inside ECDSA-SHA-256 and for the log chain. The core's matching uses full byte equality, not hashes.
- **A3 Distinct boots.** `bootId` is 32 random bytes, so two boots never share one. Approvals from an earlier boot can therefore never match a request of a later boot.
- **A4, A5.** These are spec assumptions 4 and 5 (the sandbox, and upstreams rejecting unauthenticated requests). They are listed, but nothing in Lean uses them.
- **A6 Faithful shell.** The Rust shell sends upstream exactly the `forward` outputs and nothing else. This is kept small and explicit (§3.5), and it is the one link the proof cannot see.

**Theorems** (where `forward c u t args` appears in the outputs of step i of `run init inputs`):
1. **Approved.** Either the effective policy at step i was `allow`, or there is a request `r` with `r.upstream = u`, `r.tool = t`, `r.args = args`, and a set `S` of distinct approver IDs. Every `a ∈ S` was registered, active and eligible for `(r.agentId, tool)` at step i, and `OwnerApproved a (sigMsg (encode r))` holds. `|S| ≥ 1` for any-of and `|S| ≥ k` for k-of-n.
2. **Exact.** By (1) and `encode_injective`, the owner approved exactly `r`: its upstream, tool, arguments, justification, agent, session, nonce and times.
3. **Single-use.** For every request, at most one `forward` is emitted over the whole trace.
4. **Fresh.** At step i, `r.session` is open, the call `c` belongs to `r.session` and is still live, and if `r.expiresMs = some e` then `now < e`.
5. **Session binding.** `c`'s session equals `r.session`. A call from another session never matches.
6. **Fail-closed.** No `forward` is ever emitted for a call that is:
   - under a `deny` policy,
   - from a paused, revoked or unknown agent,
   - for an unknown tool,
   - from a closed session,
   - from a malformed input (any bytes that `decode` rejects),
   - for a request that has ended.
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

This is the only consumer of core outputs. Each output is handled as: write the log entry durably, then do the effect.

| Output | Effect (after the log entry is durable) |
|---|---|
| `forward c u t args` | Send the exact `args` to upstream `u`'s tool `t` through `bogo-upstream`, apply `bogo-filter`, resolve waiter `c`. Never retried. |
| `reject c why` | Resolve waiter `c` with the model-readable text (§3.6). |
| `pendingApproval c` | Resolve `c` with the pending text. |
| `ask r bytes to group` | Hub delivers to each approver in `to`. Delivery retries until `ended`. |
| `ended r why to` | Hub sends ended notices and retracts undelivered messages. |
| `agentPaused a` | Persist `paused=true` in `agents.json`. |
| `counted` / `ignored` / `floodDropped` | Log only. Flood drops never notify anyone. |

- **Waiters.** Waiters are keyed by `CallId`, a 128-bit value Rust mints per call and passes in the `call` input. The shell never builds upstream arguments itself. The `forward` output is the only source.
- **Time.** `tick` comes from one timer that wakes at the earliest `expiresMs` among pending requests. The core reports that value in a `nextDeadline` field of every step's result. There is no polling.

### 3.6 MCP front (`bogo-front`)

- **Server.** `rmcp` `StreamableHttpService` bound to `127.0.0.1:<port>`. It uses rmcp's loopback `allowed_hosts` and enforces Origin validation.
  - **Legacy session mode on.** Protocol 2025-11-25 and earlier gives real `Mcp-Session-Id` sessions.
  - **2026-07-28.** Requests that negotiate 2026-07-28 are stateless under that spec ([MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)), and rmcp serves them that way.
- **Layers, outermost first:**
  1. **Agent auth.** The bearer token is hashed with SHA-256 and looked up among non-revoked agents. Without a match the request gets 401 and never reaches rmcp. The `AgentId` goes into the request extensions. rmcp copies `http::request::Parts` into the handler's `RequestContext.extensions`.
  2. **Body guard.** It reads the POST body once and rejects these with 400:
     - JSON-RPC batches,
     - bodies with duplicate object keys at any depth (a serde visitor that checks keys without building a map),
     - bodies over the configured size.

     This makes "ambiguous → reject" true before rmcp parses anything.
  3. **Call liveness.** For a `tools/call`, it registers a `Liveness` token keyed by the JSON-RPC id and session, and wraps the response body in a drop guard. If the body is dropped before the final message (the client disconnected), the token fires `callEnded`. rmcp's handler `ct`, which fires on `notifications/cancelled` and on rmcp's own stateless-disconnect handling (rust-sdk #857), fires `callEnded` too. For protected wait-mode calls, BOGO sends no intermediate messages, so the first message is the final one.
- **BOGO sessions** (the core's `SessionId` is `bootId ‖ random 16 bytes`):
  - **Legacy protocol.** One BOGO session per `Mcp-Session-Id`, bound to the agent of its first request. A later request on that session with a different agent token is rejected, and the session is closed. The client's self-reported name comes from `initialize.clientInfo`. The session ends on HTTP DELETE, agent revocation, daemon stop, or idle: no open request stream and no request for `session_idle`. rmcp's own `keep_alive` is disabled, and BOGO closes idle sessions through the session manager. That way a long wait for the owner never times a session out.
  - **2026-07-28 stateless.** Each `tools/call` is its own session, opened and closed around the call. The client name comes from `_meta` `io.modelcontextprotocol/clientInfo`. Wait mode works unchanged. A pending-and-retry tool has no session to retry in, so it is rejected with the text "This tool needs a session-based MCP connection (protocol 2025-11-25) or the BOGO stdio shim." That is fail-closed.
- **`tools/list`.** The combined catalog for this agent. Deny tools are hidden when `hide_denied`. Approve tools get the justification property. Order is deterministic: by upstream, then by tool. `cacheScope: "private"`. When an upstream sends `list_changed`, legacy sessions are notified.
- **`tools/call`.** The handler sends `call(session, callId, name, args, now)` to the core and awaits its waiter. It then maps the outcome:
  - forwarded → the upstream's real `CallToolResult` after filtering,
  - denied → `isError: true`, text `"The owner denied this action."` plus `" " + note` if there is a note,
  - ended → `isError: true`, `"Approval was not received in time; the action was not performed."`,
  - pending → `isError: true`, `"Pending owner approval. Retry this exact call (same arguments and justification) in this session to run it once approved."`,
  - other rejections → `isError: true` with the reason (deny policy, paused, flood, missing justification, unknown tool).
- **Not proxied.** Upstream resources, prompts, completions, sampling, elicitation and roots are not exposed. Exposing them would open paths around the gate. BOGO advertises only the `tools` capability.

### 3.7 Upstream manager (`bogo-upstream`)

- **One shared connection per upstream.**
  - Local upstreams: `TokioChildProcess` with `command`, `args` and an environment built from `secrets.toml` references. Credentials exist only in that child's environment.
  - Remote upstreams: `StreamableHttpClientTransport` with headers from secrets.
- **Naming.** Upstream names match `[a-z0-9-]+`, with no `__`, so splitting `<upstream>__<tool>` at the first `__` is unambiguous. A namespaced name over MCP's 128-character limit, or with characters outside `[A-Za-z0-9_.-]`, is not exposed. It is reported in `bogo tools` as `unexposable`.
- **Justification field.** For approve tools the property is named `justification`. If the upstream schema already has a top-level `justification`, it is named `bogo_justification`. The chosen key is recorded per tool in the catalog, so the core strips exactly that key. It is added to `required` when the policy requires it.
- **Catalog.** Catalog changes are persisted to `state/tools.json` with first-seen times, so `bogo tools` works while BOGO is stopped. A new catalog goes to the core as a `configure` input. New tools get the default policy (`approve`).
- **Forwarding.** `call_tool` with arguments converted from the `forward` `JVal`. Numbers become `serde_json::Number` from their exact text, which is lossless under `arbitrary_precision`. A tool call is never retried after it has been sent. An upstream that crashes mid-call gives the agent `isError: true` "upstream failed; the action may or may not have happened", and the log records outcome unknown.
- **Upstream health.** A child process that exits is restarted with exponential backoff. While an upstream is down, its tools are kept in the catalog, and calls to them get "upstream unavailable" after the core decided `forward`. They are never queued, and the log shows `forwarded` → `upstream_unavailable`.
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
   "kind":"request_created","agent":{"id":"…","name":"Trip planner"},"session":"…","tool":"stripe__create_payment_link",
   "req":1042,"request_b64":"…","justification":"booking the 6pm flight…","policy":"approve"}
  ```

- **Entry kinds.**
  - Lifecycle: `boot` (boot_seq, bootId, bogo.toml SHA-256), `tail_recovered`.
  - Agents: `agent_added`, `agent_revoked`, `agent_paused`, `agent_unpaused`.
  - Approvers: `approver_registered`, which stores the public keys, algorithm, App Attest key ID and environment, and the attestation SHA-256. Also `approver_revoked`.
  - Calls: `call` (every attempt, any policy), `rejected` (with reason), `request_created`, `approval` (approver ID, algorithm, proof, `counted` or `ignored`+why), `denial` (+note), `request_ended` (+why), `forwarded`, `result` (`ok`, `is_error`, `upstream_failed` or `unknown`, filtered fields). Result content is not logged.
- **Credentials never appear.** `Secret` values have no `Serialize`, and the log writer only accepts `LogEvent` values, which can't hold one.
- **Writer.** One task with group commit. Every entry that is waiting is written, then one `sync_data` runs (F_FULLFSYNC on macOS), then all those waiters are released. Effects wait for their entry. A crash therefore never leaves an effect without its record.
- **Recovery.** At startup, a last line without a trailing newline, or one that isn't valid JSON, is moved to `audit.torn.<ts>`, and a `tail_recovered` entry carrying its hash is appended. `verify` reports this as a recovery, not as tampering. A `forwarded` entry that has no `result` before the next `boot` is reported as "outcome unknown (BOGO stopped)".
- **`bogo log verify`.**
  1. Recompute the chain.
  2. Replay `approver_registered`/`approver_revoked` in order to know who was registered at each point.
  3. For every `approval` entry, check `bogo_core_check_approval` (the same Lean code) against the key registered at that moment, over the logged request bytes.
  4. Check that every `forwarded` protected request has enough counted approvals.

  It reports the first break with its line number.
- **`bogo log [search]`** prints a filtered, decoded view (filters: agent, tool, decision, time range, text). Request bytes are decoded by the Lean decoder export. **`bogo log export`** writes JSON Lines or CSV.

### 3.10 Approver hub and route interface (`bogo-approver`)

```rust
#[async_trait]
pub trait ApproverRoute: Send + Sync + 'static {
    fn kind(&self) -> &'static str;                                   // "iphone", "soft"
    async fn register(&self, name: &str, owner: &dyn OwnerPrompt) -> Result<NewApprover, RegError>;
    async fn deliver(&self, a: &ApproverRecord, r: &Outbound) -> Result<(), DeliveryError>; // idempotent per (a, r.id)
    async fn ended(&self, a: &ApproverRecord, r: ReqId, why: EndReason) -> Result<(), DeliveryError>;
    async fn boot(&self, a: &ApproverRecord, boot: &BootNotice) -> Result<(), DeliveryError>;
    fn inbound(&self) -> BoxStream<'static, Inbound>;                 // already channel-authenticated
}
pub struct NewApprover { pub alg: u16, pub sig_pk: Vec<u8>, pub route_data: serde_json::Value }
pub enum Inbound { Approval { approver: ApproverId, req: ReqId, alg: u16, proof: Vec<u8> },
                   Denial { approver: ApproverId, req: ReqId, note: Option<String> },
                   Pause { approver: ApproverId, agent: AgentId }, Seen { approver: ApproverId, req: ReqId } }
```

- **Hub.**
  - For `ask` it fans out to each listed approver's route.
  - It retries `deliver` with backoff until `Seen` arrives or the request ends. This is how "delivery keeps being retried" is met.
  - It turns `Inbound` into core inputs.
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
Envelope := "BOGOE2E" 0x00 | u8 version=1 | u8 type | u64 counter | bytes enc | bytes ciphertext
  HPKE mode_auth, suite DHKEM(X25519,HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 (RFC 9180)
  info = "bogo/e2e/v1" ‖ bogoId ‖ approverId,  aad = header bytes (magic..counter)
```

- **Mac→phone types:**
  - `request {reqId, bytes, group}`
  - `ended {reqId, why}`
  - `boot {bootSeq, bootId}`
  - `outcome {reqId, executed|rejected(why)}`
  - `registered {macName, bogoId}`
- **Phone→Mac types:**
  - `approval {reqId, alg=1, sig}`
  - `denial {reqId, note}`
  - `pause {agentId, bootId}`
  - `seen {reqId}`
  - `pushToken {token, env}`
- **Auth mode.** The relay can neither read nor forge either direction.
- **Replay.**
  - The phone deduplicates by `(bogoId, bootSeq, reqId)` and ignores a `boot` whose `bootSeq` isn't greater than the last one it saw.
  - BOGO accepts phone messages only with `counter` greater than the last counter it saw from that approver during this boot.
  - `pause` must carry the current `bootId`, so a replayed pause cannot re-pause an agent the owner un-paused.
  - Replayed approvals and denials are harmless, because approvals are idempotent and requests are single-use.

**Delivery.**
- For each `ask`, the route does two things concurrently:
  - puts a `request` envelope in the phone's mailbox (`msg_id = H(reqId‖approverId‖bootId)`, so resends are idempotent at the relay),
  - sends one APNs alert:

    ```
    apns-push-type: alert, apns-priority: 10, apns-topic: com.johansardar.applebridge.ios
    apns-collapse-id: hex(HMAC(macE2E-derived key, group))[:32]
    {"aps":{"alert":{"title":"BOGO","body":"Approval requested"},"interruption-level":"time-sensitive",
            "category":"bogo.request","thread-id":"bogo","content-available":1,"sound":"default"},
     "bogo":{"v":1,"mac":"<bogoId prefix>","rid":<reqId>,"boot":<bootSeq>}}
    ```

- The push carries no request content. The collapse ID makes duplicate requests collapse into one banner. The phone counts duplicates.
- A push is retried until APNs accepts it. The relay copy is retried until `seen`.
- The APNs host is sandbox or production, according to the environment the phone reported. JWT provider tokens are ES256, cached, and refreshed within Apple's limits ([APNs token auth](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns), [sending requests](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns)).

**Registration (numeric comparison).** This follows the commitment scheme of Bluetooth LE Secure Connections numeric comparison, so a man in the middle has one guess at a 6-digit code ([Bluetooth pairing, numeric comparison](https://www.bluetooth.com/blog/bluetooth-pairing-part-4/)).

1. The Mac (`bogo approver add "Johan iPhone"`) creates an ephemeral X25519 `eM` and posts a lobby offer `{offerId, ePubM, macLabel}` to the relay. It refreshes the offer while the command runs.
2. The phone (BOGO → Macs → Add Mac) lists the open offers. It usually finds one, and shows several by label and age if there are more. It creates `eP` and sends `ePubP` to the offer.
3. The Mac sends the commitment `Cm = SHA-256("bogo-reg-commit" ‖ ePubM ‖ ePubP ‖ Nm)`, with `Nm` 16 random bytes.
4. The phone sends `Np`. Then the Mac reveals `Nm`, and the phone checks `Cm`.
5. Both sides compute `code = u32be(SHA-256("bogo-reg-code" ‖ ePubM ‖ ePubP ‖ Nm ‖ Np)[0..4]) mod 10^6` and show it as `382 917`. From then on, all registration traffic is sealed under `K = HKDF(X25519(eM,eP), transcript)`.
6. The owner confirms on the Mac. The Mac sends `macConfirmed`, and only after that does the phone enable its Confirm button.
7. The owner confirms on the phone with Face ID. That single `LAContext` evaluation is used to create the SE key and to sign `"BOGO-REG\x00v1" ‖ transcriptHash` as proof of possession. The phone then:
   - creates `phoneE2E` and `phoneRelay`,
   - runs App Attest `generateKey` and `attestKey(keyId, clientDataHash = SHA-256(transcriptHash ‖ sePub ‖ phoneE2E.pub ‖ phoneRelay.pub))`,
   - sends everything plus its push token and environment.
8. The Mac verifies all of the following, then sends `registered` with `macE2E.pub`, `macRelay` mailbox, `bogoId` and the Mac's name:
   - the attestation, with the `appattest` crate against the pinned Apple App Attestation root, `app_id = AX3C2B78YD.com.johansardar.applebridge.ios`, nonce, key ID and counter 0,
   - the AAGUID environment (`appattestdevelop` for development builds, production for TestFlight, accepted per `[approvers.iphone] app_attest = ["development","production"]`),
   - the proof-of-possession signature.

   If any check fails, nothing is registered. On success the Mac writes the approver record and logs `approver_registered`. It also sets its mailbox allowlist to include the phone, and the phone does the reverse.
9. The lobby offer is deleted.

What App Attest proves is that the genuine, unmodified app produced these keys on a real device. That app creates the approval key only in the Secure Enclave with `.biometryCurrentSet`, so the key's protection is checked rather than taken on trust ([validating apps](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)).

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
  - `Grouping.key(request)` equals the core's `group` input, (agent, upstream, tool, args, justification), so duplicates show as one entry with a count.
  - `Inbox` state machine, per request:
    - `pending → approving → sent → outcome(executed|rejected)`,
    - `pending → denying → sent → outcome`,
    - `pending → ended` from `ended`, from a newer `boot`, or from an expiry that has passed.

    Ended entries are greyed and offer no actions.
- **BogoCrypto.**
  - `ApprovalKey` wraps `SecureEnclave.P256.Signing.PrivateKey(accessControl:authenticationContext:)` ([CryptoKit SecureEnclave](https://developer.apple.com/documentation/cryptokit/secureenclave), [biometryCurrentSet](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset)).
  - `Channel` wraps `HPKE.Sender/Recipient(…, authenticatedBy:)` with `.Curve25519_SHA256_ChachaPoly`. CryptoKit has offered auth mode since iOS 17 ([CryptoKit HPKE](https://developer.apple.com/documentation/cryptokit/hpke)).
  - `Attest` wraps `DCAppAttestService` ([DCAppAttestService](https://developer.apple.com/documentation/devicecheck/dcappattestservice)).
  - A signing failure with the key-invalidated error marks that Mac's registration as `needsReRegistration`. A changed `LAContext.evaluatedPolicyDomainState`, checked when the tab opens, does the same. The Macs screen then asks the owner to add the Mac again.
- **BogoRelay.**
  - URLSession client: auth, long-poll while the app is active, a single fetch on push wake, send and ack.
  - The outbox is a file written atomically before any send. Signed approvals and denials are retried until BOGO's `outcome` arrives or the request is known to have ended. Every inbound `request` is answered with `seen`.
- **BogoSection.**
  - Screens: Inbox (grouped, with counts), History (decisions and outcomes), Macs (list, Add Mac, remove, re-register prompt), Review, and the registration flow.
  - Review shows **Approve** and **Deny** (with an optional note) and **Pause agent**. Approve becomes tappable only after `approveArmDelay` once the screen is shown, and pressing it triggers Face ID through the SE key's signing.
  - A grouped entry reviews its oldest live request. Approve signs that one request only. Deny on a grouped entry denies every request in the group, each with its own denial.

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
- **Existing model checks.** The repo's checks that reference the Approvals tab are updated with the change: `lab/ios/ShellProof.swift` and the `shell` entry in `packaging/dev/check-models.py`. `check-models.py` gains a `bogo-model` entry that compiles `BogoModel` with a vector runner, following the repo's existing pattern.
- **Untouched.** The Apple Bridge pairing, gateway client, Apple Bridge relay and its APNs registration path.

### 3.15 Stdio shim (`bogo-shim`)

- `bogo-shim` reads `BOGO_URL` and `BOGO_AGENT_TOKEN` from its environment.
- It runs an rmcp server on stdio for the client, whatever protocol the client negotiates, and one rmcp client in legacy session mode to BOGO.
- It passes through `tools/list`, `tools/call` (including cancellation: a dropped call future sends `notifications/cancelled`) and `list_changed`. The client's `clientInfo.name` is forwarded as the shim's own `clientInfo`.
- When stdin closes, it sends DELETE for the session and exits, which ends the session's requests.
- It holds only the agent token and contains no BOGO logic.

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

- **Writer lock.** `~/.bogo/run/lock` (`flock`) allows one writer. When the daemon runs, mutating commands go over the control socket. When it doesn't, the CLI takes the lock and uses the same library code. `approver add` while the daemon is down runs registration in the CLI process.
- **Agent tokens.** `bogo_agt_` plus 32 random bytes in base64url. The token is printed once, and only its SHA-256 is stored.
- **Startup checks.** These fail closed and refuse to start:
  - `bogo.toml` has unknown keys (`deny_unknown_fields`),
  - `secrets.toml` is readable by group or others,
  - a policy names an approver that is not registered (the tool is reported as having no eligible approver, and its calls are rejected),
  - k is larger than the number of eligible approvers (same report).

### 3.17 Reference sandbox and bypass suite

- **`sandbox/compose.yml`:**
  - Network `bogo-net` with `internal: true` ([Docker internal networks](https://docs.docker.com/engine/network/drivers/bridge/)).
  - Service `gate` (`alpine/socat`) on `bogo-net` and the default bridge. It forwards only `gate:8790 → host.docker.internal:<bogo port>` ([Docker Desktop networking](https://docs.docker.com/desktop/features/networking/)).
  - Service `agent` on `bogo-net` only, with `BOGO_URL=http://gate:8790/mcp` and `BOGO_AGENT_TOKEN` from `sandbox/.env`. It has no bind mounts of the home directory, `~/.bogo`, SSH or Docker sockets, and no `secrets.toml`.
- **`bogo-bypass`.** Runs inside `agent` and prints one PASS or FAIL per attempt. Every attempt must fail:
  - TCP and DNS to `api.stripe.com`, `link.com`, the relay `bogo.eilmer.si`, a public IP, IPv6 and cloud metadata addresses;
  - `host.docker.internal` on any port, and `gate` on any port other than 8790;
  - a scan of the filesystem and environment for credential patterns: `sk_test_`, `sk_live_`, `.p8`, `secrets.toml`, Link CLI auth files;
  - MCP with no token or a wrong token;
  - a protected tool called without approval, using cancel-after-send so nothing is left pending;
  - a fake approval smuggled in `_meta` or the arguments;
  - a call to the un-namespaced upstream name;
  - a deny-policy tool;
  - the same session ID reused with another agent's token;
  - the Docker socket.

## 4. Data flows

**S1. Payment approved.**
1. The agent POSTs `tools/call stripe__create_payment_link {amount:4700, …, justification:"booking the 6pm flight…, $47"}`. The front authenticates "Trip planner", the body guard passes, and liveness registers.
2. The core resolves the policy: approve, wait. It strips the justification, builds and encodes the request, and outputs `ask`.
3. The log entry is written durably. Then the hub sends the relay envelope and APNs.
4. The banner (Deny only) appears on the phone. The owner taps it, the app fetches the envelope and decodes it, and Review shows "$47.00", "Requested by Trip planner" and the reason.
5. After the arm delay, the owner taps Approve, Face ID runs, and the SE signs. The outbox stores the approval, then sends it to the relay.
6. BOGO's long-poll returns the approval. It is opened and the counter checked, then it goes into the core as `approval`. The core verifies through `bogo_verify`, counts it (1 of any-of) and outputs `forward` with the stored arguments.
7. The `forwarded` entry is written durably. Then the upstream is called, the result is filtered and logged, and the agent gets Stripe's real result. The phone gets `outcome executed`.

**S2. A lie in the reason.** Same path. The phone shows $500.00 and the mismatch warning "Reason says $5, but this will charge $500.00". The owner taps Deny with the note "wrong amount". The phone sends a `denial`, the core outputs `reject(denied "wrong amount")`, and the agent gets "The owner denied this action. wrong amount". There is no `forward`, so nothing reaches Stripe.

**S3. Changing the call after approval.**
- **`amount:4701`, or a new justification.** This is a different request with a new `seq`, and the old signature doesn't verify over its bytes. In wait mode, the first call has already run once and been removed.
- **Another session.** Session binding means it never matches.
- **A replay of the approval.** The request has been removed (`ignored(ended)`), or the approver is already counted.
- **Pending-and-retry.** The approved request runs once on the first identical retry. Any later retry creates a new request.

**S4. Allowed tool.** Core `forward` → log write → upstream. There is no approver traffic.

**S5. Denied tool for Researcher.** The per-agent override is deny, so `tools/list` omits the tool. A direct call gives `reject(denyPolicy)`, which is logged, and there is no upstream contact.

**S6. No answer.**
- **The client gives up.** It sends `notifications/cancelled`, or the response stream drops. Either one leads to `callEnded`. The core outputs `ended` and `reject(ended)`, and the phone greys the entry out. A late Approve arrives as `ignored(ended)`, and BOGO answers `outcome rejected(ended)`, which the phone shows.
- **A 10-minute expiry.** The deadline timer leads to `tick`, with the same result. The phone's countdown has already reached zero.

**S7. Phone offline.** The envelope waits in the relay. APNs stores the alert. The hub keeps retrying until `seen`. When the phone comes back, it fetches from the relay, the request appears in the Inbox, and it can still be decided while the session is alive.

**S8. Adding the phone.** This follows §3.11. `bogo approver list` shows "Johan iPhone (iphone, App Attest: development|production, registered …)".

**S9. Adding an agent.** `bogo agent add "Trip planner"` stores a token hash, logs `agent_added` and prints the token. Requests then carry agentName "Trip planner". A connection with no token, or a wrong one, gets 401 at the auth layer.

**S10. Stolen phone.** The Inbox is visible. Approve needs the SE key, which needs Face ID. `bogo approver revoke "Johan iPhone"` causes `approverRevoked`: any later approval is `ignored(revoked)`, and pending requests that relied on that approver end if k is now unreachable. A Deny or Pause from the thief only refuses things, which is fail-closed.

**S11. Face ID changed.** Signing fails with the key-invalidated error, or a domain-state change is seen, so the Mac is marked `needsReRegistration`. The BOGO tab asks the owner to add the Mac again, and the new registration replaces the old approver.

**S12. Two approvers (2-of-2).** One soft approver plus the iPhone, or two iPhones. The first approval is `counted`. A second approval from the same approver is not counted again. The second distinct approver produces `forward`. Any denial under the default `anyDenial` gives `reject(denied)`.

**S13. Output filtering.** The upstream result contains `share_url`. With `filter_output=["share_url"]`, the filter strips it from the structured content and the JSON text before the agent sees it. The log records `filtered: ["share_url"]`.

**S14. Escape attempts.** `bogo-bypass` inside the container fails at every attempt. The only route is through `gate` to BOGO, and there the agent token gives no authority.

**S15. Checking the record.** `bogo log verify` checks the chain, replays the approver registry, re-verifies every approval with the Lean check, and confirms every protected `forwarded` request has its threshold. It prints a summary per decision type.

**S16. A flood.**
1. Identical requests share a `group`. APNs collapses their banners, and the Inbox shows one entry with a count.
2. At `max_pending`, the core outputs `floodDropped` for each new call. That is logged, no approver is notified, and the agent gets the flood rejection.
3. The owner taps Pause agent. The phone sends `pause`, the core denies all of that agent's pending requests and outputs `agentPaused`, which is persisted. Every new call from the agent is rejected.
4. `bogo agent unpause` causes `agentUnpaused`.

**S17. Two upstreams.** Stripe (`link-cli --mcp`) and the filesystem server are separate rmcp clients with separate namespaces, policies and restart state. A crash in one doesn't touch the other.

## 5. Failure

| Part | Crash / disconnect | Bad input | Recovery |
|---|---|---|---|
| **Core thread** (Lean) | The daemon process dies with it, because Lean is in-process. Every session drops, so no protected call runs. | Any malformed `Input` bytes give `reject(malformed)`, which is proved. | launchd KeepAlive restarts it. There is a new bootId and an empty state, so earlier approvals can never match (A3). |
| **Daemon** | All pending requests end, because their sessions are gone. The log is durable up to the last effect. | — | On restart it repairs a torn log tail, logs `boot`, and sends `boot{bootSeq}` to every approver so phones grey out old requests. Upstreams reconnect. |
| **Front** | Client disconnect leads to `callEnded`. An idle session is closed, ending its requests. | Batches, duplicate keys, oversize bodies, bad tokens and a session reused by another agent are all rejected before the core. | Clients reconnect and re-list tools. |
| **Upstream** | A child exiting mid-call returns "may or may not have happened" and logs `unknown`. It is never retried. The child is restarted with backoff. | A malformed result, or an MRTR/server request, is returned to the agent as an error. | The tools stay listed. Calls during an outage get "upstream unavailable". |
| **Log** | An effect waits for its entry, so a crash means no effect without its record. | A torn tail is moved aside and logged. | If the disk is full or the write fails, the daemon refuses every call that needs logging, which is every call. Fail-closed. |
| **Approver hub** | If the relay is unreachable, delivery keeps retrying until the request ends, and requests wait. If APNs fails, pushes are retried. | An envelope that fails to open or fails the counter check is dropped and counted in diagnostics. An unknown approver is ignored. | Long-poll reconnects with backoff. |
| **Relay** | If down, both sides retry. Messages are durable in SQLite. | Bad auth gives 401. A non-allowlisted sender gives 403. A full mailbox gives 409, and the sender retries. | systemd `Restart=always`. A relay restart drops in-memory tokens, and clients re-authenticate. |
| **Phone app** | A crash after signing is safe, because the outbox is written before sending and resent at the next launch or wake. If it is killed, the APNs alert still shows, and Deny works in the background. | An undecodable or non-canonical request, the wrong `bogoId`, or an unknown encoding version is shown as "Unreadable request" with Deny only. A failed signature check on an envelope means it is dropped. | Fetch on launch, foreground and push wake. |
| **SE key / Face ID** | Face ID failure or cancel means nothing is sent, and the request stays pending. | An invalidated key leads to `needsReRegistration`. | Re-register. |
| **Registration** | An interruption at any step means nothing is registered. Either side can restart from scratch. | A commitment, SAS, attestation or proof-of-possession failure aborts the registration. | Run `bogo approver add` again. |
| **Shim** | Stdin closing sends DELETE and ends the session. If BOGO is unreachable, the shim returns errors to the client, and rmcp reconnects. | — | — |
| **Config** | — | Unknown keys, bad permissions on secrets, or an unexposable tool name: the daemon refuses to start or the tool is not exposed. | The owner fixes the file and restarts. |
| **Clock** | — | A Mac clock jump only moves expiries (the clock is trusted). A phone clock jump only changes the countdown shown. | — |

## 6. Data and versions

**`~/.bogo/` (directory 0700):**

```
bogo.toml               owner-edited policy (format below)
secrets.toml            0600; refused otherwise
keys/mac_e2e.key        X25519, 0600
keys/mac_relay.key      Ed25519, 0600
state/agents.json       {"v":1,"agents":[{"id","name","token_sha256","created","revoked","paused"}]}
state/approvers.json    {"v":1,"approvers":[{"id","name","kind","alg","sig_pk","route":{…},"registered","revoked"}]}
state/tools.json        {"v":1,"tools":[{"name","upstream","tool","first_seen","justification_key","exposable"}]}
state/boot              {"v":1,"boot_seq":N}  (incremented and synced at every start)
log/audit.jsonl         hash-chained log
run/bogo.sock, run/lock
```

The state files are written atomically: write to a temp file, `sync`, then rename. The daemon or the lock holder is the only writer.

**`bogo.toml`** (`version = 1`, `deny_unknown_fields` everywhere):

```toml
version = 1
[server]
port = 8790
session_idle = "5m"                # BOGO's idle end for legacy sessions; owner to confirm (§11)
max_body = "1MiB"
[relay]
url = "https://bogo.eilmer.si:8443"
[apns]
key = { secret = "apns_p8" }       # secrets.toml: apns_p8 = { path = "/Users/…/AuthKey_XXXX.p8" }
key_id = "XXXXXXXXXX"; team_id = "AX3C2B78YD"; topic = "com.johansardar.applebridge.ios"
[approvers.iphone]
app_attest = ["development", "production"]
[upstreams.stripe]
command = "npx"; args = ["-y", "@stripe/link-cli", "--mcp"]
env = { }                          # e.g. { API_KEY = { secret = "x" } }
[upstreams.files]
command = "npx"; args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/johansardar/bogo-test"]
# remote: url = "https://…/mcp", headers = { Authorization = { secret = "tok" } }
[defaults]
policy = "approve"; hide_denied = true; max_pending = 5
[tools."stripe__create_payment_link"]
policy = "approve"; justification = "required"
highlight = { amount = "usd_cents", currency = "text" }
approvers = ["Johan iPhone"]; require = "any"   # or { k = 2 }
on_deny = "any"                                  # or "when_unreachable"
expiry = "10m"; mode = "wait"                    # or "pending_retry"
filter_output = ["url"]; filter_action = "strip" # or "redact"
[agents."Researcher".tools."stripe__create_payment_link"]
policy = "deny"
```

`max_pending` has no value in the spec. The template ships the line with a placeholder value that the owner sets.

**Formats and how they change:**

| Format | Version marker | Change rule |
|---|---|---|
| Request encoding | `"BOGOREQ\0"` + u16 | A new version is a new Lean encoder with its own injectivity proof. The phone advertises the versions it supports at registration and in `pushToken` messages. BOGO encodes with the highest common version. An unknown version on the phone shows as unreadable, with Deny only. |
| Rust↔Lean wire | `bogo_core_abi()` | Built together. A mismatch refuses to start. |
| E2E envelope | `"BOGOE2E\0"` + u8, HPKE info `bogo/e2e/v1` | New types are added. Unknown types are ignored after a successful open. A new suite gets a new version. |
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
    bogo-core-sys/ (build.rs, shim.c)  bogo-core/  bogo-verify/
    bogo-config/  bogo-state/  bogo-log/  bogo-filter/
    bogo-upstream/  bogo-front/
    bogo-approver/  bogo-approver-iphone/  bogo-approver-soft/
    bogo-relay-proto/  bogo-e2e/  bogo-apns/
    bogo-daemon/
  bins/
    bogo/  bogo-shim/  bogo-relay/  bogo-standin/  bogo-bypass/
  sandbox/      compose.yml  .env.example  README.md
  deploy/relay/ bogo-relay.service  lego-renew.sh  nftables-bogo.conf
  docs/         README.md  configuration.md  threat-model.md  proved-and-assumed.md  SPEC.md  adr/
  Cargo.toml (workspace; serde_json features = ["arbitrary_precision"]; rmcp pinned "=3.10.0")
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
- `bogo-approver-iphone` must not depend on `bogo-core` internals, only on the shared ID and request types re-exported by `bogo-approver`.
- `bogo-approver-soft` is listed under `[features] test-approvers` and is absent from the default build.
- `bogo-shim`, `bogo-bypass` and `bogo-relay` depend on no daemon crate.
- Nothing in either repo references Apple Bridge Mac code, its gateway paths (`/v1/iphone/*`), relay or pairing.
- In BogoKit, the direction is BogoModel ← BogoCrypto ← BogoRelay ← BogoSection. The host app imports only `BogoSection`. BogoKit never imports host code.

## 8. Build order

1. **`BogoCore` encoding** (`Json`, `Encoding`) with `decode_encode` and `encode_injective`, then `BogoVectors` → `vectors/`. Both platforms need these bytes before anything else.
2. **Crypto and transport building blocks:** `bogo-e2e`, `bogo-relay-proto`, `bogo-apns`, `bogo-verify` (P-256), then the `bogo-relay` service deployed on the VPS (DNS, certificate, port rule).
3. **`bogo-approver`** (trait and hub) and **`bogo-approver-iphone`** (registration with SAS and App Attest, delivery, intake), with `bogo-state` for keys and the approver registry.
4. **`bogo-standin`**: registers a phone, sends requests taken from `vectors/`, prints each decision verified with `bogo-verify`, and sends `ended`, `boot` and `outcome` on command. With this in place, the phone can be built and exercised end to end.
5. **`BogoKit`** (Model → Crypto → Relay → Section) and the host-app edge edits in apple-bridge-iphone.
6. **`BogoCore` decision logic** (`Policy`, `Core`, `Wire`, `Ffi`) and **`BogoProofs`**. This can run in parallel with steps 3–5, because it depends only on step 1.
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
| `serde_json` 1.0 + `arbitrary_precision` | Numbers keep their exact text from parse to forward | [github.com/serde-rs/json](https://github.com/serde-rs/json) |
| `tokio` 1.54, `axum` 0.8, `tower` | The runtime and the HTTP layers around rmcp, including the relay server | [tokio](https://github.com/tokio-rs/tokio), [axum](https://github.com/tokio-rs/axum) |
| Lean 4 v4.35.0 + Lake (`:static` facet) | Required by the spec. The decision code is compiled to C and statically linked. | [lean4 releases](https://github.com/leanprover/lean4/releases), [Lake README](https://github.com/leanprover/lean4/blob/master/src/lake/README.md), [FFI reference](https://lean-lang.org/doc/reference/latest/Run-Time-Code/Foreign-Function-Interface/) |
| `cc` | Compiles BOGO's own C shim against the pinned `lean.h`. `lean-sys` was rejected: last release 2025-09, bound to older headers. | [github.com/rust-lang/cc-rs](https://github.com/rust-lang/cc-rs) |
| `hpke` 0.15 (x25519, chacha) | RFC 9180 auth mode. Interoperates with CryptoKit HPKE `.Curve25519_SHA256_ChachaPoly`. | [github.com/rozbb/rust-hpke](https://github.com/rozbb/rust-hpke), [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) |
| `p256` 0.14 / `ecdsa` 0.17 | Verifies Secure Enclave P-256 signatures | [RustCrypto/elliptic-curves](https://github.com/RustCrypto/elliptic-curves) |
| `ed25519-dalek` 3 | Relay mailbox auth, and the soft test approver | [curve25519-dalek repo](https://github.com/dalek-cryptography/curve25519-dalek) |
| `sha2` 0.11 | Log chain, token hashes, group keys | [RustCrypto/hashes](https://github.com/RustCrypto/hashes) |
| `appattest` 0.1.1 | App Attest attestation checks: chain, nonce, RP ID, counter, AAGUID, key ID. Wrapped behind BOGO's own `attest` function with a pinned root and an environment check. | [github.com/PrismaPhonic/appattest](https://github.com/PrismaPhonic/appattest) |
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
| Docker Compose + `alpine/socat` | Reference sandbox: internal network, single-port gate | [Docker bridge networks](https://docs.docker.com/engine/network/drivers/bridge/), [Docker Desktop networking](https://docs.docker.com/desktop/features/networking/) |
| `@stripe/link-cli --mcp`, `@modelcontextprotocol/server-filesystem` | The upstreams the spec uses for proof. Link CLI exposes spend-request tools over MCP and can return card details on request, which is a natural output-filter target. | [github.com/stripe/link-cli](https://github.com/stripe/link-cli), [servers/filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) |

## 10. Risks and open questions

| Risk | Why it matters | How to find out |
|---|---|---|
| **MCP 2026-07-28 removed sessions** | "Session = one MCP connection" now only exists in legacy versions. Stateless clients get call-scoped sessions, which makes pending-and-retry unavailable to them. If clients drop legacy versions, session semantics shrink further. | Check which protocol Claude Code, Cursor and Claude Desktop negotiate against BOGO. Watch rmcp's `legacy_session_mode` across releases. |
| **Disconnect detection in legacy sessions** | The liveness layer depends on hyper dropping the response body when the client goes away. | Run a protected wait-mode call, kill the client, and confirm `callEnded` shows in the log. |
| **Lean static link on macOS** | `lean.h` is unstable, and the link line (`leanc --print-ldflags`, libc++, gmp) can change between toolchains | Pin the toolchain. The ABI check runs at startup. Build the shim against the pinned header on each toolchain bump. |
| **Proof boundary (A6)** | The Rust shell could forward something other than the `forward` output | Keep the shell's forward path one function from output to rmcp `call_tool`, with no other caller of `call_tool` in the workspace. Check it with a grep-able rule: `call_tool` is used in only one place. |
| **`appattest` crate maturity** | It is young, and it pulls in `openssl` and `aws-lc-rs` | Feed it real attestations from development and TestFlight builds. It is wrapped behind one function, so a self-written verifier using `x509-parser` and `p256` could replace it. |
| **Docker Desktop `host.docker.internal` reaching host loopback** | The gate depends on it. BOGO listens on 127.0.0.1 only. | Run `bogo-bypass` and a real agent call from the container. |
| **Agent harness needs its model API** | A sandbox that allows only BOGO also cuts off the agent's LLM | Owner decision (§11) |
| **iOS background Deny and push wake** | A force-quit app gets no background wake. Deny from the banner still launches it, but the timing is up to iOS. | Try Deny from a locked phone with the app force-quit. The outbox makes a late send safe. |
| **Link CLI behaviour** | It may use elicitation or MRTR, which BOGO refuses, or need its device-flow login on the Mac side | List its tools and run a test-mode spend through BOGO. |
| **Scenario 13 tool** | The official filesystem server has no "share" tool that returns a public link | Owner decision (§11) |
| **Relay lobby is global** | Anyone can post offers. Numeric comparison keeps registration secure, but junk offers could clutter Add Mac. | Watch the lobby. A per-offer label and age is shown. |
| **Log chain without an anchor** | Someone with file access could rewrite the whole chain. Mac compromise is out of scope, but that is the limit of what the chain shows. | State it in the threat-model doc. |
| **Number formats on the phone** | `moneyMinor` on a non-integer number text must not mislead | The vectors include `4700`, `4700.0`, `4.7e3` and `-0`. Non-integers show raw and are marked. |

## 11. Questions for the user

1. **Sandbox egress for the agent's model.** The spec says the container has no network except BOGO, but an agent harness such as Claude Code must reach its model API. Should `gate` also allow one named model API host, or must the agent's model run outside the container?
2. **Protocol 2026-07-28 clients.** That protocol has no sessions. Is it acceptable that pending-and-retry tools need either a session-capable connection or the stdio shim, and are rejected for stateless HTTP clients?
3. **Owner cancel.** The spec lists "the owner cancels it" as a way a request ends, but no command is drafted for it. Is `bogo request list | cancel <id>` acceptable, or should cancel live on the phone?
4. **Grouped entries.** When identical requests are grouped, Approve signs only the oldest one and Deny denies the whole group. Is that right?
5. **Numbers the spec leaves open.** These are behaviour values, not performance goals:
   - the Approve arm delay ("a short delay"),
   - the legacy-session idle timeout (the design uses rmcp's 5-minute default),
   - the default `max_pending` flood limit,
   - the relay's maximum message age and mailbox caps.
6. **Relay port.** 8443 is assumed. Is it free on the VPS?
7. **Banner text.** The push carries no content ("BOGO: Approval requested"). Showing the agent or tool name on the banner would need an encrypted payload plus a Notification Service Extension. Is the generic banner fine?
8. **Upstream resources and prompts.** These are not exposed, so they can't be used to go around the gate. Is that OK, given that the spec only talks about tools?
9. **Scenario 13.** The official filesystem server returns no public sharing link. Which tool should show output filtering? Stripe Link's card-details retrieval is one option, or a small test upstream.
10. **Spec §9 open questions carried over:**
    - whether the PRD's speed goals apply (overhead on allowed calls, notification latency, setup time),
    - whether a second real device exists for 2-of-2,
    - which Link tools are protected (all of them, or only the ones that create spend requests or credentials).
