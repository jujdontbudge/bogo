# What is proved / What is assumed

BOGO proves properties of its **decision core**, not of the whole Mac, phone or
provider. The core is Lean code compiled into the daemon, not a separate model
that Rust reimplements. The proofs themselves are checked at build time and
are not linked into the daemon. The Rust shell, C boundary, crypto libraries,
phone and sandbox remain outside that proof.

The statements below were read from
[`Promise.lean`](../lean/BogoProofs/Promise.lean), with definitions from
[`Spec.lean`](../lean/BogoProofs/Spec.lean). A trace is any list of inputs from
an empty `Boot bogoId bootId`: arbitrary order, duplicates, forgeries, scheduling,
owner policy changes and even arbitrary clock values. Each forward is judged
against the state **immediately before that step**. A `forward` is permission
to send one upstream call. It does not prove successful delivery, provider
execution, or an exactly-once business effect.

## What is proved

Every theorem name below is in namespace `Bogo.Proofs`.

| Property | What the theorem actually says | Theorem |
|---|---|---|
| Approved, or explicitly allowed | A forward is either an explicitly allowed call under the effective policy now, or the exact stored protected request with enough distinct approvers. Each counted approver is registered now, eligible both at admission and under the current policy, and has not denied. Both the admission threshold and current threshold are met. Under A1, each holder approved this request's signed bytes. The destination still agrees with the catalog. | `approved` |
| Exact | For a protected forward, the upstream, tool and arguments are the stored well-formed request's. Its signed bytes decode to that request; no other well-formed request has those signed bytes. Combined with `approved`, the owner approval refers to exactly this request. | `exact` |
| Single-use | Two forwards of the same request ID must be the same trace step. Two protected forwards with equal signed request bytes must also be the same step. If a call ID forwards at two different steps, there must be a new `call` input using that ID strictly between them. It does not forbid legitimate new calls. | `single_use` |
| Fresh and session-bound | A forward is the dispatch of a live call in an open session whose agent is active. A protected request is bound to that call, session and agent, and dispatch's supplied `now` is strictly before any expiry. Requests ended earlier cannot forward. Earlier agent revocation is respected; a pause blocks until an intervening owner unpause. | `fresh` |
| Fail-closed gate | Every forward requires the live call/session/agent, matching catalog destination and the effective policy now. A protected request must be settled, bound, canonical, unexpired and meet the standing-approval gate. Missing any required condition gives no forward. This is a precise gate statement, not a proof that every possible failure elsewhere means “nothing happened.” | `fail_closed` |
| Safe default | A forward without a protected request requires an explicit allow in the tool policy or agent override. With neither entry nor override, effective policy cannot be allow. | `safe_default`, `unlisted_never_allow` |
| Only admitted requests are shown | An `ask` comes from admission of a call at that step. It contains the stored request's exact encoding, eligible recipient IDs and grouping key. Admission includes an active known agent and approve policy. | `asks_admitted` |
| Flood limit | At every `ask`, that agent's live-request count **before admission** is below configured `maxPending`; the agent is neither paused nor revoked. This does not bound all traffic or prove immunity to approval fatigue. | `flood_limit` |
| Blocked agents cannot cause asks | When an agent is paused or revoked, any `ask` at that step belongs to another agent. Revocation persists forever in that boot trace; pause persists until an owner unpause input. | `blocked_agent_not_asked`, `blocked_after` |
| Revoked approvers stay gone | After an approverRevoked input, no registered approver later has that ID. Together with `approved`, its vote cannot count toward a later forward. Re-registration needs a new identity. | `revoked_approver_gone` |
| Settlement is final for decisions | Given a settled request in a state, an approval or denial input returns that state unchanged and an ignored/settled output. This does not make it immune to later cancellation, expiry, revocation or the final dispatch gate. | `settled_final` |
| An attached retry does not execute separately | If a call was attached to a primary call, any later forward under the attached call ID requires a new call input with that ID in between. It receives the primary's result through the shell, not its own permission to execute. | `attach_never_runs` |

`fwd_step` further pins every forward to `dispatch` and the current registry
sequence; it removes the call and, for a protected forward, its request.
`fwd_live` gives the live-call/open-session/active-agent fact directly. The
remaining lemmas in `Promise.lean` support these statements (request immutability,
spent requests staying spent, call removal and policy resolution); they are not
additional claims about external I/O.

Request equality includes upstream, tool, arguments, justification, display
hints, agent identity/name, client name, session, nonce and times as defined by
`Request`. Arguments use the exact JSON **value tree**: numbers retain text
(`4700`, `4700.0`, `4.7e3` differ), object keys are sorted, and string escapes are
decoded. JSON whitespace and alternative escape spelling are not separate
values. Absent arguments differ from `{}`; absent justification differs from
an empty string. None of this says an arbitrary provider interprets those
values the way the owner expects.

## Encoding and the bytes Rust supplies

These statements come from
[`Encoding.lean`](../lean/BogoProofs/Encoding.lean),
[`Decode.lean`](../lean/BogoProofs/Decode.lean) and
[`Bytes.lean`](../lean/BogoProofs/Bytes.lean), not an informal claim that parsing
“must be safe.”

| Theorem | Statement in words |
|---|---|
| `decode_encode` | Every well-formed request round-trips through its encoding. |
| `encode_injective`, `sigMsg_injective` | Equal encodings, or equal domain-prefixed signed messages, imply equal well-formed requests. |
| `encodeValue_injective` | Equal encodings imply equal well-formed argument values. |
| `encode_decode` | Bytes accepted as a request re-encode to exactly those bytes; alternative noncanonical encodings are not accepted. |
| `decode_injective` | If two byte strings decode to the same request, those strings are equal. |
| `malformed_never_runs` | An input rejected by the Lean wire decoder leaves state unchanged, emits only a malformed rejection, and retains the next deadline. It neither asks nor forwards. |
| `bytes_lift` | A forward or ask in a byte trace is the same output, from the same state, in the successfully decoded input trace. Malformed steps cannot hide a forward or ask. This connects the decision theorems to the bytes the FFI receives. |
| `single_use_bytes` | Two forwards of one protected request ID in a byte trace occur at the same step. |
| `approved_bytes` | A protected byte-trace forward has the exact stored destination/arguments and enough distinct registered eligible holders who approved its signed bytes, under A1. The fuller policy conditions follow through `bytes_lift` and `approved`. |

The core's tool names are opaque strings. With per-action policy
(`select`, see [configuration](configuration.md#per-action-policy-toolsupstream__toolargvalue)),
the daemon passes the policy key `tool[arg=value]` as the call's name, and each
key is its own catalog entry for the same upstream tool. Every theorem above
therefore holds per key unchanged. That the daemon picks the key from exactly the
call's arguments, and falls back to the tool's own name otherwise, is part of A6.

This does not prove the Rust HTTP JSON parser or Swift decoder equivalent to
the Lean decoder. Shared vectors and runtime checks provide evidence for those
implementations; their fidelity is part of the assumptions below.

## What `#print axioms` actually reports

Run from the repository root with elan first on PATH:

```sh
export PATH="$HOME/.elan/bin:$PATH"
(cd lean && lake build BogoProofs)
(cd lean && lake env lean BogoProofs/Axioms.lean)
```

[`Axioms.lean`](../lean/BogoProofs/Axioms.lean) wraps each `#print axioms` in
`#guard_msgs`: success is normally quiet for that second command. The build
fails if the recorded dependency list changes, including introduction of
`sorryAx`. To see the output directly, create a temporary Lean file importing
`BogoProofs.Axioms` and add `#print axioms Bogo.Proofs.approved` (or another
listed theorem), then run it with `lake env lean` from `lean/`.

The checked dependency sets are:

- `approved` and `approved_bytes`: `propext`, `Classical.choice`, `Quot.sound`,
  **`Bogo.Proofs.A1_unforgeable`**.
- `unlisted_never_allow`: `propext` only.
- Every other theorem guarded in `Axioms.lean`: `propext`, `Classical.choice`,
  `Quot.sound`. No other project axiom appears and no `sorryAx` appears.

The standard three are Lean's propositional extensionality (equivalent
propositions are equal), classical choice (choose a witness from an existence
claim), and quotient soundness (equivalent representatives have the same
quotient). Trust in those logical principles and Lean's kernel is part of
trusting the proof; if that foundation is unsound, the certificates no longer
establish the claims. They do not establish any cryptographic or device fact.

## What is assumed, and what fails without it

These names follow `Spec.lean` and [ARCHITECTURE §3.3](ARCHITECTURE.md#33-proof-bogoproofs--what-is-proved--what-is-assumed).
Only **A1** is a custom Lean axiom. A2–A10 are conditions for interpreting the
core's theorem as a real-system guarantee; their absence from `#print axioms`
is not proof that the surrounding system meets them.

| Assumption | What is trusted | If it fails |
|---|---|---|
| **A1 — Unforgeable, user-verified approvals** | `verify alg pk msg proof = true` implies that holder approved exactly msg after user verification. This is the precise axiom `A1_unforgeable`; `OwnerApproved` is opaque. It includes signature unforgeability and control of key use. | A counted signature may not mean the owner approved. The human-approval conclusions of `approved` / `approved_bytes` fail, even if the state machine still enforces byte matching and single use. A software approver deliberately does not meet the Face ID interpretation. |
| **A2 — Hash collision resistance** | SHA-256 inside approval signatures and audit links. Core request matching uses full bytes, not hashes. | Forged bindings/signatures or an altered audit chain could become possible. Direct encoding injectivity is still a separate mathematical result. |
| **A3 — Distinct boots** | Each boot has a fresh random 32-byte bootId. Theorems start from one empty boot. | A request identity and session binding could recur across boots, undermining cross-restart replay protection. |
| **A4 — Agent isolation** | Agent has no route to upstreams or their credentials except BOGO. The reference sandbox is an implementation to check, not a theorem. | The agent can bypass BOGO altogether. A host Claude process with shell access does not satisfy this just because it has an MCP config. |
| **A5 — Provider authentication** | Providers reject requests without valid credentials. | Direct provider access may work despite BOGO withholding credentials/approval. |
| **A6 — Faithful shell and toolchain** | Rust sends exactly, and only, the core's forward at the requested transport write; it reports real lifecycle events, preserves argument text and verifies signatures faithfully. Lean compiler/runtime, C shim, FFI and relevant libraries behave correctly. | Actual sends can differ from proved outputs; an unreported disconnect can appear live, a changed argument can execute, or a false verifier result can count. The Lean theorem still concerns its supplied inputs/outputs. |
| **A7 — Genuine app** | Valid App Attest identifies the intended build on real hardware. That build creates its own Secure Enclave key with biometryCurrentSet and no supplied-key import path. App Attest does **not** directly attest the approval key's access-control flags. | An unprotected/imported key or misleading app could be registered, invalidating the Face ID/user-verification interpretation of A1. Hardware qualification is outstanding. |
| **A8 — Owner and identity origin** | Owner inputs come from trusted startup config, owner CLI/socket or log replay; session agent identity is derived from the verified token. A registered phone's remove message can only take authority away. | An attacker can change policy/registration or impersonate an agent. Theorems remain relative to that maliciously supplied policy/registry. Anyone with the owner's Mac-account access is inside this trust boundary. |
| **A9 — Clock** | Dispatch time comes from the boot's nondecreasing clock that counts Mac sleep. | “Before expiry” is only before the supplied number, not real time; an expired request might appear fresh. |
| **A10 — Storage durability** | A record acknowledged durable survives a crash, including macOS F_FULLFSYNC behavior. | Registry, revocation and outcome recovery can lose acknowledged history; crash recovery and audit assurances fail. |

The spec's five assumptions map to A1 (signatures and user verification), A2
(hashes), A4 (isolation) and A5 (provider authentication). A3 and A6–A10 make
additional implementation boundaries explicit.

Human judgment is not proved: approving accurately displayed harmful arguments
is still approval. Neither notification delivery, general availability,
compatibility with every schema/client, detecting a silent direct HTTP client,
nor downstream business effects are proved. A crash or connection loss after
send can leave the outcome unknown. BOGO does not retry that call; single-use
permission is not a provider transaction protocol.

See the [threat model](threat-model.md) and
[verification records](verification/daemon-cli.md) for observed checks and
remaining work. Software/simulator approval, local relay tests and synthetic
attestation rejection tests do not establish Face ID, hardware App Attest,
public relay operation, APNs delivery or completed Link login.
