/-
The model the promise is stated in (ARCHITECTURE §3.3).

**Traces.** A trace is any `List Input`, run with `step` from `initState bogoId bootId`. Nothing
restricts it: the agent's `call`, `callEnded`, `sessionOpened` and `sessionClosed`, the
network's `approval`, `denial` and `pauseAgent` (forgeries, replays, reordering, duplicates),
the shell's `dispatch`, `notSent` and `tick`, and the owner's inputs can come in any order, any
number of times, with any values, including any `nowMs`. `BogoProofs.Promise` also lifts every
theorem to raw byte strings fed to `stepBytes`, which is what Rust actually calls.

**What is assumed.** The only assumption the Lean proofs use is A1, stated below as the one
axiom beyond Lean's standard three. The others in ARCHITECTURE §3.3 are about things outside
the Lean model and are listed here so `#print axioms` and this file say the same:

* **A1 Unforgeable, user-verified approvals** (spec assumptions 1 and 3): `verify` accepting a
  proof over a message under a registered key means the holder of that key approved that exact
  message after its user verification. `OwnerApproved` names that event; it is opaque, so
  nothing in Lean can prove it except through A1.
* **A2 Hash collision resistance** is not used in Lean: the core matches requests by full byte
  equality, never by hash. It matters inside ECDSA-SHA-256 (part of A1) and for the audit log.
* **A3 Distinct boots**: a trace is one boot. Requests never outlive a boot (the state starts
  empty), so across boots only `bootId` freshness matters, and that is outside Lean.
* **A4, A5** (the sandbox; upstreams reject unauthenticated requests): not about the core.
* **A6 Faithful shell**: Rust writes upstream exactly the `forward` outputs and reports real
  events as the inputs they are; the Lean compiler, runtime, C shim and FFI are correct;
  `bogo_rs_verify` is a faithful P-256 verifier.
* **A7 Genuine app**, **A8 Owner and identity origin**, **A10 Storage**: about registration,
  where inputs come from, and the log.
* **A9 Clock**: "fresh" is proved against the `nowMs` of the dispatch step; that this is the
  real time rests on the core clock.
-/
import BogoProofs.Step

namespace Bogo.Proofs
open Bogo

/-- "The holder of key `pk` (algorithm `alg`) approved exactly `msg`, after its user
verification." Opaque: only A1 can establish it. -/
opaque OwnerApproved : UInt16 → ByteArray → ByteArray → Prop

/-- **A1.** A proof that `verify` accepts is an approval by the key's holder. -/
axiom A1_unforgeable :
  ∀ (alg : UInt16) (pk msg proof : ByteArray), verify alg pk msg proof = true →
    OwnerApproved alg pk msg

/-! ### Traces -/

/-- The state after running `xs` from `s`. -/
def run (s : State) (xs : List Input) : State := xs.foldl (fun s x => (step s x).1) s

/-- The state just before step `i` of the trace `xs` from `s0`. -/
def before (s0 : State) (xs : List Input) (i : Nat) : State := run s0 (xs.take i)

/-- The outputs of step `i` of the trace `xs` from `s0`. -/
def outputsAt (s0 : State) (xs : List Input) (i : Nat) : List Output :=
  match xs[i]? with
  | some x => (step (before s0 xs i) x).2.1
  | none => []

/-- The decisions BOGO actually emits from the start of a boot. -/
abbrev Boot (bogoId bootId : ByteArray) : State := initState bogoId bootId

/-! ### Byte traces: what Rust actually calls -/

def runBytes (s : State) (bs : List ByteArray) : State :=
  bs.foldl (fun s b => (Wire.stepBytes s b).1) s

def beforeBytes (s0 : State) (bs : List ByteArray) (i : Nat) : State := runBytes s0 (bs.take i)

def outputsAtBytes (s0 : State) (bs : List ByteArray) (i : Nat) : List Output :=
  match bs[i]? with
  | some b => (Wire.stepBytes (beforeBytes s0 bs i) b).2.1
  | none => []

/-! ### Words used in the theorems -/

/-- The agent whose session a call belongs to, as the core knows it in state `s`. -/
def callAgent (s : State) (c : CallId) : Option AgentId :=
  match findCall s c with
  | some cr =>
    match findSession s cr.session with
    | some sess => some sess.agent
    | none => none
  | none => none

/-- The owner explicitly set `allow` for this tool: in its own entry, or in an override for
this agent. -/
def ExplicitAllow (cfg : PolicyConfig) (agentName name : String) : Prop :=
  (∃ o ∈ cfg.overrides, o.agentName = agentName ∧ o.tool = name ∧ o.kind = some .allow) ∨
  (∃ p, (name, p) ∈ cfg.tools ∧ p.kind = .allow)

/-- An input that ends the live request `q`. -/
def Ends (x : Input) (q : ReqRec) : Prop :=
  x = .sessionClosed q.req.session ∨
  x = .ownerCancel q.req.nonce ∨
  (∃ seq, x = .agentRevoked seq q.req.agentId) ∨
  (∃ c, q.call = some c ∧ (x = .callEnded c ∨ x = .notSent c)) ∨
  (∃ now, x = .tick now ∧ notExpired q.req now = false)

end Bogo.Proofs
