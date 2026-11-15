/-
What every theorem rests on. `#guard_msgs` makes `lake build` fail if that ever changes: a
`sorry` shows up as `sorryAx`, and any new axiom by its name.

The only axiom beyond Lean's standard three (`propext`, `Classical.choice`, `Quot.sound`) is
`Bogo.Proofs.A1_unforgeable`, assumption A1 of ARCHITECTURE §3.3 (see `BogoProofs.Spec`). Only
the theorems that conclude `OwnerApproved` use it.
-/
import BogoProofs.Encoding
import BogoProofs.Bytes

/-! ### The encoding (Foundations) -/

/-- info: 'Bogo.Proofs.decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.decode_encode

/-- info: 'Bogo.Proofs.encode_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.encode_injective

/-- info: 'Bogo.Proofs.sigMsg_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.sigMsg_injective

/-- info: 'Bogo.Proofs.encodeValue_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.encodeValue_injective

/-- info: 'Bogo.Proofs.encode_decode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.encode_decode

/-- info: 'Bogo.Proofs.decode_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.decode_injective

/-! ### The five promises of SPEC §3.8 -/

/-- info: 'Bogo.Proofs.approved' depends on axioms: [propext, Classical.choice, Quot.sound, Bogo.Proofs.A1_unforgeable] -/
#guard_msgs in #print axioms Bogo.Proofs.approved

/-- info: 'Bogo.Proofs.exact' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.exact

/-- info: 'Bogo.Proofs.single_use' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.single_use

/-- info: 'Bogo.Proofs.fresh' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.fresh

/-- info: 'Bogo.Proofs.fail_closed' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.fail_closed

/-! ### The rest of the promise -/

/-- info: 'Bogo.Proofs.safe_default' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.safe_default

/-- info: 'Bogo.Proofs.unlisted_never_allow' depends on axioms: [propext] -/
#guard_msgs in #print axioms Bogo.Proofs.unlisted_never_allow

/-- info: 'Bogo.Proofs.asks_admitted' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.asks_admitted

/-- info: 'Bogo.Proofs.flood_limit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.flood_limit

/-- info: 'Bogo.Proofs.blocked_agent_not_asked' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.blocked_agent_not_asked

/-- info: 'Bogo.Proofs.blocked_after' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.blocked_after

/-- info: 'Bogo.Proofs.revoked_approver_gone' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.revoked_approver_gone

/-- info: 'Bogo.Proofs.settled_final' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.settled_final

/-! ### Raw bytes -/

/-- info: 'Bogo.Proofs.attach_never_runs' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.attach_never_runs

/-- info: 'Bogo.Proofs.malformed_never_runs' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.malformed_never_runs

/-- info: 'Bogo.Proofs.bytes_lift' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.bytes_lift

/-- info: 'Bogo.Proofs.single_use_bytes' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.single_use_bytes

/-- info: 'Bogo.Proofs.approved_bytes' depends on axioms: [propext, Classical.choice, Quot.sound, Bogo.Proofs.A1_unforgeable] -/
#guard_msgs in #print axioms Bogo.Proofs.approved_bytes
