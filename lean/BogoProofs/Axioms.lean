/-
The encoding theorems use only Lean's standard axioms. `#guard_msgs` makes `lake build` fail
if that ever changes (a `sorry` shows up as `sorryAx`, an added axiom by its name).
-/
import BogoProofs.Encoding

/-- info: 'Bogo.Proofs.decode_encode' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.decode_encode

/-- info: 'Bogo.Proofs.encode_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.encode_injective

/-- info: 'Bogo.Proofs.sigMsg_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.sigMsg_injective

/-- info: 'Bogo.Proofs.encodeValue_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Bogo.Proofs.encodeValue_injective
