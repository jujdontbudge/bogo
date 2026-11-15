/-
The exports the C shim calls (ARCHITECTURE §3.1, §3.4). Lean exports are `bogo_lean_*`; the
shim's own ABI is `bogo_core_*`; the Rust verifier is `bogo_rs_verify`.

Exported functions take their arguments owned (Lean does not allow borrow annotations on
`@[export]`); the shim passes a fresh reference for each call.
-/
import BogoCore.Wire

namespace Bogo.Ffi
open Bogo Bogo.Wire

/-- The Rust↔Lean wire and C ABI version. Rust refuses to start if it differs. -/
def abi : UInt32 := 1

@[export bogo_lean_abi]
def abiFfi (_ : Unit) : UInt32 := abi

@[export bogo_lean_init]
def initFfi (bogoId bootId : ByteArray) : State := initState bogoId bootId

/-- One step: decode the input bytes (in Lean), run `step`, encode the outputs. -/
@[export bogo_lean_step]
def stepFfi (s : State) (input : ByteArray) : State × ByteArray :=
  let (s', outs, deadline) := stepBytes s input
  (s', encodeOutputs outs deadline)

/-- Canonical request bytes come back unchanged; anything else gives the empty array (which is
never a request, since every request starts with the magic). -/
@[export bogo_lean_decode_request]
def decodeRequestFfi (b : ByteArray) : ByteArray :=
  match decode b with
  | some r => encode r
  | none => ByteArray.empty

/-- Whether `proof` is a valid approval of these canonical request bytes under `pk`. -/
@[export bogo_lean_check_approval]
def checkApprovalFfi (alg : UInt16) (pk req proof : ByteArray) : Bool :=
  (decode req).isSome && verify alg pk (sigMsg req) proof

end Bogo.Ffi
