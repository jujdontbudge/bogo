/-
The Rust↔Lean wire codec (ARCHITECTURE §3.1, §3.4).

Rust sends each `Input` as bytes and Lean decodes it here, so malformed input is handled by
proved code: `stepBytes` leaves the state unchanged on anything `decodeInput` rejects. Lean
encodes the `Output`s and the next deadline the same way. Primitives are the request
encoding's: `u32` big-endian lengths and counts, `u64` big-endian numbers, `opt(x) := 0x00 |
0x01 x`, `str := u32 len utf8`, `bytes := u32 len raw`, values in the request value grammar.

```
input   := u8 tag | fields (by tag, below) — and nothing after
  0x00 configure       u64 seq | config | list(catalogEntry)
  0x01 approverSet     u64 seq | bytes id | str name | u16 alg | bytes pk
  0x02 approverRevoked u64 seq | bytes id
  0x03 agentSet        u64 seq | bytes id | str name
  0x04 agentRevoked    u64 seq | bytes id
  0x05 ownerPause      u64 seq | bytes agent
  0x06 agentUnpaused   u64 seq | bytes id
  0x07 ownerCancel     bytes req
  0x08 sessionOpened   bytes session | bytes agent | opt(str) client
  0x09 sessionClosed   bytes session
  0x0A call            bytes call | bytes session | str name | opt(value) args | u64 now
  0x0B callEnded       bytes call
  0x0C approval        bytes approver | bytes req | u16 alg | bytes proof | u64 now
  0x0D denial          bytes approver | bytes req | opt(str) note
  0x0E pauseAgent      bytes approver | bytes agent | u64 epoch
  0x0F dispatch        bytes call | u64 now
  0x10 notSent         bytes call
  0x11 tick            u64 now
config       := u8 default(0 approve, 1 deny) | u64 maxPending | list(str name, toolPolicy)
                | list(override)
toolPolicy   := u8 kind(0 allow, 1 approve, 2 deny) | u8 justificationRequired(0, 1)
                | list(hint) | opt(u64) expiryMs | list(str) approvers | requirement
                | u8 denyRule(0 anyDenial, 1 whenUnreachable) | u8 mode(0 wait, 1 pendingRetry)
requirement  := 0x00 anyOf | 0x01 u32 k
override     := str agentName | str tool | opt(u8 kind) | opt(list(str)) | opt(requirement)
catalogEntry := str name | str upstream | str tool | str justKey

outputs := list(output) | opt(u64) nextDeadline
output  := u8 tag | fields
  0x00 authorized    bytes call | opt(bytes) req
  0x01 forward       bytes call | opt(bytes) req | str upstream | str tool | opt(value) args
                     | u64 registrySeq
  0x02 attach        bytes call | bytes primary
  0x03 reject        bytes call | rejection
  0x04 pendingApproval bytes call
  0x05 ask           bytes req | bytes requestBytes | list(bytes) to | bytes groupKey
                     | u64 pauseEpoch
  0x06 settled       bytes req | list(bytes) to
  0x07 ended         bytes req | u8 endReason | list(bytes) to
  0x08 counted       bytes req | bytes approver
  0x09 ignored       bytes req | bytes approver | u8 ignoreReason
  0x0A floodDropped  bytes call
  0x0B agentPaused   bytes agent
rejection := u8 tag (order of `Rejection`) | for `denied` (tag 0x0A): opt(str) note
```
-/
import BogoCore.Core

namespace Bogo.Wire
open Bogo

/-! ### Decoding inputs -/

def decNat64 : Dec Nat := decU64

def decU16v : Dec UInt16 := fun r =>
  match decU16 r with
  | some (n, r) => some (UInt16.ofNat n, r)
  | none => none

def decBool : Dec Bool
  | b :: r => if b = 0 then some (false, r) else if b = 1 then some (true, r) else none
  | [] => none

def decKind : Dec PolicyKind
  | b :: r =>
    if b = 0 then some (.allow, r) else if b = 1 then some (.approve, r)
    else if b = 2 then some (.deny, r) else none
  | [] => none

def decDefault : Dec DefaultPolicy
  | b :: r => if b = 0 then some (.approve, r) else if b = 1 then some (.deny, r) else none
  | [] => none

def decRequirement : Dec Requirement
  | b :: r =>
    if b = 0 then some (.anyOf, r)
    else if b = 1 then
      match decU32 r with
      | some (k, r) => some (.kOfN k, r)
      | none => none
    else none
  | [] => none

def decDenyRule : Dec DenyRule
  | b :: r =>
    if b = 0 then some (.anyDenial, r) else if b = 1 then some (.whenUnreachable, r) else none
  | [] => none

def decMode : Dec Mode
  | b :: r => if b = 0 then some (.wait, r) else if b = 1 then some (.pendingRetry, r) else none
  | [] => none

def decToolPolicy : Dec ToolPolicy :=
  Dec.bind decKind fun kind =>
  Dec.bind decBool fun justificationRequired =>
  Dec.bind (decList decHint) fun hints =>
  Dec.bind (decOpt decU64) fun expiryMs =>
  Dec.bind (decList decStr) fun approvers =>
  Dec.bind decRequirement fun requirement =>
  Dec.bind decDenyRule fun denyRule =>
  Dec.bind decMode fun mode =>
  fun r => some ({ kind, justificationRequired, hints, expiryMs, approvers, requirement,
                   denyRule, mode }, r)

def decToolEntry : Dec (String × ToolPolicy) :=
  Dec.bind decStr fun name =>
  Dec.bind decToolPolicy fun p =>
  fun r => some ((name, p), r)

def decOverride : Dec AgentOverride :=
  Dec.bind decStr fun agentName =>
  Dec.bind decStr fun tool =>
  Dec.bind (decOpt decKind) fun kind =>
  Dec.bind (decOpt (decList decStr)) fun approvers =>
  Dec.bind (decOpt decRequirement) fun requirement =>
  fun r => some ({ agentName, tool, kind, approvers, requirement }, r)

def decConfig : Dec PolicyConfig :=
  Dec.bind decDefault fun defaultPolicy =>
  Dec.bind decU64 fun maxPending =>
  Dec.bind (decList decToolEntry) fun tools =>
  Dec.bind (decList decOverride) fun overrides =>
  fun r => some ({ defaultPolicy, maxPending, tools, overrides }, r)

def decCatalogEntry : Dec CatalogEntry :=
  Dec.bind decStr fun name =>
  Dec.bind decStr fun upstream =>
  Dec.bind decStr fun tool =>
  Dec.bind decStr fun justKey =>
  fun r => some ({ name, upstream, tool, justKey }, r)

def done {α : Type} (a : α) : Dec α := fun r => some (a, r)

/-- The fields of an input, by tag. `fuel` bounds the nesting depth of argument values. -/
def decInputBody (fuel : Nat) (tag : UInt8) : Dec Input :=
  match tag.toNat with
  | 0 =>
    Dec.bind decU64 fun seq => Dec.bind decConfig fun cfg =>
    Dec.bind (decList decCatalogEntry) fun cat => done (.configure seq cfg cat)
  | 1 =>
    Dec.bind decU64 fun seq => Dec.bind decBytes fun id => Dec.bind decStr fun name =>
    Dec.bind decU16v fun alg => Dec.bind decBytes fun pk =>
    done (.approverSet seq { id, name, alg, pk })
  | 2 => Dec.bind decU64 fun seq => Dec.bind decBytes fun id => done (.approverRevoked seq id)
  | 3 =>
    Dec.bind decU64 fun seq => Dec.bind decBytes fun id => Dec.bind decStr fun name =>
    done (.agentSet seq id name)
  | 4 => Dec.bind decU64 fun seq => Dec.bind decBytes fun id => done (.agentRevoked seq id)
  | 5 => Dec.bind decU64 fun seq => Dec.bind decBytes fun a => done (.ownerPause seq a)
  | 6 => Dec.bind decU64 fun seq => Dec.bind decBytes fun id => done (.agentUnpaused seq id)
  | 7 => Dec.bind decBytes fun r => done (.ownerCancel r)
  | 8 =>
    Dec.bind decBytes fun sid => Dec.bind decBytes fun a => Dec.bind (decOpt decStr) fun cl =>
    done (.sessionOpened sid a cl)
  | 9 => Dec.bind decBytes fun sid => done (.sessionClosed sid)
  | 10 =>
    Dec.bind decBytes fun c => Dec.bind decBytes fun sid => Dec.bind decStr fun name =>
    Dec.bind (decOpt (decVal fuel)) fun args => Dec.bind decU64 fun now =>
    done (.call c sid name args now)
  | 11 => Dec.bind decBytes fun c => done (.callEnded c)
  | 12 =>
    Dec.bind decBytes fun a => Dec.bind decBytes fun r => Dec.bind decU16v fun alg =>
    Dec.bind decBytes fun proof => Dec.bind decU64 fun now =>
    done (.approval a r alg proof now)
  | 13 =>
    Dec.bind decBytes fun a => Dec.bind decBytes fun r => Dec.bind (decOpt decStr) fun note =>
    done (.denial a r note)
  | 14 =>
    Dec.bind decBytes fun a => Dec.bind decBytes fun ag => Dec.bind decU64 fun ep =>
    done (.pauseAgent a ag ep)
  | 15 => Dec.bind decBytes fun c => Dec.bind decU64 fun now => done (.dispatch c now)
  | 16 => Dec.bind decBytes fun c => done (.notSent c)
  | 17 => Dec.bind decU64 fun now => done (.tick now)
  | _ => fun _ => none

/-- Decode one input; `none` unless the bytes are exactly one well-formed input. -/
def decodeInputL : List UInt8 → Option Input
  | [] => none
  | tag :: r =>
    match decInputBody r.length tag r with
    | some (i, []) => some i
    | _ => none

def decodeInput (b : ByteArray) : Option Input := decodeInputL (rawBytes b)

/-- For a malformed input that still names a call, the call it names, so its waiter hears
"malformed". -/
def peekCallId (b : ByteArray) : CallId :=
  match rawBytes b with
  | tag :: r =>
    if tag = 10 || tag = 11 || tag = 15 || tag = 16 then
      match decBytes r with
      | some (c, _) => c
      | none => ByteArray.empty
    else ByteArray.empty
  | [] => ByteArray.empty

/-! ### Encoding outputs -/

def encRejection : Rejection → List UInt8
  | .malformed => [0]
  | .unknownSession => [1]
  | .unknownAgent => [2]
  | .revokedAgent => [3]
  | .pausedAgent => [4]
  | .duplicateCall => [5]
  | .unknownTool => [6]
  | .denyPolicy => [7]
  | .justificationRequired => [8]
  | .noEligibleApprover => [9]
  | .denied note => 10 :: encOpt encStr note
  | .endedWithoutDecision => [11]
  | .notAuthorized => [12]
  | .gateClosed => [13]
  | .upstreamUnavailable => [14]
  | .exhausted => [15]

def encEndReason : EndReason → UInt8
  | .denied => 0
  | .cancelled => 1
  | .callEnded => 2
  | .sessionClosed => 3
  | .agentRevoked => 4
  | .agentPaused => 5
  | .expired => 6
  | .unreachable => 7
  | .dispatchFailed => 8
  | .notSent => 9

def encIgnoreReason : IgnoreReason → UInt8
  | .unknown => 0
  | .settled => 1
  | .expired => 2
  | .notEligible => 3
  | .duplicate => 4
  | .badSignature => 5
  | .staleEpoch => 6

def encOutput : Output → List UInt8
  | .authorized c r => 0 :: encBytes c ++ encOpt encBytes r
  | .forward c r u t args seq =>
    1 :: encBytes c ++ encOpt encBytes r ++ encStr u ++ encStr t ++ encOpt encVal args ++
      encU64 seq
  | .attach c p => 2 :: encBytes c ++ encBytes p
  | .reject c why => 3 :: encBytes c ++ encRejection why
  | .pendingApproval c => 4 :: encBytes c
  | .ask r bytes to gk ep =>
    5 :: encBytes r ++ encBytes bytes ++ encList encBytes to ++ encBytes gk ++ encU64 ep
  | .settled r to => 6 :: encBytes r ++ encList encBytes to
  | .ended r why to => 7 :: encBytes r ++ [encEndReason why] ++ encList encBytes to
  | .counted r a => 8 :: encBytes r ++ encBytes a
  | .ignored r a why => 9 :: encBytes r ++ encBytes a ++ [encIgnoreReason why]
  | .floodDropped c => 10 :: encBytes c
  | .agentPaused a => 11 :: encBytes a

def encodeOutputs (outs : List Output) (deadline : Option Nat) : ByteArray :=
  ⟨(encList encOutput outs ++ encOpt encU64 deadline).toArray⟩

/-! ### The byte-level step -/

/-- One step on raw bytes: anything `decodeInput` rejects leaves the state unchanged and
produces only `reject(call, malformed)`. -/
def stepBytes (s : State) (b : ByteArray) : State × List Output × Option Nat :=
  match decodeInput b with
  | some i => step s i
  | none => (s, [.reject (peekCallId b) .malformed], nextDeadline s)

end Bogo.Wire
