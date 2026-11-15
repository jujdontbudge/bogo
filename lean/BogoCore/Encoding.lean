/-
The signed request encoding (ADR 0001, ARCHITECTURE §3.2).

A tagged, length-prefixed binary format. All lengths and counts are `u32` big-endian.

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
list(x)  := u32 count x*
```

The encoder works on `List UInt8` so that the proofs in `BogoProofs.Encoding` stay short;
`encode` and `decode` wrap it in `ByteArray`. `decode` rejects every byte string that is not
exactly the encoding of a canonical request: bad magic or version, an unknown or misplaced
tag, a bad option byte, a length running past the end, invalid UTF-8, a number text outside
the JSON grammar, unsorted or duplicate object keys, and trailing bytes.
-/
import BogoCore.Json

namespace Bogo

abbrev AgentId := ByteArray
abbrev SessionId := ByteArray
/-- 40 bytes: bootId (32) ‖ u64 seq. The nonce and the request ID everywhere. -/
abbrev ReqId := ByteArray

/-- One step of a path into the arguments. -/
inductive PathElem where
  | key (k : String)
  | index (i : Nat)
  deriving Repr, DecidableEq, Inhabited

abbrev Path := List PathElem

/-- How the approver displays a highlighted field. `"usd_cents"` is `moneyMinor "USD"`. -/
inductive Format where
  | text
  | moneyMinor (iso4217 : String)
  deriving Repr, DecidableEq, Inhabited

/-- An approval request: exactly the fields of SPEC §3.6, nothing more. -/
structure Request where
  bogoId : ByteArray
  upstream : String
  tool : String
  /-- `none` when the agent sent no `arguments` at all; different from `some (obj [])`. -/
  args : Option JVal
  /-- `none` when no justification was given; different from `some ""`. -/
  justification : Option String
  hints : List (Path × Format)
  agentId : AgentId
  agentName : String
  clientName : Option String
  session : SessionId
  nonce : ReqId
  createdMs : Nat
  expiresMs : Option Nat
  deriving Inhabited

instance : BEq Request where
  beq a b :=
    a.bogoId == b.bogoId && a.upstream == b.upstream && a.tool == b.tool &&
    a.args == b.args && a.justification == b.justification && a.hints == b.hints &&
    a.agentId == b.agentId && a.agentName == b.agentName && a.clientName == b.clientName &&
    a.session == b.session && a.nonce == b.nonce && a.createdMs == b.createdMs &&
    a.expiresMs == b.expiresMs

/-! ### Primitive encoders -/

abbrev u64Bound : Nat := 18446744073709551616

def u8 (n : Nat) : UInt8 := UInt8.ofNat n

def encU16 (n : Nat) : List UInt8 := [u8 (n / 256), u8 n]

def encU32 (n : Nat) : List UInt8 := [u8 (n / 16777216), u8 (n / 65536), u8 (n / 256), u8 n]

def encU64 (n : Nat) : List UInt8 := encU32 (n / u32Bound) ++ encU32 n

/-- Raw bytes of a `ByteArray`, as a list. -/
def rawBytes (b : ByteArray) : List UInt8 := b.data.toList

def encBytes (b : ByteArray) : List UInt8 := encU32 b.size ++ rawBytes b

def encStr (s : String) : List UInt8 := encU32 (utf8 s).length ++ utf8 s

def encOpt {α : Type} (f : α → List UInt8) : Option α → List UInt8
  | none => [0]
  | some a => 1 :: f a

def encList {α : Type} (f : α → List UInt8) (xs : List α) : List UInt8 :=
  encU32 xs.length ++ (xs.map f).flatten

/-! ### Values -/

mutual
def encVal : JVal → List UInt8
  | .null => [0]
  | .bool false => [1]
  | .bool true => [2]
  | .num t => 3 :: encStr t
  | .str s => 4 :: encStr s
  | .arr xs => 5 :: encU32 xs.length ++ encArr xs
  | .obj kvs => 6 :: encU32 kvs.length ++ encObj kvs

def encArr : List JVal → List UInt8
  | [] => []
  | x :: xs => encVal x ++ encArr xs

def encObj : List (String × JVal) → List UInt8
  | [] => []
  | (k, v) :: kvs => encStr k ++ encVal v ++ encObj kvs
end

/-! ### Hints -/

def encPathElem : PathElem → List UInt8
  | .key k => 0 :: encStr k
  | .index i => 1 :: encU32 i

def encFormat : Format → List UInt8
  | .text => [0]
  | .moneyMinor c => 1 :: encStr c

def encHint (h : Path × Format) : List UInt8 := encList encPathElem h.1 ++ encFormat h.2

/-! ### Requests -/

/-- `"BOGOREQ" 0x00`. -/
def magic : List UInt8 := [66, 79, 71, 79, 82, 69, 81, 0]

/-- The only request encoding version this module defines. -/
def version : Nat := 1

/-- The encoding of a request, as a list of bytes. -/
def encodeL (r : Request) : List UInt8 :=
  magic ++ encU16 version ++
  1 :: encBytes r.bogoId ++
  2 :: encStr r.upstream ++
  3 :: encStr r.tool ++
  4 :: encOpt encVal r.args ++
  5 :: encOpt encStr r.justification ++
  6 :: encList encHint r.hints ++
  7 :: encBytes r.agentId ++
  8 :: encStr r.agentName ++
  9 :: encOpt encStr r.clientName ++
  10 :: encBytes r.session ++
  11 :: encBytes r.nonce ++
  12 :: encU64 r.createdMs ++
  13 :: encOpt encU64 r.expiresMs

/-! ### Canonical requests -/

def strOk (s : String) : Bool := decide ((utf8 s).length < u32Bound)
def bytesOk (b : ByteArray) : Bool := decide (b.size < u32Bound)

def PathElem.wf : PathElem → Bool
  | .key k => strOk k
  | .index i => decide (i < u32Bound)

def Format.wf : Format → Bool
  | .text => true
  | .moneyMinor c => strOk c

def hintWf (h : Path × Format) : Bool :=
  decide (h.1.length < u32Bound) && h.1.all PathElem.wf && h.2.wf

def optWf {α : Type} (f : α → Bool) : Option α → Bool
  | none => true
  | some a => f a

/-- A canonical request: every value is canonical and every length, count and number fits
its field. Every request BOGO builds is canonical; `decode` returns only canonical ones. -/
def Request.wf (r : Request) : Bool :=
  bytesOk r.bogoId && strOk r.upstream && strOk r.tool && optWf JVal.wf r.args &&
  optWf strOk r.justification &&
  decide (r.hints.length < u32Bound) && r.hints.all hintWf &&
  bytesOk r.agentId && strOk r.agentName && optWf strOk r.clientName &&
  bytesOk r.session && bytesOk r.nonce &&
  decide (r.createdMs < u64Bound) && optWf (fun e => decide (e < u64Bound)) r.expiresMs

/-! ### Primitive decoders

Each decoder reads a prefix and returns what it read with the rest. -/

abbrev Dec (α : Type) := List UInt8 → Option (α × List UInt8)

def decU8 : Dec UInt8
  | b :: r => some (b, r)
  | [] => none

def decU16 : Dec Nat
  | a :: b :: r => some (a.toNat * 256 + b.toNat, r)
  | _ => none

def decU32 : Dec Nat
  | a :: b :: c :: d :: r =>
    some (a.toNat * 16777216 + b.toNat * 65536 + c.toNat * 256 + d.toNat, r)
  | _ => none

def decU64 : Dec Nat := fun r =>
  match decU32 r with
  | some (hi, r) =>
    match decU32 r with
    | some (lo, r) => some (hi * u32Bound + lo, r)
    | none => none
  | none => none

/-- Exactly `n` bytes. -/
def takeN (n : Nat) : Dec (List UInt8) := fun l =>
  if n ≤ l.length then some (l.take n, l.drop n) else none

def decBytes : Dec ByteArray := fun r =>
  match decU32 r with
  | some (n, r) =>
    match takeN n r with
    | some (bs, r) => some (⟨bs.toArray⟩, r)
    | none => none
  | none => none

def decStr : Dec String := fun r =>
  match decU32 r with
  | some (n, r) =>
    match takeN n r with
    | some (bs, r) =>
      match String.fromUTF8? ⟨bs.toArray⟩ with
      | some s => some (s, r)
      | none => none
    | none => none
  | none => none

/-- A number text: a string whose bytes follow the JSON number grammar. -/
def decNum : Dec String := fun r =>
  match decStr r with
  | some (s, r) => if isJsonNumber (utf8 s) then some (s, r) else none
  | none => none

def decOpt {α : Type} (d : Dec α) : Dec (Option α)
  | b :: r =>
    if b = 0 then some (none, r)
    else if b = 1 then
      match d r with
      | some (a, r) => some (some a, r)
      | none => none
    else none
  | [] => none

/-- `n` items. -/
def decN {α : Type} (d : Dec α) : Nat → Dec (List α)
  | 0, r => some ([], r)
  | n + 1, r =>
    match d r with
    | some (a, r) =>
      match decN d n r with
      | some (as, r) => some (a :: as, r)
      | none => none
    | none => none

def decList {α : Type} (d : Dec α) : Dec (List α) := fun r =>
  match decU32 r with
  | some (n, r) => decN d n r
  | none => none

/-- One expected byte. -/
def expect (t : UInt8) : List UInt8 → Option (List UInt8)
  | b :: r => if b = t then some r else none
  | [] => none

/-! ### Values

`fuel` bounds the nesting depth; `decode` passes the input length, which is always enough
because every nested value takes at least one byte. -/

mutual
def decVal : Nat → Dec JVal
  | 0, _ => none
  | _ + 1, [] => none
  | fuel + 1, b :: r =>
    match b.toNat with
    | 0 => some (.null, r)
    | 1 => some (.bool false, r)
    | 2 => some (.bool true, r)
    | 3 =>
      match decNum r with
      | some (t, r) => some (.num t, r)
      | none => none
    | 4 =>
      match decStr r with
      | some (s, r) => some (.str s, r)
      | none => none
    | 5 =>
      match decU32 r with
      | some (n, r) =>
        match decArr fuel n r with
        | some (xs, r) => some (.arr xs, r)
        | none => none
      | none => none
    | 6 =>
      match decU32 r with
      | some (n, r) =>
        match decObj fuel n r with
        | some (kvs, r) => if keysAsc (kvs.map (·.1)) then some (.obj kvs, r) else none
        | none => none
      | none => none
    | _ => none
  termination_by fuel _ => (fuel, 0)

def decArr (fuel : Nat) : Nat → Dec (List JVal)
  | 0, r => some ([], r)
  | n + 1, r =>
    match decVal fuel r with
    | some (x, r) =>
      match decArr fuel n r with
      | some (xs, r) => some (x :: xs, r)
      | none => none
    | none => none
  termination_by n _ => (fuel, n + 1)

def decObj (fuel : Nat) : Nat → Dec (List (String × JVal))
  | 0, r => some ([], r)
  | n + 1, r =>
    match decStr r with
    | some (k, r) =>
      match decVal fuel r with
      | some (v, r) =>
        match decObj fuel n r with
        | some (kvs, r) => some ((k, v) :: kvs, r)
        | none => none
      | none => none
    | none => none
  termination_by n _ => (fuel, n + 1)
end

/-! ### Hints -/

def decPathElem : Dec PathElem
  | b :: r =>
    if b = 0 then
      match decStr r with
      | some (k, r) => some (.key k, r)
      | none => none
    else if b = 1 then
      match decU32 r with
      | some (i, r) => some (.index i, r)
      | none => none
    else none
  | [] => none

def decFormat : Dec Format
  | b :: r =>
    if b = 0 then some (.text, r)
    else if b = 1 then
      match decStr r with
      | some (c, r) => some (.moneyMinor c, r)
      | none => none
    else none
  | [] => none

def decHint : Dec (Path × Format) := fun r =>
  match decList decPathElem r with
  | some (p, r) =>
    match decFormat r with
    | some (f, r) => some ((p, f), r)
    | none => none
  | none => none

/-! ### Requests -/

/-- A field: its tag byte, then its payload. -/
def field {α : Type} (tag : UInt8) (d : Dec α) : Dec α := fun r =>
  match expect tag r with
  | some r => d r
  | none => none

/-- Sequence two decoders. -/
def Dec.bind {α β : Type} (d : Dec α) (k : α → Dec β) : Dec β := fun r =>
  match d r with
  | some (a, r) => k a r
  | none => none

/-- The thirteen fields, in their fixed order. -/
def decFields (fuel : Nat) : Dec Request :=
  Dec.bind (field 1 decBytes) fun bogoId =>
  Dec.bind (field 2 decStr) fun upstream =>
  Dec.bind (field 3 decStr) fun tool =>
  Dec.bind (field 4 (decOpt (decVal fuel))) fun args =>
  Dec.bind (field 5 (decOpt decStr)) fun justification =>
  Dec.bind (field 6 (decList decHint)) fun hints =>
  Dec.bind (field 7 decBytes) fun agentId =>
  Dec.bind (field 8 decStr) fun agentName =>
  Dec.bind (field 9 (decOpt decStr)) fun clientName =>
  Dec.bind (field 10 decBytes) fun session =>
  Dec.bind (field 11 decBytes) fun nonce =>
  Dec.bind (field 12 decU64) fun createdMs =>
  Dec.bind (field 13 (decOpt decU64)) fun expiresMs =>
  fun r => some ({ bogoId, upstream, tool, args, justification, hints, agentId, agentName,
                   clientName, session, nonce, createdMs, expiresMs }, r)

/-- Decode a request, with `fuel` bounding the nesting depth of the arguments. -/
def decodeFuel (fuel : Nat) (b : List UInt8) : Option Request :=
  match takeN 8 b with
  | some (m, r) =>
    if m = magic then
      match decU16 r with
      | some (v, r) =>
        if v = version then
          match decFields fuel r with
          | some (q, []) => some q
          | _ => none
        else none
      | none => none
    else none
  | none => none

/-- Decode a request from a list of bytes. Returns `none` unless the bytes are exactly the
encoding of a canonical request. The input length is always enough fuel. -/
def decodeL (b : List UInt8) : Option Request := decodeFuel b.length b

/-! ### The public interface -/

/-- The bytes an approver signs (before the domain tag): BOGO's encoding of the request. -/
def encode (r : Request) : ByteArray := ⟨(encodeL r).toArray⟩

/-- Decode request bytes; `none` for anything that is not exactly a canonical encoding. -/
def decode (b : ByteArray) : Option Request := decodeL (rawBytes b)

/-- `"BOGO-APPROVAL" 0x00 "v1"`: the domain tag in front of every signed request. -/
def approvalDomain : List UInt8 :=
  [66, 79, 71, 79, 45, 65, 80, 80, 82, 79, 86, 65, 76, 0, 118, 49]

/-- The exact message an approval signs: the domain tag, then the request bytes. -/
def sigMsg (requestBytes : ByteArray) : ByteArray :=
  ⟨(approvalDomain ++ rawBytes requestBytes).toArray⟩

/-- The value grammar alone, for vectors and for other encodings built on it. -/
def encodeValue (v : JVal) : ByteArray := ⟨(encVal v).toArray⟩

def decodeValue (b : ByteArray) : Option JVal :=
  match decVal (rawBytes b).length (rawBytes b) with
  | some (v, []) => some v
  | _ => none

end Bogo
