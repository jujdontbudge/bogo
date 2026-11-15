/-
A strict JSON text parser, used only by the vector generator.

It turns each vector's JSON source text into the `JVal` the vectors record, independently of
Rust's `bogo-json`, so the two parsers check each other. It follows RFC 8259 strictly:
numbers keep their exact text, duplicate keys are refused, lone surrogates (escaped or as
raw bytes) are refused, raw control characters inside strings are refused, and nothing may
follow the value but whitespace.

Error kinds are the same words `bogo-json` reports: `syntax`, `bad_number`,
`control_character`, `bad_escape`, `lone_surrogate`, `invalid_utf8`, `duplicate_key`,
`trailing`.
-/
import BogoCore.Json

namespace Bogo.Vectors
open Bogo


def isWs (b : UInt8) : Bool := b = 0x20 || b = 0x09 || b = 0x0A || b = 0x0D

def skipWs (l : List UInt8) : List UInt8 := l.dropWhile isWs

def isNumByte (b : UInt8) : Bool :=
  isDigit b || b = 0x2D || b = 0x2B || b = 0x2E || b = 0x65 || b = 0x45

def hexVal (b : UInt8) : Option Nat :=
  if 48 ≤ b && b ≤ 57 then some (b.toNat - 48)
  else if 97 ≤ b && b ≤ 102 then some (b.toNat - 87)
  else if 65 ≤ b && b ≤ 70 then some (b.toNat - 55)
  else none

def hex4 : List UInt8 → Option (Nat × List UInt8)
  | a :: b :: c :: d :: r => do
    let a ← hexVal a; let b ← hexVal b; let c ← hexVal c; let d ← hexVal d
    some (((a * 16 + b) * 16 + c) * 16 + d, r)
  | _ => none

def charBytes (n : Nat) : List UInt8 := utf8 (String.singleton (Char.ofNat n))

/-- The body of a string, after the opening quote. `acc` holds raw UTF-8 bytes, reversed. -/
partial def strBody (acc : List UInt8) : List UInt8 → Except String (String × List UInt8)
  | [] => .error "syntax"
  | b :: r =>
    if b = 0x22 then
      match String.fromUTF8? ⟨acc.reverse.toArray⟩ with
      | some s => .ok (s, r)
      | none =>
        -- Raw bytes ED A0..BF xx are UTF-8-encoded surrogates; name them as such.
        if (acc.reverse.zip (acc.reverse.drop 1)).any (fun (x, y) => x = 0xED && y ≥ 0xA0)
        then .error "lone_surrogate" else .error "invalid_utf8"
    else if b = 0x5C then
      match r with
      | [] => .error "syntax"
      | e :: r =>
        if e = 0x22 then strBody (0x22 :: acc) r
        else if e = 0x5C then strBody (0x5C :: acc) r
        else if e = 0x2F then strBody (0x2F :: acc) r
        else if e = 0x62 then strBody (0x08 :: acc) r
        else if e = 0x66 then strBody (0x0C :: acc) r
        else if e = 0x6E then strBody (0x0A :: acc) r
        else if e = 0x72 then strBody (0x0D :: acc) r
        else if e = 0x74 then strBody (0x09 :: acc) r
        else if e = 0x75 then
          match hex4 r with
          | none => .error "bad_escape"
          | some (u, r) =>
            if 0xD800 ≤ u && u ≤ 0xDBFF then
              match r with
              | 0x5C :: 0x75 :: r' =>
                match hex4 r' with
                | some (lo, r'') =>
                  if 0xDC00 ≤ lo && lo ≤ 0xDFFF then
                    let c := 0x10000 + (u - 0xD800) * 0x400 + (lo - 0xDC00)
                    strBody ((charBytes c).reverse ++ acc) r''
                  else .error "lone_surrogate"
                | none => .error "bad_escape"
              | _ => .error "lone_surrogate"
            else if 0xDC00 ≤ u && u ≤ 0xDFFF then .error "lone_surrogate"
            else strBody ((charBytes u).reverse ++ acc) r
        else .error "bad_escape"
    else if b < 0x20 then .error "control_character"
    else strBody (b :: acc) r

def literal (word : List UInt8) (v : JVal) (l : List UInt8) : Except String (JVal × List UInt8) :=
  if l.take word.length = word then .ok (v, l.drop word.length) else .error "syntax"

mutual
partial def value (l : List UInt8) : Except String (JVal × List UInt8) :=
  match skipWs l with
  | [] => .error "syntax"
  | b :: r =>
    if b = 0x7B then members [] (skipWs r) true
    else if b = 0x5B then elements [] (skipWs r) true
    else if b = 0x22 then (strBody [] r).map fun (s, r) => (.str s, r)
    else if b = 0x74 then literal (utf8 "true") (.bool true) (b :: r)
    else if b = 0x66 then literal (utf8 "false") (.bool false) (b :: r)
    else if b = 0x6E then literal (utf8 "null") .null (b :: r)
    else if b = 0x2D || isDigit b then
      let text := (b :: r).takeWhile isNumByte
      if isJsonNumber text then
        match String.fromUTF8? ⟨text.toArray⟩ with
        | some t => .ok (.num t, (b :: r).drop text.length)
        | none => .error "bad_number"
      else .error "bad_number"
    else if b = 0x2B || b = 0x2E then .error "bad_number"
    else .error "syntax"

/-- Object members after `{`, members so far reversed. -/
partial def members (acc : List (String × JVal)) (l : List UInt8) (first : Bool) :
    Except String (JVal × List UInt8) :=
  match l with
  | 0x7D :: r =>
    if first then .ok (.obj [], r)
    else .error "syntax"
  | 0x22 :: r => do
    let (k, r) ← strBody [] r
    match skipWs r with
    | 0x3A :: r => do
      let (v, r) ← value r
      let acc := (k, v) :: acc
      match skipWs r with
      | 0x2C :: r => members acc (skipWs r) false
      | 0x7D :: r =>
        match JVal.objOf? acc.reverse with
        | some o => .ok (o, r)
        | none => .error "duplicate_key"
      | _ => .error "syntax"
    | _ => .error "syntax"
  | _ => .error "syntax"

/-- Array elements after `[`, elements so far reversed. -/
partial def elements (acc : List JVal) (l : List UInt8) (first : Bool) : Except String (JVal × List UInt8) :=
  match l with
  | 0x5D :: r => if first then .ok (.arr [], r) else .error "syntax"
  | _ => do
    let (v, r) ← value l
    let acc := v :: acc
    match skipWs r with
    | 0x2C :: r => elements acc (skipWs r) false
    | 0x5D :: r => .ok (.arr acc.reverse, r)
    | _ => .error "syntax"
end

/-- Parse a whole JSON text. -/
def parse (bytes : List UInt8) : Except String JVal := do
  let (v, r) ← value bytes
  if skipWs r = [] then pure v else throw "trailing"

end Bogo.Vectors
