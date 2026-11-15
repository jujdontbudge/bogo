/-
BOGO's exact JSON value tree (ARCHITECTURE §3.1, §3.2).

* Numbers keep their exact source text. `4700`, `4700.0`, `4.7e3`, `4.7E3`, `4.7e+3` and `-0`
  are six different values, and nothing here ever reads a number as a number.
* Strings are sequences of Unicode scalar values (Lean `String`s are valid UTF-8 by
  construction), so escape spelling in JSON source is syntax, not a different value.
* Object keys are kept strictly ascending by their UTF-8 bytes. That rules out duplicate
  keys and makes key order in the source irrelevant.

This module also defines the exact JSON writer: the one text every BOGO writer (Rust's
`bogo-json`, and anything else) must produce for a value, byte for byte.
-/

namespace Bogo

/-- The exact JSON tree. Canonical values (`JVal.wf`) have object keys strictly ascending by
UTF-8 bytes and number texts that match the RFC 8259 number grammar. -/
inductive JVal where
  | null
  | bool (b : Bool)
  | num (text : String)
  | str (s : String)
  | arr (xs : List JVal)
  | obj (kvs : List (String × JVal))
  deriving Repr, Inhabited

/-- The UTF-8 bytes of a string, as a list. -/
def utf8 (s : String) : List UInt8 := s.toUTF8.data.toList

/-! ### Equality -/

mutual
/-- Structural equality on values. -/
def JVal.beq : JVal → JVal → Bool
  | .null, .null => true
  | .bool a, .bool b => a == b
  | .num a, .num b => a == b
  | .str a, .str b => a == b
  | .arr xs, .arr ys => JVal.beqArr xs ys
  | .obj xs, .obj ys => JVal.beqObj xs ys
  | _, _ => false

def JVal.beqArr : List JVal → List JVal → Bool
  | [], [] => true
  | x :: xs, y :: ys => JVal.beq x y && JVal.beqArr xs ys
  | _, _ => false

def JVal.beqObj : List (String × JVal) → List (String × JVal) → Bool
  | [], [] => true
  | (k, x) :: xs, (l, y) :: ys => k == l && JVal.beq x y && JVal.beqObj xs ys
  | _, _ => false
end

instance : BEq JVal := ⟨JVal.beq⟩

/-! ### Byte order of keys -/

/-- Strict lexicographic order on byte strings. -/
def bytesLt : List UInt8 → List UInt8 → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => if a < b then true else if a = b then bytesLt as bs else false

/-- Keys strictly ascending by UTF-8 bytes (so no duplicates). -/
def keysAsc : List String → Bool
  | [] => true
  | [_] => true
  | a :: b :: rest => bytesLt (utf8 a) (utf8 b) && keysAsc (b :: rest)

/-! ### The JSON number grammar (RFC 8259 §6), on ASCII bytes

```
number = [ "-" ] int [ frac ] [ exp ]
int    = "0" / ( digit1-9 *DIGIT )
frac   = "." 1*DIGIT
exp    = ( "e" / "E" ) [ "-" / "+" ] 1*DIGIT
```
-/

def isDigit (b : UInt8) : Bool := 48 ≤ b && b ≤ 57

/-- Consume one or more digits. -/
def numDigits1 : List UInt8 → Option (List UInt8)
  | b :: r => if isDigit b then some (r.dropWhile isDigit) else none
  | [] => none

def numInt : List UInt8 → Option (List UInt8)
  | b :: r =>
    if b = 48 then some r
    else if 49 ≤ b && b ≤ 57 then some (r.dropWhile isDigit)
    else none
  | [] => none

def numFrac : List UInt8 → Option (List UInt8)
  | b :: r => if b = 46 then numDigits1 r else some (b :: r)
  | [] => some []

def numSign : List UInt8 → List UInt8
  | b :: r => if b = 43 || b = 45 then r else b :: r
  | [] => []

def numExp : List UInt8 → Option (List UInt8)
  | b :: r => if b = 101 || b = 69 then numDigits1 (numSign r) else some (b :: r)
  | [] => some []

def numMinus : List UInt8 → List UInt8
  | b :: r => if b = 45 then r else b :: r
  | [] => []

/-- Whether the bytes are exactly one JSON number, with nothing before or after. -/
def isJsonNumber (bs : List UInt8) : Bool :=
  match numInt (numMinus bs) >>= numFrac >>= numExp with
  | some [] => true
  | _ => false

/-! ### Canonical values -/

/-- The bound on every length and count in the encoding (`u32`). -/
abbrev u32Bound : Nat := 4294967296

mutual
/-- A canonical value: number texts follow the JSON grammar, object keys are strictly
ascending by UTF-8 bytes, and every length and count fits in a `u32`. -/
def JVal.wf : JVal → Bool
  | .null => true
  | .bool _ => true
  | .num t => isJsonNumber (utf8 t) && decide ((utf8 t).length < u32Bound)
  | .str s => decide ((utf8 s).length < u32Bound)
  | .arr xs => decide (xs.length < u32Bound) && JVal.wfArr xs
  | .obj kvs => decide (kvs.length < u32Bound) && keysAsc (kvs.map (·.1)) && JVal.wfObj kvs

def JVal.wfArr : List JVal → Bool
  | [] => true
  | x :: xs => JVal.wf x && JVal.wfArr xs

def JVal.wfObj : List (String × JVal) → Bool
  | [] => true
  | (k, v) :: kvs => decide ((utf8 k).length < u32Bound) && JVal.wf v && JVal.wfObj kvs
end

/-! ### Building objects -/

/-- Insert into a list sorted strictly by key bytes; `none` on a duplicate key. -/
def insertKey (k : String) (v : JVal) : List (String × JVal) → Option (List (String × JVal))
  | [] => some [(k, v)]
  | (k', v') :: rest =>
    if bytesLt (utf8 k) (utf8 k') then some ((k, v) :: (k', v') :: rest)
    else if utf8 k = utf8 k' then none
    else ((k', v') :: ·) <$> insertKey k v rest

/-- Sort object members by key bytes. `none` if any key occurs twice. -/
def sortKeys : List (String × JVal) → Option (List (String × JVal))
  | [] => some []
  | (k, v) :: rest => sortKeys rest >>= insertKey k v

/-- Build an object from members in any order. `none` on a duplicate key. -/
def JVal.objOf? (kvs : List (String × JVal)) : Option JVal := JVal.obj <$> sortKeys kvs

/-! ### The exact writer

Compact JSON with no whitespace. Keys come out in their (sorted) tree order. Numbers come out
as their exact text. Strings escape only what JSON requires: `"` and `\` as `\"` and `\\`;
U+0008, U+0009, U+000A, U+000C, U+000D as `\b`, `\t`, `\n`, `\f`, `\r`; every other code
point below U+0020 as `\u00xx` with lowercase hex. Everything else, including U+007F,
U+2028 and U+2029 and every non-ASCII character, is written as raw UTF-8.
-/

def hexDigitLower (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def escapeChar (c : Char) : String :=
  if c = '"' then "\\\""
  else if c = '\\' then "\\\\"
  else if c.toNat = 8 then "\\b"
  else if c.toNat = 9 then "\\t"
  else if c.toNat = 10 then "\\n"
  else if c.toNat = 12 then "\\f"
  else if c.toNat = 13 then "\\r"
  else if c.toNat < 32 then
    "\\u00" ++ String.singleton (hexDigitLower (c.toNat / 16)) ++
      String.singleton (hexDigitLower (c.toNat % 16))
  else String.singleton c

def writeString (s : String) : String :=
  "\"" ++ String.join (s.toList.map escapeChar) ++ "\""

mutual
/-- The exact JSON text of a value. -/
def JVal.write : JVal → String
  | .null => "null"
  | .bool true => "true"
  | .bool false => "false"
  | .num t => t
  | .str s => writeString s
  | .arr xs => "[" ++ JVal.writeArr xs ++ "]"
  | .obj kvs => "{" ++ JVal.writeObj kvs ++ "}"

def JVal.writeArr : List JVal → String
  | [] => ""
  | [x] => JVal.write x
  | x :: xs => JVal.write x ++ "," ++ JVal.writeArr xs

def JVal.writeObj : List (String × JVal) → String
  | [] => ""
  | [(k, v)] => writeString k ++ ":" ++ JVal.write v
  | (k, v) :: kvs => writeString k ++ ":" ++ JVal.write v ++ "," ++ JVal.writeObj kvs
end

end Bogo
