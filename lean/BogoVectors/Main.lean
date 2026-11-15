/-
`lake exe BogoVectors [outDir]` writes the shared test vectors (default `../vectors`).

* `json.json`: JSON argument texts with the exact `JVal` they parse to, the exact text the
  writer must produce for it, and the value bytes; plus texts every parser must refuse.
* `requests.json`: approval requests: their argument text, the encoded bytes, the signed
  message, and the request as decoded back from those bytes by the Lean decoder.
* `decode_reject.json`: byte strings the request decoder must refuse.
* `manifest.json`: the toolchain and `BogoCore` commit that produced them.

Every vector is checked here before it is written: each accepted text parses, is canonical,
and round-trips through the writer and the value encoding; each request decodes back to
itself; each rejected text or byte string is refused. The generator exits non-zero otherwise.
Output is deterministic, so regenerating without a change gives identical files.
-/
import BogoCore.Encoding
import BogoVectors.JsonText

namespace Bogo.Vectors
open Bogo

/-! ### Output helpers -/

def hexByte (b : UInt8) : String :=
  String.singleton (hexDigitLower (b.toNat / 16)) ++ String.singleton (hexDigitLower (b.toNat % 16))

def hex (l : List UInt8) : String := String.join (l.map hexByte)

def hexBA (b : ByteArray) : String := hex b.data.toList

def jstr (s : String) : JVal := .str s
/-- A u64 as a decimal string, so readers whose numbers are doubles stay exact. -/
def jnat (n : Nat) : JVal := .str (toString n)
def jcount (n : Nat) : JVal := .num (toString n)
def jopt {α : Type} (f : α → JVal) : Option α → JVal
  | none => .null
  | some a => f a

/-- A JSON object for the vector files, in the order given (not a canonical value). -/
def jobj (kvs : List (String × JVal)) : JVal := .obj kvs

/-- Pretty JSON for the vector files: short values on one line, longer ones split. -/
partial def pretty (indent : String) (v : JVal) : String :=
  let flat := v.write
  if flat.length + indent.length ≤ 100 then flat else
  let ind := indent ++ "  "
  match v with
  | .arr xs =>
    "[\n" ++ String.intercalate ",\n" (xs.map fun x => ind ++ pretty ind x) ++ "\n" ++ indent ++ "]"
  | .obj kvs =>
    "{\n" ++ String.intercalate ",\n"
      (kvs.map fun (k, x) => ind ++ writeString k ++ ": " ++ pretty ind x) ++ "\n" ++ indent ++ "}"
  | _ => flat

/-- The value as a tagged tree that any JSON reader can load without touching numbers:
`["null"]`, `["bool", b]`, `["num", text]`, `["str", s]`, `["arr", [..]]`,
`["obj", [[key, value], ..]]`. -/
partial def tagged : JVal → JVal
  | .null => .arr [jstr "null"]
  | .bool b => .arr [jstr "bool", .bool b]
  | .num t => .arr [jstr "num", jstr t]
  | .str s => .arr [jstr "str", jstr s]
  | .arr xs => .arr [jstr "arr", .arr (xs.map tagged)]
  | .obj kvs => .arr [jstr "obj", .arr (kvs.map fun (k, v) => .arr [jstr k, tagged v])]

def pathJ (p : Path) : JVal :=
  .arr (p.map fun
    | .key k => jobj [("key", jstr k)]
    | .index i => jobj [("index", jnat i)])

def formatJ : Format → JVal
  | .text => jstr "text"
  | .moneyMinor c => jobj [("money_minor", jstr c)]

/-- The decoded form of a request. -/
def requestJ (q : Request) : JVal := jobj [
  ("bogo_id_hex", jstr (hexBA q.bogoId)),
  ("upstream", jstr q.upstream),
  ("tool", jstr q.tool),
  ("args", jopt tagged q.args),
  ("args_written", jopt (fun v => jstr v.write) q.args),
  ("justification", jopt jstr q.justification),
  ("hints", .arr (q.hints.map fun (p, f) => jobj [("path", pathJ p), ("format", formatJ f)])),
  ("agent_id_hex", jstr (hexBA q.agentId)),
  ("agent_name", jstr q.agentName),
  ("client_name", jopt jstr q.clientName),
  ("session_hex", jstr (hexBA q.session)),
  ("nonce_hex", jstr (hexBA q.nonce)),
  ("created_ms", jnat q.createdMs),
  ("expires_ms", jopt jnat q.expiresMs)]

/-! ### Deterministic identifiers -/

/-- `n` pseudo-random bytes from a seed string (a fixed LCG, so vectors never change). -/
def seedBytes (seed : String) (n : Nat) : ByteArray := Id.run do
  let mut x : UInt64 := 1469598103934665603
  for b in utf8 seed do
    x := (x ^^^ b.toUInt64) * 1099511628211
  let mut out : Array UInt8 := #[]
  for _ in [0:n] do
    x := x * 6364136223846793005 + 1442695040888963407
    out := out.push (x >>> 56).toUInt8
  pure ⟨out⟩

def bogoId : ByteArray := seedBytes "bogo-id" 32
def bootId : ByteArray := seedBytes "boot-1" 32

def u64Bytes (n : Nat) : ByteArray := ⟨(encU64 n).toArray⟩

/-- A request ID: bootId (32) ‖ u64 seq. -/
def reqId (seq : Nat) : ByteArray := bootId ++ u64Bytes seq

/-- A session ID: bootId ‖ 16 random bytes. -/
def sessionId (seed : String) : ByteArray := bootId ++ seedBytes seed 16

def agentTrip : ByteArray := seedBytes "agent-trip-planner" 16
def agentResearch : ByteArray := seedBytes "agent-researcher" 16

/-! ### JSON text cases -/

structure TextCase where
  name : String
  about : String
  source : String

/-- Texts every BOGO parser must accept, with the value and writer text the vectors record. -/
def acceptCases : List TextCase := [
  ⟨"int-4700", "an integer amount", "{\"amount\":4700}"⟩,
  ⟨"decimal-4700.0", "4700.0 is a different value from 4700", "{\"amount\":4700.0}"⟩,
  ⟨"exp-4.7e3", "lowercase exponent kept as written", "{\"amount\":4.7e3}"⟩,
  ⟨"exp-4.7E3", "uppercase exponent kept as written, never 4.7e+3 or 4700", "{\"amount\":4.7E3}"⟩,
  ⟨"exp-4.7e+3", "explicit plus sign kept", "{\"amount\":4.7e+3}"⟩,
  ⟨"exp-47e-1", "negative exponent", "{\"amount\":47E-1}"⟩,
  ⟨"neg-zero", "-0 is its own text, not 0", "{\"amount\":-0}"⟩,
  ⟨"neg-zero-decimal", "-0.0", "{\"amount\":-0.0}"⟩,
  ⟨"zero", "plain zero", "0"⟩,
  ⟨"long-integer", "a 400-digit integer, far beyond any float",
    "{\"n\":" ++ String.join (List.replicate 40 "1234567890") ++ "}"⟩,
  ⟨"long-decimal", "a long fraction with a huge exponent",
    "{\"n\":-0." ++ String.join (List.replicate 30 "0000000001") ++ "e-99999}"⟩,
  ⟨"u64-overflow", "integers past 2^64 stay exact", "[18446744073709551616,-9223372036854775809]"⟩,
  ⟨"float-edge", "values that floats would round", "[0.1,1e400,5e-324,9007199254740993]"⟩,
  ⟨"keys-unordered", "keys in any order are sorted by UTF-8 bytes",
    "{\"zeta\":1,\"alpha\":2,\"Mid\":3,\"_x\":4}"⟩,
  ⟨"nested-unordered", "nested objects with keys in different orders and whitespace",
    "{ \"order\" : { \"z\": [ {\"b\":1, \"a\":2} ], \"a\" : {\"y\":null,\"x\":true} },\n  \"amount\":4700 }"⟩,
  ⟨"keys-unicode-order", "byte order, not UTF-16 order: \"z\" < \"é\" < \"😀\" < \"ｚ\"",
    "{\"ｚ\":4,\"😀\":3,\"é\":2,\"z\":1}"⟩,
  ⟨"keys-prefix", "a key sorts before its extensions", "{\"ab\":2,\"a\":1,\"\":0}"⟩,
  ⟨"unicode-raw", "raw UTF-8 text",
    "{\"note\":\"Café ☕ — 東京 → Zürich, שלום, e\u0301\"}"⟩,
  ⟨"unicode-escaped", "\\u escapes and a surrogate pair decode to the same scalars as raw text",
    "{\"note\":\"Caf\\u00e9 \\u2615 \\ud83d\\ude00 \\u6771\\u4eac\"}"⟩,
  ⟨"escapes", "every short escape; the writer uses the canonical spelling",
    "[\"q\\\" b\\\\ s\\/ \\b\\f\\n\\r\\t\"]"⟩,
  ⟨"control-escaped", "escaped control characters, NUL, DEL and U+2028",
    "[\"\\u0000\\u0001\\u001f\\u007f\\u2028\\u2029\"]"⟩,
  ⟨"empty-object", "empty arguments", "{}"⟩,
  ⟨"empty-array", "an empty array", "[]"⟩,
  ⟨"empty-string", "empty string key and value", "{\"\":\"\"}"⟩,
  ⟨"literals", "true, false and null", "[true,false,null]"⟩,
  ⟨"deep", "nesting with mixed containers", "{\"a\":[[[{\"b\":[{\"c\":[1,[2,[3]]]}]}]]]}"⟩,
  ⟨"whitespace", "all four whitespace bytes around everything", " \t\n\r{ \"a\" :\t[ 1 ,2 ]\r\n} \n"⟩,
  ⟨"stripe-like", "a payment-link style argument object",
    "{\"line_items\":[{\"price\":\"price_1PqXyZ\",\"quantity\":1}],\"amount\":4700,\"currency\":\"usd\",\"test\":true,\"metadata\":{\"trip\":\"LJU-SFO\",\"seat\":\"14C\"}}"⟩
]

structure RejectCase where
  name : String
  about : String
  bytes : List UInt8
  why : String

def rj (name about src why : String) : RejectCase := ⟨name, about, utf8 src, why⟩

/-- Texts every BOGO parser must refuse, with the error kind. -/
def rejectCases : List RejectCase := [
  rj "duplicate-key" "the same key twice" "{\"amount\":4700,\"amount\":1}" "duplicate_key",
  rj "duplicate-key-nested" "duplicate deep inside" "{\"a\":[{\"k\":1,\"k\":1}]}" "duplicate_key",
  rj "duplicate-key-escaped" "the same key spelled two ways" "{\"é\":1,\"\\u00e9\":2}" "duplicate_key",
  rj "lone-high-surrogate" "an escaped high surrogate alone" "[\"\\ud800\"]" "lone_surrogate",
  rj "lone-low-surrogate" "an escaped low surrogate alone" "[\"\\udc00\"]" "lone_surrogate",
  rj "high-then-text" "a high surrogate followed by text" "[\"\\ud83dx\"]" "lone_surrogate",
  rj "high-then-high" "two high surrogates" "[\"\\ud83d\\ud83d\"]" "lone_surrogate",
  rj "lone-surrogate-key" "a lone surrogate in a key" "{\"\\udfff\":1}" "lone_surrogate",
  ⟨"raw-surrogate-bytes", "a surrogate encoded directly as UTF-8 bytes",
    [0x5B, 0x22, 0xED, 0xA0, 0x80, 0x22, 0x5D], "lone_surrogate"⟩,
  ⟨"invalid-utf8", "a stray continuation byte", [0x5B, 0x22, 0x80, 0x22, 0x5D], "invalid_utf8"⟩,
  ⟨"overlong-utf8", "an overlong encoding of '/'", [0x5B, 0x22, 0xC0, 0xAF, 0x22, 0x5D],
    "invalid_utf8"⟩,
  ⟨"raw-control", "a raw newline inside a string", [0x5B, 0x22, 0x0A, 0x22, 0x5D],
    "control_character"⟩,
  ⟨"raw-nul", "a raw NUL inside a string", [0x5B, 0x22, 0x00, 0x22, 0x5D], "control_character"⟩,
  rj "leading-zero" "01" "[01]" "bad_number",
  rj "leading-plus" "+1" "[+1]" "bad_number",
  rj "bare-dot" ".5" "[.5]" "bad_number",
  rj "trailing-dot" "1." "[1.]" "bad_number",
  rj "empty-exponent" "1e" "[1e]" "bad_number",
  rj "sign-only-exponent" "1e+" "[1e+]" "bad_number",
  rj "minus-only" "-" "[-]" "bad_number",
  rj "nan" "NaN is not JSON" "[NaN]" "syntax",
  rj "infinity" "Infinity is not JSON" "[Infinity]" "syntax",
  rj "hex-number" "0x10: a 0 then junk" "[0x10]" "syntax",
  rj "bad-escape" "\\x is not an escape" "[\"\\x41\"]" "bad_escape",
  rj "short-unicode-escape" "\\u with three digits" "[\"\\u004\"]" "bad_escape",
  rj "trailing-comma-object" "a trailing comma" "{\"a\":1,}" "syntax",
  rj "trailing-comma-array" "a trailing comma" "[1,]" "syntax",
  rj "single-quotes" "single quotes" "{'a':1}" "syntax",
  rj "unquoted-key" "an unquoted key" "{a:1}" "syntax",
  rj "trailing-value" "two values" "{} {}" "trailing",
  rj "trailing-garbage" "garbage after the value" "[1]x" "trailing",
  rj "empty" "no value at all" "" "syntax",
  rj "only-whitespace" "only whitespace" " \n" "syntax",
  rj "unterminated-string" "a string that never ends" "[\"abc" "syntax",
  rj "unterminated-array" "an array that never ends" "[1,2" "syntax",
  rj "comment" "comments are not JSON" "[1 /* one */]" "syntax",
  rj "bom" "a byte order mark before the value" "\uFEFF{}" "syntax"
]

/-! ### Request cases -/

structure ReqCase where
  name : String
  about : String
  argsSource : Option String
  build : Option JVal → Request

def usdHints : List (Path × Format) :=
  [([.key "amount"], .moneyMinor "USD"), ([.key "currency"], .text), ([.key "test"], .text)]

def stripeTool : String := "create_payment_link"

/-- A Trip planner payment request, with the arguments filled in by the case. -/
def payment (seq : Nat) (just : Option String) (expires : Option Nat) (args : Option JVal) :
    Request := {
  bogoId := bogoId, upstream := "stripe", tool := stripeTool, args, justification := just,
  hints := usdHints, agentId := agentTrip, agentName := "Trip planner",
  clientName := some "claude-code", session := sessionId "session-trip-1", nonce := reqId seq,
  createdMs := 1763200000000 + seq * 1000,
  expiresMs := expires.map fun m => 1763200000000 + seq * 1000 + m }

def flight : Option String := some "booking the 6pm flight you asked for, $47"

def tenMinutes : Option Nat := some 600000

def filesWrite (a : Option JVal) : Request := {
  bogoId := bogoId, upstream := "files", tool := "write_file", args := a,
  justification := some "saving the itinerary", hints := [([.key "path"], .text)],
  agentId := agentTrip, agentName := "Trip planner", clientName := some "claude-code",
  session := sessionId "session-trip-1", nonce := reqId 21, createdMs := 1763200021000,
  expiresMs := none }

def reqCases : List ReqCase := [
  ⟨"payment-approved", "Scenario 1: pay $47, with a justification, no expiry",
    some "{\"amount\":4700,\"currency\":\"usd\",\"test\":true}", payment 1 flight none⟩,
  ⟨"payment-with-expiry", "the same call on a tool with a 10-minute expiry",
    some "{\"amount\":4700,\"currency\":\"usd\",\"test\":true}", payment 2 flight tenMinutes⟩,
  ⟨"amount-4700.0", "4700.0 is a different request from 4700",
    some "{\"amount\":4700.0,\"currency\":\"usd\",\"test\":true}", payment 3 flight none⟩,
  ⟨"amount-4.7e3", "lowercase exponent",
    some "{\"amount\":4.7e3,\"currency\":\"usd\",\"test\":true}", payment 4 flight none⟩,
  ⟨"amount-4.7E3", "uppercase exponent",
    some "{\"amount\":4.7E3,\"currency\":\"usd\",\"test\":true}", payment 5 flight none⟩,
  ⟨"amount-4.7e+3", "explicit plus in the exponent",
    some "{\"amount\":4.7e+3,\"currency\":\"usd\",\"test\":true}", payment 6 flight none⟩,
  ⟨"amount-neg-zero", "-0",
    some "{\"amount\":-0,\"currency\":\"usd\",\"test\":true}", payment 7 flight none⟩,
  ⟨"amount-4701", "Scenario 3: one cent more is a different request",
    some "{\"amount\":4701,\"currency\":\"usd\",\"test\":true}", payment 8 flight none⟩,
  ⟨"lie-in-reason", "Scenario 2: the reason says $5 but the amount is 50000 cents",
    some "{\"amount\":50000,\"currency\":\"usd\",\"test\":true}",
    payment 9 (some "just a small $5 test charge") none⟩,
  ⟨"amount-long", "a 300-digit amount",
    some ("{\"amount\":" ++ String.join (List.replicate 30 "9876543210") ++
      ",\"currency\":\"usd\",\"test\":true}"), payment 10 flight none⟩,
  ⟨"keys-unordered", "the agent sent keys in another order, with whitespace",
    some "{ \"test\" : true, \"currency\" : \"usd\", \"amount\" : 4700 }", payment 11 flight none⟩,
  ⟨"nested-unordered", "nested objects with keys in different orders",
    some "{\"metadata\":{\"seat\":\"14C\",\"trip\":{\"to\":\"SFO\",\"from\":\"LJU\"}},\"amount\":4700,\"line_items\":[{\"quantity\":1,\"price\":\"price_1PqXyZ\"}],\"currency\":\"usd\",\"test\":true}",
    fun a => { payment 12 flight none a with
      hints := usdHints ++ [([.key "line_items", .index 0, .key "price"], .text)] }⟩,
  ⟨"unicode", "unicode in arguments, keys and the justification",
    some "{\"amount\":4700,\"currency\":\"usd\",\"description\":\"Hotel Zürich — 2 nights ☕ \\ud83d\\ude00\",\"東京\":\"→\",\"test\":true}",
    payment 13 (some "rezervacija za Ljubljano, 47 €, okej? 👍") none⟩,
  ⟨"justification-absent", "no justification at all",
    some "{\"amount\":4700,\"currency\":\"usd\",\"test\":true}", payment 14 none none⟩,
  ⟨"justification-empty", "an empty justification is different from none",
    some "{\"amount\":4700,\"currency\":\"usd\",\"test\":true}", payment 15 (some "") none⟩,
  ⟨"args-empty", "empty arguments {}", some "{}",
    fun a => { payment 16 none none a with hints := [] }⟩,
  ⟨"args-absent", "no arguments field at all: different from {}", none,
    fun a => { payment 17 none none a with hints := [] }⟩,
  ⟨"client-name-absent", "a client that reported no name",
    some "{\"amount\":4700,\"currency\":\"usd\",\"test\":true}",
    fun a => { payment 18 flight none a with clientName := none }⟩,
  ⟨"other-session", "the identical call from another session",
    some "{\"amount\":4700,\"currency\":\"usd\",\"test\":true}",
    fun a => { payment 1 flight none a with session := sessionId "session-trip-2", nonce := reqId 19 }⟩,
  ⟨"researcher", "another named agent with k-of-n hints in euro",
    some "{\"amount\":1999,\"currency\":\"eur\",\"test\":true}",
    fun a => { payment 20 (some "monthly dataset licence") tenMinutes a with
      agentId := agentResearch, agentName := "Researcher", clientName := some "cursor",
      session := sessionId "session-research-1",
      hints := [([.key "amount"], .moneyMinor "EUR"), ([.key "currency"], .text)] }⟩,
  ⟨"filesystem-write", "the filesystem upstream: a write with multi-line content",
    some "{\"path\":\"/Users/johansardar/bogo-test/notes.md\",\"content\":\"# Trip\\n\\n- LJU → SFO\\n- \\\"6pm\\\"\\tflight\\n\"}",
    filesWrite⟩,
  ⟨"max-times", "times at the top of the u64 range",
    some "[null,true,false,[],{}]",
    fun a => { payment 22 flight none a with
      hints := [([.index 4294967295], .text)],
      createdMs := 18446744073709551614, expiresMs := some 18446744073709551615 }⟩
]

/-! ### Decoder reject cases -/

def base : Request := payment 1 flight none
  (JVal.objOf? [("amount", .num "4700"), ("currency", .str "usd")])

/-- Hand-encode a request whose args bytes are given directly (to place bad values). -/
def withArgsBytes (argBytes : List UInt8) : List UInt8 :=
  let q := base
  magic ++ encU16 version ++
  1 :: encBytes q.bogoId ++ 2 :: encStr q.upstream ++ 3 :: encStr q.tool ++
  4 :: 1 :: argBytes ++
  5 :: encOpt encStr q.justification ++ 6 :: encList encHint q.hints ++
  7 :: encBytes q.agentId ++ 8 :: encStr q.agentName ++ 9 :: encOpt encStr q.clientName ++
  10 :: encBytes q.session ++ 11 :: encBytes q.nonce ++ 12 :: encU64 q.createdMs ++
  13 :: encOpt encU64 q.expiresMs

def numBytes (t : List UInt8) : List UInt8 := 3 :: encU32 t.length ++ t
def strBytes (t : List UInt8) : List UInt8 := 4 :: encU32 t.length ++ t
def objBytes (kvs : List (List UInt8 × List UInt8)) : List UInt8 :=
  6 :: encU32 kvs.length ++ (kvs.map fun (k, v) => encU32 k.length ++ k ++ v).flatten

def setAt (l : List UInt8) (i : Nat) (b : UInt8) : List UInt8 := l.set i b

def decodeRejects : List (String × String × List UInt8) :=
  let good := encodeL base
  [ ("empty", "no bytes", []),
    ("bad-magic", "magic is BOGOREQ\\0", setAt good 0 0x62),
    ("version-2", "only version 1 is defined", setAt good 9 2),
    ("version-0", "only version 1 is defined", setAt good 9 0),
    ("trailing-byte", "one byte after the last field", good ++ [0]),
    ("truncated", "the last byte missing", good.dropLast),
    ("header-only", "magic and version, no fields", magic ++ encU16 1),
    ("wrong-first-tag", "fields must start with tag 0x01", setAt good 10 2),
    ("unknown-tag", "tag 0x0E after the last field", good ++ [14, 0]),
    ("bad-option-byte", "an option byte other than 0 or 1 (expiresMs)",
      setAt good (good.length - 1) 2),
    ("unsorted-keys", "object keys out of byte order",
      withArgsBytes (objBytes [(utf8 "currency", strBytes (utf8 "usd")),
        (utf8 "amount", numBytes (utf8 "4700"))])),
    ("duplicate-keys", "the same key twice",
      withArgsBytes (objBytes [(utf8 "amount", numBytes (utf8 "4700")),
        (utf8 "amount", numBytes (utf8 "4700"))])),
    ("number-leading-zero", "number text 0100", withArgsBytes (numBytes (utf8 "0100"))),
    ("number-plus", "number text +1", withArgsBytes (numBytes (utf8 "+1"))),
    ("number-space", "number text with a space", withArgsBytes (numBytes (utf8 " 1"))),
    ("number-empty", "empty number text", withArgsBytes (numBytes [])),
    ("number-nan", "number text NaN", withArgsBytes (numBytes (utf8 "NaN"))),
    ("string-invalid-utf8", "a string with a stray continuation byte",
      withArgsBytes (strBytes [0x80])),
    ("string-surrogate-bytes", "a string holding a UTF-8-encoded surrogate",
      withArgsBytes (strBytes [0xED, 0xA0, 0x80])),
    ("unknown-value-tag", "value tag 0x07", withArgsBytes [7]),
    ("length-past-end", "a string length longer than the input",
      withArgsBytes (4 :: encU32 1000000 ++ utf8 "usd")),
    ("count-past-end", "an array count larger than its items",
      withArgsBytes (5 :: encU32 3 ++ [0, 0])) ]

/-! ### Building and checking -/

def fail {α : Type} (msg : String) : IO α := throw (IO.userError msg)

def parseText (bytes : List UInt8) : Except String JVal := parse bytes

def textCaseJ (c : TextCase) : IO JVal := do
  let bytes := utf8 c.source
  let v ← match parseText bytes with
    | .ok v => pure v
    | .error e => fail s!"accept case {c.name} was refused: {e}"
  unless v.wf do fail s!"accept case {c.name}: value not canonical"
  let written := v.write
  match parseText (utf8 written) with
  | .ok v' => unless v' == v do fail s!"accept case {c.name}: written text parses differently"
  | .error e => fail s!"accept case {c.name}: written text refused: {e}"
  unless (decodeValue (encodeValue v)) == some v do fail s!"accept case {c.name}: value bytes"
  pure <| jobj [("name", jstr c.name), ("about", jstr c.about), ("source", jstr c.source),
    ("source_hex", jstr (hex bytes)), ("value", tagged v), ("written", jstr written),
    ("written_is_source", .bool (written == c.source)),
    ("value_hex", jstr (hexBA (encodeValue v)))]

def rejectCaseJ (c : RejectCase) : IO JVal := do
  match parseText c.bytes with
  | .ok _ => fail s!"reject case {c.name} was accepted"
  | .error e => unless e == c.why do fail s!"reject case {c.name}: expected {c.why}, got {e}"
  let src := match String.fromUTF8? ⟨c.bytes.toArray⟩ with
    | some s => jstr s
    | none => .null
  pure <| jobj [("name", jstr c.name), ("about", jstr c.about), ("source", src),
    ("source_hex", jstr (hex c.bytes)), ("error", jstr c.why)]

def reqCaseJ (c : ReqCase) : IO JVal := do
  let args ← match c.argsSource with
    | none => pure none
    | some src => match parseText (utf8 src) with
      | .ok v => pure (some v)
      | .error e => fail s!"request {c.name}: args refused: {e}"
  let q := c.build args
  unless q.wf do fail s!"request {c.name}: not canonical"
  let bytes := encode q
  let some d := decode bytes | fail s!"request {c.name}: decode failed"
  unless d == q do fail s!"request {c.name}: decoded request differs"
  unless (encode d).data == bytes.data do fail s!"request {c.name}: re-encoding differs"
  pure <| jobj [("name", jstr c.name), ("about", jstr c.about),
    ("args_source", jopt jstr c.argsSource),
    ("encoded_hex", jstr (hexBA bytes)),
    ("signed_message_hex", jstr (hexBA (sigMsg bytes))),
    ("decoded", requestJ d)]

def decodeRejectJ (c : String × String × List UInt8) : IO JVal := do
  let (name, about, bytes) := c
  if (decode ⟨bytes.toArray⟩).isSome then fail s!"decode reject {name} was accepted"
  pure <| jobj [("name", jstr name), ("about", jstr about), ("hex", jstr (hex bytes))]

def runGit (args : Array String) : IO String := do
  let out ← IO.Process.output { cmd := "git", args }
  if out.exitCode != 0 then fail s!"git {args}: {out.stderr}"
  pure out.stdout.trimAscii.toString

def writeFile (dir name : String) (v : JVal) : IO Unit := do
  IO.FS.writeFile (dir ++ "/" ++ name) (pretty "" v ++ "\n")
  IO.println s!"wrote {dir}/{name}"

def main (args : List String) : IO UInt32 := do
  let dir := args.headD "../vectors"
  IO.FS.createDirAll dir
  let accept ← acceptCases.mapM textCaseJ
  let reject ← rejectCases.mapM rejectCaseJ
  let reqs ← reqCases.mapM reqCaseJ
  let drej ← decodeRejects.mapM decodeRejectJ
  -- Distinct requests must have distinct bytes (a spot check of encode_injective).
  let encs := reqCases.filterMap fun c =>
    let args := c.argsSource.bind fun s => (parseText (utf8 s)).toOption
    some (hexBA (encode (c.build args)))
  unless encs.eraseDups.length == encs.length do fail "two request vectors encode the same"
  let toolchain := (← IO.FS.readFile "lean-toolchain").trimAscii.toString
  let commit ← runGit #["log", "-1", "--format=%H", "--", "BogoCore", "BogoCore.lean"]
  let dirty := (← runGit #["status", "--porcelain", "--", "BogoCore", "BogoCore.lean"]) != ""
  writeFile dir "json.json" <| jobj [
    ("about", jstr "JSON argument texts. accept: parse source to value; writing value must give written exactly; value_hex is the value grammar of the request encoding. reject: every parser must refuse source_hex with this error kind."),
    ("accept", .arr accept), ("reject", .arr reject)]
  writeFile dir "requests.json" <| jobj [
    ("about", jstr "Approval requests. args_source is the agent's argument text (null: no arguments field). encoded_hex is the request encoding; signed_message_hex is what an approval signs; decoded is the request as the Lean decoder reads it back from encoded_hex."),
    ("requests", .arr reqs)]
  writeFile dir "decode_reject.json" <| jobj [
    ("about", jstr "Byte strings the request decoder must refuse."),
    ("reject", .arr drej)]
  writeFile dir "manifest.json" <| jobj [
    ("generator", jstr "lean/BogoVectors (lake exe BogoVectors)"),
    ("lean_toolchain", jstr toolchain),
    ("bogocore_commit", jstr commit),
    ("bogocore_dirty", .bool dirty),
    ("request_encoding_version", jcount version),
    ("request_magic_hex", jstr (hex magic)),
    ("approval_domain_hex", jstr (hex approvalDomain)),
    ("files", .arr [jstr "json.json", jstr "requests.json", jstr "decode_reject.json"]),
    ("counts", jobj [("json_accept", jcount accept.length), ("json_reject", jcount reject.length),
      ("requests", jcount reqs.length), ("decode_reject", jcount drej.length)])]
  pure 0

end Bogo.Vectors

def main (args : List String) : IO UInt32 := Bogo.Vectors.main args
