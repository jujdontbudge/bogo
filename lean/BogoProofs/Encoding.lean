/-
Proofs about the request encoding (ARCHITECTURE §3.2, §3.3 theorem 10).

* `decode_encode`: decoding the encoding of a canonical request gives back that request.
* `encode_injective`: two different canonical requests never encode to the same bytes.

No `sorry`, no `axiom`. `#print axioms` on both theorems lists only Lean's standard axioms.
-/
import BogoCore.Encoding

namespace Bogo.Proofs
open Bogo

/-! ### Primitives -/

theorem decU16_enc {n : Nat} (r : List UInt8) (h : n < 65536) :
    decU16 (encU16 n ++ r) = some (n, r) := by
  simp only [encU16, decU16, u8, List.cons_append, List.nil_append, UInt8.toNat_ofNat',
    Option.some.injEq, Prod.mk.injEq, and_true]
  omega

theorem decU32_enc {n : Nat} (r : List UInt8) (h : n < u32Bound) :
    decU32 (encU32 n ++ r) = some (n, r) := by
  simp only [encU32, decU32, u8, List.cons_append, List.nil_append, UInt8.toNat_ofNat',
    Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [u32Bound] at h
  omega

theorem decU64_enc {n : Nat} (r : List UInt8) (h : n < u64Bound) :
    decU64 (encU64 n ++ r) = some (n, r) := by
  have h1 : n / u32Bound < u32Bound := by
    simp only [u32Bound, u64Bound] at *; omega
  have h2 : n % u32Bound < u32Bound := Nat.mod_lt _ (by decide)
  have e : encU32 n = encU32 (n % u32Bound) := by
    simp only [encU32, u8]
    congr 1
    · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega
    congr 1
    · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega
    congr 1
    · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega
    congr 1
    · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega
  simp only [decU64, encU64, List.append_assoc, decU32_enc _ h1, e, decU32_enc _ h2,
    Option.some.injEq, Prod.mk.injEq, and_true]
  simp only [u32Bound]; omega

theorem takeN_append (xs r : List UInt8) : takeN xs.length (xs ++ r) = some (xs, r) := by
  simp [takeN]

theorem length_rawBytes (b : ByteArray) : (rawBytes b).length = b.size := by
  cases b with
  | mk data => exact Array.length_toList

theorem mk_rawBytes (b : ByteArray) : (⟨(rawBytes b).toArray⟩ : ByteArray) = b := by
  cases b with
  | mk data => simp only [rawBytes, Array.toArray_toList]

theorem fromUTF8_utf8 (s : String) : String.fromUTF8? ⟨(utf8 s).toArray⟩ = some s := by
  simp only [utf8, Array.toArray_toList, String.toUTF8_eq_toByteArray]
  simp [String.fromUTF8?, String.fromUTF8, s.isValidUTF8]

theorem decBytes_enc {b : ByteArray} (r : List UInt8) (h : bytesOk b = true) :
    decBytes (encBytes b ++ r) = some (b, r) := by
  simp only [bytesOk, decide_eq_true_eq] at h
  have := takeN_append (rawBytes b) r
  rw [length_rawBytes] at this
  rw [encBytes, List.append_assoc, decBytes, decU32_enc _ h]
  dsimp only
  rw [this]
  dsimp only
  rw [mk_rawBytes]

theorem decStr_enc {s : String} (r : List UInt8) (h : strOk s = true) :
    decStr (encStr s ++ r) = some (s, r) := by
  simp only [strOk, decide_eq_true_eq] at h
  rw [encStr, List.append_assoc, decStr, decU32_enc _ h]
  dsimp only
  rw [takeN_append]
  dsimp only
  rw [fromUTF8_utf8]

theorem decNum_enc {t : String} (r : List UInt8) (h1 : isJsonNumber (utf8 t) = true)
    (h2 : strOk t = true) : decNum (encStr t ++ r) = some (t, r) := by
  rw [decNum, decStr_enc _ h2]
  dsimp only
  rw [h1]; rfl

theorem decOpt_enc {α : Type} {d : Dec α} {f : α → List UInt8} {p : α → Bool}
    (hd : ∀ a r, p a = true → d (f a ++ r) = some (a, r)) :
    ∀ (o : Option α) (r : List UInt8), optWf p o = true → decOpt d (encOpt f o ++ r) = some (o, r)
  | none, r, _ => by simp [encOpt, decOpt]
  | some a, r, h => by simp only [optWf] at h; simp [encOpt, decOpt, hd a r h]

theorem decN_enc {α : Type} {d : Dec α} {f : α → List UInt8} {p : α → Bool}
    (hd : ∀ a r, p a = true → d (f a ++ r) = some (a, r)) :
    ∀ (xs : List α) (r : List UInt8), xs.all p = true →
      decN d xs.length ((xs.map f).flatten ++ r) = some (xs, r)
  | [], r, _ => by simp [decN]
  | x :: xs, r, h => by
    simp only [List.all_cons, Bool.and_eq_true] at h
    simp only [List.length_cons, List.map_cons, List.flatten_cons, List.append_assoc, decN,
      hd x _ h.1, decN_enc hd xs r h.2]

theorem decList_enc {α : Type} {d : Dec α} {f : α → List UInt8} {p : α → Bool}
    (hd : ∀ a r, p a = true → d (f a ++ r) = some (a, r))
    (xs : List α) (r : List UInt8) (h1 : xs.length < u32Bound) (h2 : xs.all p = true) :
    decList d (encList f xs ++ r) = some (xs, r) := by
  simp only [decList, encList, List.append_assoc, decU32_enc _ h1, decN_enc hd xs r h2]

theorem expect_cons (t : UInt8) (r : List UInt8) : expect t (t :: r) = some r := by
  simp [expect]

theorem field_enc {α : Type} {d : Dec α} {t : UInt8} {bs r : List UInt8} {a : α}
    (h : d (bs ++ r) = some (a, r)) : field t d (t :: bs ++ r) = some (a, r) := by
  simp only [field, List.cons_append, expect_cons, h]

/-! ### Values -/

mutual
/-- Nesting depth: the fuel `decVal` needs. -/
def depth : JVal → Nat
  | .arr xs => depthArr xs + 1
  | .obj kvs => depthObj kvs + 1
  | _ => 1

def depthArr : List JVal → Nat
  | [] => 0
  | x :: xs => max (depth x) (depthArr xs)

def depthObj : List (String × JVal) → Nat
  | [] => 0
  | (_, v) :: kvs => max (depth v) (depthObj kvs)
end

theorem decArr_zero (fuel : Nat) (r : List UInt8) : decArr fuel 0 r = some ([], r) := by
  rw [decArr]

theorem decObj_zero (fuel : Nat) (r : List UInt8) : decObj fuel 0 r = some ([], r) := by
  rw [decObj]

mutual
theorem decVal_enc : ∀ (v : JVal) (fuel : Nat) (r : List UInt8),
    v.wf = true → depth v ≤ fuel → decVal fuel (encVal v ++ r) = some (v, r)
  | .null, fuel + 1, r, _, _ => by rw [encVal, List.cons_append, List.nil_append, decVal]; rfl
  | .bool false, fuel + 1, r, _, _ => by
    rw [encVal, List.cons_append, List.nil_append, decVal]; rfl
  | .bool true, fuel + 1, r, _, _ => by
    rw [encVal, List.cons_append, List.nil_append, decVal]; rfl
  | .num t, fuel + 1, r, h, _ => by
    simp only [JVal.wf, Bool.and_eq_true] at h
    rw [encVal, List.cons_append, decVal]
    try dsimp only
    rw [decNum_enc _ h.1 (by simpa [strOk] using h.2)]
    rfl
  | .str s, fuel + 1, r, h, _ => by
    simp only [JVal.wf] at h
    rw [encVal, List.cons_append, decVal]
    try dsimp only
    rw [decStr_enc _ (by simpa [strOk] using h)]
    rfl
  | .arr xs, fuel + 1, r, h, hd => by
    simp only [JVal.wf, Bool.and_eq_true, decide_eq_true_eq] at h
    simp only [depth, Nat.add_le_add_iff_right] at hd
    simp only [encVal, List.cons_append, List.append_assoc]
    rw [decVal]
    try dsimp only
    rw [decU32_enc _ h.1]
    try dsimp only
    rw [decArr_enc xs fuel r h.2 hd]
    rfl
  | .obj kvs, fuel + 1, r, h, hd => by
    simp only [JVal.wf, Bool.and_eq_true, decide_eq_true_eq] at h
    simp only [depth, Nat.add_le_add_iff_right] at hd
    simp only [encVal, List.cons_append, List.append_assoc]
    rw [decVal]
    try dsimp only
    rw [decU32_enc _ h.1.1]
    try dsimp only
    rw [decObj_enc kvs fuel r h.2 hd]
    try dsimp only
    rw [h.1.2]; rfl
  | .null, 0, _, _, hd | .bool _, 0, _, _, hd | .num _, 0, _, _, hd | .str _, 0, _, _, hd
  | .arr _, 0, _, _, hd | .obj _, 0, _, _, hd => by simp [depth] at hd

theorem decArr_enc : ∀ (xs : List JVal) (fuel : Nat) (r : List UInt8),
    JVal.wfArr xs = true → depthArr xs ≤ fuel →
      decArr fuel xs.length (encArr xs ++ r) = some (xs, r)
  | [], fuel, r, _, _ => by rw [encArr, List.nil_append]; exact decArr_zero fuel r
  | x :: xs, fuel, r, h, hd => by
    simp only [JVal.wfArr, Bool.and_eq_true] at h
    simp only [depthArr, Nat.max_le] at hd
    rw [encArr, List.length_cons, List.append_assoc, decArr, decVal_enc x fuel _ h.1 hd.1]
    try dsimp only
    rw [decArr_enc xs fuel r h.2 hd.2]

theorem decObj_enc : ∀ (kvs : List (String × JVal)) (fuel : Nat) (r : List UInt8),
    JVal.wfObj kvs = true → depthObj kvs ≤ fuel →
      decObj fuel kvs.length (encObj kvs ++ r) = some (kvs, r)
  | [], fuel, r, _, _ => by rw [encObj, List.nil_append]; exact decObj_zero fuel r
  | (k, v) :: kvs, fuel, r, h, hd => by
    simp only [JVal.wfObj, Bool.and_eq_true] at h
    simp only [depthObj, Nat.max_le] at hd
    rw [encObj, List.length_cons, List.append_assoc, List.append_assoc, decObj,
      decStr_enc _ (by simpa [strOk] using h.1.1)]
    try dsimp only
    rw [decVal_enc v fuel _ h.1.2 hd.1]
    try dsimp only
    rw [decObj_enc kvs fuel r h.2 hd.2]
end


theorem field_enc' {α : Type} {d : Dec α} {t : UInt8} {bs r : List UInt8} {a : α}
    (h : d (bs ++ r) = some (a, r)) : field t d (t :: (bs ++ r)) = some (a, r) := by
  simp only [field, expect_cons, h]

theorem decOptStr_enc {o : Option String} (r : List UInt8) (h : optWf strOk o = true) :
    decOpt decStr (encOpt encStr o ++ r) = some (o, r) :=
  decOpt_enc (p := strOk) (fun _ r h => decStr_enc r h) o r h

theorem decOptU64_enc {o : Option Nat} (r : List UInt8)
    (h : optWf (fun e => decide (e < u64Bound)) o = true) :
    decOpt decU64 (encOpt encU64 o ++ r) = some (o, r) :=
  decOpt_enc (p := fun e => decide (e < u64Bound))
    (fun _ r h => decU64_enc r (by simpa using h)) o r h

theorem decOptVal_enc {o : Option JVal} {fuel : Nat} (r : List UInt8)
    (h : optWf JVal.wf o = true) (hf : ∀ v, o = some v → depth v ≤ fuel) :
    decOpt (decVal fuel) (encOpt encVal o ++ r) = some (o, r) := by
  cases o with
  | none => rfl
  | some v =>
    simp only [optWf] at h
    rw [encOpt, List.cons_append, decOpt, ite_eq_right (by decide), ite_eq_left rfl,
      decVal_enc v fuel r h (hf v rfl)]

theorem decPathElem_enc {e : PathElem} (r : List UInt8) (h : e.wf = true) :
    decPathElem (encPathElem e ++ r) = some (e, r) := by
  cases e with
  | key k =>
    simp only [PathElem.wf] at h
    rw [encPathElem, List.cons_append, decPathElem, ite_eq_left rfl, decStr_enc r h]
  | index i =>
    simp only [PathElem.wf, decide_eq_true_eq] at h
    rw [encPathElem, List.cons_append, decPathElem, ite_eq_right (by decide), ite_eq_left rfl,
      decU32_enc r h]

theorem decFormat_enc {f : Format} (r : List UInt8) (h : f.wf = true) :
    decFormat (encFormat f ++ r) = some (f, r) := by
  cases f with
  | text => rfl
  | moneyMinor c =>
    simp only [Format.wf] at h
    rw [encFormat, List.cons_append, decFormat, ite_eq_right (by decide), ite_eq_left rfl,
      decStr_enc r h]

theorem decHint_enc {x : Path × Format} (r : List UInt8) (h : hintWf x = true) :
    decHint (encHint x ++ r) = some (x, r) := by
  simp only [hintWf, Bool.and_eq_true, decide_eq_true_eq] at h
  have hl := decList_enc (f := encPathElem) (p := PathElem.wf) (fun _ r h => decPathElem_enc r h)
    x.1 (encFormat x.2 ++ r) h.1.1 h.1.2
  rw [decHint, encHint, List.append_assoc, hl]
  dsimp only
  rw [decFormat_enc r h.2]

theorem takeN_magic (r : List UInt8) : takeN 8 (magic ++ r) = some (magic, r) :=
  takeN_append magic r

theorem Dec.bind_ok {α β : Type} {d : Dec α} {k : α → Dec β} {r r' : List UInt8} {a : α}
    (h : d r = some (a, r')) : Dec.bind d k r = k a r' := by
  simp only [Dec.bind, h]

theorem decodeFuel_enc (q : Request) (fuel : Nat) (h : q.wf = true)
    (hf : ∀ v, q.args = some v → depth v ≤ fuel) : decodeFuel fuel (encodeL q) = some q := by
  simp only [Request.wf, Bool.and_eq_true, decide_eq_true_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨hb, hu⟩, ht⟩, ha⟩, hj⟩, hhl⟩, hh⟩, hai⟩, han⟩, hcn⟩, hs⟩, hn⟩, hc⟩, he⟩ := h
  have e13 := field_enc' (t := 13) (decOptU64_enc [] he)
  rw [List.append_nil] at e13
  simp only [encodeL, List.cons_append, List.append_assoc]
  rw [decodeFuel, takeN_magic]
  dsimp only
  rw [ite_eq_left rfl, decU16_enc _ (by decide)]
  dsimp only
  rw [ite_eq_left rfl]
  rw [decFields,
    Dec.bind_ok (field_enc' (decBytes_enc _ hb)),
    Dec.bind_ok (field_enc' (decStr_enc _ hu)),
    Dec.bind_ok (field_enc' (decStr_enc _ ht)),
    Dec.bind_ok (field_enc' (decOptVal_enc _ ha hf)),
    Dec.bind_ok (field_enc' (decOptStr_enc _ hj)),
    Dec.bind_ok (field_enc' (decList_enc (f := encHint) (p := hintWf)
      (fun _ r h => decHint_enc r h) q.hints _ hhl hh)),
    Dec.bind_ok (field_enc' (decBytes_enc _ hai)),
    Dec.bind_ok (field_enc' (decStr_enc _ han)),
    Dec.bind_ok (field_enc' (decOptStr_enc _ hcn)),
    Dec.bind_ok (field_enc' (decBytes_enc _ hs)),
    Dec.bind_ok (field_enc' (decBytes_enc _ hn)),
    Dec.bind_ok (field_enc' (decU64_enc _ hc)),
    Dec.bind_ok e13]

mutual
theorem depth_le : ∀ v : JVal, depth v ≤ (encVal v).length
  | .null => by simp [depth, encVal]
  | .bool b => by cases b <;> simp [depth, encVal]
  | .num _ => by simp [depth, encVal]
  | .str _ => by simp [depth, encVal]
  | .arr xs => by
    have := depthArr_le xs
    simp only [depth, encVal, List.length_cons, List.length_append]; omega
  | .obj kvs => by
    have := depthObj_le kvs
    simp only [depth, encVal, List.length_cons, List.length_append]; omega

theorem depthArr_le : ∀ xs : List JVal, depthArr xs ≤ (encArr xs).length
  | [] => by simp [depthArr]
  | x :: xs => by
    have := depth_le x; have := depthArr_le xs
    simp only [depthArr, encArr, List.length_append]; omega

theorem depthObj_le : ∀ kvs : List (String × JVal), depthObj kvs ≤ (encObj kvs).length
  | [] => by simp [depthObj]
  | (_, v) :: kvs => by
    have := depth_le v; have := depthObj_le kvs
    simp only [depthObj, encObj, List.length_append]; omega
end

theorem args_depth_le (q : Request) : ∀ v, q.args = some v → depth v ≤ (encodeL q).length := by
  intro v hv
  have h1 := depth_le v
  have h2 : (encVal v).length ≤ (encodeL q).length := by
    simp only [encodeL, hv, encOpt, List.length_append, List.length_cons]; omega
  omega

theorem decodeL_encodeL (q : Request) (h : q.wf = true) : decodeL (encodeL q) = some q :=
  decodeFuel_enc q _ h (args_depth_le q)

theorem rawBytes_mk (l : List UInt8) : rawBytes ⟨l.toArray⟩ = l := rfl

/-- **Round trip.** Decoding the encoding of a canonical request gives back that request. -/
theorem decode_encode (q : Request) (h : q.wf = true) : decode (encode q) = some q := by
  rw [decode, encode, rawBytes_mk, decodeL_encodeL q h]

/-- **Injectivity.** Two canonical requests with the same encoding are the same request:
different requests never encode the same way. -/
theorem encode_injective (q₁ q₂ : Request) (h₁ : q₁.wf = true) (h₂ : q₂.wf = true)
    (h : encode q₁ = encode q₂) : q₁ = q₂ := by
  have e₁ := decode_encode q₁ h₁
  rw [h, decode_encode q₂ h₂] at e₁
  exact Option.some.inj e₁.symm

/-- The signed message determines the request too: the domain tag is a fixed prefix. -/
theorem sigMsg_injective (q₁ q₂ : Request) (h₁ : q₁.wf = true) (h₂ : q₂.wf = true)
    (h : sigMsg (encode q₁) = sigMsg (encode q₂)) : q₁ = q₂ := by
  apply encode_injective q₁ q₂ h₁ h₂
  simp only [sigMsg, ByteArray.mk.injEq] at h
  have h' := List.toArray_inj h
  rw [List.append_cancel_left_eq] at h'
  rw [← mk_rawBytes (encode q₁), ← mk_rawBytes (encode q₂), h']

/-- The value grammar on its own round-trips too. -/
theorem decodeValue_encodeValue (v : JVal) (h : v.wf = true) :
    decodeValue (encodeValue v) = some v := by
  have := decVal_enc v (encVal v).length [] h (depth_le v)
  rw [List.append_nil] at this
  rw [decodeValue, encodeValue, rawBytes_mk, this]

theorem encodeValue_injective (v₁ v₂ : JVal) (h₁ : v₁.wf = true) (h₂ : v₂.wf = true)
    (h : encodeValue v₁ = encodeValue v₂) : v₁ = v₂ := by
  have e₁ := decodeValue_encodeValue v₁ h₁
  rw [h, decodeValue_encodeValue v₂ h₂] at e₁
  exact Option.some.inj e₁.symm

end Bogo.Proofs

