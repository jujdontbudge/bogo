/-
The direction Foundations left open (ARCHITECTURE §3.2): every byte string the decoder accepts
is exactly the encoding of what it decoded, and what it decoded is canonical.

* `encode_decode`: `decode b = some q → encode q = b ∧ q.wf`.
* `decode_injective`: two different byte strings never decode to the same request, so they can
  never show the owner the same screen.

No `sorry`, no `axiom`.
-/
import BogoProofs.Encoding

namespace Bogo.Proofs
open Bogo

/-- A decoder is sound for an encoder and a predicate: whatever it reads is exactly the
encoding of what it returns, and what it returns satisfies the predicate. -/
def Sound {α : Type} (d : Dec α) (enc : α → List UInt8) (p : α → Prop) : Prop :=
  ∀ l a r, d l = some (a, r) → l = enc a ++ r ∧ p a

/-! ### Fixed-width numbers -/

theorem u8_toNat (a : UInt8) : u8 a.toNat = a := by
  apply UInt8.toNat_inj.mp; simp only [u8, UInt8.toNat_ofNat']; have := a.toNat_lt; omega

theorem encU32_mod (n : Nat) : encU32 n = encU32 (n % u32Bound) := by
  simp only [encU32, u8]
  congr 1
  · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega
  congr 1
  · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega
  congr 1
  · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega
  congr 1
  · apply UInt8.toNat.inj; simp only [UInt8.toNat_ofNat', u32Bound]; omega

theorem decU16_sound : Sound decU16 encU16 (· < 65536) := by
  intro l n r h
  match l, h with
  | a :: b :: r', h =>
    simp only [decU16, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    have ha := a.toNat_lt; have hb := b.toNat_lt
    refine ⟨?_, by omega⟩
    simp only [encU16, u8, List.cons_append, List.nil_append, List.cons.injEq, and_true]
    constructor <;> (apply UInt8.toNat_inj.mp; simp only [UInt8.toNat_ofNat']; omega)

theorem decU32_sound : Sound decU32 encU32 (· < u32Bound) := by
  intro l n r h
  match l, h with
  | a :: b :: c :: d :: r', h =>
    simp only [decU32, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    have ha := a.toNat_lt; have hb := b.toNat_lt; have hc := c.toNat_lt; have hd := d.toNat_lt
    refine ⟨?_, by simp only [u32Bound]; omega⟩
    simp only [encU32, u8, List.cons_append, List.nil_append, List.cons.injEq, and_true]
    refine ⟨?_, ?_, ?_, ?_⟩ <;> (apply UInt8.toNat_inj.mp; simp only [UInt8.toNat_ofNat']; omega)

theorem decU64_sound : Sound decU64 encU64 (· < u64Bound) := by
  intro l n r h
  simp only [decU64] at h
  split at h
  · rename_i hi r1 h1
    split at h
    · rename_i lo r2 h2
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨e1, b1⟩ := decU32_sound _ _ _ h1
      obtain ⟨e2, b2⟩ := decU32_sound _ _ _ h2
      refine ⟨?_, by simp only [u32Bound, u64Bound] at *; omega⟩
      have q : (hi * u32Bound + lo) / u32Bound = hi := by simp only [u32Bound] at *; omega
      have m : (hi * u32Bound + lo) % u32Bound = lo := by simp only [u32Bound] at *; omega
      rw [e1, e2, encU64, List.append_assoc, q, encU32_mod (hi * u32Bound + lo), m]
    · simp at h
  · simp at h

/-! ### Byte strings and text -/

theorem takeN_sound {n : Nat} {l bs r : List UInt8} (h : takeN n l = some (bs, r)) :
    l = bs ++ r ∧ bs.length = n := by
  simp only [takeN] at h
  split at h
  · rename_i hn
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨(List.take_append_drop n l).symm, by simp; omega⟩
  · simp at h

theorem decBytes_sound : Sound decBytes encBytes (fun b => bytesOk b = true) := by
  intro l b r h
  simp only [decBytes] at h
  split at h
  · rename_i n r1 h1
    split at h
    · rename_i bs r2 h2
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨e1, b1⟩ := decU32_sound _ _ _ h1
      obtain ⟨e2, b2⟩ := takeN_sound h2
      have hs : (⟨bs.toArray⟩ : ByteArray).size = n := by simp [ByteArray.size, b2]
      refine ⟨?_, ?_⟩
      · rw [e1, e2, encBytes, hs, rawBytes_mk, List.append_assoc]
      · simp only [bytesOk, hs, decide_eq_true_eq]; exact b1
    · simp at h
  · simp at h

theorem utf8_of_fromUTF8 {bs : List UInt8} {s : String}
    (h : String.fromUTF8? ⟨bs.toArray⟩ = some s) : utf8 s = bs := by
  unfold String.fromUTF8? at h
  split at h
  · cases h; rfl
  · cases h

theorem decStr_sound : Sound decStr encStr (fun s => strOk s = true) := by
  intro l s r h
  simp only [decStr] at h
  split at h
  · rename_i n r1 h1
    split at h
    · rename_i bs r2 h2
      split at h
      · rename_i s' h3
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨e1, b1⟩ := decU32_sound _ _ _ h1
        obtain ⟨e2, b2⟩ := takeN_sound h2
        have hu := utf8_of_fromUTF8 h3
        refine ⟨?_, ?_⟩
        · rw [e1, e2, encStr, hu, b2, List.append_assoc]
        · simp only [strOk, hu, b2, decide_eq_true_eq]; exact b1
      · simp at h
    · simp at h
  · simp at h

theorem decNum_sound :
    Sound decNum encStr (fun t => isJsonNumber (utf8 t) = true ∧ strOk t = true) := by
  intro l s r h
  simp only [decNum] at h
  split at h
  · rename_i s' r1 h1
    split at h
    · rename_i hn
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨e1, b1⟩ := decStr_sound _ _ _ h1
      exact ⟨e1, hn, b1⟩
    · simp at h
  · simp at h

/-! ### Combinators -/

theorem decOpt_sound {α : Type} {d : Dec α} {f : α → List UInt8} {p : α → Bool}
    (hd : Sound d f (fun a => p a = true)) :
    Sound (decOpt d) (encOpt f) (fun o => optWf p o = true) := by
  intro l o r h
  match l, h with
  | b :: r', h =>
    simp only [decOpt] at h
    split at h
    · rename_i hb
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      subst hb
      exact ⟨rfl, rfl⟩
    · split at h
      · rename_i _ hb
        subst hb
        split at h
        · rename_i a r2 h2
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨e, pa⟩ := hd _ _ _ h2
          exact ⟨by rw [e]; rfl, pa⟩
        · simp at h
      · simp at h

theorem decN_sound {α : Type} {d : Dec α} {f : α → List UInt8} {p : α → Bool}
    (hd : Sound d f (fun a => p a = true)) :
    ∀ (n : Nat) (l : List UInt8) (xs : List α) (r : List UInt8), decN d n l = some (xs, r) →
      l = (xs.map f).flatten ++ r ∧ xs.all p = true ∧ xs.length = n
  | 0, l, xs, r, h => by
    simp only [decN, Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | n + 1, l, xs, r, h => by
    simp only [decN] at h
    split at h
    · rename_i a r1 h1
      split at h
      · rename_i as r2 h2
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨e1, p1⟩ := hd _ _ _ h1
        obtain ⟨e2, p2, n2⟩ := decN_sound hd n _ _ _ h2
        refine ⟨?_, ?_, ?_⟩
        · rw [e1, e2]; simp
        · simp [p1, p2]
        · simp [n2]
      · simp at h
    · simp at h

theorem decList_sound {α : Type} {d : Dec α} {f : α → List UInt8} {p : α → Bool}
    (hd : Sound d f (fun a => p a = true)) :
    Sound (decList d) (encList f) (fun xs => xs.length < u32Bound ∧ xs.all p = true) := by
  intro l xs r h
  simp only [decList] at h
  split at h
  · rename_i n r1 h1
    obtain ⟨e1, b1⟩ := decU32_sound _ _ _ h1
    obtain ⟨e2, p2, n2⟩ := decN_sound hd n _ _ _ h
    refine ⟨?_, by rw [n2]; exact b1, p2⟩
    rw [e1, e2, encList, n2, List.append_assoc]
  · simp at h

theorem field_sound {α : Type} {d : Dec α} {t : UInt8} {l r : List UInt8} {a : α}
    (h : field t d l = some (a, r)) : ∃ l', l = t :: l' ∧ d l' = some (a, r) := by
  match l, h with
  | b :: l', h =>
    simp only [field, expect] at h
    by_cases hb : b = t
    · subst hb
      simp only [ite_true] at h
      exact ⟨l', rfl, h⟩
    · simp [hb] at h

theorem bind_some {α β : Type} {d : Dec α} {k : α → Dec β} {l : List UInt8} {x : β × List UInt8}
    (h : Dec.bind d k l = some x) : ∃ a l', d l = some (a, l') ∧ k a l' = some x := by
  simp only [Dec.bind] at h
  split at h
  · rename_i a l' h1
    exact ⟨a, l', h1, h⟩
  · simp at h

/-! ### Values -/

mutual
theorem decVal_sound : ∀ (fuel : Nat) (l : List UInt8) (v : JVal) (r : List UInt8),
    decVal fuel l = some (v, r) → l = encVal v ++ r ∧ v.wf = true
  | 0, l, v, r, h => by simp [decVal] at h
  | _ + 1, [], v, r, h => by simp [decVal] at h
  | fuel + 1, b :: l, v, r, h => by
    have hb := b.toNat_lt
    have eb : b = u8 b.toNat := (u8_toNat b).symm
    rw [decVal] at h
    split at h
    · rename_i hn
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨?_, rfl⟩
      rw [eb, hn]; rfl
    · rename_i hn
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨?_, rfl⟩
      rw [eb, hn]; rfl
    · rename_i hn
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      refine ⟨?_, rfl⟩
      rw [eb, hn]; rfl
    · rename_i hn
      split at h
      · rename_i t r1 h1
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨e1, g1, s1⟩ := decNum_sound _ _ _ h1
        refine ⟨?_, ?_⟩
        · rw [eb, hn, e1]; rfl
        · simp only [JVal.wf, g1, Bool.true_and, decide_eq_true_eq]
          simpa [strOk] using s1
      · simp at h
    · rename_i hn
      split at h
      · rename_i s r1 h1
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨e1, s1⟩ := decStr_sound _ _ _ h1
        refine ⟨?_, ?_⟩
        · rw [eb, hn, e1]; rfl
        · simpa [JVal.wf, strOk] using s1
      · simp at h
    · rename_i hn
      split at h
      · rename_i n r1 h1
        split at h
        · rename_i xs r2 h2
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨e1, b1⟩ := decU32_sound _ _ _ h1
          obtain ⟨n2, e2, w2⟩ := decArr_sound fuel n _ _ _ h2
          refine ⟨?_, ?_⟩
          · rw [eb, hn, e1, e2, ← n2]; simp [encVal]; rfl
          · simp only [JVal.wf, w2, Bool.and_true, decide_eq_true_eq]; rw [n2]; exact b1
        · simp at h
      · simp at h
    · rename_i hn
      split at h
      · rename_i n r1 h1
        split at h
        · rename_i kvs r2 h2
          split at h
          · rename_i hk
            simp only [Option.some.injEq, Prod.mk.injEq] at h
            obtain ⟨rfl, rfl⟩ := h
            obtain ⟨e1, b1⟩ := decU32_sound _ _ _ h1
            obtain ⟨n2, e2, w2⟩ := decObj_sound fuel n _ _ _ h2
            refine ⟨?_, ?_⟩
            · rw [eb, hn, e1, e2, ← n2]; simp [encVal]; rfl
            · simp only [JVal.wf, w2, hk, Bool.and_true, decide_eq_true_eq]; rw [n2]; exact b1
          · simp at h
        · simp at h
      · simp at h
    · simp at h
  termination_by fuel _ _ _ => (fuel, 0)

theorem decArr_sound : ∀ (fuel n : Nat) (l : List UInt8) (xs : List JVal) (r : List UInt8),
    decArr fuel n l = some (xs, r) → xs.length = n ∧ l = encArr xs ++ r ∧ JVal.wfArr xs = true
  | fuel, 0, l, xs, r, h => by
    rw [decArr] at h
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, rfl, rfl⟩
  | fuel, n + 1, l, xs, r, h => by
    rw [decArr] at h
    split at h
    · rename_i x r1 h1
      split at h
      · rename_i xs' r2 h2
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨e1, w1⟩ := decVal_sound fuel _ _ _ h1
        obtain ⟨n2, e2, w2⟩ := decArr_sound fuel n _ _ _ h2
        refine ⟨by simp [n2], ?_, ?_⟩
        · rw [e1, e2, encArr, List.append_assoc]
        · simp [JVal.wfArr, w1, w2]
      · simp at h
    · simp at h
  termination_by fuel n _ _ _ => (fuel, n + 1)

theorem decObj_sound : ∀ (fuel n : Nat) (l : List UInt8) (kvs : List (String × JVal))
    (r : List UInt8),
    decObj fuel n l = some (kvs, r) →
      kvs.length = n ∧ l = encObj kvs ++ r ∧ JVal.wfObj kvs = true
  | fuel, 0, l, kvs, r, h => by
    rw [decObj] at h
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨rfl, rfl⟩ := h
    exact ⟨rfl, rfl, rfl⟩
  | fuel, n + 1, l, kvs, r, h => by
    rw [decObj] at h
    split at h
    · rename_i k r1 h1
      split at h
      · rename_i v r2 h2
        split at h
        · rename_i kvs' r3 h3
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨e1, s1⟩ := decStr_sound _ _ _ h1
          obtain ⟨e2, w2⟩ := decVal_sound fuel _ _ _ h2
          obtain ⟨n3, e3, w3⟩ := decObj_sound fuel n _ _ _ h3
          refine ⟨by simp [n3], ?_, ?_⟩
          · rw [e1, e2, e3, encObj, List.append_assoc, List.append_assoc]
          · simp only [JVal.wfObj, w2, w3, Bool.and_true, decide_eq_true_eq]
            simpa [strOk] using s1
        · simp at h
      · simp at h
    · simp at h
  termination_by fuel n _ _ _ => (fuel, n + 1)
end

/-! ### Hints -/

theorem decPathElem_sound : Sound decPathElem encPathElem (fun e => e.wf = true) := by
  intro l e r h
  match l, h with
  | b :: l', h =>
    simp only [decPathElem] at h
    split at h
    · rename_i hb
      subst hb
      split at h
      · rename_i k r1 h1
        simp only [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨e1, s1⟩ := decStr_sound _ _ _ h1
        exact ⟨by rw [e1]; rfl, s1⟩
      · simp at h
    · split at h
      · rename_i _ hb
        subst hb
        split at h
        · rename_i i r1 h1
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨e1, s1⟩ := decU32_sound _ _ _ h1
          exact ⟨by rw [e1]; rfl, by simpa [PathElem.wf] using s1⟩
        · simp at h
      · simp at h

theorem decFormat_sound : Sound decFormat encFormat (fun f => f.wf = true) := by
  intro l f r h
  match l, h with
  | b :: l', h =>
    simp only [decFormat] at h
    split at h
    · rename_i hb
      subst hb
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨rfl, rfl⟩
    · split at h
      · rename_i _ hb
        subst hb
        split at h
        · rename_i c r1 h1
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨e1, s1⟩ := decStr_sound _ _ _ h1
          exact ⟨by rw [e1]; rfl, s1⟩
        · simp at h
      · simp at h

theorem decHint_sound : Sound decHint encHint (fun x => hintWf x = true) := by
  intro l x r h
  simp only [decHint] at h
  split at h
  · rename_i p r1 h1
    split at h
    · rename_i f r2 h2
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      obtain ⟨e1, ⟨l1, a1⟩⟩ := decList_sound decPathElem_sound _ _ _ h1
      obtain ⟨e2, w2⟩ := decFormat_sound _ _ _ h2
      refine ⟨?_, ?_⟩
      · rw [e1, e2, encHint, List.append_assoc]
      · simp only [hintWf, a1, w2, Bool.and_true, decide_eq_true_eq]; exact l1
    · simp at h
  · simp at h

/-! ### Requests -/

theorem decodeFuel_sound (fuel : Nat) (l : List UInt8) (q : Request)
    (h : decodeFuel fuel l = some q) : encodeL q = l ∧ q.wf = true := by
  simp only [decodeFuel] at h
  split at h
  · rename_i m r0 h0
    split at h
    · rename_i hm
      subst hm
      split at h
      · rename_i v r1 h1
        split at h
        · rename_i hv
          subst hv
          split at h
          · rename_i q' h2
            simp only [Option.some.injEq] at h
            subst h
            obtain ⟨e0, _⟩ := takeN_sound h0
            obtain ⟨e1, _⟩ := decU16_sound _ _ _ h1
            simp only [decFields] at h2
            obtain ⟨bogoId, l1, f1, h2⟩ := bind_some h2
            obtain ⟨upstream, l2, f2, h2⟩ := bind_some h2
            obtain ⟨tool, l3, f3, h2⟩ := bind_some h2
            obtain ⟨args, l4, f4, h2⟩ := bind_some h2
            obtain ⟨justification, l5, f5, h2⟩ := bind_some h2
            obtain ⟨hints, l6, f6, h2⟩ := bind_some h2
            obtain ⟨agentId, l7, f7, h2⟩ := bind_some h2
            obtain ⟨agentName, l8, f8, h2⟩ := bind_some h2
            obtain ⟨clientName, l9, f9, h2⟩ := bind_some h2
            obtain ⟨session, l10, f10, h2⟩ := bind_some h2
            obtain ⟨nonce, l11, f11, h2⟩ := bind_some h2
            obtain ⟨createdMs, l12, f12, h2⟩ := bind_some h2
            obtain ⟨expiresMs, l13, f13, h2⟩ := bind_some h2
            simp only [Option.some.injEq, Prod.mk.injEq] at h2
            obtain ⟨rfl, rfl⟩ := h2
            obtain ⟨k1, rfl, g1⟩ := field_sound f1
            obtain ⟨k2, rfl, g2⟩ := field_sound f2
            obtain ⟨k3, rfl, g3⟩ := field_sound f3
            obtain ⟨k4, rfl, g4⟩ := field_sound f4
            obtain ⟨k5, rfl, g5⟩ := field_sound f5
            obtain ⟨k6, rfl, g6⟩ := field_sound f6
            obtain ⟨k7, rfl, g7⟩ := field_sound f7
            obtain ⟨k8, rfl, g8⟩ := field_sound f8
            obtain ⟨k9, rfl, g9⟩ := field_sound f9
            obtain ⟨k10, rfl, g10⟩ := field_sound f10
            obtain ⟨k11, rfl, g11⟩ := field_sound f11
            obtain ⟨k12, rfl, g12⟩ := field_sound f12
            obtain ⟨k13, rfl, g13⟩ := field_sound f13
            obtain ⟨d1, w1⟩ := decBytes_sound _ _ _ g1
            obtain ⟨d2, w2⟩ := decStr_sound _ _ _ g2
            obtain ⟨d3, w3⟩ := decStr_sound _ _ _ g3
            obtain ⟨d4, w4⟩ := decOpt_sound
              (fun l a r h => decVal_sound fuel l a r h) _ _ _ g4
            obtain ⟨d5, w5⟩ := decOpt_sound decStr_sound _ _ _ g5
            obtain ⟨d6, ⟨w6a, w6b⟩⟩ := decList_sound decHint_sound _ _ _ g6
            obtain ⟨d7, w7⟩ := decBytes_sound _ _ _ g7
            obtain ⟨d8, w8⟩ := decStr_sound _ _ _ g8
            obtain ⟨d9, w9⟩ := decOpt_sound decStr_sound _ _ _ g9
            obtain ⟨d10, w10⟩ := decBytes_sound _ _ _ g10
            obtain ⟨d11, w11⟩ := decBytes_sound _ _ _ g11
            obtain ⟨d12, w12⟩ := decU64_sound _ _ _ g12
            obtain ⟨d13, w13⟩ := decOpt_sound (p := fun e => decide (e < u64Bound))
              (fun l a r h => by
                obtain ⟨e, b⟩ := decU64_sound l a r h
                exact ⟨e, by simpa using b⟩) _ _ _ g13
            refine ⟨?_, ?_⟩
            · rw [e0, e1, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13]
              simp [encodeL, magic, version]
            · simp [Request.wf, w1, w2, w3, w4, w5, w6a, w6b, w7, w8, w9, w10, w11, w12, w13]
          · simp at h
        · simp at h
      · simp at h
    · simp at h
  · simp at h

/-- **Decode then encode.** Any byte string the decoder accepts is exactly the encoding of the
canonical request it returns. -/
theorem encode_decode (b : ByteArray) (q : Request) (h : decode b = some q) :
    encode q = b ∧ q.wf = true := by
  obtain ⟨e, w⟩ := decodeFuel_sound _ _ q h
  refine ⟨?_, w⟩
  rw [encode, e, mk_rawBytes]

/-- Two different byte strings never decode to the same request, so they can never show the
owner the same screen. -/
theorem decode_injective (b₁ b₂ : ByteArray) (q : Request) (h₁ : decode b₁ = some q)
    (h₂ : decode b₂ = some q) : b₁ = b₂ := by
  rw [← (encode_decode b₁ q h₁).1, ← (encode_decode b₂ q h₂).1]

end Bogo.Proofs
