/-
The promise for raw bytes: what Rust actually passes to the core.

Rust hands every input to `bogo_lean_step` as bytes, and Lean decodes them itself
(`Wire.stepBytes`). Bytes the decoder rejects change nothing and produce only a `malformed`
rejection. Bytes it accepts are exactly one `Input`, so a byte trace runs exactly like the trace
of the inputs it decodes to, and every theorem in `BogoProofs.Promise` applies to it.
-/
import BogoProofs.Promise

namespace Bogo.Proofs
open Bogo

/-- The inputs the decoder accepted, in order. -/
def decoded (bs : List ByteArray) : List Input := bs.filterMap Wire.decodeInput

/-- Where byte step `i` lands in the decoded trace. -/
def idx (bs : List ByteArray) (i : Nat) : Nat := (decoded (bs.take i)).length

theorem decoded_append (a b : List ByteArray) : decoded (a ++ b) = decoded a ++ decoded b := by
  simp [decoded, List.filterMap_append]

theorem runBytes_cons (s : State) (b : ByteArray) (bs : List ByteArray) :
    runBytes s (b :: bs) = runBytes (Wire.stepBytes s b).1 bs := rfl

theorem runBytes_eq : ∀ (bs : List ByteArray) (s : State), runBytes s bs = run s (decoded bs)
  | [], _ => rfl
  | b :: bs, s => by
    rw [runBytes_cons]
    cases h : Wire.decodeInput b with
    | none =>
      have : decoded (b :: bs) = decoded bs := by simp [decoded, h]
      rw [this]; simp only [Wire.stepBytes, h]; exact runBytes_eq bs s
    | some x =>
      have : decoded (b :: bs) = x :: decoded bs := by simp [decoded, h]
      rw [this, run_cons]; simp only [Wire.stepBytes, h, step_fst]; exact runBytes_eq bs _

theorem beforeBytes_eq (s0 : State) (bs : List ByteArray) (i : Nat) :
    beforeBytes s0 bs i = before s0 (decoded bs) (idx bs i) := by
  unfold beforeBytes before idx
  rw [runBytes_eq]
  congr 1
  have e : decoded bs = decoded (bs.take i) ++ decoded (bs.drop i) := by
    rw [← decoded_append, List.take_append_drop]
  rw [e, List.take_left' rfl]

theorem decoded_at {bs : List ByteArray} {i : Nat} {b : ByteArray} {x : Input}
    (hb : bs[i]? = some b) (hx : Wire.decodeInput b = some x) :
    (decoded bs)[idx bs i]? = some x := by
  have hi : i < bs.length := (List.getElem?_eq_some_iff.mp hb).1
  have hbi : bs[i] = b := (List.getElem?_eq_some_iff.mp hb).2
  have e : bs = bs.take i ++ b :: bs.drop (i + 1) := by
    conv => lhs; rw [← List.take_append_drop i bs]
    rw [List.drop_eq_getElem_cons hi, hbi]
  have : decoded bs = decoded (bs.take i) ++ x :: decoded (bs.drop (i + 1)) := by
    conv => lhs; rw [e]
    rw [decoded_append]; simp [decoded, hx]
  rw [this, idx]
  simp

theorem idx_succ {bs : List ByteArray} {i : Nat} {b : ByteArray} {x : Input}
    (hb : bs[i]? = some b) (hx : Wire.decodeInput b = some x) : idx bs (i + 1) = idx bs i + 1 := by
  unfold idx
  rw [List.take_add_one, hb, decoded_append]
  simp [decoded, hx]

theorem idx_mono (bs : List ByteArray) {i j : Nat} (h : i ≤ j) : idx bs i ≤ idx bs j := by
  unfold idx
  have : bs.take i = (bs.take j).take i := by rw [List.take_take, Nat.min_eq_left h]
  rw [this]
  conv => rhs; rw [← List.take_append_drop i (bs.take j), decoded_append]
  simp

theorem idx_lt {bs : List ByteArray} {i j : Nat} {b : ByteArray} {x : Input} (hij : i < j)
    (hb : bs[i]? = some b) (hx : Wire.decodeInput b = some x) : idx bs i < idx bs j := by
  have := idx_mono bs (Nat.succ_le_of_lt hij)
  rw [idx_succ hb hx] at this
  omega

/-- **Malformed bytes never run.** Bytes the decoder rejects leave the state unchanged and
produce only a `malformed` rejection: no forward, no ask, nothing else. -/
theorem malformed_never_runs (s : State) (b : ByteArray) (h : Wire.decodeInput b = none) :
    Wire.stepBytes s b = (s, [.reject (Wire.peekCallId b) .malformed], nextDeadline s) := by
  simp [Wire.stepBytes, h]

/-- **The lift.** A forward or an ask at byte step `i` is that same output at step `idx bs i`
of the decoded trace, from the same state, for the input those bytes decode to. So every
theorem in `BogoProofs.Promise` holds for byte traces. -/
theorem bytes_lift {s0 : State} {bs : List ByteArray} {i : Nat} {o : Output}
    (h : o ∈ outputsAtBytes s0 bs i) (ho : o.isForward = true ∨ o.isAsk = true) :
    o ∈ outputsAt s0 (decoded bs) (idx bs i) ∧
      before s0 (decoded bs) (idx bs i) = beforeBytes s0 bs i ∧
      ∃ b x, bs[i]? = some b ∧ Wire.decodeInput b = some x ∧ (decoded bs)[idx bs i]? = some x := by
  unfold outputsAtBytes at h
  split at h
  · rename_i b hb
    cases hx : Wire.decodeInput b with
    | none =>
      rw [malformed_never_runs _ _ hx] at h
      simp only [List.mem_singleton] at h
      subst h; simp at ho
    | some x =>
      simp only [Wire.stepBytes, hx, step_out] at h
      have hd := decoded_at hb hx
      refine ⟨?_, (beforeBytes_eq s0 bs i).symm, b, x, hb, hx, hd⟩
      unfold outputsAt
      simp only [hd, step_out]
      rw [← beforeBytes_eq]
      exact h
  · simp at h

/-- **Single-use, for bytes.** A request forwards at most once in any byte trace. -/
theorem single_use_bytes {bogoId bootId : ByteArray} {bs : List ByteArray} {i j : Nat}
    {c c' : CallId} {r : ReqId} {u u' t t' : String} {a a' : Option JVal} {s1 s2 : Nat}
    (hi : Output.forward c (some r) u t a s1 ∈ outputsAtBytes (Boot bogoId bootId) bs i)
    (hj : Output.forward c' (some r) u' t' a' s2 ∈ outputsAtBytes (Boot bogoId bootId) bs j) :
    i = j := by
  obtain ⟨hi', -, b, x, hb, hx, -⟩ := bytes_lift hi (.inl rfl)
  obtain ⟨hj', -, b', x', hb', hx', -⟩ := bytes_lift hj (.inl rfl)
  have e := (single_use (bogoId := bogoId) (bootId := bootId)).1 hi' hj'
  rcases Nat.lt_trichotomy i j with h | h | h
  · have := idx_lt h hb hx; omega
  · exact h
  · have := idx_lt h hb' hx'; omega

/-- **Approved, for bytes.** -/
theorem approved_bytes {bogoId bootId : ByteArray} {bs : List ByteArray} {i : Nat} {c : CallId}
    {rid : ReqId} {u t : String} {args : Option JVal} {seq : Nat}
    (h : Output.forward c (some rid) u t args seq ∈ outputsAtBytes (Boot bogoId bootId) bs i) :
    let s := beforeBytes (Boot bogoId bootId) bs i
    ∃ q, findReq s rid = some q ∧ q.req.upstream = u ∧ q.req.tool = t ∧ q.req.args = args ∧
      ∃ S : List Approver, (S.map (·.id)).Nodup ∧
        (resolve s.cfg (agentName s q.req.agentId) q.name).requirement.need ≤ S.length ∧
        ∀ ap ∈ S, ap ∈ s.approvers ∧ ap.id ∈ q.eligible ∧
          OwnerApproved ap.alg ap.pk (sigMsg (encode q.req)) := by
  dsimp only
  obtain ⟨h', e, -⟩ := bytes_lift h (.inl rfl)
  rw [← e]
  rcases approved h' with ⟨hr, -⟩ | ⟨rid', q, hr, hq, -, hu, ht, ha, -, -, S, hnd, hn, -, hS⟩
  · cases hr
  · cases hr
    exact ⟨q, hq, hu, ht, ha, S, hnd, hn, fun ap hap =>
      ⟨(hS ap hap).1, (hS ap hap).2.1, (hS ap hap).2.2.2.2⟩⟩

end Bogo.Proofs
