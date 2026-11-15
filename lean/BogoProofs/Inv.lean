/-
What holds at every state of every trace, and what stays true once it becomes true:
request IDs are unique and never come back, a revoked approver stays unregistered, a revoked
agent stays revoked, a paused agent stays paused until the owner un-pauses it, and an ended
call stays ended until the agent makes a new call with that ID.
-/
import BogoProofs.Spec

namespace Bogo.Proofs
open Bogo

/-! ### Traces step by step -/

@[simp] theorem step_fst (s : State) (x : Input) : (step s x).1 = (handle s x).1 := rfl
@[simp] theorem step_out (s : State) (x : Input) : (step s x).2.1 = (handle s x).2 := rfl

theorem run_cons (s : State) (x : Input) (xs : List Input) :
    run s (x :: xs) = run (handle s x).1 xs := rfl

theorem run_append (s : State) (xs ys : List Input) : run s (xs ++ ys) = run (run s xs) ys := by
  simp [run, List.foldl_append]

theorem before_succ (s0 : State) (xs : List Input) (i : Nat) :
    before s0 xs (i + 1) = match xs[i]? with
      | some x => (handle (before s0 xs i) x).1
      | none => before s0 xs i := by
  unfold before
  rw [List.take_add_one]
  split <;> rename_i h <;> simp [h, run]

theorem before_succ_some {s0 : State} {xs : List Input} {i : Nat} {x : Input}
    (h : xs[i]? = some x) : before s0 xs (i + 1) = (handle (before s0 xs i) x).1 := by
  rw [before_succ, h]

theorem mem_outputsAt {s0 : State} {xs : List Input} {i : Nat} {o : Output}
    (h : o ∈ outputsAt s0 xs i) : ∃ x, xs[i]? = some x ∧ o ∈ (handle (before s0 xs i) x).2 := by
  unfold outputsAt at h
  split at h
  · rename_i x hx; exact ⟨x, hx, h⟩
  · simp at h

/-- A property every step keeps holds after any run. -/
theorem run_induct {P : State → Prop} (hstep : ∀ s x, P s → P (handle s x).1) :
    ∀ (xs : List Input) (s : State), P s → P (run s xs)
  | [], _, h => h
  | x :: xs, s, h => by rw [run_cons]; exact run_induct hstep xs _ (hstep s x h)

/-- A property that holds before step `m`, and that every step from `m` up to `J` keeps, holds
before every step from `m` to `J`. -/
theorem persist {P : State → Prop} {s0 : State} {xs : List Input} {m J : Nat}
    (hP : P (before s0 xs m))
    (hstep : ∀ l x, m ≤ l → l < J → xs[l]? = some x → P (before s0 xs l) →
      P (handle (before s0 xs l) x).1) :
    ∀ j, m ≤ j → j ≤ J → P (before s0 xs j) := by
  intro j hj
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le hj
  induction k with
  | zero => exact fun _ => hP
  | succ n ih =>
    intro hn
    have h := ih (by omega) (by omega)
    rw [show m + (n + 1) = (m + n) + 1 by omega, before_succ]
    split
    · rename_i x hx; exact hstep (m + n) x (by omega) (by omega) hx h
    · exact h

/-! ### Request IDs -/

theorem mkReqId_inj {b : ByteArray} {k k' : Nat} (hk : k < u64Bound) (hk' : k' < u64Bound)
    (h : mkReqId b k = mkReqId b k') : k = k' := by
  unfold mkReqId at h
  simp only [ByteArray.mk.injEq] at h
  have h' := List.toArray_inj h
  rw [List.append_cancel_left_eq] at h'
  have e1 := decU64_enc [] hk
  have e2 := decU64_enc [] hk'
  rw [h'] at e1
  rw [e1] at e2
  simpa using e2

theorem frz_req {q q' : ReqRec} (h : frz q = frz q') : q.req = q'.req := congrArg (·.1) h

theorem keptL_nonces {l l' : List ReqRec} (h : KeptL l l') :
    (l'.map (·.req.nonce)).Sublist (l.map (·.req.nonce)) := by
  have := h.map (fun t => t.1.nonce)
  simpa [List.map_map, Function.comp_def, frz] using this

theorem nodup_map_eq {α β : Type} {f : α → β} :
    ∀ {l : List α} {a b : α}, (l.map f).Nodup → a ∈ l → b ∈ l → f a = f b → a = b
  | [], _, _, _, ha, _, _ => by simp at ha
  | x :: l, a, b, hn, ha, hb, e => by
    simp only [List.map_cons, List.nodup_cons, List.mem_map, not_exists, not_and] at hn
    rcases List.mem_cons.mp ha with h1 | h1 <;> rcases List.mem_cons.mp hb with h2 | h2
    · rw [h1, h2]
    · subst h1; exact absurd e.symm (hn.1 b h2)
    · subst h2; exact absurd e (hn.1 a h1)
    · exact nodup_map_eq hn.2 h1 h2 e

/-- Every live request's ID is `bootId ‖ k` for a `k` already used, and no two live requests
share an ID. -/
def ReqsInv (s : State) : Prop :=
  (∀ q ∈ s.reqs, ∃ k < s.nextSeq, q.req.nonce = mkReqId s.bootId k) ∧
  (s.reqs.map (·.req.nonce)).Nodup

theorem reqsInv_kept {s s' : State} (h : ReqsInv s) (hk : KeptL s.reqs s'.reqs)
    (hb : s'.bootId = s.bootId) (hn : s'.nextSeq = s.nextSeq) : ReqsInv s' := by
  refine ⟨fun q' hq' => ?_, (keptL_nonces hk).nodup h.2⟩
  obtain ⟨q, hq, e⟩ := keptL_mem hk hq'
  obtain ⟨k, hk, hkq⟩ := h.1 q hq
  exact ⟨k, hn ▸ hk, by rw [← frz_req e, hkq, hb]⟩

theorem admitted_nonce {s : State} {sid : SessionId} {n : String} {a : Option JVal} {now : Nat}
    {q : ReqRec} (h : Admitted s sid n a now q) :
    q.req.nonce = mkReqId s.bootId s.nextSeq ∧ s.nextSeq < u64Bound := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hreq, _, _, _, hseq⟩ := h
  exact ⟨by rw [hreq], hseq⟩

theorem reqsInv_new {s s' : State} {q : ReqRec} (h : ReqsInv s) (hr : s'.reqs = q :: s.reqs)
    (hb : s'.bootId = s.bootId) (hn : s'.nextSeq = s.nextSeq + 1)
    (hq : q.req.nonce = mkReqId s.bootId s.nextSeq) (hseq : s.nextSeq < u64Bound) :
    ReqsInv s' := by
  refine ⟨fun q' hq' => ?_, ?_⟩
  · rw [hr] at hq'
    rcases List.mem_cons.mp hq' with rfl | hq'
    · exact ⟨s.nextSeq, by omega, by rw [hq, hb]⟩
    · obtain ⟨k, hk, e⟩ := h.1 q' hq'
      exact ⟨k, by omega, by rw [e, hb]⟩
  · rw [hr, List.map_cons, List.nodup_cons]
    refine ⟨fun hm => ?_, h.2⟩
    obtain ⟨q', hq', e⟩ := List.mem_map.mp hm
    obtain ⟨k, hk, e'⟩ := h.1 q' hq'
    rw [hq, e'] at e
    have := mkReqId_inj (by omega) hseq e
    omega

theorem reqsInv_step (s : State) (x : Input) (h : ReqsInv s) : ReqsInv (handle s x).1 := by
  by_cases hx : ∃ c sid n a now, x = .call c sid n a now
  · obtain ⟨c, sid, n, a, now, rfl⟩ := hx
    obtain ⟨hb, -, -, hk | ⟨q, hr, hn, ha, -⟩⟩ := onCall_shape s c sid n a now
    · exact reqsInv_kept h hk.1 hb hk.2.1
    · obtain ⟨hq, hseq⟩ := admitted_nonce ha
      exact reqsInv_new h hr hb hn hq hseq
  · simp only [not_exists] at hx
    obtain ⟨hk, -, hb, -, hn⟩ := handle_quietly s x hx
    exact reqsInv_kept h hk hb hn

/-- No live request has ID `r`. -/
def Gone (r : ReqId) (s : State) : Prop := ∀ q ∈ s.reqs, q.req.nonce ≠ r

/-- `r` was used and is gone: no step can bring it back. -/
def Spent (r : ReqId) (s : State) : Prop :=
  Gone r s ∧ ∃ k < s.nextSeq, r = mkReqId s.bootId k

theorem spent_step (s : State) (x : Input) {r : ReqId} (h : Spent r s) :
    Spent r (handle s x).1 := by
  obtain ⟨hg, k, hk, hr⟩ := h
  have kept : ∀ {s' : State}, KeptL s.reqs s'.reqs → s'.bootId = s.bootId →
      s.nextSeq ≤ s'.nextSeq → Spent r s' := by
    intro s' hk' hb hn
    refine ⟨fun q' hq' e => ?_, k, by omega, by rw [hb]; exact hr⟩
    obtain ⟨q, hq, e'⟩ := keptL_mem hk' hq'
    exact hg q hq (by rw [frz_req e', e])
  by_cases hx : ∃ c sid n a now, x = .call c sid n a now
  · obtain ⟨c, sid, n, a, now, rfl⟩ := hx
    obtain ⟨hb, -, -, hk' | ⟨q, hrq, hn, ha, -⟩⟩ := onCall_shape s c sid n a now
    · exact kept hk'.1 hb (by have := hk'.2.1; simp only [handle]; omega)
    · obtain ⟨hq, hseq⟩ := admitted_nonce ha
      refine ⟨fun q' hq' e => ?_, k, by simp only [handle]; omega, by simp only [handle]; rw [hb]; exact hr⟩
      simp only [handle] at hq'
      rw [hrq] at hq'
      rcases List.mem_cons.mp hq' with rfl | hq'
      · rw [hq, hr] at e
        have := mkReqId_inj hseq (by omega) e
        omega
      · exact hg q' hq' e
  · simp only [not_exists] at hx
    obtain ⟨hk', -, hb, -, hn⟩ := handle_quietly s x hx
    exact kept hk' hb (Nat.le_of_eq hn.symm)

/-! ### Approvers -/

@[simp] theorem endWhere_revokedApprovers (s : State) (p : ReqRec → Bool) (w : EndReason)
    (j : Rejection) : (endWhere s p w j).1.revokedApprovers = s.revokedApprovers := rfl

@[simp] theorem endWhere_cfg (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    (endWhere s p w j).1.cfg = s.cfg := rfl

/-- Only the owner's approver inputs change the approver registry. -/
theorem approvers_step (s : State) (x : Input) :
    ((handle s x).1.approvers = s.approvers ∧
      (handle s x).1.revokedApprovers = s.revokedApprovers) ∨
    (∃ seq a, x = .approverSet seq a) ∨ (∃ seq id, x = .approverRevoked seq id) := by
  cases x with
  | approverSet seq a => exact .inr (.inl ⟨seq, a, rfl⟩)
  | approverRevoked seq id => exact .inr (.inr ⟨seq, id, rfl⟩)
  | agentSet seq id n =>
    left; simp only [handle, onAgentSet]; split <;> simp [setAgent, bumpSeq]
  | agentRevoked seq id =>
    left; simp only [handle, onAgentRevoked, markRevoked, endWhere_approvers,
      endWhere_revokedApprovers]; split <;> simp [setAgent, bumpSeq]
  | sessionOpened sid a c =>
    left; simp only [handle, onSessionOpened]; split <;> simp
  | call c sid n a now =>
    left; simp only [handle, onCall, admitProtected]
    repeat' split
    all_goals simp
  | approval a r alg p now =>
    left; simp only [handle, onApproval, setReq]
    repeat' split
    all_goals simp
  | denial a r note =>
    left; simp only [handle, onDenial, setReq]
    repeat' split
    all_goals simp
  | pauseAgent a ag ep =>
    left; simp only [handle, onPauseAgent, pause, setAgent]
    repeat' split
    all_goals simp
  | ownerPause seq a =>
    left; simp only [handle, pause, setAgent]
    repeat' split
    all_goals simp [bumpSeq]
  | dispatch c now =>
    left; simp only [handle, onDispatch, removeCall]
    repeat' split
    all_goals simp
  | _ => left; simp [handle, bumpSeq, setAgent, onSessionClosed, onCallEnded, onNotSent,
      removeCall]

/-- No registered approver has a revoked ID. -/
def AppInv (s : State) : Prop := ∀ a ∈ s.approvers, a.id ∉ s.revokedApprovers

theorem appInv_step (s : State) (x : Input) (h : AppInv s) : AppInv (handle s x).1 := by
  rcases approvers_step s x with ⟨h1, h2⟩ | ⟨seq, a, rfl⟩ | ⟨seq, id, rfl⟩
  · intro a ha; rw [h1] at ha; rw [h2]; exact h a ha
  · simp only [handle, onApproverSet]
    split
    · exact h
    · rename_i hm
      intro b hb
      simp only [List.mem_cons, List.mem_filter] at hb
      rcases hb with rfl | ⟨hb, _⟩
      · simpa [bumpSeq] using hm
      · exact h b hb
  · unfold AppInv
    simp only [handle, onApproverRevoked, endWhere_approvers, endWhere_revokedApprovers, bumpSeq]
    intro b hb
    simp only [List.mem_filter] at hb
    have hne : b.id ≠ id := by simpa [eqB] using hb.2
    simp only [List.mem_cons, not_or]
    exact ⟨hne, h b hb.1⟩

theorem revoked_step (s : State) (x : Input) {a : ApproverId} (h : a ∈ s.revokedApprovers) :
    a ∈ (handle s x).1.revokedApprovers := by
  rcases approvers_step s x with ⟨_, h2⟩ | ⟨seq, b, rfl⟩ | ⟨seq, id, rfl⟩
  · rw [h2]; exact h
  · simp only [handle, onApproverSet]; split <;> simpa [bumpSeq] using h
  · simp only [handle, onApproverRevoked, endWhere_revokedApprovers]
    exact List.mem_cons_of_mem _ h

/-! ### The invariant -/

def Inv (s : State) : Prop := ReqsInv s ∧ AppInv s

theorem inv_step (s : State) (x : Input) (h : Inv s) : Inv (handle s x).1 :=
  ⟨reqsInv_step s x h.1, appInv_step s x h.2⟩

theorem inv_init (b i : ByteArray) : Inv (Boot b i) := by
  refine ⟨⟨?_, ?_⟩, ?_⟩ <;> simp [Boot, initState, AppInv]

theorem inv_before (b i : ByteArray) (xs : List Input) (n : Nat) : Inv (before (Boot b i) xs n) :=
  run_induct (P := Inv) inv_step _ _ (inv_init b i)

/-! ### Agents -/

/-- The agent is known, and every record with its ID is revoked. -/
def RevokedA (s : State) (a : AgentId) : Prop :=
  (∃ x ∈ s.agents, x.id = a) ∧ ∀ x ∈ s.agents, x.id = a → x.revoked = true

/-- The agent is known, and every record with its ID is paused. -/
def PausedA (s : State) (a : AgentId) : Prop :=
  (∃ x ∈ s.agents, x.id = a) ∧ ∀ x ∈ s.agents, x.id = a → x.paused = true

theorem revokedA_inactive {s : State} {a : AgentId} (h : RevokedA s a) : agentActive s a = false := by
  cases hc : agentActive s a
  · rfl
  · obtain ⟨x, hx, e, hr, -⟩ := agentActive_iff.mp hc
    rw [h.2 x hx e] at hr; cases hr

theorem pausedA_inactive {s : State} {a : AgentId} (h : PausedA s a) : agentActive s a = false := by
  cases hc : agentActive s a
  · rfl
  · obtain ⟨x, hx, e, -, hp⟩ := agentActive_iff.mp hc
    rw [h.2 x hx e] at hp; cases hp

theorem findAgent_none {s : State} {a : AgentId} (h : findAgent s a = none) :
    ∀ x ∈ s.agents, x.id ≠ a := by
  intro x hx e
  have := List.find?_eq_none.mp h x hx
  simp [e] at this

theorem mem_setAgent {s : State} {a : AgentId} {f : AgentRec → AgentRec} {y : AgentRec} :
    y ∈ (setAgent s a f).agents ↔ ∃ x ∈ s.agents, (if eqB x.id a then f x else x) = y := by
  simp [setAgent]

/-- Only these owner and approver inputs change the agent records. -/
theorem agents_step (s : State) (x : Input) :
    (handle s x).1.agents = s.agents ∨ (∃ seq id n, x = .agentSet seq id n) ∨
    (∃ seq id, x = .agentRevoked seq id) ∨ (∃ seq a, x = .ownerPause seq a) ∨
    (∃ seq id, x = .agentUnpaused seq id) ∨ (∃ ap a ep, x = .pauseAgent ap a ep) := by
  cases x with
  | agentSet seq id n => exact .inr (.inl ⟨seq, id, n, rfl⟩)
  | agentRevoked seq id => exact .inr (.inr (.inl ⟨seq, id, rfl⟩))
  | ownerPause seq a => exact .inr (.inr (.inr (.inl ⟨seq, a, rfl⟩)))
  | agentUnpaused seq id => exact .inr (.inr (.inr (.inr (.inl ⟨seq, id, rfl⟩))))
  | pauseAgent ap a ep => exact .inr (.inr (.inr (.inr (.inr ⟨ap, a, ep, rfl⟩))))
  | approverSet seq a =>
    left; simp only [handle, onApproverSet]; split <;> simp [bumpSeq]
  | approverRevoked seq id => left; simp [handle, onApproverRevoked, bumpSeq]
  | sessionOpened sid a c =>
    left; simp only [handle, onSessionOpened]; split <;> simp
  | call c sid n a now =>
    left; simp only [handle, onCall, admitProtected]
    repeat' split
    all_goals simp
  | approval a r alg p now =>
    left; simp only [handle, onApproval, setReq]
    repeat' split
    all_goals simp
  | denial a r note =>
    left; simp only [handle, onDenial, setReq]
    repeat' split
    all_goals simp
  | dispatch c now =>
    left; simp only [handle, onDispatch, removeCall]
    repeat' split
    all_goals simp
  | _ => left; simp [handle, bumpSeq, onSessionClosed, onCallEnded, onNotSent, removeCall]

/-- `setAgent` with an update that keeps IDs keeps the agent known. -/
theorem setAgent_known {s : State} {b a : AgentId} {f : AgentRec → AgentRec}
    (hf : ∀ x, (f x).id = x.id) (h : ∃ x ∈ s.agents, x.id = a) :
    ∃ x ∈ (setAgent s b f).agents, x.id = a := by
  obtain ⟨x, hx, e⟩ := h
  refine ⟨if eqB x.id b then f x else x, mem_setAgent.mpr ⟨x, hx, rfl⟩, ?_⟩
  split <;> simp [hf, e]

theorem setAgent_all {s : State} {b a : AgentId} {f : AgentRec → AgentRec} {P : AgentRec → Prop}
    (hf : ∀ x, (f x).id = x.id) (hP : ∀ x, x.id = a → eqB x.id b = true → P x → P (f x))
    (h : ∀ x ∈ s.agents, x.id = a → P x) :
    ∀ x ∈ (setAgent s b f).agents, x.id = a → P x := by
  intro y hy e
  obtain ⟨x, hx, rfl⟩ := mem_setAgent.mp hy
  by_cases hb : eqB x.id b = true
  · simp only [hb, ↓reduceIte] at e ⊢; rw [hf] at e; exact hP x e hb (h x hx e)
  · simp only [hb] at e ⊢; exact h x hx e

theorem revokedA_setAgent {s : State} {b a : AgentId} {f : AgentRec → AgentRec}
    (hf : ∀ x, (f x).id = x.id) (hr : ∀ x, x.revoked = true → (f x).revoked = true)
    (h : RevokedA s a) : RevokedA (setAgent s b f) a :=
  ⟨setAgent_known hf h.1, setAgent_all (P := fun x => x.revoked = true) hf (fun x _ _ => hr x) h.2⟩

theorem pausedA_setAgent {s : State} {b a : AgentId} {f : AgentRec → AgentRec}
    (hf : ∀ x, (f x).id = x.id)
    (hp : ∀ x, x.id = a → eqB x.id b = true → x.paused = true → (f x).paused = true)
    (h : PausedA s a) : PausedA (setAgent s b f) a :=
  ⟨setAgent_known hf h.1, setAgent_all (P := fun x => x.paused = true) hf hp h.2⟩

/-- Revocation of an agent is permanent. -/
theorem revokedA_step (s : State) (x : Input) {a : AgentId} (h : RevokedA s a) :
    RevokedA (handle s x).1 a := by
  rcases agents_step s x with e | ⟨seq, id, n, rfl⟩ | ⟨seq, id, rfl⟩ | ⟨seq, b, rfl⟩ |
      ⟨seq, id, rfl⟩ | ⟨ap, b, ep, rfl⟩
  · unfold RevokedA; rw [e]; exact h
  · simp only [handle, onAgentSet]
    split
    · exact revokedA_setAgent (fun _ => rfl) (fun _ h => h) h
    · rename_i hn
      refine ⟨?_, ?_⟩
      · obtain ⟨y, hy, e⟩ := h.1; exact ⟨y, List.mem_cons_of_mem _ hy, e⟩
      · intro y hy e
        rcases List.mem_cons.mp hy with rfl | hy
        · exact absurd h.1 (by
            rintro ⟨z, hz, ez⟩
            exact findAgent_none hn z hz (by simp [bumpSeq] at *; rw [ez, ← e]))
        · exact h.2 y hy e
  · simp only [handle, onAgentRevoked]
    unfold RevokedA; simp only [endWhere_agents]
    unfold markRevoked
    split
    · exact revokedA_setAgent (fun _ => rfl) (fun _ _ => rfl) h
    · refine ⟨?_, ?_⟩
      · obtain ⟨y, hy, e⟩ := h.1; exact ⟨y, List.mem_cons_of_mem _ hy, e⟩
      · intro y hy e
        rcases List.mem_cons.mp hy with rfl | hy
        · rfl
        · exact h.2 y hy e
  · simp only [handle]
    split
    · unfold pause; unfold RevokedA; simp only [endWhere_agents]
      exact revokedA_setAgent (fun _ => rfl) (fun _ h => h) h
    · exact h
  · simp only [handle]
    exact revokedA_setAgent (fun _ => rfl) (fun _ h => h) h
  · simp only [handle, onPauseAgent]
    split
    · split
      · unfold pause; unfold RevokedA; simp only [endWhere_agents]
        exact revokedA_setAgent (fun _ => rfl) (fun _ h => h) h
      · exact h
    · exact h

/-- A pause lasts until the owner un-pauses that agent. -/
theorem pausedA_step (s : State) (x : Input) {a : AgentId} (h : PausedA s a)
    (hu : ∀ seq, x ≠ .agentUnpaused seq a) : PausedA (handle s x).1 a := by
  rcases agents_step s x with e | ⟨seq, id, n, rfl⟩ | ⟨seq, id, rfl⟩ | ⟨seq, b, rfl⟩ |
      ⟨seq, id, rfl⟩ | ⟨ap, b, ep, rfl⟩
  · unfold PausedA; rw [e]; exact h
  · simp only [handle, onAgentSet]
    split
    · exact pausedA_setAgent (fun _ => rfl) (fun _ _ _ h => h) h
    · rename_i hn
      refine ⟨?_, ?_⟩
      · obtain ⟨y, hy, e⟩ := h.1; exact ⟨y, List.mem_cons_of_mem _ hy, e⟩
      · intro y hy e
        rcases List.mem_cons.mp hy with rfl | hy
        · exact absurd h.1 (by
            rintro ⟨z, hz, ez⟩
            exact findAgent_none hn z hz (by simp [bumpSeq] at *; rw [ez, ← e]))
        · exact h.2 y hy e
  · simp only [handle, onAgentRevoked]
    unfold PausedA; simp only [endWhere_agents]
    unfold markRevoked
    split
    · exact pausedA_setAgent (fun _ => rfl) (fun _ _ _ h => h) h
    · rename_i hn
      refine ⟨?_, ?_⟩
      · obtain ⟨y, hy, e⟩ := h.1; exact ⟨y, List.mem_cons_of_mem _ hy, e⟩
      · intro y hy e
        rcases List.mem_cons.mp hy with rfl | hy
        · exact absurd h.1 (by
            rintro ⟨z, hz, ez⟩
            exact findAgent_none hn z hz (by simp [bumpSeq] at *; rw [ez, ← e]))
        · exact h.2 y hy e
  · simp only [handle]
    split
    · unfold pause; unfold PausedA; simp only [endWhere_agents]
      exact pausedA_setAgent (fun _ => rfl) (fun _ _ _ _ => rfl) h
    · exact h
  · have hne : id ≠ a := fun e => hu seq (by rw [e])
    simp only [handle]
    refine pausedA_setAgent (fun _ => rfl) ?_ h
    intro y hy hb _
    simp only [eqB_iff] at hb
    exact absurd (hb.symm.trans hy) hne
  · simp only [handle, onPauseAgent]
    split
    · split
      · unfold pause; unfold PausedA; simp only [endWhere_agents]
        exact pausedA_setAgent (fun _ => rfl) (fun _ _ _ _ => rfl) h
      · exact h
    · exact h

/-- After `setAgent s a f`, every record with ID `a` went through `f`. -/
theorem setAgent_self_all {s : State} {a : AgentId} {f : AgentRec → AgentRec}
    {P : AgentRec → Prop} (hP : ∀ x, P (f x)) :
    ∀ y ∈ (setAgent s a f).agents, y.id = a → P y := by
  intro y hy e
  obtain ⟨x, hx, rfl⟩ := mem_setAgent.mp hy
  by_cases hb : eqB x.id a = true
  · simp only [hb, ↓reduceIte]; exact hP x
  · have e' : x.id = a := by simpa [hb] using e
    simp [e', eqB] at hb

theorem setAgent_self_known {s : State} {a : AgentId} {f : AgentRec → AgentRec}
    (hf : ∀ x, (f x).id = x.id) {y : AgentRec} (hy : findAgent s a = some y) :
    ∃ x ∈ (setAgent s a f).agents, x.id = a := by
  have ⟨hy1, hy2⟩ := findAgent_spec hy
  exact setAgent_known hf ⟨y, hy1, hy2⟩

/-- After `agentRevoked`, the agent is revoked. -/
theorem revokedA_after (s : State) (seq : Nat) (a : AgentId) :
    RevokedA (handle s (.agentRevoked seq a)).1 a := by
  simp only [handle, onAgentRevoked]
  unfold RevokedA; simp only [endWhere_agents]
  unfold markRevoked
  split
  · rename_i y hy
    exact ⟨setAgent_self_known (fun _ => rfl) hy,
      setAgent_self_all (P := fun x => x.revoked = true) (fun _ => rfl)⟩
  · rename_i hn
    refine ⟨⟨_, List.mem_cons_self, rfl⟩, ?_⟩
    intro y hy e
    rcases List.mem_cons.mp hy with rfl | hy
    · rfl
    · exact absurd e (findAgent_none hn y hy)

theorem endWhere_no_agentPaused (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection)
    (a : AgentId) : Output.agentPaused a ∉ (endWhere s p w j).2 := by
  intro ho
  simp only [endWhere, List.mem_flatMap, List.mem_filter] at ho
  obtain ⟨r, _, hr⟩ := ho
  rcases List.mem_append.mp hr with h | h
  · split at h <;> simp at h
  · simp at h

@[simp] def _root_.Bogo.Output.isPause : Output → Bool
  | .agentPaused _ => true
  | _ => false

/-- No `agentPaused` among these outputs. -/
def Calm (outs : List Output) : Prop := ∀ o ∈ outs, o.isPause = false

@[simp] theorem calm_nil : Calm [] := by simp [Calm]

@[simp] theorem calm_cons {o : Output} {l : List Output} :
    Calm (o :: l) ↔ o.isPause = false ∧ Calm l := by simp [Calm]

@[simp] theorem calm_append {a b : List Output} : Calm (a ++ b) ↔ Calm a ∧ Calm b := by
  simp only [Calm, List.mem_append]
  exact ⟨fun h => ⟨fun o ho => h o (.inl ho), fun o ho => h o (.inr ho)⟩,
    fun h o ho => ho.elim (h.1 o) (h.2 o)⟩

@[simp] theorem endWhere_calm (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    Calm (endWhere s p w j).2 := by
  intro o ho
  simp only [endWhere, List.mem_flatMap, List.mem_filter] at ho
  obtain ⟨r, _, hr⟩ := ho
  rcases List.mem_append.mp hr with h | h
  · split at h <;> simp_all
  · simp at h; subst h; simp

@[simp] theorem allowedReject_calm (s : State) (c : CallId) (j : Rejection) :
    Calm (allowedReject s c j) := by
  unfold allowedReject
  split <;> simp

theorem filterMap_reject_calm (cs : List CallRec) :
    Calm (cs.filterMap (fun c => match c.status with
      | .allowed .. => some (Output.reject c.id .endedWithoutDecision)
      | .bound _ => none)) := by
  intro o ho
  simp only [List.mem_filterMap] at ho
  obtain ⟨c, _, hc⟩ := ho
  split at hc <;> simp at hc
  subst hc; simp

/-- A step that reports `agentPaused a` leaves `a` paused, with no live request left. -/
theorem agentPaused_out (s : State) (x : Input) {a : AgentId}
    (h : Output.agentPaused a ∈ (handle s x).2) :
    PausedA (handle s x).1 a ∧ ∀ q ∈ (handle s x).1.reqs, q.req.agentId ≠ a := by
  have hp : ∀ (s : State) (b : AgentId), (∃ y, findAgent s b = some y) →
      Output.agentPaused a ∈ (pause s b).2 →
      PausedA (pause s b).1 a ∧ ∀ q ∈ (pause s b).1.reqs, q.req.agentId ≠ a := by
    intro s b ⟨y, hy⟩ ho
    have hab : b = a := by
      simp only [pause, List.mem_append, List.mem_singleton, Output.agentPaused.injEq] at ho
      rcases ho with ho | ho
      · exact absurd ho (endWhere_no_agentPaused _ _ _ _ _)
      · exact ho.symm
    subst hab
    refine ⟨?_, ?_⟩
    · unfold pause PausedA; simp only [endWhere_agents]
      exact ⟨setAgent_self_known (fun _ => rfl) hy,
        setAgent_self_all (P := fun x => x.paused = true) (fun _ => rfl)⟩
    · intro q hq e
      simp only [pause, endWhere_reqs, List.mem_filter, setAgent] at hq
      simp [e, eqB] at hq
  cases x with
  | ownerPause seq b =>
    simp only [handle] at h ⊢
    cases hf : findAgent s b with
    | none => simp [hf] at h
    | some y =>
      simp only [hf] at h ⊢
      exact hp _ b ⟨y, by simpa [findAgent, bumpSeq] using hf⟩ h
  | pauseAgent ap b ep =>
    simp only [handle, onPauseAgent] at h ⊢
    cases hp1 : findApprover s ap with
    | none => simp [hp1] at h
    | some z =>
      cases hf : findAgent s b with
      | none => simp [hp1, hf] at h
      | some y =>
        simp only [hp1, hf] at h ⊢
        by_cases he : (y.epoch == ep) = true
        · simp only [he, ↓reduceIte] at h ⊢; exact hp _ b ⟨y, hf⟩ h
        · simp only [he] at h; simp at h
  | sessionClosed sid =>
    exfalso
    have hc : Calm (handle s (.sessionClosed sid)).2 := by
      simp only [handle, onSessionClosed, calm_append, endWhere_calm, and_true]
      exact filterMap_reject_calm _
    exact absurd (hc _ h) (by simp)
  | _ =>
    exfalso
    revert h
    simp only [handle, onCall, admitProtected, onApproval, onDenial, onApproverRevoked,
      onAgentRevoked, onCallEnded, onNotSent, onDispatch]
    intro h
    have hc : ∀ {l : List Output}, Calm l → Output.agentPaused a ∉ l :=
      fun hl ho => absurd (hl _ ho) (by simp)
    revert h
    apply hc
    repeat' split
    all_goals simp

end Bogo.Proofs
