/-
Lemmas about the decision core (`BogoCore.Core`): what each check means, where `forward` and
`ask` can come from, how request records evolve, and what each ending removes.
-/
import BogoProofs.Decode
import BogoCore.Ffi

namespace Bogo.Proofs
open Bogo

/-! ### Booleans that mean what they say -/

@[simp] theorem eqB_iff {a b : ByteArray} : eqB a b = true ↔ a = b := by simp [eqB]

@[simp] theorem memB_iff {x : ByteArray} {xs : List ByteArray} : memB x xs = true ↔ x ∈ xs := by
  simp only [memB, List.any_eq_true, eqB_iff]
  exact ⟨fun ⟨y, hy, e⟩ => e ▸ hy, fun h => ⟨x, h, rfl⟩⟩

theorem find?_mem {α : Type} {p : α → Bool} {l : List α} {a : α} (h : l.find? p = some a) :
    a ∈ l ∧ p a = true := ⟨List.mem_of_find?_eq_some h, List.find?_some h⟩

theorem findSession_spec {s : State} {sid : SessionId} {x : SessionRec}
    (h : findSession s sid = some x) : x ∈ s.sessions ∧ x.id = sid := by
  have := find?_mem h; simpa using this

theorem findAgent_spec {s : State} {a : AgentId} {x : AgentRec}
    (h : findAgent s a = some x) : x ∈ s.agents ∧ x.id = a := by
  have := find?_mem h; simpa using this

theorem findCall_spec {s : State} {c : CallId} {x : CallRec}
    (h : findCall s c = some x) : x ∈ s.calls ∧ x.id = c := by
  have := find?_mem h; simpa using this

theorem findReq_spec {s : State} {r : ReqId} {x : ReqRec}
    (h : findReq s r = some x) : x ∈ s.reqs ∧ x.req.nonce = r := by
  have := find?_mem h; simpa using this

theorem findCatalog_spec {s : State} {n : String} {x : CatalogEntry}
    (h : findCatalog s n = some x) : x ∈ s.catalog ∧ x.name = n := by
  have := find?_mem h; simpa using this

theorem agentActive_iff {s : State} {a : AgentId} :
    agentActive s a = true ↔ ∃ x ∈ s.agents, x.id = a ∧ x.revoked = false ∧ x.paused = false := by
  simp [agentActive, List.any_eq_true, Bool.and_eq_true, and_assoc]

theorem notExpired_iff {r : Request} {now : Nat} :
    notExpired r now = true ↔ ∀ e, r.expiresMs = some e → now < e := by
  unfold notExpired
  cases r.expiresMs <;> simp

/-- A requirement is met by a list of counted approvals with distinct IDs, each still valid. -/
theorem requirementMet_spec {s : State} {q : ReqRec} (h : requirementMet s q = true) :
    ∃ S : List Counted, (∀ e ∈ S, e ∈ q.counted ∧ countedValid s q e = true) ∧
      (S.map (·.id)).Nodup ∧ q.requirement.need ≤ S.length := by
  simp only [requirementMet, Bool.and_eq_true, decide_eq_true_eq] at h
  refine ⟨validCounted s q, fun e he => ?_, h.1, h.2⟩
  simp only [validCounted, List.mem_filter] at he
  exact he

theorem countedValid_spec {s : State} {q : ReqRec} {e : Counted}
    (h : countedValid s q e = true) :
    e.id ∈ q.eligible ∧ (∃ a ∈ s.approvers, a.id = e.id ∧ a.alg = e.alg ∧ a.pk = e.pk) ∧
      verify e.alg e.pk (sigMsg (encode q.req)) e.proof = true := by
  simp only [countedValid, recMsg, Bool.and_eq_true, memB_iff, List.any_eq_true] at h
  obtain ⟨⟨h1, h2⟩, h3⟩ := h
  refine ⟨h1, ?_, h3⟩
  obtain ⟨a, ha, h4⟩ := h2
  simp only [eqB_iff, beq_iff_eq] at h4
  exact ⟨a, ha, h4.1.1, h4.1.2, h4.2⟩

/-! ### The gates -/

/-- What `allowedGate` checks, spelled out. -/
theorem allowedGate_spec {s : State} {cr : CallRec} {name u t : String}
    (h : allowedGate s cr name u t = true) :
    ∃ sess, findSession s cr.session = some sess ∧ agentActive s sess.agent = true ∧
      (∃ e, findCatalog s name = some e ∧ e.upstream = u ∧ e.tool = t) ∧
      (resolve s.cfg (agentName s sess.agent) name).kind = .allow := by
  unfold allowedGate at h
  split at h
  · simp at h
  · rename_i sess hs
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨⟨h1, h2⟩, h3⟩ := h
    refine ⟨sess, hs, h1, ?_, h3⟩
    split at h2
    · rename_i e he
      simp only [Bool.and_eq_true, beq_iff_eq] at h2
      exact ⟨e, he, h2.1, h2.2⟩
    · simp at h2

/-- What `standsNow` checks, spelled out. -/
theorem standsNow_spec {s : State} {q : ReqRec} {pol : ToolPolicy} {e : Counted}
    (h : standsNow s q pol e = true) :
    e.id ∈ q.eligible ∧ e.id ∉ q.denied ∧
      (∃ a ∈ s.approvers, a.id = e.id ∧ a.alg = e.alg ∧ a.pk = e.pk ∧
        (pol.approvers = [] ∨ a.name ∈ pol.approvers)) ∧
      verify e.alg e.pk (sigMsg (encode q.req)) e.proof = true := by
  simp only [standsNow, recMsg, Bool.and_eq_true, memB_iff, List.any_eq_true] at h
  obtain ⟨⟨⟨h1, h0⟩, a, ha, h2⟩, h3⟩ := h
  simp only [eqB_iff, beq_iff_eq, Bool.or_eq_true, List.isEmpty_iff,
    List.contains_iff_mem] at h2
  refine ⟨h1, fun hd => ?_, ⟨a, ha, h2.1.1.1, h2.1.1.2, h2.1.2, h2.2⟩, h3⟩
  rw [show memB e.id q.denied = true from memB_iff.mpr hd] at h0; cases h0

/-- Distinct standing approvals, enough for both requirements. -/
theorem gateMet_spec {s : State} {q : ReqRec} {pol : ToolPolicy} (h : gateMet s q pol = true) :
    ∃ S : List Counted, (∀ e ∈ S, e ∈ q.counted ∧ standsNow s q pol e = true) ∧
      (S.map (·.id)).Nodup ∧ q.requirement.need ≤ S.length ∧ pol.requirement.need ≤ S.length := by
  simp only [gateMet, Bool.and_eq_true, decide_eq_true_eq] at h
  refine ⟨q.counted.filter (standsNow s q pol), fun e he => ?_, h.1.1, h.1.2, h.2⟩
  simpa using he

/-- What `protectedGate` checks, spelled out. -/
theorem protectedGate_spec {s : State} {cr : CallRec} {q : ReqRec} {now : Nat}
    (h : protectedGate s cr q now = true) :
    q.status = .settled ∧ q.call = some cr.id ∧ q.req.session = cr.session ∧
      (∃ sess, findSession s cr.session = some sess ∧ sess.agent = q.req.agentId ∧
        agentActive s sess.agent = true) ∧
      notExpired q.req now = true ∧
      (∃ e, findCatalog s q.name = some e ∧ e.upstream = q.req.upstream ∧
        e.tool = q.req.tool) ∧
      (resolve s.cfg (agentName s q.req.agentId) q.name).kind = .approve ∧
      q.req.wf = true ∧ gateMet s q (resolve s.cfg (agentName s q.req.agentId) q.name) = true := by
  unfold protectedGate at h
  simp only [Bool.and_eq_true, beq_iff_eq] at h
  obtain ⟨⟨⟨⟨⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩, h6⟩, h7⟩, h8⟩, h9⟩ := h
  refine ⟨h1, ?_, by simpa using h3, ?_, h5, ?_, h7, h8, h9⟩
  · cases hc : q.call with
    | none => simp [hc] at h2
    | some c => simp [hc] at h2; rw [h2]
  · split at h4
    · rename_i sess hs
      simp only [Bool.and_eq_true, eqB_iff] at h4
      exact ⟨sess, hs, h4.1, h4.2⟩
    · simp at h4
  · split at h6
    · rename_i e he
      simp only [Bool.and_eq_true, beq_iff_eq] at h6
      exact ⟨e, he, h6.1, h6.2⟩
    · simp at h6

/-! ### Where `forward` and `ask` come from -/

@[simp] def _root_.Bogo.Output.isForward : Output → Bool
  | .forward .. => true
  | _ => false

@[simp] def _root_.Bogo.Output.isAsk : Output → Bool
  | .ask .. => true
  | _ => false

/-- Neither a forward nor an ask. -/
def Quiet (outs : List Output) : Prop := ∀ o ∈ outs, o.isForward = false ∧ o.isAsk = false

@[simp] theorem quiet_nil : Quiet [] := by simp [Quiet]

@[simp] theorem quiet_cons {o : Output} {l : List Output} :
    Quiet (o :: l) ↔ (o.isForward = false ∧ o.isAsk = false) ∧ Quiet l := by
  simp [Quiet]

@[simp] theorem quiet_append {a b : List Output} : Quiet (a ++ b) ↔ Quiet a ∧ Quiet b := by
  simp only [Quiet, List.mem_append]
  exact ⟨fun h => ⟨fun o ho => h o (.inl ho), fun o ho => h o (.inr ho)⟩,
    fun h o ho => ho.elim (h.1 o) (h.2 o)⟩

@[simp] theorem endWhere_quiet (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    Quiet (endWhere s p w j).2 := by
  intro o ho
  simp only [endWhere, List.mem_flatMap, List.mem_filter] at ho
  obtain ⟨r, _, hr⟩ := ho
  rcases List.mem_append.mp hr with h | h
  · split at h <;> simp_all
  · simp at h; subst h; simp

@[simp] theorem allowedReject_quiet (s : State) (c : CallId) (j : Rejection) :
    Quiet (allowedReject s c j) := by
  unfold allowedReject
  split <;> simp

theorem filterMap_reject_quiet (cs : List CallRec) :
    Quiet (cs.filterMap (fun c => match c.status with
      | .allowed .. => some (Output.reject c.id .endedWithoutDecision)
      | .bound _ => none)) := by
  intro o ho
  simp only [List.mem_filterMap] at ho
  obtain ⟨c, _, hc⟩ := ho
  split at hc <;> simp at hc
  subst hc; simp

/-- Everything but `call` and `dispatch` is quiet: no forward, no ask. -/
theorem handle_quiet (s : State) (x : Input)
    (hc : ∀ c sid n a now, x ≠ .call c sid n a now) (hd : ∀ c now, x ≠ .dispatch c now) :
    Quiet (handle s x).2 := by
  cases x with
  | call c sid n a now => exact absurd rfl (hc c sid n a now)
  | dispatch c now => exact absurd rfl (hd c now)
  | sessionClosed sid =>
    simp only [handle, onSessionClosed, quiet_append, endWhere_quiet, and_true]
    exact filterMap_reject_quiet _
  | _ =>
    simp only [handle, onApproverRevoked, onAgentRevoked, onCallEnded, onNotSent, onApproval,
      onDenial, onPauseAgent, pause]
    repeat' split
    all_goals simp

/-- No forward among these outputs. -/
def NoFwd (outs : List Output) : Prop := ∀ o ∈ outs, o.isForward = false

@[simp] theorem noFwd_nil : NoFwd [] := by simp [NoFwd]

@[simp] theorem noFwd_cons {o : Output} {l : List Output} :
    NoFwd (o :: l) ↔ o.isForward = false ∧ NoFwd l := by
  simp [NoFwd]

@[simp] theorem noFwd_append {a b : List Output} : NoFwd (a ++ b) ↔ NoFwd a ∧ NoFwd b := by
  simp only [NoFwd, List.mem_append]
  exact ⟨fun h => ⟨fun o ho => h o (.inl ho), fun o ho => h o (.inr ho)⟩,
    fun h o ho => ho.elim (h.1 o) (h.2 o)⟩

/-- A call never forwards. -/
theorem onCall_noForward (s : State) (c : CallId) (sid : SessionId) (n : String)
    (a : Option JVal) (now : Nat) : NoFwd (onCall s c sid n a now).2 := by
  simp only [onCall, admitProtected]
  repeat' split
  all_goals simp

/-- Only `dispatch` can forward. -/
theorem forward_only_dispatch {s : State} {x : Input} {o : Output} (ho : o ∈ (handle s x).2)
    (hf : o.isForward = true) : ∃ c now, x = .dispatch c now := by
  by_cases h1 : ∃ c sid n a now, x = .call c sid n a now
  · obtain ⟨c, sid, n, a, now, rfl⟩ := h1
    have := onCall_noForward s c sid n a now o ho
    rw [hf] at this; cases this
  by_cases h2 : ∃ c now, x = .dispatch c now
  · exact h2
  · simp only [not_exists] at h1 h2
    have := (handle_quiet s x h1 h2 o ho).1
    rw [hf] at this; cases this

/-- What a forward from `dispatch` carries, and what had to hold for it. -/
theorem onDispatch_forward {s : State} {c : CallId} {now : Nat} {c' : CallId}
    {r : Option ReqId} {u t : String} {a : Option JVal} {seq : Nat}
    (h : Output.forward c' r u t a seq ∈ (onDispatch s c now).2) :
    c' = c ∧ seq = s.registrySeq ∧ (onDispatch s c now).2 = [.forward c' r u t a seq] ∧
    (onDispatch s c now).1.calls = s.calls.filter (fun x => !eqB x.id c) ∧
    ∃ cr, findCall s c = some cr ∧
      ((r = none ∧ (∃ name, cr.status = .allowed name u t a ∧
          allowedGate s cr name u t = true) ∧ (onDispatch s c now).1.reqs = s.reqs) ∨
       (∃ rid q, r = some rid ∧ cr.status = .bound rid ∧ findReq s rid = some q ∧
          protectedGate s cr q now = true ∧ u = q.req.upstream ∧ t = q.req.tool ∧
          a = q.req.args ∧
          (onDispatch s c now).1.reqs = s.reqs.filter (fun x => !isReq rid x))) := by
  unfold onDispatch at h ⊢
  split at h
  · simp at h
  · rename_i cr hcr
    split at h
    · rename_i name u' t' a' hst
      split at h
      · rename_i hg
        simp only [List.mem_singleton, Output.forward.injEq] at h
        obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩ := h
        refine ⟨rfl, rfl, by simp [hg], by simp [hg, removeCall], cr, hcr,
          .inl ⟨rfl, ⟨name, hst, hg⟩, by simp [hg, removeCall]⟩⟩
      · simp at h
    · rename_i rid hst
      split at h
      · simp at h
      · rename_i q hq
        split at h
        · rename_i hg
          simp only [List.mem_singleton, Output.forward.injEq] at h
          obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl⟩ := h
          refine ⟨rfl, rfl, by simp [hg], by simp [hg, removeCall], cr,
            hcr, .inr ⟨rid, q, rfl, hst, hq, hg, rfl, rfl, rfl,
              by simp [hg, removeCall]⟩⟩
        · simp only [List.mem_append] at h
          rcases h with h | h
          · split at h <;> simp at h
          · have := endWhere_quiet _ _ _ _ _ h
            simp at this

end Bogo.Proofs
