/-
How one step changes the state: which request records and calls can appear, what never
changes, and what each ending removes.
-/
import BogoProofs.Core

namespace Bogo.Proofs
open Bogo

/-! ### What a request record keeps from its admission -/

/-- The part of a request record fixed at admission. -/
def frz (q : ReqRec) : Request × String × Requirement × DenyRule × Mode × List ApproverId :=
  (q.req, q.name, q.requirement, q.denyRule, q.mode, q.eligible)

/-- Every record in `l'` comes from a record in `l` with the same admission context. -/
def KeptL (l l' : List ReqRec) : Prop := ∀ q' ∈ l', ∃ q ∈ l, frz q = frz q'

@[simp] theorem keptL_refl (l : List ReqRec) : KeptL l l := fun q h => ⟨q, h, rfl⟩

@[simp] theorem keptL_filter {l l' : List ReqRec} {p : ReqRec → Bool} (h : KeptL l l') :
    KeptL l (l'.filter p) := by
  intro q hq
  exact h q (List.mem_filter.mp hq).1

@[simp] theorem keptL_map {l l' : List ReqRec} {f : ReqRec → ReqRec}
    (hf : ∀ x, frz (f x) = frz x) (h : KeptL l l') : KeptL l (l'.map f) := by
  intro q hq
  obtain ⟨x, hx, rfl⟩ := List.mem_map.mp hq
  obtain ⟨y, hy, e⟩ := h x hx
  exact ⟨y, hy, by rw [e, hf]⟩

theorem frz_ite {c : Bool} {g : ReqRec → ReqRec} (hg : ∀ x, frz (g x) = frz x) (x : ReqRec) :
    frz (if c then g x else x) = frz x := by
  split <;> simp [hg]

/-- Calls in `l'` were all in `l`. -/
def CallsL (l l' : List CallRec) : Prop := ∀ c ∈ l', c ∈ l

@[simp] theorem callsL_refl (l : List CallRec) : CallsL l l := fun _ h => h

@[simp] theorem callsL_filter {l l' : List CallRec} {p : CallRec → Bool} (h : CallsL l l') :
    CallsL l (l'.filter p) := fun c hc => h c (List.mem_filter.mp hc).1

/-- One step that adds no request record and no call, and keeps the IDs and the counter. -/
def Quietly (s s' : State) : Prop :=
  KeptL s.reqs s'.reqs ∧ CallsL s.calls s'.calls ∧
    s'.bootId = s.bootId ∧ s'.bogoId = s.bogoId ∧ s'.nextSeq = s.nextSeq

@[simp] theorem endWhere_reqs (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    (endWhere s p w j).1.reqs = s.reqs.filter (fun r => !p r) := rfl

@[simp] theorem endWhere_calls (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    (endWhere s p w j).1.calls =
      s.calls.filter (fun c => !memB c.id ((s.reqs.filter p).filterMap (·.call))) := rfl

@[simp] theorem endWhere_bootId (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    (endWhere s p w j).1.bootId = s.bootId := rfl

@[simp] theorem endWhere_bogoId (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    (endWhere s p w j).1.bogoId = s.bogoId := rfl

@[simp] theorem endWhere_nextSeq (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    (endWhere s p w j).1.nextSeq = s.nextSeq := rfl

@[simp] theorem endWhere_agents (s : State) (p : ReqRec → Bool) (w : EndReason) (j : Rejection) :
    (endWhere s p w j).1.agents = s.agents := rfl

@[simp] theorem endWhere_sessions (s : State) (p : ReqRec → Bool) (w : EndReason)
    (j : Rejection) : (endWhere s p w j).1.sessions = s.sessions := rfl

@[simp] theorem endWhere_approvers (s : State) (p : ReqRec → Bool) (w : EndReason)
    (j : Rejection) : (endWhere s p w j).1.approvers = s.approvers := rfl

theorem onApproverSet_eq (s : State) (a : Approver) :
    (onApproverSet s a).reqs = s.reqs ∧ (onApproverSet s a).calls = s.calls ∧
    (onApproverSet s a).bootId = s.bootId ∧ (onApproverSet s a).bogoId = s.bogoId ∧
    (onApproverSet s a).nextSeq = s.nextSeq ∧ (onApproverSet s a).agents = s.agents ∧
    (onApproverSet s a).sessions = s.sessions := by
  unfold onApproverSet; split <;> simp

theorem onAgentSet_eq (s : State) (id : AgentId) (n : String) :
    (onAgentSet s id n).reqs = s.reqs ∧ (onAgentSet s id n).calls = s.calls ∧
    (onAgentSet s id n).bootId = s.bootId ∧ (onAgentSet s id n).bogoId = s.bogoId ∧
    (onAgentSet s id n).nextSeq = s.nextSeq ∧ (onAgentSet s id n).sessions = s.sessions := by
  unfold onAgentSet; split <;> simp [setAgent]

theorem markRevoked_eq (s : State) (id : AgentId) :
    (markRevoked s id).reqs = s.reqs ∧ (markRevoked s id).calls = s.calls ∧
    (markRevoked s id).bootId = s.bootId ∧ (markRevoked s id).bogoId = s.bogoId ∧
    (markRevoked s id).nextSeq = s.nextSeq ∧ (markRevoked s id).sessions = s.sessions := by
  unfold markRevoked; split <;> simp [setAgent]

theorem onSessionOpened_eq (s : State) (sid : SessionId) (a : AgentId) (c : Option String) :
    (onSessionOpened s sid a c).reqs = s.reqs ∧ (onSessionOpened s sid a c).calls = s.calls ∧
    (onSessionOpened s sid a c).bootId = s.bootId ∧
    (onSessionOpened s sid a c).bogoId = s.bogoId ∧
    (onSessionOpened s sid a c).nextSeq = s.nextSeq ∧
    (onSessionOpened s sid a c).agents = s.agents := by
  unfold onSessionOpened; split <;> simp

/-- Every input except `call` adds no request record and no call. -/
theorem handle_quietly (s : State) (x : Input) (hc : ∀ c sid n a now, x ≠ .call c sid n a now) :
    Quietly s (handle s x).1 := by
  have hm : ∀ (f : ReqRec → ReqRec), (∀ x, frz (f x) = frz x) →
      ∀ r : ReqId, KeptL s.reqs (s.reqs.map (fun x => if isReq r x then f x else x)) :=
    fun f hf r => keptL_map (fun x => by split <;> simp [hf]) (keptL_refl _)
  cases x with
  | call c sid n a now => exact absurd rfl (hc c sid n a now)
  | configure => simp [handle, Quietly, bumpSeq]
  | approverSet seq a =>
    obtain ⟨h1, h2, h3, h4, h5, -⟩ := onApproverSet_eq (bumpSeq s seq) a
    simp only [handle, Quietly]; rw [h1, h2, h3, h4, h5]; simp [bumpSeq]
  | approverRevoked => simp [handle, Quietly, onApproverRevoked, bumpSeq]
  | agentSet seq id n =>
    obtain ⟨h1, h2, h3, h4, h5, -⟩ := onAgentSet_eq (bumpSeq s seq) id n
    simp only [handle, Quietly]; rw [h1, h2, h3, h4, h5]; simp [bumpSeq]
  | agentRevoked seq id =>
    obtain ⟨h1, h2, h3, h4, h5, -⟩ := markRevoked_eq (bumpSeq s seq) id
    simp only [handle, Quietly, onAgentRevoked, endWhere_reqs, endWhere_calls, endWhere_bootId,
      endWhere_bogoId, endWhere_nextSeq]; rw [h1, h2, h3, h4, h5]; simp [bumpSeq]
  | ownerPause =>
    simp only [handle]
    split <;> simp [Quietly, pause, setAgent, bumpSeq]
  | agentUnpaused => simp [handle, Quietly, setAgent, bumpSeq]
  | ownerCancel => simp [handle, Quietly]
  | sessionOpened sid a cl =>
    obtain ⟨h1, h2, h3, h4, h5, -⟩ := onSessionOpened_eq s sid a cl
    simp only [handle, Quietly]; rw [h1, h2, h3, h4, h5]; simp
  | sessionClosed => simp [handle, Quietly, onSessionClosed]
  | callEnded => simp [handle, Quietly, onCallEnded, removeCall]
  | approval a r alg proof now =>
    simp only [handle, onApproval]
    repeat' split
    all_goals simp only [Quietly, setReq, endWhere_reqs, endWhere_calls, endWhere_bootId,
      endWhere_bogoId, endWhere_nextSeq]
    all_goals refine ⟨?_, by simp⟩
    all_goals first
      | (simp; done)
      | exact keptL_map (fun x => by split <;> rfl) (keptL_refl _)
      | exact keptL_filter (keptL_map (fun x => by split <;> rfl) (keptL_refl _))
  | denial a r note =>
    simp only [handle, onDenial]
    repeat' split
    all_goals simp only [Quietly, setReq, endWhere_reqs, endWhere_calls, endWhere_bootId,
      endWhere_bogoId, endWhere_nextSeq]
    all_goals refine ⟨?_, by simp⟩
    all_goals first
      | (simp; done)
      | exact keptL_map (fun x => by split <;> rfl) (keptL_refl _)
      | exact keptL_filter (keptL_map (fun x => by split <;> rfl) (keptL_refl _))
  | pauseAgent =>
    simp only [handle, onPauseAgent]
    repeat' split
    all_goals simp [Quietly, pause, setAgent]
  | dispatch c now =>
    simp only [handle, onDispatch]
    repeat' split
    all_goals simp [Quietly, removeCall]
  | notSent => simp [handle, Quietly, onNotSent, removeCall]
  | tick => simp [handle, Quietly]

/-- What admitting a protected call fixed in the new record: everything comes from the agent's
call, the session and agent the core knows, the catalog, and the policy in force at that
step. -/
def Admitted (s : State) (sid : SessionId) (n : String) (a : Option JVal) (now : Nat)
    (q : ReqRec) : Prop :=
  ∃ sess ag e, findSession s sid = some sess ∧ findAgent s sess.agent = some ag ∧
    ag.revoked = false ∧ ag.paused = false ∧ findCatalog s n = some e ∧
    (resolve s.cfg ag.name n).kind = .approve ∧
    q.name = e.name ∧
    q.requirement = (resolve s.cfg ag.name n).requirement ∧
    q.denyRule = (resolve s.cfg ag.name n).denyRule ∧
    q.mode = (resolve s.cfg ag.name n).mode ∧
    q.eligible = eligibleApprovers s (resolve s.cfg ag.name n).approvers ∧
    (resolve s.cfg ag.name n).requirement.need ≤ q.eligible.length ∧
    stripJust e.justKey a = some (q.req.args, q.req.justification) ∧
    ((resolve s.cfg ag.name n).justificationRequired = true → q.req.justification.isSome) ∧
    q.req = { bogoId := s.bogoId, upstream := e.upstream, tool := e.tool, args := q.req.args,
              justification := q.req.justification, hints := (resolve s.cfg ag.name n).hints,
              agentId := ag.id, agentName := ag.name, clientName := sess.client,
              session := sess.id, nonce := mkReqId s.bootId s.nextSeq, createdMs := now,
              expiresMs := (resolve s.cfg ag.name n).expiryMs.map (now + ·) } ∧
    q.status = .pending ∧ q.counted = [] ∧
    liveCount s ag.id < s.cfg.maxPending ∧ s.nextSeq < u64Bound

/-- Calls in `l'` were in `l`, or are the call `c`. -/
def CallsPlus (l l' : List CallRec) (c : CallId) : Prop := ∀ x ∈ l', x ∈ l ∨ x.id = c

@[simp] theorem callsPlus_refl (l : List CallRec) (c : CallId) : CallsPlus l l c :=
  fun x hx => .inl hx

@[simp] theorem callsPlus_cons {l : List CallRec} {x : CallRec} {c : CallId} (h : x.id = c) :
    CallsPlus l (x :: l) c := by
  intro y hy
  rcases List.mem_cons.mp hy with rfl | hy
  · exact .inr h
  · exact .inl hy

/-- A `call` either adds no request record, or adds exactly one, admitted from that call. -/
theorem onCall_shape (s : State) (c : CallId) (sid : SessionId) (n : String) (a : Option JVal)
    (now : Nat) :
    (onCall s c sid n a now).1.bootId = s.bootId ∧ (onCall s c sid n a now).1.bogoId = s.bogoId ∧
    CallsPlus s.calls (onCall s c sid n a now).1.calls c ∧
    ((KeptL s.reqs (onCall s c sid n a now).1.reqs ∧
        (onCall s c sid n a now).1.nextSeq = s.nextSeq ∧
        ∀ o ∈ (onCall s c sid n a now).2, o.isAsk = false) ∨
     (∃ q, (onCall s c sid n a now).1.reqs = q :: s.reqs ∧
        (onCall s c sid n a now).1.nextSeq = s.nextSeq + 1 ∧ Admitted s sid n a now q ∧
        ∀ o ∈ (onCall s c sid n a now).2, o.isAsk = true →
          ∃ ep, o = .ask q.req.nonce (encode q.req) q.eligible (groupKey q.req) ep)) := by
  unfold onCall
  split
  · simp
  · rename_i sess hs
    split
    · simp
    · rename_i ag hag
      split
      · simp
      split
      · simp
      split
      · simp
      split
      · simp
      · rename_i e he
        dsimp only
        split
        · simp
        · simp
        · rename_i hk
          unfold admitProtected
          dsimp only
          split
          · simp
          · rename_i stripped j hj
            split
            · simp
            · rename_i hjr
              split
              · rename_i q hr
                split
                · simp
                · split
                  · simp
                  · refine ⟨rfl, rfl, callsPlus_cons rfl, .inl ⟨keptL_map
                      (fun x => by split <;> rfl) (keptL_refl _), rfl, by simp⟩⟩
              · split
                · simp
                · rename_i hflood
                  split
                  · simp
                  · rename_i helig
                    split
                    · simp
                    · rename_i hseq
                      split
                      · simp
                      · rename_i hwf
                        have hst := findSession_spec hs
                        have hagt := findAgent_spec hag
                        refine ⟨rfl, rfl, ?_, .inr ⟨_, rfl, rfl, ?_, ?_⟩⟩
                        · split
                          · exact callsPlus_cons rfl
                          · exact callsPlus_refl _ _
                        · refine ⟨sess, ag, e, hs, hag, by simpa using ‹¬ag.revoked = true›,
                            by simpa using ‹¬ag.paused = true›, he, hk, rfl, rfl, rfl, rfl, rfl,
                            by simp only []; omega, hj, ?_, rfl, rfl, rfl, by omega, by omega⟩
                          intro hr
                          simp only [hr, Bool.true_and] at hjr
                          cases j <;> simp_all
                        · intro o ho hask
                          split at ho
                          · simp at ho
                            subst ho
                            exact ⟨_, rfl⟩
                          · simp at ho
                            rcases ho with rfl | rfl
                            · exact ⟨_, rfl⟩
                            · simp at hask

end Bogo.Proofs
