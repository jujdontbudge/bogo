/-
The promise (SPEC §3.8, §3.8.1, §3.18; ARCHITECTURE §3.3), for every trace.

Each theorem is about a `forward` (the only permission to write upstream) at step `i` of an
arbitrary trace `xs` from `Boot bogoId bootId`, and is stated against the state just before
that step: the registry, policy, sessions and agents in force at the moment of the write.
`BogoProofs.Bytes` lifts them to the raw byte strings Rust passes to the core.
-/
import BogoProofs.Inv

namespace Bogo.Proofs
open Bogo

/-! ### One forward, one step -/

/-- A forward can only come from `dispatch` of that call, and carries exactly what the gate
checked. -/
theorem fwd_step {s : State} {x : Input} {c : CallId} {r : Option ReqId} {u t : String}
    {a : Option JVal} {seq : Nat} (h : Output.forward c r u t a seq ∈ (handle s x).2) :
    ∃ now, x = .dispatch c now ∧ seq = s.registrySeq ∧
    (handle s x).1.calls = s.calls.filter (fun y => !eqB y.id c) ∧
    ∃ cr, findCall s c = some cr ∧
      ((r = none ∧ (∃ name, cr.status = .allowed name u t a ∧
          allowedGate s cr name u t = true) ∧ (handle s x).1.reqs = s.reqs) ∨
       (∃ rid q, r = some rid ∧ cr.status = .bound rid ∧ findReq s rid = some q ∧
          protectedGate s cr q now = true ∧ u = q.req.upstream ∧ t = q.req.tool ∧
          a = q.req.args ∧ (handle s x).1.reqs = s.reqs.filter (fun y => !isReq rid y))) := by
  obtain ⟨c0, now, rfl⟩ := forward_only_dispatch h rfl
  have h' : Output.forward c r u t a seq ∈ (onDispatch s c0 now).2 := h
  obtain ⟨rfl, hseq, -, hcalls, rest⟩ := onDispatch_forward h'
  exact ⟨now, rfl, hseq, hcalls, rest⟩

/-- At a forward, the call is live, its session is open and its agent is active. -/
theorem fwd_live {s : State} {x : Input} {c : CallId} {r : Option ReqId} {u t : String}
    {a : Option JVal} {seq : Nat} (h : Output.forward c r u t a seq ∈ (handle s x).2) :
    ∃ cr sess, findCall s c = some cr ∧ findSession s cr.session = some sess ∧
      agentActive s sess.agent = true := by
  obtain ⟨now, -, -, -, cr, hcr, hal | ⟨rid, q, -, -, -, hg, -⟩⟩ := fwd_step h
  · obtain ⟨-, ⟨name, -, hg⟩, -⟩ := hal
    obtain ⟨sess, hs, ha, -⟩ := allowedGate_spec hg
    exact ⟨cr, sess, hcr, hs, ha⟩
  · obtain ⟨-, -, -, ⟨sess, hs, -, ha⟩, -⟩ := protectedGate_spec hg
    exact ⟨cr, sess, hcr, hs, ha⟩

theorem callAgent_eq {s : State} {c : CallId} {cr : CallRec} {sess : SessionRec}
    (h1 : findCall s c = some cr) (h2 : findSession s cr.session = some sess) :
    callAgent s c = some sess.agent := by
  simp [callAgent, h1, h2]

/-! ### Small facts used below -/

theorem choose_list {α β γ : Type} {P : α → β → Prop} {g : α → γ} {k : β → γ} :
    ∀ L : List α, (∀ e ∈ L, ∃ b, P e b ∧ k b = g e) →
      ∃ M : List β, M.map k = L.map g ∧ ∀ b ∈ M, ∃ e ∈ L, P e b
  | [], _ => ⟨[], rfl, by simp⟩
  | e :: L, h => by
    obtain ⟨b, hb, hk⟩ := h e List.mem_cons_self
    obtain ⟨M, hM, hM'⟩ := choose_list L (fun e' he' => h e' (List.mem_cons_of_mem _ he'))
    refine ⟨b :: M, by simp [hk, hM], ?_⟩
    intro b' hb'
    rcases List.mem_cons.mp hb' with rfl | hb'
    · exact ⟨e, List.mem_cons_self, hb⟩
    · obtain ⟨e', he', hP⟩ := hM' b' hb'; exact ⟨e', List.mem_cons_of_mem _ he', hP⟩

/-- `sigMsg` is injective on byte strings: the signed message determines the request bytes. -/
theorem sigMsg_inj {b₁ b₂ : ByteArray} (h : sigMsg b₁ = sigMsg b₂) : b₁ = b₂ := by
  simp only [sigMsg, ByteArray.mk.injEq] at h
  have h' := List.toArray_inj h
  rw [List.append_cancel_left_eq] at h'
  rw [← mk_rawBytes b₁, ← mk_rawBytes b₂, h']

theorem toolPolicy_allow {cfg : PolicyConfig} {n : String} (h : (toolPolicy cfg n).kind = .allow) :
    ∃ p, (n, p) ∈ cfg.tools ∧ p.kind = .allow := by
  unfold toolPolicy at h
  split at h
  · rename_i e he
    obtain ⟨hm, hp⟩ := find?_mem he
    simp only [beq_iff_eq] at hp
    refine ⟨e.2, ?_, h⟩
    rw [← hp]; exact hm
  · simp only [defaultTool] at h
    cases hd : cfg.defaultPolicy <;> simp [hd, DefaultPolicy.kind] at h

/-- The default has no `allow`. -/
theorem DefaultPolicy.kind_ne_allow (d : DefaultPolicy) : d.kind ≠ .allow := by
  cases d <;> simp [DefaultPolicy.kind]

/-- The effective policy is `allow` only if the owner wrote `allow` for this tool. -/
theorem resolve_allow {cfg : PolicyConfig} {an n : String} (h : (resolve cfg an n).kind = .allow) :
    ExplicitAllow cfg an n := by
  unfold resolve at h
  split at h
  · rename_i o ho
    simp only at h
    unfold findOverride at ho
    obtain ⟨hm, hp⟩ := find?_mem ho
    simp only [Bool.and_eq_true, beq_iff_eq] at hp
    cases hk : o.kind with
    | some k =>
      rw [hk] at h
      simp only [Option.getD_some] at h
      exact .inl ⟨o, hm, hp.1, hp.2, by rw [hk, h]⟩
    | none =>
      rw [hk] at h
      exact .inr (toolPolicy_allow h)
  · exact .inr (toolPolicy_allow h)

/-- A step never lowers the sequence counter and never changes the boot. -/
theorem seq_step (s : State) (x : Input) :
    s.nextSeq ≤ (handle s x).1.nextSeq ∧ (handle s x).1.bootId = s.bootId := by
  by_cases hx : ∃ c sid n a now, x = .call c sid n a now
  · obtain ⟨c, sid, n, a, now, rfl⟩ := hx
    obtain ⟨hb, -, -, hk | ⟨q, -, hn, -⟩⟩ := onCall_shape s c sid n a now
    · exact ⟨by simp only [handle]; omega, hb⟩
    · exact ⟨by simp only [handle]; omega, hb⟩
  · simp only [not_exists] at hx
    obtain ⟨-, -, hb, -, hn⟩ := handle_quietly s x hx
    exact ⟨by omega, hb⟩

/-- A live request ID always names the same request: after any step, a record with the ID of
a record from before carries that same request. -/
theorem after_nonce {s : State} {x : Input} (hI : Inv s) {q q' : ReqRec} (hq : q ∈ s.reqs)
    (hq' : q' ∈ (handle s x).1.reqs) (e : q'.req.nonce = q.req.nonce) : q'.req = q.req := by
  have kept : KeptL s.reqs (handle s x).1.reqs → q'.req = q.req := by
    intro hk
    obtain ⟨q'', hq'', hf⟩ := keptL_mem hk hq'
    have hr := frz_req hf
    have : q'' = q := nodup_map_eq hI.1.2 hq'' hq (by show q''.req.nonce = q.req.nonce; rw [hr, e])
    rw [← hr, this]
  by_cases hx : ∃ c sid n a now, x = .call c sid n a now
  · obtain ⟨c, sid, n, a, now, rfl⟩ := hx
    obtain ⟨-, -, -, hk | ⟨q0, hr, -, ha, -⟩⟩ := onCall_shape s c sid n a now
    · exact kept hk.1
    · simp only [handle] at hq'
      rw [hr] at hq'
      rcases List.mem_cons.mp hq' with rfl | hq'
      · obtain ⟨hn, hseq⟩ := admitted_nonce ha
        obtain ⟨k, hk, hkq⟩ := hI.1.1 q hq
        rw [hn, hkq] at e
        have := mkReqId_inj hseq (by omega) e
        omega
      · rw [nodup_map_eq hI.1.2 hq' hq e]
  · simp only [not_exists] at hx
    exact kept (handle_quietly s x hx).1

/-- A request that a step removed is spent: it can never come back. -/
theorem spent_of_gone {s : State} {x : Input} (hI : Inv s) {q : ReqRec} (hq : q ∈ s.reqs)
    (hg : Gone q.req.nonce (handle s x).1) : Spent q.req.nonce (handle s x).1 := by
  obtain ⟨k, hk, hkq⟩ := hI.1.1 q hq
  obtain ⟨hn, hb⟩ := seq_step s x
  exact ⟨hg, k, by omega, by rw [hb]; exact hkq⟩

theorem gone_filter {s s' : State} (hI : Inv s) {q : ReqRec} (hq : q ∈ s.reqs)
    {p : ReqRec → Bool} (hp : p q = true) (h : s'.reqs = s.reqs.filter (fun x => !p x)) :
    Gone q.req.nonce s' := by
  intro q' hq' e
  rw [h, List.mem_filter] at hq'
  have := nodup_map_eq hI.1.2 hq'.1 hq e
  subst this
  simp [hp] at hq'

/-- Each ending removes the request it ends. -/
theorem ends_gone {s : State} {x : Input} (hI : Inv s) {q : ReqRec} (hq : q ∈ s.reqs)
    (he : Ends x q) : Gone q.req.nonce (handle s x).1 := by
  rcases he with rfl | rfl | ⟨seq, rfl⟩ | ⟨c, hc, rfl | rfl⟩ | ⟨now, rfl, hn⟩
  · exact gone_filter hI hq (p := fun x => eqB x.req.session q.req.session) (by simp)
      (by simp [handle, onSessionClosed])
  · intro q' hq' e
    simp only [handle, endWhere_reqs, List.mem_filter] at hq'
    simp [isReq, e, eqB] at hq'
  · obtain ⟨h1, -⟩ := markRevoked_eq (bumpSeq s seq) q.req.agentId
    exact gone_filter hI hq (p := fun x => eqB x.req.agentId q.req.agentId) (by simp)
      (by simp only [handle, onAgentRevoked, endWhere_reqs]; rw [h1]; rfl)
  · exact gone_filter hI hq (p := boundTo c) (by simp [boundTo, hc])
      (by simp [handle, onCallEnded, removeCall])
  · exact gone_filter hI hq (p := boundTo c) (by simp [boundTo, hc])
      (by simp [handle, onNotSent, removeCall])
  · exact gone_filter hI hq (p := expiredAt now) (by simp [expiredAt, hn])
      (by simp [handle])

/-- A spent request never forwards. -/
theorem spent_no_forward {s : State} {x : Input} {r : ReqId} (hs : Spent r s) {c : CallId}
    {u t : String} {a : Option JVal} {seq : Nat} :
    Output.forward c (some r) u t a seq ∉ (handle s x).2 := by
  intro h
  obtain ⟨now, -, -, -, cr, -, ⟨hr, -⟩ | ⟨rid, q, hr, -, hq, -⟩⟩ := fwd_step h
  · cases hr
  · cases hr
    obtain ⟨hm, hn⟩ := findReq_spec hq
    exact hs.1 q hm hn

/-- Once spent before step `m`, a request never forwards at any step from `m` on. -/
theorem spent_forever {s0 : State} {xs : List Input} {m j : Nat} {r : ReqId}
    (hs : Spent r (before s0 xs m)) (hj : m ≤ j) {c : CallId} {u t : String} {a : Option JVal}
    {seq : Nat} : Output.forward c (some r) u t a seq ∉ outputsAt s0 xs j := by
  intro h
  obtain ⟨x, -, hx⟩ := mem_outputsAt h
  have := persist (P := Spent r) (J := j) hs (fun l x _ _ _ h => spent_step _ x h) j hj (Nat.le_refl _)
  exact spent_no_forward this hx

/-- No live call with ID `c`. -/
def NoCall (c : CallId) (s : State) : Prop := ∀ y ∈ s.calls, y.id ≠ c

theorem noCall_step (s : State) (x : Input) {c : CallId} (h : NoCall c s)
    (hx : ∀ sid n a now, x ≠ .call c sid n a now) : NoCall c (handle s x).1 := by
  by_cases hc : ∃ c' sid n a now, x = .call c' sid n a now
  · obtain ⟨c', sid, n, a, now, rfl⟩ := hc
    have hne : c' ≠ c := fun e => hx sid n a now (by rw [e])
    obtain ⟨-, -, hp, -⟩ := onCall_shape s c' sid n a now
    intro y hy
    rcases hp y hy with hy | hy
    · exact h y hy
    · rw [hy]; exact hne
  · simp only [not_exists] at hc
    obtain ⟨-, hl, -⟩ := handle_quietly s x hc
    exact fun y hy => h y (hl y hy)

theorem noCall_no_forward {s : State} {x : Input} {c : CallId} (h : NoCall c s)
    {r : Option ReqId} {u t : String} {a : Option JVal} {seq : Nat} :
    Output.forward c r u t a seq ∉ (handle s x).2 := by
  intro hf
  obtain ⟨cr, -, hcr, -⟩ := fwd_live hf
  obtain ⟨hm, hid⟩ := findCall_spec hcr
  exact h cr hm hid

/-- After `NoCall c` holds before step `m`, a forward of `c` at a later step `j` needs a new
`call c` at some step from `m` to `j`. -/
theorem noCall_until_call {s0 : State} {xs : List Input} {m j : Nat} {c : CallId}
    (h0 : NoCall c (before s0 xs m)) (hj : m ≤ j) {r : Option ReqId} {u t : String}
    {a : Option JVal} {seq : Nat} (hf : Output.forward c r u t a seq ∈ outputsAt s0 xs j) :
    ∃ l, m ≤ l ∧ l < j ∧ ∃ sid n args now, xs[l]? = some (.call c sid n args now) := by
  apply Classical.byContradiction
  intro hne
  simp only [not_exists, not_and] at hne
  have := persist (P := NoCall c) (J := j) h0
    (fun l x hl hlj hx h => noCall_step _ x h (fun sid n a now e => hne l hl hlj sid n a now
      (by rw [hx, e]))) j hj (Nat.le_refl _)
  obtain ⟨x, -, hx⟩ := mem_outputsAt hf
  exact noCall_no_forward this hx

/-! ## The five promises of SPEC §3.8 -/

/-- **1. Approved.** A forward is either an allowed call whose effective policy for this agent
is `allow` right now (and the owner wrote that `allow`), or a protected request whose
requirement is met right now: there is a list `S` of approvers with distinct IDs, at least as
many as both the requirement the request was admitted with and the one in force now need
(1 for any-of, k for k-of-n), each registered now, eligible for this request and under the
policy in force now, none having denied it, and each having approved exactly this request's signed bytes (A1). The
forwarded upstream, tool and arguments are the request's. -/
theorem approved {bogoId bootId : ByteArray} {xs : List Input} {i : Nat} {c : CallId}
    {r : Option ReqId} {u t : String} {args : Option JVal} {seq : Nat}
    (h : Output.forward c r u t args seq ∈ outputsAt (Boot bogoId bootId) xs i) :
    let s := before (Boot bogoId bootId) xs i
    (r = none ∧ ∃ cr name sess, findCall s c = some cr ∧ cr.status = .allowed name u t args ∧
        findSession s cr.session = some sess ∧
        (resolve s.cfg (agentName s sess.agent) name).kind = .allow ∧
        ExplicitAllow s.cfg (agentName s sess.agent) name ∧
        ∃ e, findCatalog s name = some e ∧ e.upstream = u ∧ e.tool = t) ∨
    (∃ rid q, r = some rid ∧ findReq s rid = some q ∧ q.req.nonce = rid ∧
        q.req.upstream = u ∧ q.req.tool = t ∧ q.req.args = args ∧
        (∃ e, findCatalog s q.name = some e ∧ e.upstream = u ∧ e.tool = t) ∧
        (resolve s.cfg (agentName s q.req.agentId) q.name).kind = .approve ∧
        ∃ S : List Approver, (S.map (·.id)).Nodup ∧
          (resolve s.cfg (agentName s q.req.agentId) q.name).requirement.need ≤ S.length ∧
          q.requirement.need ≤ S.length ∧
          ∀ ap ∈ S, ap ∈ s.approvers ∧ ap.id ∈ q.eligible ∧ ap.id ∉ q.denied ∧
            ((resolve s.cfg (agentName s q.req.agentId) q.name).approvers = [] ∨
              ap.name ∈ (resolve s.cfg (agentName s q.req.agentId) q.name).approvers) ∧
            OwnerApproved ap.alg ap.pk (sigMsg (encode q.req))) := by
  dsimp only
  obtain ⟨x, -, hx⟩ := mem_outputsAt h
  obtain ⟨now, -, -, -, cr, hcr, ⟨hr, ⟨name, hst, hg⟩, -⟩ | ⟨rid, q, hr, -, hq, hg, hu, ht, ha, -⟩⟩ :=
    fwd_step hx
  · obtain ⟨sess, hs, -, ⟨e, he, heu, het⟩, hk⟩ := allowedGate_spec hg
    exact .inl ⟨hr, cr, name, sess, hcr, hst, hs, hk, resolve_allow hk, e, he, heu, het⟩
  · obtain ⟨-, -, -, -, -, ⟨e, he, heu, het⟩, hk, -, hmet⟩ := protectedGate_spec hg
    obtain ⟨Sc, hSc, hnd, hn1, hn2⟩ := gateMet_spec hmet
    obtain ⟨M, hM, hM'⟩ := choose_list (k := (·.id)) (g := (·.id))
      (P := fun (_ : Counted) (ap : Approver) =>
        ap ∈ (before (Boot bogoId bootId) xs i).approvers ∧ ap.id ∈ q.eligible ∧
        ap.id ∉ q.denied ∧
        ((resolve (before (Boot bogoId bootId) xs i).cfg
            (agentName (before (Boot bogoId bootId) xs i) q.req.agentId) q.name).approvers = [] ∨
          ap.name ∈ (resolve (before (Boot bogoId bootId) xs i).cfg
            (agentName (before (Boot bogoId bootId) xs i) q.req.agentId) q.name).approvers) ∧
        OwnerApproved ap.alg ap.pk (sigMsg (encode q.req))) Sc (by
      intro e' he'
      obtain ⟨helig, hden, ⟨ap, hap, hid, halg, hpk, hname⟩, hv⟩ :=
        standsNow_spec (hSc e' he').2
      have hA := A1_unforgeable _ _ _ _ hv
      rw [← halg, ← hpk] at hA
      exact ⟨ap, ⟨hap, hid ▸ helig, hid ▸ hden, hname, hA⟩, hid⟩)
    have hlen : M.length = Sc.length := by
      have := congrArg List.length hM; simpa using this
    obtain ⟨hm, hn⟩ := findReq_spec hq
    refine .inr ⟨rid, q, hr, hq, hn, hu.symm, ht.symm, ha.symm, ⟨e, he, heu ▸ hu ▸ rfl,
      het ▸ ht ▸ rfl⟩, hk, M, by rw [hM]; exact hnd, by omega, by omega, fun ap hap => ?_⟩
    obtain ⟨_, _, hP⟩ := hM' ap hap
    exact hP

/-- **2. Exact.** A protected forward runs exactly the request the approvers signed: its signed
bytes decode to that request and to nothing else, and no other well-formed request has the
same signed bytes. Together with (1), approving one call never approves any other. -/
theorem exact {bogoId bootId : ByteArray} {xs : List Input} {i : Nat} {c : CallId}
    {rid : ReqId} {u t : String} {args : Option JVal} {seq : Nat}
    (h : Output.forward c (some rid) u t args seq ∈ outputsAt (Boot bogoId bootId) xs i) :
    let s := before (Boot bogoId bootId) xs i
    ∃ q, findReq s rid = some q ∧ q.req.nonce = rid ∧ q.req.upstream = u ∧ q.req.tool = t ∧
      q.req.args = args ∧ q.req.wf = true ∧
      (∀ b, sigMsg b = sigMsg (encode q.req) → b = encode q.req ∧ decode b = some q.req) ∧
      (∀ r' : Request, r'.wf = true → sigMsg (encode r') = sigMsg (encode q.req) → r' = q.req) := by
  dsimp only
  obtain ⟨x, -, hx⟩ := mem_outputsAt h
  obtain ⟨now, -, -, -, cr, -, ⟨hr, -⟩ | ⟨rid', q, hr, -, hq, hg, hu, ht, ha, -⟩⟩ := fwd_step hx
  · cases hr
  · cases hr
    obtain ⟨-, -, -, -, -, -, -, hwf, -⟩ := protectedGate_spec hg
    obtain ⟨-, hn⟩ := findReq_spec hq
    refine ⟨q, hq, hn, hu.symm, ht.symm, ha.symm, hwf, fun b hb => ?_,
      fun r' hr' e => sigMsg_injective r' q.req hr' hwf e⟩
    have := sigMsg_inj hb
    exact ⟨this, by rw [this]; exact decode_encode q.req hwf⟩

/-- **3. Single-use.** A request forwards at most once over the whole trace, and so does each
call: a second forward of call `c` needs a new `call c` in between. An approval authorizes at
most one execution: two protected forwards whose requests have the same signed bytes are the
same step. -/
theorem single_use {bogoId bootId : ByteArray} {xs : List Input} :
    (∀ {i j : Nat} {c c' : CallId} {r : ReqId} {u u' t t' : String} {a a' : Option JVal}
        {s1 s2 : Nat},
      Output.forward c (some r) u t a s1 ∈ outputsAt (Boot bogoId bootId) xs i →
      Output.forward c' (some r) u' t' a' s2 ∈ outputsAt (Boot bogoId bootId) xs j → i = j) ∧
    (∀ {i j : Nat} {c : CallId} {r1 r2 : Option ReqId} {u u' t t' : String}
        {a a' : Option JVal} {s1 s2 : Nat},
      Output.forward c r1 u t a s1 ∈ outputsAt (Boot bogoId bootId) xs i →
      Output.forward c r2 u' t' a' s2 ∈ outputsAt (Boot bogoId bootId) xs j → i < j →
      ∃ m, i < m ∧ m < j ∧ ∃ sid n args now, xs[m]? = some (.call c sid n args now)) ∧
    (∀ {i j : Nat} {c c' : CallId} {r r' : ReqId} {u u' t t' : String} {a a' : Option JVal}
        {s1 s2 : Nat} {q q' : ReqRec},
      Output.forward c (some r) u t a s1 ∈ outputsAt (Boot bogoId bootId) xs i →
      Output.forward c' (some r') u' t' a' s2 ∈ outputsAt (Boot bogoId bootId) xs j →
      findReq (before (Boot bogoId bootId) xs i) r = some q →
      findReq (before (Boot bogoId bootId) xs j) r' = some q' →
      sigMsg (encode q.req) = sigMsg (encode q'.req) → i = j) := by
  -- a protected forward at `i` spends its request
  have spend : ∀ {i : Nat} {c : CallId} {r : ReqId} {u t : String} {a : Option JVal}
      {s1 : Nat}, Output.forward c (some r) u t a s1 ∈ outputsAt (Boot bogoId bootId) xs i →
      Spent r (before (Boot bogoId bootId) xs (i + 1)) := by
    intro i c r u t a s1 h
    obtain ⟨x, hxi, hx⟩ := mem_outputsAt h
    rw [before_succ_some hxi]
    obtain ⟨now, -, -, -, cr, -, ⟨hr, -⟩ | ⟨rid, q, hr, -, hq, -, -, -, -, hreqs⟩⟩ := fwd_step hx
    · cases hr
    · cases hr
      obtain ⟨hm, hn⟩ := findReq_spec hq
      have hI := inv_before bogoId bootId xs i
      rw [← hn]
      exact spent_of_gone hI hm (gone_filter hI hm (p := isReq r) (by simp [isReq, hn]) hreqs)
  have once : ∀ {i j : Nat} {c c' : CallId} {r : ReqId} {u u' t t' : String}
      {a a' : Option JVal} {s1 s2 : Nat},
      Output.forward c (some r) u t a s1 ∈ outputsAt (Boot bogoId bootId) xs i →
      Output.forward c' (some r) u' t' a' s2 ∈ outputsAt (Boot bogoId bootId) xs j → i = j := by
    intro i j c c' r u u' t t' a a' s1 s2 hi hj
    rcases Nat.lt_trichotomy i j with hij | hij | hij
    · exact absurd hj (spent_forever (spend hi) hij)
    · exact hij
    · exact absurd hi (spent_forever (spend hj) hij)
  refine ⟨once, ?_, ?_⟩
  · intro i j c r1 r2 u u' t t' a a' s1 s2 hi hj hij
    obtain ⟨x, hxi, hx⟩ := mem_outputsAt hi
    obtain ⟨-, -, -, hcalls, -⟩ := fwd_step hx
    have h0 : NoCall c (before (Boot bogoId bootId) xs (i + 1)) := by
      rw [before_succ_some hxi]
      intro y hy e
      rw [hcalls] at hy
      simp [e, eqB] at hy
    obtain ⟨l, hl, hlj, rest⟩ := noCall_until_call h0 hij hj
    exact ⟨l, by omega, hlj, rest⟩
  · intro i j c c' r r' u u' t t' a a' s1 s2 q q' hi hj hq hq' e
    obtain ⟨x, -, hx⟩ := mem_outputsAt hi
    obtain ⟨x', -, hx'⟩ := mem_outputsAt hj
    have wf : ∀ {s : State} {x : Input} {c : CallId} {r : ReqId} {u t : String}
        {a : Option JVal} {s1 : Nat} {q : ReqRec},
        Output.forward c (some r) u t a s1 ∈ (handle s x).2 → findReq s r = some q →
        q.req.wf = true ∧ q.req.nonce = r := by
      intro s x c r u t a s1 q h hq
      obtain ⟨now, -, -, -, cr, -, ⟨hr, -⟩ | ⟨rid, q0, hr, -, hq0, hg, -⟩⟩ := fwd_step h
      · cases hr
      · cases hr
        rw [hq] at hq0; cases hq0
        exact ⟨(protectedGate_spec hg).2.2.2.2.2.2.2.1, (findReq_spec hq).2⟩
    obtain ⟨hw, hn⟩ := wf hx hq
    obtain ⟨hw', hn'⟩ := wf hx' hq'
    have := sigMsg_injective _ _ hw hw' e
    have e2 : r = r' := by rw [← hn, ← hn', this]
    subst e2
    exact once hi hj

/-- **4. Fresh** (with session binding). At a forward, which is the `dispatch` step of that
call: the call is live, its session is open, the agent is active (registered, not paused, not
revoked), and for a protected call the request is bound to this call and this session's agent
and its expiry has not passed at the dispatch time. Every ending, revocation and pause the
core saw before is honoured. -/
theorem fresh {bogoId bootId : ByteArray} {xs : List Input} {i : Nat} {c : CallId}
    {r : Option ReqId} {u t : String} {args : Option JVal} {seq : Nat}
    (h : Output.forward c r u t args seq ∈ outputsAt (Boot bogoId bootId) xs i) :
    let s := before (Boot bogoId bootId) xs i
    (∃ now cr sess, xs[i]? = some (.dispatch c now) ∧ findCall s c = some cr ∧
      findSession s cr.session = some sess ∧ agentActive s sess.agent = true ∧
      ∀ rid, r = some rid → ∃ q, findReq s rid = some q ∧ q.call = some c ∧
        q.req.session = cr.session ∧ q.req.agentId = sess.agent ∧
        ∀ e, q.req.expiresMs = some e → now < e) ∧
    (∀ m < i, ∀ x, xs[m]? = some x → ∀ q ∈ (before (Boot bogoId bootId) xs m).reqs, Ends x q →
      r ≠ some q.req.nonce) ∧
    (∀ m < i, ∀ a, Output.agentPaused a ∈ outputsAt (Boot bogoId bootId) xs m →
      ∀ q ∈ (before (Boot bogoId bootId) xs m).reqs, q.req.agentId = a → r ≠ some q.req.nonce) ∧
    (∀ m < i, ∀ seq' a, xs[m]? = some (.agentRevoked seq' a) → callAgent s c ≠ some a) ∧
    (∀ m < i, ∀ a, Output.agentPaused a ∈ outputsAt (Boot bogoId bootId) xs m →
      (∀ l seq', m < l → l < i → xs[l]? ≠ some (.agentUnpaused seq' a)) →
      callAgent s c ≠ some a) := by
  dsimp only
  obtain ⟨x, hxi, hx⟩ := mem_outputsAt h
  obtain ⟨cr0, sess0, hcr0, hs0, hact0⟩ := fwd_live hx
  have hca := callAgent_eq hcr0 hs0
  -- a request that a step at `m < i` removed does not forward at `i`
  have gone_at : ∀ m < i, ∀ x, xs[m]? = some x → ∀ q ∈ (before (Boot bogoId bootId) xs m).reqs,
      Gone q.req.nonce (handle (before (Boot bogoId bootId) xs m) x).1 → r ≠ some q.req.nonce := by
    intro m hm x hxm q hq hg e
    subst e
    have hsp := spent_of_gone (inv_before bogoId bootId xs m) hq hg
    rw [← before_succ_some hxm] at hsp
    exact spent_forever hsp hm h
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · obtain ⟨now, rfl, -, -, cr, hcr, hal | ⟨rid, q, hr, hst, hq, hg, -⟩⟩ := fwd_step hx
    · refine ⟨now, cr0, sess0, hxi, hcr0, hs0, hact0, fun rid hr => ?_⟩
      rw [hal.1] at hr; cases hr
    · rw [hcr] at hcr0; injection hcr0 with e1; subst e1
      obtain ⟨-, hc, hsess, ⟨sess, hs, hag, -⟩, hexp, -⟩ := protectedGate_spec hg
      rw [hs] at hs0; injection hs0 with e2; subst e2
      refine ⟨now, cr, sess, hxi, hcr, hs, hact0, fun rid' hr' => ?_⟩
      rw [hr] at hr'; cases hr'
      obtain ⟨-, hid⟩ := findCall_spec hcr
      exact ⟨q, hq, hid ▸ hc, hsess, hag.symm, notExpired_iff.mp hexp⟩
  · intro m hm x hxm q hq he
    exact gone_at m hm x hxm q hq (ends_gone (inv_before bogoId bootId xs m) hq he)
  · intro m hm a hp q hq ha
    obtain ⟨x, hxm, hpx⟩ := mem_outputsAt hp
    refine gone_at m hm x hxm q hq (fun q' hq' e => ?_)
    have := after_nonce (inv_before bogoId bootId xs m) hq hq' e
    exact (agentPaused_out _ x hpx).2 q' hq' (by rw [this, ha])
  · intro m hm seq' a hxm e
    rw [hca] at e; cases e
    have h1 : RevokedA (before (Boot bogoId bootId) xs (m + 1)) sess0.agent := by
      rw [before_succ_some hxm]; exact revokedA_after _ _ _
    have := persist (P := fun s => RevokedA s sess0.agent) (J := i) h1
      (fun l x _ _ _ h => revokedA_step _ x h) i hm (Nat.le_refl _)
    rw [revokedA_inactive this] at hact0; cases hact0
  · intro m hm a hp hu e
    rw [hca] at e; cases e
    obtain ⟨x, hxm, hpx⟩ := mem_outputsAt hp
    have h1 : PausedA (before (Boot bogoId bootId) xs (m + 1)) sess0.agent := by
      rw [before_succ_some hxm]; exact (agentPaused_out _ x hpx).1
    have := persist (P := fun s => PausedA s sess0.agent) (J := i) h1
      (fun l x hl hli hxl h => pausedA_step _ x h (fun seq' e => hu l seq' hl hli (by rw [hxl, e])))
      i hm (Nat.le_refl _)
    rw [pausedA_inactive this] at hact0; cases hact0

/-- **5. Fail-closed.** A forward happens only when every check passed at that step: it is the
`dispatch` of a live call whose session is open and whose agent is registered, not paused and
not revoked; the tool is in the catalog under the same upstream and tool; an allowed call's
effective policy is `allow` now; a protected call's request is live, settled, bound to this
call, canonical, not expired, still needs approval (not deny, not unlisted-allow) under the
policy now, and has enough standing approvals now. Anything missing, invalid, expired,
revoked, ended or denied means no forward. (Malformed bytes: `malformed_never_runs`.) -/
theorem fail_closed {bogoId bootId : ByteArray} {xs : List Input} {i : Nat} {c : CallId}
    {r : Option ReqId} {u t : String} {args : Option JVal} {seq : Nat}
    (h : Output.forward c r u t args seq ∈ outputsAt (Boot bogoId bootId) xs i) :
    let s := before (Boot bogoId bootId) xs i
    ∃ now cr sess, xs[i]? = some (.dispatch c now) ∧ findCall s c = some cr ∧
      findSession s cr.session = some sess ∧
      (∃ ag ∈ s.agents, ag.id = sess.agent ∧ ag.revoked = false ∧ ag.paused = false) ∧
      (r = none → ∃ name e, cr.status = .allowed name u t args ∧
        findCatalog s name = some e ∧ e.upstream = u ∧ e.tool = t ∧
        (resolve s.cfg (agentName s sess.agent) name).kind = .allow) ∧
      (∀ rid, r = some rid → ∃ q e, cr.status = .bound rid ∧ findReq s rid = some q ∧
        q.status = .settled ∧ q.call = some c ∧ q.req.session = cr.session ∧
        q.req.agentId = sess.agent ∧ q.req.wf = true ∧ notExpired q.req now = true ∧
        findCatalog s q.name = some e ∧ e.upstream = u ∧ e.tool = t ∧
        (resolve s.cfg (agentName s q.req.agentId) q.name).kind = .approve ∧
        gateMet s q (resolve s.cfg (agentName s q.req.agentId) q.name) = true) := by
  dsimp only
  obtain ⟨x, hxi, hx⟩ := mem_outputsAt h
  obtain ⟨now, rfl, -, -, cr, hcr, hal | ⟨rid, q, hr, hst, hq, hg, hu, ht, -⟩⟩ := fwd_step hx
  · obtain ⟨hr, ⟨name, hst, hg⟩, -⟩ := hal
    obtain ⟨sess, hs, hact, ⟨e, he, heu, het⟩, hk⟩ := allowedGate_spec hg
    obtain ⟨ag, hag, hid, hrv, hps⟩ := agentActive_iff.mp hact
    refine ⟨now, cr, sess, hxi, hcr, hs, ⟨ag, hag, hid, hrv, hps⟩,
      ⟨fun _ => ⟨name, e, hst, he, heu, het, hk⟩, fun rid h' => ?_⟩⟩
    rw [hr] at h'; cases h'
  · obtain ⟨hset, hc, hsess, ⟨sess, hs, hag, hact⟩, hexp, ⟨e, he, heu, het⟩, hk, hwf, hmet⟩ :=
      protectedGate_spec hg
    obtain ⟨ag, hagm, hid, hrv, hps⟩ := agentActive_iff.mp hact
    obtain ⟨-, hcid⟩ := findCall_spec hcr
    refine ⟨now, cr, sess, hxi, hcr, hs, ⟨ag, hagm, hid, hrv, hps⟩,
      ⟨(fun h' => by rw [hr] at h'; cases h'), fun rid' h' => ?_⟩⟩
    rw [hr] at h'; cases h'
    exact ⟨q, e, hst, hq, hset, hcid ▸ hc, hsess, hag.symm, hwf, hexp, he, heu ▸ hu ▸ rfl,
      het ▸ ht ▸ rfl, hk, hmet⟩

/-! ## The rest of the promise -/

/-- **Safe default.** A forward without approval needs an `allow` the owner wrote for that
tool: in its entry, or in an override for that agent. A tool with no entry and no override
never runs without approval, whatever the default, because the default has no `allow`. -/
theorem safe_default {bogoId bootId : ByteArray} {xs : List Input} {i : Nat} {c : CallId}
    {u t : String} {args : Option JVal} {seq : Nat}
    (h : Output.forward c none u t args seq ∈ outputsAt (Boot bogoId bootId) xs i) :
    let s := before (Boot bogoId bootId) xs i
    ∃ name, callAgent s c ≠ none ∧
      ∀ ag, callAgent s c = some ag → ExplicitAllow s.cfg (agentName s ag) name := by
  dsimp only
  obtain ⟨x, -, hx⟩ := mem_outputsAt h
  obtain ⟨now, -, -, -, cr, hcr, ⟨-, ⟨name, -, hg⟩, -⟩ | ⟨rid, q, hr, -⟩⟩ := fwd_step hx
  · obtain ⟨sess, hs, -, -, hk⟩ := allowedGate_spec hg
    refine ⟨name, by rw [callAgent_eq hcr hs]; simp, fun ag e => ?_⟩
    rw [callAgent_eq hcr hs] at e; cases e
    exact resolve_allow hk
  · cases hr

/-- No owner configuration makes a tool with no entry and no override `allow`. -/
theorem unlisted_never_allow (cfg : PolicyConfig) (an n : String)
    (h1 : ∀ p, (n, p) ∉ cfg.tools) (h2 : ∀ o ∈ cfg.overrides, o.agentName = an → o.tool ≠ n) :
    (resolve cfg an n).kind ≠ .allow := by
  intro h
  rcases resolve_allow h with ⟨o, ho, e1, e2, -⟩ | ⟨p, hp, -⟩
  · exact h2 o ho e1 e2
  · exact h1 p hp

/-- No `ask` without admission. -/
theorem onDispatch_noAsk (s : State) (c : CallId) (now : Nat) :
    ∀ o ∈ (onDispatch s c now).2, o.isAsk = false := by
  intro o ho
  unfold onDispatch at ho
  repeat' split at ho
  all_goals first
    | (simp at ho; subst ho; rfl)
    | (simp only [List.mem_append] at ho
       rcases ho with ho | ho
       · first | (simp at ho; done) | (simp at ho; subst ho; rfl) | (split at ho <;> simp at ho)
       · exact (endWhere_quiet _ _ _ _ _ ho).2)

/-- **Asks, and the flood limit.** The owner is asked only about a call admitted at that step:
its agent known, not paused and not revoked, the effective policy `approve`, and that agent
having fewer live requests than the flood limit. What they are asked is exactly that
request's bytes, sent to its eligible approvers. -/
theorem asks_admitted {bogoId bootId : ByteArray} {xs : List Input} {i : Nat} {r : ReqId}
    {b : ByteArray} {to : List ApproverId} {g : ByteArray} {ep : Nat}
    (h : Output.ask r b to g ep ∈ outputsAt (Boot bogoId bootId) xs i) :
    ∃ c sid n args now q, xs[i]? = some (.call c sid n args now) ∧
      Admitted (before (Boot bogoId bootId) xs i) sid n args now q ∧ r = q.req.nonce ∧
      b = encode q.req ∧ to = q.eligible ∧ g = groupKey q.req := by
  obtain ⟨x, hxi, hx⟩ := mem_outputsAt h
  by_cases hc : ∃ c sid n a now, x = .call c sid n a now
  · obtain ⟨c, sid, n, a, now, rfl⟩ := hc
    obtain ⟨-, -, -, hk | ⟨q, -, -, ha, hask⟩⟩ :=
      onCall_shape (before (Boot bogoId bootId) xs i) c sid n a now
    · have := hk.2.2 _ hx; simp at this
    · obtain ⟨ep', e⟩ := hask _ hx rfl
      simp only [Output.ask.injEq] at e
      obtain ⟨rfl, rfl, rfl, rfl, -⟩ := e
      exact ⟨c, sid, n, a, now, q, hxi, ha, rfl, rfl, rfl, rfl⟩
  · by_cases hd : ∃ c now, x = .dispatch c now
    · obtain ⟨c, now, rfl⟩ := hd
      have := onDispatch_noAsk _ c now _ hx; simp at this
    · simp only [not_exists] at hc hd
      have := (handle_quiet _ x hc hd _ hx).2; simp at this

/-- The flood limit, spelled out from `asks_admitted`. -/
theorem flood_limit {bogoId bootId : ByteArray} {xs : List Input} {i : Nat} {r : ReqId}
    {b : ByteArray} {to : List ApproverId} {g : ByteArray} {ep : Nat}
    (h : Output.ask r b to g ep ∈ outputsAt (Boot bogoId bootId) xs i) :
    let s := before (Boot bogoId bootId) xs i
    ∃ c sid n args now sess ag, xs[i]? = some (.call c sid n args now) ∧
      findSession s sid = some sess ∧ findAgent s sess.agent = some ag ∧
      ag.paused = false ∧ ag.revoked = false ∧ liveCount s ag.id < s.cfg.maxPending := by
  dsimp only
  obtain ⟨c, sid, n, args, now, q, hxi, ⟨sess, ag, _, hs, hag, hrv, hps, _, _, _, _, _, _, _, _, _,
    _, _, _, _, hlive, _⟩, -⟩ := asks_admitted h
  exact ⟨c, sid, n, args, now, sess, ag, hxi, hs, hag, hps, hrv, hlive⟩

/-- **Pause and revocation stop new requests.** After the core reports `agentPaused a`, until
the owner un-pauses `a`, and after `agentRevoked a` forever, nothing is asked for a call
from `a`'s sessions. -/
theorem blocked_agent_not_asked {bogoId bootId : ByteArray} {xs : List Input} {j : Nat}
    {a : AgentId} (hb : PausedA (before (Boot bogoId bootId) xs j) a ∨
      RevokedA (before (Boot bogoId bootId) xs j) a)
    {r : ReqId} {b : ByteArray} {to : List ApproverId} {g : ByteArray} {ep : Nat}
    (h : Output.ask r b to g ep ∈ outputsAt (Boot bogoId bootId) xs j) :
    ∃ c sid n args now sess, xs[j]? = some (.call c sid n args now) ∧
      findSession (before (Boot bogoId bootId) xs j) sid = some sess ∧ sess.agent ≠ a := by
  obtain ⟨c, sid, n, args, now, q, hxi, ⟨sess, ag, _, hs, hag, hrv, hps, -⟩, -⟩ := asks_admitted h
  refine ⟨c, sid, n, args, now, sess, hxi, hs, fun e => ?_⟩
  obtain ⟨hm, hid⟩ := findAgent_spec hag
  rcases hb with hb | hb
  · rw [hb.2 ag hm (hid.trans e)] at hps; cases hps
  · rw [hb.2 ag hm (hid.trans e)] at hrv; cases hrv

/-- A revoked agent stays blocked; a paused one until un-paused. -/
theorem blocked_after {bogoId bootId : ByteArray} {xs : List Input} {m j : Nat} {a : AgentId}
    (hmj : m < j) :
    ((∃ seq, xs[m]? = some (.agentRevoked seq a)) →
      RevokedA (before (Boot bogoId bootId) xs j) a) ∧
    (Output.agentPaused a ∈ outputsAt (Boot bogoId bootId) xs m →
      (∀ l seq, m < l → l < j → xs[l]? ≠ some (.agentUnpaused seq a)) →
      PausedA (before (Boot bogoId bootId) xs j) a) := by
  refine ⟨fun ⟨seq, hxm⟩ => ?_, fun hp hu => ?_⟩
  · have h1 : RevokedA (before (Boot bogoId bootId) xs (m + 1)) a := by
      rw [before_succ_some hxm]; exact revokedA_after _ _ _
    exact persist (P := fun s => RevokedA s a) (J := j) h1
      (fun l x _ _ _ h => revokedA_step _ x h) j hmj (Nat.le_refl _)
  · obtain ⟨x, hxm, hpx⟩ := mem_outputsAt hp
    have h1 : PausedA (before (Boot bogoId bootId) xs (m + 1)) a := by
      rw [before_succ_some hxm]; exact (agentPaused_out _ x hpx).1
    exact persist (P := fun s => PausedA s a) (J := j) h1
      (fun l x hl hlj hxl h => pausedA_step _ x h (fun seq e => hu l seq hl hlj (by rw [hxl, e])))
      j hmj (Nat.le_refl _)

/-- **Revoked approvers.** After `approverRevoked a`, no registered approver has ID `a` ever
again, so (by `approved`) no forward counts an approval from `a`. -/
theorem revoked_approver_gone {bogoId bootId : ByteArray} {xs : List Input} {m j : Nat}
    {seq : Nat} {a : ApproverId} (hxm : xs[m]? = some (.approverRevoked seq a)) (hmj : m < j) :
    ∀ ap ∈ (before (Boot bogoId bootId) xs j).approvers, ap.id ≠ a := by
  have h1 : a ∈ (before (Boot bogoId bootId) xs (m + 1)).revokedApprovers := by
    rw [before_succ_some hxm]
    simp [handle, onApproverRevoked]
  have := persist (P := fun s => a ∈ s.revokedApprovers) (J := j) h1
    (fun l x _ _ _ h => revoked_step _ x h) j hmj (Nat.le_refl _)
  intro ap hap e
  exact (inv_before bogoId bootId xs j).2 ap hap (e ▸ this)

/-- **Settled is final.** A settled request ignores every later approval and denial. -/
theorem settled_final {s : State} {r : ReqId} {q : ReqRec} (hq : findReq s r = some q)
    (hs : q.status = .settled) :
    (∀ a alg p now, handle s (.approval a r alg p now) = (s, [.ignored r a .settled])) ∧
    (∀ a note, handle s (.denial a r note) = (s, [.ignored r a .settled])) := by
  refine ⟨fun a alg p now => ?_, fun a note => ?_⟩
  · simp [handle, onApproval, hq, hs]
  · simp [handle, onDenial, hq, hs]

@[simp] def _root_.Bogo.Output.isAttach : Output → Bool
  | .attach .. => true
  | _ => false

/-- No output satisfying `P`. -/
def Free (P : Output → Bool) (outs : List Output) : Prop := ∀ o ∈ outs, P o = false

@[simp] theorem free_nil {P : Output → Bool} : Free P [] := by simp [Free]

@[simp] theorem free_cons {P : Output → Bool} {o : Output} {l : List Output} :
    Free P (o :: l) ↔ P o = false ∧ Free P l := by simp [Free]

@[simp] theorem free_append {P : Output → Bool} {a b : List Output} :
    Free P (a ++ b) ↔ Free P a ∧ Free P b := by
  simp only [Free, List.mem_append]
  exact ⟨fun h => ⟨fun o ho => h o (.inl ho), fun o ho => h o (.inr ho)⟩,
    fun h o ho => ho.elim (h.1 o) (h.2 o)⟩

@[simp] theorem endWhere_attachFree (s : State) (p : ReqRec → Bool) (w : EndReason)
    (j : Rejection) : Free Output.isAttach (endWhere s p w j).2 := by
  intro o ho
  simp only [endWhere, List.mem_flatMap, List.mem_filter] at ho
  obtain ⟨r, _, hr⟩ := ho
  rcases List.mem_append.mp hr with h | h
  · split at h <;> simp_all
  · simp at h; subst h; simp

@[simp] theorem allowedReject_attachFree (s : State) (c : CallId) (j : Rejection) :
    Free Output.isAttach (allowedReject s c j) := by
  unfold allowedReject
  split <;> simp

theorem onCall_attach {s : State} {c c0 p : CallId} {sid : SessionId} {n : String}
    {a : Option JVal} {now : Nat} (h : Output.attach c0 p ∈ (onCall s c sid n a now).2) :
    c0 = c ∧ (onCall s c sid n a now).1 = s ∧ (findCall s c).isSome = false := by
  revert h
  unfold onCall
  split
  · simp
  split
  · simp
  split
  · simp
  split
  · simp
  split
  · simp
  · rename_i hfc
    split
    · simp
    · dsimp only
      split
      · simp
      · simp
      · unfold admitProtected
        repeat' split
        all_goals first
          | (simp_all; done)
          | (intro h; exfalso; simp only at h
             repeat' split at h
             all_goals simp_all)

theorem attach_noCall {s : State} {x : Input} {c p : CallId}
    (h : Output.attach c p ∈ (handle s x).2) : NoCall c (handle s x).1 := by
  by_cases hc : ∃ c' sid n a now, x = .call c' sid n a now
  · obtain ⟨c', sid, n, a, now, rfl⟩ := hc
    obtain ⟨rfl, hs, hf⟩ := onCall_attach h
    simp only [handle]; rw [hs]
    intro y hy e
    have hn : findCall s c = none := by
      cases hfc : findCall s c with
      | none => rfl
      | some _ => rw [hfc] at hf; cases hf
    have := List.find?_eq_none.mp hn y hy
    simp [e] at this
  · exfalso
    simp only [not_exists] at hc
    have hfree : Free Output.isAttach (handle s x).2 := by
      cases x with
      | call c' sid n a now => exact absurd rfl (hc c' sid n a now)
      | sessionClosed sid =>
        simp only [handle, onSessionClosed, free_append, endWhere_attachFree, and_true]
        intro o ho
        simp only [List.mem_filterMap] at ho
        obtain ⟨y, _, hy⟩ := ho
        split at hy <;> simp at hy
        subst hy; simp
      | _ =>
        simp only [handle, onApproval, onDenial, onApproverRevoked, onAgentRevoked,
          onCallEnded, onNotSent, onDispatch, onPauseAgent, pause]
        repeat' split
        all_goals simp
    exact absurd (hfree _ h) (by simp)

/-- **Attach never runs.** A call answered with `attach` gets no forward of its own: any later
forward under that call ID needs a new `call` with that ID. -/
theorem attach_never_runs {bogoId bootId : ByteArray} {xs : List Input} {m j : Nat}
    {c p : CallId} (ha : Output.attach c p ∈ outputsAt (Boot bogoId bootId) xs m)
    (hmj : m < j) {r : Option ReqId} {u t : String} {args : Option JVal} {seq : Nat}
    (hf : Output.forward c r u t args seq ∈ outputsAt (Boot bogoId bootId) xs j) :
    ∃ l, m < l ∧ l < j ∧ ∃ sid n args now, xs[l]? = some (.call c sid n args now) := by
  obtain ⟨x, hxm, hx⟩ := mem_outputsAt ha
  have h0 : NoCall c (before (Boot bogoId bootId) xs (m + 1)) := by
    rw [before_succ_some hxm]
    exact attach_noCall hx
  obtain ⟨l, hl, hlj, rest⟩ := noCall_until_call h0 hmj hf
  exact ⟨l, by omega, hlj, rest⟩

end Bogo.Proofs
