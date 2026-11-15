/-
The decision core (ARCHITECTURE §3.1): a deterministic state machine.

Every event that can affect a decision is an `Input`; every decision is an `Output`. The core
does no I/O, reads the time only from its inputs, and mints request sequence numbers itself.

The final gate (`dispatch`) does not trust anything it stored earlier. At the moment of the
upstream write it re-checks, from the current state alone, everything the promise needs: the
call is live, its session is open and bound to the request, the agent is active, the expiry has
not passed, the tool still maps to the same upstream tool and still needs approval under the
policy in force now, the request is canonical, and enough distinct approvers that are
registered now and eligible now have signatures that `verify` accepts over this request's exact
bytes. That keeps the proof of each forward local to one step.

`verify` is the one hook into Rust (`bogo_rs_verify`); what it means is assumption A1.
-/
import BogoCore.Policy

namespace Bogo

/-! ### The verify hook -/

/-- Signature check, implemented in Rust behind the C shim. Assumption A1 says what it means. -/
@[extern "bogo_shim_verify"]
opaque verify (alg : UInt16) (pk : @& ByteArray) (msg : @& ByteArray) (proof : @& ByteArray) : Bool

/-! ### Registry and state records -/

/-- A registered approver. -/
structure Approver where
  id : ApproverId
  name : String
  alg : UInt16
  pk : ByteArray
  deriving Inhabited

/-- A named agent as the core tracks it. `revoked` is permanent for that ID. -/
structure AgentRec where
  id : AgentId
  name : String
  paused : Bool
  epoch : Nat
  revoked : Bool
  deriving Inhabited

structure SessionRec where
  id : SessionId
  agent : AgentId
  client : Option String
  deriving Inhabited

inductive CallStatus where
  /-- An allowed call, holding what it will forward. -/
  | allowed (name upstream tool : String) (args : Option JVal)
  /-- A call bound to a protected request. -/
  | bound (r : ReqId)
  deriving Inhabited

structure CallRec where
  id : CallId
  session : SessionId
  status : CallStatus
  deriving Inhabited

inductive ReqStatus where
  | pending
  | settled
  deriving Repr, DecidableEq, Inhabited

/-- One counted approval: who, with which registered key, and the proof itself. The gate
verifies the proof again against the key registered at that moment. -/
structure Counted where
  id : ApproverId
  alg : UInt16
  pk : ByteArray
  proof : ByteArray
  deriving Inhabited

/-- A live request and the context it was admitted with. Only `status`, `call`, `counted`
and `denied` ever change after admission. -/
structure ReqRec where
  req : Request
  /-- The exposed tool name. -/
  name : String
  requirement : Requirement
  denyRule : DenyRule
  mode : Mode
  /-- Approvers that were registered and eligible at admission. -/
  eligible : List ApproverId
  status : ReqStatus
  /-- The call that will run it, once there is one. -/
  call : Option CallId
  counted : List Counted
  denied : List ApproverId
  deriving Inhabited

structure State where
  bogoId : ByteArray
  bootId : ByteArray
  nextSeq : Nat
  registrySeq : Nat
  cfg : PolicyConfig
  catalog : List CatalogEntry
  approvers : List Approver
  revokedApprovers : List ApproverId
  agents : List AgentRec
  sessions : List SessionRec
  calls : List CallRec
  reqs : List ReqRec
  deriving Inhabited

/-- The state at boot: nothing configured, nothing registered, nothing can run. -/
def initState (bogoId bootId : ByteArray) : State :=
  { bogoId, bootId, nextSeq := 0, registrySeq := 0, cfg := emptyConfig, catalog := [],
    approvers := [], revokedApprovers := [], agents := [], sessions := [], calls := [],
    reqs := [] }

/-! ### Inputs and outputs -/

inductive Input where
  | configure (seq : Nat) (cfg : PolicyConfig) (catalog : List CatalogEntry)
  | approverSet (seq : Nat) (a : Approver)
  | approverRevoked (seq : Nat) (id : ApproverId)
  | agentSet (seq : Nat) (id : AgentId) (name : String)
  | agentRevoked (seq : Nat) (id : AgentId)
  | ownerPause (seq : Nat) (agent : AgentId)
  | agentUnpaused (seq : Nat) (id : AgentId)
  | ownerCancel (r : ReqId)
  | sessionOpened (s : SessionId) (agent : AgentId) (client : Option String)
  | sessionClosed (s : SessionId)
  | call (c : CallId) (s : SessionId) (name : String) (args : Option JVal) (nowMs : Nat)
  | callEnded (c : CallId)
  | approval (a : ApproverId) (r : ReqId) (alg : UInt16) (proof : ByteArray) (nowMs : Nat)
  | denial (a : ApproverId) (r : ReqId) (note : Option String)
  | pauseAgent (a : ApproverId) (agent : AgentId) (epoch : Nat)
  | dispatch (c : CallId) (nowMs : Nat)
  | notSent (c : CallId)
  | tick (nowMs : Nat)
  deriving Inhabited

inductive Rejection where
  | malformed
  | unknownSession
  | unknownAgent
  | revokedAgent
  | pausedAgent
  | duplicateCall
  | unknownTool
  | denyPolicy
  | justificationRequired
  | noEligibleApprover
  | denied (note : Option String)
  | endedWithoutDecision
  | notAuthorized
  | gateClosed
  | upstreamUnavailable
  | exhausted
  deriving Repr, Inhabited

inductive EndReason where
  | denied
  | cancelled
  | callEnded
  | sessionClosed
  | agentRevoked
  | agentPaused
  | expired
  | unreachable
  | dispatchFailed
  | notSent
  deriving Repr, DecidableEq, Inhabited

inductive IgnoreReason where
  | unknown
  | settled
  | expired
  | notEligible
  | duplicate
  | badSignature
  | staleEpoch
  deriving Repr, DecidableEq, Inhabited

inductive Output where
  /-- Allowed (`none`) or requirement met (`some r`): record it, then stage the send. -/
  | authorized (c : CallId) (r : Option ReqId)
  /-- The only permission to write upstream. `r` is the request it consumes, if protected. -/
  | forward (c : CallId) (r : Option ReqId) (upstream tool : String) (args : Option JVal)
      (registrySeq : Nat)
  | attach (c primary : CallId)
  | reject (c : CallId) (why : Rejection)
  | pendingApproval (c : CallId)
  | ask (r : ReqId) (bytes : ByteArray) (to : List ApproverId) (groupKey : ByteArray)
      (pauseEpoch : Nat)
  | settled (r : ReqId) (to : List ApproverId)
  | ended (r : ReqId) (why : EndReason) (to : List ApproverId)
  | counted (r : ReqId) (a : ApproverId)
  | ignored (r : ReqId) (a : ApproverId) (why : IgnoreReason)
  | floodDropped (c : CallId)
  | agentPaused (agent : AgentId)
  deriving Inhabited

/-! ### Lookups -/

def findSession (s : State) (sid : SessionId) : Option SessionRec :=
  s.sessions.find? (fun x => eqB x.id sid)

def findAgent (s : State) (a : AgentId) : Option AgentRec :=
  s.agents.find? (fun x => eqB x.id a)

def findCall (s : State) (c : CallId) : Option CallRec :=
  s.calls.find? (fun x => eqB x.id c)

def findReq (s : State) (r : ReqId) : Option ReqRec :=
  s.reqs.find? (fun x => eqB x.req.nonce r)

def findApprover (s : State) (a : ApproverId) : Option Approver :=
  s.approvers.find? (fun x => eqB x.id a)

def findCatalog (s : State) (name : String) : Option CatalogEntry :=
  s.catalog.find? (fun e => e.name == name)

/-- Registered, not revoked and not paused. -/
def agentActive (s : State) (a : AgentId) : Bool :=
  s.agents.any (fun x => eqB x.id a && !x.revoked && !x.paused)

/-- The name the owner gave an agent, for per-agent overrides. -/
def agentName (s : State) (a : AgentId) : String :=
  match findAgent s a with
  | some x => x.name
  | none => ""

/-! ### Request IDs -/

/-- `bootId ‖ u64 seq`: the nonce and the request ID everywhere. -/
def mkReqId (bootId : ByteArray) (seq : Nat) : ReqId :=
  ⟨(rawBytes bootId ++ encU64 seq).toArray⟩

/-! ### Approvals -/

/-- The exact bytes an approval of this request must sign. -/
def recMsg (q : ReqRec) : ByteArray := sigMsg (encode q.req)

/-- A counted approval still stands: its approver is eligible for this request, is registered
now with the same algorithm and key, and the proof verifies over this request's bytes. -/
def countedValid (s : State) (q : ReqRec) (e : Counted) : Bool :=
  memB e.id q.eligible &&
  s.approvers.any (fun a => eqB a.id e.id && a.alg == e.alg && eqB a.pk e.pk) &&
  verify e.alg e.pk (recMsg q) e.proof

def validCounted (s : State) (q : ReqRec) : List Counted :=
  q.counted.filter (countedValid s q)

/-- The requirement is met by distinct, valid approvals. -/
def requirementMet (s : State) (q : ReqRec) : Bool :=
  let v := validCounted s q
  decide ((v.map (·.id)).Nodup) && decide (q.requirement.need ≤ v.length)

/-- Approvers that could still approve: eligible, registered now, and not having denied. -/
def reachable (s : State) (q : ReqRec) : Nat :=
  (q.eligible.filter (fun a => (findApprover s a).isSome && !memB a q.denied)).length

def notExpired (r : Request) (now : Nat) : Bool :=
  match r.expiresMs with
  | some e => decide (now < e)
  | none => true

/-! ### Ending requests -/

/-- End every live request matching `p`: remove it and its bound call, tell a waiting call,
and tell the approvers. -/
def endWhere (s : State) (p : ReqRec → Bool) (why : EndReason) (rej : Rejection) :
    State × List Output :=
  let gone := s.reqs.filter p
  let goneCalls := gone.filterMap (·.call)
  ({ s with
      reqs := s.reqs.filter (fun r => !p r)
      calls := s.calls.filter (fun c => !memB c.id goneCalls) },
   gone.flatMap (fun r =>
     (match r.call with
      | some c => [Output.reject c rej]
      | none => []) ++ [Output.ended r.req.nonce why r.eligible]))

def isReq (r : ReqId) (q : ReqRec) : Bool := eqB q.req.nonce r

/-! ### Admission of a call -/

/-- Split the justification out of the arguments. `none` when the value at the key is not a
string. Absent arguments stay absent; an object that held only the justification becomes
`{}`. -/
def stripJust (key : String) : Option JVal → Option (Option JVal × Option String)
  | some (.obj kvs) =>
    match kvs.find? (fun kv => kv.1 == key) with
    | some (_, .str j) => some (some (.obj (kvs.filter (fun kv => !(kv.1 == key)))), some j)
    | some _ => none
    | none => some (some (.obj kvs), none)
  | a => some (a, none)

/-- The grouping key: (agentId, upstream, tool, stripped args, justification). -/
def groupKey (r : Request) : ByteArray :=
  ⟨(encBytes r.agentId ++ encStr r.upstream ++ encStr r.tool ++ encOpt encVal r.args ++
    encOpt encStr r.justification).toArray⟩

/-- An identical live pending-and-retry request in the same session. -/
def findRetry (s : State) (sid : SessionId) (agent : AgentId) (name : String)
    (args : Option JVal) (j : Option String) : Option ReqRec :=
  s.reqs.find? (fun x =>
    x.mode == .pendingRetry && eqB x.req.session sid && eqB x.req.agentId agent &&
    x.name == name && x.req.args == args && x.req.justification == j)

/-- The live request a pending-and-retry call is a retry of, if any. -/
def retryOf (s : State) (pol : ToolPolicy) (sid : SessionId) (agent : AgentId) (name : String)
    (args : Option JVal) (j : Option String) : Option ReqRec :=
  if pol.mode == .pendingRetry then findRetry s sid agent name args j else none

def eligibleApprovers (s : State) (names : List String) : List ApproverId :=
  (s.approvers.filter (fun a => names.isEmpty || names.contains a.name)).map (·.id)

def liveCount (s : State) (agent : AgentId) : Nat :=
  (s.reqs.filter (fun x => eqB x.req.agentId agent)).length

/-- A protected call, after the policy said approve. -/
def admitProtected (s : State) (c : CallId) (sess : SessionRec) (ag : AgentRec)
    (e : CatalogEntry) (pol : ToolPolicy) (args : Option JVal) (now : Nat) :
    State × List Output :=
  match stripJust e.justKey args with
  | none => (s, [.reject c .malformed])
  | some (stripped, j) =>
    if pol.justificationRequired && j.isNone then (s, [.reject c .justificationRequired])
    else
      match retryOf s pol sess.id ag.id e.name stripped j with
      | some q =>
        match q.status with
        | .pending => (s, [.pendingApproval c])
        | .settled =>
          match q.call with
          | some p => (s, [.attach c p])
          | none =>
            ({ s with
                reqs := s.reqs.map (fun x =>
                  if isReq q.req.nonce x then { x with call := some c } else x)
                calls := { id := c, session := sess.id, status := .bound q.req.nonce } ::
                  s.calls },
             [.authorized c (some q.req.nonce)])
      | none =>
        if s.cfg.maxPending ≤ liveCount s ag.id then (s, [.floodDropped c])
        else
          let elig := eligibleApprovers s pol.approvers
          if elig.length < pol.requirement.need then (s, [.reject c .noEligibleApprover])
          else if u64Bound ≤ s.nextSeq then (s, [.reject c .exhausted])
          else
            let r : ReqId := mkReqId s.bootId s.nextSeq
            let req : Request :=
              { bogoId := s.bogoId, upstream := e.upstream, tool := e.tool, args := stripped,
                justification := j, hints := pol.hints, agentId := ag.id,
                agentName := ag.name, clientName := sess.client, session := sess.id,
                nonce := r, createdMs := now, expiresMs := pol.expiryMs.map (now + ·) }
            if !req.wf then (s, [.reject c .malformed])
            else
              let wait := pol.mode == .wait
              let q : ReqRec :=
                { req, name := e.name, requirement := pol.requirement,
                  denyRule := pol.denyRule, mode := pol.mode, eligible := elig,
                  status := .pending, call := if wait then some c else none, counted := [],
                  denied := [] }
              ({ s with
                  nextSeq := s.nextSeq + 1
                  reqs := q :: s.reqs
                  calls := if wait then
                    { id := c, session := sess.id, status := .bound r } :: s.calls
                    else s.calls },
               [.ask r (encode req) elig (groupKey req) ag.epoch] ++
                 (if wait then [] else [.pendingApproval c]))

def onCall (s : State) (c : CallId) (sid : SessionId) (name : String) (args : Option JVal)
    (now : Nat) : State × List Output :=
  match findSession s sid with
  | none => (s, [.reject c .unknownSession])
  | some sess =>
    match findAgent s sess.agent with
    | none => (s, [.reject c .unknownAgent])
    | some ag =>
      if ag.revoked then (s, [.reject c .revokedAgent])
      else if ag.paused then (s, [.reject c .pausedAgent])
      else if (findCall s c).isSome then (s, [.reject c .duplicateCall])
      else
        match findCatalog s name with
        | none => (s, [.reject c .unknownTool])
        | some e =>
          let pol := resolve s.cfg ag.name name
          match pol.kind with
          | .deny => (s, [.reject c .denyPolicy])
          | .allow =>
            ({ s with calls :=
                { id := c, session := sid, status := .allowed name e.upstream e.tool args } ::
                  s.calls },
             [.authorized c none])
          | .approve => admitProtected s c sess ag e pol args now

/-! ### Decisions from approvers -/

/-- Update the request records with this ID. Callers change only `status`, `call`, `counted`
and `denied`; the admission context stays as it was. -/
def setReq (s : State) (r : ReqId) (f : ReqRec → ReqRec) : State :=
  { s with reqs := s.reqs.map (fun x => if isReq r x then f x else x) }

def onApproval (s : State) (a : ApproverId) (r : ReqId) (alg : UInt16) (proof : ByteArray)
    (now : Nat) : State × List Output :=
  match findReq s r with
  | none => (s, [.ignored r a .unknown])
  | some q =>
    match q.status with
    | .settled => (s, [.ignored r a .settled])
    | .pending =>
      if !notExpired q.req now then
        let e := endWhere s (isReq r) .expired .endedWithoutDecision
        (e.1, .ignored r a .expired :: e.2)
      else
        match findApprover s a with
        | none => (s, [.ignored r a .notEligible])
        | some ap =>
          if !memB a q.eligible || memB a q.denied || !(ap.alg == alg) then
            (s, [.ignored r a .notEligible])
          else if q.counted.any (fun e => eqB e.id a) then (s, [.ignored r a .duplicate])
          else if !verify ap.alg ap.pk (recMsg q) proof then
            (s, [.ignored r a .badSignature])
          else
            let q' := { q with
              counted := q.counted ++ [{ id := a, alg := ap.alg, pk := ap.pk, proof }] }
            if requirementMet s q' then
              (setReq s r (fun x => { x with counted := q'.counted, status := .settled }),
               [.counted r a, .settled r q.eligible] ++
                 (match q.call with
                  | some c => [.authorized c (some r)]
                  | none => []))
            else (setReq s r (fun x => { x with counted := q'.counted }), [.counted r a])

def onDenial (s : State) (a : ApproverId) (r : ReqId) (note : Option String) :
    State × List Output :=
  match findReq s r with
  | none => (s, [.ignored r a .unknown])
  | some q =>
    match q.status with
    | .settled => (s, [.ignored r a .settled])
    | .pending =>
      if (findApprover s a).isNone || !memB a q.eligible then (s, [.ignored r a .notEligible])
      else
        match q.denyRule with
        | .anyDenial => endWhere s (isReq r) .denied (.denied note)
        | .whenUnreachable =>
          -- A denial withdraws that approver: it can no longer approve, and an approval it
          -- gave earlier no longer counts.
          let q' := { q with denied := a :: q.denied,
                             counted := q.counted.filter (fun e => !eqB e.id a) }
          let s' := setReq s r (fun x => { x with denied := q'.denied, counted := q'.counted })
          if reachable s' q' < q.requirement.need then
            endWhere s' (isReq r) .denied (.denied note)
          else (s', [])

/-! ### Pause -/

def setAgent (s : State) (a : AgentId) (f : AgentRec → AgentRec) : State :=
  { s with agents := s.agents.map (fun x => if eqB x.id a then f x else x) }

/-- Pause an agent: deny every live request it has. -/
def pause (s : State) (agent : AgentId) : State × List Output :=
  let s1 := setAgent s agent (fun x => { x with paused := true })
  let e := endWhere s1 (fun x => eqB x.req.agentId agent) .agentPaused .pausedAgent
  (e.1, e.2 ++ [.agentPaused agent])

def onPauseAgent (s : State) (a : ApproverId) (agent : AgentId) (epoch : Nat) :
    State × List Output :=
  match findApprover s a, findAgent s agent with
  | some _, some ag =>
    if ag.epoch == epoch then pause s agent else (s, [])
  | _, _ => (s, [])

/-! ### Registry -/

def bumpSeq (s : State) (seq : Nat) : State := { s with registrySeq := max s.registrySeq seq }

def onApproverSet (s : State) (a : Approver) : State :=
  if memB a.id s.revokedApprovers then s
  else { s with approvers := a :: s.approvers.filter (fun x => !eqB x.id a.id) }

/-- Revocation is permanent for that ID. Pending requests that can no longer reach their
requirement end; settled ones are caught by the gate. -/
def onApproverRevoked (s : State) (id : ApproverId) : State × List Output :=
  let s1 := { s with
    approvers := s.approvers.filter (fun x => !eqB x.id id)
    revokedApprovers := id :: s.revokedApprovers }
  endWhere s1 (fun x => x.status == .pending && reachable s1 x < x.requirement.need)
    .unreachable .endedWithoutDecision

def onAgentSet (s : State) (id : AgentId) (name : String) : State :=
  match findAgent s id with
  | some _ => setAgent s id (fun x => { x with name })
  | none => { s with agents := { id := id, name := name, paused := false, epoch := 0, revoked := false } ::
      s.agents }

def markRevoked (s : State) (id : AgentId) : State :=
  match findAgent s id with
  | some _ => setAgent s id (fun x => { x with revoked := true })
  | none =>
    let a : AgentRec := { id := id, name := "", paused := false, epoch := 0, revoked := true }
    { s with agents := a :: s.agents }

def onAgentRevoked (s : State) (id : AgentId) : State × List Output :=
  let s1 := markRevoked s id
  endWhere s1 (fun x => eqB x.req.agentId id) .agentRevoked .revokedAgent

/-! ### Sessions and calls -/

def onSessionOpened (s : State) (sid : SessionId) (agent : AgentId) (client : Option String) :
    State :=
  match findSession s sid with
  | some _ => s
  | none => { s with sessions := { id := sid, agent := agent, client := client } :: s.sessions }

def onSessionClosed (s : State) (sid : SessionId) : State × List Output :=
  let dropped := s.calls.filter (fun c => eqB c.session sid)
  let s1 := { s with
    sessions := s.sessions.filter (fun x => !eqB x.id sid)
    calls := s.calls.filter (fun c => !eqB c.session sid) }
  let e := endWhere s1 (fun x => eqB x.req.session sid) .sessionClosed
    .endedWithoutDecision
  (e.1, dropped.filterMap (fun c => match c.status with
      | .allowed .. => some (.reject c.id .endedWithoutDecision)
      | .bound _ => none) ++ e.2)

def removeCall (s : State) (c : CallId) : State :=
  { s with calls := s.calls.filter (fun x => !eqB x.id c) }

/-- Whether a request is bound to this call. -/
def boundTo (c : CallId) (q : ReqRec) : Bool := q.call.any (eqB c)

/-- A reject for an allowed call that is being dropped. -/
def allowedReject (s : State) (c : CallId) (why : Rejection) : List Output :=
  match findCall s c with
  | some { status := .allowed .., .. } => [.reject c why]
  | _ => []

/-- A call ended: drop it, and end the request bound to it. -/
def onCallEnded (s : State) (c : CallId) : State × List Output :=
  let e := endWhere (removeCall s c) (boundTo c) .callEnded .endedWithoutDecision
  (e.1, allowedReject s c .endedWithoutDecision ++ e.2)

/-! ### The final gate -/

/-- An allowed call may run now: its session is open, its agent is active, the tool is in the
catalog under the same upstream and tool, and the effective policy right now is `allow`. -/
def allowedGate (s : State) (cr : CallRec) (name u t : String) : Bool :=
  match findSession s cr.session with
  | none => false
  | some sess =>
    agentActive s sess.agent &&
    (match findCatalog s name with
     | some e => e.upstream == u && e.tool == t
     | none => false) &&
    (resolve s.cfg (agentName s sess.agent) name).kind == .allow

/-- At the gate, a counted approval stands if its approver was eligible when the request was
admitted, has not denied it, is registered now with the key it signed with and a name the policy in force now
makes eligible, and its proof verifies over this request's exact bytes. -/
def standsNow (s : State) (q : ReqRec) (pol : ToolPolicy) (e : Counted) : Bool :=
  memB e.id q.eligible && !memB e.id q.denied &&
  s.approvers.any (fun a => eqB a.id e.id && a.alg == e.alg && eqB a.pk e.pk &&
    (pol.approvers.isEmpty || pol.approvers.contains a.name)) &&
  verify e.alg e.pk (recMsg q) e.proof

/-- Enough distinct approvals stand now for both the requirement the request was admitted with
and the one in force now. -/
def gateMet (s : State) (q : ReqRec) (pol : ToolPolicy) : Bool :=
  let v := q.counted.filter (standsNow s q pol)
  decide ((v.map (·.id)).Nodup) && decide (q.requirement.need ≤ v.length) &&
    decide (pol.requirement.need ≤ v.length)

/-- A protected call may run now. Everything is judged against the current state: the session,
the agent, the catalog and the effective policy for this agent and tool right now. -/
def protectedGate (s : State) (cr : CallRec) (q : ReqRec) (now : Nat) : Bool :=
  q.status == .settled &&
  q.call.any (eqB cr.id) &&
  eqB q.req.session cr.session &&
  (match findSession s cr.session with
   | some sess => eqB sess.agent q.req.agentId && agentActive s sess.agent
   | none => false) &&
  notExpired q.req now &&
  (match findCatalog s q.name with
   | some e => e.upstream == q.req.upstream && e.tool == q.req.tool
   | none => false) &&
  (resolve s.cfg (agentName s q.req.agentId) q.name).kind == .approve &&
  q.req.wf &&
  gateMet s q (resolve s.cfg (agentName s q.req.agentId) q.name)

def onDispatch (s : State) (c : CallId) (now : Nat) : State × List Output :=
  match findCall s c with
  | none => (s, [.reject c .notAuthorized])
  | some cr =>
    let s1 := removeCall s c
    match cr.status with
    | .allowed name u t args =>
      if allowedGate s cr name u t then (s1, [.forward c none u t args s.registrySeq])
      else (s1, [.reject c .gateClosed])
    | .bound r =>
      match findReq s r with
      | none => (s1, [.reject c .endedWithoutDecision])
      | some q =>
        if protectedGate s cr q now then
          ({ s1 with reqs := s1.reqs.filter (fun x => !isReq r x) },
           [.forward c (some r) q.req.upstream q.req.tool q.req.args s.registrySeq])
        else
          let e := endWhere s1 (isReq r) .dispatchFailed .gateClosed
          -- `endWhere` already rejects the call when the request is bound to it;
          -- report the gate closing to this call either way.
          (e.1, (if q.call.any (eqB c) then [] else [.reject c .gateClosed]) ++ e.2)

/-- The shell could not stage the send: the call's authority is consumed. -/
def onNotSent (s : State) (c : CallId) : State × List Output :=
  let e := endWhere (removeCall s c) (boundTo c) .notSent .upstreamUnavailable
  (e.1, allowedReject s c .upstreamUnavailable ++ e.2)

def expiredAt (now : Nat) (x : ReqRec) : Bool := !notExpired x.req now

/-! ### Step -/

def handle (s : State) : Input → State × List Output
  | .configure seq cfg catalog => ({ bumpSeq s seq with cfg, catalog }, [])
  | .approverSet seq a => (onApproverSet (bumpSeq s seq) a, [])
  | .approverRevoked seq id => onApproverRevoked (bumpSeq s seq) id
  | .agentSet seq id name => (onAgentSet (bumpSeq s seq) id name, [])
  | .agentRevoked seq id => onAgentRevoked (bumpSeq s seq) id
  | .ownerPause seq agent =>
    match findAgent s agent with
    | some _ => pause (bumpSeq s seq) agent
    | none => (bumpSeq s seq, [])
  | .agentUnpaused seq id =>
    (setAgent (bumpSeq s seq) id (fun x => { x with paused := false, epoch := seq }), [])
  | .ownerCancel r => endWhere s (isReq r) .cancelled .endedWithoutDecision
  | .sessionOpened sid agent client => (onSessionOpened s sid agent client, [])
  | .sessionClosed sid => onSessionClosed s sid
  | .call c sid name args now => onCall s c sid name args now
  | .callEnded c => onCallEnded s c
  | .approval a r alg proof now => onApproval s a r alg proof now
  | .denial a r note => onDenial s a r note
  | .pauseAgent a agent epoch => onPauseAgent s a agent epoch
  | .dispatch c now => onDispatch s c now
  | .notSent c => onNotSent s c
  | .tick now => endWhere s (expiredAt now) .expired .endedWithoutDecision

/-- The earliest expiry among live requests: when the shell should next send `tick`. -/
def nextDeadline (s : State) : Option Nat :=
  (s.reqs.filterMap (·.req.expiresMs)).min?

/-- One step: the new state, the decisions, and the next deadline. -/
def step (s : State) (i : Input) : State × List Output × Option Nat :=
  let h := handle s i
  (h.1, h.2, nextDeadline h.1)

end Bogo
