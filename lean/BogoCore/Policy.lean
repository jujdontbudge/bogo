/-
Policy and its resolution (ARCHITECTURE §3.1, SPEC §3.4).

* Every tool has exactly one `PolicyKind`: allow, approve or deny.
* The default for tools the owner never listed has type `DefaultPolicy`, which has no `allow`
  constructor, so no configuration can make an unlisted tool run without approval
  (Principle 5).
* A per-agent override replaces the tool's kind, approvers or requirement for one named agent.
-/
import BogoCore.Encoding

namespace Bogo

abbrev ApproverId := ByteArray
abbrev CallId := ByteArray

/-- Byte-string equality as a `Bool`, decided by `ByteArray`'s `DecidableEq` (so it is lawful). -/
def eqB (a b : ByteArray) : Bool := decide (a = b)

/-- Whether a list of byte strings contains one. -/
def memB (x : ByteArray) (xs : List ByteArray) : Bool := xs.any (eqB x)

inductive PolicyKind where
  | allow
  | approve
  | deny
  deriving Repr, DecidableEq, Inhabited

/-- The default policy. It has no `allow`. -/
inductive DefaultPolicy where
  | approve
  | deny
  deriving Repr, DecidableEq, Inhabited

def DefaultPolicy.kind : DefaultPolicy → PolicyKind
  | .approve => .approve
  | .deny => .deny

/-- Any-of, or at least `k` distinct approvers. -/
inductive Requirement where
  | anyOf
  | kOfN (k : Nat)
  deriving Repr, DecidableEq, Inhabited

/-- How many distinct approvals a requirement needs. Never zero: a `kOfN 0` that reached the
core anyway still needs one approval, so `approve` can never mean "no approval". -/
def Requirement.need : Requirement → Nat
  | .anyOf => 1
  | .kOfN k => max k 1

/-- For k-of-n: does one denial end the request, or only a denial that leaves `k`
unreachable? -/
inductive DenyRule where
  | anyDenial
  | whenUnreachable
  deriving Repr, DecidableEq, Inhabited

inductive Mode where
  | wait
  | pendingRetry
  deriving Repr, DecidableEq, Inhabited

/-- One tool's policy, as the owner configured it. -/
structure ToolPolicy where
  kind : PolicyKind
  justificationRequired : Bool
  hints : List (Path × Format)
  expiryMs : Option Nat
  /-- Eligible approvers by name. Empty means every registered approver. -/
  approvers : List String
  requirement : Requirement
  denyRule : DenyRule
  mode : Mode
  deriving Inhabited

/-- A per-agent override for one tool. Unset fields fall back to the tool's own policy. -/
structure AgentOverride where
  agentName : String
  tool : String
  kind : Option PolicyKind
  approvers : Option (List String)
  requirement : Option Requirement
  deriving Inhabited

/-- Everything `bogo.toml` says that the core needs. -/
structure PolicyConfig where
  defaultPolicy : DefaultPolicy
  /-- Per-agent flood limit: live (pending plus settled) requests at once. -/
  maxPending : Nat
  /-- By exposed name, `<upstream>__<tool>`. -/
  tools : List (String × ToolPolicy)
  overrides : List AgentOverride
  deriving Inhabited

/-- One discovered tool. -/
structure CatalogEntry where
  /-- The exposed name, `<upstream>__<tool>`. -/
  name : String
  upstream : String
  tool : String
  /-- The justification property chosen for this tool; the only key the core strips. -/
  justKey : String
  deriving Inhabited

/-- The policy of a tool with no entry: the default kind, nothing else set. -/
def defaultTool (d : DefaultPolicy) : ToolPolicy :=
  { kind := d.kind, justificationRequired := false, hints := [], expiryMs := none,
    approvers := [], requirement := .anyOf, denyRule := .anyDenial, mode := .wait }

/-- The tool's own entry, else the default. -/
def toolPolicy (cfg : PolicyConfig) (name : String) : ToolPolicy :=
  match cfg.tools.find? (fun e => e.1 == name) with
  | some e => e.2
  | none => defaultTool cfg.defaultPolicy

/-- The override for this agent and tool, if any. -/
def findOverride (cfg : PolicyConfig) (agentName name : String) : Option AgentOverride :=
  cfg.overrides.find? (fun o => o.agentName == agentName && o.tool == name)

/-- The effective policy: the per-agent override, else the tool's entry, else the default. -/
def resolve (cfg : PolicyConfig) (agentName name : String) : ToolPolicy :=
  let base := toolPolicy cfg name
  match findOverride cfg agentName name with
  | some o =>
    { base with
      kind := o.kind.getD base.kind
      approvers := o.approvers.getD base.approvers
      requirement := o.requirement.getD base.requirement }
  | none => base

/-- A config that lets nothing run: the state before the first `configure`. -/
def emptyConfig : PolicyConfig :=
  { defaultPolicy := .approve, maxPending := 0, tools := [], overrides := [] }

end Bogo
