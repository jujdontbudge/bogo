# User documentation verification

2026-11-15. Docs branch `t3/write-bogo-user-docs`, based on `build/bogo` at
`943e3a8`. This record is new; existing specification, architecture, ADRs and
verification records were not edited. The code was not changed.

## 1. README: empty home to real Claude approval

Ran the README shell blocks from the repository root on this Mac, using a fresh
`mktemp -d /tmp/bogo-quickstart.XXXXXX` directory. Used the installed Rust/elan,
Node/npm, Python and logged-in Claude Code; no login or credential changes were
made. The README documents those prerequisites rather than implying it installs
or authenticates Claude. Kept the existing account HOME and existing BOGO service
alone. The demo daemon was a separate foreground process on port 18790.

Commands and observed results:

```text
cargo build -p bogo -p bogo-daemon -p bogo-shim --features bogo/test-approvers
  Finished dev profile
bogo --home <demo>/home init
  Created <demo>/home; user LaunchAgent prepared (not loaded)
npm install --prefix <demo>/upstream --no-audit --no-fund \
  @modelcontextprotocol/server-filesystem@2.3.0
  added 9 packages in 1s
bogo --home <demo>/home upstream add files -- <node> <server>/dist/index.js <demo>/scratch
  Added upstream files; start BOGO to discover its tools.
bogo --home <demo>/home serve
bogo --home <demo>/home status
  {"agents":0,"approvers":0,"boot_seq":1,"requests":0,
   "running":true,"upstreams":{"files":true}}
bogo --home <demo>/home approver add 'Demo approver' --kind soft
  {"kind":"soft","name":"Demo approver", ...}
bogo --home <demo>/home agent add 'Demo agent'
  Token captured directly to the shim environment; not printed in evidence.
bogo --home <demo>/home tools
  files__read_text_file: Allow
  files__write_file: Approve
  eligible_approvers: 1; require: 1; unexposable: []
```

Ran real `claude -p` from the empty demo client directory, with the README's
`--mcp-config`, `--strict-mcp-config`, `--tools ''`,
`--allowedTools 'mcp__bogo__*'`, and `--permission-mode dontAsk`. The MCP JSON
contains only the absolute shim command; token and URL are inherited env vars.
Claude first used the real filesystem read, then attempted the protected write.

The first immediate request-list query returned `[]` while the model was still
working; the next showed one pending request. `request list` currently returns
hex request bytes, not decoded fields. Corrected the README to use
`bogo log search files__write_file` for inspecting this fresh demo's sole write:

```text
agent_name: Demo agent
tool: files__write_file
policy: Approve
arguments: {"content":"BOGO APPROVED",
            "justification":"Quick start protected write",
            "path":"<demo>/scratch/approved.txt"}
test ! -e <demo>/scratch/approved.txt
  Not written before approval
bogo --home <demo>/home soft 'Demo approver' <full pending ID>
  decision recorded
```

The full request ID was supplied from that live request, replacing the README's
placeholder. Claude exited 0 and reported both actual upstream results:

```text
files__read_text_file:
  {"content":"Hello from BOGO\n"}
files__write_file:
  {"content":"Successfully wrote to <demo>/scratch/approved.txt"}
```

Independent filesystem read: exactly `b'BOGO APPROVED'`, no trailing newline.
The audit contained exactly one protected `forwarded` entry. Verification:

```text
bogo --home <demo>/home log verify
chain intact; Report { entries: 21, approvers_registered: 1,
  approvers_revoked: 0, approvals_counted: 1, approvals_ignored: 0,
  denials_applied: 0, denials_ignored: 0 }
```

Sent TERM to this demo foreground daemon and waited for its successful exit.
Stopped log verification returned the same intact report. As an additional
persistence check, restarted that home once and checked status:

```text
{"agents":1,"approvers":1,"boot_seq":2,"requests":0,
 "running":true,"upstreams":{"files":true}}
Agent and approver survived restart; one protected forward; file unchanged
```

Stopped it again. Final verification: chain intact, 23 entries, still one
counted approval. No old call replayed. Removed the validation-only private
token handoff file; no demo service was left running or installed in launchd.
The software seed remains private demo state, never a documentation artifact.

Also executed the README's separate production build command:

```sh
CARGO_TARGET_DIR=target/production cargo build -p bogo -p bogo-daemon -p bogo-shim
```

It passed with no test features. The production service installation/start
instructions were read against `owner.rs`; no existing login service was
replaced to recheck launchd in this docs-only task.

## 2. Configuration reference against the real parser

Built a temporary Rust CLI outside the repository linked to the actual
`bogo-config` rlib. It called `Secrets::load` and `Config::parse` on temporary
files. A temporary driver varied one field at a time and checked exit status.
It is a direct usage probe, not a new repository test or a mock parser.
Only synthetic noncredential strings were used. Full normalized output:
[user-docs-config-output.txt](user-docs-config-output.txt).

```text
191/191 configuration cases matched expectation
21/21 additional boundary/type cases matched expectation
```

The 212 cases cover every raw table/key, missing required fields/tables,
unknown keys, wrong TOML types, version, port/size bounds, IPv4 Host entries,
unsafe defaults, flood limits, positive duration grammar/overflow, relay
requirements, APNs references/nonblank IDs, App Attest environment validation,
upstream names/transports/secret references, tool names, policy/justification,
highlight paths/formats, approver duplicates/blanks, requirement syntax/bounds,
deny rules, mode, filter paths/actions, agent overrides, and secret names,
values/path tables, permissions and symlink refusal for the secrets file.

Accepted controls checked the complete configuration, minimal defaults,
development environment, remote HTTP, currency format without registry
validation, unknown approver names, literal bracket filter path, root-array
highlight, and unreachable override threshold. These keep the reference from
claiming validation stronger than the parser implements.

Eight separate real-daemon startup probes confirmed checks beyond the parser:

```text
2MiB max_body: server max_body exceeds the strict parser limit (1MiB)
Outside path secret: path secret auth must live inside BOGO home
Existing symlink escape: path secret auth must live inside BOGO home
Upstream root, child, parent, and --directory=<home> (four cases):
  upstream command/args reaches BOGO home or its parent
APNs value secret with iPhone route: APNs key must be a path secret
```

One additional probe exposed the bug below. The first runtime driver stopped
at its timeout because it expected that dangling symlink to be refused. A later
comparison initially compared macOS `/var` to `/private/var`; canonicalizing
both sides corrected that probe assertion. Neither failure was hidden as a
product pass. All probe daemons were stopped; no code was changed.

## Reported bug: dangling symlink path secret

`crates/bogo-daemon/src/owner.rs`, `normalize` and `load`: when `canonicalize`
fails for a dangling symlink, recursive parent normalization can retain the
symlink name inside BOGO home. The path-secret containment check then accepts
it. Later creating the target makes that accepted credential path resolve
outside BOGO home. Existing resolvable symlink escapes were correctly refused.

Minimal reproduction, with only disposable state and no upstream/relay:

1. Initialize a new BOGO home under a fresh temporary parent. Write the minimal
   valid config with a free port and max_pending.
2. Make `<home>/escape` a symlink to `<parent>/not-created-yet`, which does not
   exist. Set `auth = { path = "<home>/escape/auth.json" }` in the private
   secrets file.
3. Run `bogo --home <home> serve`. Observed `bogo status`: `running: true`.
4. Create `<parent>/not-created-yet/auth.json` with synthetic fixture text.
   Resolving `<home>/escape/auth.json` now yields that file outside BOGO home.
5. Stop the foreground daemon.

Expected under the stated startup constraint: refuse the unresolved symlink
escape rather than accepting an outside path. This weakens startup path
validation; it is not evidence that an isolated agent can create the symlink or
that an upstream credential was exposed. No actual credential was involved.
Reported only, per the docs-only constraint. The reference and threat model
explicitly describe the limitation instead of promising complete containment.

## 3. Theorems and assumptions

Read each documented property against the theorem statement and its definitions
in `Promise.lean`, `Spec.lean`, `Bytes.lean`, `Encoding.lean` and `Decode.lean`.
The table includes the weaker call-ID/retry qualifications instead of claiming
unconditional exactly-once provider execution. A1–A10 each have a stated failure
consequence; A1 is distinguished from external assumptions.

```sh
export PATH="$HOME/.elan/bin:$PATH"
(cd lean && lake build BogoProofs)
(cd lean && lake env lean BogoProofs/Axioms.lean)
```

Both passed. The build checked 18 jobs, including all proof modules and guarded
axiom lists. Also ran an external temporary Lean file importing the axioms
module and directly printing every one of its 24 named dependency lists.
Observed examples:

```text
'Bogo.Proofs.approved' depends on axioms:
  [propext, Classical.choice, Quot.sound, Bogo.Proofs.A1_unforgeable]
'Bogo.Proofs.exact' depends on axioms:
  [propext, Classical.choice, Quot.sound]
'Bogo.Proofs.unlisted_never_allow' depends on axioms: [propext]
'Bogo.Proofs.approved_bytes' depends on axioms:
  [propext, Classical.choice, Quot.sound, Bogo.Proofs.A1_unforgeable]
```

Only approved/approved_bytes used A1; every other guarded theorem used the
standard three except unlisted_never_allow (propext only). No sorryAx or other
project axiom appeared. The docs report exactly these sets.

## 4. Threat model and guardrails

Compared the threat model with SPEC §3.19 and the existing full bypass report,
including its model-edge limitation, credential-scan scope, real replay and
session-reuse attempts. The recorded 145/0/3 result is explicitly historical,
not presented as a rerun or proof of absence of escapes. Read the iPhone
`build/bogo` versions of registration, approval key, review and App Attest code
with `git show`; its working checkout was on main and was not switched/edited.

Only README and new documentation/evidence files changed. No SPEC,
ARCHITECTURE, glossary, ADR or existing verification record changed. No Apple
Bridge Mac repo was accessed; the iPhone repo was read-only. No password
prompts, sudo, keychain writes, system LaunchAgents or desktop apps with an
overridden HOME were used. No actual secrets, tokens or owner details were
copied into these docs. All daemon experiments used temporary homes and dummy
upstreams/credential fixtures, except the real filesystem/Claude walkthrough.

```sh
cargo clippy --workspace --all-targets --features bogo/test-approvers -- -D warnings
git diff --check
```

Both passed. Clippy checked all workspace targets and types with the demo
feature. No code package was changed, so no Rust test suite or sol-loop was
needed; Lean proof checking and real parser/daemon/client use are the relevant
checks here. No new repository tests were added.

## Not checked

No fresh machine/toolchain install or Claude login; existing prerequisite
installations/login were used. No new launchd install, logout/login, sleep/wake,
clock-change or crash injection. No hardware iPhone/Face ID/App Attest or
provisioning-prefix qualification, APNs delivery, public relay deployment,
completed Link login/payment or authenticated Link output filtering. No fresh
sandbox bypass run; the threat model was checked against its existing report.
No exhaustive enumeration of infinite invalid input strings or all third-party
transport validation: parser probes cover the documented refusal classes and
boundaries. No claim that the software demo meets production user verification.
