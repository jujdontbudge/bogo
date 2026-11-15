# Daemon and owner CLI verification

Worktree branch: `t3/assemble-bogo-daemon-cli`. Test data was kept in the private
BOGO directory `/tmp/bogo-assembly-verification/home`; the filesystem upstream
could reach only the sibling `scratch` directory. No Apple Bridge repository,
gateway, relay or production credentials were changed. No password prompt,
Keychain write, system service or desktop app with an overridden home was used.
The user LaunchAgent used the real login session with an explicit `--home`.

## Checks

Build output was kept small with `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, and `CARGO_INCREMENTAL=0`.

```sh
cargo build -p bogo -p bogo-daemon -p bogo-shim
cargo build -p bogo --features test-approvers,test-registration
cargo build -p bogo-relay
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features bogo/test-approvers,bogo/test-registration -- -D warnings
cargo test --workspace
cargo test --workspace --features bogo/test-approvers,bogo/test-registration
```

Default and feature workspace tests and Clippy passed. The first build failed
because the disk was full; it succeeded after the owner freed space. The first
workspace test invocation lacked the separately built `bogo-relay` binary used
by an existing stand-in regression. After building it, the full suite passed.
That regression's relay invocation now supplies `--mailbox-capacity 100`, since
this ticket removes the old shipped capacity default. No check was skipped.
Scoped formatting passed; existing repository formatting was left alone.

## 1. Empty setup, real upstream, login service

Ran `bogo --home ... init` from an empty BOGO directory. Set `max_pending = 2`
only in the test configuration. Added the official filesystem server 2.3.0,
using its installed `dist/index.js` and a scratch directory. Ran `bogo start`.
`launchctl print gui/501/si.eilmer.bogo` showed `type = LaunchAgent`,
`state = running`, and the CLI's absolute executable plus `--home ... serve`.

```text
{"running":true,"boot_seq":1,"agents":0,"approvers":1,
 "requests":0,"upstreams":{"files":true}}
```

The control socket had mode 0600. The BOGO directories were 0700. The CLI created
0600 secrets and keys. Named agents were added with unique tokens captured only
in the client's memory/environment; tokens are omitted from all evidence.
Stopped agent add/list/revoke commands also worked under the writer lock.

## 2. Real clients, allow, protected writes and changed arguments

Used `bogo-shim` as an actual stdio MCP client transport. Its tools/list returned
15 filesystem tools, hiding denied `files__list_directory`. An allowed
`files__read_text_file` immediately returned:

```text
BOGO allowed read evidence\n
```

A protected `files__write_file` remained pending and its target did not exist.
`bogo soft 'Soft A' <request>` approved the core's exact bytes. The official
server returned `Successfully wrote to .../approved.txt`; the file contained
exactly `exact approved content\n`. Changing the content created a different
full request ID and left the old file unchanged until a new decision.

Ran logged-in `claude -p`, without `--bare`, with only the BOGO MCP server,
`--tools ''`, `--allowedTools 'mcp__bogo__*'`, and `--permission-mode dontAsk`.
The shim inherited its token through the environment; its MCP JSON config
contained no token. Claude read the allowed file, then its write appeared in
`bogo request list` while `claude.txt` still did not exist. After CLI soft
approval, Claude exited 0 and reported both real tool results. The file was
independently checked to contain exactly `CLAUDE APPROVED CONTENT\n`.

An append tool in pending-and-retry mode returned the specified pending text.
After approval it still had not run. The identical retry appended one line;
the next identical call required a new request and approval. The file had only
one approved appended line. The audit contained only one `forwarded` per
approved request.

The final dispatch path was exercised again after moving its durability wait
before the final core check. The real allowed read and protected write passed.
Its durable sequence was:

```text
request_created → approval → request_settled → authorized
→ dispatch_intent → forwarded → call_result(executed) → result
```

There is no awaited log operation after an accepted final `forward`. The
already durable intent/authorization covers an interruption before the
forwarding record. This resolves the architecture's competing requirements to
record before effects and to wait for nothing after the freshness check.

## 3. Denial and client loss

A denial with note `wrong amount` reached the MCP client as:

```text
The owner denied this action. wrong amount
```

A separate real Claude run received and reported exactly that error text; its
requested file did not exist. Another real Claude process group was killed
while its write waited. The request disappeared, `request_ended` was durable,
and no target file was created. Killing a raw shim during a wait also ended
its request. A direct deny-policy call returned `This tool is denied by policy.`
A Researcher override hid write_file in tools/list and denied a direct call.

## 4. Thresholds and iPhone route

Two registered software approvers exercised the core's real threshold:

```text
ONE IS NOT ENOUGH 1
SAME APPROVER TWICE 1
TWO DISTINCT RESULT Successfully wrote to .../two.txt
```

The Simulator UI check is **blocked**. The device tool returned:

```text
Error (DEVICE_IN_USE): Device is already in use by another session.
Waited 1002ms for this device and it stayed busy.
```

Its suggested bounded wait was tried once. The existing session was neither
reused nor closed, and the iPhone app was not changed.

As separate route evidence, ran a private TLS `bogo-relay` on localhost:18843,
with explicit 3600-second retention and capacity 100. Enabled the daemon's
`test-registration` feature, set the iPhone arm delay to 1s in that test config,
and used the existing `bogo-simphone` as a whole software phone. Compared matching
SAS values, confirmed both endpoints, and registered through `bogo approver add`.
The registry logged `simulator-test` evidence. This is not hardware attestation.
A new protected call required two approvals, one soft plus this P-256 relay route:

```text
← request #1 (boot 6, arm 1000 ms)
SOFT ALONE STILL WAITING
RELAY SECOND APPROVAL RESULT Successfully wrote to .../relay-approved.txt
← settled
← outcome = executed
```

The exact file content was checked. Log verification counted both distinct
signatures. This uses the daemon's actual iPhone route, registration driver,
HPKE envelopes, relay mailbox and outcome notices; it does not verify Swift UI,
Face ID or the concurrently developed native app relay link.

## 5. Pause, flood, cancel and revocation

Pause ended a waiting call with `This agent is paused.` A subsequent read was
rejected with that same message. Unpause allowed a fresh shim session to run.
Three simultaneous distinct calls against `max_pending = 2` produced two live
requests and one `The pending request limit was reached.` No third request or
approver delivery was created; `flood_dropped` was logged. CLI cancellation
returned the spec's exact ended message for the waiting calls.

Revoking Soft B while a 2-of-2 request waited ended it without executing. Owner
revocation, pause and unpause survived restart through log replay. Approver
re-registration uses a new key and invalidates the replaced approver in the core.

## 6. Crash, restart and corruption

Used a FIFO in the scratch directory to keep the official filesystem server's
read in progress. Approved it, observed its durable `forwarded` record, and sent
SIGKILL to this user LaunchAgent through launchctl. KeepAlive restarted the daemon:

```text
KEEPALIVE RESTART {"boot_seq":4,"requests":0,"running":true,
                  "upstreams":{"files":true}}
VERIFY AFTER CRASH chain intact
NO REPLAY: exactly one forwarded record
```

The old request was never retried. Its log-only outcome is unknown because it
was forwarded without a result before the new boot. Earlier pending requests
cannot be resumed. JSONL and CSV exports succeeded. Editing one byte in a copy
of the log produced:

```text
bogo: audit log line 2 is corrupt: previous-hash link broken
```

The authoritative original was not edited. The final checked log had 179 entries,
9 counted approvals, one ignored duplicate and two applied denials; the chain,
canonical request bytes and signatures verified through the linked Lean code.

## 7. Configuration and output guardrails

Startup rejected each independently configured case before opening an upstream:
unset max_pending, default allow, an unknown field, unset relay retention, unset
relay capacity, unset iPhone arm delay, an upstream pointed at the BOGO directory
or its parent, a 0644 secrets file, and a path secret outside the BOGO directory.
The errors identified the relevant field or path constraint without printing
secret values.

Output filtering was exercised against the real filesystem server. With
`filter_output = ["content"]`, its original read text was absent from all result
representations. Structured content became `{}` and plain text was withheld:

```text
[output withheld by BOGO: not filterable]
call_result: outcome=executed, filtered_fields=1, withheld=1
```

The returned body was not persisted in the audit. All upstream staging goes
through the one manager.call site, and only the exact transport's dispatch
result supplies upstream arguments. Absent arguments are now preserved as
absent, rather than synthesized as `{}`.

## Not checked

The native Simulator app/Face ID and soft-plus-Simulator 2-of-2 flow could not
be driven because the device was in use. Real-device App Attest, APNs delivery,
and the public relay deployment were not tested. No sleep/wake or wall-clock
change was induced. No real logout/login was performed; launchd bootstrap,
KeepAlive restart, stop and plist RunAtLoad were checked. The sandbox and Link
CLI remain separate tickets. The initial audit verification and guards were
performed with real clients; no new implementation-mirroring tests were added.

## Sol review ledger

Round 1: `codex`, `gpt-6.1-sol`, medium effort. Verdict: CHANGES.

- R1 (blocker, fixed): verification accepted a protected forward without its
  threshold. It now checks distinct counted signatures against eligible active
  registrations at the recorded registry sequence, binding votes to the checked
  key registration. The reviewer's public-owner-API regression failed before
  the fix and passes afterward.
- R2 (should, fixed): running log queries failed above the 1 MiB frame limit.
  Results now travel in bounded base64 chunks, including exports. The reviewer's
  real daemon regression with four 300 KB records failed before the fix and
  passes afterward.

Both reviewer tests are retained in `crates/bogo-daemon/tests/review_daemon.rs`.
Default and feature-enabled full workspace tests and Clippy passed after both
fixes. The feature suite also passed on the pre-review final code. A fresh real
shim allow/read and protected write passed, with exactly one forwarding record
and exact approved file content. The strengthened verifier accepted the real
199-entry audit (10 counted approvals, one ignored duplicate, two denials).

Evidence output: `/tmp/bogo-assembly-verification/review-before.out`,
`review-after.out`, `review-real-use.out`, `review-workspace.out`,
`review-default-tests.out`, `review-clippy.out`, `review-default-clippy.out`.
The first rerun of the usage script stopped because its old agent name already
existed; it was rerun with a fresh name and succeeded. No product error was
hidden or check weakened.

Round 2: `codex`, `gpt-6.1-sol`, medium effort. Verdict: APPROVE. R1 and R2
were marked resolved, with no new findings. The reviewer reran the two retained
regressions: 2 passed, 0 failed. No findings declined. Review usage was not
exposed. Nothing was pushed. Before review: 29 files, 2960 insertions, 6 deletions;
after fixes: 30 files, 3218 insertions, 22 deletions (before this final note).

The verification LaunchAgent was stopped and its installed plist removed after
checking its executable and canonical home matched this test. The prepared
plist and private test home remain available; a future login will not start
this temporary verification configuration.
