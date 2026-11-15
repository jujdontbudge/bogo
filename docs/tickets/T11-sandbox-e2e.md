# The reference sandbox, the bypass suite, and BOGO end to end on real upstreams

## Goal
Build the reference sandbox and the bypass suite (`sandbox/` and `bogo-bypass`), as `docs/ARCHITECTURE.md` §3.17 and §8 step 11 describe, for `docs/SPEC.md` §3.17 and the threat model. Then connect BOGO to its two real test upstreams: the Stripe Link CLI in test mode (`link-cli --mcp` with `--test`, logged in through the owner's device flow, its auth file under `~/.bogo` as the architecture says) and the official filesystem MCP server.

BOGO's promise holds only for calls that go through BOGO. The sandbox is how the owner makes sure an agent has no other way out. When this is done, an agent such as Claude Code runs inside the Docker sandbox, and its network is default-deny: it can reach BOGO and nothing else, apart from whatever ARCHITECTURE §11 question 1 settles about the model's API host. Every attempt in the bypass suite fails, and the suite reports each attempt it made and how it was stopped. The attempts include reaching an upstream or the internet directly, reading BOGO's secrets or the Link auth file, talking to the relay, and forging, replaying or altering an approval. From inside the sandbox, the agent then plays SPEC §4's scenarios on the real upstreams:
- a Link test-mode payment that waits for approval and runs exactly once with the approved amount;
- a changed amount that needs a new approval;
- a denied payment;
- filesystem reads that run at once, and writes that need approval;
- output filtering, per the scenario ARCHITECTURE §11 question 9 settles.

If the sandbox's isolation and getting a scenario to work pull against each other, isolation wins.

ARCHITECTURE §11 questions 1, 9 and 14 are still open with the owner. Take the architecture's recommended option for each, and say which one you took in your report so the owner can change it.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/`, `docs/ARCHITECTURE.md`, `docs/daemon.md` and `docs/verification/` on `build/bogo`. Everything except the sandbox and the docs is merged there.
- `docker` and `colima` are installed with Homebrew; the colima VM isn't running. `link-cli` is at `~/.local/bin/link-cli`. Chrome is signed in to the owner's Stripe account; drive it with the cua driver for the Link device-flow login. If that login needs the owner's phone (an SMS code or a passkey), stop that part and leave it for the final device session; finish everything else.
- The Mac's disk is nearly full (about 10 GB free). Keep images and the colima disk small, and clean up what you create.
- Claude Code logs in when run as `claude -p` (not `--bare`).
- Running at the same time: the iPhone relay-link ticket in `/Users/johansardar/apple-bridge-iphone`, which may hold the Simulator.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Stripe in test mode only; never a live payment.
- No password prompts on this Mac: no Keychain writes, `sudo` only as `sudo -n`.
- Secrets and the Link auth file never appear in logs, the repo, the sandbox or your report.
- Never touch the Apple Bridge Mac repo, its relay or its gateway.

## Guardrails
- No path from inside the sandbox reaches an upstream except through BOGO.
- Every merged crate's own checks still pass.

## How to verify
1. Start the sandbox. From inside it, show BOGO reachable and every other destination refused.
2. Run the bypass suite and show its full report: every attempt and how it was stopped.
3. Log Link in through the device flow, or report why it waits for the device session. Show `bogo` listing the Link and filesystem upstreams and their tools.
4. From Claude Code inside the sandbox, run each scenario in the Goal, approving with the soft approver. Show what the agent received, what the upstream did (the Stripe test dashboard for Link, the files on disk), and the log entries.
5. Show `bogo log verify` passing after the run.
6. `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
