# The BOGO daemon and the `bogo` command

## Goal
Assemble BOGO into the product the owner runs: `bogo-daemon` and the `bogo` CLI, the rest of `bogo-log`, the launchd user agent, and `bogo-approver-soft` in its feature build, as `docs/ARCHITECTURE.md` §2, §3, §4, §5, §6 and §8 step 9 describe for every part of `docs/SPEC.md` §3 that the daemon and CLI own. That covers setup and config, upstreams, named agents with their tokens and per-agent policy, pause and un-pause, registering approvers, listing and cancelling requests, reading and checking the log, and start/stop at login.

Everything built so far is a piece: the Lean core and `bogo-core`, the MCP front and shim, the upstream manager and filter, the approver hub, the iPhone route and the stand-in. This ticket makes them one daemon, so an agent's protected call really waits for the owner's approval and then runs exactly once on the real upstream. When this is done, the owner can do this from the CLI on this Mac. They set up `~/.bogo`, add the official filesystem MCP server as an upstream, add a named agent and give its token to Claude Code, and register approvers. Then they watch the scenarios in SPEC §4 play out for real:
- an allowed call runs at once;
- a protected call waits until it is approved, then runs exactly once with exactly the approved arguments;
- a denied call and a denial come back in the spec's wording;
- 2-of-2 needs two distinct approvers;
- Pause stops an agent;
- the flood limit rejects quietly;
- a dropped session ends its requests;
- the log verifies, and shows a break if anyone edits it.

Here, approvals come from the soft approver and from the iPhone app in the Simulator through `bogo-standin`'s route code, now in the daemon. Values the spec leaves open (the arm delay, `max_pending`, the relay's message limits) ship unset, and BOGO refuses to start until they are set, as ARCHITECTURE §11 says. Set them in your own test config, never as defaults.

If keeping the core promise and making something work pull against each other, the promise wins: BOGO refuses or fails closed, and you report it.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/`, `docs/ARCHITECTURE.md` and `docs/RELAY-PROTOCOL.md`. Everything listed in ARCHITECTURE §2 except the daemon, the CLI, the rest of the log, the soft approver and the sandbox is merged on `build/bogo`. Each merged ticket left its own verification notes under `docs/verification/` and how to run it.
- Claude Code on this Mac is logged in when run as `claude -p` (not with `--bare`), so it can be the real agent.
- The relay at `bogo.eilmer.si` may not be live yet; if it isn't, run `bogo-relay` locally.
- Running at the same time: the ticket that adds the iPhone app's relay link (in `/Users/johansardar/apple-bridge-iphone`). Don't change the app.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- No password prompts or approval dialogs on this Mac: install only a per-user LaunchAgent, no system launchd items, no Keychain writes, `sudo` only as `sudo -n`.
- Secrets stay in `~/.bogo/secrets.toml` (0600) and never appear in logs, the repo or your report.
- Never touch the Apple Bridge Mac repo, its relay or its gateway.

## Guardrails
- No tool call ever reaches an upstream without the decision the core output for it.
- `allow` is refused as the default policy.
- The audit log stays the only durable authority; a crash at any point loses no record of a call that ran.
- Every merged crate's own checks still pass.

## How to verify
1. From an empty `~/.bogo` (use a temporary home), set up BOGO, add the filesystem upstream on a scratch folder, add a named agent, and start the daemon through the LaunchAgent. Show `bogo` status.
2. Point real Claude Code at it with the agent's token. Show the tools it sees, an allowed read running at once, and a protected `write_file` waiting, then approved with the soft approver and written exactly once with the approved content. Show a changed-argument retry needing a new approval.
3. Deny one call with a note and show the exact text Claude Code receives. Kill Claude Code mid-wait and show the request ended in the log.
4. Show 2-of-2 with the soft approver plus the Simulator app through the relay: one approval is not enough, the same approver twice is not enough, and two distinct approvers run the call.
5. Pause the agent, then un-pause it. Run a flood past `max_pending`, which should be quiet and logged. Revoke an approver. Each behaves as SPEC §4 says.
6. Kill the daemon mid-call and restart it. Nothing runs twice, and the log verifies. Edit one log byte, and `bogo log verify` points at the break.
7. Start with an unset open value, and with `allow` as the default policy: both refused with a clear message.
8. `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
