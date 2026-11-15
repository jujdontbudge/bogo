# The MCP front agents connect to, and the stdio shim

## Goal
Build `bogo-front` and `bogo-shim` as `docs/ARCHITECTURE.md` §3.6 and §3.15 describe, for `docs/SPEC.md` §3.2, §3.3, §3.7 and §3.9: the MCP server agents see (Streamable HTTP via `rmcp`), agent-token authentication, the layer that hands the exact request body to the core, call and session liveness (a disconnect, cancel or client timeout ends the call), BOGO sessions, the per-agent `tools/list`, and the model-readable results ("The owner denied this action." plus any note; "Approval was not received in time; the action was not performed."; pending-and-retry answers); and the stdio shim that forwards bytes to BOGO without ever re-encoding them, one BOGO session per process, holding a liveness stream so a crashed shim ends its session.

This is the only door an agent has into BOGO, so to the agent it must feel like one ordinary MCP server, and it must never let a call through on its own say-so. When this is done, real MCP clients connect: Claude Code over HTTP with an agent token, and a stdio-only client through the shim. A connection without a valid token is refused; each agent sees only its own tool list (denied tools hidden); a call's exact bytes reach the core's input untouched; killing the client or the shim mid-call ends that call and its session; and each kind of outcome comes back in the exact model-readable wording. The core, upstreams and approvers are wired together in a later ticket, so here drive the front against the linked Lean core (`bogo-core`) with a simple stand-in for everything else.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/` and `docs/ARCHITECTURE.md`. Merged on `build/bogo`: `bogo-json`, `bogo-config`, the Lean core and `bogo-core`, `bogo-upstream`, `bogo-filter`, the crypto and relay crates.
- `rmcp` is pinned at `=3.10.0` because BOGO depends on its internals. The current MCP protocol version is stateless; the architecture says how sessions and pending-and-retry work for each protocol version.
- Running at the same time: the approver hub ticket. Keep to the crate boundaries the architecture names (`bogo-front` never depends on upstream internals or approver routes; `bogo-shim` depends on no daemon crate).
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- The shim never rewrites `params`; it reads only envelope fields.
- Never touch the Apple Bridge Mac repo. No password prompts; `sudo` only as `sudo -n`.

## Guardrails
- No call reaches the core's forward path without a valid agent token.
- Argument bytes reach the core exactly as the agent sent them, through both HTTP and the shim.
- Standard MCP clients work with no change beyond their MCP config.

## How to verify
1. Point Claude Code at the front with an agent token and list tools: the agent's own list, denied tools absent, names prefixed by upstream. Try with no token and a wrong token: refused.
2. Through the shim from a stdio client, send a call with `4.7E3` and keys in odd order; show the bytes the core receives are identical to what was sent.
3. Kill the client mid-call, then kill the shim mid-call: each ends its call and session (visible in what the core is told).
4. Drive each outcome from the stand-in (approved result, denied with note, ended without decision, pending-and-retry on a session-capable connection, rejected on a stateless one) and show the exact text the agent receives.
5. `cargo clippy --workspace` passes.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
