# Upstream connections, the final gate, and output filtering

## Goal
Build `bogo-upstream` and `bogo-filter` as `docs/ARCHITECTURE.md` §3.7 and §3.8 describe, for `docs/SPEC.md` §3.1, §3.2, §3.4–§3.5 and §3.10: connecting to unmodified upstream MCP servers (local processes and remote URLs), the namespaced combined tool catalog (`<upstream>__<tool>`, always prefixed), adding the justification field to protected tools' schemas, the exact transports that write each `tools/call` byte for byte and only after the `Gate` port says `dispatch`, removing configured secret values from results, restarting upstreams, and per-tool output filtering.

This is where a tool call actually leaves BOGO, so it is where the promise is kept or broken: nothing reaches an upstream unless the core said so at the moment of writing, and what reaches it is exactly what was approved. When this is done, against the real official filesystem MCP server and a small echo upstream: the catalog lists every tool with its original description and schema, prefixed by upstream, following pagination; protected tools carry the justification field and upstreams never receive it; a call is written to the upstream only after `dispatch` returns yes, byte for byte, so `4.7E3` and `-0` arrive exactly as the agent sent them; a refused `dispatch` writes nothing; an upstream that is down fails closed instead of waiting to reconnect; credentials live only in that upstream's environment and never reach results or logs; output filtering strips the configured fields.

The real `Gate` port is provided later by the daemon; here, drive it with a simple stand-in so every path can be exercised.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/` and `docs/ARCHITECTURE.md`. `bogo-json` and `bogo-config` come from the Foundations ticket already merged on `build/bogo`.
- Upstreams the owner chose: the official filesystem MCP server (`@modelcontextprotocol/server-filesystem`) and Stripe's Link CLI (`link-cli --mcp`, test mode). Link needs a one-time login that happens in a later ticket; use the filesystem server and an echo upstream here.
- Running at the same time: the Lean core ticket (the core behind `dispatch`) and the crypto crates ticket. `bogo-upstream` reaches the core only through the `Gate` port.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Upstreams run unmodified.
- Only the exact transports write a `tools/call`; nothing reads rmcp's parsed `arguments`.
- Never touch the Apple Bridge Mac repo. No password prompts; `sudo` only as `sudo -n`.

## Guardrails
- Nothing is written to an upstream without a yes from `dispatch` at the moment of writing.
- Argument bytes reach the upstream exactly as the agent sent them.
- Credentials never appear in results, errors or logs.

## How to verify
1. Connect the real filesystem server and the echo upstream; print the combined catalog and compare each tool's description and schema with what the server itself lists.
2. Send a call with arguments containing `4.7E3`, `-0`, nested keys in odd order, and a justification; the echo upstream shows the exact bytes received, without the justification.
3. Have the stand-in gate refuse; show nothing reaches the upstream. Kill the upstream, then call; it fails closed and the upstream restarts afterward.
4. Configure a secret and an upstream that echoes it; the result shows it removed. Configure an output filter on a field; it is stripped.
5. `cargo clippy --workspace` passes.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
