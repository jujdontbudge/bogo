# Per-action policy for wrapper tools like Link's call_write_tool

## Goal
Let the owner give one upstream tool different policies depending on which action it is asked to do, chosen by the value of one argument. Link's MCP server puts every action behind two wrapper tools, `call_read_tool` and `call_write_tool`, with the real action in the `name` argument (`spend-request_create`, `spend-request_retrieve`, `ucp_catalog_search`, …). In the first real-device test on 2026-11-16, a fresh agent ("pi test") sent catalog searches and status polls through `call_write_tool`, so the owner's phone asked them to approve searches and polls, which they found confusing and noisy. Only actions that spend money or act for the owner should reach the phone.

When this is done, the owner can write, for example:

```toml
[tools.stripe__call_write_tool]
policy = "approve"
select = "name"            # one policy per value of the `name` argument

[tools."stripe__call_write_tool[name=spend-request_retrieve]"]
policy = "allow"

[tools."stripe__call_write_tool[name=ucp_catalog_search]"]
policy = "allow"
```

and a `spend-request_create` still waits for the phone with every protection it has today, while a status poll or search runs at once. Any value with no entry of its own, a missing or non-string selector argument, or a value that doesn't match exactly falls back to the base tool's policy, so the default stays "approve".

The design to use: the daemon derives a policy key `tool[arg=value]` from the call's exact arguments and hands that key to the Lean core as the tool name. The core treats tool names as opaque strings, so its proved promises hold per key and the Lean code doesn't change. The phone, the log and `bogo tools` show the key, so the owner sees which action was approved. If showing it cleanly and keeping the proofs untouched pull against each other, untouched proofs win.

## Context
- Read `/Users/johansardar/.t3/projects/bogo/docs/SPEC.md`, `GLOSSARY.md`, `docs/adr/`, `docs/ARCHITECTURE.md`, `docs/configuration.md`, `docs/proved-and-assumed.md` and `crates/bogo-daemon/src/policy.rs`, `crates/bogo-config/src/lib.rs` and `crates/bogo-front` on `build/bogo`.
- The live BOGO at `~/.bogo` (LaunchAgent `si.eilmer.bogo`, binaries in `~/.local/bin`) is the owner's real install with their iPhone registered. Test with your own temporary BOGO home and port; don't stop or change the live one. Link is logged in under `~/.bogo/upstreams/stripe/`; don't copy that file. Use the filesystem upstream or a small test MCP server to check the selector, and Link only read-only if at all.
- A blank pi agent setup (`~/pi-test`, `PI_CODING_AGENT_DIR=~/pi-test/agent`) exists if you want a real agent client; point a copy of it at your own BOGO home, not the live one.
- Commit on your own branch in your worktree, small commits, each ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- No change to `lean/` or to the signed request encoding. The key is computed in the daemon from the same argument bytes that are signed and forwarded.
- The selector reads one top-level argument by exact name. Matching is exact string equality; no patterns.
- A key never lets an agent pick a looser policy than the owner wrote: the agent controls the argument, so an unknown value must land on the base policy, and the forwarded call must carry exactly the arguments the key was computed from.

## Guardrails
- Every existing config without `select` behaves exactly as before.
- All five proved promises still hold; `lake build` and `#print axioms` are unchanged.

## How to verify
1. With a test upstream, show a selected allow-value running at once, an approve-value waiting for approval, an unknown value and a missing argument falling back to the base policy, and a deny-value refused.
2. Show an approval for one value can't be reused for another (change the value after approval: new request).
3. Show `bogo tools` and the log naming the key.
4. Update `docs/configuration.md` and the Link template in `ARCHITECTURE.md` §9 with a recommended Link setup: searches, status reads and retrieval run at once; anything that creates or approves spending waits for the phone.
5. `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and `lake build` pass.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
