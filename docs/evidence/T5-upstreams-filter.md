# T5 implementation evidence

Branch: `t3/upstream-gate-filter`. Implementation head before Sol review: `f21aa0d`.

The executable client uses the library API as the future daemon will: a single-use
stand-in Gate returns exact JVal arguments, the manager performs upstream I/O,
then the shell applies the independent pure bogo-filter before displaying results.
The echo fixture receives real stdio/HTTP messages, captures actual call bytes,
and deliberately returns its synthetic credential in text, structured content,
resource URIs, embedded resources, result metadata and stderr.

Commands:

```sh
npm install --prefix /tmp/bogo-upstream-fs --no-audit --no-fund @modelcontextprotocol/server-filesystem@2.3.0
cargo clippy --workspace --all-targets
cargo test --workspace
BOGO_FS_SERVER=/tmp/bogo-upstream-fs/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js cargo run -p bogo-upstream --example verify
```

Clippy passed with no warnings. The full workspace suite passed: the three existing
Foundations regression/vector tests and all unit/doc targets. No CI exists here;
the full suite was run locally. No new tests were added by the implementation;
the verification program is the explicitly requested client/stand-in exercise.

Client output:

```text
CATALOG: 16 filesystem tools match direct tools/list descriptions and schemas; 2 stdio + 2 HTTP echo tools (pagination followed).
echo__echo
echo__extra
fs__append_file
fs__copy_file
fs__create_directory
fs__directory_tree
fs__edit_file
fs__get_file_info
fs__list_allowed_directories
fs__list_directory
fs__list_directory_with_sizes
fs__move_file
fs__read_file
fs__read_media_file
fs__read_multiple_files
fs__read_text_file
fs__search_files
fs__write_file
remote__echo
remote__extra
SCHEMAS: protected tools have optional justification; catalog persisted and reloaded.
echo EXACT: {"b":-0,"z":{"a":4.7E3,"q":-0}}; justification and marker absent on wire.
echo RESULT: credential="[credential removed by BOGO]", base64="[credential removed by BOGO]", stripped fields=10, withheld blocks=3
echo REFUSAL + REPLAY: dispatch refused; captured call count unchanged at 1.
remote EXACT: {"b":-0,"z":{"a":4.7E3,"q":-0}}; justification and marker absent on wire.
remote RESULT: credential="[credential removed by BOGO]", base64="[credential removed by BOGO]", stripped fields=10, withheld blocks=3
remote REFUSAL + REPLAY: dispatch refused; captured call count unchanged at 1.
FILESYSTEM CALL: list_allowed_directories returned the configured root.
KILLED CHILD: upstream unavailable: not_sent; captured call count unchanged at 1; catalog retained.
RESTART: new child connected, rediscovered, and accepted a fresh gated call.
MISSING MARKER: internal_send_refused; zero writes.
REDACT: dotted array wildcard replaced both selected values.
PASS: all requested client verification steps completed.
```

The input's deliberately odd key order is canonicalized by the approved writer,
as required by ARCHITECTURE §3.2 / ADR 0001. `4.7E3` and `-0` retain their original
spellings; the assertion compares the echo's received arguments with the exact
core output, and inspects the wire capture for absent justification and marker.

Each transport's refused and replayed call leaves its actual capture count at one.
The killed child is observed through its connection EOF before the down call;
that call is `not_sent`, retains the catalog, and never waits for reconnect. The
restart is then observed through health/catalog updates, with a different PID and
a successful fresh call. No earlier call is replayed.

Credential and base64 scans of both stdout and stderr passed without printing the
configured value. Representative scrubbed log output:

```text
2026-11-15T08:47:12.598382Z DEBUG bogo_upstream::child: upstream stderr stderr=[credential removed by BOGO] [credential removed by BOGO]
2026-11-15T08:47:12.747087Z DEBUG bogo_upstream::child: upstream stderr stderr=[credential removed by BOGO] [credential removed by BOGO]
2026-11-15T08:47:12.749427Z ERROR bogo_upstream::wire: internal_send_refused
```

The fixture also asserts the initialized client capabilities are empty; the
filesystem call verifies command-line roots are retained. A direct call without
the private marker is refused before writing. Filters remove fields in the text,
structured, embedded-resource and metadata representations, withhold unfilterable
prose/URI strings, and redact dotted array-wildcard selections.

Not checked in this manual run: Stripe Link login; real Lean Gate/daemon and durable
audit effects (separate tickets); a live external HTTPS service; HTTP SSE,
redirect/session-expiry fault injection; interactive upstream input; notifications
changing the catalog; exhaustive JSON Schema combinations. The code implements
these paths, but this transcript makes no claim of exercising them.

Known conservative choices: output schemas are omitted for all filtered tools;
unsupported pattern regexes or no available name among 4096 justification candidates
make a tool unexposable. Secret scrubbing detects exact configured values and
base64, not arbitrary transformations. See the crate README for daemon wiring.

Sol review ledger:

- Round 1, GPT-6.1 Sol, medium effort: CHANGES. S1 (should) found that stripping
  resource URI fields made the filtered result fail MCP deserialization.
- Applied Sol's single regression test and reproduced its failure on the reviewed
  implementation: `missing field uri`. The same targeted test now passes.
- Fixed S1 with 18 product lines: a resource link or embedded resource whose
  required fields were stripped becomes a valid withheld text block. Nothing from
  the invalid resource is exposed. Kept Sol's 28-line regression test.
- After the fix, `cargo clippy --workspace --all-targets -- -D warnings`, the full
  `cargo test --workspace` suite (now four tests), and the real verification client
  all passed. No findings declined. Usage was not exposed. Nothing pushed.
- Round 2: pending; restricted to S1 and the changed behavior.

Review diff (Cargo manifests/lock and the two crates): 3918 additions / 82 deletions
before S1, 3964 additions / 82 deletions after S1. Most lines are Cargo.lock.

