# BOGO: Spec

Status: 2026-11-14, written from the grill.

## 1. Goal

AI agents get their power from MCP servers: tools that send email, move files, change infrastructure and spend money. Today, once an agent has a tool, it can call it with any arguments whenever it likes. If it is confused, wrong, or taken over by a prompt injection, nothing stops it.

BOGO sits between the agent and those MCP servers. The owner picks which tools are protected. A protected tool call does not run until the owner approves **that exact call**, on their iPhone, with Face ID. The agent can attach a reason. The phone shows that reason next to the exact action, clearly marked as the agent's own unverified claim.

The promise: for any MCP tool behind BOGO, and for any behavior of the agent (malicious, confused or prompt-injected), no protected call runs unless the owner approved that exact call, with those exact arguments, once, while it was still valid.

It is for one owner running agents on their own Mac. Four things set it apart:

- **It works with any MCP server, unmodified,** in any domain, not just payments.
- **It cannot be talked around.** Enforcement never depends on the agent cooperating or asking.
- **Each approval covers exactly one call.** It is bound to the exact tool and arguments, so any change, reuse or replay fails.
- **The decision logic is proved correct in Lean 4,** and the code that runs is the same Lean code the proof is about.

## 2. Principles

1. **Fail closed.** If anything is missing, invalid, ambiguous, revoked, expired, timed out or broken, the call does not run. The owner can trust silence to mean "nothing happened".
2. **The agent is untrusted.** Every guarantee has to hold no matter what messages the agent sends, in any order, at any rate. Agents are exactly what goes wrong.
3. **Exact, single-use approvals.** An approval covers one call: same upstream, same tool, identical arguments, same justification, same agent, same session. It authorizes at most one execution. Anything looser lets an approval be stretched into something the owner never saw.
4. **The owner sees what they sign.** The phone builds the approval screen from the exact bytes it signs, never from a separate summary. Everything shown as "will execute" comes from the real arguments. That way BOGO can't show one thing and get another approved.
5. **Safe by default.** Newly discovered tools require approval. A forgotten tool should never be open.
6. **Small, proved core.** The part that decides "execute or reject" is small, isolated and proved in Lean 4, and BOGO runs that same proved code. The promise is only as good as the code that keeps it.
7. **Approval routes are modules.** New ways to approve can be added without changing the core or weakening the promise.
8. **The relay is trusted with nothing.** Decisions are signed and request contents are encrypted end to end, so whoever runs or watches the relay can neither forge an approval nor read the arguments.
9. **Leave Apple Bridge alone.** The iPhone approver lives inside the Apple Bridge iPhone app, but BOGO never touches, depends on or reuses any Apple Bridge Mac part: not its gateway, relay, pairing or APNs path. The owner wants the two products fully separate.
10. **Ask before removing.** The owner can add things freely. Taking any feature out needs the owner's approval first, unless it is truly redundant.

## 3. What it does

### 3.1 Upstreams

- The owner can connect any number of upstream MCP servers. Local ones are started as a process; remote ones are reached by URL.
- Upstreams run unmodified.
- Upstream credentials (API keys, tokens and so on) are held and used only by BOGO. The agent never sees them. They live in `~/.bogo/secrets.toml`, readable only by the owner, outside anything the agent can reach. The policy config refers to them by name.

### 3.2 What the agent sees

- To the agent, BOGO is one ordinary MCP server. It offers the combined tool list of every upstream, with each tool's original description and input schema.
- Tool names are namespaced by upstream, as `<upstream>__<tool>` (for example `stripe__create_payment_link`), so two upstreams can never collide.
- Tools with policy **deny** are hidden from the agent by default. The owner can instead show them and have every call rejected.
- BOGO runs as one long-running service on the Mac, reached over HTTP. MCP clients that only speak stdio, such as Claude Desktop or Cursor, use a small stdio shim. Standard MCP clients work with no changes beyond pointing their MCP config at BOGO.

### 3.3 Named agents

- The owner names every agent: `bogo agent add "Trip planner"` creates the agent and gives it its own connection token. That token goes into the agent's MCP config.
- BOGO refuses any connection without a valid agent token. The owner can list and revoke agents.
- BOGO knows the agent name is true, so it is part of what the owner signs. It appears on the phone under "Will execute" as "Requested by Trip planner". Whatever name the MCP client reports for itself (for example "claude-code") is shown only in the unverified section.
- The token only says who is calling. It never authorizes a protected call.
- A session is one MCP connection from an agent to BOGO.

### 3.4 Policy

- Each tool has exactly one policy: **allow** (runs right away), **approve** (needs the owner's approval) or **deny** (never runs).
- Tools not listed explicitly get the default policy. Newly discovered tools default to **approve**.
- Per tool, the owner can set:
  - whether a justification is required,
  - which argument fields the phone highlights, and how to format them (for example, show an integer `amount` as a currency amount in cents),
  - an optional expiry (§3.7),
  - which approvers are eligible, and whether one approval suffices (**any-of**) or at least k distinct approvers must approve (**k-of-n**),
  - output filtering (§3.10),
  - pending-and-retry mode instead of waiting (§3.9).
- **Per-agent overrides:** a tool's policy and approvers can be set differently for each named agent. For example, "Trip planner" may use the payment tool with approval, while "Researcher" is denied it entirely. Otherwise the tool's own policy applies.
- All policy lives in one human-readable file, `~/.bogo/bogo.toml`, that the owner edits by hand. Changes take effect on restart; live reload is welcome but optional.

### 3.5 Justification

- For every tool with policy approve, BOGO adds an optional justification field to the tool's input. It holds free text explaining why, plus any context, for example "booking the 6pm flight you asked for, $47".
- BOGO removes the field before forwarding. Upstreams never see it.
- If a tool requires a justification and none is given, the call is rejected with a message telling the agent to include one.
- The justification is part of what the owner signs. A retry with a different reason is a new request, because the owner approved what they were shown.
- The phone labels the justification as the agent's unverified claim. The amount, recipient and every other "will execute" value come only from the real arguments.
- **Mismatch warning:** if the justification mentions an amount of money ("$47", "47 USD", "47 dollars") that doesn't equal any field shown as currency, the phone shows a visible warning, such as "Reason says $5, but this will charge $500.00". Other numbers, like "6pm" or a flight number, are ignored so the warning doesn't cry wolf. The phone works this out from the signed bytes. The rule is deliberately simple; it is a warning, not a guarantee. A justification with no amount gets no warning, and the real values are still shown under "Will execute".

### 3.6 Approval requests

Each approval request carries:
- the upstream and tool name,
- the complete, exact arguments,
- the agent's justification, if any,
- the display hints: which fields to highlight and how to format them,
- the agent name, plus the client's self-reported name,
- an identifier for the session,
- a unique one-time nonce,
- the creation time, plus the expiry time if the tool has one.

The bytes the phone signs are a deterministic, unambiguous encoding of the request. The same request always encodes the same way, and two different requests never encode the same way. Numbers keep their exact text, so `4700`, `4700.0` and `4.7e3` are never treated as the same value.

### 3.7 When a request ends

- By default a request has no preset expiry. It ends when:
  - it is approved or denied,
  - the owner cancels it,
  - or the agent's call or session ends (a disconnect, a cancel, or the client giving up on a long call).
- Once a request has ended, a late approval is rejected. It can never run afterward.
- If the tool has an expiry set, the request also ends when that time passes.
- If the phone is offline, the request just waits. Delivery keeps being retried until the request ends for one of the reasons above. Nothing fails just because the phone is out of reach.

### 3.8 Approvals

Every protected call that BOGO forwards upstream meets all five:
1. **Approved:** the tool's requirement (any-of or k-of-n) is met. Each counted approval comes from a distinct approver that is still registered, after that approver's user verification (Face ID).
2. **Exact:** each approval covers exactly this call. Approving one call never approves any other.
3. **Single-use:** each approval authorizes at most one execution. Reusing or replaying it fails.
4. **Fresh:** the approval belongs to a session that is still alive, and its expiry, if set, has not passed.
5. **Fail-closed:** if anything is missing, invalid, ambiguous, expired, timed out, revoked or broken, the call does not run.

On top of that:
- Approvals belong to the session that asked. Another session sending the identical call cannot use them.
- Each request goes to all eligible approvers. Once the requirement is met, the request is settled and later responses are ignored.
- For k-of-n, any single denial denies the request by default; the owner can change that per tool.
- The same approver approving twice counts once.
- The owner approves or denies a call **as it is**. There is no editing the call before approving it. A denial can include a short note back to the agent.

### 3.8.1 Approval fatigue

A confused or prompt-injected agent could flood the owner's phone until they approve by reflex, which is how push-approval systems are most often beaten. BOGO resists that:
- **Duplicates are grouped:** identical pending requests show as one entry with a count.
- **Pause an agent:** one tap in the app pauses an agent. That also denies its pending requests, and every new request from that agent is rejected until the owner un-pauses it on the Mac.
- **Flood limit:** if one agent has too many pending requests at once, its new ones are rejected without notifying the owner and are logged. The limit is set in `bogo.toml`.
- **No reflex taps:** Approve becomes tappable only after a short delay once the review screen opens.

### 3.9 What the agent gets back

- By default a protected call **waits** until it is approved, denied or ended.
- The agent gets a clear, model-readable outcome:
  - approved → the upstream tool's real result,
  - denied → "The owner denied this action." plus the owner's note, if any,
  - ended without a decision → "Approval was not received in time; the action was not performed."
- **Pending-and-retry mode** (per tool, off by default): BOGO answers "pending approval" right away. The agent retries the identical call in the same session, and the retry runs only once it has been approved.

### 3.10 Output filtering

Per tool, the owner can strip or redact fields from upstream results before the agent sees them (for example sharing links, download URLs or tokens). That way an approved call can't hand the agent a way around BOGO.

### 3.11 Audit log

- BOGO logs every protected call attempt:
  - what was requested,
  - the decision (approved, denied, ended or rejected) and why,
  - timestamps,
  - which approvers responded,
  - the signed approvals.
- The log is append-only. Each entry carries the hash of the previous one, so a missing or altered entry shows.
- `bogo log verify` checks the chain, and checks that every approval was signed by an approver registered at the time.
- The owner can view, search and export the log.
- Argument values appear in the log, since they are the point of the record. Upstream credentials never do.

### 3.12 Owner commands

From the `bogo` command, the owner can:
- set up a new BOGO,
- start and stop BOGO,
- register, list, revoke and re-register approvers,
- add, list and revoke named agents,
- list every discovered tool with its current policy,
- view the log and verify its approvals.

### 3.13 Approvers

An approver is a route that shows the owner an approval request and returns a signed decision. BOGO treats approvers as interchangeable modules behind one interface.

Every approver:
- holds a private approval key that can't be exported and can only be used after a user-verification step,
- is registered with BOGO in a way BOGO trusts,
- renders each request from the exact bytes it signs,
- shows the two-part approval screen (§3.15),
- returns either a signed approval over those exact bytes or a denial,
- can be revoked on its own.

The owner can register several approvers, each with a name and type (for example "Johan iPhone"). With several approvers in any-of mode, the setup is only as strong as the weakest one.

### 3.14 The iPhone approver

The first approver is a **BOGO section inside the existing Apple Bridge iPhone app**. It is not a separate app.

- **It replaces the app's old Approvals feature entirely.** The Approvals tab becomes the BOGO tab.
  - Apple Bridge approval jobs that still arrive from the Mac are ignored, so they expire there. Nothing on the Mac side of Apple Bridge changes.
  - Capture (photo and audio), which relied on the old feature, now always comes back denied.
- It is isolated from the rest of the app: its own keys, its own screens and storage, and its own relay connection and push handling. It touches the host app only through a narrow edge: receive a request, show it, return a decision. It shares only the app's push token. The narrow edge is there so the section can be reused in other apps later.
- It works on a phone that was never paired with the Apple Bridge Mac gateway.
- The BOGO tab has:
  - **Inbox:** pending requests. Ended ones are greyed out and can't be approved.
  - **History:** past decisions.
  - **Macs:** registered BOGO setups, **Add Mac**, and remove.
- A new request arrives as a time-sensitive notification. The notification offers **Deny** only. Tapping it opens the full review screen, which is the only place **Approve** exists, because a banner can't show every argument.
- Every approval needs Face ID. The approval key lives in the Secure Enclave and works only after Face ID. If Face ID enrollment changes, the key stops working and the phone must be registered again.

**Registration (Add Mac)** uses numeric comparison, like pairing a Bluetooth device. There is no QR code to scan and nothing to type:
1. On the Mac, the owner runs `bogo approver add "Johan iPhone"`.
2. On the phone, the owner opens BOGO → Macs → **Add Mac**.
3. Both screens show the same 6 digits.
4. The owner confirms on the Mac, then confirms on the phone with Face ID. That creates the phone's approval key.

During registration the phone also proves, through Apple's App Attest, that it is the genuine, unmodified app on a real iPhone. BOGO refuses registration without that proof, so "the approval key is a Face ID–locked Secure Enclave key" is something BOGO checks, not just something it hopes.

### 3.15 The approval screen

The screen has two sections that look clearly different:
1. **"Will execute (exact)"**: the upstream, tool and every argument, rendered from the exact bytes being approved. It also shows who requested it ("Requested by Trip planner"). Highlighted fields use the tool's display formats. If the tool has an expiry, a countdown shows.
2. **"Agent's reason (unverified)"**: the justification, the client's self-reported name and a session tag, plus any mismatch warning.

The actions are **Approve** (needs Face ID) and **Deny** (with an optional note).

### 3.16 The relay

- BOGO has its **own relay** at `bogo.eilmer.si`.
- It runs on the same VPS as Apple Bridge's relay, but as a separate service, completely unconnected: its own port, its own service and its own state.
- It lets the phone reach BOGO from anywhere, cellular included, without hosting BOGO in the cloud.
- It only passes messages along. Request contents are encrypted end to end between BOGO and the phone, and decisions are signed, so the relay sees only ciphertext and timing.
- BOGO on the Mac sends the push notifications itself, with the owner's existing APNs key. The relay holds no secrets.

### 3.17 The sandbox

The promise holds only if the agent can't go around BOGO. BOGO comes with:
- **a reference setup:** the agent runs in a Docker container with no network access except to BOGO, and no upstream credentials inside,
- **a bypass test suite:** run from inside that container, it tries to reach upstreams directly, find credentials, or call protected tools without approval. Every attempt must fail.

BOGO does not gate tools that don't go through MCP, such as an agent harness's built-in shell. The sandbox is what covers those.

### 3.18 Proof

- The decision logic is a small, isolated component with a precise specification. Given the policy, the request, the approvals, the registered approvers and the current state, it says execute or reject.
- The core promise (§3.8: approved, exact, single-use, fresh, fail-closed) is proved in Lean 4. The proof uses a model in which the agent is fully adversarial and may send any message at any time. It covers any set of registered approvers, any-of and k-of-n requirements, revocation, per-agent policy and session binding.
- The request encoding is defined in Lean, and it is proved that different requests never encode the same.
- Cryptography and the assumptions below are axioms, each one listed.
- **The decision logic and the encoding that run inside BOGO are the same Lean code the proof is about.**
- The docs include a section "What is proved / What is assumed".

### 3.19 Threat model

**BOGO defends against:**
- an agent calling protected tools without approval, directly or through any sequence of messages,
- an agent changing arguments after approval, or reusing, replaying or combining old approvals,
- an agent lying in its justification (exact arguments come from the signed bytes, plus the mismatch warning),
- an agent using another session's approval, or pretending to be a different named agent,
- prompt injection that makes the agent try harmful actions,
- tampering with or watching traffic between BOGO, the relay and the phone (approvals stay unforgeable and exact; contents stay private),
- BOGO showing the phone a misleading display (the phone renders only from the bytes it signs),
- a revoked approver trying to approve,
- an agent flooding the owner with requests until one is approved by reflex,
- a modified app registering an ordinary, unprotected key in place of a Secure Enclave key,
- a lost or stolen locked phone (approval needs Face ID).

**Out of scope, stated as assumptions:**
- a compromised Mac running BOGO,
- a compromised phone OS, or broken biometrics or secure hardware,
- bugs or access-control failures inside upstream providers,
- the owner approving something harmful that was shown accurately.

**Assumptions:**
1. The signature scheme used for approvals can't be forged.
2. The hash function used is collision-resistant.
3. Each registered approver's key can only be used after its user verification.
4. The agent's environment has no route to upstreams or their credentials except through BOGO.
5. Upstream providers correctly reject requests that lack valid credentials.

### 3.20 Docs

- a README with a quick start,
- a configuration reference,
- the threat model and assumptions,
- the "What is proved / What is assumed" section.

## 4. Scenarios

**1. A payment, approved.** "Trip planner" is connected to BOGO, and Stripe (test mode, through Link) is one of the upstreams. The agent calls the Stripe tool to pay $47, with the justification "booking the 6pm flight you asked for, $47". BOGO holds the call and the owner's iPhone buzzes. The notification offers only Deny, so the owner taps it and the review screen opens:
- Under **Will execute**: Stripe, the tool, `amount` shown as $47.00, and "Requested by Trip planner".
- Under **Agent's reason (unverified)**: the flight sentence.

The owner taps Approve and Face ID confirms. The call runs exactly as approved, and the agent gets Stripe's real result. The log records the request, the reason the owner saw and the signed approval.

**2. A lie in the reason.** The agent's justification says "$5", but `amount` is 50000 cents. The phone shows $500.00 under Will execute and a clear mismatch warning beside the reason. The owner taps Deny and adds the note "wrong amount". The agent gets "The owner denied this action. wrong amount". Nothing reaches Stripe.

**3. Changing the call after approval.** The owner approves a call with `amount` 4700. The agent then sends the same call with `amount` 4701, or with a different justification, or from another session, or tries to reuse the first approval a second time. Each one is rejected. Only the exact approved call ever runs, and only once.

**4. Allowed tools just run.** Reading a file from the filesystem upstream has policy allow. It runs right away, with no notification.

**5. Denied tools don't exist.** "Researcher" has the payment tool set to deny. The tool doesn't appear in its tool list, and if it calls it anyway, the call is rejected and never reaches the upstream.

**6. No answer.** The owner never responds. The agent's MCP client gives up on the call, so its session's request ends. When the owner taps Approve later, the phone shows it as ended and BOGO refuses it, and nothing runs. On a tool with a 10-minute expiry, the same happens when the countdown runs out.

**7. Phone offline.** The phone is in airplane mode when a request arrives. The request waits. When the phone reconnects, the request appears in the Inbox and the owner can still decide it, as long as the session is alive.

**8. Adding the phone.** The owner runs `bogo approver add "Johan iPhone"` on the Mac and taps Add Mac in the BOGO tab. Both show 382 917. The owner confirms on both, with Face ID on the phone. The phone now appears in `bogo approver list`.

**9. Adding an agent.** The owner runs `bogo agent add "Trip planner"` and pastes the printed token into Claude Code's MCP config. From then on, requests from that agent say "Requested by Trip planner". A connection without the token is refused.

**10. A stolen phone.** Someone takes the locked phone. They can see pending requests in the Inbox, but they can't approve anything without Face ID. The owner runs `bogo approver revoke "Johan iPhone"`, and any later approval from that phone is rejected.

**11. Face ID changed.** The owner adds a new face in iOS Settings. The phone's BOGO key stops working, and the BOGO tab asks the owner to add the Mac again.

**12. Two approvers.** A tool requires 2-of-2. One approval alone doesn't run it, and the same approver approving twice still counts once. When the second, distinct approver approves, it runs. If either one denies, it is denied.

**13. Output filtering.** The filesystem tool that shares a file returns a public sharing link. The owner has filtered that field, so the agent gets the result without the link.

**14. The agent tries to escape.** Inside the sandbox, the agent tries to reach Stripe's API directly, look for keys on disk, or connect to the relay. All of it fails. The only thing it can reach is BOGO.

**15. Checking the record.** Afterward, the owner runs `bogo log verify`. Every scenario above appears in the log with its decision and reason, the chain is unbroken, and every approval checks out against a registered approver.

**16. A flood.** A prompt-injected agent starts sending the same payment request over and over. The phone shows one entry with a growing count. Once that agent hits its pending limit, new requests are rejected quietly and logged. The owner taps **Pause agent**, and everything from that agent is refused until they un-pause it on the Mac.

**17. Two upstreams at once.** Stripe (payments) and the filesystem server (non-commerce) are both connected, each with its own policies, and they behave independently.

## 5. Names

The words are defined in [GLOSSARY.md](../GLOSSARY.md): **Owner**, **Agent**, **Agent name**, **BOGO**, **Upstream**, **Approver**, **Relay**, **Registration**, **Session**, **Tool call**, **Policy**, **Protected tool**, **Justification**, **Approval request**, **Approval**, **Denial** and **Rejection**.

Note the difference between the last two. A **denial** is the owner saying no. A **rejection** is BOGO refusing a call for any reason, including a denial. The product is always "BOGO", never "Gate".

## 6. Stack

- **Rust** for BOGO and its relay, using the `rmcp` MCP SDK. It's the same stack the owner already uses, and Rust can call the C that Lean compiles to.
- **Lean 4** for the decision logic, the request encoding and their proofs. That compiled Lean code is what runs inside BOGO.
- **Swift / iOS**, inside the existing **apple-bridge-iphone** app (`/Users/johansardar/apple-bridge-iphone`), for the iPhone approver: Secure Enclave keys with Face ID.
- **macOS** for BOGO in this version.
- **The VPS that hosts Apple Bridge's relay** also hosts BOGO's relay, at **`bogo.eilmer.si`**, on its own port and service. DNS for `eilmer.si` is on Cloudflare.
- **APNs** with the owner's existing key, sent from the Mac.
- **Docker** for the reference sandbox.
- **TOML** for `~/.bogo/bogo.toml` (policy) and `~/.bogo/secrets.toml` (credentials, readable only by the owner).
- **Upstreams used to prove it:**
  - **Stripe in test mode through Link**, via Stripe's Link CLI MCP server (`link-cli --mcp`) logged in with `--test`. Test credentials use a test card, so no real money moves.
  - The official **filesystem** MCP server, as the non-commerce upstream.

## 7. Drafted

Drafted: this shows intent. The architecture decides.

**Commands**

```
bogo init
bogo start | stop
bogo approver add "<name>" | list | revoke <name>
bogo agent add "<name>" | list | revoke <name> | pause <name> | unpause <name>
bogo tools
bogo log [search] | export | verify
```

**Config sketch**

```toml
[upstreams.stripe]
command = "link-cli"
args = ["--mcp"]

[upstreams.files]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/johansardar/bogo-test"]

[defaults]
policy = "approve"
hide_denied = true

[tools."stripe__create_payment_link"]
policy = "approve"
justification = "required"
highlight = { amount = "usd_cents", currency = "text" }
approvers = ["Johan iPhone"]
require = "any"          # or { k = 2 }
expiry = "10m"           # optional; none by default
mode = "wait"            # or "pending_retry"
filter_output = ["url"]

[agents."Researcher".tools."stripe__create_payment_link"]
policy = "deny"
```

**Signed encoding.** BOGO's own tagged, length-prefixed binary format, defined in Lean (ADR 0001):
- JSON arguments become a tree with object keys sorted.
- Numbers keep their exact decimal text and are never turned into floats.
- The Swift and Rust code is checked against test vectors made by the Lean encoder.

**Flow**

```
Agent (Docker sandbox) ──MCP/HTTP + agent token──▶ BOGO (Mac) ──▶ Upstreams (Stripe/Link, filesystem…)
                                                    │  ▲
                                   APNs push ◀──────┘  │ encrypted request / signed decision
                                                       │
                                  iPhone BOGO tab ◀──▶ Relay (bogo.eilmer.si, VPS)
```

**Registration.** Both sides take part in a key exchange through the relay, and both show a 6-digit code derived from it. Confirming the code on both ends defeats a man in the middle. The phone's Secure Enclave key (P-256, usable only with Face ID and tied to the current enrollment) is created when the owner confirms with Face ID. The keys for end-to-end encryption are exchanged in the same step.

**Relay TLS.** A normal public certificate for `bogo.eilmer.si`, from Let's Encrypt via a Cloudflare DNS token scoped to `eilmer.si`. The port is separate from Apple Bridge's relay, which holds 443 on that VPS, so it needs its own firewall rule.

**Test-only approver.** Automated 2-of-2 tests use a software approver that only exists in the test setup and can't be registered in a normal BOGO.

**Payment test setup.** Stripe's Link CLI is open to US and Canadian Link accounts. Its login is a one-time device flow (a verification URL and a short phrase), done by the owner, or by Claude in Chrome on the owner's say-so. The Link session then lives only on BOGO's side.

## 8. Not doing

- **A local web dashboard.** The owner cut it; policy is edited in `bogo.toml` and inspected with the `bogo` commands.
- **A hosted or cloud BOGO.** It runs on the owner's Mac. The relay only carries messages.
- **Judging whether an action is wise.** BOGO guarantees the owner decided; it doesn't decide for them.
- **Gating tools outside MCP** (for example a built-in shell). The sandbox covers those.
- **Editing a call before approving it.** It would mean signing a call the agent never made, and it would complicate the proof. Approve or deny as-is; a denial can carry a note.
- **Time-window grants** ("allow this exact call for 10 minutes"). They break single-use. Left out on purpose.
- **Approving from the notification banner.** It can't show every argument. The banner offers only Deny.
- **Using Apple Bridge's gateway, relay, pairing or APNs path,** or changing anything in the Apple Bridge Mac repository.
- **The old Approvals feature in the iPhone app.** It's replaced entirely by the BOGO section.
- **QR-code registration.** The owner finds it less clean than matching 6 digits.
- **Mac Touch ID approver.** Skipped for now.
- **Browser passkey, hardware security key and second-person approvers.** The design allows them; they're not built now.
- **Android approver.**
- **Kraken, EVM wallets, Lightning (Alby) and Stripe's regular MCP server** were considered as payment upstreams. The owner chose Stripe test mode through Link instead.
- **The Keychain for upstream credentials.** The owner's machine rules forbid Keychain writes that can prompt, so a file readable only by the owner is used instead.

## 9. Open questions

- **The PRD's speed and setup goals.** The original requirements said: negligible overhead on allowed calls, notifications arriving within a few seconds, and setup with one upstream and one approver in under 10 minutes. None of these were reconfirmed as hard goals, so they aren't goals yet.
- **A second real device.** Is there a second iPhone or iPad for checking 2-of-2 on real hardware? Until then, 2-of-2 is shown with the test-only approver.
- **Which Stripe Link tools are protected.** The Link wallet has its own approval steps for spend requests. Should BOGO protect every Link tool, or only the ones that create spend requests or credentials?

## 10. Notes from the grill

- The product name is **BOGO**. "Gate" was only the PRD's working name.
- The owner wants every milestone of the original PRD built now (v1, v2 and v3), except the Mac Touch ID approver. Work on the iPhone section comes first, built against a stand-in for BOGO, with the Mac side after.
- The owner said Claude can use Chrome (through the cua driver) to get anything needed, such as a Link test login or a Cloudflare token.
- In the original PRD, an approval always expired. The owner wanted no preset expiry, so requests are tied to the session instead (ADR 0002).
- BOGO's relay is deliberately its own service, unconnected to Apple Bridge's, even though they share a VPS (ADR 0003).
- The old phone approvals used a Keychain key that was usable after first unlock, with Face ID only as a screen check. That is part of why it was replaced: BOGO's key itself requires Face ID.
- Possible later approver routes: a Mac passkey or Touch ID, a hardware security key, and a second person's phone for k-of-n.
- The approval-fatigue defenses and App Attest came from comparing BOGO with how top systems do this: passkeys, bank payment rules ("dynamic linking"), hardware wallets ("clear signing"), number matching in MFA apps, multisig wallets, and the 2022 Uber push-flood breach.
- Tailscale was considered as the way for the phone to reach BOGO, and dropped in favor of BOGO's own relay.
