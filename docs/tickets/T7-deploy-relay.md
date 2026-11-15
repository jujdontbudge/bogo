# Deploy BOGO's relay at bogo.eilmer.si

## Goal
Put BOGO's own relay (`bogo-relay`, already built and merged on `build/bogo`) live at `bogo.eilmer.si`, so the owner's phone can reach BOGO from anywhere, cellular included, without BOGO being hosted in the cloud. It runs on the same VPS that hosts Apple Bridge's relay but as a completely separate service: its own port, systemd unit, system user, state directory and certificate, as `docs/ARCHITECTURE.md` §3.12 and §7 (`deploy/relay/`) describe and `docs/SPEC.md` §3.16 defines.

When this is done: `bogo.eilmer.si` resolves to the VPS through a DNS-only Cloudflare record; the relay answers over TLS on its own port with a valid Let's Encrypt certificate for that name (issued with a Cloudflare token scoped only to the `eilmer.si` zone's DNS), with renewal set up; a firewall rule opens only that port; the service restarts on failure and is enabled to start at boot (never reboot the VM to prove it: a reboot would restart Apple Bridge's relay); and two clients on this Mac exchange sealed messages through the live relay over the internet. Apple Bridge's relay keeps working exactly as before, untouched. If deploying BOGO's relay and leaving Apple Bridge's relay untouched ever pull against each other, Apple Bridge's relay wins and you stop and report.

## Context
- The VPS is the Google Cloud VM `ab-relay` (zone `us-central1-a`, project `excerlock`, external IP 136.65.0.235). `gcloud` on this Mac is signed in to the owner's account with project `excerlock`; use `gcloud compute ssh` and `gcloud compute firewall-rules`.
- Apple Bridge's relay (`ab-relay.service`) holds port 443 on that VM. Ports 80 and 8443 were closed from outside when last checked. The owner left the port choice open; 8443 was the proposal. Pick a free port, and record which one you used in `deploy/relay/` and your report.
- DNS for `eilmer.si` is on Cloudflare. Chrome on this Mac is signed in for the owner (Google, and "sign in with Google" works for other sites); drive it with the cua driver to create the scoped Cloudflare API token and the A record. Never print the token in logs, the repo or your report; store it on the VM readable only by the relay's renewal job.
- The owner's standing approval covers this deployment. Commit `deploy/relay/` changes on your own branch in your worktree, each commit ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Constraints
- Never modify, restart, reconfigure or reuse anything belonging to Apple Bridge on that VM or anywhere else: not `ab-relay.service`, its config, state, certificates, DNS zones (`ab.lexaai.tech`, `applebridge.eilmer.si`) or firewall rules. Never touch the Apple Bridge Mac repo.
- Don't change other Cloudflare records or zones.
- No password prompts on this Mac; `sudo` on the VM is fine.

## Guardrails
- Apple Bridge's relay serves exactly as before: same port, same certificate, same responses.
- Only the one new port is opened.
- The Cloudflare token can only edit DNS for `eilmer.si`, and appears nowhere outside the VM's protected file.

## How to verify
1. Before changing anything, record Apple Bridge's relay state: `systemctl status ab-relay`, the certificate it serves on 443 (`openssl s_client -connect 136.65.0.235:443 -servername ab.lexaai.tech`), and the firewall rules list.
2. `dig +short bogo.eilmer.si` returns 136.65.0.235; the record is DNS-only.
3. From this Mac, `openssl s_client -connect bogo.eilmer.si:<port> -servername bogo.eilmer.si` shows a valid Let's Encrypt certificate for `bogo.eilmer.si`; a dry-run renewal succeeds.
4. Two clients on this Mac, using `bogo-relay-proto` and `bogo-e2e`, exchange sealed messages through the live relay both ways; one held message survives `sudo systemctl restart bogo-relay`; `systemctl is-enabled bogo-relay` says enabled. Do not reboot the VM.
5. Repeat step 1's checks: identical. List the firewall rules: only the new port was added.
6. Show the token's permissions in Cloudflare (DNS edit, `eilmer.si` only) and that its file on the VM is mode 0600 owned by the renewal user.

## Evidence of done
When you are done, use it yourself the way a user would: run the real app and go through it like they do. If it has no user, use it the way its real client would, such as a program calling the API or an agent calling the tool. Check that it works, that it does everything this ticket asks, and that you hit no other problems. Go through every step in How to verify and check every guardrail. Follow the `agent-testing` skill for all testing. If you changed code, run the `sol-loop` skill on it and give Sol this ticket. In your report, show what you saw at each step: screenshots, a video, or the output. Then list anything you did not check.
