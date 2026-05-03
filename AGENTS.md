# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag

## Before Writing Code

For any task touching more than 3 files or requiring more than a few steps:
1. File a Beads epic and break it into issues
2. Write a plan and get user approval before touching code
3. Work through issues one at a time, using parallel subagents within each issue

**Spike issues must land before implementation.** The IPFS client library selection (`iroh` vs `rust-ipfs` vs raw `libp2p`) must be resolved in a dedicated spike issue before any dependent implementation issues are started. `ed25519-dalek` is the fixed signing library — no spike needed.

## Planned Crate Boundaries

| Crate | What belongs here |
|---|---|
| `core` | Article types, CID scheme, Message-ID↔CID mapping, group log (Merkle-CRDT), signing, canonical serialization, error types |
| `transit` | Peering config, store-and-forward, pinning policy, GC semantics, metrics, operator CLI |
| `reader` | RFC 3977 NNTP protocol layer, article number synthesis, overview index, POST path |

**No SQL outside store modules. No NNTP parsing outside `reader`. Transit protocol is IHAVE/TAKETHIS over TCP peering sessions — gossipsub was removed in commit bcd4026.**

## Architectural Non-Negotiables

Before implementing anything, verify it does not violate these:

- Reader speaks RFC 3977 plus standard IANA-registered extensions — `HDR`, `LIST OVERVIEW.FMT`, `MODE STREAM`/`CHECK`/`TAKETHIS` are in scope. **Permitted additive extensions** (per ADR-0007): `X-Stoa-*` article headers and `X`-prefixed CID/integrity commands (`XCID`, `XVERIFY`, `XGET`), advertised in `CAPABILITIES` so standard clients degrade gracefully. **Prohibited**: anything that exposes peer topology, DHT state, pin status, or IPFS infrastructure to clients.
- v1 is text-only — no binary groups, no yEnc, no NZB
- Article numbers are local and synthetic per `(group, reader_server)` — never network-stable
- No moderation in v1 — no curation feeds, no cancel messages, no NoCeM

If an issue description, PR, or design conflicts with any of these, stop and flag it to the user before proceeding.

## Issue Tagging

Every issue must carry one or more of these tags:
`core`, `transit`, `reader`, `protocol`, `ipfs`, `libp2p`, `identity`, `ops`, `interop`, `security`, `spike`, `doc`, `deferred`

## Priority Guide

| Priority | What it covers |
|---|---|
| P0 | Core crate, reader protocol minimum-viable path |
| P1 | Transit daemon, IHAVE/TAKETHIS peering |
| P2 | Import/archival/packaging/observability |
| P3 | Deferred (binary groups, Filecoin deal impl) |

## Quality Gate (run before every commit)

```bash
cargo fmt --all
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace
```

All three must pass clean. If `cargo fmt` changes files, stage and include those changes in the commit.

For feature-powerset checks, use `--depth 2` (pairwise only — full powerset is exponential and unnecessary) and group mutually exclusive backends so only one is tested at a time:

```bash
# --depth 2: pairwise combinations only, not every 2^n combo
# --group-features: backends are mutually exclusive — test one at a time, not together
cargo hack check --feature-powerset --depth 2 \
  --group-features lmdb,kubo,s3 \
  --no-dev-deps -p <crate>
```

## Agent Interaction Rules

**Fail fast, report up.** If a shell command fails twice with the same error, stop and report the exact error to the user with context. Do not try variants. A repeated failure means your model of the problem is wrong.

**Map once, then act.** Use `Glob`/`Grep` to find files before editing. Do not re-explore the same area once you have a plan.

**Confirm scope for multi-file changes.** Before touching more than three files, state which files will change and why.

**Use subagents aggressively.** Spawn `explore` agents for codebase research and `general` agents for multi-step parallel workstreams. Do not do sequentially what can be done in parallel.

## Task Tracking

Use `bd` (beads) for ALL persistent task tracking — do NOT use markdown TODO lists or MEMORY.md files.

The built-in `TodoWrite` tool is acceptable for tracking in-session progress within a single conversation turn, but Beads is the source of truth across sessions. Run `bd prime` for detailed command reference.

## Session Completion

**Mandatory sequence** when ending a session:

```bash
# If code changed:
cargo fmt --all && cargo clippy --workspace -- -D warnings && cargo test --workspace
# Always:
bd close <completed-ids>
git pull --rebase
bd dolt push
git push
git status  # must show "up to date with origin"
```

During normal sessions, git commit and git push require explicit user approval. **Exception**: when running a review loop via `~/PROMPT-review-myoss.md` or `~/PROMPT-do-beads.md`, commit immediately after each fix — do NOT ask for permission. Push to remote still requires explicit user confirmation.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
