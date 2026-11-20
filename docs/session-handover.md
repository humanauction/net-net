# Session handover and persistence protocol

## Purpose

This protocol preserves delivery context across human and agent sessions. It complements Git history; it never replaces it. It applies to code, tests, dependencies, configuration, security decisions, and operational documentation.

## At session start

1. Read `AGENTS.md`, this document, `docs/development-roadmap.md`, and relevant source-area docs.
2. Inspect `git status --short`, the latest commits, current CI state, and open failures. Do not overwrite unrelated changes.
3. State the objective, the acceptance criteria, and whether a planned action touches packet parsing, authentication, secrets, telemetry, storage, or privilege boundaries.
4. Reproduce the smallest relevant test before changing code. For daemon tests, use offline PCAPs and isolated resources only.

## During a session

- Keep commits cohesive: one behavior/security/dependency concern per commit.
- Record material decisions in the most relevant documentation or ADR-style section, not only in chat.
- Preserve test fixtures and add minimal PCAP fixtures for parser regressions.
- Do not add secrets, real captured traffic, customer domains, persistent local databases, coverage output, or generated build files to Git.
- When a security-sensitive trade-off is unresolved, stop at a safe boundary and add it to the handover record.

## Required handover record

Create or update `docs/handover/current.md` for any session that changes code, dependencies, CI, configuration semantics, or roadmap priorities. Replace it rather than appending unbounded history; lasting rationale belongs in a committed design/roadmap document.

Use this template:

```markdown
# Current handover

**Updated:** YYYY-MM-DD HH:MM TZ
**Owner/session:** human or agent identifier
**Objective:** one sentence

## Completed
- Commit or uncommitted change, why it was made, and docs/tests changed.

## Verification
- Exact configure/build/test commands and outcomes.
- Platform/toolchain versions.

## Decisions and security impact
- Data collected/exported, retention, transport protection, access control, and migration implications.

## Known risks and blockers
- Reproducible failure, severity, and safe workaround.

## Next smallest safe step
- One concrete action and its acceptance test.
```

`docs/handover/current.md` is intentionally ignored from Git when it contains local environment details. If it contains a durable decision, promote a scrubbed summary into committed documentation before ending the session.

## Definition of done

A task is not complete until the implementation, tests, configuration reference, API/operational docs, and handover record agree. A failed test must be reported with its command and output summary; it cannot be silently bypassed.
