# pi-secret-guard

A global guard for the Pi coding agent. It stops the model from reading `.env`
files and credential stores, and stops secret-shaped values from reaching the
model at all — with you in the loop, defaulting to **no**.

## What it actually blocks

Two layers, in this order.

**1. `tool_call` — refuse before execution.** The tool input is inspected and,
on a match, you get a dialog:

```
secret-guard · read · environment file (.env)
❯ Deny — keep it secret (default)
  Allow this one call
  Allow for the rest of this session
```

Deny is the highlighted default, so a bare Enter refuses. Silence is also a
refusal: the dialog auto-dismisses to deny after 5 seconds. In a headless
session (`ctx.hasUI === false`) there is no human to ask, so it denies without
prompting — fail-open is the exact bug this plugin exists to prevent.

**2. `tool_result` — scrub after execution.** Every tool result is scanned for
secret-shaped values and replaced with `«secret-guard:kind»` *before the model
reads it*. This is the net for what layer 1 could not predict: an MCP server
that reads a credential file on its own, a script that prints a token, a test
fixture that happens to contain a live key.

## What counts as a secret

**Paths** — `.env` and every real variant, but not `.env.example` /
`.env.sample` / `.env.template`; `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`,
`*.ppk`, `*.keytab`; `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.kube`;
`.npmrc`, `.netrc`, `.pgpass`, `.git-credentials`; `credentials*.json`,
`*service-account*.json`, `client_secret*.json`; Docker, gcloud, GitHub CLI and
Azure credential stores; `~/.pi/agent/auth.json`; browser `Login Data` /
`Cookies` / `Local State`; macOS Keychains and Linux keyrings.

**Shell** — wholesale dumps (`env`, `printenv`, `set`, `export -p`,
`Get-ChildItem Env:`), credential CLIs (`gh auth token`, `gcloud auth
print-access-token`, `aws configure get`, `cmdkey /list`, `security
dump-keychain`, `pass show`, `gpg --export-secret-keys`), and any reference to a
secret-bearing variable in `$VAR`, `${VAR}`, `$env:VAR`, `%VAR%` or
`[Environment]::GetEnvironmentVariable`.

Name matching works on whole underscore-delimited segments, so
`TOKENIZERS_PARALLELISM` and `SSH_KEY_PATH` are left alone while
`GITHUB_TOKEN` and `DATABASE_PASSWORD` are not.

**Values** — OpenAI/Anthropic, GitHub, GitLab, Slack, AWS, Google, npm, PyPI,
Stripe, SendGrid, Telegram, Hugging Face, JWTs, `Bearer` headers, credentials
embedded in URLs, PEM/PGP/age key blocks, and a generic `KEY = value` catch-all
for internal tokens no prefix rule knows about. Placeholders
(`your-api-key`, `<token>`, `${VAR}`, `xxxxx`) are recognised and left alone.

## Configuration

Cascade: defaults ← `~/.pi/agent/pi-secret-guard.json` ←
`<cwd>/.pi/pi-secret-guard.json` (project wins).
```json
{
  "mode": "enforce",
  "approvalTimeoutMs": 5000,
  "allowWriteToSecrets": true,
  "redactOutput": true,
  "allowPathPatterns": [],
  "allowEnvNames": ["PI_*"],
  "extraEnvDumpPatterns": [],
  "extraSecretRules": ["internal-token::INT-[0-9]{8}"]
}
```

- `mode` — `enforce` (block and ask), `redact-only` (never block, still scrub),
  or `off`.
- `allowWriteToSecrets` — creating a `.env` is normal dev work, so writes pass
  and only reads are guarded. Set `false` to guard both.
- `allowPathPatterns` — path substrings that bypass the path rules.
- `allowEnvNames` — name globs (`MY_*`) that bypass the variable rules.
- `extraSecretRules` — `kind::regex` pairs appended to the value rules.

`/secret-guard status` prints the effective config, the block/redaction
counters and the recent block list. `/secret-guard on|off` changes the mode;
`/secret-guard off --global` persists it for every session, without the flag it
lands in the current project. `/secret-guard forget` clears the session
approvals.

### `enforce` is a floor, not just a default

`mode: "enforce"` is the default, but it is also the weakest value a **project**
config may set. A project config is a file inside a repository, so it can arrive
with a clone — and any repo shipping `.pi/pi-secret-guard.json` with
`{"mode": "off"}` would otherwise switch your guard off silently. So:

- only the global file (yours) may set `off` or `redact-only`
- a project may set `mode: "enforce"` and may shorten `approvalTimeoutMs`, but
  never lengthen it
- a project may not set `redactOutput: false`; it may tighten
  `allowWriteToSecrets` to `false`
- `/secret-guard off` without `--global` is refused, with the fix spelled out

Verified: shipped default `enforce / 5000 ms`, no config anywhere `enforce`,
hostile project file `{"mode":"off"}` → still `enforce`.

The model also gets `pi_secret_guard_check`, which answers "would you block
this path or command?" without running it — so it can find out before spending a
denied call.

## Limits — read this before trusting it

This is a **guard rail, not a sandbox**. It intercepts Pi's own tool layer, and
that has hard edges:

- It cannot see inside a script the model writes and then runs. `node -e "..."`
  that opens a file by a path no rule recognises is opaque to text analysis.
  Layer 2 is the backstop.
- External CLI subagents (Codex, Claude Code, …) and any process they spawn run
  outside Pi's extension runtime entirely. Nothing here constrains them.
- Redaction is pattern-based. A secret in an unrecognised format, split across
  lines, or base64-encoded inside a fixture will pass through.
- A user who approves a call has approved that call. Approvals are session-only
  and never written to disk.

For a hard guarantee, the environment has to be scrubbed before Pi starts —
that is a wrapper script's job, not an extension's.

## Install

```bash
pi install git:github.com/mastnacek/pi-secret-guard
```

Test unreleased code for a single run without touching settings:

```bash
pi -e ./pi-secret-guard
```

## Development

```bash
npm test    # tsc + 37 unit tests over the rule set
```

MIT.
