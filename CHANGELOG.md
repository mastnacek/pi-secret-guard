# Changelog

## 0.2.0 — tool exemptions and payload detection

- `exemptTools` in the config: tool-name globs (`insert`, `mcp__*`) that skip
  layer 1 for that tool. Global layer only, so a project file arriving with a
  clone cannot switch input inspection off — same rule as `mode: "off"`.
  Output redaction (layer 2) still runs on an exempted tool's results.
- `/secret-guard exempt add|remove|list|clear`, global-only, with the second
  completion level wired to the Trailing Space Contract.
- `pi_secret_guard_check` gained `kind: "tool"` plus a `tool` name argument: it
  replays the exact input sweep the real call would hit, so a denial is known
  before the call is sent rather than after.
- `/secret-guard status` lists the active exemptions.

### Why

`pi-hashline-edit-pro` registers `insert`, `replace`, `anchor_grep` and
`undo_last_change`. The guard has no schema for any of them, so it swept every
string in their arguments with the shell rules. A JavaScript template literal
naming something called `key` was denied as "secret env var (KEY)" — source code
in an editor argument, no secret anywhere. The exemption is the escape hatch;
rephrasing the payload is still the narrower fix.
