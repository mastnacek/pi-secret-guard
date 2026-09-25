import test from "node:test";
import assert from "node:assert/strict";
import { checkEnvName, checkShellCommand } from "../src/shared/env.js";

test("flags secret-bearing variable names", () => {
	for (const n of [
		"OPENAI_API_KEY",
		"GITHUB_TOKEN",
		"AWS_SECRET_ACCESS_KEY",
		"DB_PASSWORD",
		"SESSION_SECRET",
		"HF_TOKEN",
	]) {
		assert.equal(checkEnvName(n).blocked, true, `expected block for ${n}`);
	}
});

test("does not flag descriptive or innocent names", () => {
	for (const n of [
		"TOKENIZERS_PARALLELISM",
		"KEYBOARD",
		"SSH_KEY_PATH",
		"GITHUB_TOKEN_NAME",
		"ENCRYPTION_KEY_TYPE",
		"PUBLIC_KEY",
		"PI_MODEL",
		"NODE_ENV",
	]) {
		assert.equal(checkEnvName(n).blocked, false, `expected allow for ${n}`);
	}
});

test("allowlist globs win", () => {
	assert.equal(checkEnvName("MY_APP_KEY", { allowed: ["MY_*"] }).blocked, false);
	assert.equal(checkEnvName("OTHER_KEY", { allowed: ["MY_*"] }).blocked, true);
});

test("blocks wholesale environment dumps", () => {
	for (const c of [
		"env",
		"printenv",
		"env | sort",
		"export -p",
		"declare -p",
		"set",
		"Get-ChildItem Env:",
		"dir env:",
		"echo hi && printenv",
	]) {
		assert.equal(checkShellCommand(c).blocked, true, `expected block for: ${c}`);
	}
});

test("blocks credential-export CLIs", () => {
	for (const c of [
		"cmdkey /list",
		"gh auth token",
		"gcloud auth print-access-token",
		"aws configure get aws_secret_access_key",
		"security dump-keychain",
		"pass show github",
		"gpg --export-secret-keys",
	]) {
		assert.equal(checkShellCommand(c).blocked, true, `expected block for: ${c}`);
	}
});

test("blocks env-var references in every shell dialect", () => {
	for (const c of [
		"echo $OPENAI_API_KEY",
		"echo ${GITHUB_TOKEN}",
		'echo "%USERPROFILE%" && echo %ANTHROPIC_API_KEY%',
		"Write-Output $env:OPENAI_API_KEY",
		"[Environment]::GetEnvironmentVariable('OPENAI_API_KEY')",
	]) {
		assert.equal(checkShellCommand(c).blocked, true, `expected block for: ${c}`);
	}
});

test("leaves ordinary shell work alone", () => {
	for (const c of [
		"npm test",
		"ls -la",
		"git status",
		"set -euo pipefail && npm run build",
		"echo $HOME",
		"echo $PI_MODEL",
		"grep -r 'tokenizer' src/",
		"python -c \"import os; print(os.getcwd())\"",
	]) {
		assert.equal(checkShellCommand(c, { allowedEnvNames: ["PI_*"] }).blocked, false,
			`expected allow for: ${c}`);
	}
});

test("a malformed user pattern cannot break the guard", () => {
	const result = checkShellCommand("npm test", { extraEnvDumpPatterns: ["([unclosed"] });
	assert.equal(result.blocked, false);
});

test("re-checked regexes stay stateless across calls", () => {
	const a = checkShellCommand("echo $OPENAI_API_KEY");
	const b = checkShellCommand("echo $OPENAI_API_KEY");
	assert.equal(a.blocked, true);
	assert.equal(b.blocked, true);
});
