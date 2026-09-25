import test from "node:test";
import assert from "node:assert/strict";
import { inspectToolCall } from "../src/shared/inspect.js";
import { DEFAULT_CONFIG, parseSecretRules, type GuardConfig } from "../src/shared/config.js";
import { createInitialState, grantKey, recordBlock } from "../src/shared/state.js";

const cfg = (over: Partial<GuardConfig> = {}): GuardConfig => ({ ...DEFAULT_CONFIG, ...over });

test("read of .env is a violation; write of .env is not", () => {
	assert.ok(inspectToolCall("read", { path: "app/.env" }, cfg()));
	assert.equal(inspectToolCall("write", { path: "app/.env" }, cfg()), null);
	assert.ok(inspectToolCall("read", { path: "app/.env" }, cfg({ allowWriteToSecrets: false })));
});

test("read of .env.example is always clean", () => {
	assert.equal(inspectToolCall("read", { path: ".env.example" }, cfg()), null);
});

test("bash naming a secret file is a violation", () => {
	const found = inspectToolCall("bash", { command: "cat .env.local" }, cfg());
	assert.ok(found);
	assert.equal(found?.reason.includes("environment file"), true);
});

test("bash dumping the environment is a violation", () => {
	assert.ok(inspectToolCall("bash", { command: "printenv | grep KEY" }, cfg()));
	assert.equal(inspectToolCall("bash", { command: "npm test" }, cfg()), null);
});

test("custom and MCP tools are swept string by string", () => {
	const found = inspectToolCall(
		"mcp__filesystem__read_file",
		{ path: "/home/u/.aws/credentials", encoding: "utf8" },
		cfg(),
	);
	assert.ok(found);
	assert.equal(found?.target, "/home/u/.aws/credentials");

	const nested = inspectToolCall(
		"some_other_extension_tool",
		{ options: { nested: [{ target: "~/.ssh/id_rsa" }] } },
		cfg(),
	);
	assert.ok(nested);
});

test("deeply nested junk is bounded, not unbounded", () => {
	let deep: unknown = ".env";
	for (let i = 0; i < 20; i++) deep = { next: deep };
	assert.equal(inspectToolCall("weird_tool", deep, cfg()), null);
});

test("a non-string or missing path is clean, not a crash", () => {
	assert.equal(inspectToolCall("read", {}, cfg()), null);
	assert.equal(inspectToolCall("read", { path: 42 }, cfg()), null);
	assert.equal(inspectToolCall("read", null, cfg()), null);
});

test("violation keys are stable so one approval covers repeats", () => {
	const a = inspectToolCall("read", { path: "app/.env" }, cfg());
	const b = inspectToolCall("read", { path: "APP/.ENV" }, cfg());
	assert.equal(a?.key, b?.key);
	assert.equal(a?.key, grantKey("read", a!.reason, "app/.env"));
});

test("parseSecretRules skips malformed entries instead of throwing", () => {
	const rules = parseSecretRules(["good::A[0-9]+", "no-separator", "bad::([unclosed"]);
	assert.equal(rules.length, 1);
	assert.equal(rules[0].kind, "good");
});

test("state counts blocks and keeps a bounded history", () => {
	const state = createInitialState();
	for (let i = 0; i < 30; i++) {
		recordBlock(state, { tool: "read", reason: "environment file", target: `.env${i}`, level: "once", at: i });
	}
	assert.equal(state.blockedCount, 30);
	assert.equal(state.history.length, 20);
	assert.equal(state.history[0].target, ".env29");
});

test("config cascade: project file overrides global, defaults fill the gaps", async () => {
	const { loadConfig, saveGlobalConfig, projectConfigPath } = await import(
		"../src/shared/config.js"
	);
	const os = await import("node:os");
	const fs = await import("node:fs");
	const path = await import("node:path");

	const root = fs.mkdtempSync(path.join(os.tmpdir(), "secret-guard-"));
	const globalPath = path.join(root, "global", "pi-secret-guard.json");
	const project = path.join(root, "proj");
	fs.mkdirSync(path.join(project, ".pi"), { recursive: true });

	// No files at all -> defaults.
	assert.equal(loadConfig(project, globalPath).mode, "enforce");

	saveGlobalConfig(cfg({ mode: "redact-only", approvalTimeoutMs: 1000 }), globalPath);
	assert.equal(loadConfig(project, globalPath).mode, "redact-only");

	// Project wins over global; keys it does not set still inherit.
	fs.writeFileSync(
		path.join(project, ".pi", "pi-secret-guard.json"),
		JSON.stringify({ mode: "off" }),
		"utf8",
	);
	const merged = loadConfig(project, globalPath);
	assert.equal(merged.mode, "off");
	assert.equal(merged.approvalTimeoutMs, 1000, "unset keys must inherit, not reset");
	assert.equal(projectConfigPath(project), path.join(project, ".pi", "pi-secret-guard.json"));

	fs.rmSync(root, { recursive: true, force: true });
});

test("a corrupt config file falls back to defaults instead of failing open silently", async () => {
	const { loadConfig } = await import("../src/shared/config.js");
	const fs = await import("node:fs");
	const os = await import("node:os");
	const path = await import("node:path");

	const root = fs.mkdtempSync(path.join(os.tmpdir(), "secret-guard-bad-"));
	const globalPath = path.join(root, "pi-secret-guard.json");
	const project = path.join(root, "proj");
	fs.mkdirSync(path.join(project, ".pi"), { recursive: true });
	fs.writeFileSync(globalPath, "{ not json", "utf8");

	const merged = loadConfig(project, globalPath);
	assert.equal(merged.mode, "enforce", "corrupt global file must not disable the guard");
	assert.equal(merged.redactOutput, true);

	fs.writeFileSync(path.join(project, ".pi", "pi-secret-guard.json"), "]]]", "utf8");
	assert.equal(loadConfig(project, globalPath).mode, "enforce");

	fs.rmSync(root, { recursive: true, force: true });
});
