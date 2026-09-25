import test from "node:test";
import assert from "node:assert/strict";
import { inspectToolCall, CHECK_TOOL_NAME } from "../src/shared/inspect.js";
import {
	DEFAULT_CONFIG,
	loadConfig,
	parseSecretRules,
	type GuardConfig,
} from "../src/shared/config.js";
import { createInitialState, grantKey, recordBlock } from "../src/shared/state.js";

const cfg = (over: Partial<GuardConfig> = {}): GuardConfig => ({ ...DEFAULT_CONFIG, ...over });

test("the advisory tool is never blocked, even for a secret path", () => {
	// The regression: the guard could not be *asked* about a secret path,
	// because the path sat inside the checker's own arguments.
	for (const target of [
		"C:/Users/u/.ssh/id_ed25519",
		"/home/u/.aws/credentials",
		"/srv/app/.env",
	]) {
		assert.equal(
			inspectToolCall(CHECK_TOOL_NAME, { kind: "path", value: target }, cfg()),
			null,
			`checker must be exempt for ${target}`,
		);
	}
	// A command argument gets the same exemption.
	assert.equal(
		inspectToolCall(CHECK_TOOL_NAME, { kind: "command", value: "printenv | grep KEY" }, cfg()),
		null,
	);
});

test("the exemption is narrow — it does not leak to other tools", () => {
	const args = { kind: "path", value: "/srv/app/.env" };
	// A lookalike name is still swept.
	assert.ok(inspectToolCall(CHECK_TOOL_NAME + "_x", args, cfg()));
	assert.ok(inspectToolCall("mcp__fs__read", args, cfg()));
	// And the real read tool is still guarded.
	assert.ok(inspectToolCall("read", { path: "/srv/app/.env" }, cfg()));
});

test("the checker name lives in exactly one place", () => {
	assert.equal(CHECK_TOOL_NAME, "pi_secret_guard_check");
});

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

test("the shipped default is the human-in-the-loop mode", () => {
	assert.equal(DEFAULT_CONFIG.mode, "enforce", "enforce = block and ask the user");
	assert.ok(DEFAULT_CONFIG.approvalTimeoutMs > 0, "silence must auto-deny, not hang");
	assert.equal(loadConfig("/nonexistent-project", "/nonexistent-global").mode, "enforce");
});

test("a project config arriving with a clone cannot disable the guard", async () => {
	const { loadConfig, projectConfigPath } = await import("../src/shared/config.js");
	const fs = await import("node:fs");
	const os = await import("node:os");
	const path = await import("node:path");

	const root = fs.mkdtempSync(path.join(os.tmpdir(), "sg-hostile-"));
	const globalPath = path.join(root, "pi-secret-guard.json");
	const project = path.join(root, "repo");
	fs.mkdirSync(path.join(project, ".pi"), { recursive: true });

	for (const hostile of [{ mode: "off" }, { mode: "redact-only" }]) {
		fs.writeFileSync(projectConfigPath(project), JSON.stringify(hostile), "utf8");
		const merged = loadConfig(project, globalPath);
		assert.equal(merged.mode, "enforce", `project ${hostile.mode} must not win`);
	}
	fs.rmSync(root, { recursive: true, force: true });
});

test("a project config may tighten but never lengthen", async () => {
	const { loadConfig, saveGlobalConfig, projectConfigPath } = await import(
		"../src/shared/config.js"
	);
	const fs = await import("node:fs");
	const os = await import("node:os");
	const path = await import("node:path");

	const root = fs.mkdtempSync(path.join(os.tmpdir(), "sg-tighten-"));
	const globalPath = path.join(root, "pi-secret-guard.json");
	const project = path.join(root, "repo");
	fs.mkdirSync(path.join(project, ".pi"), { recursive: true });

	// Shorter window: a project may insist on a faster auto-deny.
	fs.writeFileSync(projectConfigPath(project), JSON.stringify({ approvalTimeoutMs: 1000 }), "utf8");
	assert.equal(loadConfig(project, globalPath).approvalTimeoutMs, 1000);

	// Longer window: ignored, the global 5000 stands.
	fs.writeFileSync(projectConfigPath(project), JSON.stringify({ approvalTimeoutMs: 60000 }), "utf8");
	assert.equal(loadConfig(project, globalPath).approvalTimeoutMs, 5000);

	// Only the global file may widen it, and only its own user may.
	saveGlobalConfig(cfg({ approvalTimeoutMs: 60000 }), globalPath);
	assert.equal(loadConfig(project, globalPath).approvalTimeoutMs, 60000);

	fs.rmSync(root, { recursive: true, force: true });
});

test("a project config may still tighten the other switches", async () => {
	const { loadConfig, projectConfigPath } = await import("../src/shared/config.js");
	const fs = await import("node:fs");
	const os = await import("node:os");
	const path = await import("node:path");

	const root = fs.mkdtempSync(path.join(os.tmpdir(), "sg-tighten2-"));
	const globalPath = path.join(root, "pi-secret-guard.json");
	const project = path.join(root, "repo");
	fs.mkdirSync(path.join(project, ".pi"), { recursive: true });

	fs.writeFileSync(
		projectConfigPath(project),
		JSON.stringify({ redactOutput: false, allowWriteToSecrets: false }),
		"utf8",
	);
	const merged = loadConfig(project, globalPath);
	assert.equal(merged.redactOutput, true, "a project must not switch redaction off");
	assert.equal(merged.allowWriteToSecrets, false, "guarding writes is a tightening");

	fs.rmSync(root, { recursive: true, force: true });
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

	// The global layer is the user's own, so it may set the mode and the keys
	// it leaves out still inherit the defaults rather than resetting.
	saveGlobalConfig(cfg({ mode: "redact-only", approvalTimeoutMs: 1000 }), globalPath);
	const fromGlobal = loadConfig(project, globalPath);
	assert.equal(fromGlobal.mode, "redact-only");
	assert.equal(fromGlobal.approvalTimeoutMs, 1000);
	assert.equal(fromGlobal.redactOutput, true, "unset keys must inherit, not reset");
	assert.equal(projectConfigPath(project), path.join(project, ".pi", "pi-secret-guard.json"));

	// No project file -> the global layer stands untouched.
	assert.equal(loadConfig(path.join(root, "no-project"), globalPath).mode, "redact-only");

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
