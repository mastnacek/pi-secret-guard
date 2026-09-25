/**
 * Configuration kernel for pi-secret-guard.
 *
 * Cascade: defaults <- `~/.pi/agent/pi-secret-guard.json` (global) <-
 * `<cwd>/.pi/pi-secret-guard.json` (project wins). The global file is how the
 * rule set follows the user across projects; the project file is how a repo
 * relaxes it for a fixture directory it legitimately needs.
 *
 * Loading is fail-safe throughout: a missing or corrupt file yields defaults,
 * because a guard that refuses to start is worse than no guard at all.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import type { SecretRule } from "./secrets.js";

export type GuardMode = "enforce" | "redact-only" | "off";

export interface GuardConfig {
	/** enforce = block and ask; redact-only = never block, still redact. */
	mode: GuardMode;
	/** Approval dialog lifetime. Silence (or timeout) means auto-deny. */
	approvalTimeoutMs: number;
	/** Writing a `.env` is normal dev work; only reading it is guarded. */
	allowWriteToSecrets: boolean;
	/** Redact secret-shaped values out of every tool result. */
	redactOutput: boolean;
	/** Notify in the footer when something is blocked or redacted. */
	notify: boolean;
	/** Path substrings that bypass layer 1 entirely. */
	allowPathPatterns: string[];
	/** Env var name globs that bypass layer 2. `PI_*` ships by default. */
	allowEnvNames: string[];
	/** Extra regex sources for the env-dump layer. */
	extraEnvDumpPatterns: string[];
	/** Extra value rules for layer 3, user-supplied as `kind::regex` pairs. */
	extraSecretRules: string[];
}

export const GLOBAL_CONFIG_PATH = join(homedir(), ".pi", "agent", "pi-secret-guard.json");

export function projectConfigPath(cwd: string): string {
	return join(cwd, ".pi", "pi-secret-guard.json");
}

export const DEFAULT_CONFIG: GuardConfig = {
	mode: "enforce",
	approvalTimeoutMs: 5000,
	allowWriteToSecrets: true,
	redactOutput: true,
	notify: true,
	allowPathPatterns: [],
	// Pi's own bash prompt tells the model to inspect PI_*; blocking that would
	// fight the engine.
	allowEnvNames: ["PI_*", "NODE_OPTIONS", "TERM", "SHELL", "USER", "HOME", "PWD"],
	extraEnvDumpPatterns: [],
	extraSecretRules: [],
};

/** Parse `kind::regex` strings into rules, skipping malformed entries. */
export function parseSecretRules(entries: string[]): SecretRule[] {
	const rules: SecretRule[] = [];
	for (const entry of entries) {
		const sep = entry.indexOf("::");
		if (sep <= 0) continue;
		const kind = entry.slice(0, sep).trim();
		try {
			rules.push({ kind, re: new RegExp(entry.slice(sep + 2), "g") });
		} catch {
			// Ignore an unparseable user rule rather than failing the whole guard.
		}
	}
	return rules;
}

function coerce(raw: unknown): Partial<GuardConfig> {
	if (typeof raw !== "object" || raw === null) return {};
	const r = raw as Record<string, unknown>;
	const out: Partial<GuardConfig> = {};

	if (r.mode === "enforce" || r.mode === "redact-only" || r.mode === "off") {
		out.mode = r.mode;
	}
	if (typeof r.approvalTimeoutMs === "number" && r.approvalTimeoutMs >= 0) {
		out.approvalTimeoutMs = r.approvalTimeoutMs;
	}
	for (const key of ["allowWriteToSecrets", "redactOutput", "notify"] as const) {
		if (typeof r[key] === "boolean") out[key] = r[key] as boolean;
	}
	for (const key of [
		"allowPathPatterns",
		"allowEnvNames",
		"extraEnvDumpPatterns",
		"extraSecretRules",
	] as const) {
		if (Array.isArray(r[key])) {
			out[key] = (r[key] as unknown[]).filter((v): v is string => typeof v === "string");
		}
	}
	return out;
}

function readLayer(path: string): Partial<GuardConfig> {
	try {
		if (!existsSync(path)) return {};
		return coerce(JSON.parse(readFileSync(path, "utf8")));
	} catch {
		return {};
	}
}

/** defaults <- global <- project. `globalPath` exists so tests stay hermetic. */
export function loadConfig(cwd?: string, globalPath: string = GLOBAL_CONFIG_PATH): GuardConfig {
	const merged: GuardConfig = {
		...DEFAULT_CONFIG,
		...readLayer(globalPath),
		...(cwd ? readLayer(projectConfigPath(cwd)) : {}),
	};
	// An empty allowlist in a project file means "inherit", not "allow nothing".
	if (!merged.allowEnvNames.length) merged.allowEnvNames = DEFAULT_CONFIG.allowEnvNames;
	return merged;
}

function writeConfigFile(path: string, config: GuardConfig): void {
	mkdirSync(dirname(path), { recursive: true });
	writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

export function saveGlobalConfig(
	config: GuardConfig,
	path: string = GLOBAL_CONFIG_PATH,
): void {
	writeConfigFile(path, config);
}

export function saveProjectConfig(config: GuardConfig, cwd: string): void {
	if (!cwd) return;
	writeConfigFile(projectConfigPath(cwd), config);
}
