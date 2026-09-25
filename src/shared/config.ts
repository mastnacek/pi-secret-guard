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

/** Which config layer a value came from. Only the global layer may weaken. */
type Layer = "global" | "project";

function coerce(raw: unknown, layer: Layer): Partial<GuardConfig> {
	if (typeof raw !== "object" || raw === null) return {};
	const r = raw as Record<string, unknown>;
	const out: Partial<GuardConfig> = {};
	// A project config is a file inside a repository, so it can arrive from a
	// clone. It may only tighten the guard; only the user's own global file may
	// turn it down. `enforce` is the floor, and that is the whole point of the
	// human-in-the-loop default.
	const canWeaken = layer === "global";

	if (r.mode === "enforce") {
		out.mode = "enforce";
	} else if (canWeaken && (r.mode === "redact-only" || r.mode === "off")) {
		out.mode = r.mode;
	}

	// Kept for both layers; `loadConfig` lets a project file shorten the window
	// but never lengthen it, so a longer one only ever buys unattended time.
	if (typeof r.approvalTimeoutMs === "number" && r.approvalTimeoutMs >= 0) {
		out.approvalTimeoutMs = r.approvalTimeoutMs;
	}

	// `redactOutput: false` weakens; `notify: false` is cosmetic and allowed.
	if (typeof r.redactOutput === "boolean" && (canWeaken || r.redactOutput)) {
		out.redactOutput = r.redactOutput;
	}
	if (typeof r.allowWriteToSecrets === "boolean") {
		out.allowWriteToSecrets = r.allowWriteToSecrets;
	}
	if (typeof r.notify === "boolean") out.notify = r.notify;

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

function readLayer(path: string, layer: Layer): Partial<GuardConfig> {
	try {
		if (!existsSync(path)) return {};
		return coerce(JSON.parse(readFileSync(path, "utf8")), layer);
	} catch {
		return {};
	}
}

/** defaults <- global <- project. `globalPath` exists so tests stay hermetic. */
export function loadConfig(cwd?: string, globalPath: string = GLOBAL_CONFIG_PATH): GuardConfig {
	const global = readLayer(globalPath, "global");
	const project = cwd ? readLayer(projectConfigPath(cwd), "project") : {};
	const base: GuardConfig = { ...DEFAULT_CONFIG, ...global };
	const merged: GuardConfig = { ...base, ...project };

	// A project file may shorten the approval window but never lengthen it, so
	// the comparison is against the pre-project value, not the merged one.
	if (typeof project.approvalTimeoutMs === "number") {
		merged.approvalTimeoutMs = Math.min(base.approvalTimeoutMs, project.approvalTimeoutMs);
	}
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
