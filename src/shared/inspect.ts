/**
 * Tool-input inspection for pi-secret-guard.
 *
 * Turns a raw tool call into a violation verdict, or null when the call is
 * clean. Pure, so the whole decision table is unit testable without a session.
 *
 * Built-in tools are inspected field by field (a `path` is a path; a `command`
 * is a shell command). Everything else — MCP tools, other extensions' custom
 * tools, `read_all` — has no schema we know, so every string in the input is
 * swept with both the path and the shell rules. Over-matching there costs one
 * approval prompt; under-matching there is a leak.
 */

import { checkPath, checkShellCommand } from "./patterns.js";
import type { GuardConfig } from "./config.js";
import { truncate } from "./state.js";

export interface Violation {
	/** What tripped the guard. */
	reason: string;
	/** The offending text, already truncated for display. */
	target: string;
	/** Stable key so one approval covers repeats. */
	key: string;
}

/** Tools whose job is to read a file the user named. */
const PATH_TOOLS = new Set(["read", "edit", "write", "read_all"]);
/** Tools whose job is to run shell text. */
const SHELL_TOOLS = new Set(["bash", "powershell", "shell", "user_bash"]);

function violation(tool: string, reason: string, target: string): Violation {
	return {
		reason,
		target: truncate(target),
		key: `${tool}::${reason}::${target.toLowerCase()}`,
	};
}

function stringLeaves(value: unknown, out: string[], depth = 0): void {
	if (depth > 6 || value === null || value === undefined) return;
	if (typeof value === "string") {
		out.push(value);
		return;
	}
	if (Array.isArray(value)) {
		for (const item of value) stringLeaves(item, out, depth + 1);
		return;
	}
	if (typeof value === "object") {
		for (const item of Object.values(value as Record<string, unknown>)) {
			stringLeaves(item, out, depth + 1);
		}
	}
}

/** Tokens in a shell command that could be a path argument. */
const SHELL_PATH_TOKEN = /(?:[~.]?[\w.\-]*[/\\][^\s"'`;|&<>()]*|\.env[\w.\-]*|[\w.\-]+\.(?:pem|key|p12|pfx|jks|ppk|keytab|asc|gpg|ovpn|p8|p9))/gi;

/**
 * Pull path-looking tokens out of shell text.
 *
 * `checkPath` works on a whole path, so `cat ../.env.local` has to be split
 * before the basename rules can see anything. Non-path words are filtered out
 * by requiring a separator, a leading dot, or a key-file extension.
 */
function shellPathTokens(command: string): string[] {
	return command.match(SHELL_PATH_TOKEN) ?? [];
}

/**
 * Decide whether a tool call may proceed.
 *
 * Returns null when clean. Never throws: a guard that crashes must not silently
 * wave the call through, so an internal failure resolves to the safe verdict.
 */
export function inspectToolCall(
	toolName: string,
	input: unknown,
	config: GuardConfig,
): Violation | null {
	try {
		const args = (input ?? {}) as Record<string, unknown>;

		if (PATH_TOOLS.has(toolName)) {
			const raw = typeof args.path === "string" ? args.path : "";
			if (!raw) return null;
			if (toolName === "write" && config.allowWriteToSecrets) return null;
			const hit = checkPath(raw, { allowed: config.allowPathPatterns });
			return hit.blocked ? violation(toolName, hit.reason, raw) : null;
		}

		if (SHELL_TOOLS.has(toolName)) {
			const command = typeof args.command === "string" ? args.command : "";
			if (!command) return null;
			// A shell command can name a secret file as readily as it can name a
			// secret variable, so sweep the text for both.
			for (const token of shellPathTokens(command)) {
				const pathHit = checkPath(token, { allowed: config.allowPathPatterns });
				if (pathHit.blocked) return violation(toolName, pathHit.reason, command);
			}
			const shell = checkShellCommand(command, {
				allowedEnvNames: config.allowEnvNames,
				extraEnvDumpPatterns: config.extraEnvDumpPatterns,
			});
			return shell.blocked ? violation(toolName, shell.reason, command) : null;
		}

		// Unknown tool (MCP server, another extension): sweep every string.
		// The leaf may be a bare path or a whole command, so try both readings.
		const leaves: string[] = [];
		stringLeaves(input, leaves);
		for (const leaf of leaves) {
			if (leaf.length < 3) continue;
			for (const token of [leaf, ...shellPathTokens(leaf)]) {
				const pathHit = checkPath(token, { allowed: config.allowPathPatterns });
				if (pathHit.blocked) return violation(toolName, pathHit.reason, truncate(leaf));
			}
			const shell = checkShellCommand(leaf, {
				allowedEnvNames: config.allowEnvNames,
				extraEnvDumpPatterns: config.extraEnvDumpPatterns,
			});
			if (shell.blocked) return violation(toolName, shell.reason, leaf);
		}
		return null;
	} catch {
		// Fail closed on our own bug: an unexaminable call is not a call we trust.
		return {
			reason: "input could not be inspected",
			target: truncate(String(toolName ?? "unknown tool")),
			key: `${toolName}::uninspectable::`,
		};
	}
}
