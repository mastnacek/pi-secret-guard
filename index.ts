/**
 * pi-secret-guard — Pi coding agent extension.
 *
 * Composition root only: registers slices, drains their listeners on
 * `session_shutdown`, and guards against subagent recursion.
 *
 * What it does, in two layers:
 *   1. `tool_call`  — a credential path or a secret-bearing shell command stops
 *      the call and asks the user. Deny is the highlighted default, and the
 *      dialog auto-dismisses to deny after `approvalTimeoutMs`.
 *   2. `tool_result` — secret-shaped values are redacted out of tool output
 *      before the model reads it. This catches what layer 1 could not predict,
 *      including MCP servers that read credential files on their own.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createInitialState } from "./src/shared/state.js";
import { registerCommands } from "./src/slices/commands/index.js";
import { registerHooks } from "./src/slices/pipeline/index.js";
import { registerTools } from "./src/slices/tools/index.js";

/** Subagent recursion guard: avoid duplicating hooks in child sessions. */
function isDelegatedSession(): boolean {
	return process.env.PI_SUBAGENT === "true" || Boolean(process.env.PI_CHILD_SESSION);
}

export default function (pi: ExtensionAPI): void {
	if (isDelegatedSession()) return;

	const state = createInitialState();
	const unsubscribers: Array<() => void> = [];

	registerCommands(pi, state);
	registerTools(pi, state);
	unsubscribers.push(...registerHooks(pi, state));

	// Drain every listener on shutdown; keep this idempotent because reload,
	// cancellation and process exit can all converge here.
	pi.on("session_shutdown", async () => {
		while (unsubscribers.length > 0) {
			unsubscribers.pop()?.();
		}
	});
}
