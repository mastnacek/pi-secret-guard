/**
 * Hook slice for pi-secret-guard.
 *
 * Two hooks, in this order:
 *
 *   tool_call   — inspect the input, and on a violation ask the user. Default
 *                 answer is DENY; silence or the 5 s timeout is also deny.
 *   tool_result — redact secret-shaped values out of the output before the
 *                 model ever sees it. This is the layer that catches what the
 *                 input inspection could not predict.
 *
 * Returns its own unsubscribe handles; the composition root drains them on
 * `session_shutdown` so nothing leaks across `/reload` or a replaced session.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { loadConfig, parseSecretRules } from "../../shared/config.js";
import { redactSecrets } from "../../shared/patterns.js";
import { truncate, recordBlock, type ApprovalLevel, type PluginState } from "../../shared/state.js";
import { inspectToolCall, type Violation } from "../../shared/inspect.js";

/** Dialog choices. Index 0 is the highlighted default, so Enter denies. */
const DENY = "Deny — keep it secret (default)";
const ALLOW_ONCE = "Allow this one call";
const ALLOW_SESSION = "Allow for the rest of this session";

function footerBadge(state: PluginState): string {
	if (!state.enabled || state.config.mode === "off") return "secret-guard: off";
	const parts = [`secret-guard: ${state.config.mode}`];
	if (state.blockedCount) parts.push(`blocked ${state.blockedCount}`);
	if (state.redactedCount) parts.push(`redacted ${state.redactedCount}`);
	return parts.join(" · ");
}

/**
 * Ask the user. Returns the granted level, or null for deny.
 *
 * Headless sessions (`ctx.hasUI === false`) deny without asking: there is no
 * human to ask, and fail-open is exactly the bug this plugin exists to prevent.
 */
async function requestApproval(
	ctx: ExtensionContext,
	state: PluginState,
	tool: string,
	found: Violation,
): Promise<ApprovalLevel | null> {
	if (!ctx.hasUI) return null;
	const choice = await ctx.ui.select(
		`secret-guard · ${truncate(tool, 24)} · ${found.reason}`,
		[DENY, ALLOW_ONCE, ALLOW_SESSION],
		{ timeout: state.config.approvalTimeoutMs },
	);
	if (choice === ALLOW_ONCE) return "once";
	if (choice === ALLOW_SESSION) return "session";
	// Undefined means the dialog timed out or was dismissed: that is a deny.
	return null;
}

export function registerHooks(pi: ExtensionAPI, state: PluginState): Array<() => void> {
	state.config = loadConfig();

	const unsubs: Array<() => void> = [];

	unsubs.push(
		pi.on("session_start", (_event, ctx) => {
			// The project layer depends on cwd, which can change across forks.
			state.config = loadConfig(ctx.cwd);
			if (ctx.hasUI) ctx.ui.setStatus("pi-secret-guard", footerBadge(state));
		}),

		pi.on("tool_call", async (event, ctx) => {
			if (!state.enabled) return;
			if (state.config.mode !== "enforce") return;

			const found = inspectToolCall(event.toolName, event.input, state.config);
			if (!found) return;

			// A standing approval for this exact hit covers the call.
			if (state.sessionWide.has(found.key)) return;
			if (state.grants.has(found.key)) {
				state.grants.delete(found.key); // "once" is consumed here
				return;
			}

			const level = await requestApproval(ctx, state, event.toolName, found);
			if (level === null) {
				recordBlock(state, {
					tool: event.toolName,
					reason: found.reason,
					target: found.target,
					level: "once",
					at: Date.now(),
				});
				if (ctx.hasUI) {
					if (state.config.notify) {
						ctx.ui.notify(
							`secret-guard denied ${event.toolName} → ${found.reason}`,
							"warning",
						);
					}
					ctx.ui.setStatus("pi-secret-guard", footerBadge(state));
				}
				return {
					block: true,
					reason:
						`BLOCKED by pi-secret-guard (${found.reason}).\n` +
						`Target: ${found.target}\n` +
						"The user declined to share this. Do not retry through another tool, " +
						"another spelling of the path, or an indirect command — the refusal " +
						"covers the request, not just this call. Work from a placeholder.",
				};
			}

			if (level === "session") state.sessionWide.add(found.key);
			else state.grants.set(found.key, "once");
			return;
		}),

		pi.on("tool_result", async (event, ctx) => {
			if (!state.enabled) return;
			if (state.config.mode === "off" || !state.config.redactOutput) return;

			const extra = parseSecretRules(state.config.extraSecretRules);
			let changed = false;
			const content = event.content.map((part) => {
				if (part.type !== "text") return part;
				const result = redactSecrets(part.text, extra);
				if (result.count === 0) return part;
				changed = true;
				state.redactedCount++;
				state.redactedValues += result.count;
				return { ...part, text: result.text };
			});

			if (!changed) return;
			if (ctx.hasUI && state.config.notify) {
				ctx.ui.setStatus("pi-secret-guard", footerBadge(state));
			}
			return { content };
		}),
	);

	return unsubs;
}
