/**
 * Tools slice for pi-secret-guard.
 *
 * One tool, so the model can ask about its own cage: `pi_secret_guard_check`
 * reports what the guard would do with a given path or command without
 * executing anything. It is the honest way to discover a denial is coming,
 * instead of burning a tool call on it.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { checkPath, checkShellCommand } from "../../shared/patterns.js";
import { inspectToolCall } from "../../shared/inspect.js";
import type { PluginState } from "../../shared/state.js";

const KindSchema = StringEnum(["path", "command"] as const);

export function registerTools(pi: ExtensionAPI, state: PluginState): void {
	pi.registerTool({
		name: "pi_secret_guard_check",
		label: "Secret guard check",
		description:
			"Ask the secret guard what it would do with a file path or shell command, without " +
			"running it. Use before reading a config file you are unsure about, so you do not " +
			"spend a denied tool call finding out.",
		parameters: Type.Object({
			kind: KindSchema,
			value: Type.String({ description: "The path or command to test" }),
		}),
		async execute(_toolCallId, params) {
			const config = state.config;
			const value = params.value;

			const detail =
				params.kind === "path"
					? checkPath(value, { allowed: config.allowPathPatterns })
					: checkShellCommand(value, {
							allowedEnvNames: config.allowEnvNames,
							extraEnvDumpPatterns: config.extraEnvDumpPatterns,
						});

			const viaTool = inspectToolCall(
				params.kind === "path" ? "read" : "bash",
				params.kind === "path" ? { path: value } : { command: value },
				config,
			);

			const blocked = detail.blocked || viaTool !== null;
			const reason = detail.reason || viaTool?.reason || "no rule matched";

			return {
				content: [
					{
						type: "text",
						text: blocked
							? `BLOCKED (${reason}). Reading this needs explicit user approval; ` +
									"the default answer is deny and the dialog closes on its own after " +
									`${config.approvalTimeoutMs} ms. Ask the user for the value, or work ` +
									"from a placeholder."
							: `ALLOWED — no rule matched this ${params.kind}.`,
					},
				],
				details: { blocked, reason, mode: config.mode },
			};
		},
	});
}
