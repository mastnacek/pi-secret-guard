/**
 * Tools slice for pi-secret-guard.
 *
 * One tool, so the model can ask about its own cage: `pi_secret_guard_check`
 * reports what the guard would do with a given path, command, or whole tool
 * payload without executing anything. It is the honest way to discover a denial
 * is coming, instead of burning a tool call on it.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { checkPath, checkShellCommand } from "../../shared/patterns.js";
import type { GuardMode } from "../../shared/config.js";
import { CHECK_TOOL_NAME, inspectToolCall, isExemptTool } from "../../shared/inspect.js";
import type { PluginState } from "../../shared/state.js";

const KindSchema = StringEnum(["path", "command", "tool"] as const);

/**
 * Parse a tool payload the model is about to send.
 *
 * A tool call whose name the guard does not know is swept string by string, so
 * the honest way to predict a denial is to replay that sweep. Unparseable text
 * is kept as a bare string leaf rather than rejected: the sweep would read it the
 * same way.
 */
function parsePayload(value: string): unknown {
	try {
		return JSON.parse(value);
	} catch {
		return { value };
	}
}

/**
 * One shape for every answer, so the union of the four return paths stays a
 * single result type for the tool contract.
 */
interface CheckDetails {
	blocked: boolean;
	reason: string;
	mode: GuardMode;
	/** Whole-payload mode only: the tool whose payload was tested. */
	tool?: string;
	/** Whole-payload mode only: the tool already matched a user exemption. */
	exempt?: boolean;
}
export function registerTools(pi: ExtensionAPI, state: PluginState): void {
	pi.registerTool({
		name: CHECK_TOOL_NAME,
		label: "Secret guard check",
		description:
			"Ask the secret guard what it would do with a file path, a shell command, or a whole " +
			"tool payload, without running it. Use before reading a config file you are unsure " +
			"about, and before sending a call to a tool the guard has no schema for (any custom " +
			"or MCP tool), so you do not spend a denied tool call finding out.",
		parameters: Type.Object({
			kind: KindSchema,
			tool: Type.Optional(
				Type.String({ description: "Tool name; required when kind is tool" }),
			),
			value: Type.String({
				description: "The path, command, or JSON tool payload to test",
			}),
		}),
		async execute(_toolCallId, params) {
			const config = state.config;
			const value = params.value;

			// Whole-payload mode: replay the input sweep the real call would hit,
			// so a denial is known before the call is sent rather than after.
			if (params.kind === "tool") {
				const name = (params.tool ?? "").trim();
				if (!name) {
					return {
						content: [
							{
								type: "text",
								text:
									'kind "tool" needs the tool name in `tool`, and `value` as the ' +
									"JSON payload you were about to send. Example: tool=insert, " +
									'value={"anchor":"abcd","lines":["const x = 1;"]}.',
							},
						],
						details: {
							blocked: false,
							reason: "no tool name given",
							mode: config.mode,
						} as CheckDetails,
					};
				}
				const found = inspectToolCall(name, parsePayload(value), config);
				if (!found) {
					return {
						content: [
							{
								type: "text",
								text: `ALLOWED — no rule matched this ${name} payload.`,
							},
						],
						details: {
							blocked: false,
							reason: "no rule matched",
							tool: name,
							mode: config.mode,
						} as CheckDetails,
					};
				}
				const exempt = isExemptTool(name, config.exemptTools);
				return {
					content: [
						{
							type: "text",
							text:
								`BLOCKED — ${name} would be denied (${found.reason}).\n` +
								`Target: ${found.target}\n` +
								"Tools the guard has no schema for are swept string by string, so " +
								"code in their arguments can match a rule meant for something else. " +
								(exempt
									? "The tool is already exempted, which means a stale config was loaded."
									: `Ask the user to exempt this tool: /secret-guard exempt add ${name} --global. ` +
										"Exempting a tool skips input inspection for it only; output " +
										"redaction still runs. Otherwise rephrase the payload."),
						},
					],
					details: {
						blocked: true,
						reason: found.reason,
						tool: name,
						exempt,
						mode: config.mode,
					} as CheckDetails,
				};
			}

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
				details: { blocked, reason, mode: config.mode } as CheckDetails,
			};
		},
	});
}
