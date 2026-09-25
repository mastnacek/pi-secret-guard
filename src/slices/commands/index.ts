/**
 * Commands slice for pi-secret-guard.
 *
 * `/secret-guard` is the escape hatch: every false positive the guard produces
 * has to be fixable without hand-editing a JSON file.
 *
 * Setting changes follow the repo-wide cascade contract — a trailing `--global`
 * persists to `~/.pi/agent/pi-secret-guard.json` for every session; without it
 * the change lands in `<cwd>/.pi/pi-secret-guard.json` and stays in this repo.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
	GLOBAL_CONFIG_PATH,
	loadConfig,
	projectConfigPath,
	saveGlobalConfig,
	saveProjectConfig,
	type GuardConfig,
} from "../../shared/config.js";
import { truncate, type PluginState } from "../../shared/state.js";

const ACTIONS = ["status", "on", "off", "forget", "allow"] as const;
type Action = (typeof ACTIONS)[number];

const ACTION_HELP: Record<Action, string> = {
	status: "show mode, counters, and recent blocks",
	on: "switch to enforce mode (block and ask)",
	off: "disable the guard",
	forget: "clear every approval granted this session",
	allow: "show how to extend the allowlists",
};

function describe(config: GuardConfig, state: PluginState, cwd: string): string {
	const lines = [
		`mode             ${config.mode}`,
		`approval window  ${config.approvalTimeoutMs} ms (silence = deny)`,
		`redact output    ${config.redactOutput ? "on" : "off"}`,
		`write secrets    ${config.allowWriteToSecrets ? "allowed" : "guarded"}`,
		`blocked          ${state.blockedCount}`,
		`redacted         ${state.redactedCount} tool result(s), ${state.redactedValues} value(s)`,
		`session grants   ${state.sessionWide.size} standing, ${state.grants.size} pending`,
		`global config    ${GLOBAL_CONFIG_PATH}`,
		`project config   ${projectConfigPath(cwd)}`,
	];
	if (state.history.length) {
		lines.push("", "recent blocks:");
		for (const item of state.history.slice(0, 5)) {
			lines.push(`  ${item.tool} · ${item.reason} · ${truncate(item.target, 60)}`);
		}
	}
	if (config.allowPathPatterns.length) {
		lines.push("", "allowed paths:", ...config.allowPathPatterns.map((p) => `  ${p}`));
	}
	return lines.join("\n");
}

export function registerCommands(pi: ExtensionAPI, state: PluginState): void {
	pi.registerCommand("secret-guard", {
		description: "Pi secret guard — block .env and credential reads, redact secrets from output",
		getArgumentCompletions: (arg) => {
			const partial = arg.split(/\s+/).pop() ?? "";
			if (arg.includes(" ")) return [];
			return ACTIONS.filter((a) => a.startsWith(partial)).map((a) => ({
				value: a,
				label: `${a} — ${ACTION_HELP[a]}`,
			}));
		},
		handler: async (args, ctx) => {
			const tokens = args.trim().split(/\s+/).filter(Boolean);
			const action = (tokens[0] || "status") as Action;
			const isGlobal = tokens.includes("--global");
			const cwd = ctx.cwd;
			const say = (text: string): void => {
				if (ctx.hasUI) ctx.ui.notify(text);
			};
			const persist = (config: GuardConfig): void => {
				if (isGlobal) saveGlobalConfig(config);
				else saveProjectConfig(config, cwd);
			};

			switch (action) {
				case "on":
					state.config = { ...state.config, mode: "enforce" };
					state.enabled = true;
					persist(state.config);
					say(`secret-guard: enforce mode on (${isGlobal ? "global" : "project"})`);
					return;
				case "off":
					state.config = { ...state.config, mode: "off" };
					state.enabled = false;
					persist(state.config);
					say(`secret-guard: off (${isGlobal ? "global" : "project"})`);
					return;
				case "forget":
					state.sessionWide.clear();
					state.grants.clear();
					say("secret-guard: session approvals cleared");
					return;
				case "allow":
					say(
						[
							"add to the global file (or the project file without --global):",
							`  ${isGlobal ? GLOBAL_CONFIG_PATH : projectConfigPath(cwd)}`,
							'  "allowPathPatterns": ["' +
								cwd +
								'/fixtures"]',
							'  "allowEnvNames": ["PI_*", "MY_APP_KEY"]',
						].join("\n"),
					);
					return;
				case "status":
					say(describe(loadConfig(cwd), state, cwd));
					return;
				default:
					say(`unknown action "${action}". Try: ${ACTIONS.join(", ")}`);
			}
		},
	});
}
