/**
 * Shared state kernel for pi-secret-guard.
 *
 * Slices never import each other; they read and mutate this object. Session
 * grants live here (not on disk) so an approval never outlives the session that
 * granted it.
 */

import { DEFAULT_CONFIG, type GuardConfig } from "./config.js";

export type ApprovalLevel = "once" | "session";

export interface BlockRecord {
	/** Tool that was blocked, e.g. "read" or "bash". */
	tool: string;
	/** What tripped the guard, e.g. "environment file (.env)". */
	reason: string;
	/** The offending target, already truncated. */
	target: string;
	level: ApprovalLevel;
	at: number;
}

export interface PluginState {
	config: GuardConfig;
	enabled: boolean;
	/** Targets approved for the rest of this session, keyed by rule signature. */
	grants: Map<string, ApprovalLevel>;
	/** Same, but for every subsequent call (user picked "allow for session"). */
	sessionWide: Set<string>;
	blockedCount: number;
	redactedCount: number;
	redactedValues: number;
	lastBlockTimestamp: number;
	history: BlockRecord[];
}

export function createInitialState(config: GuardConfig = DEFAULT_CONFIG): PluginState {
	return {
		config,
		enabled: true,
		grants: new Map(),
		sessionWide: new Set(),
		blockedCount: 0,
		redactedCount: 0,
		redactedValues: 0,
		lastBlockTimestamp: 0,
		history: [],
	};
}

/** Stable key for a rule hit, so one approval covers repeats of the same thing. */
export function grantKey(tool: string, reason: string, target: string): string {
	return `${tool}::${reason}::${target.toLowerCase()}`;
}

export function recordBlock(state: PluginState, record: BlockRecord): void {
	state.blockedCount++;
	state.lastBlockTimestamp = record.at;
	state.history.unshift(record);
	if (state.history.length > 20) state.history.length = 20;
}

/** Keep target text short enough for a one-line dialog. */
export function truncate(text: string, max = 160): string {
	return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}
