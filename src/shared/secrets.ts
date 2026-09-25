/**
 * Secret value rules for pi-secret-guard — layer 3.
 *
 * Runs on tool *output*, after execution, before the model sees it. This is the
 * safety net for paths the other two layers did not predict: an MCP server that
 * reads a credential file on its own, a script that prints a token, a fixture
 * that happens to contain a live key.
 */

export interface SecretRule {
	kind: string;
	re: RegExp;
	/** When set, only capture group N is kept; the rest of the match is replaced. */
	group?: number;
	/** Replacement used when the rule fires. */
	replacement?: string;
}

/** Values that are obviously placeholders rather than live secrets. */
const PLACEHOLDER_RE =
	/^(?:[x*.]{3,}|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[^%]*%|(?:your|my|the|some|example|sample|test|dummy|fake|placeholder|redacted|changeme|todo)[-_ ]?[a-z0-9_-]*|none|null|true|false|undefined|empty|insert|xxx+)$/i;

/** Marker shape this plugin emits, used to make redaction idempotent. */
const MARKER_RE = /«secret-guard:[^»]*»/g;

function isPlaceholder(value: string): boolean {
	return PLACEHOLDER_RE.test(value.trim());
}

/**
 * Key *segments* for the generic `KEY = value` rule. A key word may be preceded
 * and followed by other name parts, but never glued straight onto a letter or
 * digit — that boundary rule is what keeps `tokenizer`, `monkey` and
 * `authorship` out of the results even though the pattern is case-insensitive.
 */

export const SECRET_RULES: SecretRule[] = [
	{
		kind: "private-key",
		re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
	},
	{ kind: "age-key", re: /AGE-SECRET-KEY-1[0-9A-Z]{58}/g },
	// Provider prefixes, ordered so the longer forms win over `sk-`.
	{ kind: "anthropic-key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
	{ kind: "openai-project-key", re: /\bsk-proj-[A-Za-z0-9_-]{20,}/g },
	{ kind: "openai-key", re: /\bsk-(?!ant-|proj-)[A-Za-z0-9_-]{20,}/g },
	{ kind: "github-pat", re: /\bgithub_pat_[A-Za-z0-9_]{20,}/g },
	{ kind: "github-token", re: /\bgh[pousr]_[A-Za-z0-9]{20,}/g },
	{ kind: "gitlab-token", re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
	{ kind: "slack-token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/g },
	{ kind: "slack-app-token", re: /\bxapp-[A-Za-z0-9-]{10,}/g },
	{ kind: "slack-webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g },
	{ kind: "aws-access-key", re: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
	{ kind: "google-api-key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
	{ kind: "npm-token", re: /\bnpm_[A-Za-z0-9]{36}\b/g },
	{ kind: "pypi-token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}/g },
	{ kind: "stripe-key", re: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g },
	{ kind: "sendgrid-key", re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g },
	{ kind: "telegram-token", re: /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g },
	{ kind: "huggingface-token", re: /\bhf_[A-Za-z0-9]{30,}/g },
	{ kind: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
	// Keep the scheme (and the trailing `@`) so the line still reads as a URL.
	{
		kind: "basic-auth-url",
		re: /(\b[a-z][a-z0-9+.-]*:\/\/)[^\s:@/]+:[^\s@/]{3,}(?=@)/gi,
		group: 1,
	},
	{ kind: "bearer-token", re: /\b(Bearer\s+)[A-Za-z0-9._~+/-]{20,}=*/g, group: 1 },
];

/**
 * The generic catch-all: a real `key = value` shape with a long, non-placeholder
 * value. This is what catches bespoke internal tokens no prefix rule knows.
 */
const ASSIGNMENT_RE = new RegExp(
	String.raw`(?<![A-Za-z0-9])((?:[A-Za-z0-9.\-]*[_.\-])?(?:API[_.\-]?KEY|ACCESS[_.\-]?KEY|SECRET[_.\-]?KEY|PRIVATE[_.\-]?KEY|APIKEY|SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|CREDENTIALS?|AUTH|BEARER|JWT|COOKIE)(?:[_.\-][A-Za-z0-9.\-]+)*)(?![A-Za-z0-9])(\s*[:=]\s*)(["']?)([^\s"',;)\]}]{12,})\3`,
	"gi",
);

/** Stands in for an already-redacted span while the generic pass runs. */
const MASK_RE = /\u0000(\d+)\u0000/g;

export interface RedactionResult {
	text: string;
	/** Number of values replaced. */
	count: number;
	/** Kinds that fired, for the notification line. */
	kinds: Set<string>;
}

/**
 * Replace secret-shaped values in arbitrary text.
 *
 * Prefix rules run first so their replacements (which contain no `=` and no
 * long tokens) cannot be re-matched by the generic assignment rule.
 */
export function redactSecrets(
	input: string,
	extraRules: SecretRule[] = [],
): RedactionResult {
	const kinds = new Set<string>();
	let count = 0;
	let text = input;

	for (const rule of [...SECRET_RULES, ...extraRules]) {
		const replacement = rule.replacement ?? `«secret-guard:${rule.kind}»`;
		text = text.replace(rule.re, (...args: unknown[]) => {
			const whole = args[0] as string;
			if (rule.group !== undefined) {
				const kept = args[rule.group] as string | undefined;
				if (typeof kept !== "string") return whole;
				kinds.add(rule.kind);
				count++;
				return kept + replacement;
			}
			if (rule.kind !== "private-key" && isPlaceholder(whole)) return whole;
			kinds.add(rule.kind);
			count++;
			return replacement;
		});
	}

	// Mask existing markers, run the generic pass, then restore them verbatim.
	// Without this the marker's own kind name — `private-key` — reads as a key
	// name, and redaction is not idempotent.
	const markers: string[] = [];
	text = text.replace(MARKER_RE, (m) => {
		markers.push(m);
		return `\u0000${markers.length - 1}\u0000`;
	});

	ASSIGNMENT_RE.lastIndex = 0;
	text = text.replace(
		ASSIGNMENT_RE,
		(match: string, key: string, sep: string, quote: string, value: string) => {
			if (isPlaceholder(value)) return match;
			kinds.add("assigned-secret");
			count++;
			return `${key}${sep}${quote}«secret-guard:assigned-secret»${quote}`;
		},
	);

	MASK_RE.lastIndex = 0;
	text = text.replace(MASK_RE, (_m, i: string) => markers[Number(i)] ?? "");

	return { text, count, kinds };
}
