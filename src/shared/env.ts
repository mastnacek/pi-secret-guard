/**
 * Environment-variable rules for pi-secret-guard — layer 2.
 *
 * Catches two shapes: commands that dump the whole environment, and commands
 * that name a specific secret-bearing variable. Matching on whole
 * underscore-delimited segments is what keeps `TOKENIZERS_PARALLELISM` and
 * `KEYBOARD_LAYOUT` out of the results.
 */

/** Segments that mark a variable as secret-bearing. */
const SECRET_NAME_SEGMENTS = new Set([
	"KEY",
	"KEYS",
	"APIKEY",
	"ACCESSKEY",
	"SECRETKEY",
	"PRIVATEKEY",
	"SECRET",
	"SECRETS",
	"TOKEN",
	"TOKENS",
	"BEARER",
	"PASSWORD",
	"PASSWD",
	"PASSPHRASE",
	"CREDENTIAL",
	"CREDENTIALS",
	"JWT",
	"COOKIE",
]);

/**
 * Segments meaning the variable *describes* a secret rather than being one
 * (`SSH_KEY_PATH`, `GITHUB_TOKEN_NAME`, `ENCRYPTION_KEY_TYPE`).
 */
const NON_SECRET_NAME_SEGMENTS = new Set([
	"PATH",
	"PATHS",
	"FILE",
	"DIR",
	"NAME",
	"NAMES",
	"ID",
	"ENABLED",
	"MODE",
	"TYPE",
	"KIND",
	"LENGTH",
	"SIZE",
	"COUNT",
	"MAX",
	"MIN",
	"LIMIT",
	"TTL",
	"ROTATION",
	"EXPIRY",
	"EXPIRATION",
	"FORMAT",
	"ALGORITHM",
	"PUBLIC",
	"PUBLIK",
	"CERT",
	"CERTS",
	"ALLOWLIST",
	"WHITELIST",
	"PREFIX",
	"SUFFIX",
	"URL",
	"PROVIDER",
	"SCOPE",
]);

export interface EnvNameVerdict {
	blocked: boolean;
	reason: string;
}

/** Glob matcher supporting `*` and `?`, case-insensitive. */
function nameMatches(name: string, pattern: string): boolean {
	const rx = new RegExp(
		`^${pattern
			.replace(/[.+^${}()|[\]\\]/g, "\\$&")
			.replace(/\*/g, ".*")
			.replace(/\?/g, ".")}$`,
		"i",
	);
	return rx.test(name);
}

export function checkEnvName(
	name: string,
	opts: { allowed?: string[] } = {},
): EnvNameVerdict {
	const upper = name.toUpperCase();

	for (const pattern of opts.allowed ?? []) {
		if (pattern && nameMatches(upper, pattern.toUpperCase())) {
			return { blocked: false, reason: "" };
		}
	}

	const segments = upper.split(/[^A-Z0-9]+/).filter(Boolean);
	// Descriptive names win over secret-looking ones: SSH_KEY_PATH is a path.
	for (const seg of segments) {
		if (NON_SECRET_NAME_SEGMENTS.has(seg)) return { blocked: false, reason: "" };
	}
	for (const seg of segments) {
		if (SECRET_NAME_SEGMENTS.has(seg)) {
			return { blocked: true, reason: `secret env var (${upper})` };
		}
	}
	return { blocked: false, reason: "" };
}

/** Every env-var reference form the shells accept. */
const ENV_REFERENCE_PATTERNS: RegExp[] = [
	/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g,
	/\$env:([A-Za-z_][A-Za-z0-9_]*)/gi,
	/\$([A-Za-z_][A-Za-z0-9_]{2,})/g,
	/%([A-Za-z_][A-Za-z0-9_]*)%/g,
	/getenvironmentvariable\(\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*\)/gi,
];

/** Commands that dump the whole environment in one shot. */
const ENV_DUMP_PATTERNS: RegExp[] = [
	/(^|[;&|(]\s*|\$\(\s*)(env|printenv)\s*($|[;&|)\s])/,
	/(^|[;&|(]\s*)(export|declare)\s+-p\b/,
	/(^|[;&|(]\s*)set\s*($|[;&|)])/,
	/\b(get-childitem|get-item|gci|dir|ls)\s+env:/i,
	/\bset\s*\|\s*(findstr|more|type|sort|select)/i,
	/\bprintenv\s*\|\s*(head|more|less|cat)/,
];

/** CLIs whose sole purpose is handing out a live credential. */
const CREDENTIAL_CLI_PATTERNS: RegExp[] = [
	/\bcmdkey\s+\/list\b/i,
	/\bsecurity\s+dump-keychain\b/i,
	/\bsecret-tool\s+search\b/i,
	/\bgcloud\s+auth\s+print-access-token\b/i,
	/\bgh\s+auth\s+token\b/i,
	/\bgh\s+auth\s+refresh\b/i,
	/\baws\s+configure\s+get\b/i,
	/\baws\s+sts\s+get-session-token\b/i,
	/\bgpg\s+--export-secret-keys?\b/i,
	/\bpass\s+(show|ls)\b/i,
	/\bvault\s+(read|kv\s+get)\b/i,
	/\bkeyctl\s+(keyring|list)\b/i,
	/\bget-credential\b/i,
	/\bexport-clixml\b/i,
	/\bdpapi\s*::\s*unprotect\b/i,
];

export interface ShellVerdict {
	blocked: boolean;
	reason: string;
}

/**
 * Inspect a shell command for environment exfiltration.
 *
 * Pure text analysis: it cannot see what a script does after `node -e` or
 * `python -c`, which is exactly why the output-redaction layer exists as well.
 */
export function checkShellCommand(
	command: string,
	opts: { allowedEnvNames?: string[]; extraEnvDumpPatterns?: string[] } = {},
): ShellVerdict {
	for (const re of ENV_DUMP_PATTERNS) {
		if (re.test(command)) return { blocked: true, reason: "environment dump command" };
	}
	for (const pattern of opts.extraEnvDumpPatterns ?? []) {
		try {
			if (new RegExp(pattern, "i").test(command)) {
				return { blocked: true, reason: `environment dump command (${pattern})` };
			}
		} catch {
			// A malformed user pattern must never break the guard.
		}
	}
	for (const re of CREDENTIAL_CLI_PATTERNS) {
		if (re.test(command)) {
			return { blocked: true, reason: "credential-export command" };
		}
	}

	const seen = new Set<string>();
	for (const re of ENV_REFERENCE_PATTERNS) {
		re.lastIndex = 0;
		let m: RegExpExecArray | null;
		while ((m = re.exec(command)) !== null) {
			const name = m[1];
			if (name === undefined) continue;
			const upper = name.toUpperCase();
			if (seen.has(upper)) continue;
			seen.add(upper);
			const verdict = checkEnvName(name, { allowed: opts.allowedEnvNames });
			if (verdict.blocked) return verdict;
			if (m.index === re.lastIndex) re.lastIndex++;
		}
	}

	return { blocked: false, reason: "" };
}
