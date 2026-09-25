/**
 * Path rules for pi-secret-guard — layer 1.
 *
 * Decides whether a filesystem path may be handed to the model. Pure text
 * analysis, no filesystem access, so it also works for paths that do not exist.
 *
 * Bias: conservative on the block side, generous on the allow side. A false
 * block costs the user one keystroke in the approval dialog; a missed secret
 * costs them a credential.
 */

/** Normalise Windows separators so one rule set covers both platforms. */
export function normalizePath(p: string): string {
	return p.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
}

/** Lower-cased final path segment, or "" for trailing slashes. */
export function basename(p: string): string {
	const n = normalizePath(p);
	const idx = n.lastIndexOf("/");
	return (idx === -1 ? n : n.slice(idx + 1)).toLowerCase();
}

/**
 * .env variants that are templates, not secrets. Reading these is normal
 * onboarding work and must never prompt.
 */
const ENV_TEMPLATE_NAMES = new Set([
	".env.example",
	".env.sample",
	".env.template",
	".env.dist",
	".env.defaults",
	".env.default",
	".env.schema.example",
	"env.example",
]);

/** Exact basenames that are always credential material. */
const DENY_BASENAMES = new Set([
	".npmrc",
	".pypirc",
	".netrc",
	"_netrc",
	".pgpass",
	".s3cfg",
	".my.cnf",
	".git-credentials",
	".git-credential-cache",
	".git-credential-store",
	".htpasswd",
	".env",
	"credentials",
	"credentials.json",
	"credentials.yaml",
	"credentials.yml",
	"credentials.toml",
	"secrets",
	"secrets.json",
	"secrets.yaml",
	"secrets.yml",
	"secrets.toml",
	"auth.json",
	"authinfo",
	"wallet.dat",
	"keystore",
	"shadow",
]);

/** Suffixes marking key material. `.pub` is public, so it stays readable. */
const DENY_SUFFIXES = [
	".pem",
	".key",
	".p12",
	".pfx",
	".jks",
	".keystore",
	".ppk",
	".keytab",
	".asc",
	".gpg",
	".ovpn",
];

/** Private SSH key names. Their `.pub` counterparts stay readable. */
const DENY_SSH_KEYS = new Set([
	"id_rsa",
	"id_dsa",
	"id_ecdsa",
	"id_ed25519",
	"identity",
]);

const DENY_GLOBS = [
	".env.*",
	"*-credentials.json",
	"*-credentials.yaml",
	"*-credentials.yml",
	"client_secret*.json",
	"client-secret*.json",
	"secrets.*.json",
	"gcloud-service-key*.json",
	"*service-account*.json",
	"*service-account*.key",
	"*.p8",
	"*.p9",
];

function globToRegExp(glob: string): RegExp {
	const escaped = glob
		.replace(/[.+^${}()|[\]\\]/g, "\\$&")
		.replace(/\*\*/g, "\u0000")
		.replace(/\*/g, "[^/]*")
		.replace(/\u0000/g, ".*");
	return new RegExp(`^${escaped}$`, "i");
}

const COMPILED_GLOBS = DENY_GLOBS.map((g) => ({ re: globToRegExp(g), glob: g }));

/**
 * Path segments that mark a whole directory as a credential store. Matched as a
 * full segment, so `/home/x/.aws/config` is fine but `/home/x/.aws/credentials`
 * is not.
 */
const DENY_SEGMENTS = new Set([
	".ssh",
	".gnupg",
	".aws",
	".azure",
	".kube",
	".password-store",
]);

/** Sub-paths inside otherwise-allowed directories that still hold secrets. */
const DENY_SUBPATHS = [
	".docker/config.json",
	".config/gcloud/",
	".config/rclone/",
	".config/gh/hosts.yml",
	".config/secrets/",
	".gem/credentials",
	".cargo/credentials",
	".cargo/credentials.toml",
	"appdata/roaming/microsoft/credentials",
	"appdata/roaming/gh/hosts.yml",
	"library/keychains",
	".local/share/keyrings",
	".pi/agent/auth.json",
	// browser credential stores
	"/logindata",
	"/cookies",
	"/web data",
	"/local state",
	"/login data",
];

export interface PathVerdict {
	blocked: boolean;
	/** Why it was flagged; empty when allowed. */
	reason: string;
}

const ALLOW = (): PathVerdict => ({ blocked: false, reason: "" });
const DENY = (reason: string): PathVerdict => ({ blocked: true, reason });

/**
 * Decide whether a path may be handed to the model.
 *
 * `opts.allowed` short-circuits everything: a user allowlist entry always wins,
 * which is the escape hatch for false positives.
 */
export function checkPath(
	rawPath: string,
	opts: { allowed?: string[] } = {},
): PathVerdict {
	const norm = normalizePath(rawPath).toLowerCase();
	const base = basename(norm);
	if (!base) return ALLOW();

	for (const pattern of opts.allowed ?? []) {
		if (pattern && norm.includes(normalizePath(pattern).toLowerCase())) return ALLOW();
	}

	if (ENV_TEMPLATE_NAMES.has(base)) return ALLOW();

	if (base === ".env" || base.startsWith(".env.")) {
		return DENY(`environment file (${base})`);
	}
	if (DENY_BASENAMES.has(base)) return DENY(`credential file (${base})`);
	if (DENY_SSH_KEYS.has(base)) return DENY(`private SSH key (${base})`);

	for (const suffix of DENY_SUFFIXES) {
		if (base.endsWith(suffix) && !base.endsWith(".pub")) {
			return DENY(`key material (*${suffix})`);
		}
	}
	for (const { re, glob } of COMPILED_GLOBS) {
		if (re.test(base)) return DENY(`credential file (${glob})`);
	}

	for (const seg of norm.split("/").filter(Boolean)) {
		if (DENY_SEGMENTS.has(seg)) return DENY(`credential directory (${seg}/)`);
	}
	for (const sub of DENY_SUBPATHS) {
		const bare = sub.replace(/\/$/, "");
		if (norm.includes(`/${sub}`) || norm.endsWith(`/${bare}`)) {
			return DENY(`credential store (${bare})`);
		}
	}

	return ALLOW();
}
