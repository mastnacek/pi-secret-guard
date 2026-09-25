import test from "node:test";
import assert from "node:assert/strict";
import { redactSecrets } from "../src/shared/secrets.js";

const MARK = "«secret-guard:";

function scrubbed(text: string): boolean {
	return redactSecrets(text).text.includes(MARK);
}

test("redacts provider token prefixes", () => {
	for (const secret of [
		"sk-ant-api03-" + "a".repeat(40),
		"sk-proj-" + "b".repeat(40),
		"sk-" + "c".repeat(40),
		"github_pat_" + "d".repeat(30),
		"ghp_" + "e".repeat(36),
		"glpat-" + "f".repeat(20),
		"xoxb-1234567890-abcdefghij",
		"AKIAIOSFODNN7EXAMPLE",
		"AIza" + "g".repeat(35),
		"npm_" + "h".repeat(36),
		"hf_" + "i".repeat(34),
	]) {
		assert.ok(scrubbed(secret), `expected redaction for ${secret.slice(0, 12)}…`);
	}
});

test("redacts a whole PEM block, delimiters included", () => {
	const pem = [
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEowIBAAKCAQEAx0000",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"-----END RSA PRIVATE KEY-----",
	].join("\n");
	const out = redactSecrets(pem);
	assert.equal(out.count, 1);
	assert.ok(!out.text.includes("MIIEowIBAAKCAQEAx"));
	assert.ok(!out.text.includes("-----BEGIN"));
	assert.equal(out.text, "«secret-guard:private-key»");
});

test("redacts generic KEY=value assignments", () => {
	const out = redactSecrets("DATABASE_PASSWORD=hunter2hunter2hunter2");
	assert.ok(out.text.includes(MARK));
	assert.ok(!out.text.includes("hunter2hunter2hunter2"));
	assert.ok(out.text.startsWith("DATABASE_PASSWORD="));
});

test("keeps placeholders and ordinary code intact", () => {
	for (const line of [
		'const apiKey = "your-api-key-here";',
		"password: <your-password>",
		'api_key = "${API_KEY}"',
		"const tokenizer = getTokenizer();",
		"const monkey = 1;",
		"keyboardLayout = 'us'",
		"// export function readConfig() {}",
		"GITHUB_TOKEN=xxxxx",
	]) {
		const out = redactSecrets(line);
		assert.equal(out.count, 0, `unexpected redaction in: ${line}`);
	}
});

test("redacts credentials embedded in URLs but keeps the scheme", () => {
	const out = redactSecrets("git clone https://user:s3cr3tp4ss@github.com/o/r.git");
	assert.ok(out.text.includes("https://«secret-guard:basic-auth-url»"));
	assert.ok(!out.text.includes("s3cr3tp4ss"));
	assert.ok(out.text.endsWith("@github.com/o/r.git"));
});

test("redacts bearer tokens and JWTs", () => {
	assert.ok(scrubbed("Authorization: Bearer abcdefghij0123456789ABCDEFGH"));
	assert.ok(scrubbed("eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2Q"));
});

test("is idempotent — a second pass finds nothing new", () => {
	const once = redactSecrets("key = abcdefghijklmnop").text;
	const twice = redactSecrets(once);
	assert.equal(twice.count, 0);
	assert.equal(twice.text, once);
});

test("honours user-supplied rules and skips broken ones", () => {
	const rules = [
		{ kind: "internal", re: /INT-[0-9]{6}/g },
		{ kind: "broken", re: null as unknown as RegExp },
	];
	const out = redactSecrets("ticket INT-123456", rules);
	assert.ok(out.text.includes("«secret-guard:internal»"));
});
