import test from "node:test";
import assert from "node:assert/strict";
import { checkPath, normalizePath, basename } from "../src/shared/paths.js";

const blocked = (p: string) => checkPath(p).blocked;

test("normalizes Windows separators", () => {
	assert.equal(normalizePath("C:\\Users\\x\\.env"), "C:/Users/x/.env");
	assert.equal(basename("C:\\Users\\x\\.env"), ".env");
});

test("blocks .env and every real variant", () => {
	for (const p of [
		".env",
		"app/.env",
		"C:\\proj\\.env",
		".env.local",
		".env.production",
		"/srv/api/.env.staging",
	]) {
		assert.equal(blocked(p), true, `expected block for ${p}`);
	}
});

test("allows .env templates — onboarding must not prompt", () => {
	for (const p of [".env.example", ".env.sample", ".env.template", "docs/.env.dist"]) {
		assert.equal(blocked(p), false, `expected allow for ${p}`);
	}
});

test("blocks key material and every file under .ssh, public half included", () => {
	for (const p of [
		"certs/server.pem",
		"keys/private.key",
		"bundle.p12",
		"store.jks",
		"~/.ssh/id_rsa",
		"~/.ssh/id_ed25519",
		"~/.ssh/config",
	]) {
		assert.equal(blocked(p), true, `expected block for ${p}`);
	}
	assert.equal(blocked("certs/server.crt"), false);
});

test("a directory named .env is still a secret path", () => {
	assert.equal(blocked("test/fixtures/.env"), true);
});

test("blocks credential dotfiles and stores", () => {
	for (const p of [
		"/home/u/.npmrc",
		"/home/u/.netrc",
		"/home/u/.aws/credentials",
		"/home/u/.config/gcloud/credentials.db",
		"/home/u/.docker/config.json",
		"/home/u/.config/gh/hosts.yml",
		"/home/u/.gnupg/secring.gpg",
		"C:/Users/u/.pi/agent/auth.json",
		"C:/Users/u/AppData/Roaming/Microsoft/Credentials/abc",
		"/home/u/Library/Keychains/login.keychain-db",
		"service-account.json",
		"gcp-prod-credentials.json",
	]) {
		assert.equal(blocked(p), true, `expected block for ${p}`);
	}
});

test("does not block ordinary source files", () => {
	for (const p of [
		"src/index.ts",
		"package.json",
		"docs/keys.md",
		"src/tokenizer.rs",
		"src/monkey.js",
		"config/app.settings.json",
		"test/fixtures/env.sample",
	]) {
		assert.equal(blocked(p), false, `expected allow for ${p}`);
	}
});

test("allowlist wins over every rule", () => {
	const opts = { allowed: ["c:/proj/fixtures"] };
	assert.equal(checkPath("c:/proj/fixtures/.env", opts).blocked, false);
	assert.equal(checkPath("c:/other/.env", opts).blocked, true);
});
