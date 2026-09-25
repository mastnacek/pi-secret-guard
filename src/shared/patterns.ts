/**
 * Detection barrel for pi-secret-guard.
 *
 * Slices import from here, never from the leaf modules, so the rule set can be
 * reorganised without touching call sites.
 */

export { normalizePath, basename, checkPath } from "./paths.js";
export type { PathVerdict } from "./paths.js";

export { checkEnvName, checkShellCommand } from "./env.js";
export type { EnvNameVerdict, ShellVerdict } from "./env.js";

export { redactSecrets, SECRET_RULES } from "./secrets.js";
export type { RedactionResult, SecretRule } from "./secrets.js";
