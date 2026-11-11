import type { CommandResult } from "../types.js";

// Opaque command results, NOT a CI classifier. No command in this table is run.
export const commandOutcomeFixtures: { name: string; command: string; result: CommandResult }[] = [
  { name: "pending", command: "gh pr checks 42", result: { exitCode: 8, stdout: "CI\tpending\t0\thttps://example.invalid/check\n", stderr: "" } },
  { name: "success", command: "gh pr checks 42", result: { exitCode: 0, stdout: "CI\tpass\t1s\thttps://example.invalid/check\n", stderr: "" } },
  { name: "failed-check", command: "gh pr checks 42", result: { exitCode: 1, stdout: "CI\tfail\t1s\thttps://example.invalid/check\n", stderr: "" } },
  { name: "API-error", command: "gh pr checks 42", result: { exitCode: 1, stdout: "", stderr: "HTTP 502: fixture API error\n" } },
  { name: "authentication-error", command: "gh pr checks 42", result: { exitCode: 4, stdout: "", stderr: "fixture: authentication required\n" } },
  { name: "transport-error", command: "gh pr checks 42", result: { exitCode: 1, stdout: "", stderr: "fixture: failed to connect\n" } }
];
