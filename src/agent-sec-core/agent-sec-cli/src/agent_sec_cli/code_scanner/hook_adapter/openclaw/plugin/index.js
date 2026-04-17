/**
 * code-scanner plugin for OpenClaw.
 *
 * Registers a `before_tool_call` hook that intercepts `exec` tool calls,
 * invokes `agent-sec-cli code-scan` for security analysis, and
 * returns { skip: true, skipReason } when a dangerous pattern is detected.
 */

const { spawnSync } = require("node:child_process");

const TIMEOUT_MS = 1000;

module.exports = function register(api) {
  api.on(
    "before_tool_call",
    (event) => {
      if (event.toolName !== "exec") {
        return {};
      }

      const command = (event.params && event.params.command) || "";
      if (!command) {
        return {};
      }

      try {
        const proc = spawnSync("agent-sec-cli", ["code-scan", "--code", command, "--language", "bash"], {
          encoding: "utf-8",
          timeout: TIMEOUT_MS,
          stdio: ["pipe", "pipe", "pipe"],
        });

        if (proc.status !== 0 || proc.error) {
          // Fail open — scanner failure should not block the user
          return {};
        }

        const scanResult = JSON.parse(proc.stdout.trim());
        const verdict = scanResult.verdict || "pass";
        const summary = scanResult.summary || "";

        if (verdict === "deny") {
          return { skip: true, skipReason: `[code-scanner] ${summary}` };
        }
        if (verdict === "warn") {
          return { skip: false, skipReason: `[code-scanner] ${summary}` };
        }
        return {};
      } catch {
        // Fail open on any unexpected error
        return {};
      }
    },
    { priority: 100 },
  );
};
