/**
 * code-scanner plugin for OpenClaw.
 *
 * Registers a `before_tool_call` hook that intercepts `exec` tool calls,
 * pipes them through the Python code_scanner for security analysis, and
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

      const input = JSON.stringify({
        tool_name: event.toolName,
        tool_input: event.params,
      });

      try {
        const proc = spawnSync("agent-sec-cli", ["code-scan", "--mode", "openclaw"], {
          input,
          encoding: "utf-8",
          timeout: TIMEOUT_MS,
          stdio: ["pipe", "pipe", "pipe"],
        });

        if (proc.status !== 0 || proc.error) {
          // Fail open — scanner failure should not block the user
          return {};
        }

        const result = JSON.parse(proc.stdout.trim());
        if (result.skip) {
          return { skip: true, skipReason: result.skipReason || "Blocked by code-scanner" };
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
