import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const command = process.argv[2];

if (!["dev", "build", "start"].includes(command)) {
  console.error("Usage: node build/vinext-runner.mjs <dev|build|start>");
  process.exit(64);
}

const cli = fileURLToPath(
  new URL("../node_modules/vinext/dist/cli.js", import.meta.url),
);

const child = spawn(process.execPath, [cli, command], {
  stdio: "inherit",
  env: {
    ...process.env,
    WRANGLER_LOG_PATH:
      process.env.WRANGLER_LOG_PATH ?? ".wrangler/wrangler.log",
  },
});

child.on("error", (error) => {
  console.error(error);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
