#!/usr/bin/env node
"use strict";

// Thin npm shim: delegate to the Python CLI installed by pipx/venv.
// The real work lives in the Python package; this only forwards argv/stdin/stdout.

const { spawnSync } = require("child_process");

const result = spawnSync("omni", process.argv.slice(2), { stdio: "inherit" });

if (result.error && result.error.code === "ENOENT") {
  console.error(
    "OmniAgentCS: no se encontró el binario `omni` en PATH.\n" +
      "Instálalo con `pipx install omniagentcs` o ejecuta scripts/install.sh."
  );
  process.exit(127);
}

process.exit(result.status === null ? 1 : result.status);
