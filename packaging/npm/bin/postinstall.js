#!/usr/bin/env node
"use strict";

// Best-effort: install the Python backend with pipx so `omni` is on PATH.
// Never fail the npm install if pipx or network is unavailable.

const { spawnSync } = require("child_process");

const PYPI_NAME = process.env.OMNI_PYPI_NAME || "omniagentcs";

function has(cmd) {
  return spawnSync(cmd, ["--version"], { stdio: "ignore" }).status === 0;
}

if (!has("pipx")) {
  console.warn(
    "OmniAgentCS: pipx no está disponible. Instala el backend con " +
      "`pipx install " +
      PYPI_NAME +
      "` para usar el comando `omni`."
  );
  process.exit(0);
}

const result = spawnSync("pipx", ["install", "--force", PYPI_NAME], {
  stdio: "inherit",
});

if (result.status !== 0) {
  console.warn(
    "OmniAgentCS: no se pudo instalar el backend automáticamente. " +
      "Ejecuta `pipx install " +
      PYPI_NAME +
      "` manualmente."
  );
}

process.exit(0);
