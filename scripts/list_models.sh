#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT/.venv/bin/python" - "$ROOT" <<'PYTHON'
import sys
from pathlib import Path
from dotenv import load_dotenv
import os
import httpx
load_dotenv(Path(sys.argv[1]) / ".env", override=False)
key = os.getenv("GROQ_API_KEY", "")
if not key:
    raise SystemExit("Configura GROQ_API_KEY en el entorno o .env")
response = httpx.get("https://api.groq.com/openai/v1/models",
                     headers={"Authorization": "Bearer " + key}, timeout=15)
response.raise_for_status()
for model in response.json().get("data", []):
    print(model["id"])
PYTHON
