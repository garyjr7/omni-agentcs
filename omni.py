#!/usr/bin/env python3
"""Entry point del CLI omni."""

import sys
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "nexus_core"))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env", override=False)

from nexus_core.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
