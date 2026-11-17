#!/usr/bin/env python3
"""Write the runtime tool catalog as JSON (V1-8).

The inventory used to be maintained by hand, so it drifted from what the
gateway actually registers (55 ids counted by regex vs 64 in the catalog). This
script is the only writer: the file it produces is compared against the runtime
by ``test_audit_ledger_catalog_and_result_versions_consistent``.

Usage::

    .venv/bin/python scripts/omni_catalog.py                       # stdout
    .venv/bin/python scripts/omni_catalog.py --out docs/.../catalog.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_OUT = Path("docs/audit/catalog.json")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=None, help=f"destination file (default: {DEFAULT_OUT})")
    parser.add_argument("--tenant", default="system")
    args = parser.parse_args(argv)

    from nexus_core.tools.registry import tool_catalog

    catalog = tool_catalog(args.tenant)
    text = json.dumps(catalog, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    if args.out:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        print(f"{catalog['tool_count']} tools -> {destination}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
