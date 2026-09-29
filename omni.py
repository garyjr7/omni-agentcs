#!/usr/bin/env python3
"""Entry point del CLI omni."""

import sys
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "nexus_core"))

from dotenv import load_dotenv


def main(argv=None) -> int:
    # No files, wizard, or environment mutation at import time.
    load_dotenv(ROOT / ".env", override=False)
    from nexus_core.cli.main import build_parser, main as cli_main
    from nexus_core.config.xdg import resolve_xdg_paths
    from nexus_core.config.loader import ConfigError, apply_environment, load_config, save_config
    from nexus_core.cli.wizard import WizardAborted, run_wizard, should_run_wizard

    args = build_parser().parse_args(argv)
    paths = resolve_xdg_paths()
    if args.config_path:
        print(paths.config_file)
        return 0
    try:
        paths.ensure_dirs()
        if args.reset_config and paths.config_file.exists():
            backup = paths.config_file.with_name(
                "config.toml.reset." + str(time.time_ns()) + ".bak"
            )
            paths.config_file.replace(backup)
            backup.chmod(0o600)
        config = load_config(paths)
        if args.config:
            from nexus_core.provisioner.installer import open_editor

            if not paths.config_file.exists():
                save_config(config, paths)
            return open_editor(paths.config_file)
        if args.doctor:
            from nexus_core.cli.doctor import run_doctor

            return run_doctor(paths, config, as_json=args.json)
        if args.json:
            print("--json requiere --doctor", file=sys.stderr)
            return 2
        if should_run_wizard(paths, force_no_wizard=args.no_wizard):
            config = run_wizard(paths)
        elif args.reset_config:
            save_config(config, paths)
        apply_environment(config, paths)
        os.environ.setdefault(
            "NEXUS_LLM_DEFAULT_PROVIDER", os.getenv("LLM_PROVIDER", config.llm.default_provider)
        )
        return cli_main(argv, config=config, paths=paths)
    except WizardAborted:
        print("Onboarding cancelado.", file=sys.stderr)
        return 1
    except (ConfigError, OSError, ValueError) as exc:
        print(
            f"No se pudo completar onboarding/configuración ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
