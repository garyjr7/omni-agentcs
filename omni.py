#!/usr/bin/env python3
"""Entry point del CLI omni."""

import sys
import time
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "nexus_core"))



def main(argv: Sequence[str] | None = None) -> int:
    from nexus_core.cli.llm_env import configure_logging, publish_default_provider

    configure_logging()
    # No files, wizard, or environment mutation at import time.
    from nexus_core.config.bootstrap import bootstrap_secrets_and_config

    bootstrap_secrets_and_config(ROOT, load_configuration=False)
    # Respect a log-level preference from .env before onboarding or clients.
    configure_logging()
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
            return int(open_editor(paths.config_file))
        if args.doctor:
            from nexus_core.cli.doctor import run_doctor

            return int(run_doctor(paths, config, as_json=args.json))
        if args.setup:
            from nexus_core.cli.setup import run_setup

            # run_setup reflects config-derived secrets (scope signing, provider
            # keys) before assessing, not only what the shell already exported.
            return int(run_setup(
                paths,
                config,
                install=args.install,
                assume_yes=args.yes,
                as_json=args.json,
            ))
        # ``--json`` is shared by ``--doctor``/``--setup`` and the headless run
        # (``omni run "<objetivo>" --json``): only reject it when neither applies.
        if args.json and not (args.command or args.objective or args.stream_json):
            print("--json requiere --doctor, --setup o un objetivo headless", file=sys.stderr)
            return 2
        if args.reset_config and should_run_wizard(paths, force_no_wizard=args.no_wizard):
            config = run_wizard(paths, root=ROOT)
        elif args.reset_config:
            save_config(config, paths)
        apply_environment(config, paths)
        # One canonical resolution for the CLI, the worker and execute_react: a
        # stale LLM_PROVIDER=fake must not shadow a working real provider.
        publish_default_provider(config)
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
