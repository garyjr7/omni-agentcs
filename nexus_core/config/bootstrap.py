"""Shared CLI/worker startup: shell > .env > secret store; no import side effects."""
from pathlib import Path


def bootstrap_secrets_and_config(root, *, load_configuration=True):
    from dotenv import load_dotenv
    from .secrets import load_secrets_into_env
    from .loader import load_config, apply_environment
    from .xdg import resolve_xdg_paths

    load_dotenv(Path(root) / ".env", override=False)
    load_secrets_into_env()
    if not load_configuration:
        return None
    paths = resolve_xdg_paths()
    config = load_config(paths)
    apply_environment(config, paths)
    return paths, config
