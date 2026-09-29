"""XDG Base Directory paths; empty or relative environment values are ignored."""

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class XdgPaths:
    config_home: Path
    data_home: Path
    state_home: Path
    cache_home: Path

    @property
    def config_dir(self):
        return self.config_home / "omni"

    @property
    def data_dir(self):
        return self.data_home / "omni"

    @property
    def state_dir(self):
        return self.state_home / "omni"

    @property
    def cache_dir(self):
        return self.cache_home / "omni"

    @property
    def config_file(self):
        return self.config_dir / "config.toml"

    @property
    def db_file(self):
        return self.data_dir / "control.db"

    def ensure_dirs(self):
        for path in (self.config_dir, self.data_dir, self.state_dir, self.cache_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)


def resolve_xdg_paths() -> XdgPaths:
    home = Path.home()
    defaults = (home / ".config", home / ".local/share", home / ".local/state", home / ".cache")

    def resolve(name, default):
        value = os.getenv("XDG_" + name + "_HOME", "")
        return Path(value) if value and Path(value).is_absolute() else default

    return XdgPaths(
        *(
            resolve(name, default)
            for name, default in zip(
                ("CONFIG", "DATA", "STATE", "CACHE"),
                defaults,
            )
        )
    )
