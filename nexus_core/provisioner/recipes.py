"""Trusted package recipes shipped with Omni; model input never supplies argv."""

import json
from pathlib import Path


def load_recipes() -> dict:
    with (Path(__file__).parent / "data/install_recipes.json").open(encoding="utf-8") as stream:
        return json.load(stream)


def find_tool_recipe(tool_name: str):
    return load_recipes().get(tool_name)


def available_recipes(tool_name: str, managers: tuple[str, ...]) -> list[str]:
    from .detector import detect_os

    recipe = find_tool_recipe(tool_name)
    if not recipe:
        return []
    distro = detect_os().distro
    return [
        name
        for name in managers
        if name in recipe["recipes"]
        and (
            "distros" not in recipe["recipes"][name] or distro in recipe["recipes"][name]["distros"]
        )
    ]


def preferred_manager(tool_name: str, managers: tuple[str, ...], prefer_user: bool = True):
    available = available_recipes(tool_name, managers)
    if prefer_user:
        available.sort(key=lambda name: name not in {"go", "cargo", "pipx", "brew"})
    return available[0] if available else None
