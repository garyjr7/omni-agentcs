"""Trusted package recipes shipped with Omni; model input never supplies argv."""

import json
from pathlib import Path


def load_recipes() -> dict:
    with (Path(__file__).parent / "data/install_recipes.json").open(encoding="utf-8") as stream:
        return json.load(stream)


def find_tool_recipe(tool_name: str):
    """Resolve a tool name to its recipe, accepting a declared alias.

    A recipe key is the *component id* (``ripgrep``), but the model and the
    preflight reason in binary names (``rg``). Recipes may declare
    ``"aliases": ["rg"]``; without this, ``nexus.system.check_env(tools=["rg"])``
    failed with ``unknown tool`` in the E2E run #2 (B6) instead of reporting the
    missing binary.
    """
    recipes = load_recipes()
    recipe = recipes.get(tool_name)
    if recipe is not None:
        return recipe
    wanted = str(tool_name or "").strip().lower()
    if not wanted:
        return None
    for candidate in recipes.values():
        aliases = candidate.get("aliases") if isinstance(candidate, dict) else None
        if any(str(alias).strip().lower() == wanted for alias in (aliases or ())):
            return candidate
    return None


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
