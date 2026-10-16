"""Trusted package recipes shipped with Omni; model input never supplies argv."""

from __future__ import annotations

import json
from typing import Any
from pathlib import Path


def validate_recipes(value: object) -> dict[str, Any]:
    """Fail before planning an installation when the trusted catalog is malformed."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError("recipe catalog must be a mapping")
    names = {name.lower() for name in value}

    def argv(command: object) -> None:
        if (
            not isinstance(command, list)
            or not command
            or not all(
                isinstance(arg, str) and arg and not any(char in arg for char in "\x00\r\n")
                for arg in command
            )
        ):
            raise ValueError("recipe command must be a nonempty string argv")

    for recipe in value.values():
        if not isinstance(recipe, dict) or not isinstance(recipe.get("recipes"), dict):
            raise ValueError("invalid recipe entry")
        argv(recipe.get("verify"))
        aliases = recipe.get("aliases", [])
        if not isinstance(aliases, list):
            raise ValueError("recipe aliases must be a list")
        for alias in aliases:
            if not isinstance(alias, str) or not alias.strip() or alias.lower() in names:
                raise ValueError("ambiguous recipe alias")
            names.add(alias.lower())
        for spec in recipe["recipes"].values():
            if not isinstance(spec, dict) or type(spec.get("sudo")) is not bool:
                raise ValueError("invalid installation recipe")
            argv(spec.get("command"))
            if "verify" in spec:
                argv(spec["verify"])
    return value


def load_recipes() -> dict[str, Any]:
    with (Path(__file__).parent / "data/install_recipes.json").open(encoding="utf-8") as stream:
        return validate_recipes(json.load(stream))


def find_tool_recipe(tool_name: str) -> dict[str, Any] | None:
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
        return dict(recipe)
    wanted = str(tool_name or "").strip().lower()
    if not wanted:
        return None
    for candidate in recipes.values():
        aliases = candidate.get("aliases") if isinstance(candidate, dict) else None
        if any(str(alias).strip().lower() == wanted for alias in (aliases or ())):
            return dict(candidate)
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


def preferred_manager(
    tool_name: str, managers: tuple[str, ...], prefer_user: bool = True
) -> str | None:
    available = available_recipes(tool_name, managers)
    if prefer_user:
        available.sort(key=lambda name: name not in {"go", "cargo", "pipx", "brew"})
    return available[0] if available else None
