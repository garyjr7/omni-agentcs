import pytest
from nexus_core.provisioner.recipes import (
    available_recipes,
    find_tool_recipe,
    load_recipes,
    preferred_manager,
)

pytestmark = pytest.mark.usefixtures("onboarding_env")


def test_load_recipes_valid_json():
    recipes = load_recipes()
    assert len(recipes) == 10
    assert all({"description", "purpose", "verify", "recipes"} <= set(r) for r in recipes.values())


def test_find_tool_recipe_returns_dict():
    assert isinstance(find_tool_recipe("nmap"), dict)


def test_find_tool_recipe_unknown_returns_none():
    assert find_tool_recipe("unknown") is None


def test_available_recipes_filters_by_managers():
    assert available_recipes("nmap", ("apt", "go")) == ["apt"]


def test_preferred_manager_prefers_user_install():
    assert preferred_manager("ffuf", ("apt", "go")) == "go"


def test_preferred_manager_falls_back_to_system():
    assert preferred_manager("nmap", ("apt", "go")) == "apt"
