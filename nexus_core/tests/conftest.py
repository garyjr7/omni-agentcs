"""Shared fixtures for the current CLI test suite."""

import os

import pytest

from nexus_core.tests.onboarding_support import onboarding_env  # noqa: F401 - pytest fixture


@pytest.fixture(autouse=True)
def _neutralize_no_color(request):
    """Isolate inherited color preferences; explicit no_color_env tests own them."""
    if "no_color_env" in request.fixturenames:
        yield
        return
    original = os.environ.pop("NO_COLOR", None)
    try:
        yield
    finally:
        if original is not None:
            os.environ["NO_COLOR"] = original
        else:
            os.environ.pop("NO_COLOR", None)
