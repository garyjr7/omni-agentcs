"""Extensible tool registration (audit finding H7).

The durable catalog used to be a single literal dict inside
:mod:`nexus_core.tools.registry`, so adding a tool meant editing a kernel module
and every new capability (skills, MCP, plugins) had to patch the core. This
module introduces ``@register_tool`` plus discovery, so a builtin handler, an
in-repo plugin or a third-party package can contribute a tool **without touching
the core**.

Two discovery sources are supported:

* **package scan** — every module under :data:`HANDLER_PACKAGE` is imported once
  so module-level decorators run;
* **entry points** — distributions publishing the :data:`ENTRY_POINT_GROUP`
  entry-point group are loaded, and their targets register on import.

Discovery is *additive and non-fatal*: a module that fails to import is recorded
in the report and skipped, so a broken plugin can never take down the catalog.
Builtins keep precedence unless a registration opts in with ``replace=True``.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any, Awaitable, Callable

from nexus_core.kernel.models import RunContext, ToolDefinition, ToolResult

Handler = Callable[[dict[str, Any], RunContext], Awaitable[ToolResult]]
DefinitionFactory = Callable[[str], ToolDefinition]

#: Package scanned for builtin tools that self-register.
HANDLER_PACKAGE = "nexus_core.tools.handlers"
#: Entry-point group third-party distributions publish tools under.
ENTRY_POINT_GROUP = "nexus.tools"


@dataclass(frozen=True)
class ToolRegistration:
    """One tool contribution: how to build its definition and its handler."""

    tool_id: str
    definition_factory: DefinitionFactory
    handler: Handler
    source: str = "builtin"
    replace: bool = False

    def resolve_definition(self, tenant_id: str) -> ToolDefinition:
        """Build the concrete definition for ``tenant_id``."""
        return self.definition_factory(tenant_id)


@dataclass(frozen=True)
class DiscoveryReport:
    """Outcome of one discovery pass (counts + non-fatal import errors)."""

    modules: int = 0
    entry_points: int = 0
    errors: tuple[tuple[str, str], ...] = ()


_REGISTRATIONS: dict[str, ToolRegistration] = {}
_state: dict[str, Any] = {"done": False, "modules": 0, "entry_points": 0, "errors": []}


def register(
    tool_id: str,
    definition_factory: DefinitionFactory,
    handler: Handler,
    *,
    source: str = "builtin",
    replace: bool = False,
) -> ToolRegistration:
    """Register (or replace) a tool programmatically. Returns the registration."""
    registration = ToolRegistration(
        tool_id=str(tool_id),
        definition_factory=definition_factory,
        handler=handler,
        source=source,
        replace=replace,
    )
    _REGISTRATIONS[registration.tool_id] = registration
    return registration


def register_tool(
    tool_id: str,
    definition: ToolDefinition | DefinitionFactory | None = None,
    *,
    definition_factory: DefinitionFactory | None = None,
    source: str = "builtin",
    replace: bool = False,
):
    """Decorator registering ``handler`` under ``tool_id``.

    ``definition`` may be a :class:`ToolDefinition` (per-tenant factories are
    preferred) or a factory ``(tenant_id) -> ToolDefinition``. ``definition_factory``
    is an explicit alias. The decorated function is returned unchanged, so the
    handler keeps its own name.
    """
    factory: DefinitionFactory
    if definition_factory is not None:
        factory = definition_factory
    elif definition is None:
        raise TypeError("register_tool requires definition or definition_factory")
    elif isinstance(definition, ToolDefinition):
        frozen = definition

        def factory(_tenant_id: str) -> ToolDefinition:
            return frozen

    else:
        factory = definition

    def decorator(handler: Handler) -> Handler:
        register(tool_id, factory, handler, source=source, replace=replace)
        return handler

    return decorator


def registered_tools() -> dict[str, ToolRegistration]:
    """Snapshot of every explicit registration (excluding discoveries)."""
    return dict(_REGISTRATIONS)


def unregister(tool_id: str) -> bool:
    """Remove one explicit registration; returns whether it existed.

    Used by dynamic sources (MCP) that re-sync their catalog: a tool that is no
    longer allowlisted must disappear instead of lingering from a previous sync.
    """
    return _REGISTRATIONS.pop(str(tool_id), None) is not None


def clear_registrations() -> None:
    """Drop every registration and reset discovery state (tests)."""
    _REGISTRATIONS.clear()
    reset_discovery()


def reset_discovery() -> None:
    """Forget that discovery already ran, so the next call scans again."""
    _state.update(done=False, modules=0, entry_points=0, errors=[])


def _scan_package(package: str) -> tuple[int, list[tuple[str, str]]]:
    module = importlib.import_module(package)
    imported = 0
    errors: list[tuple[str, str]] = []
    for info in pkgutil.iter_modules(list(module.__path__)):
        name = f"{package}.{info.name}"
        try:
            importlib.import_module(name)
            imported += 1
        except Exception as exc:  # noqa: BLE001 - a broken plugin must not fatal
            errors.append((name, f"{type(exc).__name__}: {exc}"))
    return imported, errors


def _load_entry_points() -> tuple[int, list[tuple[str, str]]]:
    loaded = 0
    errors: list[tuple[str, str]] = []
    try:
        try:
            selected = list(entry_points(group=ENTRY_POINT_GROUP))
        except TypeError:  # pragma: no cover - pre-3.10 importlib API
            selected = list(entry_points().get(ENTRY_POINT_GROUP, []))
    except Exception:  # noqa: BLE001 - metadata is best-effort
        return 0, []
    for entry in selected:
        try:
            entry.load()
            loaded += 1
        except Exception as exc:  # noqa: BLE001 - a broken distribution must not fatal
            errors.append((f"{ENTRY_POINT_GROUP}:{getattr(entry, 'name', '?')}", f"{type(exc).__name__}: {exc}"))
    return loaded, errors


def discover(*, package: str = HANDLER_PACKAGE, force: bool = False) -> DiscoveryReport:
    """Import self-registering modules once; return the discovery report.

    Idempotent: repeated calls are cheap no-ops unless ``force=True``.
    """
    if _state["done"] and not force:
        return DiscoveryReport(
            modules=_state["modules"],
            entry_points=_state["entry_points"],
            errors=tuple(_state["errors"]),
        )
    modules, package_errors = _scan_package(package)
    entry_points_count, entry_errors = _load_entry_points()
    _state.update(
        done=True,
        modules=modules,
        entry_points=entry_points_count,
        errors=[*package_errors, *entry_errors],
    )
    return DiscoveryReport(
        modules=modules,
        entry_points=entry_points_count,
        errors=tuple(_state["errors"]),
    )


def discovered_registrations() -> dict[str, ToolRegistration]:
    """Registrations from decorators/entry points, after ensuring discovery ran."""
    discover()
    return registered_tools()


__all__ = [
    "ENTRY_POINT_GROUP",
    "HANDLER_PACKAGE",
    "DiscoveryReport",
    "ToolRegistration",
    "clear_registrations",
    "discover",
    "discovered_registrations",
    "register",
    "register_tool",
    "registered_tools",
    "reset_discovery",
    "unregister",
]
