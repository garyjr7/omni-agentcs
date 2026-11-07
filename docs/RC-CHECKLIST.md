# Checklist de release — `v3.0.0-rc1`

Estado a 2026-11-07. Este documento no crea el tag: enumera lo medido, lo que
queda abierto y las decisiones que requieren autorización explícita.

## Gates ejecutados

| Gate | Comando | Resultado |
| --- | --- | --- |
| Tipos estrictos | `.venv/bin/python -m mypy nexus_core/kernel nexus_core/tools nexus_core/scope` | **0 errores** en 181 ficheros |
| Suite completa | `.venv/bin/python -m pytest nexus_core/tests -q` | **4871 passed, 56 skipped** (363 s) |
| Tests SEC-05 | `.venv/bin/python -m pytest nexus_core/tests/unit/test_tools_trust.py -q` | **7 passed** |
| Ruff (ficheros tocados) | `.venv/bin/ruff check $(git diff --name-only -- '*.py')` | Sin avisos nuevos; quedan avisos preexistentes (`I001` en bloques de imports, `ASYNC230`, `UP017`) fuera del alcance de este cambio |

`TYPECHECK_STRICT_PATHS` en `Makefile:64` cubre `nexus_core/kernel`,
`nexus_core/tools` y `nexus_core/scope`; el comando anterior es exactamente lo
que ejecuta `make typecheck-strict`.

## Seguridad

- **SEC-01 — Parcial.** Shell local con aislamiento opt-in
  (`NEXUS_SHELL_ISOLATION=egress`): bwrap + netns + socat, egreso gobernado por
  scope y `proxychains` envolviendo *todo* comando. Limitación declarada en
  `SECURITY.md`: `nmap` solo funciona con `-sT` (sin SYN/UDP/OS scan).
- **SEC-05 — Cerrado.** Los entry points de `nexus.tools` no se importan sin
  aprobación humana; `tools-trust.json` (0600) fija el SHA-256 de todos los
  ficheros de la distribución y cualquier cambio revoca la confianza. El pin no
  cubre dependencias de la distribución (documentado en `SECURITY.md`).
- Sin `# type: ignore` añadidos en la limpieza de tipos; el estrechamiento se
  hizo con guardas explícitas (`if client is None`, `if scope is None`) y
  `isinstance`.

## Limpieza de tipos realizada

- **Sliver** (56 errores): `build_client()` devuelve `(SliverClient | None,
  ToolResult | None)`; cada handler comprueba `client is None` y devuelve el
  `failure` ya construido, con lo que mypy estrecha el tipo para todo el cuerpo.
- **noPac** (10): `_require_binary()` estrecha los binarios ya verificados por el
  bloque `missing`; ninguna ruta cambió de comportamiento.
- **FTP** (8): `value` se liga a una variable antes de `isinstance`; los kwargs
  del blackboard se pasan explícitos en vez de con `**dict`.
- **Kernel y handlers restantes**: guardas de `context.scope` en `sessions.py`,
  `listener.py`, `ffuf.py`, `ntlm_capture.py`, `msf_session_list.py`;
  `Path(root)` en las dos llamadas de `shell_exec_local.py`; `catalog` anotado
  como `dict[str, tuple[ToolDefinition, Handler]]` en `registry.py`.

## Pendiente antes de publicar

1. **Tag `v3.0.0-rc1`** — no creado; requiere autorización.
2. **Push a GitHub** — no realizado; requiere autorización.
3. **Release en PyPI** (`pipx install omni-agentcs`) — no preparada.
4. **Auditoría comparativa final** — fuera de este repositorio.
5. **Deuda de lint preexistente** — los avisos de ruff listados arriba no son
   del cambio de tipos y no bloquean el RC; conviene un commit aparte.
