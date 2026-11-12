# Auditoría previa del cleanup

Fecha: 2026-09-29. Rama: `chore/final-cleanup`. Base: `5885267`.
Estado: **DETENIDO antes de borrar o mover archivos**.

## 1. Imports de nexus_api

Se ejecutó la búsqueda solicitada sobre nexus_core/, omni.py, nexus_worker.py
y tests/, excluyendo nexus_core/tests/ del resultado. Sin coincidencias.
También se buscaron referencias textuales en todas las rutas protegidas del
punto 4: sin referencias a nexus_api, nexus_mcp, junior_jarvis,
bajioware_landing, factory_runner o nexus_frontend.

La búsqueda ampliada en otros módulos encontró referencias legacy:

- nexus_core/agents/generated/kill_switch_agent.py:17: nexus_api/main.py.
- nexus_core/agents/generated/project_manager_agent.py:5: DB en nexus_api/database.db.
- nexus_core/agents/generated/guardian_agent.py:73: directorio nexus_api.

Esas rutas no pertenecen a la lista protegida (agents/ plural es distinto de
agent/), pero necesitan clasificarse antes de declarar eliminado todo el legacy.
No se autoriza un borrado a partir de esta auditoría parcial.

## 2. Imports de nexus_mcp

Búsqueda solicitada sobre nexus_core/, omni.py y nexus_worker.py: sin coincidencias.

## 3. DB activa y engagements

`omni --doctor --no-wizard` confirmó:

```text
Base de datos:
  path: "/home/<operador>/NEXUS/data/nexus_pro.db"
  exists: true
  size_bytes: 630784
  backend: "sqlite"
  diagnostic: "local read-only"
```

El destino predeterminado `/home/<operador>/.local/share/omni/control.db` no existe.
La DB de data/ NO se puede borrar. Antes de retirarla deberá hacerse una copia
consistente SQLite, ajustar la configuración efectiva que hoy apunta a data/,
y comprobar los mismos engagements consultando realmente el destino XDG.
Una simple copia sin cambiar la configuración seguiría consultando el original.

Salida real de `.venv/bin/python omni.py --list-engagements --no-wizard`:

```text
  eng-scanme               scanme-lab                   cliente=NEXUS  hasta 2030-01-01T00:00:00+00:00
```

No se migró, respaldó ni eliminó la DB durante esta misión.

## 4. tests/ y scripts/

`tests/` contiene únicamente el directorio vacío `manual/`.
`find tests -type f -name '*.py'`, `find tests -type f` y `git ls-files tests`
no devolvieron archivos. La suite de 470 tests está en nexus_core/tests/unit/.

`scripts/` contiene install_msfrpcd_service.sh, msf_verify.py y __pycache__.
`react_e2e_manual.py` y `list_models.sh` están ambos en la raíz; la premisa de
que list_models.sh ya estaba en scripts/ no coincide con el árbol real.

## Bloqueo previo: reglas incompatibles con Ruff limpio

Comando ejecutado antes de borrar:

```bash
.venv/bin/ruff check nexus_core omni.py nexus_worker.py --select F,E9
```

Resultado: **Found 29 errors.** Son previos al cleanup. Seis están en rutas
que el punto 4 prohíbe modificar:

```text
nexus_core/utils/logger.py:9:8     F401 `contextlib` imported but unused
nexus_core/utils/security.py:4:8   F401 `typing` imported but unused
nexus_core/utils/security.py:5:8   F401 `re` imported but unused
nexus_core/utils/security.py:7:8   F401 `pathlib` imported but unused
nexus_core/utils/security.py:9:8   F401 `json` imported but unused
nexus_core/utils/security.py:11:8  F401 `functools` imported but unused
```

**Requiere refactor autorizado:** retirar esos imports de utils/ o cambiar
explícitamente el alcance de la validación. No se aplicaron ignores, cambios
a ruff.toml ni fixes para ocultar el fallo. Los otros 23 errores están en
agents/generated/, core/, state/, team_orchestrator.py y tests/unit/.

Se aplica la instrucción final del usuario: “Si algo no se puede cumplir,
PARA y reporta con el error exacto”. Fases 2–7 no ejecutadas.
