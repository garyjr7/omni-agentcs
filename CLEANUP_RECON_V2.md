# Cleanup: reconocimiento V2

Fecha: 2026-09-29. Rama existente: `chore/final-cleanup`.
Base: `efa4227`. Árbol de trabajo inicialmente limpio.

## Resultado de la fase 1

**DETENIDO antes de modificar utils/ o borrar archivos.**
La autorización nueva para los seis F401 y agents/ (plural) queda reconocida.
El bloqueo actual es distinto: tests/** está protegido y tiene imports de
core/, state/ y evolution/, carpetas cuyo borrado exige esta misión.

Se ejecutaron las búsquedas solicitadas, incluyendo explícitamente los tests
porque la regla 4 los protege, aunque el primer bucle del prompt los excluya.

| Destino legacy | Rutas protegidas sin tests | Tests protegidos |
|---|---|---|
| agents/ (plural) | Sin coincidencias | Sin coincidencias |
| core/ | Sin coincidencias | conftest.py, test_kernel_offline.py, test_event_bus.py |
| state/ | Sin coincidencias | conftest.py, test_kernel_offline.py, test_state_manager.py |
| planner/ | Sin coincidencias | Sin coincidencias |
| evolution/ | Sin coincidencias | test_kernel_offline.py |
| hitl/ | Sin coincidencias | Sin coincidencias |
| vector/ | Sin coincidencias | Sin coincidencias |
| team_orchestrator.py | Sin coincidencias | Sin coincidencias |

### Referencias exactas encontradas

```text
nexus_core/tests/conftest.py:6:from nexus_core.core.event_bus import EventBus
nexus_core/tests/conftest.py:7:from nexus_core.state.manager import StateManager
nexus_core/tests/unit/test_kernel_offline.py:24:from nexus_core.evolution import EvolutionLab, EvolutionState
nexus_core/tests/unit/test_kernel_offline.py:30:from nexus_core.evolution import EvolutionWorkspace
nexus_core/tests/unit/test_kernel_offline.py:32:from nexus_core.state.manager import StateManager, TaskState, TaskStatus
nexus_core/tests/unit/test_kernel_offline.py:33:from nexus_core.core.event_bus import EventBus, EventType
nexus_core/tests/unit/test_event_bus.py:5:from nexus_core.core.event_bus import Event, EventBus, EventType
nexus_core/tests/unit/test_state_manager.py:6:from nexus_core.state.manager import StateManager, TaskState, TaskStatus
```

conftest.py no solo importa estos símbolos: instancia StateManager y EventBus
como fixtures compartidas. Borrar los módulos impediría cargar el conftest de
la suite. No se provocó ese fallo deliberadamente; los imports anteriores son
la evidencia directa del bloqueo. No se borraron ni se deshabilitaron tests.

### memory/ y workforce/

Sin coincidencias para imports absolutos nexus_core.memory / nexus_core.workforce
en las rutas protegidas de runtime indicadas por el prompt. No se tocaron esas
carpetas. Esto no sustituye una auditoría de imports relativos o consumidores
indirectos antes de decidir su eliminación.

### Otro conflicto con el objetivo Ruff limpio

El diagnóstico vuelve a dar 29 errores. Los seis F401 de utils/ ya están
expresamente autorizados; no son el motivo para detener esta misión V2.
Pero también existen errores en tests protegidos:

```text
nexus_core/tests/unit/test_sovereign_runtime.py:38:5: F841 Local variable `task` is assigned to but never used
nexus_core/tests/unit/test_sovereign_runtime.py:78:5: F841 Local variable `task` is assigned to but never used
```

Se necesitaría autorización para eliminar esas dos asignaciones conservando
las llamadas y los tests. No se cambiaron las reglas de Ruff ni se añadieron ignores.

## Condición para retomar

Hay que resolver explícitamente la contradicción: conservar core/, state/ y
evolution/ mientras sus tests sigan siendo obligatorios, o autorizar una
migración de sus implementaciones/contratos y consumidores protegidos antes
de borrarlas. Borrar tests o añadir skips no conserva los 470 tests existentes.
También habría que autorizar la corrección de los dos F841 indicados.

Por la instrucción «Si aparece cualquier referencia DESDE el protegido HACIA
el legacy, PARA y reporta», no se iniciaron las fases 2–8.
