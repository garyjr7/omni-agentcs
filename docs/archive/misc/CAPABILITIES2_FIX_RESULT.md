# CAPABILITIES2 — fixes de seguridad

Fecha: 2026-09-30. Rama: `feat/capabilities-ad-attacks`.

## Resultado

Los tres fixes están implementados y verificados: redacción de campos sensibles,
aprobaciones de un solo uso y resolución de nombres de ejecutables Impacket.
La implementación parcial encontrada al iniciar esta reanudación se revisó,
completó y probó antes de preparar el commit.

La integración de las cinco tools se detuvo posteriormente por el fallo de
Impacket dentro del sandbox descrito en `CAPABILITIES2_RESULT.md`.

## Cambios mínimos

- `kernel/audit.py`: conjunto explícito de nombres sensibles. Incluye hashes
  de autenticación; preserva `content_sha256`, `raw_sha256` y `event_hash`.
- `agent/memory.py`: sanea metadata y JSON en el contenido antes de persistir.
  Reconoce también JSON entre fences Markdown o precedido por prosa, formatos
  que ya acepta el parser. El texto ordinario sin JSON se conserva.
- `agent/react.py`: redacta copias de argumentos en los dos registros de
  acciones; la llamada al ejecutor conserva los argumentos originales.
- `kernel/approvals.py`: `consume()` actualiza condicionalmente `consumed_at`
  en una transacción `BEGIN IMMEDIATE`. Solo una invocación puede reclamar la
  aprobación. `verify()` ya no considera válidas las aprobaciones consumidas.
- `kernel/tool_gateway.py`: consume aprobaciones una vez, incluida la vía de
  instalación, evitando un doble consumo dentro de la misma invocación.
- `kernel/control_store.py`: migración aditiva e idempotente `consumed_at TEXT`.
- `tools/handlers/_impacket_resolver.py`: busca los nombres con prefijo
  `impacket-`, sufijo `.py` y nombre simple, con caché.

No se modificaron PolicyEngine, ScopeValidator, firmas públicas del gateway o
ejecutores, parser, prompts ni lógica de decisión del bucle.

## Decisiones de diseño

La regla inicial de no cambiar schema contradice la Fase 2, que autoriza
expresamente `ALTER TABLE ... consumed_at`. Se aplicó esa excepción específica
y se conservó la migración ya presente en el workspace. En este repositorio,
`_migrate_sqlite` reside en `control_store.py`, no en `migrations.py`.
No hubo rebuild, renames ni tablas nuevas.

El consumo sucede antes del handler: un intento que posteriormente falla
también gasta su aprobación. Está vinculado a tenant/run/acción, no al digest
de argumentos. No se afirma que resuelva la vinculación al contenido exacto
de cada comando, que no forma parte de este cambio.

La redacción protege campos estructurados y JSON persistido. No es un detector
universal de secretos escritos en prosa libre ni una limpieza retroactiva de
filas históricas. No se alteraron las credenciales necesarias para ejecutar
la herramienta ni se modificaron registros históricos/audit chains.

## Verificación

Primera corrida dirigida sobre la implementación parcial: **39 passed**.
Después se añadió cobertura para fences/prosa, concurrencia, migración sobre
una base existente y rechazo de IDs desconocidos: **44 tests nuevos** en total
en los seis archivos específicos de esta misión (40 unitarios, 4 de integración).

Suite completa:

```text
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q
1264 passed, 23 skipped in 57.17s

env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests -q
1264 passed, 23 skipped in 60.25s
```

Los 1219 tests unitarios previos siguen pasando. Las 23 omisiones son las
pruebas condicionadas de la suite; no se presentan como pruebas ejecutadas.

E2E de persistencia, ejecutado con fake LLM y ejecutor espía, sin red:

````text
test_e2e_credentials_never_persisted_to_kernel_messages[{}] PASSED
test_e2e_credentials_never_persisted_to_kernel_messages[```json\n{}\n```] PASSED
test_e2e_credentials_never_persisted_to_kernel_messages[Acción:\n{}\nFin.] PASSED
````

Cada variante verifica SQL en `kernel_messages` sin `secret123` ni el hash
ficticio, y verifica que el ejecutor recibió ambos valores originales.

E2E de replay, gateway y store reales, handler inocuo:

```text
test_e2e_approval_cannot_be_replayed PASSED
test_consume_is_atomic_across_connections PASSED
test_additive_migration_preserves_existing_approvals PASSED
```

Ruff:

```text
.venv/bin/ruff check nexus_core/kernel nexus_core/agent nexus_core/tools nexus_core/tests --select F,E9
All checks passed!
```

Salidas completas locales: `/tmp/capabilities2-fixes-color.txt`,
`/tmp/capabilities2-fixes-nocolor.txt`, `/tmp/capabilities2-fixes-ruff.txt`.
