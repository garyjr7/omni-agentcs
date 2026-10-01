# CAPABILITIES2 — tres fixes de seguridad; integraciones AD no implementadas

Fecha: 2026-10-01. Rama: `feat/capabilities-ad-attacks`.

## Resultado y alcance

Se implementaron los tres fixes críticos y se verificó la suite. No se
implementaron las cinco integraciones AD. La misión completa no está terminada.
El límite comunicado fue no incorporar extracción de credenciales y ejecución
remota a un agente ofensivo autónomo; no es un bloqueo de pipx o del sandbox.

| Componente | Estado |
|---|---|
| Sanitización de respuestas malformadas | Implementada y probada |
| PostgreSQL: esquema, migración y consumo de aprobación | Implementado; prueba real PG omitida por falta de DATABASE_URL |
| Sesiones vinculadas a tenant/engagement | Implementado y probado con RPC simulado |
| nexus.recon.netexec | No implementada |
| nexus.recon.bloodhound_python | No implementada |
| nexus.attack.impacket_secretsdump | No implementada |
| nexus.attack.impacket_getuserspns | No implementada |
| nexus.attack.impacket_psexec | No implementada |

El catálogo tiene **21 tools preexistentes**. No son 16 anteriores más cinco
nuevas: agregar las cinco al estado encontrado produciría 26.

## Fix 1: persistencia de texto malformado

`kernel/redaction.py` centraliza nombres sensibles y sanitización recursiva.
Procesa fragmentos JSON válidos, JSON en prosa/fences, valores entre comillas
con escapes, valores incompletos y asignaciones conocidas con `:` o `=`.
Cuando un valor no tiene comillas y no se puede interpretar con seguridad,
redacta el resto de la línea. Puede eliminar contexto adicional deliberadamente.

Se aplica a:
- `agent.memory.append_step`, mediante `_sanitize_content_for_persistence`.
- `ControlStore.append_message`, incluso sin pasar por memory.
- `AuditWriter._sanitize`, incluyendo strings como `raw_response`.
- Eventos de run, resultados de tareas/runs y errores de reintento.

No se reparan solicitudes para ejecutarlas. Los argumentos originales siguen
llegando a la ejecución; solo se modifica la copia persistida. Los nombres de
integridad `event_hash`, `raw_sha256` y `content_sha256` se conservan.

Los E2E usan un LLM simulado, SQLite real y ejecución simulada. Comprueban
`kernel_messages`, `kernel_audit_events`, eventos de run y la cadena de auditoría.
Con JSON malformado también comprueban que no se invoca la herramienta.

Limitaciones: se reconocen campos conocidos, no cualquier secreto arbitrario en
prosa. No se reescribió la auditoría histórica ni se borraron posibles secretos
persistidos antes del fix. Tampoco se rediseñó el transporte de credenciales en
payloads de tareas encoladas; no se añadieron herramientas que lo utilicen.

## Fix 2: aprobaciones y PostgreSQL

- `consumed_at TEXT` está en el esquema compartido.
- PostgreSQL ejecuta `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` para bases
  existentes; cambiar solo CREATE TABLE no habría migrado esas bases.
- El adaptador expone `commit()` y `rollback()`.
- `consume` usa un único UPDATE condicionado por tenant, run, acción, estado y
  `consumed_at IS NULL`; devuelve `rowcount == 1` después del commit del contexto.
  No existe un SELECT seguido de UPDATE vulnerable a una carrera.
- No necesita detectar el backend por el nombre de su clase ni mezclar formatos
  de placeholders: el adaptador PostgreSQL ya traduce los placeholders.

La prueba real PostgreSQL crea un esquema temporal exclusivo, inicializa el
store y enfrenta cuatro consumidores concurrentes. Elimina únicamente ese
esquema al finalizar. Está escrita y **se omitió** porque no hay DATABASE_URL
PostgreSQL configurada. No se afirma haber validado PostgreSQL contra un servidor
real. Pasan los contratos del adaptador/SQL y la concurrencia SQLite existente.

## Fix 3: pertenencia de sesiones

`kernel_sessions` conserva UUID, tenant, engagement, run, tipo, target, origen,
fecha de apertura y cierre. `SessionRegistry` impide reasignar o reabrir un
registro existente bajo otra operación.

- El engagement se obtiene de `context.scope.engagement_id`; RunContext no
  tiene el atributo `engagement_id` supuesto en el pseudocódigo.
- Las tres tools de sesión requieren scope. El gateway valida el contexto
  para estas tools sin target explícito; no cambia ninguna firma pública.
- Los handlers comprueban tenant, vigencia/firma, pertenencia, cierre y target
  antes de abrir una conexión RPC. El listado filtra antes de calcular el total
  y el digest; no expone el total global del daemon.
- El inventario y attach del CLI usan el mismo filtrado.
- Un kill confirmado registra `closed_at`.
- El handler que abre sesiones exige store y registra la pertenencia.

Se encontró una carrera de atribución adicional: el cliente RPC devuelve la
primera sesión nueva observada, que puede pertenecer a otro job concurrente.
El handler ahora exige UUID estable, `exploit_uuid` coincidente con el job y
host coincidente con la IP validada. Sin esos datos devuelve
`session_provenance_unverified`, sin reclamar ni operar la sesión ajena.

Consecuencia deliberada: sesiones antiguas sin registro o daemons que no
aporten esa evidencia no quedan disponibles automáticamente. No se implementó
una importación manual ni una migración que adivine el propietario. El cliente
RPC sigue usando su polling anterior; la nueva comprobación deniega una
atribución incierta, no intenta seleccionar otra sesión.

Las pruebas antiguas que afirmaban que no se necesitaba scope se sustituyeron
por pruebas de denegación. Los fixtures autorizados ahora crean registros de
pertenencia reales; no se simuló el control para ocultar fallos. Los E2E MSF
opt-in existentes también tienen fixtures con contexto/registro explícitos,
pero no se ejecutaron contra un daemon real en esta misión.

## Verificación ejecutada

```sh
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q
env -u NO_COLOR .venv/bin/python -m pytest nexus_core/tests -q
.venv/bin/ruff check nexus_core --select F,E9
git diff --check
```

Salidas reales:

```text
Con NO_COLOR=1: 1301 passed, 24 skipped in 59.11s
Sin NO_COLOR:  1301 passed, 24 skipped in 59.49s
Ruff: All checks passed!
git diff --check: sin errores
```

Batería crítica de unit tests, resolver y aprobaciones:

```sh
.venv/bin/python -m pytest \
  nexus_core/tests/unit/test_react_invalid_json_sanitization.py \
  nexus_core/tests/unit/test_session_engagement_binding.py \
  nexus_core/tests/unit/test_postgres_approval_consume.py \
  nexus_core/tests/unit/test_impacket_resolver.py \
  nexus_core/tests/unit/test_approval_consumed.py -q
```

```text
44 passed, 1 skipped in 4.38s
```

E2E críticos:

```sh
.venv/bin/python -m pytest \
  nexus_core/tests/integration/test_credential_leak_e2e.py \
  nexus_core/tests/integration/test_session_engagement_e2e.py -v
```

```text
credenciales / JSON válido plano                  PASSED
credenciales / JSON válido en fence               PASSED
credenciales / JSON válido en prosa               PASSED
credenciales / JSON malformado plano              PASSED
credenciales / JSON malformado en fence            PASSED
credenciales / JSON malformado en prosa            PASSED
cross_engagement_denied_even_with_approval        PASSED
7 passed in 6.43s
```

Imports comprobados: agent.memory, agent.react, kernel.redaction,
kernel.postgres_store, kernel.sessions, tools.registry y omni: **7 OK**.

## Estado del bloqueo de Impacket comprobado en esta sesión de trabajo

Ya existía Impacket 0.13.1 instalado con pipx. No se desinstaló ni reinstaló.
`secretsdump.py` apunta al venv de pipx y tiene este shebang:

```text
#!/home/operator/.local/share/pipx/venvs/impacket/bin/python
```

Consultas realizadas: `pipx list`, `readlink -f ~/.local/bin/secretsdump.py`
y consultas de ayuda/versión mediante `sandbox_for_environment` con workspace
temporal, HOME efímero y allowlist de rutas absolutas resueltas. No se alteró
HOME/PYTHONPATH para restaurar el user-site.

```text
/home/operator/.local/bin/nxc --version
exit=1 timeout=False
1.5.0 - Yippie-Ki-Yay - f1877176 - 0

/home/operator/.local/bin/bloodhound-python -h
exit=0 timeout=False
usage: bloodhound-python [-h] [-c COLLECTIONMETHOD] [-d DOMAIN] [-v]

/home/operator/.local/bin/secretsdump.py -h
exit=0 timeout=False
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

/home/operator/.local/bin/GetUserSPNs.py -h
exit=0 timeout=False
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

/home/operator/.local/bin/psexec.py -h
exit=0 timeout=False
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies
```

Los tres scripts Impacket arrancan sin ModuleNotFoundError. NetExec hace
`sys.exit(1)` deliberadamente después de imprimir --version; se comprobó en
`nxc/cli.py` instalado. Esa salida no indica fallo de importación.

La comprobación fue en LocalSandbox de desarrollo, no en una imagen OCI de
producción. El resolver existente ya reconoce los nombres `.py` y no cambió.
Las siete correcciones del recon sobre flags no se aplicaron a handlers AD
porque no se implementaron esos handlers.

## Git

Se entrega únicamente el commit de fixes críticos, con el mensaje:
`fix(security): sanitize raw_response, PG consumed_at, session-engagement binding`.
No se crea un commit de capacidades inexistentes. No se hace push.

`git log --oneline -5` previo al nuevo commit (el hash final se informa en la
respuesta de entrega):

```text
60eff11 fix(security): redact hash credentials, consume approvals, resolve impacket binaries
02d0b7a feat(tools): add sqlmap, gobuster, whatweb, searchsploit, dalfox
f65b4ca fix(cli): single-writer boundary, contextual /ask, markdown wrap
824dbc7 feat(cli): region-based TUI layout + working indicator + live tool stream
ac844a9 feat(cli): completion, markdown rendering, multiline, view-live
```
