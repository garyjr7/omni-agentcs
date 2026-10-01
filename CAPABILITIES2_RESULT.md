# CAPABILITIES2 — 3 fixes críticos + 5 tools AD

Fecha: 2026-10-01. Rama: `feat/capabilities-ad-attacks`.

## Resultado

Los tres fixes críticos ya estaban implementados y verificados (commit
`62a6f9d`); en esta sesión se comprobaron de nuevo y **no se relajó ninguno**.
Sobre esa base se implementaron las cinco herramientas AD, con parser
determinista, handler por sandbox, allowlist de flags, tests unitarios y un E2E
opt-in contra los binarios reales.

| Componente | Estado |
|---|---|
| Sanitización de `raw_response`/JSON malformado | Implementada (commit previo); reverificada |
| PostgreSQL `consumed_at` + `commit()` | Implementado (commit previo); reverificado |
| Sesiones vinculadas a tenant/engagement | Implementado (commit previo); reverificado |
| `nexus.recon.netexec` | Implementada |
| `nexus.recon.bloodhound_python` | Implementada |
| `nexus.attack.impacket_secretsdump` | Implementada |
| `nexus.attack.impacket_getuserspns` | Implementada |
| `nexus.attack.impacket_psexec` | Implementada |

## Nota sobre el conteo de tools

La misión asumía **16 tools preexistentes** y esperaba **21** al añadir cinco.
El catálogo real al iniciar ya tenía **21 tools** (`nexus.web.sqlmap`,
`nexus.recon.gobuster`, `nexus.recon.whatweb`, `nexus.exploit.searchsploit` y
`nexus.web.dalfox` se añadieron en la misión web anterior). Por tanto el catálogo
final es **26 tools = 21 + 5**, no 21. No se retiró ninguna herramienta para
cuadrar un número: se informa el valor real. El test que fija el conteo
(`test_system_env_handler.py`) se actualizó a 26.

## Fixes críticos (reverificados)

1. **Sanitización antes de persistir.** `kernel/redaction.py` centraliza los
   nombres sensibles y la sanitización recursiva; `agent/memory.py` la aplica en
   `append_step` y `ControlStore.append_message` antes del INSERT. Un JSON
   malformado con `"password": "..."` no conserva el secreto.
2. **PostgreSQL.** `consumed_at TEXT` está en `SCHEMA`, `_migrate_sqlite` lo
   añade a bases SQLite existentes y `PostgresControlStore.initialize()` ejecuta
   `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`. `_PostgresConnection` expone
   `commit()` y `rollback()`. `ApprovalService.consume` es un único UPDATE
   condicional (tenant/run/acción/estado/`consumed_at IS NULL`) y devuelve
   `rowcount == 1`; el adaptador traduce los placeholders, así que no hace falta
   ramificar por backend.
3. **Sesiones.** `kernel_sessions` y `SessionRegistry` ligan UUID, tenant,
   engagement, run, tipo, target y tool de origen. Las tres tools de sesión
   exigen scope y deniegan sesiones de otro engagement
   (`session_engagement_mismatch`), no registradas (`session_not_registered`),
   cerradas o fuera de scope. El List filtrado no expone el total global del
   daemon.

Salidas:

```text
NO_COLOR=1 pytest nexus_core/tests -q
1350 passed, 30 skipped in 46.76s

pytest test_react_invalid_json_sanitization test_session_engagement_binding \
       test_postgres_approval_consume test_impacket_resolver \
       test_approval_consumed test_recipes -q
51 passed, 1 skipped in 3.57s

pytest test_credential_leak_e2e test_session_engagement_e2e -v
7 passed in 2.69s
```

## Las cinco tools AD

Todas verifican scope (`scope_required=True`), corren por
`sandbox_for_environment` con allowlist y ejecutan el binario por **ruta
absoluta** (el PATH del sandbox es `/usr/local/bin:/usr/bin:/bin`, que no
incluye `~/.local/bin` de pipx).

| Tool | Riesgo | scope target | Efecto |
|---|---|---|---|
| `nexus.recon.netexec` | MEDIUM | `target` | recon SMB/LDAP |
| `nexus.recon.bloodhound_python` | MEDIUM | `dc` | recon del grafo AD |
| `nexus.attack.impacket_secretsdump` | HIGH | `target` | credential_dump |
| `nexus.attack.impacket_getuserspns` | MEDIUM | `dc_ip` | credential_access |
| `nexus.attack.impacket_psexec` | DESTRUCTIVE | `target` | execution |

- **NetExec**: `operation` → flag real; siempre `--no-progress`; credenciales por
  `-u/-p/-d/-H`. Prohibidos `-x`, `-X`, `-M`, `--sam`, `--lsa`, `--ntds`,
  `--put-file`, `--get-file`, `--taskkill`, `--wmi`, `--amsi-bypass`, `--log`.
- **BloodHound.py**: `--auth-method ntlm` por defecto, `-dc HOST`, `-ns
  NAMESERVER`, colecciones validadas (sin `ComputerOnly`), `-op` gestionado por
  el handler; lee y resume los JSON del workspace.
- **secretsdump**: `-outputfile` tratado como prefijo (`.sam`, `.secrets`,
  `.cached`, `.ntds`), `method` ∈ {all, ntds, ntds_ntlm} → `-just-dc`/
  `-just-dc-ntlm`; hashes por `-hashes` con `-no-pass`; `-debug`, `-ts`,
  `-history` permitidos.
- **GetUserSPNs**: positional `domain/username:password` (no `...@host`);
  `-dc-ip`/`-dc-host`; `-request` + `-outputfile` gestionados.
- **psexec**: DESTRUCTIVE, documentado como **RemComSvc**; siempre aprobación
  humana (incluido en trust mode); `-path`/`-file`/`-c` prohibidos.

### Correcciones de recon aplicadas

1. NetExec `--no-progress` (no `-q`); shares/users/groups como flags de
   enumeración; `--smb-sessions` y `--disks`.
2. BloodHound `--auth-method ntlm` en minúsculas, `-dc HOST` vs `-ns
   NAMESERVER`, sin `ComputerOnly`.
3. secretsdump `-outputfile` es prefijo; `-just-dc` solo NTDS.
4. GetUserSPNs `domain/username:password` como un único argumento.
5. psexec es RemComSvc, documentado en la `description`.
6. `-outputfile` genera `.sam`, `.secrets` y `.ntds` (más `.cached`).
7. `-debug`, `-ts`, `-no-pass`, `-hashes` aceptados en la allowlist.

### Registro de sesiones

Ninguna de las cinco abre una sesión MSF/Meterpreter persistente: secretsdump y
GetUserSPNs son volcados puntuales y el psexec de Impacket es una ejecución
**one-shot** (sube un binario de servicio RemComSvc y termina). Por eso no se
registra fila alguna en `kernel_sessions`; el vínculo session↔engagement queda
cubierto por `nexus.exploit.msf_exploit`, que ya registra la pertenencia.

### E2E opt-in

`nexus_core/tests/integration/test_ad_tools_e2e.py` (gate `NEXUS_E2E=1`)
comprueba que los cinco binarios resuelven a una ruta absoluta y ejecutan su
ayuda dentro del sandbox real, sin contactar ningún target:

```text
NEXUS_E2E=1 pytest test_ad_tools_e2e.py -v
6 passed in 2.08s
```

## Verificación ejecutada

```sh
NO_COLOR=1 .venv/bin/python -m pytest nexus_core/tests -q
.venv/bin/ruff check nexus_core --select F,E9
git diff --check
grep -rnE "subprocess|Popen|os\.system|shell=True" \
  nexus_core/tools/handlers/netexec.py nexus_core/tools/handlers/bloodhound.py \
  nexus_core/tools/handlers/impacket_*.py
```

Salidas reales:

```text
1350 passed, 30 skipped in 46.76s
Ruff: All checks passed!
git diff --check: sin errores
grep: OK (los handlers solo usan el sandbox)
```

Imports comprobados: `agent.memory`, `agent.react`, `kernel.postgres_store`,
`kernel.sessions`, los cinco handlers AD, `tools.registry` y `omni`: **11 OK**.
`durable_tool_definitions()` → **26 tools**.

## Limitaciones

- Las pruebas PostgreSQL reales siguen **omitidas** porque no hay `DATABASE_URL`
  configurada; los contratos del adaptador y la concurrencia SQLite sí se
  ejecutan.
- Los E2E AD solo prueban resolución y arranque del binario en el sandbox. No se
  ejecutó ningún ataque contra un DC real ni se capturaron salidas reales de
  NetExec/BloodHound/secretsdump/GetUserSPNs/psexec; los parsers se validaron con
  fixtures construidos a partir de los formatos documentados y de las ayudas
  reales.
- La redacción protege campos con nombre conocido y JSON malformado. No es un
  detector universal de secretos en prosa libre ni limpia filas históricas.

## Git

Dos commits en la rama, sin push:

```text
fix(security): sanitize raw_response, PG consumed_at, session-engagement binding
feat(tools): add NetExec, BloodHound, and impacket AD attack tools
```
