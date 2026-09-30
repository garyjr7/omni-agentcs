# SESSION_INTERACT_RESULT — interacción con sesiones + REPL stateful

Rama `feat/session-interact` (desde `fabfe17`). Implementa la Parte 2 de la
misión: write/read de sesiones, tool durable `nexus.session.interact` (15 tools),
REPL stateful con `attach`/`detach`, comandos meta, detección de sesión muerta y
tests deterministas + 2 E2E opt-in contra **loopback** (no se atacó ningún host
externo).

Todo el reconocimiento y los dos defectos de la misión anterior están en
`SESSION_INTERACT_RECON.md`.

## 1. Resultado

| Criterio | Resultado |
|---|---|
| 7 imports OK | ✅ `client`, `parsers.metasploit`, `handlers.msf_session_interact`, `cli.session`, `cli.commands`, `cli.render`, `omni` |
| 15 tools registradas | ✅ `nexus.session.interact` incluida |
| 536 tests previos siguen pasando | ✅ 626 unit (536 previos + 90 nuevos) |
| ≥14 tests cliente extendido | ✅ 26 |
| ≥5 tests parser | ✅ 11 |
| ≥10 tests handler interact | ✅ 20 |
| ≥12 tests REPL stateful | ✅ 18 |
| ≥6 tests comandos meta | ✅ 14 |
| ≥2 tests E2E opt-in | ✅ 2 (pasan 2 ejecuciones consecutivas) |
| ruff `--select F,E9` limpio | ✅ |
| Cero TODOs/FIXME/HACK | ✅ |
| Prompt cambia con attach | ✅ (`─[session <uuid>/<type>]`) |
| Líneas sin `/` van a la sesión | ✅ |
| Líneas con `/` siguen siendo meta | ✅ |
| Detección de sesión muerta | ✅ (dos mecanismos, ver §4) |
| Daemon limpio tras E2E | ✅ 0 sesiones, 0 jobs |
| Ningún handler ejecuta subprocess | ✅ (grep vacío; el subprocess del E2E es la víctima de test) |
| Sin host externo atacado | ✅ sólo `127.0.0.1` |

## 2. Ficheros

Nuevos:

| Fichero | Líneas | Qué |
|---|---|---|
| `nexus_core/tools/handlers/msf_session_interact.py` | 144 | Tool `nexus.session.interact` (HIGH, sin scope, hardening de comando, evidencia). |
| `nexus_core/tests/unit/test_metasploit_client_interact.py` | 380 | write/read + `run_in_session` (26 tests). |
| `nexus_core/tests/unit/test_msf_session_interact_handler.py` | 193 | Handler, gate de aprobación, allowlist, auditoría (20). |
| `nexus_core/tests/unit/test_cli_session_stateful.py` | 288 | REPL stateful (18). |
| `nexus_core/tests/unit/test_cli_session_commands.py` | 181 | Comandos meta (14). |
| `nexus_core/tests/unit/test_metasploit_parser_interaction.py` | 72 | Parser (11). |
| `nexus_core/tests/integration/test_session_interact_e2e.py` | 259 | 2 E2E opt-in loopback. |
| `SESSION_INTERACT_RECON.md` | 158 | Reconocimiento. |

Modificados (741 inserciones / 13 borrados): `client.py` (+172),
`cli/session.py` (+229), `cli/commands.py` (+121), `cli/render.py` (+80),
`parsers/metasploit.py` (+46), `tools/registry.py` (+8), `README.md` (+49),
`tests/msf_support.py` (+27), `test_metasploit_client_sessions.py`,
`test_system_env_handler.py`.

## 3. API del cliente (por uuid)

| Método | RPC | Contrato |
|---|---|---|
| `write_shell(uuid, cmd)` | `session.shell_write [sid, cmd+\n]` | `True` si `write_count` viene. |
| `read_shell(uuid)` | `session.shell_read [sid]` | `""` sin datos; `MetasploitError` si murió. |
| `write_meterpreter(uuid, cmd)` | `session.meterpreter_write [sid, cmd+\n]` | `True` si `result=success`. |
| `read_meterpreter(uuid)` | `session.meterpreter_read [sid]` | `""` sin datos. |
| `has_session(uuid, sessions=None)` | `session.list` | `bool`; un fallo del daemon ⇒ `False`. |
| `_resolve_session(uuid, sessions=None)` | `session.list` | `(sid:str, type:str)` o `MetasploitError`. |
| `stop_session(uuid)` | `session.stop [sid]` | resuelve uuid → sid antes del RPC. |
| `run_in_session(uuid, cmd, *, quiet_seconds=1.5, max_wait_seconds=60, poll_interval_seconds=0.2)` | `write_*` + `read_*` | `{"status": "ok"\|"timeout"\|"session_dead", "output", "bytes", "duration_seconds"}`. |

`run_in_session` decide shell vs meterpreter con el `type` de `session.list`
(la flakiness de `interactive_write` sobre shells documentada en el recon llevó a
usar los RPC específicos). Está acotado por **presupuesto de intentos** y por
**deadline monotónico**, y usa `asyncio.sleep` (cancelable).

## 4. Detección de sesión muerta

Dos mecanismos complementarios:

1. **`session.list` deja de mostrar el uuid** → `run_in_session` devuelve
   `session_dead` antes de escribir. Cubre sesiones cerradas por el daemon.
2. **El RPC de write/read falla** (500) → `run_in_session` devuelve
   `session_dead`.

Hallazgo del E2E: cuando el peer muere sin que nadie toque el socket, el daemon
**sigue listando** la sesión (no hay reader de fondo), así que la detección real
llega por el mecanismo 2 y acto seguido la sesión desaparece de `session.list`.
Medido en vivo con `AutoVerifySession=false`:

```
has_session 2s tras matar la víctima : True     (mecanismo 1 solo no basta)
run_in_session               : {'status': 'session_dead', 'output': '', 'bytes': 0, 'duration_seconds': 0.009}
session.list justo después   : {}               (la sesión ya no está)
```

En el REPL, `check_active_session()` se ejecuta antes de cada prompt y vuelve a
modo normal con `render_session_died` si el uuid activo ya no está.

## 5. REPL stateful

- Estado nuevo en `OmniSession`: `active_session_uuid`, `active_session_info`,
  `session_commands_sent`, `session_started_at`.
- Prompt: `┌──(OmniAgentCS)─[<engagement>]─[session <uuid>/<type>]` (el flag de
  trust mode se conserva).
- Enrutado: con sesión activa, una línea que **no** empieza por `/` se envía a
  `nexus.session.interact`; `/` sigue siendo comando meta; sin sesión activa el
  comportamiento es el normal (objetivo → bucle ReAct).
- Comandos nuevos: `/sessions` (tabla UUID/tipo/peer/vía/usuario), `/session
  attach <uuid>` \| `/session info`, `/detach`, `/kill-session [uuid]|all`
  (prompt `y/n/e`).

### Gobernanza (regla dura 5)

- Los comandos se envían con `OmniSession.invoke_tool()` → **mismo
  `_operator_approval_gate` de `agent/react.py`** → `execute_tool` del gateway:
  así heredan policy, scope, approval y auditoría sin duplicar lógica.
- Además se emite una auditoría propia `action="session.command"`,
  `resource_type="session"`, con `command_sha256`, `engagement_id`, `run_id` y
  `outcome` (`deny` si no se aprobó).
- `/sessions` y `check_active_session()` leen `session.list` **directo** (son
  lectura de estado, no ejecutan nada en la sesión); `/kill-session` sí pasa por
  `nexus.session.kill`.

## 6. Tool `nexus.session.interact`

- `risk=HIGH`, `effect="post_exploitation"`, `scope_required=False` (regla 6: la
  sesión no se ata al scope), `timeout_seconds=360`, `max_output_bytes=10 MB`.
- Schema: `session_uuid` (pattern del cliente), `command` (1..2000),
  `max_wait_seconds` (5..300, opcional).
- Hardening: rechaza vacío, bytes nulos y comandos que cerrarían la sesión
  (`exit`, `quit`, `background`, `bg`, `detach`, `sessions -k`, `kill`, y
  variantes como `exit(0)`) con el hint `use nexus.session.kill for termination`.
  Allowlist opcional por env `NEXUS_SESSION_COMMAND_ALLOWLIST` (desactivada por
  defecto).
- `verified = status in {ok, timeout}`; evidencia con `session_uuid`, `command`,
  `status`, `output_bytes`, `duration_seconds`, `raw_sha256`.

## 7. E2E opt-in (loopback)

`NEXUS_E2E=1` + `MSF_RPC_PASSWORD` + daemon. Escenario: `exploit/multi/handler`
con `linux/x64/shell_reverse_tcp` en `127.0.0.1:<puerto libre>`; la víctima es un
script bash (`/dev/tcp`) ejecutado en el propio host. Limpieza: `session.stop` +
`job.stop` (con espera acotada a que `job.list` lo refleje) + kill de la víctima.

```
$ NEXUS_E2E=1 .venv/bin/python -m pytest nexus_core/tests/integration/test_session_interact_e2e.py -v
nexus_core/tests/integration/test_session_interact_e2e.py::test_e2e_session_interact_against_local_shell PASSED
nexus_core/tests/integration/test_session_interact_e2e.py::test_e2e_session_death_detected PASSED
============================== 2 passed in 25.46s ==============================
```

Test 1 comprueba: `verified=True`, `status in {ok,timeout}`, `"uid=" in output`,
`evidence.output_bytes > 0` y que existe un evento de auditoría
`tool.invoke`/`nexus.session.interact` (prueba de que el comando pasó por el
gateway). Test 2 comprueba `status=session_dead`, salida vacía y que la sesión
desaparece de `session.list`.

Estado del daemon tras los E2E:

```
sessions: {}
jobs: {}
clean
```

## 8. Decisiones de diseño no cubiertas por la misión

1. **`strict_map_key=False` en `_rpc`.** `session.list` viene con claves
   `int` (el sid); el default de `msgpack.unpackb` las rechazaba. Sin esto,
   `list_sessions()` nunca podía devolver una sesión (bug latente de la misión
   8, invisible mientras no hubiera sesiones).
2. **`session.stop` recibe el sid, no el uuid.** Se añadió
   `_resolve_session(uuid) → (sid, type)` y `stop_session` lo usa. El
   `stop_session` anterior estaba roto (`500 Unknown Session ID`).
3. **RPC específicos por tipo.** `session.shell_*` para `shell`/`powershell`,
   `session.meterpreter_*` para meterpreter. `interactive_write` sobre una shell
   dio un 500 espurio una vez durante el reconocimiento.
4. **"Quiet" determinista.** No se usa un reloj: se exigen
   `ceil(quiet_seconds / poll_interval_seconds)` polls consecutivos sin datos
   nuevos; si el comando no produjo **nada**, se cierra tras
   `MIN_NO_OUTPUT_SECONDS = 5`. `max_wait_seconds` sí combina presupuesto de
   intentos y `time.monotonic()`.
5. **`/sessions` y la comprobación de liveness no pasan por el gateway** porque
   son lecturas de estado (`session.list`), no ejecuciones en la sesión. Los
   comandos y `/kill-session` sí.
6. **Auditoría redundante a propósito**: `session.command` (REPL) además del
   `tool.invoke`/`tool.complete` del gateway, para poder reconstruir la
   conversación de una sesión por separado.
7. **`scope_required=False`** en el interact: la sesión ya está abierta y sigue
   viva aunque cambie el scope; el `engagement_id` del comando se audita con el
   valor actual.
8. **`AutoVerifySession=false` en el handler de los E2E.** El daemon, con
   `AutoVerifySession` activo, lanza su propio handshake `echo <token>` justo al
   abrir la sesión; ese handshake **compite** con las lecturas del operador y se
   comía el output del primer comando (fallo intermitente, reproducido). Se
   desactivó para que el E2E pruebe *nuestro* camino de write/read de forma
   determinista (3/3 intentos con `uid=`, y 2 ejecuciones consecutivas de la
   suite en verde).
9. **Payload del E2E**: `linux/x64/shell_reverse_tcp` (crea sesión siempre);
   `cmd/unix/reverse` no abría sesión en este entorno.
10. **Token de comando.** El primer token se extrae con
    `re.split(r"[^A-Za-z0-9_-]", head, maxsplit=1)[0]`, de modo que `exit(0)`,
    `quit;` o `background && x` se detectan igual que `exit`.

## 9. Commit

```
git add -A && git commit -m "feat(session): interact tool + stateful REPL with attach/detach"
```

No se hizo push.
