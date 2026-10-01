# SLIVER_RECON — Integración de Sliver C2 vía gRPC

## 1. Entorno

| Elemento | Valor |
| --- | --- |
| Python | 3.12.3 (`.venv`) |
| `sliver-py` | **0.0.19** (instalado con `pip install 'sliver-py>=0.0.19'`) |
| Dependencias arrastradas | `grpcio 1.84.0`, `grpcio-tools 1.84.0`, `protobuf 7.35.1` |
| Import verificado | `from sliver import SliverClientConfig, SliverClient` → `sliver-py OK` |
| Team server | **no activo** (`ss -tlnp | grep 31337` → sin resultados) |

`sliver-py` es GPLv3, compatible con el proyecto, y ya está declarado en:

- `nexus_core/requirements.txt` (lista base de runtime),
- `requirements-prod.in` (`-r nexus_core/requirements.txt` + extra explícito),
- `requirements-dev.txt` (`-r requirements-prod.in` + extra explícito).

Recipe añadida a `nexus_core/provisioner/data/install_recipes.json`:

```json
"sliver-py": {
  "description": "Python gRPC client for Sliver C2",
  "purpose": "C2 post-exploitation automation",
  "verify": ["python3", "-c", "from sliver import SliverClient"],
  "recipes": {
    "pip": {"command": ["pip", "install", "sliver-py"], "sudo": false}
  }
}
```

## 2. Superficie real de `SliverClient` (0.0.19)

La API del brief se contrastó contra el paquete instalado. Las firmas reales
(inspeccionadas con `inspect`) son:

```
async connect(self) -> clientpb.Version            # retorna la versión del server
async version(self, timeout=60) -> clientpb.Version
async operators(self, timeout=60) -> List[clientpb.Operator]
async sessions(self, timeout=60) -> List[clientpb.Session]
async beacons(self, timeout=60) -> List[clientpb.Beacon]
async session_by_id(self, session_id, timeout=60) -> Optional[clientpb.Session]
async beacon_by_id(self, beacon_id, timeout=60) -> Optional[clientpb.Beacon]
async kill_session(self, session_id, force=False, timeout=60) -> None
async interact_session(self, session_id, timeout=60) -> Optional[InteractiveSession]
async interact_beacon(self, beacon_id, timeout=60) -> Optional[InteractiveBeacon]
async jobs(self, timeout=60) -> List[clientpb.Job]
async implant_builds(self, timeout=60) -> Dict[str, clientpb.ImplantConfig]
async implant_profiles(self, timeout=60) -> List[clientpb.ImplantProfile]
sync  is_connected(self) -> bool
```

Diferencias frente al borrador del brief (documentadas para trazabilidad):

1. **No existe `disconnect()` público.** El cliente guarda el canal en
   `self._channel` (`grpc.aio.Channel`). Nuestro `disconnect()` cierra el canal
   (`await channel.close()`), de forma tolerante a fallos.
2. **`version()`/`operators()`/`sessions()`/… devuelven mensajes protobuf**, no
   `dict`. Nuestro wrapper los convierte a `dict`/`list[dict]` con
   `google.protobuf.json_format.MessageToDict(..., preserving_proto_field_name=True)`
   para que los parsers trabajen con datos planos y testeables.
3. **`kill_session` devuelve `None`**; el wrapper devuelve
   `{"session_id": ..., "killed": True}`.
4. **`InteractiveSession.execute` no acepta una shell string**: su firma es
   `execute(self, exe, args, output=True) -> sliverpb.Execute`. Nuestro
   `execute_command()` decide el intérprete por SO (`cmd.exe /c` en Windows,
   `/bin/sh -c` en el resto) y pasa `args` como lista. La respuesta
   `sliverpb.Execute` expone `Status` (int32), `Stdout` (bytes), `Stderr`
   (bytes), `Pid`.

## 3. Estructura del operator config (`parse_config_file`)

`SliverClientConfig.parse_config_file(path)` hace `json.loads` del fichero y
construye el objeto con estas claves exactas:

```json
{
  "operator": "nombre",
  "lhost": "127.0.0.1",
  "lport": 31337,
  "ca_certificate": "-----BEGIN CERTIFICATE-----\n...",
  "certificate":     "-----BEGIN CERTIFICATE-----\n...",
  "private_key":     "-----BEGIN PRIVATE KEY-----\n...",
  "token":           "..."
}
```

`lport` debe cumplir `0 < lport < 65535` (si no, `ValueError`). El contenido
del `.cfg` contiene la clave privada mTLS y el token de autenticación: **nunca
se registra en logs ni se muestra**; nuestro cliente sólo guarda la *ruta*.

Generación del config (documentada, no ejecutada — no instalamos el server):

```bash
sliver-server operator --name <operador> --lhost 127.0.0.1 --save operator.cfg
```

## 4. Asincronía verificada

`sliver.client.BaseClient` construye el canal con `grpc.aio.secure_channel(...)`
y la clase se documenta como *"Asyncio client implementation"*; todos los
métodos de RPC son `async def` (confirmado con `inspect.iscoroutinefunction`).
Encaja con el `asyncio_mode = auto` de pytest y con el resto del kernel.

## 5. Estado del team server y E2E

El server **no está corriendo** en `localhost:31337`, así que el E2E opt-in se
saltará. Para levantarlo (requiere aprobación humana explícita; **no lo hemos
instalado**):

```bash
# 1) Instalar el server (fuera de este repo)
curl https://sliver.sh/install | sudo bash
# 2) Arrancar el daemon multiplayer en 127.0.0.1:31337
sudo systemctl start sliver
# 3) Generar el operator config y exportar la variable
sliver-server operator --name nexus --lhost 127.0.0.1 --save ~/.sliver-operator.cfg
export SLIVER_OPERATOR_CONFIG=~/.sliver-operator.cfg
# 4) Habilitar el E2E
NEXUS_E2E=1 .venv/bin/python -m pytest nexus_core/tests/integration/test_sliver_e2e.py -v
```

Gating del E2E: `NEXUS_E2E=1` **y** `SLIVER_OPERATOR_CONFIG` apunta a un fichero
existente **y** el puerto 31337 acepta conexión. Si falta cualquiera, `skip`.

## 6. Diseño del cliente (fail-closed)

- `SliverConfig.from_env()` lee `SLIVER_OPERATOR_CONFIG`, `SLIVER_TIMEOUT`
  (30), `SLIVER_LHOST` (127.0.0.1) y `SLIVER_LPORT` (31337).
- `connect()` es idempotente; sin config → `SliverAuthError` con el mensaje de
  generación; fichero inexistente → `SliverAuthError`; fallo de red →
  `SliverUnavailable`.
- Cada RPC se envuelve en `asyncio.timeout(...)`, sin reintentos.
- `is_available()` nunca lanza: cualquier excepción se traduce a `False`.
- Los handlers traducen `SliverError` a `ToolResult(verified=False)` con
  `verification_method` distinto por causa (`sliver_unavailable`,
  `sliver_auth_missing`, `sliver_rpc_failed`).
