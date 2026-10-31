# ADR-004: Sandbox modes and their guarantees

- Estado: aceptado (modo `oci_network` implementado con proxy de egress)
- Fecha: 2026-10-01 (actualizado 2026-10-30: egress gobernado implementado)

## Contexto

`nexus_core/kernel/sandbox.py` elegía el runner a partir de `NEXUS_ENV`
(development → `LocalSandbox`, production → `OCISandbox`) sin declarar qué
aislamiento ofrecía cada uno. La auditoría #3 detectó que el detector podía
marcar un binario como "presente" mientras el runner fallaba al ejecutarlo
(dependencias rotas, `pip --user` fuera de PATH, HOME no escribible, etc.),
porque `provisioner/detector.py` verifica con `shutil.which` + `subprocess.run`
**fuera** del sandbox.

## Decisión

Se introducen modos explícitos (`nexus_core/kernel/sandbox_modes.py`) con sus
garantías declaradas:

| Modo | FS aislado | Red aislada | Proceso aislado | Límites | Usuario aislado | Persistente | Tools de red |
|---|---|---|---|---|---|---|---|
| `local` | no | no | no | no | no | sí | sí |
| `local_strict` | no | no | sí | no | no | sí | sí |
| `oci` | sí | sí | sí | sí | sí | no | no |
| `oci_network` | sí | filtrada | sí | sí | sí | no | sí |

- `NEXUS_SANDBOX_MODE` selecciona el modo explícitamente; si no, `NEXUS_ENV=production`
  ⇒ `oci`, cualquier otro valor ⇒ `local_strict`.
- `local_strict` es el modo por defecto en desarrollo: allowlist de programas,
  workspace resolvido, HOME/XDG efímeros y **process group propio**
  (`start_new_session=True`) que permite cancelación real.
- `active_mode()`/`guarantees_for()` alimentan el banner y `/doctor`.
- `verify_tool_in_sandbox()` ejecuta el comando de verificación del binario
  *dentro* del sandbox y distingue `ABSENT` / `DETECTED` / `RUNNABLE` / `FAILED`.

## `oci_network`: implementación (egress gobernado)

Un contenedor con red, pero cuyo único camino de salida es un proxy SOCKS5 que
valida cada destino contra el scope firmado:

1. `nexus_core/kernel/egress.py` expone `Socks5EgressProxy` (solo `CONNECT`;
   `BIND` y `UDP ASSOCIATE` se rechazan) y `ScopeEgressGuard`, que reutiliza
   `ScopeValidator` en vez de reimplementar el matching de scope.
2. El proxy autoriza **antes** de crear el socket: una denegación devuelve
   `0x02`, cuenta en `EgressStats` y se emite como `egress.denied` al hook de
   auditoría; nunca llega a abrirse una conexión al destino.
3. La conexión se abre a la **IP que el validador autorizó**, no al nombre que
   envió el cliente, así que un cambio de respuesta DNS entre check y connect
   (rebinding) no redirige el tráfico.
4. `OCINetworkSandbox` une el contenedor a una red Docker `--internal` (sin
   ruta a internet) y le pasa el proxy en `ALL_PROXY`/`HTTP(S)_PROXY`. Una tool
   que ignore las variables de entorno no tiene salida: el bloqueo lo aplica el
   kernel, no una regex sobre `argv`.
5. `SandboxPolicy.resolve()` exige `NEXUS_EGRESS_PROXY=socks5://host:port` y
   `NEXUS_SANDBOX_NETWORK=<red --internal>`; si falta cualquiera, o si la red es
   `none`/`host`/`bridge`, sigue lanzando `SandboxModeNotImplemented` con esas
   dos variables en el mensaje.

Límites conocidos, que no se anuncian como garantías: la red `--internal` deja
que el contenedor alcance al host en la puerta de enlace (donde escucha el
proxy), por lo que aislar otros servicios del host requiere reglas de host; y
las tools que no respetan variables de proxy (p. ej. `hydra`) fallan cerrado en
vez de salir sin filtro.

## Consecuencias

- Los operadores leen en una línea qué garantías están activas (`/doctor`).
- Un binario "presente" ya no se reporta como utilizable sin evidencia.
- La cancelación puede matar el árbol de procesos del sandbox sin dejar
  huérfanos (`SandboxResult.cancelled` / `orphans_detected`).
- `oci_network` ya no falla por diseño: falla cerrado si no hay proxy y red
  `--internal` configurados, y cada conexión denegada queda auditada.
- Arrancar el proxy es responsabilidad del operador (no se inicia por handler):
  un proxy por llamada reiniciaría su caché de autorizaciones y ocultaría
  patrones de egress del run.
