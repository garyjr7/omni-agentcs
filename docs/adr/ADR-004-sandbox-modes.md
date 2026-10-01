# ADR-004: Sandbox modes and their guarantees

- Estado: aceptado (modo `oci_network` documentado, no implementado)
- Fecha: 2026-10-01

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

## `oci_network`: diseño (no implementado)

Un contenedor con red, pero cuyo tráfico queda restringido a las IPs/CIDRs del
scope del engagement mediante reglas `iptables` en el host:

1. El contenedor se une a una red bridge dedicada por engagement.
2. Una cadena `NEXUS_SCOPE_<engagement>` acepta `-d <cidr>` del scope y
   `DROP`ea el resto del tráfico saliente.
3. Las excepciones del scope ganan (se DROP-ean primero).
4. El runner elimina la cadena al terminar el container.

El hook existe como `SandboxMode.OCI_NETWORK`, pero `sandbox_for_mode()` lanza
`NotImplementedError` con un mensaje que apunta a este ADR: nadie debe ejecutar
tools de red creyendo que el firewall ya está aplicado.

## Consecuencias

- Los operadores leen en una línea qué garantías están activas (`/doctor`).
- Un binario "presente" ya no se reporta como utilizable sin evidencia.
- La cancelación puede matar el árbol de procesos del sandbox sin dejar
  huérfanos (`SandboxResult.cancelled` / `orphans_detected`).
- Implementar `oci_network` es trabajo futuro acotado a `iptables` + ciclo de
  vida del contenedor; hasta entonces falla ruidosamente.
