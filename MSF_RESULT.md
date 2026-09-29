# Integración Metasploit RPC: resultado

2026-09-29 UTC. Rama: `feat/metasploit-rpc`.

Partes A y B verificadas. Servicio activo y habilitado; MessagePack en
127.0.0.1:55552/api/. B comenzó después de recibir del operador la verificación
correcta de A y confirmar el estado del servicio.

## Cambios

- Cliente async RPC, normalización de cadenas binarias Ruby y errores sin
  cuerpos remotos ni secretos; sin reintentos ni procesos externos.
- Parsers frozen con SHA-256 del JSON canónico de la respuesta normalizada.
- nexus.exploit.msf_search: READ_ONLY, sin scope, filtros y límite 1–100.
- nexus.exploit.msf_auxiliary: MEDIUM, scope obligatorio sobre target único;
  ScopeValidator valida el target y se envía una IP autorizada al daemon.
- Nueve tools registradas; gateway mantiene políticas y auditoría.
- README, .env.example, instalador systemd y verificador curl documentados.
- .env configurado e ignorado por Git, con permisos 600. Cero dependencias nuevas.

## Verificación

```text
Base antes de cambios: 309 passed in 11.87s
Tests nuevos:          64 passed in 2.61s
Suite completa:       373 passed in 12.64s
E2E sin opt-in:        3 skipped in 0.13s
Imports:              4 OK
Catálogo:              9 tools
Ruff F,E9:            All checks passed!
git diff --check:     sin errores
```

Desglose nuevo: cliente 16 casos, parser 9, search handler 10, auxiliary
handler 29. Cliente probado con httpx.MockTransport; handlers cubren límites,
inyección, scope, auditoría, timeout, fallos de red y protección de secretos.

E2E reales con NEXUS_E2E=1:

```text
test_e2e_search_ms17_010_finds_eternalblue PASSED
test_e2e_auxiliary_smb_version_scanme PASSED
test_e2e_out_of_scope_denied_with_audit PASSED
3 passed in 8.04s
```

Completar smb_version no afirma que scanme tenga SMB abierto o sea vulnerable.
Los E2E usan una base de control y scopes temporales, sin crear engagements
operativos en la instalación.

## Decisiones de diseño

- MessagePack es el default verificado. Requiere arrays posicionales y header
  binary/message-pack. Se conserva la respuesta v10 completa: result no es
  un sobre JSON-RPC en ese protocolo.
- module.search recibe una cadena con filtros; module.execute recibe tipo,
  nombre sin prefijo y opciones. Polling de module.results cada dos segundos.
- JSON seleccionable usa HTTP Bearer con el token de API en MSF_RPC_PASSWORD;
  no auth.login. Cubierto con mocks, no probado en vivo.
- Los handlers comprueban límites numéricos y patrones: el validador de schema
  actual del kernel no implementa esas claves.
- Auxiliary bloquea opciones compuestas, caracteres de inyección y las opciones
  de targets/proxies/listeners/sesiones/comandos/archivos de su lista de bloqueo.
  THREADS default 1 y máximo 32; RPORT entre 1 y 65535.
- Se fija una IP validada, preferentemente IPv4, para evitar una resolución
  DNS independiente en el daemon. target no acepta rangos ni listas.
- Timeout engloba autenticación, ejecución y polling. Se solicita job.stop
  una vez, con hasta cinco segundos adicionales. Si el daemon no responde no
  se reintenta; un job puede continuar remoto si no se logra detener.
- Solo completed produce verificación positiva. Se redactan credenciales y
  tokens. Los tokens temporales expiran; auth.logout devolvió HTTP 500 en el
  diagnóstico de esta build y no se utiliza para cerrar el cliente HTTP.
- El servicio corre como root según la unidad solicitada; los módulos remotos
  se ejecutan fuera del sandbox de procesos de NEXUS.

## Comprobación adicional de Omni

```bash
.venv/bin/python omni.py --engagement eng-scanme \
  --objective 'Busca módulos MSF para MS17-010' --no-color
```

Terminó con código 2 antes de invocar tools:

```text
✗ engagement no encontrado: eng-scanme
```

La integración y los E2E pasan. La demostración Omni queda pendiente de
seleccionar o crear el engagement operativo correspondiente. No se alteraron
engagements existentes ni se creó uno como efecto secundario de la integración.

Commit solicitado con cliente, tools, scripts systemd y documentación. Sin push.
