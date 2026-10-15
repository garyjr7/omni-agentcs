# Diagnóstico de msfrpcd

**Estado final: resuelto.** Servicio activo, habilitado y autenticado por
MessagePack. Ver MSF_DAEMON_RESULT.md. Lo siguiente es el historial previo.

Fecha: 2026-09-29 (UTC). Parte A bloqueada; Parte B no iniciada.

## Entorno y permisos

- Usuario: `operator` (uid 1000), miembro del grupo `sudo`.
- PID 1: `systemd`.
- Estado inicial de Git: limpio (`git status --short` sin salida).
- El sandbox falla antes de ejecutar comandos:
  `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.
  El diagnóstico se ejecutó fuera del sandbox con autorización.
- `sudo -n -l` y `sudo -n pkill -f '[m]sfrpcd'` devolvieron:
  `sudo: a password is required`.
  Se usó `-n` para evitar pedir contraseñas o dejar procesos esperando.
  No se pudo completar la limpieza privilegiada ni inspeccionar reglas sudo.
- `tmux kill-session -t msf`: sin salida de error.
- Tras esperar un segundo, `ps -eo pid,user,comm` filtrado por
  `msfrpcd|msfconsole`: sin coincidencias. Se omitieron argumentos de procesos
  para evitar registrar credenciales.

## Instalación

`dpkg-query -W metasploit-framework`:

```text
metasploit-framework  6.5.3~20260818061200~1rapid7-1
```

`command -v msfrpcd`: `/usr/bin/msfrpcd`.

`ls -la /usr/bin/msfrpcd`:

```text
lrwxrwxrwx 1 root root 25 Aug 18 06:20 /usr/bin/msfrpcd -> /etc/alternatives/msfrpcd
```

`readlink -f /usr/bin/msfrpcd`:
`/opt/metasploit-framework/bin/msfrpcd`.

`/usr/bin/msfrpcd -h` se ejecutó sin sudo y terminó correctamente. Mostró el
asistente inicial de configuración y después la ayuda. Opciones relevantes:

```text
-f   Run the daemon in the foreground
-j   (JSON-RPC) Start JSON-RPC server
-P   Specify the password to access msfrpcd
-S   Disable SSL on the RPC socket
-U   Specify the username to access msfrpcd
```

`-E` no aparece en la ayuda ni en el parser de argumentos instalado en
`/opt/metasploit-framework/embedded/framework/msfrpcd`.
Ese código admite `MSF_RPC_USER` y `MSF_RPC_PASS` como variables de entorno
para las credenciales del servidor MessagePack. El modo JSON inicia un
servidor web separado; su autenticación todavía no se verificó.

## Servicio y red

`sudo -n ss -tlnp`:

```text
sudo: a password is required
```

`ss -tlnp 'sport = :55552'` sin sudo:

```text
State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
```

`systemctl status msfrpcd --no-pager`:

```text
Unit msfrpcd.service could not be found.
```

Sondeo HTTP inicial con curl, sin credenciales, a
`http://127.0.0.1:55552/api/v1/json-rpc`:

```text
curl: (7) Failed to connect to 127.0.0.1 port 55552 after 0 ms: Couldn't connect to server
HTTP status: 000
Content-Type:
```

No hay respuesta HTTP ni token. No se ejecutó el POST de autenticación,
porque el servicio no existe y el puerto no escucha.

## Seguimiento tras la instalación manual (2026-09-29)

La unidad que instaló el operador con `-j` terminó con código 0.
Confirmación local: `ExecMainStatus=0`, `ActiveState=inactive`, `SubState=dead`.
`sudo -n -l` sigue devolviendo `sudo: a password is required`, también
fuera del sandbox. El fallo de bwrap y la autenticación sudo son problemas
distintos.

El archivo `lib/msf/util/service_helper.rb` captura stdout/stderr de Thin
y solo los muestra con `debug: true`. El lanzador msfrpcd no propaga el
error del proceso hijo como su propio código de salida.

Thin, ejecutado directamente desde el directorio del framework como operator,
sin token de API ni base de datos configurada, devolvió:

```text
JSON-RPC server cannot start: no API token is configured and the database is not available.
Set MSF_WS_JSON_RPC_API_TOKEN to a token of at least 16 characters, which needs no database,
or run 'msfdb init' and create a user to authenticate with database API tokens.
(Msf::WebServices::JsonRpcApp::BootError)
```

No se pudo leer la configuración privada de root; esta reproducción no
demuestra que ese sea el único fallo de la ejecución original como root.
Una primera prueba desde `/` falló además porque Bootsnap intentó recorrer
`/usr/lib/ssl/private`; se corrigió usando el directorio del framework.

Se probó MessagePack con una contraseña aleatoria temporal y credenciales
por `MSF_RPC_USER`/`MSF_RPC_PASS`. Se necesita array posicional y el header
exacto `Content-Type: binary/message-pack`. Las cadenas binarias de Ruby,
incluidas las claves, necesitan normalizarse a texto.

Prueba final con `scripts/msf_verify.py`, utilizando curl:

```text
curl: HTTP 200; transporte: MessagePack; endpoint: /api/
auth.login: success; token: [REDACTED]
core.version: 6.5.3-dev-
Daemon log contains password: False
```

El daemon temporal en 127.0.0.1:55552 se cerró al terminar. Esto valida RPC,
pero falta aplicar y verificar la unidad persistente. Una prueba adicional
de `auth.logout` devolvió HTTP 500; el verificador deja expirar el token
temporal y no lo registra. No se investigó ese método opcional.

Pasaron `bash -n` del instalador, `systemd-analyze verify` de la unidad
generada y Ruff F,E9 del verificador.
