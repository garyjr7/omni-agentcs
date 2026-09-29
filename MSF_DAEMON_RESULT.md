# msfrpcd persistente: resultado final

2026-09-29 UTC. **Parte A verificada con MessagePack.**

El operador aplicó `sudo bash scripts/install_msfrpcd_service.sh`.
Unidad anterior: `/etc/systemd/system/msfrpcd.service.backup.pmQQE7`.
Salida del instalador:

```text
curl: HTTP 200; transporte: MessagePack; endpoint: /api/
auth.login: success; token: [REDACTED]
core.version: 6.5.3-dev-
active
enabled
LISTEN 0 256 127.0.0.1:55552 0.0.0.0:*
Parte A verificada. Configuración del cliente: MSF_RPC_TRANSPORT=msgpack.
```

El agente confirmó nuevamente active/enabled, el listener y RPC durante los
E2E. Se utiliza la alternativa MessagePack autorizada; JSON no es el criterio
aplicado a este servicio. No se reinició el host: la persistencia se comprobó
mediante la unidad habilitada en systemd.

## Unidad final instalada

```ini
# /etc/systemd/system/msfrpcd.service
[Unit]
Description=Metasploit MessagePack RPC Daemon (msfrpcd)
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/metasploit-framework/embedded/framework
EnvironmentFile=/etc/default/msfrpcd
Environment=MSF_RPC_USER=msf
ExecStart=/bin/sh -c 'export MSF_RPC_PASS="$$MSFRPC_PASSWORD"; exec /opt/metasploit-framework/bin/msfrpcd -S -a 127.0.0.1 -p 55552 -u /api/ -f'
Restart=on-failure
RestartSec=5
UMask=0077
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

`/etc/default/msfrpcd` contiene MSFRPC_PASSWORD, con permisos 600 root:root
validados por el instalador. No se reproduce su contenido secreto.
El escape $$ permite la expansión dentro del shell; MSF_RPC_PASS transmite
la contraseña por entorno sin -P en argv. exec conserva al daemon como
proceso principal. El arranque systemd no invoca sudo ni pide contraseñas.

## Gestión

```bash
sudo systemctl start msfrpcd.service
sudo systemctl stop msfrpcd.service
sudo systemctl restart msfrpcd.service
systemctl status msfrpcd.service --no-pager
systemctl is-enabled msfrpcd.service
sudo journalctl -u msfrpcd.service -n 50 --no-pager
ss -tlnp 'sport = :55552'
```

`scripts/msf_verify.py` repite el chequeo curl cuando MSF_RPC_PASSWORD o
MSFRPC_PASSWORD está exportada. No imprime tokens. El .env local está
configurado con transporte msgpack y permisos 600, e ignorado por Git.

## Cambio de transporte

-j inicia JSON-RPC y exige token de API/base de datos; -P no configura esa
autenticación. El lanzador oculta errores de Thin y puede salir con código 0
cuando el servidor hijo falla. Ver MSF_DAEMON_DIAG.md para el diagnóstico.
