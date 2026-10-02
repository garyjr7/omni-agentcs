#!/usr/bin/env bash
# Install (or repair) the msfrpcd systemd unit.
#
# Usage: sudo bash scripts/install_msfrpcd_service.sh [--password-file <path>]
#
# Without --password-file this only *repairs* an existing root-owned
# /etc/default/msfrpcd. With it (a 0600 file containing MSFRPC_PASSWORD=...),
# the file is seeded first, so a fresh machine can be configured in one run
# without ever passing the secret on the command line.
set -euo pipefail

password_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --password-file)
            password_file="${2:-}"
            shift 2
            ;;
        *)
            echo "Argumento desconocido: $1" >&2
            exit 2
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo 'Ejecutar con sudo bash scripts/install_msfrpcd_service.sh' >&2
    exit 1
fi

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
env_file=/etc/default/msfrpcd
unit_file=/etc/systemd/system/msfrpcd.service

if [[ ! -f $env_file || -L $env_file ]]; then
    if [[ -n $password_file && -f $password_file ]]; then
        # Seed the root-owned credential file from a user-supplied 0600 file.
        install -m 600 -o root -g root -- "$password_file" "$env_file"
        echo "Sembrado $env_file desde $password_file"
    else
        echo 'Falta /etc/default/msfrpcd o es un enlace simbólico.' >&2
        echo 'Crea el fichero (600 root:root) con MSFRPC_PASSWORD=<clave> o pasa --password-file <ruta>.' >&2
        exit 1
    fi
fi
if [[ $(stat -c '%a %u:%g' "$env_file") != '600 0:0' ]]; then
    echo 'El archivo de credenciales debe tener permisos 600 y propietario root:root.' >&2
    exit 1
fi
set -a
source "$env_file"
set +a
: "${MSFRPC_PASSWORD:?Falta MSFRPC_PASSWORD en /etc/default/msfrpcd}"
test -x /opt/metasploit-framework/bin/msfrpcd
test -x "$project_dir/.venv/bin/python"
command -v curl >/dev/null
command -v ss >/dev/null
"$project_dir/.venv/bin/python" -c 'import msgpack'

if [[ -e $unit_file ]]; then
    backup_file=$(mktemp /etc/systemd/system/msfrpcd.service.backup.XXXXXX)
    cp -p -- "$unit_file" "$backup_file"
    echo "Unidad anterior guardada en $backup_file"
fi

cat > "$unit_file" <<'UNIT'
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
UNIT
chmod 644 "$unit_file"
chown root:root "$unit_file"
systemd-analyze verify "$unit_file"
systemctl daemon-reload
systemctl enable msfrpcd.service
systemctl restart msfrpcd.service

ready=0
for ((attempt=0; attempt<60; attempt++)); do
    if ss -H -tln 'sport = :55552' | grep -q '127.0.0.1:55552'; then
        ready=1
        break
    fi
    sleep 1
done
if [[ $ready != 1 ]]; then
    echo 'ERROR: no hay listener después de 60 segundos. Revisar journalctl -u msfrpcd.' >&2
    exit 1
fi
"$project_dir/.venv/bin/python" "$project_dir/scripts/msf_verify.py"
sleep 3
systemctl is-active msfrpcd.service
systemctl is-enabled msfrpcd.service
ss -H -tln 'sport = :55552'
echo 'Parte A verificada. Configuración del cliente: MSF_RPC_TRANSPORT=msgpack.'
