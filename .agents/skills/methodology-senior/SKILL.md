---
name: methodology-senior
description: Metodología de enumeración antes de atacar: mapa completo de puertos y de la web (directorios, CMS, searchsploit) antes de elegir el vector; FTP/SSH solo con credenciales cruzadas.
---

# Metodología: enumerar todo antes de atacar

## La regla de oro

**NUNCA intentes explotar un servicio (FTP, SSH) solo porque encontraste una
pista. Primero completa la enumeración de TODOS los puertos abiertos.**

Una pista no es un vector. `vsftpd 3.0.3` abierto no es un exploit, `Anonymous
login allowed` no es acceso y `mitch:secret` en un `.txt` del FTP no es un run
cerrado: es una **hipótesis** que solo vale después de haber mirado el resto del
mapa. Medido en Simple CTF (2026-10-17, runs 19:36 / 20:49 / 23:16): el agente
encontró el FTP anónimo, pasó el resto del run intentando «explotarlo» y murió
sin haber enumerado `/simple/`, donde estaban el CMS vulnerable y el SQLi que
sostenían la cadena. Otra vez (2026-10-18): con `user.txt` y `root.txt` ya
capturadas, el cierre se perdió por citar mal la evidencia.

## El orden (no lo reordenes)

### 1. Todos los puertos, primero

```
nexus.recon.nmap(target=<ip>, profile="service")   # full_tcp / service ya llevan -p-
nexus.recon.nmap(target=<ip>, profile="full_tcp")  # si 'service' tarda demasiado
```

- Nada de `-p 21,22,80` «porque el FTP ya se ve»: el puerto que falta es el que
  cierra el run.
- Si el escaneo completo es lento, lánzalo igual y sigue leyendo el tablero; no
  lo sustituyas por el subconjunto que ya conoces.
- Antes de atacar, comprueba en el tablero que hay un hecho `service` por cada
  puerto abierto del escaneo. Un puerto escaneado y no registrado es trabajo
  perdido.

### 2. Si hay HTTP/HTTPS: enumeración web completa

```
nexus.recon.whatweb(targets=[<url>])                       # CMS, versiones, cabeceras
nexus.recon.gobuster(mode="dir", target=<url>,             # directorios y ficheros
                     wordlist="/usr/share/dirb/wordlists/common.txt")
nexus.web.ffuf(url=<url>, wordlist=<lista>)                # alternativa / vhosts
nexus.exploit.searchsploit(query="<producto> <version>")
```

- Enumerar directorios **antes** de elegir exploit: `/simple/`, `/panel/`,
  `/uploads/`, `/admin/` son la mitad de la sala.
- `whatweb` dice el CMS y la versión; `searchsploit` traduce eso a
  vulnerabilidades. Sin esa pareja, cualquier exploit es adivinación.
- Un CMS con versión vieja y un formulario de login son dos rutas distintas:
  anótalas ambas en el tablero (`endpoint`, `vulnerability`) antes de tocar una.
- Fuzzing/SQLi largos: `nexus.shell.exec` acepta `&`/`nohup` (devuelve PID y
  ruta de log) para lanzarlos en segundo plano y seguir enumerando; lee el log
  con `tail` cuando toque.

### 2b. Identidades: la web te dice quién existe

Cada respuesta de `nexus.web.request` trae ahora un bloque `extracted`. Si está,
léelo antes de elegir el siguiente paso:

- `emails`: direcciones publicadas (hechos `email`/`user` ya registrados).
- `people`: nombres con su rol (`Jack Rock - IT Staff`).
- `identities.convention`: la convención que confirma el correo (p. ej.
  `initial.last`), y `identities.candidates` ordenados por confianza.
- `next_steps`: las rutas enlazadas sin visitar, empezando por `/about.html`,
  `/contact.html`, `/team.html`. **Pídelas**: ahí suele estar el resto del
  equipo.

Reglas:

1. Un correo publicado fija el dominio y la convención; úsalo para derivar el
   resto de nombres, no para inventar cuentas sueltas.
2. Una identidad derivada es **hipótesis**: confirma que existe con
   `nexus.attack.ad_user_enum` (kerbrute o `GetNPUsers -no-pass`; no envía
   contraseña, no bloquea cuentas) antes de gastar un intento. Si devuelve
   `roastable`, lleva su hash a `nexus.post.crack_hash` con
   `hash_type=krb5asrep`. Un intento por cuenta; nada de rockyou contra AD.
3. El rol manda en la prioridad: IT/Admin/Security primero, la cola después.
   `identities.priority_targets` ya viene ordenado.
4. Si `extracted` está vacío, la página no publica identidades: sigue con el
   resto de la enumeración en vez de suponer que no hay usuarios en el entorno.

### 3. FTP anónimo: descargar, pero buscar credenciales cruzadas

```
nexus.recon.ftp(target=<ip>, action="list", remote_path="/")   # login anónimo por defecto
nexus.recon.ftp(target=<ip>, action="download", remote_path="/pub/ForMitch.txt")
```

- Descarga **todo** lo que haya (`pub/`, `.txt`, backups, `.zip`). Un `ForMitch.txt`
  con «mitch:secret» es una credencial para probar en **SSH y HTTP**, no una
  razón para atacar FTP.
- Tras leer el fichero: ¿es una credencial? Regístrala (`credential`), valídala
  en el servicio correcto (`nexus.post.ssh_exec` / `nexus.web.request`) y comprueba
  si da `access` verificado. Si no valida, sigue enumerando: la pista puede ser
  un señuelo o una pieza que necesita el paso 2.
- FTP anónimo se explota solo si hay una vulnerabilidad concreta (vsftpd 2.3.4
  backdoor, escritura en un directorio servido por HTTP). La versión 3.0.3 no
  lo es: no insistas.

### 4. Con el mapa completo, elige el vector

Solo ahora, con todos los puertos escaneados, la web enumerada y las pistas
cruzadas:

1. ordena los vectores por probabilidad y coste (web con CVE > credencial
   reutilizada > fuerza bruta);
2. ataca **uno** hasta conclusión (éxito o fallo determinista) antes de cambiar;
3. cada intento fallido se anota y **no se repite igual**: cambia parámetro,
   transporte o herramienta.

## Señales de que estás rompiendo la metodología

- Llevas 3+ llamadas a la misma herramienta sin hechos nuevos → para y vuelve al
  paso 1 o 2 (`nexus.skill.list`).
- Estás atacando un puerto mientras el escaneo completo sigue sin hechos
  `service` para los demás.
- Estás probando la misma credencial en el mismo servicio con el mismo comando.
- Estás escribiendo un `task_complete` sin haber citado un `invocation_id` real
  de este run (usa `nexus.knowledge.query_facts` para copiarlo).

## Cierre

- La evidencia es la que produjo una tool en este run: cita su `invocation_id`,
  su `fact_type` y su valor tal como aparecen en `query_facts`.
- Un hallazgo por hecho: no mezcles la escalada con la captura de la flag; si el
  hallazgo afirma root, cita el hecho `privilege` verificado.
- El run termina cuando el tablero sostiene el objetivo, no cuando se acaba el
  presupuesto.
