---
name: bruteforce-hydra
description: Prueba credenciales con hydra (SSH, FTP y formularios web http-post-form/http-get-form) para las variantes que la tool de credenciales no cubre: varios usuarios, máscaras, cookies o CSRF.
---

# Fuerza bruta con hydra

Receta para cuando hay un login (SSH, FTP o un formulario web) y una wordlist.
La tool `nexus.cred.bruteforce` ya cubre `ssh`, `ftp`, `telnet`,
`http-post-form` y `http-get-form`, descuenta `rockyou.txt` sin copiarla y deja
la contraseña en la bóveda; esta skill es para lo que la tool **no** expone.

## 1. Cuándo usar esta receta

Usa `nexus.cred.bruteforce` primero. Pasa a `nexus.shell.exec` con hydra solo si:

- necesitas variantes que la tool no expone: `-L` (varios usuarios), `-e nsr`
  (usuario=contraseña, vacía, inversa), `-x` (máscara), `-M` (lista de hosts);
- el formulario necesita cookies de sesión, un token CSRF o `:H=` (cabeceras);
- el barrido se cortó por el presupuesto (`timeout_seconds`) y tienes una pista
  **concreta** de que la contraseña está más adelante en la lista: la tool no
  impone topes propios, el corte lo decide su contrato o el presupuesto del run.

No lo uses para probar 3 credenciales sueltas ni para repetir el barrido que la
tool ya cerró con un `barrier`: ahí `nexus.cred.bruteforce` es más barato y no
expone la contraseña en el prompt.

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
se llena de basura. `nexus.cred.bruteforce` la lee de `/usr/share/wordlists` y
corta solo las líneas que va a probar.

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

Para un formulario web, la tool ya lo hace con su spec de hydra:

```
nexus.cred.bruteforce(
    target="<ip>", service="http-post-form", port=80,
    username="admin", password_file="/usr/share/wordlists/rockyou.txt",
    form_url="/admin/index.php",
    form_params="user=^USER^&pass=^PASS^&submit=Login",
    failure_string="Invalid username or password",
)
```

- `form_url` es la **ruta** que procesa el POST (mírala en el `action=` del
  HTML), no la página del formulario si son distintas;
- `form_params` son los `name=` reales de los campos, con `^USER^` y `^PASS^`
  donde van la credencial;
- `failure_string` es el texto que aparece **solo cuando falla** ("Incorrect",
  "Invalid credentials", "Login failed"). Sin él hydra no puede distinguir un
  login bueno de uno malo y reporta todo como fallo;
- si es HTTPS, el puerto 443/8443 activa `-S` solo;
- si el login exige una cookie o un token, no insistas con la tool: usa
  `nexus.shell.exec` con `hydra ... http-post-form "<path>:<params>:F=<fallo>:H=Cookie\\: <valor>"`.
- **al acertar, usa la sesión que la tool ya abrió**: la respuesta trae
  `session.session_ref` (una referencia del vault, no la cookie en claro).
  Pásala a `nexus.web.request(session_ref="vault:...")` para pedir
  `/admin/panel/`, la clave o el siguiente paso autenticado; volver a barrer o
  repetir el login sin la cookie es el muro que dejó el run v7 sin avanzar.

A mano sería:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 80 -t 4 -f -I \
  <target> http-post-form "/admin/index.php:user=^USER^&pass=^PASS^&submit=Login:F=Invalid username or password"
```

## 4. Comprueba el acierto

Hydra imprime la línea del hallazgo:

```
[2222][ssh] host: 10.10.10.5   login: mitch   password: secret
```

y **el código de salida no es el veredicto** (puede terminar en 0 o en 255 sin
encontrar nada), así que no te fíes de él. Verifica con un login real, no
repitiendo el ataque:

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

- **`outcome="partial"`**: la tool prueba un slice (5 000 entradas por
  defecto) y la lista tiene más. La respuesta dice `next_start_at`: repite la
  llamada con ese `start_at`; no es un veredicto sobre el objetivo y no cierra
  la rama. Solo un barrido que llegó al final sin hit es `negative` y deja un
  `barrier` (ahí se pivota, no se repite).
- **El barrido se corta por presupuesto** (`timeout_seconds`, 900 s por
  defecto): no es un veredicto. No relances rockyou entero: sube
  `timeout_seconds`, baja `max_attempts` y continúa con `start_at`, o cambia de
  vector.
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
