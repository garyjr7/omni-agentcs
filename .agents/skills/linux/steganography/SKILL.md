---
name: linux/steganography
description: Steghide sin root, señuelos y flags por OCR cuando apt-get install falla.
---

# Esteganografía en una sala (steghide sin root)

Receta medida en `blackbox-10.67.183.218` (2026-10-19). La página entregaba
cuatro imágenes, una nota con una contraseña y un enlace que resolvía a
*Stegosauria*. El agente de OMNI lo entendió todo y aun así no lo resolvió:
`steghide` no estaba instalado, `apt-get install steghide` falló por permisos
(el sandbox no es root) y `nexus.system.install_tool` respondió
`tool is not in the install catalog`. La credencial estaba en `header.jpg`,
detrás de esa contraseña, y el run murió sin intentar la ruta sin root.

## Regla de oro

**La contraseña de la nota es la passphrase de la imagen, no un login.**
Si un comentario, un `README` o una nota dice *"recuerda tu password: X"*,
prueba X contra **todas** las imágenes del sitio antes de tocar cualquier
formulario. Después de extraer, las credenciales que salgan sí van al login.

**Prueba todas las imágenes, no la que parece obvia.** En esta sala
`stego.jpg` era un señuelo que respondía *"You're on the right path, but wrong
image!"*; el payload estaba en `header.jpg`. Si una extracción dice "wrong
image", no es un fallo: es una instrucción.

## 1. Si `steghide` no está: instálalo sin root

`sudo` está prohibido en `nexus.shell.exec` y `apt-get install` siempre falla
con `Permission denied`. La vía que funciona es descargar el `.deb` y
extraerlo en el workspace — no requiere privilegios:

```bash
cd "$PWD"
apt-get download steghide
dpkg -x steghide_*.deb ./steghide
export PATH=$PATH:$PWD/steghide/usr/bin
steghide --version
```

Si el binario arranca pero se queja de una librería, añade la del paquete:

```bash
export LD_LIBRARY_PATH=$PWD/steghide/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
```

Y comprueba que no falte nada con `ldd "$PWD/steghide/usr/bin/steghide"`.
No compiles desde el código fuente: `gcc` y `make` están, pero faltan
`jpeglib.h`/`mcrypt.h` y el intento consume turnos sin producir binario.

## 2. Extrae el payload

```bash
steghide info imagen.jpg                    # ¿lleva datos? (pide passphrase)
steghide extract -sf imagen.jpg -p 'PASS' -xf salida.txt -f
cat salida.txt
```

Orden de intentos: la passphrase de la nota, vacía (`-p ''`), el nombre del
usuario, el nombre del archivo. Nunca más de una decena: si no sale, la imagen
no es o la pista no era esa.

## 3. Si `steghide` no es una opción

Antes de instalar nada, agota lo que ya está (detalle en
`linux/forensics-basics`):

```bash
file imagen.jpg
strings -n 6 imagen.jpg | grep -Ei 'pass|flag|thm|htb|token|secret|/home|/root'
exiftool imagen.jpg 2>/dev/null
binwalk imagen.jpg 2>/dev/null || true
```

- Un `PK\x03\x04` en la cabecera es un ZIP: `unzip -l imagen.jpg`.
- Un JPEG/PNG con datos tras el `FFD9`/`IEND`: `binwalk -e` o `dd` desde el
  offset que marca `binwalk`.
- LSB (PNG sobre todo):

```bash
python3 - <<'PY'
from PIL import Image
im = Image.open("imagen.png").convert("RGB")
bits = "".join(str(p[i] & 1) for p in im.getdata() for i in range(3))
print(bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))[:200])
PY
```

## 4. Flags impresas en una foto

Una "flag" puede estar **escrita en la imagen**, no escondida en sus bits. Si
`steghide`, `strings` y `binwalk` no dan nada y la imagen es una foto o un
escaneo, haz OCR:

```bash
tesseract imagen.jpg stdout 2>/dev/null | grep -Ei 'flag|thm|htb|securi|\{'
```

En esta sala la flag de usuario estaba impresa en `user.jpg` (una receta de
sopa) y solo aparecía por OCR.

## 5. Antes de cerrar

- Copia lo extraído a un artefacto del run y cita la ruta: el verificador solo
  acredita lo que aparece en la salida de una tool.
- Las credenciales extraídas van a `nexus.knowledge.record_fact`
  (`fact_type="credential"`) y se prueban en el login de la misma página.
- Si la extracción falla, **no repitas el mismo comando**: cambia de imagen, de
  passphrase o de técnica. Tres fallos idénticos son un turno perdido.
