---
name: linux/forensics-basics
description: Busca pistas en imágenes y archivos locales (strings, file, exiftool, binwalk) sin instalar paquetes, y usa steghide solo si ya está.
---

# Forense local sin instalar nada

Receta para cuando el objetivo entrega una imagen, un archivo comprimido o un
binario y hace falta sacar de ahí una pista (contraseña, ruta, flag). Medida en
`blackbox-10.67.183.218` (2026-10-19): el agente intentó `apt-get install
steghide` tres veces, el sandbox rechazó la instalación por permisos y el turno
se perdió; el mismo resultado estaba en las herramientas que ya trae Kali.

## Regla

**No instales paquetes.** El sandbox no es root y `apt` solo produce
`Permission denied`. Si el binario no está, usa una alternativa local. `steghide`
solo se ejecuta si `command -v steghide` lo encuentra; nunca lo instales.

## 1. Identifica el archivo antes de tocarlo

```bash
file archivo
ls -la archivo
xxd -l 64 archivo          # cabecera: PNG, JPEG, ZIP, ELF, PDF
```

La extensión miente; la cabecera no. Un `PK\x03\x04` es un ZIP aunque se llame
`.jpg`: `unzip -l archivo` lista su contenido.

## 2. Texto incrustado (sin dependencias)

```bash
strings -n 6 archivo
strings -el archivo        # UTF-16 (típico en binarios Windows)
strings archivo | grep -Ei 'pass|flag|thm|htb|token|secret|/home|/root'
```

Para una imagen, `strings` suele revelar comentarios, rutas y credenciales
dejadas por herramientas de esteganografía.

## 3. Metadatos

```bash
exiftool archivo 2>/dev/null || identify -verbose archivo 2>/dev/null
```

`exiftool` viene en Kali; si no está, `identify` de ImageMagick cubre lo básico.
Mira `Comment`, `Artist`, `Software`, `Description` y cualquier campo con texto
legible.

## 4. Esteganografía y contenedores

```bash
command -v steghide >/dev/null && steghide info archivo        # solo si existe
binwalk archivo                                                # firmas y offsets
binwalk -e archivo                                             # extrae (si está)
foremost -i archivo -o salida 2>/dev/null                      # alternativa
```

Si `steghide` pide contraseña y no la tienes, no adivines: busca primero en
metadatos, `strings` y el nombre del archivo. Una contraseña vacía es común:
`steghide extract -sf archivo -p ''`.

## 5. Imágenes y audio

```bash
zsteg archivo.png 2>/dev/null || true       # PNG/BMP (si está instalado)
python3 - <<'PY'
from PIL import Image
print(Image.open("archivo.png").info)
PY
```

Si Pillow no está, `pngcheck -v archivo.png` o `xxd` sobre los chunks `tEXt`
siguen siendo locales y suficientes para una pista.

## 6. Antes de cerrar

- Copia el hallazgo a un artefacto del run (`nexus.workspace.write`) y cita la
  ruta exacta; el verificador solo acredita lo que aparece en la salida.
- Si el archivo no da nada, vuelve a la enumeración: la pista suele estar en el
  servicio (FTP, SMB, web), no dentro de la imagen.
- **Nunca** propongas `apt-get install`/`apt install` como siguiente paso.
