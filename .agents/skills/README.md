# Skills de OmniAgentCS

Una *skill* es un procedimiento curado en `.agents/skills/<nombre>/SKILL.md`. El
operador puede activarlas (`/skills use`, `--skill`), y desde WP4 el agente
también puede consultarlas y cargarlas por su cuenta con las tools de solo
lectura `nexus.skill.list` y `nexus.skill.load`: el prompt lleva un índice de una
línea por skill y, si el bucle detecta un atasco (tres turnos con la misma tool
sin hechos nuevos), le sugiere cargar la que encaje. El cuerpo cargado sigue
siendo **datos no confiables**, con su estado de firma y sus señales.

## Skills incluidas

| Skill | Para qué |
| --- | --- |
| `example` | Barrido de puertos y servicios (solo lectura). |
| `web-upload-webshell` | Subir una webshell a un formulario, evadir el filtro de extensión y conseguir RCE (receta medida en RootMe). |
| `bruteforce-hydra` | Lanzar hydra desde `nexus.shell.exec` cuando `nexus.cred.bruteforce` rechaza la wordlist (rockyou.txt, 133 MB) o se queda corto (receta medida en Simple CTF). |
| `privesc-sudo` | Escalar con sudo cuando `sudo -n -l` falla: contraseña por stdin (`sudo -S -l`), PTY con `ssh -tt`/tmux/pexpect y abuso de `sudo vim` (receta medida en Simple CTF). |
| `methodology-senior` | Enumerar antes de atacar: mapa completo de puertos y de la web (directorios, CMS, searchsploit) y FTP anónimo solo como pista con credenciales cruzadas (medido en Simple CTF). |

## Estados de confianza

| Estado | Cuándo | Cómo la trata el agente |
| --- | --- | --- |
| `firmada` | `SKILL.md.sig` coincide con el HMAC bajo `NEXUS_SCOPE_SIGNING_SECRET` | guía de confianza, aún delimitada como datos |
| `sin firma` | no hay `.sig` | **datos no confiables** con aviso explícito |
| `inválida` | hay `.sig` pero no verifica | **se rechaza**; nunca llega al prompt |

## La skill de ejemplo (`example/`)

`example/SKILL.md` se envía **sin firma** a propósito: una firma válida depende
de *tu* `NEXUS_SCOPE_SIGNING_SECRET` y no puede venir en el repositorio (firmar
con un secreto público sería forjable; incluir tu secreto lo filtraría). Sin
firma, la skill se trata como datos no confiables, que es el modo seguro.

## Firmar tu propia skill

Con `NEXUS_SCOPE_SIGNING_SECRET` definido en el entorno:

```bash
.venv/bin/python - <<'PY'
import os
from pathlib import Path
from nexus_core.agent.skills import sign_skill, SIGNATURE_SUFFIX, SKILL_FILENAME

body = Path(".agents/skills/example") / SKILL_FILENAME
body.with_name(SKILL_FILENAME + SIGNATURE_SUFFIX).write_text(
    sign_skill(body.read_bytes(), os.environ["NEXUS_SCOPE_SIGNING_SECRET"])
)
print("firma escrita en", body.with_name(SKILL_FILENAME + SIGNATURE_SUFFIX))
PY
```

## Usarlas desde el REPL

```
/skills list          # lista con estado de confianza y sha256
/skills show example  # previsualiza el contenido antes de activarla
/skills use example   # la activa para esta sesión
/skills off           # desactiva todas
```

En modo headless: `omni run "<objetivo>" --skill example --json`.
