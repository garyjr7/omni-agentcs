# Skills de OmniAgentCS

Una *skill* es un procedimiento curado en `.agents/skills/<nombre>/SKILL.md`. El
operador decide cuáles activar; nada se carga de forma implícita.

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
