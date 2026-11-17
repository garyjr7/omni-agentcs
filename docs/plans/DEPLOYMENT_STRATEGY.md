# Estrategia de despliegue — instalación y actualización

**Fecha:** 2026-10-28 · **Base:** `ca2f011` · **Piezas nuevas:** `install.sh`
(raíz), `nexus_core/cli/update.py`, aviso de actualización en la TUI.

Regla que ordena todo el documento: **el código y la configuración del operador
viven en sitios distintos y se mueven por caminos distintos**. El instalador y el
actualizador solo tocan código (venv/pipx + enlace en `~/.local/bin`);
`~/.config/omni` —donde están `config.toml` y `secrets.json`— no se escribe ni se
lee con permiso de escritura en ningún paso.

---

## 1. Ciclo de vida

```
curl … /main/install.sh | bash        omni            omni update
        │                              │                 │
        ▼                              ▼                 ▼
   install.sh              wizard/`omni auth login`   GitHub API (o $OMNI_UPDATE_URL)
   ├─ Python ≥3.12         ├─ ~/.config/omni/        ├─ compara con PROGRAM_VERSION
   ├─ pip + git            │   config.toml           ├─ pregunta [y/N]
   ├─ pipx o venv          │   secrets.json (0600)   ├─ git pull --ff-only
   └─ ~/.local/bin/omni    └─ sqlite en ~/.local/share└─ pip install en el venv actual
        (solo código)          /omni/…                   (config intacta, verificada)
```

### 1.1 Instalación — `install.sh`

1. **Requisitos:** busca en `PATH` la primera versión de Python que cumpla
   `OMNI_MIN_PYTHON` (por defecto **3.12**, que es lo que declara
   `pyproject.toml`; ver §4.1), y exige `pip` y `git` presentes.
2. **Fuente**, por orden: `$OMNI_SOURCE` → checkout local (el script junto a un
   `pyproject.toml`) → `$OMNI_GIT_URL`. No hay fallback a PyPI: si la fuente
   falla, el instalador falla cerrado.
3. **Instalación aislada:** `pipx install --force` si hay pipx; si no, crea
   `~/.local/share/omniagentcs/venv` e instala ahí. El Python del sistema no se
   modifica en ningún caso.
4. **Enlace:** `~/.local/bin/omni` → binario del venv (o el que crea pipx).
   Si `~/.local/bin` no está en `PATH`, imprime la línea `export` exacta.
5. **Garantías:** no ejecuta `omni` (sería lo único capaz de crear la config por
   el wizard), no escribe fuera del venv y de `~/.local/bin`, y compara la huella
   de `~/.config/omni/secrets.json` antes/después: si cambiara, falla con error.
6. **Idempotente:** se puede repetir; `--dry-run` imprime fuente y plan sin tocar
   nada.

### 1.2 Uso

Primera ejecución: `omni auth login` (clave oculta, guardada por el gestor de
secretos) y `omni` (wizard de configuración + engagement). El wizard es lo único
que crea `~/.config/omni`, y solo si hay TTY y no existe configuración previa.

### 1.3 Actualización — `omni update`

| Paso | Qué hace | Qué NO hace |
|---|---|---|
| Consulta | `GET /repos/garyjr7/omni-agentcs/releases/latest`; si no hay release, lee `version` del `pyproject.toml` de `main`. Timeout 2 s. | No bloquea: cualquier fallo es “no se pudo consultar”. |
| Compara | `parse_version()` numérico (`3.10 > 3.9`), contra `PROGRAM_VERSION`. | No compara texto ni asume que el tag empiece por `v`. |
| Pregunta | `Nueva versión vX.Y.Z disponible. ¿Deseas actualizar ahora? [y/N]` | Sin TTY y sin respuesta afirmativa, no hace nada. |
| Aplica | Subproceso aparte: `git pull --ff-only` (si hay `.git`) y `pip install --upgrade` en el entorno del intérprete actual, o `pipx upgrade`. | No descarga y ejecuta código en el proceso vivo; no fuerza merges; no toca el Python del sistema. |
| Verifica | Recalcula la huella de `~/.config/omni` (sha256 por fichero) y la compara. | Si cambió, **código de salida 3** con la lista de ficheros afectados en vez de un éxito silencioso. |

Códigos de salida: `0` al día / actualizado / cancelado · `1` sin red o un paso
falló · `2` uso incorrecto o instalación dentro de la config (se niega) · `3` la
configuración cambió durante la actualización.

`omni update --check` hace solo la comparación: es la forma segura de comprobar
sin modificar nada (y de probar el actualizador, §3).

### 1.4 Aviso en la TUI

Al pintar el banner, `OmniSession._announce_update_in_background()` lanza un hilo
daemon que consulta la misma fuente con el mismo tope de 2 s y, si hay versión
nueva, escribe una línea amarilla en el scrollback:

```
[!] Actualización disponible: vX.Y.Z. Ejecuta 'omni update' para instalar.
```

Nunca se espera: el prompt aparece ya; el aviso llega cuando la consulta termina
(o no llega). La escritura usa el mismo buffer bloqueado que el streaming de los
tools, así que no puede entrelazarse con la salida de un comando. Se desactiva
con `OMNI_NO_UPDATE_CHECK=1` (fuera de línea, CI, laboratorio aislado).

---

## 2. Dónde se guarda cada cosa

| Qué | Ruta | Quién lo escribe | ¿Lo toca la actualización? |
|---|---|---|---|
| Código (venv) | `~/.local/share/omniagentcs/venv` | `install.sh` | Sí: es el destino del `pip install` |
| Código (pipx) | `~/.local/pipx/venvs/omniagentcs` | `install.sh` / `pipx` | Sí: `pipx upgrade` |
| Binario en `PATH` | `~/.local/bin/omni` (symlink) | `install.sh` | No (el symlink no cambia) |
| **Configuración** | `~/.config/omni/config.toml` (`$XDG_CONFIG_HOME`) | wizard (`omni`), `omni --setup` | **No** — verificado por huella |
| **API keys** | `~/.config/omni/secrets.json` (`0600`) o keyring del SO | `omni auth login`, `/secrets` | **No** — verificado por huella |
| Base de datos | `~/.local/share/omni/control.db` (`$XDG_DATA_HOME`) | el kernel, en cada run | No |
| Estado / vault | `~/.local/state/omni/` (`$XDG_STATE_HOME`) | sesiones, vault de credenciales | No |
| Caché | `~/.cache/omni/` | el runtime | No |

Consecuencias prácticas:

- **Actualizar no cuesta reconfigurar.** Ni claves, ni engagement, ni historial.
- **Desinstalar** es `rm -rf ~/.local/share/omniagentcs ~/.local/bin/omni`
  (o `pipx uninstall omniagentcs`); `~/.config/omni` sobrevive por diseño, y se
  borra a mano si el operador quiere empezar de cero.
- **Respaldar** es copiar `~/.config/omni` (con `secrets.json` en `0600`); el
  código es reemplazable, la configuración no.
- **Trampa cubierta:** si alguien instala el código *dentro* de
  `~/.config/omni` (por ejemplo clonando ahí), `omni update` se niega a
  actualizar (código 2) porque un `git pull` podría pisar `config.toml`.

---

## 3. Cómo probar el actualizador localmente

### 3.1 Sin red y sin riesgo

```bash
bash install.sh --dry-run        # requisitos, fuente y plan; no instala
omni update --check              # compara versiones; no modifica nada
omni update                      # responde "n" en el prompt: no modifica nada
```

### 3.2 Con un manifiesto local (sin publicar el repo)

`OMNI_UPDATE_URL` apunta la consulta a cualquier endpoint que devuelva el JSON de
GitHub Releases. Sirve un fichero con `file://`, o un `http.server` si quieres
probar el transporte real:

```bash
echo '{"tag_name": "v9.9.9", "html_url": "https://example/rel"}' > /tmp/release.json
OMNI_UPDATE_URL=file:///tmp/release.json omni update --check
#   Nueva versión v9.9.9 disponible (actual v3.0.0).
#   --check: no se ha modificado nada. Ejecuta `omni update` para actualizar.

OMNI_UPDATE_URL=file:///tmp/release.json omni update
#   Nueva versión v9.9.9 disponible. ¿Deseas actualizar ahora? [y/N]
```

Un manifiesto explícito **no** usa el fallback de `pyproject.toml`: si no
responde, el resultado es “no se pudo consultar” y no un falso “al día”.

### 3.3 Actualización real, en un repo desechable

Esta es la prueba que se ejecutó (git real, pip real, config real), y no toca el
checkout de trabajo ni tu `$HOME`:

```bash
set -e; rm -rf /tmp/upd-e2e; mkdir -p /tmp/upd-e2e/config/omni; cd /tmp/upd-e2e
git init -q --bare --initial-branch=main remote.git
mkdir seed && cd seed && git init -q -b main && git config user.email t@t && git config user.name t
: > requirements-prod.in && git add -A && git commit -qm v1
git remote add origin ../remote.git && git push -q -u origin main
cd /tmp/upd-e2e && git clone -q remote.git work
cd seed && echo cambio > CHANGELOG && git add -A && git commit -qm v2 && git push -q origin main
printf '{"tag_name":"v9.9.9"}' > /tmp/upd-e2e/release.json
printf 'OPENAI_API_KEY=stored\n' > /tmp/upd-e2e/config/omni/secrets.json
printf 'schema_version = 1\n'   > /tmp/upd-e2e/config/omni/config.toml
chmod 600 /tmp/upd-e2e/config/omni/secrets.json

cd /home/<operador>/omni-agentcs
OMNI_UPDATE_URL=file:///tmp/upd-e2e/release.json .venv/bin/python - <<'PY'
import hashlib, pathlib, sys
sys.path.insert(0, "/home/<operador>/omni-agentcs")
from nexus_core.cli.update import run_update_command
work, config = pathlib.Path("/tmp/upd-e2e/work"), pathlib.Path("/tmp/upd-e2e/config/omni")
before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in config.iterdir()}
code = run_update_command([], current="3.0.0", prompt=lambda p: "y", root=work, config_dir=config)
after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in config.iterdir()}
print("exit:", code, "| config intacta:", before == after,
      "| commits:", __import__("subprocess").run(
          ["git","-C",str(work),"rev-list","--count","HEAD"], capture_output=True, text=True).stdout.strip())
PY
```

Resultado obtenido: `exit: 0 | config intacta: True | commits: 2` — el
`git pull --ff-only` avanzó el checkout desechable y `secrets.json` quedó byte a
byte idéntico, con sus permisos `600`.

### 3.4 Suite automática

```bash
pytest nexus_core/tests/unit/test_cli_update.py -q
```

Cubre: comparación de versiones, parsing de Releases y del fallback, manifiesto
local por `OMNI_UPDATE_URL`, que el prompt sea la frase documentada, que “n” no
ejecute nada, que un paso fallido no toque la config, **que `secrets.json`
sobreviva intacto**, que una escritura en `~/.config/omni` durante la
actualización se detecte (código 3), el rechazo a actualizar un árbol dentro de
la config, el aviso de la TUI (incluido el opt-out) y que `install.sh` exista en
la ruta que sirve el one-liner y su `--dry-run` no cree configuración.

---

## 4. Decisiones y límites declarados

### 4.1 Python: 3.12, no 3.10

El encargo pedía verificar `>= 3.10`, pero `pyproject.toml` declara
`requires-python = ">=3.12"`. Aceptar 3.10 solo movería el fallo a la resolución
de dependencias; el instalador exige **3.12** y el mínimo es configurable con
`OMNI_MIN_PYTHON` para forks. Si se quiere bajar el suelo real, hay que cambiar
`requires-python` y probar la suite en esa versión.

### 4.2 La actualización corre en un proceso aparte, no “en background”

`omni update` ejecuta los pasos como subprocesos (`git`, `pip`/`pipx`) y espera
su resultado: es la única forma de poder afirmar “actualizado” y de verificar
después que la configuración sigue intacta. Lo que sí es asíncrono y no
bloqueante es la **comprobación de la TUI** (hilo daemon, tope 2 s). Interpretar
“en segundo plano” como “que el comando termine antes de actualizar” dejaría al
operador sin saber si la actualización funcionó.

### 4.3 Repo privado ⇒ la consulta no puede funcionar todavía

`api.github.com/repos/garyjr7/omni-agentcs/releases/latest` y la URL `raw` de
`main` devuelven **404** mientras el repositorio sea privado (verificado el
2026-10-28). Por eso `omni update` responde “no se pudo consultar” y por eso
existe `OMNI_UPDATE_URL` (§3.2). Al publicar el repo —o al crear el primer
release— la consulta empieza a funcionar sin cambiar código.

### 4.4 Lo que este diseño no hace

- No hay auto-actualización silenciosa: siempre hay un `[y/N]`.
- No hay firma ni verificación criptográfica del artefacto más allá de TLS + git;
  la cadena de confianza es la del remoto configurado en el clon.
- `git pull --ff-only` falla (y lo dice) si el checkout tiene cambios locales que
  estorban; no hay `stash` ni `reset` automáticos, a propósito.
- No se migra la configuración entre versiones: si una versión futura cambia el
  esquema de `config.toml`, el aviso y la migración deben implementarse aparte
  (hoy `schema_version` existe pero el updater no lo toca).
