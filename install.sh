#!/usr/bin/env bash
# OmniAgentCS — instalador de un solo comando.
#
#   curl -fsSL https://raw.githubusercontent.com/garyjr7/omni-agentcs/main/install.sh | bash
#
# Fuente de instalación, en orden de preferencia:
#   1. $OMNI_SOURCE     spec instalable de pip/pipx (ruta local, git URL o nombre)
#   2. checkout local   si este script vive en un repo con pyproject.toml
#   3. $OMNI_GIT_URL    repo del proyecto (por defecto git+https://github.com/garyjr7/omni-agentcs.git)
#   4. PyPI             $OMNI_PYPI_NAME (último recurso, solo si las anteriores fallan)
#
# Instala de forma aislada con pipx (preferido) o, si no está, crea un venv en
# ~/.local/share/omniagentcs/venv y enlaza `omni` en ~/.local/bin.
#
# GARANTÍA: este script NO crea ni modifica configuración ni claves. El código
# va al venv (o a pipx) y el enlace a ~/.local/bin; la configuración del
# operador (~/.config/omni: config.toml, secrets.json) no se toca y se verifica
# al final que siga intacta. `omni` nunca se ejecuta aquí: sería lo único capaz
# de crear esa carpeta (wizard de primera ejecución).
set -euo pipefail

PYPI_NAME="${OMNI_PYPI_NAME:-omniagentcs}"
GIT_URL="${OMNI_GIT_URL:-git+https://github.com/garyjr7/omni-agentcs.git}"
BIN_DIR="${HOME}/.local/bin"
VENV_DIR="${HOME}/.local/share/omniagentcs/venv"
CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/omni"
# El proyecto declara ``requires-python = ">=3.12"`` en pyproject.toml, así que
# es lo que se exige aquí: aceptar 3.10 solo movería el fallo a la resolución
# de dependencias. Sobrescribible para forks con un mínimo distinto.
MIN_PYTHON="${OMNI_MIN_PYTHON:-3.12}"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help)
            echo "Uso: install.sh [--dry-run]"
            echo "  --dry-run  imprime la fuente y el plan sin instalar nada"
            exit 0
            ;;
        *)
            echo "Argumento desconocido: $arg" >&2
            exit 2
            ;;
    esac
done

log() { printf '  %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

version_at_least() {
    # $1 = "mayor.menor" detectado, $2 = "mayor.menor" exigido.
    local have="$1" need="$2"
    local hmaj hmin nmaj nmin
    hmaj="${have%%.*}"
    hmin="${have#*.}"; hmin="${hmin%%.*}"
    nmaj="${need%%.*}"
    nmin="${need#*.}"; nmin="${nmin%%.*}"
    [[ -n "$hmaj" && -n "$hmin" ]] || return 1
    (( hmaj > nmaj )) && return 0
    (( hmaj == nmaj && 10#${hmin:-0} >= 10#${nmin:-0} )) && return 0
    return 1
}

python_version() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null; }

python_bin() {
    # Primera versión de Python del PATH que satisface MIN_PYTHON.
    local candidate found=""
    for candidate in python3.13 python3.12 python3.14 python3 python; do
        command -v "$candidate" >/dev/null 2>&1 || continue
        found="$(python_version "$candidate" || true)"
        [[ -n "$found" ]] || continue
        if version_at_least "$found" "$MIN_PYTHON"; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

source_kind() {
    case "$1" in
        git+*|http://*|https://*) echo "git" ;;
        *pyproject.toml|/*|./*|../*) echo "ruta" ;;
        *) echo "paquete" ;;
    esac
}

resolve_source() {
    if [[ -n "${OMNI_SOURCE:-}" ]]; then
        printf '%s' "$OMNI_SOURCE"
        return 0
    fi
    # El script vive en la raíz del repo (o en /dev/fd al ir por curl | bash).
    local here
    here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || true
    if [[ -n "${here:-}" && -f "${here}/pyproject.toml" ]]; then
        printf '%s' "$here"
        return 0
    fi
    printf '%s' "$GIT_URL"
}

config_hash() {
    # Huella de las claves del operador, para comprobar que el install no las tocó.
    local secret="${CONFIG_DIR}/secrets.json"
    if [[ -f "$secret" ]]; then
        python3 - "$secret" <<'PY' 2>/dev/null || true
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
PY
    else
        echo "ausente"
    fi
}

echo "OmniAgentCS — instalación"

# --- Requisitos ---------------------------------------------------------------
if ! PY="$(python_bin)"; then
    fail "se requiere Python ${MIN_PYTHON}+ (declarado en pyproject.toml) y no se encontró una versión válida en PATH."
fi
log "python: $PY ($(python_version "$PY"))"

command -v pip >/dev/null 2>&1 || "$PY" -m pip --version >/dev/null 2>&1 \
    || fail "se requiere pip (ni 'pip' ni '$PY -m pip' están disponibles)."
log "pip: OK"

command -v git >/dev/null 2>&1 || fail "se requiere git en PATH."
log "git: $(git --version)"

SOURCE="$(resolve_source)"
KIND="$(source_kind "$SOURCE")"
log "fuente: $SOURCE ($KIND)"

# --- Plan ---------------------------------------------------------------------
if [[ "$DRY_RUN" == 1 ]]; then
    log "modo --dry-run: no se instala nada"
    if command -v pipx >/dev/null 2>&1; then
        log "plan: pipx install --force \"$SOURCE\""
    else
        log "plan: python -m venv $VENV_DIR"
        log "plan: $VENV_DIR/bin/python -m pip install --upgrade \"$SOURCE\""
        log "plan: ln -sf $VENV_DIR/bin/omni $BIN_DIR/omni"
    fi
    if command -v nuclei >/dev/null 2>&1; then
        log "plan: nuclei -update-templates -update-template-dir $HOME/.local/nuclei-templates (si aún no hay templates)"
    else
        log "plan: omitir templates de nuclei (binario nuclei ausente)"
    fi
    log "configuración del operador: $CONFIG_DIR (no se toca)"
    exit 0
fi

BEFORE_CONFIG="$(config_hash)"
if [[ -d "$CONFIG_DIR" ]]; then
    log "configuración existente: $CONFIG_DIR (se deja como está)"
else
    log "configuración: $CONFIG_DIR se creará en el primer \`omni\`, no aquí"
fi

# --- Instalación --------------------------------------------------------------
install_spec() {
    # $1 = instalador: "pipx" | "venv"
    local via="$1" spec="$2"
    if [[ "$via" == "pipx" ]]; then
        pipx install --force "$spec"
    else
        "$VENV_DIR/bin/python" -m pip install --upgrade "$spec"
    fi
}

install_from_source() {
    local via="$1"
    if install_spec "$via" "$SOURCE"; then
        return 0
    fi
    if [[ "$SOURCE" != "$PYPI_NAME" ]]; then
        log "la fuente '$SOURCE' falló; reintentando con PyPI ($PYPI_NAME)"
        install_spec "$via" "$PYPI_NAME"
        return $?
    fi
    fail "no se pudo instalar '$SOURCE'."
}

install_nuclei_templates() {
    # Nuclei is an external system tool, not a Python dependency. When it is
    # already installed, provision its community templates once into the user
    # location that the handler knows how to discover. Do not make an optional
    # scanner feed failure abort the Omni installation.
    if ! command -v nuclei >/dev/null 2>&1; then
        log "nuclei templates: omitido (nuclei no está instalado)"
        return 0
    fi

    local templates="${HOME}/.local/nuclei-templates"
    if find "$templates" -type f -name '*.yaml' -print -quit 2>/dev/null | grep -q .; then
        log "nuclei templates: ya disponibles en $templates"
        return 0
    fi

    log "nuclei templates: descargando a $templates"
    if nuclei -update-templates -update-template-dir "$templates"; then
        if find "$templates" -type f -name '*.yaml' -print -quit 2>/dev/null | grep -q .; then
            log "nuclei templates: listos en $templates"
        else
            log "AVISO: nuclei terminó sin dejar templates YAML; doctor lo reportará"
        fi
    else
        log "AVISO: no se pudieron descargar templates de nuclei; la instalación de Omni continúa"
    fi
}

if command -v pipx >/dev/null 2>&1; then
    log "pipx detectado: instalando desde $SOURCE"
    install_from_source pipx
else
    log "pipx ausente: creando venv aislado en $VENV_DIR"
    "$PY" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
    install_from_source venv
    mkdir -p "$BIN_DIR"
    ln -sf "$VENV_DIR/bin/omni" "$BIN_DIR/omni"
    log "enlace creado: $BIN_DIR/omni"
fi

install_nuclei_templates

# --- Verificación de que la configuración del operador sobrevive --------------
AFTER_CONFIG="$(config_hash)"
if [[ "$AFTER_CONFIG" != "$BEFORE_CONFIG" ]]; then
    fail "la configuración del operador cambió durante la instalación ($CONFIG_DIR/secrets.json). Restáurala desde tu copia."
fi
log "configuración del operador intacta: $CONFIG_DIR"

if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
    log "NOTA: añade $BIN_DIR a tu PATH:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
fi

echo
log "Listo. Siguiente paso (crea tu configuración y tus claves): omni auth login"
