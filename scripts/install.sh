#!/usr/bin/env bash
# OmniAgentCS — instalador de un solo comando.
#
#   curl -fsSL https://raw.githubusercontent.com/garyjr7/NEXUS/main/scripts/install.sh | sh
#
# Fuente de instalación, en orden de preferencia:
#   1. $OMNI_SOURCE     spec instalable de pip/pipx (ruta local, git URL o nombre)
#   2. checkout local   si este script vive dentro de un repo con pyproject.toml
#   3. $OMNI_GIT_URL    repo del proyecto (por defecto git+https://github.com/garyjr7/NEXUS.git)
#   4. PyPI             $OMNI_PYPI_NAME (último recurso, solo si las anteriores fallan)
#
# Instala de forma aislada con pipx (preferido) o, si no está, crea un venv en
# ~/.local/share/omniagentcs y enlaza `omni` en ~/.local/bin.
set -euo pipefail

PYPI_NAME="${OMNI_PYPI_NAME:-omniagentcs}"
GIT_URL="${OMNI_GIT_URL:-git+https://github.com/garyjr7/NEXUS.git}"
BIN_DIR="${HOME}/.local/bin"
VENV_DIR="${HOME}/.local/share/omniagentcs/venv"

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

python_bin() {
    for candidate in python3.12 python3.13 python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
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
    local here repo
    here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || true
    if [[ -n "${here:-}" ]]; then
        repo="$(cd -- "${here}/.." 2>/dev/null && pwd)" || true
        if [[ -n "${repo:-}" && -f "${repo}/pyproject.toml" ]]; then
            printf '%s' "$repo"
            return 0
        fi
    fi
    printf '%s' "$GIT_URL"
}

SOURCE="$(resolve_source)"
KIND="$(source_kind "$SOURCE")"

if [[ "$KIND" == "git" && "$DRY_RUN" != 1 ]] && ! command -v git >/dev/null 2>&1; then
    echo "ERROR: la fuente '$SOURCE' requiere git y no está en PATH." >&2
    exit 1
fi

echo "OmniAgentCS — instalación"
log "fuente: $SOURCE ($KIND)"

if [[ "$DRY_RUN" == 1 ]]; then
    log "modo --dry-run: no se instala nada"
    if command -v pipx >/dev/null 2>&1; then
        log "plan: pipx install --force \"$SOURCE\""
    else
        log "plan: python -m venv $VENV_DIR"
        log "plan: $VENV_DIR/bin/python -m pip install --upgrade \"$SOURCE\""
        log "plan: ln -sf $VENV_DIR/bin/omni $BIN_DIR/omni"
    fi
    exit 0
fi

PY="$(python_bin || true)"
if [[ -z "$PY" ]]; then
    echo "ERROR: se requiere Python 3.12+ y no se encontró en PATH." >&2
    exit 1
fi
log "python: $($PY --version 2>&1)"

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
    echo "ERROR: no se pudo instalar '$SOURCE'." >&2
    return 1
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

if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
    log "NOTA: añade $BIN_DIR a tu PATH:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
fi

echo
log "Listo. Ejecuta: omni --setup"
