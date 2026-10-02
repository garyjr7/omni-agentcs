#!/usr/bin/env bash
# OmniAgentCS — instalador de un solo comando.
#
#   curl -fsSL https://raw.githubusercontent.com/bajioware/omni-agentcs/main/scripts/install.sh | sh
#
# Instala el CLI de forma aislada con pipx (preferido) o, si no está, crea un
# venv en ~/.local/share/omniagentcs y enlaza `omni` en ~/.local/bin.
set -euo pipefail

PYPI_NAME="${OMNI_PYPI_NAME:-omniagentcs}"
BIN_DIR="${HOME}/.local/bin"
VENV_DIR="${HOME}/.local/share/omniagentcs/venv"

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

PY="$(python_bin || true)"
if [[ -z "$PY" ]]; then
    echo "ERROR: se requiere Python 3.12+ y no se encontró en PATH." >&2
    exit 1
fi

echo "OmniAgentCS — instalación"
log "python: $($PY --version 2>&1)"

if command -v pipx >/dev/null 2>&1; then
    log "pipx detectado: instalando $PYPI_NAME"
    pipx install --force "$PYPI_NAME"
elif "$PY" -m pip --version >/dev/null 2>&1; then
    log "pipx ausente: creando venv aislado en $VENV_DIR"
    "$PY" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
    "$VENV_DIR/bin/python" -m pip install --upgrade "$PYPI_NAME"
    mkdir -p "$BIN_DIR"
    ln -sf "$VENV_DIR/bin/omni" "$BIN_DIR/omni"
    log "enlace creado: $BIN_DIR/omni"
else
    echo "ERROR: no hay pipx ni pip disponibles para $PY." >&2
    exit 1
fi

if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
    log "NOTA: añade $BIN_DIR a tu PATH:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
fi

echo
log "Listo. Ejecuta: omni --doctor --no-wizard"
