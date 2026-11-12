#!/usr/bin/env bash
# purge_history.sh — CONTINGENCIA INERTE para SEC-00.
#
# Estado: NO se ha ejecutado y NO se debe ejecutar mientras docs/audits/SEC00_VERIFICATION.md
# diga LIMPIO. El escaneo del 2026-10-28 (223 commits, 2903 blobs) no encontró
# ninguna credencial de proveedor, y los commits b127c29 / a8c2046 que cita la
# auditoría no existen en este repositorio. Usa este script solo si:
#   (a) descubres que esos SHAs siguen resolviendo en GitHub, o
#   (b) tienes que limpiar el clon ANTIGUO del operador (H2 en el informe).
#
# Qué hace: reescribe el historial de un CLON MIRROR (nunca del repo de trabajo),
# sustituyendo secretos literales y borrando ficheros .env versionados por error.
# Qué NO hace: no hace push, no toca el repo original, no rota claves.
#
# Requisitos:
#   pip install git-filter-repo      # o: apt install git-filter-repo
#
# Uso:
#   1) Crea el fichero de patrones (fuera del repo, en /tmp), UN secreto por
#      línea con el formato de git-filter-repo. Los valores literales NUNCA se
#      commitean:
#
#        cat > /tmp/sec00-patterns.txt <<'EOF'
#        sk-proj-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX==>***REMOVED***
#        AIzaSyXXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXX==>***REMOVED***
#        regex:sk-[A-Za-z0-9_-]{32,}==>***REMOVED***
#        regex:AIza[0-9A-Za-z_-]{35}==>***REMOVED***
#        EOF
#
#   2) Revisa el plan (no modifica nada):
#        scripts/purge_history.sh --patterns /tmp/sec00-patterns.txt
#
#   3) Ejecuta de verdad:
#        scripts/purge_history.sh --patterns /tmp/sec00-patterns.txt --confirm
#
#   4) Publica (manual, decisión del operador, coordinado con todo el equipo):
#        cd /tmp/omni-purge-*/omni-agentcs.git
#        git push --force --mirror origin
#      Después: pedir a GitHub Support la purga de objetos colgantes, avisar a
#      todos los clones de que re-clonen, y verificar con:
#        git clone --mirror <url> /tmp/verify && cd /tmp/verify && git log --all --oneline
#
set -euo pipefail

REPO_URL_DEFAULT="$(git -C "$(dirname "$0")/.." remote get-url origin 2>/dev/null || echo '')"
PATTERNS=""
REPO_URL="$REPO_URL_DEFAULT"
CONFIRM=0

usage() { sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --patterns) PATTERNS="${2:-}"; shift 2 ;;
    --repo)     REPO_URL="${2:-}"; shift 2 ;;
    --confirm)  CONFIRM=1; shift ;;
    -h|--help)  usage 0 ;;
    *) echo "argumento desconocido: $1" >&2; usage 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

[ -n "$PATTERNS" ] || die "falta --patterns <fichero>. Ver la cabecera de este script."
[ -f "$PATTERNS" ] || die "no existe el fichero de patrones: $PATTERNS"
[ -s "$PATTERNS" ] || die "el fichero de patrones está vacío: $PATTERNS"
[ -n "$REPO_URL" ] || die "no se pudo determinar la URL del remoto; pasa --repo <url>"

# El fichero de patrones no puede vivir dentro de un árbol git: sería un secreto
# nuevo en el repo que estamos intentando limpiar.
if git -C "$(dirname "$PATTERNS")" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  die "el fichero de patrones está dentro de un repositorio git. Muévelo a /tmp."
fi

command -v git >/dev/null || die "git no está instalado."

if ! git filter-repo --version >/dev/null 2>&1; then
  cat >&2 <<'EOF'
ERROR: git-filter-repo no está instalado.

  pip install git-filter-repo
  # o
  apt install git-filter-repo        # Debian/Ubuntu con el paquete disponible

BFG Repo-Cleaner es una alternativa, pero requiere Java y su modo
`--replace-text` es menos preciso con expresiones regulares. Este script usa
git-filter-repo porque es el que permite combinar reemplazo de texto y borrado
de rutas en una sola pasada, y verificar el resultado antes de publicar.
EOF
  exit 1
fi

echo "== SEC-00 · purga de historial =="
echo "  remoto      : $REPO_URL"
echo "  patrones    : $PATTERNS ($(grep -cve '^[[:space:]]*$' "$PATTERNS" || true) reglas)"
echo "  modo        : $([ "$CONFIRM" -eq 1 ] && echo 'EJECUCIÓN' || echo 'PLAN (sin cambios)')"
echo

# --- Plan visible siempre -----------------------------------------------------
# Las reglas `regex:` se muestran enteras (son patrones, no secretos); los valores
# literales se enmascaran dejando solo el prefijo identificable. El separador
# `==>` no se toca para que el operador pueda comprobar que la regla está bien
# formada.
echo "-- Reglas que se aplicarán (literales enmascarados) --"
awk '
  /^[[:space:]]*$/ { next }
  /^(regex|glob|literal):/ { print "   " $0; next }
  {
    i = index($0, "==>")
    if (i == 0) { print "   (sin separador ==> · se ignora) " $0; next }
    left = substr($0, 1, i - 1); right = substr($0, i)
    keep = (length(left) > 8) ? 8 : 0
    shown = substr(left, 1, keep)
    for (k = keep + 1; k <= length(left); k++) shown = shown "*"
    print "   " shown right
  }
' "$PATTERNS"
echo

if [ "$CONFIRM" -ne 1 ]; then
  cat <<'EOF'
Plan únicamente: no se ha tocado nada.
Repite con --confirm para ejecutar sobre un clon mirror en /tmp.
EOF
  exit 0
fi

# --- 1. Copia mirror de seguridad --------------------------------------------
WORKDIR="$(mktemp -d /tmp/omni-purge-XXXXXXXX)"
MIRROR="$WORKDIR/omni-agentcs.git"

echo "== 1/5 clonando mirror de seguridad =="
git clone --mirror "$REPO_URL" "$MIRROR"
echo "   copia intacta en: $MIRROR"
echo "   (no se borra: es el rollback si algo sale mal)"
echo

cd "$MIRROR"

# --- 2. Snapshot del estado previo -------------------------------------------
BEFORE_COUNT="$(git rev-list --all --count)"
{
  echo "# estado previo a la purga · $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# commits: $BEFORE_COUNT"
  git for-each-ref --format='%(refname) %(objectname)'
} > "$WORKDIR/before.txt"
echo "== 2/5 estado previo guardado en $WORKDIR/before.txt =="
echo

# --- 3. Reescritura ----------------------------------------------------------
echo "== 3/5 reescribiendo historial (replace-text + borrado de .env) =="
git filter-repo \
  --replace-text "$PATTERNS" \
  --invert-paths \
  --path '.env' \
  --path-glob '.env.*' \
  --path '**/.env' \
  --path-glob '**/.env.*' \
  --path-glob '*.pem' \
  --path-glob '*.key' \
  --path-glob 'credentials.json' \
  --path-glob '**/credentials.json' \
  --force

# filter-repo elimina 'origin' a propósito; el push es un paso manual y explícito.
echo
AFTER_COUNT="$(git rev-list --all --count)"
echo "   commits después: $AFTER_COUNT (antes: $BEFORE_COUNT)"
echo

# --- 4. Verificación post-purga ----------------------------------------------
echo "== 4/5 verificando que no quedan coincidencias =="
FOUND=0
while read -r blob; do
  if git cat-file blob "$blob" 2>/dev/null \
     | grep -aqIE 'sk-[A-Za-z0-9_-]{32,}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|AKIA[0-9A-Z]{16}'; then
    echo "   PENDIENTE: blob $blob"
    FOUND=1
  fi
done < <(git rev-list --objects --all | awk '{print $1}' \
         | git cat-file --batch-check='%(objectname) %(objecttype)' \
         | awk '$2=="blob"{print $1}' | sort -u)

if [ "$FOUND" -eq 1 ]; then
  echo
  echo "AVISO: quedan coincidencias con forma de clave. Revisa el fichero de patrones:"
  echo "       probablemente falta el valor literal exacto (el reemplazo por forma"
  echo "       solo cubre los formatos conocidos)."
  echo "       El mirror intacto sigue en $MIRROR"
  exit 3
fi
echo "   sin coincidencias en el historial reescrito."
echo

# --- 5. Instrucciones de publicación -----------------------------------------
echo "== 5/5 listo. NO se ha publicado nada. =="
cat <<EOF

Copia purgada: $MIRROR
Copia intacta: $WORKDIR · rollback: git clone --mirror $MIRROR <destino>

Para publicar (decisión del operador, coordinada con todo el equipo):

  cd $MIRROR
  git remote add origin $REPO_URL
  git push --force --mirror origin

Después, obligatorio:

  1. Pedir a GitHub Support la purga de objetos colgantes del repo. Un
     force-push NO borra los commits antiguos del lado servidor: siguen
     accesibles por SHA hasta que GitHub recolecta.
  2. Revisar PRs antiguas y la red de forks; si existen, hay que limpiarlas
     o recrear el repo.
  3. Avisar a todos los clones: hay que re-clonar, no hacer pull.
  4. Verificar desde cero:
       git clone --mirror $REPO_URL /tmp/verify
       cd /tmp/verify && git log --all --oneline | wc -l
  5. Rotar toda clave que estuviera en el historial (la purga no invalida
     una clave filtrada; solo evita seguir publicándola).

EOF
