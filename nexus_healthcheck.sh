#!/usr/bin/env bash
# NEXUS PRO — Health Check completo
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

BASE="${NEXUS_URL:-http://localhost:8000}"
PASS=0; FAIL=0

check() {
  local name="$1" url="$2" expect="$3"
  local result
  result=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
  if [ "$result" = "$expect" ]; then
    echo -e "  ${GREEN}✓${NC} $name (HTTP $result)"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}✗${NC} $name (esperado $expect, obtenido $result)"
    FAIL=$((FAIL+1))
  fi
}

check_auth() {
  local result
  result=$(curl -s -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@nexuspro.io","password":"synthetic-password"}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if 'access_token' in d else 'FAIL')" 2>/dev/null)
  if [ "$result" = "OK" ]; then
    echo -e "  ${GREEN}✓${NC} Auth login → JWT token"
    PASS=$((PASS+1))
  else
    echo -e "  ${RED}✗${NC} Auth login falló"
    FAIL=$((FAIL+1))
  fi
}

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║   NEXUS PRO — Health Check               ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${BOLD}Sistema:${NC}"
check "Health endpoint"    "$BASE/health"   "200"
check "API Docs"           "$BASE/docs"     "200"
check "OpenAPI schema"     "$BASE/openapi.json" "200"

echo ""
echo -e "${BOLD}Auth:${NC}"
check_auth
check "Auth sin token → 401" "$BASE/auth/me" "401"

echo ""
echo -e "${BOLD}Endpoints core:${NC}"
TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nexuspro.io","password":"synthetic-password"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)

if [ -n "$TOKEN" ]; then
  for ep in "/agents" "/tasks" "/teams-v2" "/hitl/pending" "/memory/agents" "/auth/users"; do
    result=$(curl -s -o /dev/null -w "%{http_code}" \
      -H "Authorization: Bearer $TOKEN" "$BASE$ep" 2>/dev/null)
    if [[ "$result" == "200" || "$result" == "201" ]]; then
      echo -e "  ${GREEN}✓${NC} GET $ep (HTTP $result)"
      PASS=$((PASS+1))
    else
      echo -e "  ${RED}✗${NC} GET $ep (HTTP $result)"
      FAIL=$((FAIL+1))
    fi
  done
fi

echo ""
echo "────────────────────────────────────────"
TOTAL=$((PASS+FAIL))
if [ $FAIL -eq 0 ]; then
  echo -e "${GREEN}${BOLD}✓ Todos los checks pasaron ($PASS/$TOTAL)${NC}"
else
  echo -e "${YELLOW}${BOLD}⚠ $FAIL checks fallaron ($PASS/$TOTAL pasaron)${NC}"
fi
echo ""
