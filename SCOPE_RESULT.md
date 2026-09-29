# SCOPE_RESULT — Verificación de Scope Gating

Fecha: 2026-09-29
Rama: `feat/scope-gating`
Entorno: `.venv/bin/python` (Python 3.12.3), `pytest 9.1.1`, `ruff 0.16.1`.
> Nota: `python`, `pytest`, `ruff` y `rg` no están en el PATH global; se usó el
> `.venv` del repo y `grep` en lugar de `rg`. El código nuevo sólo usa stdlib
> (json, dataclasses, datetime, enum, uuid-like, ipaddress, socket, hashlib,
> hmac, re, typing) — cero dependencias externas.

## 1. Imports

```
$ .venv/bin/python -c "import nexus_api.main"            → nexus_api.main OK
$ .venv/bin/python -c "import nexus_core.kernel.runtime" → nexus_core.kernel.runtime OK
$ .venv/bin/python -c "import nexus_core.scope"          → nexus_core.scope OK
$ .venv/bin/python -c "import nexus_worker"              → nexus_worker OK
$ .venv/bin/python -c "import nexus_mcp.server"          → nexus_mcp.server OK
```

## 2. Tests

```
$ .venv/bin/python -m pytest nexus_core/tests/unit -q
============================== 71 passed in 3.76s ==============================
```

- 43 tests originales: **siguen pasando sin modificación**.
  - `test_kernel_offline.py::...::test_tool_gateway_requires_approval_and_audits` ✅
  - `test_kernel_offline.py::...::test_tool_gateway_validates_schema_quota_and_output` ✅
- 28 tests nuevos en `test_scope.py`: **todos pasan**.

```
$ .venv/bin/python -m pytest nexus_core/tests/unit/test_scope.py -v
...
============================== 28 passed in 0.44s ==============================
```

Cobertura de los 20 tests obligatorios (todos presentes):

1.  `test_ip_in_scope_passes`
2.  `test_ip_out_of_scope_raises`
3.  `test_cidr_fully_contained_passes`
4.  `test_cidr_partially_outside_raises`
5.  `test_exclusion_overrides_scope`
6.  `test_domain_exact_match`
7.  `test_domain_wildcard_matches_subdomain`
8.  `test_domain_wildcard_does_not_match_root`
9.  `test_domain_dot_prefix_matches_root_and_sub`
10. `test_domain_resolves_to_multiple_ips_all_must_be_in_scope`
11. `test_domain_resolving_to_private_ip_outside_private_cidr_raises`
12. `test_url_target_extracts_host`
13. `test_time_window_expired_raises`
14. `test_time_window_not_yet_valid_raises`
15. `test_signature_valid_passes`
16. `test_signature_invalid_raises`
17. `test_signature_absent_is_allowed`
18. `test_tool_gateway_denies_when_scope_required_and_missing`
19. `test_tool_gateway_denies_when_target_out_of_scope`
20. `test_tool_gateway_audits_scope_denial`

Tests adicionales (8): `test_private_ip_with_private_cidr_is_allowed`,
`test_private_ip_denied_when_disabled`, `test_unrecognized_target_raises`,
`test_resolver_deduplicates_and_caches`, `test_resolver_failure_raises_unresolvable`,
`test_store_roundtrip_and_tenant_isolation`, `test_load_active_returns_current_engagement`,
`test_tool_gateway_allows_in_scope_target`.

## 3. Lint

```
$ .venv/bin/ruff check nexus_core/scope nexus_core/kernel nexus_core/tests/unit/test_scope.py --select F,E9
All checks passed!
```

## 4. Residuales

```
$ grep -rnE "TODO|FIXME|XXX|HACK|raise NotImplementedError" nexus_core/scope/ nexus_core/kernel/tool_gateway.py
(exit 1, sin coincidencias)
```

## 5. Criterios de éxito

| Criterio | Estado |
|---|---|
| Imports OK (incluye `nexus_core.scope`) | ✅ (5/5, más `nexus_core.kernel.runtime`) |
| 43 tests originales siguen pasando | ✅ |
| ≥20 tests nuevos pasan en `test_scope.py` | ✅ (28) |
| ruff sin F ni E9 en archivos nuevos/modificados | ✅ |
| Cero TODOs en el código nuevo | ✅ |
| `ToolDefinition.scope_target_field` y `scope_required` con default | ✅ |
| `RunContext.scope` con default `None` | ✅ |
| `ToolGateway` audita denegaciones con `action="scope.denied"` | ✅ |
| Commit `feat/scope-gating` | ✅ |

## 6. Decisiones de diseño no especificadas en el prompt

1. **Modelo de excepciones**: `ScopeExpired`, `ScopeSignatureInvalid`,
   `ScopeUnresolvable` y `ScopePrivateIP` heredan `__init__` de `ScopeViolation`
   (no redefinen firma), por lo que `assertRaises(ScopeViolation)` captura todas.
2. **Precedencia privada vs. contención**: para IPs, la comprobación de rango
   privado se ejecuta *antes* de la contención en CIDR, de modo que una IP privada
   fuera de todo CIDR privado produce `ScopePrivateIP` (requisito del test 11) en
   lugar de un genérico "fuera de scope". Para CIDR se comprueba primero la
   contención.
3. **`urls`**: los targets URL se validan por host (regla literal del prompt). El
   campo `urls` se persiste pero no se usa como allowlist por path; documentado.
4. **`localhost`**: sin punto, pero aceptado como dominio porque el resolver está
   especificado para resolverlo; el validator decide sobre sus IPs loopback.
5. **`EngagementStore.create()`**: INSERT simple (respeta `UNIQUE(tenant_id,name)`);
   rellena `created_at` con `utc_now()` si viene vacío.
6. **`load_active()`**: filtra en Python por ventana temporal (parseo robusto de
   ISO 8601) y devuelve el de `valid_from` más reciente.
7. **`DNSResolver`**: usa `socket.getaddrinfo(..., type=SOCK_STREAM)`, deduplica,
   cachea por TTL y aplica `timeout_seconds` vía `socket.setdefaulttimeout`
   restaurando el valor previo. Aplica `clear_cache()`.

## 7. Commit

```
git add -A && git commit -m "feat(scope): validación obligatoria de targets en ToolGateway"
```

NO se hizo push.
