# Checklist de release — `v3.2.0`

Estado medido a **2026-11-20** sobre `main` (`dd917f5`), tras el cierre de
V0-12, V0-33 y SEC-07.

Versión en código: `3.2.0` (`pyproject.toml`, `nexus_core/cli/main.py`).

Esta entrega convierte el cierre de un engagement en una decisión multi-vector,
deduplica los hechos del blackboard y exige rol de aprobador en las decisiones.
No cambia el modelo de sandbox ni el gateway.

## Gates ejecutados

| Gate | Comando | Resultado |
| --- | --- | --- |
| Versión en código | `omni.py --version` | `omni 3.2.0` |
| Sintaxis y lint | `make lint` | **All checks passed** (`F,E9`) |
| Tipos incrementales | `make typecheck TYPECHECK_BASE=HEAD` | **0 errores en 15 ficheros** |
| Tipos estrictos | `make typecheck-strict` | **0 errores en 182 ficheros** |
| Suite completa | `CI=true .venv/bin/python -m pytest nexus_core/tests -q` | **4.997 passed, 55 skipped** (337 s) |
| Tests de las áreas tocadas | `test_v320_vectors_and_supersede.py` | **9 passed** |
| Secretos | `gitleaks` sobre `0454435..dd917f5` | **0 hallazgos** |
| CI remoto | GitHub Actions sobre `dd917f5` | **Verde** (`cli`, `coverage`, `postgres`, `secrets`) |
| Tag | anotado `v3.2.0` | **Creado y publicado** (`1eaa4d7`, apunta a `dd917f5`) |

## Qué entra en `v3.2.0`

- **V0-12 · Planificador multi-vector.** Estado durable por servicio en
  `kernel_run_state` (`attack_vectors`): `discovered → tested → exploited` o
  `discarded`, con cola de prioridad. `task_complete` se rechaza mientras quede
  un vector abierto. Las credenciales verificadas se reutilizan en los demás
  servicios del host sin volver a exponer el secreto en el prompt. Prueba
  sintética de tres rutas (SSH, web y API oculta).
- **V0-33 · Supersede y deduplicación.** Clave canónica por hecho; al re-grabar
  se marca la versión anterior con `superseded_by` en la misma escritura.
  `list_facts`, el informe y el inventario devuelven una sola versión vigente.
  Un hecho verificado nunca es sombreado por una hipótesis del agente (V1-33).
- **SEC-07 · Rol del aprobador.** `ApprovalService.decide()` exige `approver` o
  `admin`, explícito o resuelto desde `kernel_users`/`kernel_service_accounts`
  del tenant. Un `viewer` recibe `PermissionError`. La CLI y el resume declaran
  su rol de forma explícita.
- **Documentación y versión.** `CHANGELOG`, `BACKLOG`, `INDEX` y
  `MASTER_ROADMAP` actualizados; `pyproject.toml` y `PROGRAM_VERSION` en
  `3.2.0`.

## Seguridad: estado honesto

- **SEC-01 — Parcial.** El shell universal no está cubierto por el scope por
  defecto. La mitigación real es el modo `egress` opt-in
  (`NEXUS_SHELL_ISOLATION=egress`): bwrap + netns + SOCKS5 gobernado por scope.
- **SEC-02 — Abierto.** En modo local el shell puede leer el HOME real; el
  aislamiento por defecto es parcial, no de lectura.
- **SEC-03 — Cerrado.** `oci_network` implementado con red `--internal` y proxy
  SOCKS5 del scope; sin proxy falla cerrado (ADR-004). La validación de rutas
  reales sigue en P1-B.
- **SEC-07 — Cerrado.** El rol se comprueba antes de decidir; los actores
  enrolados sin rol de aprobador quedan denegados. El camino local del operador
  sigue pasando su rol explícito.

## Checklist de publicación

- [x] Versión `3.2.0` en `pyproject.toml` y `PROGRAM_VERSION`.
- [x] `CHANGELOG.md` con la entrada `v3.2.0`.
- [x] `make lint`, typecheck incremental y typecheck estricto.
- [x] Suite completa en verde.
- [x] Sin atribución de IA en el commit.
- [x] CI remoto verde sobre `dd917f5`.
- [x] Tag anotado `v3.2.0` y push del tag.
- [ ] GitHub Release con las notas de `CHANGELOG.md`.

## Próximo ciclo

La deuda funcional que queda para `v3.3.0` está en `BACKLOG.md`: V0-28
(timeout/cancelación de `ssh_exec`), V0-24/V0-27/V0-30 (extractor de loot),
V0-13 (loot de Windows), V0-32 (tamaño del informe) y las mejoras de sesión y
plataforma posteriores.
