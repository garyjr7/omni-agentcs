# Checklist de release — `v3.0.0-rc3`

Estado medido a **2026-11-10** sobre `main`. Versión en código: `3.0.0rc3`
(`pyproject.toml:7`, `nexus_core/cli/main.py:17`).

Este documento no crea ni mueve tags y no autoriza un push: enumera lo medido,
lo que queda abierto y lo que requiere decisión del operador.

## Gates ejecutados

| Gate | Comando | Resultado |
| --- | --- | --- |
| Versión en código | `.venv/bin/python omni.py --version` | `omni 3.0.0rc3` |
| Tipos estrictos | `make typecheck-strict` | **0 errores en 181 ficheros** |
| Suite completa | `.venv/bin/python -m pytest nexus_core/tests -q -p no:cacheprovider` | **4894 passed, 56 skipped** (227,52 s) |
| Lint | `make lint` | **All checks passed** (`F,E9`, el contrato del proyecto) |
| Auditoría de dependencias | `make audit` | **Sin vulnerabilidades conocidas**; solo las excepciones justificadas en `SECURITY.md` §4.1 |
| Wheel | `.venv/bin/pip wheel . --no-deps -w /tmp/omni-wheel-rc3` | `omniagentcs-3.0.0rc3-py3-none-any.whl` (2.507.595 bytes) |
| Instalación (plan) | `bash install.sh --dry-run` | `pipx install --force "/home/operator/omni-agentcs"`; no toca `~/.config/omni` |
| Secretos en historia | escaneo de patrones + `gitleaks` en CI | Sin `.env` versionado; las 2 coincidencias son un fixture RSA truncado en `test_phase3n_fixes.py:44` |

## Cambios de este RC

- **Bump a `3.0.0rc3`** en `pyproject.toml` y `nexus_core/cli/main.py`. Corrige la
  incoherencia del tag `v3.0.0-rc2`, que apunta a un commit que se identifica
  como `3.0.0rc1`.
- **`typecheck-strict` es gate bloqueante de CI**: nuevo paso en
  `.github/workflows/ci.yml` que ejecuta `make typecheck-strict` en cada push y
  PR, sin base de diff. El paso incremental se conserva.
- **`make audit` ya era bloqueante** y se mantiene; no se añadió
  `continue-on-error`.
- **Lint sin cambios deliberados**: CI ejecuta el mismo `make lint` que local
  (`F,E9`). Ampliarlo a `I` produciría 277 avisos y a `I,UP,B` 840, casi todos
  preexistentes; arreglarlos es un refactor aparte, no un cambio de release. No
  se finge un gate ampliado que aún no está verde.
- **Licencia sin cambios**: `LICENSE` sigue siendo “Authorized Use Only” y
  `pyproject.toml` no declara campo `license`. La decisión entre mantenerla o
  pasar a Apache-2.0 está pendiente del operador; este RC no la asume.

## Seguridad

- **SEC-01 — Parcial.** Shell local con aislamiento opt-in
  (`NEXUS_SHELL_ISOLATION=egress`): bwrap + netns + socat, egreso gobernado por
  scope y `proxychains` envolviendo todo comando. Limitación declarada:
  `nmap` solo funciona con `-sT` (sin SYN/UDP/OS scan).
- **SEC-02 — Abierto.** En modo local el shell lee el HOME real; el aislamiento
  de escritura y proceso no es de lectura (`SECURITY.md` §1).
- **SEC-05 — Cerrado.** Los entry points de `nexus.tools` no se importan sin
  aprobación humana; `tools-trust.json` (0600) fija el SHA-256 de todos los
  ficheros de la distribución y cualquier cambio revoca la confianza. El pin no
  cubre dependencias de la distribución.
- **SEC-07 — Backlog.** `ApprovalService.decide()` no comprueba rol/tenant del
  aprobador; solo relevante con varios analistas.
- **Anti-inyección activa:** `wrap_untrusted_output`, `neutralize_delimiters` y
  `scan_untrusted_text` (`nexus_core/agent/injection.py:91-105`).

## Pendiente antes de publicar

1. **Decisión de licencia** — mantener “Authorized Use Only” o adoptar
   Apache-2.0. Si se adopta: reemplazar `LICENSE`, añadir `license =
   "Apache-2.0"` en `pyproject.toml`, crear `NOTICE` y `DISCLAIMER.md`. No se
   hizo en este RC.
2. **Push de `main`** — no realizado; requiere autorización explícita. El
   `main` remoto sigue en `0f1268f` y este RC añade commits por encima.
3. **Tag `v3.0.0-rc3`** — no creado; requiere autorización explícita. No se
   reescribe el tag remoto `v3.0.0-rc2`, que ya está publicado: rc3 se crea
   nuevo sobre el commit que resulte del push.
4. **Verificación del CI remoto** — el workflow está actualizado, pero no hay
   evidencia del run hasta que se haga push. No se puede afirmar “CI verde”
   antes de eso.
5. **Cobertura** — no re-medida en este RC. Suelo actual: 86 %
   (`Makefile:24-27`); última medida documentada: 86,2 % el 2026-11-06.
6. **Instalación limpia** — `install.sh --dry-run` solo planifica. Falta
   ejecutar `pipx install --force /home/operator/omni-agentcs` y confirmar
   `omni --version` = `3.0.0rc3` en un entorno limpio.
7. **Release en PyPI** — no preparada. La vía documentada es `install.sh` desde
   el repo.
8. **Benchmark externo vs PentAGI** — no ejecutado; ver
   `RELEASE_AUDIT_OMNI.md` §2 y §4.
9. **Documentación en inglés** — portada en inglés; `SECURITY.md`, este
   checklist y `docs/README-detailed.md` siguen en español.
10. **Documentos obsoletos** — `docs/MASTER_ROADMAP.md:1106` declara SEC-00
    abierto con commits que ya no existen en este clon; conviene archivarlo o
    actualizarlo en un commit aparte.
