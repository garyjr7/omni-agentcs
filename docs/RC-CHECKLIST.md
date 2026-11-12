# Checklist de release — `v3.0.0-rc3`

Estado medido a **2026-11-10** sobre `main` en `4d28437`. Versión en código: `3.0.0rc3`
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
- **Licencia Apache-2.0**: `LICENSE` reemplazado por el texto oficial,
  `license = "Apache-2.0"` y `license-files` en `pyproject.toml`, `NOTICE` y
  `DISCLAIMER.md` añadidos, y sección `## Disclaimer` en el README.

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

## Publicación ejecutada

- **`main`**: `0f1268f..4d28437` (`git push origin main`).
- **Tag `v3.0.0-rc3`**: anotado y publicado; `refs/tags/v3.0.0-rc3^{}` =
  `4d28437`. El tag contiene `version = "3.0.0rc3"` y `license =
  "Apache-2.0"`.
- **Reinstalación**: `pipx install --force /home/operator/omni-agentcs` →
  `omniagentcs 3.0.0rc3` (Python 3.14.8); `omni --version` → `omni 3.0.0rc3`.
- **CI remoto**: no verificado desde esta máquina (sin `gh` ni token); el run
  queda pendiente de revisión en GitHub Actions.

## Pendiente antes de publicar

1. **Verificación del CI remoto** — el workflow está actualizado, pero el run
   no se puede leer desde esta máquina. No se afirma “CI verde” sin ese run.
2. **Cobertura** — no re-medida en este RC. Suelo actual: 86 %
   (`Makefile:24-27`); última medida documentada: 86,2 % el 2026-11-06.
3. **Release en PyPI** — no preparada. La vía documentada es `install.sh` desde
   el repo.
4. **Benchmark externo vs PentAGI** — no ejecutado; ver
   `RELEASE_AUDIT_OMNI.md` §2 y §4.
5. **Documentación en inglés** — portada en inglés; `SECURITY.md`, este
   checklist y `docs/README-detailed.md` siguen en español.
6. **Documentos obsoletos** — `docs/MASTER_ROADMAP.md:1106` declara SEC-00
   abierto con commits que ya no existen en este clon; conviene archivarlo o
   actualizarlo en un commit aparte.
