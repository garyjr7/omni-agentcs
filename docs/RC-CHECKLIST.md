# Checklist de release — `v3.0.0-rc3`

Estado medido a **2026-11-17** sobre el commit de código `c5de0ec` de `main`. Versión
en código: `3.0.0rc3` (`pyproject.toml:7`, `nexus_core/cli/main.py:17`). El commit
documental que contiene este archivo tiene un SHA posterior; el tag se moverá al
HEAD final, no a `c5de0ec`, para que incluya también esta actualización.

Este documento no crea ni mueve tags y no autoriza un push: enumera lo medido,
lo que queda abierto y lo que requiere decisión del operador.

## Gates ejecutados

| Gate | Comando | Resultado |
| --- | --- | --- |
| Versión en código | `.venv/bin/python omni.py --version` | `omni 3.0.0rc3` |
| Tipos estrictos | `make typecheck-strict` | **0 errores en 181 ficheros** |
| Tipos incrementales | `make typecheck TYPECHECK_BASE=HEAD` | **0 errores en 21 ficheros** |
| Suite completa | `CI=true make test` | **4948 passed, 56 skipped** (231,07 s, 2026-11-17) |
| Lint | `make syntax lint` | **All checks passed** (`F,E9`, el contrato del proyecto) |
| Auditoría de dependencias | `make audit` | **Sin vulnerabilidades conocidas**; solo las excepciones justificadas en `SECURITY.md` §4.1 |
| Wheel | `.venv/bin/pip wheel . --no-deps -w /tmp/omni-wheel-rc3` | No re-medido tras `c5de0ec`; la medición previa del RC fue `omniagentcs-3.0.0rc3-py3-none-any.whl` (2.507.595 bytes) |
| Instalación (plan) | `bash install.sh --dry-run` | `pipx install --force "/home/<operador>/omni-agentcs"`; no toca `~/.config/omni` |
| Secretos en historia | escaneo de patrones + `gitleaks` en CI | Sin `.env` versionado; las 2 coincidencias son un fixture RSA truncado en `test_phase3n_fixes.py:44` |

## Bloqueadores de la TUI

- [x] **Scroll y follow.** `PageUp`, `PageDown`, `Ctrl+U`, `Ctrl+D` y la rueda
  real comparten el mismo estado. La rueda llegaba como `MouseEventType.SCROLL_UP`
  y `Window` solo movía el offset; el cursor seguía en el tail y el siguiente
  render devolvía la vista. `ScrollbackControl` ahora delega en
  `scroll_transcript()`.
- [x] **Verificación en terminal real.** En tmux, con 200 líneas, `PageUp`
  pasó de `OLD 101` a `OLD 083`; con la vista arriba llegó output nuevo y se
  mantuvo en `OLD 083`; la rueda real movió `101 → 98 → 95 → 98`. Con 12 paneles
  de ancho completo, 12 pulsaciones llegaron al `TURNO 00` sin cortar bordes.
- [x] **Rediseño visual.** Bloques al mismo ancho, reconstrucción al
  redimensionar, tarjetas de subagente con resultado integrado, títulos
  dinámicos, identidad roja `#ff0055` y `/copy` con OSC 52 y fallbacks nativos.

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
  se finge un gate ampliado que aún no está verde. **Deuda anotada para v3.1**:
  ampliar el lint a `I,UP,B` y corregir los 840 avisos preexistentes.
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

- **`main`**: `4329074` → `c5de0ec` (`git push origin main`, 2026-11-17).
- **Documentación**: este archivo se actualiza en un commit posterior a
  `c5de0ec`; el SHA final de `main` se reporta al operador para el CI.
- **Tag `v3.0.0-rc3`**: sin cambios; sigue en `78fd3bd`. El tag final se moverá
  al HEAD de `main` **solo después de que el CI de GitHub esté verde**; hasta
  entonces no se afirma que `c5de0ec` esté tagged.
- **Reinstalación**: `pipx install --force /home/<operador>/omni-agentcs` →
  `omniagentcs 3.0.0rc3` (Python 3.14.10); `omni --version` → `omni 3.0.0rc3`.
- **CI remoto**: pendiente para `c5de0ec` y el commit documental. Esta máquina
  no puede leer GitHub Actions (sin `gh` ni token); no se afirma “CI verde”.

## Pendiente antes de publicar

1. **Verificación del CI remoto** — ejecutar el workflow sobre `c5de0ec` y el
   HEAD documental, y confirmar los cuatro jobs en verde. No se afirma “CI
   verde” sin ese run.
2. **Tag final** — mover `v3.0.0-rc3` al HEAD de `main` cuando el CI esté
   verde; el tag actual (`78fd3bd`) no incluye la TUI final.
3. **Historial público** — contiene datos legacy de la etapa NEXUS bajo
   `data/` y un correo personal en 302 commits. No publicar el historial hasta
   decidir la purga descrita en `docs/LAUNCH_CHECKLIST.md` §0 y §2.
4. **Cobertura** — no re-medida en este RC. Suelo actual: 86 %
   (`Makefile:24-27`); última medida documentada: 86,2 % el 2026-11-06.
5. **Release en PyPI** — no preparada. La vía documentada es `install.sh` desde
   el repo.
6. **Benchmark externo vs PentAGI** — no ejecutado; ver
   `audits/RELEASE_AUDIT_OMNI.md` §2 y §4.
7. **Documentación en inglés** — portada en inglés; `SECURITY.md`, este
   checklist y `docs/README-detailed.md` siguen en español.
8. **Documentos obsoletos** — `docs/MASTER_ROADMAP.md:1106` declara SEC-00
   abierto con commits que ya no existen en este clon; conviene archivarlo o
   actualizarlo en un commit aparte.
