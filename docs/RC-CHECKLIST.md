# Checklist de release — `v3.0.0-rc4`

Estado medido a **2026-11-17** sobre el árbol saneado que se commiteará como
`v3.0.0-rc4`. Versión en código: `3.0.0rc4` (`pyproject.toml`,
`nexus_core/cli/main.py`).

Este RC **no es el `rc3`**: la historia se reescribió con `git-filter-repo` para
sacar informes de misión, evidencias, fixtures DPAPI reales y credenciales. Los
SHA y tags anteriores quedan obsoletos; un clon viejo debe re-clonarse, no hacer
`pull`.

## Gates ejecutados

| Gate | Comando | Resultado |
| --- | --- | --- |
| Versión en código | `.venv/bin/python omni.py --version` | `omni 3.0.0rc4` |
| Sintaxis y lint | `make syntax lint` | **All checks passed** (`F,E9`) |
| Tipos estrictos | `make typecheck-strict` | **0 errores en 181 ficheros** |
| Suite completa | `CI=true .venv/bin/python -m pytest nexus_core/tests -q` | **4949 passed, 55 skipped** (319,30 s) |
| Auditoría de dependencias | `make audit` | **Sin vulnerabilidades conocidas**; 2 excepciones aceptadas en `SECURITY.md` §4.1 |
| Instalador | `bash install.sh --dry-run` | `pipx install --force "<checkout>"`; sin fallback a PyPI |
| Wheel | `pip wheel . --no-deps --no-cache-dir` | `omniagentcs-3.0.0rc4-py3-none-any.whl`, **333 archivos, 1.467.386 bytes**; sin `nexus_core/tests`, `docs/`, NDJSON ni fixtures DPAPI |
| Secretos locales | búsqueda de credenciales, flags e IPs de misión | Sin `docs/missions/`, sin `hijack_v3.ndjson` real, sin las credenciales conocidas; fixtures DPAPI sintéticos |
| `gitleaks` local | no instalado en esta máquina | **No ejecutado**; el job `secrets` de CI sigue siendo el gate remoto |
| `trufflehog` local | no instalado en esta máquina | **No ejecutado**; no se afirma lo contrario |
| CI remoto | GitHub Actions | **Pendiente**: el operador debe verificar los 4 jobs sobre el SHA publicado |

## Saneamiento de este RC

- **Árbol**: se eliminó `docs/missions/`; el catálogo durable vive en
  `docs/audit/catalog.json` y el baseline en
  `docs/audit/evidence-index-baseline.txt`.
- **Fixtures**: `test_dpapi_handler.py` y `tests/fixtures/dpapi/` usan material
  sintético (SHA-256 del material: `5cf9e443…`), no artefactos de engagements.
- **Hijack v3**: el fixture `nexus_core/tests/fixtures/react/hijack_v3.ndjson`
  se conserva saneado (IDs `run_fixture_*`, target `10.0.0.5`, sin secretos).
- **Historial**: dos pasadas de `git filter-repo` eliminaron
  `docs/missions/`, `SEC00_VERIFICATION.md`, `tests/fixtures/dpapi/`,
  `hijack_v3.ndjson` antiguo, los tests con flags/credenciales y las
  credenciales históricas.
- **Credenciales**: se sustituyeron las credenciales de laboratorio y los
  usuarios reales que quedaban en tests restaurados; las flags son
  `flag{fake_flag}`, `flag{fake_flag_user}`, `flag{fake_flag_root}` o MD5
  sintéticos.
- **Instalador**: `install.sh` ya no intenta `pipx install omniagentcs`; si la
  fuente Git/ruta falla, termina con error explícito.
- **Documentación**: `README.md` declara aislamiento local parcial y `bwrap`
  opt-in (SEC-01); `SECURITY.md` ya no describe datos de laboratorio reales.
- **Wheel**: `pyproject.toml` excluye `nexus_core.tests*`; el build se hizo
  desde cero para no arrastrar `build/lib` viejo.

## Seguridad: estado honesto

- **SEC-01 — Parcial.** El shell universal no está cubierto por el scope por
  defecto. La mitigación real es el modo `egress` opt-in
  (`NEXUS_SHELL_ISOLATION=egress`): bwrap + netns + SOCKS5 gobernado por scope.
- **SEC-02 — Abierto.** En modo local el shell puede leer el HOME real; el
  aislamiento por defecto es parcial, no de lectura.
- **SEC-03 — Cerrado.** `oci_network` implementado con red `--internal` y proxy
  SOCKS5 del scope; sin proxy falla cerrado (ADR-004).
- **SEC-05 — Cerrado.** Entry points `nexus.tools` requieren aprobación humana y
  hash de distribución en `tools-trust.json`.
- **SEC-07 — Backlog.** `ApprovalService.decide()` no comprueba rol/tenant del
  aprobador; solo relevante con varios analistas.
- **`bwrap`** no es el sandbox por defecto: se usa en el modo `egress` opt-in y
  en el aislamiento local cuando está disponible, con las limitaciones de
  `SECURITY.md` §1.

## Publicación

- **Commit/tag**: pendientes en el momento de escribir este archivo; el SHA
  final se reporta al operador después del push.
- **Force-push**: obligatorio. Los tags remotos antiguos (`v3.0.0-rc1`,
  `rc2`, `rc3`, `b1`) siguen apuntando a la historia sensible hasta que se
  borren o se fuerza el push de los nuevos.
- **CI**: no se afirma “CI verde”. Esta máquina no tiene `gh` ni token para leer
  GitHub Actions; el operador debe comprobar los 4 jobs.
- **PyPI**: no se publica ni se usa como fallback. La vía soportada es
  `install.sh` desde el repo.
- **Cobertura**: no re-medida en este RC; última referencia documentada 86,2 %
  (2026-11-06).
- **Benchmark externo vs PentAGI**: no ejecutado.

## Pendiente antes de anunciar

1. Confirmar CI en verde sobre el SHA publicado.
2. Confirmar que los tags remotos antiguos ya no apuntan a la historia sensible.
3. Revisar el wheel publicado (sin tests/docs) y la instalación desde Git.
4. Decidir si se publica una nota de seguridad sobre la purga y la rotación de
   cualquier credencial que haya estado expuesta.
