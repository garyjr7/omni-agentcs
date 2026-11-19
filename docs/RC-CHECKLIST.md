# Checklist de release — `v3.1.1`

Estado medido a **2026-11-19** sobre `main`, tras la prueba en la sala Wreath.
Versión en código: `3.1.1` (`pyproject.toml`, `nexus_core/cli/main.py`).

Esta entrega corrige la precedencia del Time Budget, sanea la TUI y cierra la
deuda del Asset Graph (vigencia, escala, normalización y cadena de ataque en el
informe). **No** cambia el modelo de permisos ni el gateway.

## Gates ejecutados

| Gate | Comando | Resultado |
| --- | --- | --- |
| Versión en código | `omni.py --version` | `omni 3.1.1` |
| Sintaxis y lint | `make lint` | **All checks passed** (`F,E9`) |
| Tipos estrictos | `make typecheck-strict` | **0 errores en 181 ficheros** |
| Suite completa | `CI=true .venv/bin/python -m pytest nexus_core/tests -q` | **4.988 passed, 55 skipped** (428 s) |
| Tests de las áreas tocadas | `test_time_budget`, `test_asset_graph`, `test_tui_tool_messages`, `test_report_attack_chain` | **30 passed** (18 de ellos nuevos) |
| CI remoto | GitHub Actions | **Pendiente**: revisar los jobs `cli`, `coverage`, `postgres` y `secrets` sobre el SHA de este commit |
| Tag | anotado `v3.1.1` | **No creado**: el operador lo crea después de revisar el CI |

Nota de estabilidad: una pasada completa falló en
`test_shell_exec_local::test_an_sshpass_run_feeds_the_board_and_closes_the_objective`
con `session engagement is not valid`; el mismo test pasa aislado y la pasada
completa siguiente terminó en verde. Se registra como flake ambiental de la
suite, no como regresión de este cambio.

## Qué entra en `v3.1.1`

- **Time Budget primario.** Con `--time-budget`/`--time-budget-hours`,
  `iteration_limit` se deriva del reloj de trabajo (`max_iterations` como
  mínimo/techo secundario) y el presupuesto de tokens se deriva de ese límite.
  Un run de 4 h ya no se detiene a las 12 minutos en la iteración 20.
- **TUI.** Mensajes conversacionales para `discover_tools`, `subfinder`,
  `record_fact` y `web.request`; errores SSL/FTP/post-condition/skill sin
  traceback; cierre por presupuesto con «Se guardó el estado para --resume».
- **Asset Graph.** Aristas por `dst_uri` de los hechos del snapshot (sin el tope
  global de 2.000); reemplazo de aristas al re-grabar un hecho; normalización
  hostname↔IP en httpx/gobuster contra los hosts probados.
- **Informe.** `## Cadena de ataque` en Markdown y `attack_chain` en el JSON,
  construida desde las aristas verificadas.
- **Documentación.** `INDEX`, `RC-CHECKLIST`, `BACKLOG` y `MASTER_ROADMAP`
  actualizados; P1-C cerrado y P1-B reducido a validación de egress.

## Seguridad: estado honesto

- **SEC-01 — Parcial.** El shell universal no está cubierto por el scope por
  defecto. La mitigación real es el modo `egress` opt-in
  (`NEXUS_SHELL_ISOLATION=egress`): bwrap + netns + SOCKS5 gobernado por scope.
- **SEC-02 — Abierto.** En modo local el shell puede leer el HOME real; el
  aislamiento por defecto es parcial, no de lectura.
- **SEC-03 — Cerrado.** `oci_network` implementado con red `--internal` y proxy
  SOCKS5 del scope; sin proxy falla cerrado (ADR-004). La validación de rutas
  reales sigue en P1-B.
- **SEC-07 — Abierto.** `ApprovalService.decide()` no comprueba rol/tenant del
  aprobador; solo relevante con varios analistas.

## Checklist de publicación

- [x] Versión `3.1.1` en `pyproject.toml` y `PROGRAM_VERSION`.
- [x] `CHANGELOG.md` con la entrada `v3.1.1`.
- [x] `make lint` y `make typecheck-strict`.
- [x] Suite completa en verde.
- [x] Sin atribución de IA en el commit.
- [ ] CI remoto verde sobre el SHA publicado.
- [ ] Revisión del operador de los cambios de TUI/informe.
- [ ] Tag anotado `v3.1.1` y push del tag (después del CI).
- [ ] GitHub Release con las notas de `CHANGELOG.md`.
