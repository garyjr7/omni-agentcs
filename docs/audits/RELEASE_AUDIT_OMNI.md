# Auditoría de publicación — OMNI v3.0.0rc1 / tag `v3.0.0-rc2`

> **Documento histórico.** Describe la etapa `rc1`/`rc2`; sus SHA, tags y
> conclusiones no aplican a `v3.0.0-rc4`. Para el estado público vigente, ver
> `docs/RC-CHECKLIST.md`.

Fecha de medición: **2026-11-10**. Commit auditado: `0497991` (`main`, árbol limpio).
Alcance: auditoría interna de release + benchmark contra PentAGI con fuentes públicas.
No se hizo push, tag ni cambio de versión durante esta auditoría.

## Actualización rc3 (2026-11-10, posterior a esta auditoría)

- Versión bumped a `3.0.0rc3` en `pyproject.toml` y `nexus_core/cli/main.py`.
- `make typecheck-strict` cableado como gate bloqueante en `ci.yml` (0 errores
  en 181 ficheros). El checklist de release se reescribió para rc3.
- Licencia **Apache-2.0** adoptada (LICENSE oficial verificado contra
  apache.org, `license` en `pyproject.toml`, `NOTICE` y `DISCLAIMER.md`).
- Push de `main` (`0f1268f..4d28437`) y tag `v3.0.0-rc3` ejecutados con
  autorización del operador; el tag apunta a `4d28437`. Reinstalación pipx
  verificada: `omni 3.0.0rc3`.
- El bloqueador 2 queda resuelto en configuración, pero el run remoto de CI no
  se pudo verificar desde esta máquina. Cobertura y benchmark siguen pendientes.

## 0. Veredicto ejecutivo

**¿Listo para publicarse como v3.0.0? NO.** Está listo para un **RC privado / alpha
cerrada**, no para el mundo. El núcleo es real y diferenciado; lo que falta es
disciplina de release, decisión de licencia y validación externa.

Los tres bloqueadores, en orden:

1. **El release está mal etiquetado.** El tag `v3.0.0-rc2` está en el remoto
   (`0f1268f`) y el `main` remoto apunta ahí, pero el código de ese commit dice
   `3.0.0rc1` (`pyproject.toml:7`, `nexus_core/cli/main.py:17`). Además hay **5
   commits posteriores sin subir**, incluidos la TUI de plomería y el README
   nuevo. Un usuario que instale “rc2” recibe otra cosa que la documentada.
2. **No hay evidencia pública de CI verde.** El workflow existe y los gates
   locales pasan, pero no hay `gh` en esta máquina ni acceso a los runs del repo
   privado: no se puede afirmar “CI verde” sin captura o enlace. El typecheck
   estricto **no es un gate de CI** (`Makefile:65`, ausente en
   `.github/workflows/ci.yml`), aunque hoy pase localmente.
3. **La licencia impide competir en adopción.** OMNI es “Authorized Use Only”,
   redistribución solo con permiso escrito (`README.md:127-128`, `LICENSE:1-2`).
   PentAGI es MIT. Sin licencia permisiva no habrá contribuciones, forks ni el
   tipo de tracción que se compara con PentAGI.

**¿Es “muy básico”? No.** 88 herramientas, 4.894 tests, 86 % de suelo de
cobertura, cadena de auditoría, scope HMAC y una TUI propia no son un juguete.
Es un producto técnicamente serio con un **release inmaduro**.

**¿Es mejor que PentAGI? PARCIAL.** Gana en gobernanza, CLI/TUI y amplitud de
herramientas; pierde en ecosistema, aislamiento por defecto, integraciones,
licencia y validación pública. No hay base para decir “superior” en conjunto.

## 1. Gates de publicación

| Gate | Estado | Evidencia |
|---|---|---|
| Versión = tag | **FALLA** | `pyproject.toml:7` y `main.py:17` = `3.0.0rc1`; tag `v3.0.0-rc2` en `0f1268f`; `git describe` = `v3.0.0-rc2-5-g0497991` |
| `main` remoto = auditado | **FALLA** | `git ls-remote origin refs/heads/main` = `0f1268f`; HEAD local = `0497991` (5 commits por delante) |
| Árbol limpio | **PASA** | `git status --porcelain` vacío tras `0497991` |
| Suite completa | **PASA** | `4894 passed, 56 skipped` en 227,52 s (2026-11-10) |
| Typecheck estricto | **PASA local, no en CI** | `make typecheck-strict`: 0 errores en 181 ficheros; no hay job en `ci.yml` |
| Lint | **PARCIAL** | `make lint` pasa, pero solo `--select F,E9` (`Makefile:38-39`); no cubre I/UP/B/S |
| Cobertura | **NO RE-MEDIDA** | Suelo 86 % (`Makefile:24-27`); última medida documentada 86,2 % el 2026-11-06; job en `ci.yml:64` |
| Auditoría de dependencias | **PASA con excepción** | `paramiko 3.5.1` / `PYSEC-2026-2858` aceptada y justificada (`SECURITY.md:104-120`) |
| Secretos en historia | **PASA** | Sin `.env` versionado; 2 coincidencias de patrón son un fixture RSA truncado (`test_phase3n_fixes.py:44`); `gitleaks` en CI (`ci.yml:110`) |
| Instalación | **PARCIAL** | Wheel construido (2,4 MB, con playbooks y datos); `install.sh --dry-run` planifica `pipx install`; no se verificó un paquete en PyPI ni se ejecutó una instalación limpia |
| Documentación de release | **FALLA** | `docs/RC-CHECKLIST.md:1` sigue en `v3.0.0-rc1` y dice “tag no creado” mientras rc2 ya está en el remoto; `MASTER_ROADMAP.md:1106` declara SEC-00 abierto pese a que los commits referidos ya no existen en este clon (historial reescrito o clon filtrado) |
| Licencia coherente | **PASA técnicamente** | `README.md:127` y `LICENSE:1` coinciden: propietaria, no OSI |
| Documentación internacional | **PARCIAL** | Portada en inglés; `docs/README-detailed.md` y `SECURITY.md` están en español |

### 1.1 Lo que sí está cerrado y bien hecho

- **Gobernanza en un solo punto:** `ToolGateway` (`kernel/tool_gateway.py:232`),
  scope firmado con HMAC (`scope/roe.py:168-179`, `scope/validator.py:147-152`),
  aprobaciones atómicas de un solo uso (`kernel/approvals.py:90`).
- **Anti-inyección real:** `wrap_untrusted_output`, `neutralize_delimiters` y
  `scan_untrusted_text` (`agent/injection.py:91-105`), aplicados en el límite del
  modelo (`react_support.py:1234-1265`).
- **SEC-05:** los entry points `nexus.tools` no se importan sin aprobación; el
  SHA-256 cubre todos los ficheros de la distribución y falla cerrado
  (`tools/trust.py:1-30`).
- **Secretos:** keyring del sistema o fichero `0600` (`config/secrets.py:1-8`).
- **UX:** razonamiento de una línea, resultados plegables, tabla de puertos,
  informe Markdown y plomería oculta (`cli/tui/presentation.py:394,507,720,802`).

### 1.2 Deuda que no bloquea pero pesa

- `react_coordinator.py` tiene **6.265 líneas**: monolito difícil de auditar y de
  recibir contribuciones externas.
- **270** marcas `TODO/FIXME/XXX` en `nexus_core`.
- SEC-01 sigue **parcial**: el modo `egress` es opt-in y `nmap` solo funciona en
  TCP connect (`SECURITY.md:68-102`). Un usuario que no lea el README creerá que
  el aislamiento es por defecto.
- SEC-02 (aislamiento de lectura en local) y SEC-07 (rol del aprobador)
  abiertos (`SECURITY.md:68-78`).
- El “showcase” del README es una transcripción de ejemplo, no una captura real.

## 2. Benchmark vs PentAGI

PentAGI: 33,8 k estrellas, 5,3 k forks, MIT, ~30 contribuidores, v2.2.0
(2026-10-05), Go + React, Docker Compose, PostgreSQL + pgvector, Neo4j/Graphiti
opcional, UI web + REST/GraphQL, 20+ herramientas y sistema multi-agente.

| Dimensión | OMNI (medido) | PentAGI (público) | Ganador |
|---|---|---|---|
| **Gobernanza** | Scope HMAC por engagement, RoE, aprobaciones durables, journal encadenado, un único gateway | Sandbox Docker + permisos de operador; no aparece en su documentación pública un alcance firmado por engagement | **OMNI** |
| **Aislamiento por defecto** | `bwrap`/netns **opt-in**; en local el shell lee el HOME real (SEC-02) | Contenedor Docker por flujo, por defecto | **PentAGI** |
| **Herramientas** | 88 (`test_catalog_ledger_consistency.py:83`), incluye Sliver (C2), Impacket, NetExec, BloodHound | 20+ (nmap, Metasploit, sqlmap, masscan…) | **OMNI en amplitud**; empate en calidad no medida |
| **Modelo de agente** | ReAct único + planner determinista + subagentes; coordinador de 6.265 líneas | Multi-agente con orquestador, investigador, desarrollador, ejecutor; pipeline determinista | **PentAGI en modularidad** |
| **Conocimiento** | Blackboard SQLite + hechos verificados | PostgreSQL + pgvector; Neo4j/Graphiti opcional | **PentAGI en escala** |
| **Integración** | Sin API REST/GraphQL; CLI/TUI | REST + GraphQL bajo `/api/v1`, UI web, multi-tenant | **PentAGI** |
| **UX para Red Team de terminal** | TUI nativa, sin stack de Docker, respuestas de una línea, tablas, Markdown | UI web; requiere Docker, 2 vCPU, 4 GB RAM, 25 GB disco | **OMNI** |
| **Instalación** | `pipx`/venv + binarios de Kali | Docker Compose (instalador o manual) | **OMNI en simplicidad**; ambas dependen de herramientas externas |
| **Ecosistema** | 1 contribuidor, repo privado, sin comunidad pública | 33,8 k estrellas, 5,3 k forks, ~30 contribuidores | **PentAGI** |
| **Licencia** | Propietaria “Authorized Use Only” | MIT | **PentAGI** |
| **Madurez de release** | Tag rc2 con versión rc1, 5 commits sin subir, checklist obsoleto | v2.2.0, releases e issues públicos | **PentAGI** |
| **Validación** | 4.894 tests locales, sin benchmark público | Comunidad, demo, uso reportado | **PentAGI** |

### 2.1 Killer feature de OMNI

**La gobernanza verificable por engagement**: un scope firmado con HMAC que el
gateway valida antes de cada herramienta, aprobaciones de un solo uso y una
cadena de auditoría con hash. PentAGI aísla mejor el contenedor, pero no
documenta un contrato de alcance firmado que impida ejecutar fuera del objetivo
autorizado. Para un equipo que debe demostrar *por qué* se tocó un host, eso
vale más que 20 herramientas extra.

## 3. Truth check: lo que no se debe afirmar

- **“CI verde con 4.891 tests”**: la suite local está verde con 4.894, pero no se
  verificó GitHub Actions. Decir “CI verde” sin el run es una promesa.
- **“SEC-01: aislamiento de red real”**: es opt-in y solo TCP connect; el README
  nuevo ya lo dice, no lo contradigas en el pitch.
- **“SEC-05: plugins firmados”**: son hashes SHA-256 fijados por aprobación, no
  firmas criptográficas.
- **“Superior a PentAGI”**: no hay benchmark reproducible ni métricas de éxito en
  laboratorios reales. Hoy es superior en gobernanza y UX de terminal, inferior
  en ecosistema, aislamiento por defecto e integración.
- **“Listo para el mundo”**: el tag publicado no contiene el código documentado.

## 4. Roadmap mínimo para v3.0.0 pública

### P0 — bloqueadores de release

1. **Decidir el tag correcto.** No reescribir `v3.0.0-rc2` (ya está en el
   remoto): crear `v3.0.0-rc3` con `3.0.0rc3` en `pyproject.toml` y
   `main.py`, o borrar rc2 si nadie lo consumió. Un tag publicado no se mueve sin
   force-push, y eso requiere autorización explícita.
2. **Subir los 5 commits** (TUI + README + fix del conteo) y verificar el run de
   CI del commit tageado. Adjuntar enlace/captura al checklist.
3. **Actualizar `docs/RC-CHECKLIST.md`** con la versión real, 4.894 tests, la
   decisión sobre el tag y el estado de SEC-00 (los commits referidos ya no
   existen en este clon; el documento está obsoleto).
4. **Wire `typecheck-strict` en CI** (hoy pasa: 0/181) y ampliar `make lint` más
   allá de `F,E9`, o declarar explícitamente que no es un gate.
5. **Re-medir cobertura** y registrar el número real, no solo el suelo.

### P1 — lo que decide si compite

6. **Licencia:** elegir MIT/Apache-2.0 si el objetivo es adopción; si se mantiene
   propietaria, dejar de compararse con proyectos MIT en “comunidad”.
7. **Benchmark reproducible:** 2–3 máquinas de laboratorio (HTB/VulnHub),
   mismo modelo y mismo hardware para OMNI y PentAGI, midiendo tiempo, tokens,
   coste y tasa de éxito. Sin esto, “mejor que PentAGI” es opinión.
8. **Documentación en inglés** (al menos SECURITY, quickstart y troubleshooting).
9. **Artefacto instalable:** wheel + release de GitHub con SHA-256, o PyPI.
   `pipx install git+ssh` no es una vía para el mundo.
10. **Capturas/asciinema reales** de la TUI; el bloque de texto actual es un
    ejemplo, no una prueba visual.

### P2 — después de publicar

11. Partir `react_coordinator.py` (6.265 líneas) y bajar los 270 TODO.
12. Cerrar SEC-02 y SEC-07; decidir si `egress` pasa a default en producción.
13. Añadir un job de CI que ejecute el benchmark de humo contra un lab local.

## 5. Fuentes del benchmark

- PentAGI, métricas y licencia: <https://pentagi.com/> (33,4 k estrellas, 5,2 k
  forks, 30 contribuidores, v2.2.0), <https://github.com/vxcontrol/pentagi/blob/main/LICENSE>.
- Arquitectura y servicios: <https://pentagi.com/docs/concepts/architecture/>.
- Multi-agente y ejecución: <https://github.com/vxcontrol/pentagi/blob/main/backend/docs/flow_execution.md>.
- Riesgo documentado del socket Docker del host:
  <https://github.com/vxcontrol/pentagi/blob/main/examples/guides/worker_node.md>.
- OMNI: rutas y líneas citadas en este informe, medidas en el commit `0497991`.
