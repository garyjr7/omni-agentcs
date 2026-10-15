# Fase 3E — Reporte de Élite (CVSS 4.0, marcos, SARIF, CVE)

> Rama: `feat/report-enrichment-phase-3e` · Base: `feat/ecosystem-phase-3b` (`386fcc1`)
> Autor: BAJIOWARE · Team Red · Fecha: 2026-10-06

## 0. Estado de partida

La Fase 3B cerró el ecosistema (MCP cliente, Skills firmables, `OMNI.md`, modo
headless) y dejó la **3E entera como deuda documentada** en
`FASE3B_ECOSYSTEM.md` §13.1. Punto de partida verificado:

- suite unitaria: **1987 passed / 1 skipped**;
- el reporte (`nexus.report.generate`) ya generaba Markdown + HTML + JSON con
  CVSS 3.1, MITRE ATT&CK y chain of custody, pero:
  - solo existía CVSS 3.1 (los datos de CVSS 4.0 que ya publican NVD y muchos
    CNA no tenían sitio en el entregable);
  - no había mapeo a marcos de trabajo más allá de ATT&CK;
  - no había export SARIF (los hallazgos no llegaban a un code-scanning);
  - no había enriquecimiento por CVE (descripción, CWE, EPSS, CISA KEV).

## 1. Alcance y criterio de corte

Se implementa la Fase 3E completa:

| Tarea | Módulo | Estado |
| --- | --- | --- |
| 3E.1 CVSS 4.0 (manteniendo 3.1) | `nexus_core/report/cvss4.py` | ✅ |
| 3E.2 Mapeos PTES / WSTG / NIST 800-115 / D3FEND | `nexus_core/report/frameworks.py` | ✅ (subconjunto curado) |
| 3E.3 Export SARIF 2.1.0 | `nexus_core/report/sarif.py` | ✅ |
| 3E.4 Enriquecimiento CVE offline-first | `nexus_core/report/cve_enrichment.py` | ✅ |
| 3E.5 Integración en el reporte | `models.py` / `extractor.py` / renderers / handler | ✅ |

**Criterio de corte honesto:** los catálogos completos (≈100 tests WSTG, ≈270
técnicas D3FEND) no se vuelcan enteros. En su lugar se incluye un **subconjunto
curado y trazable** (§4) y se deja la ampliación como deuda (§13). No se inventa
ningún identificador.

## 2. Decisiones de diseño (y alternativas descartadas)

1. **El cálculo local prevalece.** Igual que en 3.1, un vector sugerido por el
   LLM o por NVD **nunca** aporta su número: solo su *vector*, que se puntúa
   localmente. Un score alucinado no llega al reporte ni por 3.1 ni por 4.0.
2. **CVSS 4.0 no es una fórmula cerrada.** El estándar define el base score como
   una tabla de *MacroVectors* (EQ1..EQ6). Reproducirla «de memoria» habría sido
   inventar datos. Se **vendoriza la tabla oficial de FIRST** (BSD-2-Clause) en
   `report/data/cvss4_lookup.json` y se porta el algoritmo de referencia.
   *Alternativa descartada:* añadir la dependencia PyPI `cvss` (prohibido sin
   autorización del operador).
3. **Offline-first de verdad.** El reporte **nunca** abre un socket. Hay dos
   caminos separados: *lookup* (solo caché, por defecto) y *update* (red, bajo
   demanda). *Alternativa descartada:* consultar NVD/EPSS en el momento de
   generar el reporte (bloquearía el engagement y rompería la reproducibilidad).
4. **SARIF con validación estructural.** Se emite el perfil 2.1.0 que consumen
   GitHub/SonarQube/VS Code y se valida con un comprobador propio. El esquema
   oficial completo (~150 KiB) no se empotra; su validación estricta es opt-in
   (§5). *Alternativa descartada:* empaquetar el JSON Schema oficial dentro del
   CLI offline-first.

## 3. 3E.1 — CVSS v4.0

`nexus_core/report/cvss4.py` implementa el **base score** mediante:

- `macro_vector(metrics)`: EQ1..EQ6 exactamente como el estándar;
- la tabla oficial `cvss4_lookup.json` (270 MacroVectors);
- `MAX_COMPOSED` / `MAX_SEVERITY` (vectores de máxima severidad y distancias)
  portados literalmente del código de referencia;
- la corrección por *severity distance* al MacroVector inferior.

Reglas de honestidad y fail-closed:

- `parse_cvss4_vector` devuelve `None` ante un vector malformado: prefijo
  incorrecto, métrica base ausente, valor fuera de rango, duplicado
  contradictorio o un vector de **otra versión** (un 3.1 no se «interpreta» como
  4.0);
- el score **siempre** se recalcula aquí; `estimate_cvss4_with_source` devuelve
  la **fuente**: `tool`, `llm`, `heuristic`, `nvd` (vector cacheado del CVE) o
  `none` (informativo, sin vector);
- el base score asume el peor caso de las métricas Threat/Environmental
  (`E:A`, `CR:H`, `IR:H`, `AR:H`) tal y como manda el estándar; por eso las
  métricas `E/CR/IR/AR` presentes en el vector se ignoran **a propósito** (no se
  reclama calcular Threat/Environmental).

**Verificación contra el estándar:** el score reproduce exactamente los **7
ejemplos oficiales publicados por FIRST** (`https://www.first.org/cvss/v4.0/examples`),
p. ej. `CVE-2022-41741 → 7.3`, `CVE-2020-3549 → 7.7`, `CVE-2023-3089 → 8.3`,
`CVE-2022-22186 → 6.9`. Ver `test_report_cvss4.py::test_official_examples`.

Además, los pares heurísticos se construyen recalculando el score **desde** el
vector (`heuristic_cvss4`) para que nunca se desincronicen, corrigiendo el sesgo
latente que existía en la tabla heurística de 3.1 (donde `critical` fija 9.5 para
un vector que puntúa 10.0).

## 4. 3E.2 — Mapeos de marcos

`nexus_core/report/frameworks.py` produce, por hallazgo, un
`FrameworkMapping(framework, technique_id, name)`:

- **PTES** — las 7 fases estándar (`PTES-1`…`PTES-7`);
- **OWASP WSTG v4.2** — identificadores reales `WSTG-<CAT>-NN` (p. ej.
  `WSTG-INPV-05` *SQL Injection*, `WSTG-CONF-01`, `WSTG-INFO-10`);
- **NIST SP 800-115** — secciones técnicas reales (§4.1 *Network Discovery*,
  §4.2 *Port and Service Identification*, §4.3 *Vulnerability Scanning*,
  §5.1 *Password Cracking*, §5.2 *Penetration Testing*);
- **MITRE D3FEND** — subconjunto de contramedidas defensivas con ID y táctica
  reales (`D3-NTA`, `D3-AL`, `D3-ANCI`, `D3-SCA`, `D3-PT`, `D3-DQSA`,
  `D3-SJA`, `D3-SFA`, `D3-SEA`, `D3-PLA`, `D3-RTA`, `D3-CAA`, `D3-CA`,
  `D3-LAM`, `D3-PSA`, `D3-SDM`, `D3-OSM`).

El mapeo se resuelve por el `kind` interno del hallazgo (lo que el toolkit
observó) y se **refina** con sus técnicas ATT&CK, que añaden contramedidas
D3FEND (`T1003 → D3-AL/D3-ANCI`, `T1053 → D3-SJA`, `T1021 → D3-RTA`, …). Un
kind desconocido degrada a `generic` (fase de análisis) en lugar de quedarse sin
mapeo, y los duplicados se eliminan preservando el orden.

**Honestidad:** el mapeo WSTG/D3FEND es **grueso y curado**, no exhaustivo. Se
documenta así en el docstring del módulo y en la deuda (§13).

## 5. 3E.3 — Export SARIF 2.1.0

`nexus_core/report/sarif.py` emite un documento SARIF válido:

- `version: "2.1.0"`, `$schema` = `https://json.schemastore.org/sarif-2.1.0.json`;
- un `run` con `tool.driver` (nombre, versión, `informationUri`) y `rules` (una
  por `kind`, deduplicadas, con `security-severity` para GitHub);
- **una `result` por hallazgo** (verificado: 3 hallazgos → 3 `results`), con
  `level` (`error`/`warning`/`note`), `message.text`, `locations` (los targets) y
  un bloque `properties` con CVSS 3.1/4.0 + fuente, CWE, CVE, EPSS, KEV, ATT&CK y
  los mapeos de marcos.

`validate_sarif(document)` es un **validador estructural** propio (campos
requeridos, `ruleId` declarado, `level` válido, `message.text` y
`artifactLocation.uri` no vacíos) y está enganchado a los tests. La validación
contra el **esquema oficial** es opt-in:

```bash
export NEXUS_SARIF_SCHEMA=/ruta/a/sarif-schema-2.1.0.json   # + pip install jsonschema
```

`validate_with_schema` usa `jsonschema` **solo si está instalado y la ruta
existe**; si no, devuelve `[]` sin fallar. Esta limitación queda explícita, no
oculta.

## 6. 3E.4 — Enriquecimiento CVE offline-first

`nexus_core/report/cve_enrichment.py`:

- **Caché** en `$XDG_CACHE_HOME/omni/cve/` (`nvd/<CVE>.json`, `epss/<CVE>.json`,
  `kev.json`);
- **lookup** (`load_cve`, `enrich_findings`): **solo caché**, sin red, sin
  bloqueo, sin excepciones; un CVE no cacheado deja los campos **vacíos**
  (`unknown`), nunca inventados;
- **update** (`update_cves`, `omni cve update`): descarga NVD 2.0 (descripción,
  CWE, CVSS 3.1/4.0), EPSS (probabilidad) y el catálogo **CISA KEV**; cada fuente
  es best-effort e independiente (un fallo se reporta en `errors`, no aborta);
- el foco del bug bounty se cubre con `NVD_API_KEY` (opcional, sube el rate limit);
- `httpx` (ya dependencia del proyecto) es el único cliente HTTP y es inyectable
  en tests, que mockean la red por completo.

El enriquecimiento **nunca sobrescribe** un vector CVSS 4.0 que el hallazgo ya
traiga: si existe, se respeta su fuente; si no, se toma el vector de NVD y su
score se recalcula localmente con `cvss4.parse_cvss4_vector`.

## 7. 3E.5 — Integración en el reporte

`Finding` gana campos (con defaults, retrocompatible):
`cvss4_score`, `cvss4_vector`, `cvss4_source`, `epss_score`, `kev`,
`cve_description` y `frameworks` (tupla de `FrameworkMapping`). El pipeline de
`build_report` pasa a ser:

```
extract_findings → enrich_cves (caché) → attach_cvss (3.1 + 4.0) → attach_frameworks
```

El **Markdown** y el **HTML** muestran por hallazgo ambos CVSS con su fuente, CWE
y CVE, EPSS, la marca **CISA KEV** («explotado en el wild») y una tabla de mapeo
de marcos; además ambos abren con una sección ejecutiva con «Hallazgos
prioritarios (para dirección)» pensada para un lector no técnico, y cierran con
«Cobertura de marcos» en los anexos.

> Nota de compatibilidad: al añadir campos a `Finding`, el `report_sha256`
> (digest canónico del reporte) cambia respecto a 3B para el mismo engagement.
> Es esperado: el digest es un hash de contenido y el contenido cambió.

## 8. CLI

- `omni report [--format markdown|html|both|sarif] [--output DIR]` — genera el
  reporte por el **gateway** (`nexus.report.generate`) sin necesidad de proveedor
  LLM; `--format sarif` escribe `report.sarif`.
- `/report [export <dir>] [--llm-cvss] [--format F]` — mismo comando en la TUI.
- `omni cve update [CVE-AAAA-NNNN …]` — rellena la caché; sin ids, usa los CVEs
  de los hallazgos del engagement activo.

## 9. Bugs encontrados y corregidos

1. **`map_finding` leía dicts con `getattr`.** `map_for_kind` pasaba un `dict` a
   `map_finding`, que hacía `getattr(finding, "kind")`; todo degradaba a
   `generic`. Se separó la lógica en `_map(kind, techniques)`.
2. **EPSS no sobrevivía al round-trip de caché.** `update_cves` escribía la forma
   normalizada `{"cve", "epss"}` pero `parse_epss` solo entendía la forma batch
   `{"data": […]}`. `parse_epss` ahora acepta ambas.
3. **`parse_nvd` crasheaba con `weaknesses` mal formadas.** El bucle asumía
   `dict` y hacía `.get` sobre un `str`. Ahora valida el tipo (encontrado por el
   test defensivo, no en producción).

## 10. Desviaciones conscientes

| # | Encargo | Lo hecho | Motivo |
| --- | --- | --- | --- |
| 1 | «catálogo MITRE D3FEND» | Subconjunto curado de 17 técnicas reales | No inventar IDs; deuda §13 |
| 2 | «catálogo WSTG» | Subconjunto de 6 tests web reales | Igual; mapeo por kind es grueso |
| 3 | `omni cve update` (sin args = NVD completo) | Requiere CVEs explícitos o un engagement | Descargar NVD entero es inviable/abusivo |
| 4 | `--format` para SARIF | `both` sigue siendo md+html+json; SARIF solo con `--format sarif` | No romper los artefactos y conteos existentes |
| 5 | Validar contra el JSON Schema oficial | Validación estructural + opt-in con el esquema oficial | No empotrar ~150 KiB en un CLI offline-first |

## 11. Limitaciones honestas

1. **EPSS/KEV/CVE aparecen solo tras `omni cve update`.** El reporte de ejemplo
   (`docs/missions/examples/`) se generó con caché vacía a propósito: demuestra la
   degradación elegante (campos vacíos, sin fallo), no datos inventados.
2. **`cvss4_source` puede valer `nvd`:** significa «el *vector* vino de NVD», no
   que el score sea de NVD (el score es siempre local).
3. **Mapeo de marcos aproximado** por `kind`: un mismo kind (p. ej. `nuclei`)
   cubre plantillas muy distintas.
4. **La validación SARIF es la del perfil que emitimos**, no la del esquema
   oficial completo (opt-in).
5. **`default_http_get` no se ejercita contra la red real en tests** (se mockea
   `httpx.get`); el contacto real con NVD/EPSS/CISA queda sin verificar aquí.
6. **Se ignoran a propósito las métricas Threat/Environmental de CVSS 4.0**: solo
   se reclama el base score.

## 12. Verificación reproducible

```bash
# suite unitaria completa
.venv/bin/python -m pytest nexus_core/tests/unit -q
# → 2074 passed, 1 skipped

# lint y compilación de todo lo tocado
.venv/bin/python -m ruff check nexus_core/report/ \
  nexus_core/tools/handlers/report_generate.py nexus_core/cli/main.py \
  nexus_core/cli/commands.py --select F,E9
.venv/bin/python -m compileall -q nexus_core/report nexus_core/cli/main.py

# cobertura del código nuevo
.venv/bin/python -m pytest nexus_core/tests/unit/test_report_cvss4.py \
  nexus_core/tests/unit/test_report_frameworks.py \
  nexus_core/tests/unit/test_report_sarif.py \
  nexus_core/tests/unit/test_report_cve_enrichment.py \
  --cov=nexus_core.report.cvss4 --cov=nexus_core.report.frameworks \
  --cov=nexus_core.report.sarif --cov=nexus_core.report.cve_enrichment \
  --cov-report=term-missing
```

| Módulo | Cobertura |
| --- | --- |
| `report/cvss4.py` | 92% |
| `report/frameworks.py` | 100% |
| `report/sarif.py` | 99% |
| `report/cve_enrichment.py` | 98% |
| **Total código nuevo** | **96%** |

Tests nuevos (todos unitarios): `test_report_cvss4.py` (oficiales + fail-closed +
LLM + heurística), `test_report_frameworks.py`, `test_report_sarif.py`,
`test_report_cve_enrichment.py`, `test_cli_report_cve_shim.py`, más ampliaciones
de `test_report_handler.py` y `test_cli_report_commands.py`. Total **+87** tests
(1987 → 2074).

Ejemplo reproducible en `docs/missions/examples/`:
`example-report.{md,html,json,sarif}` (8 hallazgos, SARIF validado).

## 13. Deuda restante

1. Ampliar el catálogo D3FEND/WSTG a un mapeo completo (cargándolo, p. ej., desde
   el CSV publicado por MITRE, con atribución).
2. Enriquecimiento por CWE→WSTG/NIST para afinar el mapeo más allá del `kind`.
3. Validación SARIF contra el esquema oficial en CI (con `jsonschema`).
4. `omni cve update` en lote/por feed (con control de rate limit de NVD) y
   `omni cve show <CVE>`.
5. Actualización automática de la caché KEK/EPSS desde un job programado.
6. Verificación en vivo contra NVD/EPSS/CISA (test de integración marcado `slow`).

## 14. Atribución de datos de terceros

- **CVSS v4.0** — tabla y algoritmo: FIRST / Red Hat, **BSD-2-Clause**
  (`cvss-v4-calculator`). Cabecera de licencia conservada en
  `data/cvss4_lookup.json` y en `cvss4.py`. CVSS es propiedad de FIRST.Org y se
  usa con permiso; los reports incluyen siempre score **y** vector.
- **MITRE D3FEND** — identificadores y tácticas de MITRE D3FEND™
  (© The MITRE Corporation; términos de uso de D3FEND).
- **OWASP WSTG v4.2** y **NIST SP 800-115** — identificadores/títulos públicos,
  citados a modo de referencia.
- **NVD / CISA KEV** — datos públicos de NIST y CISA; se almacenan en caché y se
  citan sin alteración. **No se inventa ningún dato.**
