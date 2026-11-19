# ÍNDICE DOCUMENTAL — OmniAgentCS

> Última revisión: 2026-11-19 · `v3.1.1` · documentación pública saneada.
>
> Los informes de misión, evidencias de laboratorio, bases KeePass y material
> DPAPI **no forman parte de este repositorio público**. Se retiraron del árbol y
> del historial en el saneamiento de `v3.0.0-rc4`; las referencias históricas a
> `docs/missions/` que aún aparezcan en documentos de archivo deben leerse como
> material no publicado.

---

## Verdad vigente por tema

| Tema | Documento | Ubicación |
|---|---|---|
| Producto, instalación y CLI | `README.md` | `/` |
| Política de seguridad y límites reales | `SECURITY.md` | `/` |
| Historial de versiones | `CHANGELOG.md` | `/` |
| Checklist de lanzamiento público | `LAUNCH_CHECKLIST.md` | `docs/` |
| Checklist del RC actual | `RC-CHECKLIST.md` | `docs/` |
| Deuda y backlog | `BACKLOG.md` | `docs/` |
| Catálogo durable de tools | `catalog.json` | `docs/audit/` |
| Baseline de evidencia en el índice | `evidence-index-baseline.txt` | `docs/audit/` |
| Referencia operativa completa | `README-detailed.md` | `docs/` |
| Arquitectura | `BLUEPRINT_ARQUITECTONICO.md` | `docs/` |
| Roadmap maestro | `MASTER_ROADMAP.md` | `docs/` |
| Decisiones de arquitectura | `ADR-004` … `ADR-007` | `docs/adr/` |
| Guías de uso manual y agente | `GUIA_MANUAL_1.md`, `GUIA_AGENTE_1.md` | `docs/guides/` |
| Auditorías técnicas | informes fechados | `docs/audits/` |
| Planes históricos | material de consulta | `docs/plans/` |
| Material superado o histórico | solo consulta | `docs/archive/` |

---

## Reglas de publicación

- No se versionan informes de misiones, capturas de objetivos, credenciales,
  flags, bases KeePass ni material DPAPI.
- Los fixtures de test son sintéticos y se generan sin datos de engagements.
- El catálogo de tools se escribe con `scripts/omni_catalog.py` en
  `docs/audit/catalog.json`; el test de consistencia compara ese archivo con el
  runtime (88 tools durables en `v3.1.1`).
- Cualquier nueva evidencia de engagement debe quedarse fuera del índice y el
  guard `test_repo_hygiene.py` debe seguir en verde.
