"""
DocAgent v1.0 — Memoria Técnica de BajioWare
Documenta incidentes, soluciones y lecciones en ChromaDB y SQLite.
El DocAgent es la memoria viva del sistema.
"""
import sqlite3
import json
import uuid
import subprocess
from datetime import datetime
from pathlib import Path

BASE_DIR = Path("/home/operator/BW-AI")
DB_PATH = BASE_DIR / "nexus_api/database.db"
DOCS_DIR = BASE_DIR / "data/docs"
CHROMA_PATH = str(BASE_DIR / "data/junior_memory_db")
DOCS_DIR.mkdir(parents=True, exist_ok=True)


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS technical_docs (
            doc_id TEXT PRIMARY KEY,
            doc_type TEXT,
            title TEXT,
            content TEXT,
            tags TEXT,
            project_id TEXT,
            related_incident TEXT,
            related_commit TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incident_reports (
            report_id TEXT PRIMARY KEY,
            incident_id TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            root_cause TEXT,
            solution TEXT,
            prevention TEXT,
            status TEXT DEFAULT 'open',
            assigned_to TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def document_incident(incident_id: str, title: str, description: str,
                      severity: str = "medium", root_cause: str = "",
                      solution: str = "", prevention: str = "") -> dict:
    """Documenta un incidente de seguridad o error del sistema."""
    _init_db()
    report_id = f"rpt_{uuid.uuid4().hex[:8]}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO incident_reports
           (report_id, incident_id, severity, title, description, root_cause, solution, prevention)
           VALUES (?,?,?,?,?,?,?,?)""",
        (report_id, incident_id, severity, title, description, root_cause, solution, prevention)
    )
    conn.commit()
    conn.close()

    # Guardar también como archivo markdown
    doc_path = DOCS_DIR / f"incident_{report_id}.md"
    doc_content = f"""# Reporte de Incidente: {title}
**ID:** {report_id}
**Severidad:** {severity}
**Fecha:** {datetime.utcnow().isoformat()}

## Descripción
{description}

## Causa Raíz
{root_cause or "En investigación"}

## Solución Aplicada
{solution or "Pendiente"}

## Prevención Futura
{prevention or "Por definir"}
"""
    doc_path.write_text(doc_content)

    # Indexar en ChromaDB para búsqueda semántica
    _index_in_memory(report_id, f"Incidente: {title}\n{description}\n{solution}",
                     {"type": "incident", "severity": severity, "id": report_id})

    return {
        "report_id": report_id,
        "saved": True,
        "doc_path": str(doc_path),
        "indexed_in_memory": True,
    }


def document_solution(title: str, problem: str, solution: str,
                      tags: list = None, project_id: str = "general",
                      related_commit: str = "") -> dict:
    """Documenta una solución para reutilización futura."""
    _init_db()
    doc_id = f"doc_{uuid.uuid4().hex[:8]}"
    tags_str = json.dumps(tags or [])
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO technical_docs
           (doc_id, doc_type, title, content, tags, project_id, related_commit)
           VALUES (?,?,?,?,?,?,?)""",
        (doc_id, "solution", title, f"PROBLEMA:\n{problem}\n\nSOLUCION:\n{solution}",
         tags_str, project_id, related_commit)
    )
    conn.commit()
    conn.close()

    # Guardar markdown
    doc_path = DOCS_DIR / f"solution_{doc_id}.md"
    doc_path.write_text(f"""# Solución: {title}
**ID:** {doc_id}
**Tags:** {", ".join(tags or [])}
**Commit:** {related_commit}
**Fecha:** {datetime.utcnow().isoformat()}

## Problema
{problem}

## Solución
{solution}
""")

    # Indexar en ChromaDB
    _index_in_memory(doc_id, f"Solución: {title}\nProblema: {problem}\nSolución: {solution}",
                     {"type": "solution", "tags": tags_str, "id": doc_id})

    return {"doc_id": doc_id, "saved": True, "doc_path": str(doc_path)}


def analyze_incidents_with_llm(limit: int = 14) -> dict:
    """Analiza los incidentes recientes y genera un reporte ejecutivo."""
    _init_db()
    # Obtener incidentes de seguridad
    conn = sqlite3.connect(DB_PATH)
    incidents = conn.execute(
        """SELECT id, severity, title, description, file_path, created_at
           FROM security_incidents ORDER BY created_at DESC LIMIT ?""",
        (limit,)
    ).fetchall()
    conn.close()

    if not incidents:
        return {"message": "No hay incidentes registrados", "total": 0}

    # Clasificar por severidad
    high = [i for i in incidents if i[1] == "HIGH"]
    medium = [i for i in incidents if i[1] == "MEDIUM"]
    low = [i for i in incidents if i[1] == "LOW"]

    # Agrupar por tipo
    by_type = {}
    for inc in incidents:
        t = inc[2]
        if t not in by_type:
            by_type[t] = []
        by_type[t].append({"id": inc[0], "file": inc[3] if len(inc) > 3 else "", "date": inc[4] if len(inc) > 4 else ""})

    # Generar reporte
    report = {
        "total": len(incidents),
        "by_severity": {"HIGH": len(high), "MEDIUM": len(medium), "LOW": len(low)},
        "by_type": {k: len(v) for k, v in by_type.items()},
        "top_affected_files": list(set([i[4] for i in incidents if i[4]])),
        "recommendations": [],
        "incidents": [{"id": i[0], "severity": i[1], "title": i[2],
                       "file": i[4], "date": i[5]} for i in incidents],
    }

    # Agregar recomendaciones basadas en patrones
    if len(high) > 0:
        report["recommendations"].append({
            "priority": "CRÍTICA",
            "action": f"Resolver {len(high)} incidentes de severidad HIGH inmediatamente",
            "affected": list(set([i[3] if len(i) > 3 else "" for i in high])),
        })
    if "Hardcoded secret_key" in by_type:
        report["recommendations"].append({
            "priority": "ALTA",
            "action": "Mover todas las SECRET_KEY a variables de entorno (.env)",
            "affected": list(set([i.get("file","") for i in by_type.get("Hardcoded secret_key", [])])),
        })

    # Guardar reporte
    doc_id = f"rpt_{uuid.uuid4().hex[:8]}"
    report_path = DOCS_DIR / f"incident_analysis_{doc_id}.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    report["report_saved"] = str(report_path)

    return report


def search_similar_solutions(query: str, limit: int = 5) -> list:
    """Busca soluciones similares en la memoria técnica."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        try:
            col = client.get_collection("technical_knowledge")
            results = col.query(query_texts=[query], n_results=limit)
            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            return [{"content": d[:500], "meta": m} for d, m in zip(docs, metas)]
        except Exception:
            return []
    except Exception as e:
        return [{"error": str(e)}]


def _index_in_memory(doc_id: str, content: str, metadata: dict):
    """Indexa documento en ChromaDB."""
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_PATH)
        col = client.get_or_create_collection("technical_knowledge")
        col.add(documents=[content], metadatas=[metadata], ids=[doc_id])
    except Exception:
        pass


def get_recent_docs(doc_type: str = None, limit: int = 10) -> list:
    """Obtiene documentos técnicos recientes."""
    _init_db()
    conn = sqlite3.connect(DB_PATH)
    if doc_type:
        rows = conn.execute(
            "SELECT doc_id, doc_type, title, tags, project_id, created_at FROM technical_docs WHERE doc_type=? ORDER BY created_at DESC LIMIT ?",
            (doc_type, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT doc_id, doc_type, title, tags, project_id, created_at FROM technical_docs ORDER BY created_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
    conn.close()
    return [{"doc_id": r[0], "type": r[1], "title": r[2], "tags": json.loads(r[3] or "[]"),
             "project_id": r[4], "created_at": r[5]} for r in rows]
