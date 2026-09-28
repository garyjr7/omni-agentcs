"""
GuardianAgent v1.0 — Seguridad continua BajioWare
"""
import subprocess, sqlite3, json, os, re, uuid
from datetime import datetime
from pathlib import Path
from nexus_core.config import NEXUS_ROOT, LEGACY_DATABASE_PATH

BASE_DIR = NEXUS_ROOT
DB_PATH = LEGACY_DATABASE_PATH

HARDCODED_PATTERNS = [
    (r"password\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded password"),
    (r"secret_key\s*=\s*['\"][^'\"]{4,}['\"]", "Hardcoded secret_key"),
    (r"api_key\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key"),
]


def init_incidents_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS security_incidents (
            id TEXT PRIMARY KEY,
            severity TEXT,
            title TEXT,
            description TEXT,
            file_path TEXT,
            line_number INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'open'
        )
    """)
    conn.commit()
    conn.close()


def save_incident(severity, title, description, file_path="", line_number=0):
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT OR IGNORE INTO security_incidents (id, severity, title, description, file_path, line_number) VALUES (?,?,?,?,?,?)",
        (incident_id, severity, title, description, file_path, line_number)
    )
    conn.commit()
    conn.close()
    return incident_id


def scan_for_secrets(directory=None):
    directory = Path(directory or BASE_DIR)
    skip = {"venv", "__pycache__", ".git", "node_modules"}
    incidents = []
    for f in directory.rglob("*.py"):
        if any(s in str(f) for s in skip):
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            for pattern, title in HARDCODED_PATTERNS:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Ignorar si usa getenv
                    if "getenv" in match.group() or "os.environ" in match.group():
                        continue
                    line_num = content[:match.start()].count("\n") + 1
                    rel_path = str(f).replace(str(BASE_DIR) + "/", "")
                    inc_id = save_incident("HIGH", title, f"Posible secreto: {match.group()[:50]}", rel_path, line_num)
                    incidents.append({"id": inc_id, "file": rel_path, "line": line_num, "type": title})
        except Exception:
            pass
    return incidents


def run_bandit_scan(directory=None):
    target = str(directory or BASE_DIR / "nexus_api")
    try:
        result = subprocess.run(
            f"bandit -r {target} -f json -q",
            shell=True, capture_output=True, text=True, timeout=60
        )
        try:
            data = json.loads(result.stdout)
            results_list = data.get("results", [])
            high = [r for r in results_list if r.get("issue_severity") == "HIGH"]
            for issue in high[:10]:
                save_incident("HIGH", issue.get("test_name", "Bandit"), issue.get("issue_text", ""),
                             issue.get("filename", "").replace(str(BASE_DIR) + "/", ""), issue.get("line_number", 0))
            return {"high": len(high), "medium": len([r for r in results_list if r.get("issue_severity") == "MEDIUM"]), "total": len(results_list)}
        except json.JSONDecodeError:
            return {"error": "bandit output invalid", "raw": result.stdout[:200]}
    except Exception as e:
        return {"error": str(e)}


def scan_recent_commits(n_commits=5):
    try:
        result = subprocess.run(
            f"git -C {BASE_DIR} log --oneline -{n_commits} --name-only",
            shell=True, capture_output=True, text=True
        )
        changed_files = [l.strip() for l in result.stdout.split("\n") if l.strip().endswith(".py")]
        incidents = []
        for f in set(changed_files):
            full_path = BASE_DIR / f
            if full_path.exists():
                content = full_path.read_text(encoding="utf-8", errors="replace")
                for pattern, title in HARDCODED_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        inc_id = save_incident("HIGH", f"[GIT] {title}", f"En commit reciente: {f}", f)
                        incidents.append({"id": inc_id, "file": f, "type": title})
        return {"files_scanned": len(set(changed_files)), "incidents": incidents}
    except Exception as e:
        return {"error": str(e)}


def get_open_incidents():
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute(
            "SELECT id, severity, title, file_path, line_number, created_at FROM security_incidents WHERE status='open' ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
        conn.close()
        return [{"id": r[0], "severity": r[1], "title": r[2], "file": r[3], "line": r[4], "date": r[5]} for r in rows]
    except Exception:
        return []


def full_security_scan():
    init_incidents_table()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "secrets": scan_for_secrets(),
        "bandit": run_bandit_scan(),
        "commits": scan_recent_commits(),
        "open_incidents": len(get_open_incidents()),
    }


if __name__ == "__main__":
    print(json.dumps(full_security_scan(), indent=2, ensure_ascii=False))
