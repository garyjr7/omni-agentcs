import sqlite3
import uuid
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'nexus_api', 'database.db')

class ProjectManagerAgent:
    def __init__(self):
        self.db_path = DB_PATH

    def create_project(self, name, repo_path=None):
        project_id = f'proj_{uuid.uuid4().hex[:12]}'
        conn = sqlite3.connect(self.db_path)
        conn.execute('INSERT INTO projects (project_id, name, status, repo_path) VALUES (?,?,?,?)', (project_id, name, 'PLANEACION', repo_path))
        conn.commit()
        conn.close()
        return {'success': True, 'project_id': project_id, 'name': name, 'status': 'PLANEACION'}
