import os
import json
from typing import List, Dict, Optional
from uuid import uuid4

class ProjectService:
    def __init__(self, settings):
        self.settings = settings
        self.projects_dir = os.path.join(settings.PROJECTS_DIR)
        os.makedirs(self.projects_dir, exist_ok=True)

    def create_project(self, name: str, project_type: str) -> Dict:
        project_id = f"proj_{uuid4().hex[:8]}"
        project_path = os.path.join(self.projects_dir, project_id)
        os.makedirs(project_path, exist_ok=True)
        metadata = {
            "id": project_id,
            "name": name,
            "type": project_type,
        }
        with open(os.path.join(project_path, "metadata.json"), "w") as f:
            json.dump(metadata, f)
        return metadata

    def list_projects(self) -> List[Dict]:
        projects = []
        for project_dir in os.listdir(self.projects_dir):
            metadata_path = os.path.join(self.projects_dir, project_dir, "metadata.json")
            if os.path.isfile(metadata_path):
                with open(metadata_path) as f:
                    projects.append(json.load(f))
        return projects

    def get_project(self, id: str) -> Optional[Dict]:
        project_path = os.path.join(self.projects_dir, id, "metadata.json")
        if os.path.isfile(project_path):
            with open(project_path) as f:
                return json.load(f)
        return None

    def delete_project(self, id: str) -> bool:
        project_path = os.path.join(self.projects_dir, id)
        deleted_path = os.path.join(self.projects_dir, ".deleted", id)
        os.makedirs(os.path.dirname(deleted_path), exist_ok=True)
        if os.path.exists(project_path):
            os.rename(project_path, deleted_path)
            return True
        return False
