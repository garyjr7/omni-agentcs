from nexus_core.skills.base import BaseSkill


class FileReaderSkill(BaseSkill):

    name = "file_reader"

    async def execute(self, path):

        with open(path, "r") as f:
            content = f.read()

        return {
            "file": path,
            "content": content
        }
