import subprocess
from nexus_core.skills.base import BaseSkill

class NucleiScanSkill(BaseSkill):
    name = "nuclei_scan"
    description = "Scan a target using nuclei vulnerability scanner"

    async def execute(self, target: str):
        try:
            cmd = [
                "nuclei",
                "-u", target,
                "-severity", "low,medium,high,critical",
                "-silent"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            return {
                "target": target,
                "output": result.stdout
            }

        except Exception as e:
            return {
                "error": str(e)
            }
