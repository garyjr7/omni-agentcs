import asyncio
import json


class NmapScanSkill:

    name = "nmap_scan"

    async def execute(self, target: str):

        cmd = [
            "nmap",
            "-p-",
            "--min-rate", "1000",
            "-T4",
            target
        ]

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if stderr:
            return {"error": stderr.decode()}

        result = stdout.decode()

        return {
            "target": target,
            "scan_result": result
        }
