import re

AGENT_HEADER = """from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import json
"""

class AgentGenerator:
    def __init__(self, llm_provider, logger):
        self.llm    = llm_provider
        self.logger = logger

    async def generate_agent_code(self, capability):
        prompt = f"""Generate ONLY a Python class for an AI agent with capability: {capability}

Requirements:
- Class must inherit from BaseAgent (already imported, do NOT import it)
- Must implement: async def execute(self, task_id: str, payload: dict) -> dict
- Return a dict with status and results
- Output ONLY the class definition, no imports, no markdown, no explanations

Example:
class MyAgent(BaseAgent):
    async def execute(self, task_id: str, payload: dict) -> dict:
        await asyncio.sleep(0.1)
        return {{"status": "completed", "result": "done", "task_id": task_id}}
"""
        raw = await self.llm.generate_code(prompt)

        # Extrae solo el bloque Python
        match = re.search(r"```python\s*(.*?)```", raw, re.DOTALL)
        if match:
            code = match.group(1).strip()
        else:
            match2 = re.search(r"(class\s+\w+.*)", raw, re.DOTALL)
            code   = match2.group(1).strip() if match2 else raw.strip()

        # Siempre añade los imports correctos al inicio
        final = AGENT_HEADER + "\n" + code
        self.logger.info(f"Agent code generated ({len(final)} chars)")
        return final
