from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import json

class ReportGenerationAgent(BaseAgent):
    """
    An AI agent specialized in generating reports from structured data.
    """
    capability = "AgentCapability.REPORT_GENERATION"

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Executes the report generation task.

        Args:
            task_id: The unique identifier for the task.
            payload: A dictionary containing the data and parameters for the report.
                     Expected keys:
                     - 'data_points' (list): A list of data points to include.
                     - 'report_title' (str): The title of the report.
                     - 'summary_prompt' (str): A prompt to guide the summary generation.

        Returns:
            A dictionary containing the status and the generated report content.
        """
        data_points = payload.get("data_points", [])
        title = payload.get("report_title", "Untitled Report")
        summary_prompt = payload.get("summary_prompt", "Summarize the following data:")

        if not data_points:
            return {"status": "failed", "result": "No data points provided for report generation.", "task_id": task_id}

        try:
            # Simulate complex analysis and summary generation
            header = f"# {title}\n\n"
            summary = f"## Executive Summary\n\n{summary_prompt}\nBased on the {len(data_points)} data points provided, the analysis indicates a clear trend. Key findings have been compiled and detailed below.\n\n"

            details = "## Detailed Analysis\n\n"
            for i, point in enumerate(data_points, 1):
                details += f"- Point {i}: {str(point)}\n"

            footer = "\n-- End of Report --"

            report_content = header + summary + details + footer

            return {
                "status": "completed",
                "result": {
                    "report_content": report_content,
                    "title": title,
                    "data_points_analyzed": len(data_points)
                },
                "task_id": task_id
            }
        except Exception as e:
            return {"status": "failed", "result": f"An error occurred during report generation: {str(e)}", "task_id": task_id}