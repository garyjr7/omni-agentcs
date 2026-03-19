from nexus_core.agents.base import BaseAgent, AgentMetadata, AgentCapability
import asyncio
import json

class DataAnalysisAgent(BaseAgent):
    """
    An AI agent specialized in performing various data analysis tasks on structured data.
    """
    capability = AgentCapability.DATA_ANALYSIS

    async def execute(self, task_id: str, payload: dict) -> dict:
        """
        Executes a data analysis task based on the provided payload.

        The payload must contain:
        - 'data': A list of dictionaries or a dictionary of lists (pandas DataFrame compatible).
        - 'analysis_type': The type of analysis to perform. Supported types are:
            - 'summary': Computes descriptive statistics (mean, std, etc.).
            - 'correlation': Computes the pairwise correlation of columns.
            - 'value_counts': Computes frequency counts for a specified column.
                              Requires an additional 'column' key in the payload.

        Args:
            task_id: The unique identifier for the task.
            payload: A dictionary containing the data and analysis parameters.

        Returns:
            A dictionary with the status and results of the analysis.
        """
        try:
            # Assuming necessary libraries like pandas and asyncio are available in the environment
            import pandas as pd
            import asyncio

            if 'data' not in payload or 'analysis_type' not in payload:
                raise ValueError("Payload must contain 'data' and 'analysis_type' keys.")

            df = pd.DataFrame(payload['data'])
            analysis_type = payload['analysis_type']

            if df.empty:
                raise ValueError("Input data cannot be empty.")

            # Simulate I/O or CPU-bound work for an async agent
            await asyncio.sleep(0.1)

            analysis_result = None
            if analysis_type == 'summary':
                analysis_result = df.describe().to_dict()
            elif analysis_type == 'correlation':
                # Ensure we only try to correlate numeric columns
                numeric_df = df.select_dtypes(include='number')
                if numeric_df.shape[1] < 2:
                    analysis_result = {"message": "Correlation requires at least two numeric columns."}
                else:
                    analysis_result = numeric_df.corr().to_dict()
            elif analysis_type == 'value_counts':
                if 'column' not in payload:
                    raise ValueError("Payload must specify a 'column' for 'value_counts' analysis.")
                column = payload['column']
                if column not in df.columns:
                    raise ValueError(f"Column '{column}' not found in the provided data.")
                analysis_result = df[column].value_counts().to_dict()
            else:
                raise ValueError(f"Unsupported analysis type: '{analysis_type}'.")

            return {"status": "completed", "results": analysis_result, "task_id": task_id}

        except Exception as e:
            return {"status": "failed", "results": str(e), "task_id": task_id}