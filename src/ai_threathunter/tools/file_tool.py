from typing import Type
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
import os

class FileWriteInput(BaseModel):
    """Input schema for FileWriteTool."""
    file_path: str = Field(..., description="The path to save the file to (e.g. 'reports/report.md')")
    content: str = Field(..., description="The full markdown content to write to the file")

class FileWriteTool(BaseTool):
    name: str = "Write File Tool"
    description: str = (
        "Writes text content to a specified file. CRITICAL: Use the EXACT file path provided in your task instructions. "
        "This tool will overwrite existing files, allowing you to update reports across multiple investigation rounds."
    )
    args_schema: Type[BaseModel] = FileWriteInput

    def _run(self, file_path: str, content: str) -> str:
        try:
            # Ensure directory exists
            directory = os.path.dirname(file_path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory)
                
            with open(file_path, 'w') as f:
                f.write(content)
                
            return f"Successfully wrote {len(content)} bytes to {file_path}"
        except Exception as e:
            return f"Error writing file: {str(e)}"
