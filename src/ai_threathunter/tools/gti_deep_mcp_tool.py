"""
GTI Deep Analysis MCP Tool - Deep behavioral analysis via MCP
Save this as: src/ai_threathunter/tools/gti_deep_mcp_tool.py
"""

from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional
from pydantic import BaseModel, Field
import asyncio
import os
import time
import nest_asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Import the debug manager
try:
    from ..debug_manager import DebugManager
except ImportError:
    class DebugManager:
        def __init__(self):
            self.debug_enabled = False
        def log_api_call(self, *args, **kwargs):
            pass

nest_asyncio.apply()


class GTIDeepMCPInput(BaseModel):
    """Input schema for GTI Deep Analysis MCP Tool."""
    hash: str = Field(..., description="The file hash (SHA256) to analyze.")


class GTIDeepAnalysisMCPTool(BaseTool):
    """
    Deep malware behavioral analysis via GTI MCP Server.
    Retrieves detailed behavioral summaries, sandbox execution data, and runtime analysis.
    """
    
    name: str = "GTI Deep Analysis MCP Tool"
    description: str = (
        "Performs deep malware analysis by retrieving detailed behavioral summaries for a file hash "
        "from Google Threat Intelligence via MCP server. Provides sandbox execution data, process trees, "
        "file system activity, registry changes, and network communications."
    )
    args_schema: Type[BaseModel] = GTIDeepMCPInput
    
    # MCP connection details
    mcp_command: str = Field(default="", exclude=True)
    mcp_args: list = Field(default_factory=list, exclude=True)
    _session: Optional[ClientSession] = None
    _read_stream = None
    _write_stream = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Use same configuration as GTI tool
        self.mcp_command = os.getenv('GTI_MCP_COMMAND', 'uv')
        
        # Get GTI MCP directory path
        gti_mcp_path = os.getenv('GTI_MCP_PATH', '')
        if not gti_mcp_path:
            raise ValueError("GTI_MCP_PATH environment variable must be set to the path of your GTI MCP server")
        
        # Build args for uv command
        self.mcp_args = [
            '--directory',
            gti_mcp_path,
            'run',
            'server.py'
        ]
    
    async def _ensure_connection(self):
        """Ensure MCP connection is established."""
        if self._session is not None:
            return
        
        print(f"🔌 Connecting to GTI MCP server for deep analysis...")
        
        # Get API key from environment
        api_key = os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            raise ValueError("GTI_API_KEY or VIRUSTOTAL_API_KEY must be set")
        
        server_params = StdioServerParameters(
            command=self.mcp_command,
            args=self.mcp_args,
            env={
                **os.environ,
                'vt_apikey': api_key  # Use vt_apikey as per your MCP server configuration
            }
        )
        
        self._read_stream, self._write_stream = await stdio_client(server_params).__aenter__()
        session_context = ClientSession(self._read_stream, self._write_stream)
        self._session = await session_context.__aenter__()
        await self._session.initialize()
        
        print(f"✅ Connected to GTI MCP for deep analysis")
    
    async def _get_behavior_summary(self, hash_value: str) -> str:
        """Get behavioral summary via MCP."""
        debug_manager = DebugManager()
        start_time = time.time()
        
        try:
            await self._ensure_connection()
            
            print(f"🔍 Getting behavior summary via MCP: {hash_value}")
            
            request_info = {
                'tool': 'get_file_behavior',
                'arguments': {'file_hash': hash_value},
                'server': f"{self.mcp_command} {' '.join(self.mcp_args)}"
            }
            
            # Call the MCP tool for behavior analysis
            result = await self._session.call_tool('get_file_behavior', {'file_hash': hash_value})
            
            # Extract text content
            text_content = []
            for item in result.content:
                if hasattr(item, 'text'):
                    text_content.append(item.text)
            
            response_text = '\n'.join(text_content)
            
            # Log successful call
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_Deep_Analysis_MCP',
                    endpoint='get_file_behavior',
                    request_data=request_info,
                    response_data={
                        'content': response_text[:1000],
                        'full_length': len(response_text)
                    },
                    error=None,
                    execution_time=time.time() - start_time
                )
            
            return response_text
            
        except Exception as e:
            error_msg = f"GTI behavior analysis failed: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log failed call
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_Deep_Analysis_MCP',
                    endpoint='get_file_behavior',
                    request_data=request_info if 'request_info' in locals() else {'hash': hash_value},
                    response_data={'error': str(e)},
                    error=e,
                    execution_time=time.time() - start_time
                )
            
            return error_msg
    
    def _run(self, hash: str) -> str:
        """
        Execute deep behavioral analysis via MCP.
        
        Args:
            hash: File hash to analyze
            
        Returns:
            Formatted behavioral analysis report
        """
        try:
            print(f"🔍 GTI Deep Analysis (MCP): {hash}")
            
            # Run async call
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self._get_behavior_summary(hash))
            
            # Format the result
            formatted_result = f"""
=== GTI BEHAVIORAL SUMMARY (via MCP) ===
Hash: {hash}

{result}

---
Source: Google Threat Intelligence via MCP Server
"""
            
            return formatted_result
            
        except Exception as error:
            return f"GTI deep analysis (MCP) failed for {hash}: {str(error)}"
    
    def __del__(self):
        """Cleanup MCP connection."""
        if self._session:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._cleanup())
                else:
                    loop.run_until_complete(self._cleanup())
            except:
                pass
    
    async def _cleanup(self):
        """Async cleanup of MCP resources."""
        if self._session:
            try:
                await self._session.__aexit__(None, None, None)
            except:
                pass