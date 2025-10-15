"""
Unified GTI MCP Tool - Connects to GTI MCP Server for various actions.
"""

from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional, Literal
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

# Apply nest_asyncio to allow nested event loops
nest_asyncio.apply()


class GTIMCPToolInput(BaseModel):
    """Input schema for the unified GTI MCP Tool."""
    action: Literal['lookup_ioc', 'get_behaviour_summary'] = Field(..., description="The action to perform.")
    ioc: str = Field(..., description="The IOC to analyze (IP, domain, hash, or URL).")
    ioc_type: Optional[Literal['ip', 'domain', 'hash', 'url']] = Field(None, description="Type of IOC for 'lookup_ioc' action.")


class GTIMCPTool(BaseTool):
    """
    A unified tool to interact with the Google Threat Intelligence (GTI) MCP server,
    allowing for multiple actions like IOC lookups and behavioral analysis.
    """
    
    name: str = "Unified GTI MCP Tool"
    description: str = (
        "Performs various actions using the GTI MCP server. "
        "Use action 'lookup_ioc' for general threat intelligence on an IP, domain, hash, or URL. "
        "Use action 'get_behaviour_summary' for deep behavioral analysis of a file hash."
    )
    args_schema: Type[BaseModel] = GTIMCPToolInput
    
    # Shared MCP connection details
    _session: Optional[ClientSession] = None
    _read_stream = None
    _write_stream = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mcp_command = os.getenv('GTI_MCP_COMMAND', 'uv')
        gti_mcp_path = os.getenv('GTI_MCP_PATH', '')
        if not gti_mcp_path:
            raise ValueError("GTI_MCP_PATH environment variable must be set.")
        self.mcp_args = ['--directory', gti_mcp_path, 'run', 'server.py']
        self.loop = asyncio.get_event_loop()
        print(f"🔌 Unified GTI MCP Tool initialized.")

    async def _ensure_connection(self):
        """Establishes and maintains a single MCP connection."""
        if self._session is not None:
            return
        
        print(f"🔌 Connecting to GTI MCP server...")
        api_key = os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        if not api_key:
            raise ValueError("GTI_API_KEY or VIRUSTOTAL_API_KEY must be set.")
        
        server_params = StdioServerParameters(
            command=self.mcp_command,
            args=self.mcp_args,
            env={**os.environ, 'vt_apikey': api_key}
        )
        
        self._read_stream, self._write_stream = await stdio_client(server_params).__aenter__()
        session_context = ClientSession(self._read_stream, self._write_stream)
        self._session = await session_context.__aenter__()
        await self._session.initialize()
        print(f"✅ Connected to GTI MCP.")

    async def _call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Generic method to call a tool on the MCP server."""
        debug_manager = DebugManager()
        start_time = time.time()
        request_info = {'tool': tool_name, 'arguments': arguments}
        
        try:
            await self._ensure_connection()
            print(f"🔍 Calling MCP tool: {tool_name} with {arguments}")
            result = await self._session.call_tool(tool_name, arguments)
            
            text_content = [item.text for item in result.content if hasattr(item, 'text')]
            response_text = '\n'.join(text_content)
            
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_MCP', endpoint=tool_name, request_data=request_info,
                    response_data={'content': response_text[:1000], 'full_length': len(response_text)},
                    error=None, execution_time=time.time() - start_time
                )
            return response_text
        except Exception as e:
            error_msg = f"GTI MCP call failed for tool {tool_name}: {str(e)}"
            print(f"❌ {error_msg}")
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_MCP', endpoint=tool_name, request_data=request_info,
                    response_data={'error': str(e)}, error=e, execution_time=time.time() - start_time
                )
            return error_msg

    def _run(self, action: str, ioc: str, ioc_type: Optional[str] = None) -> str:
        """Dispatches the action to the appropriate method."""
        try:
            if action == 'lookup_ioc':
                if not ioc_type:
                    return "Error: 'ioc_type' is required for the 'lookup_ioc' action."
                return self.loop.run_until_complete(self._lookup_ioc(ioc, ioc_type))
            elif action == 'get_behaviour_summary':
                return self.loop.run_until_complete(self._get_behaviour_summary(ioc))
            else:
                return f"Error: Invalid action '{action}'. Available actions are 'lookup_ioc', 'get_behaviour_summary'."
        except Exception as e:
            return f"An error occurred in the unified GTI MCP tool: {str(e)}"

    async def _lookup_ioc(self, ioc: str, ioc_type: str) -> str:
        """Handles general IOC lookups."""
        tool_mapping = {
            'hash': 'get_file_report', 'ip': 'get_ip_report',
            'domain': 'get_domain_report', 'url': 'get_url_report'
        }
        tool_name = tool_mapping.get(ioc_type)
        if not tool_name:
            return f"Unsupported IOC type for lookup: {ioc_type}"
        
        arg_mapping = {
            'hash': 'file_hash', 'ip': 'ip_address',
            'domain': 'domain', 'url': 'url'
        }
        arguments = {arg_mapping[ioc_type]: ioc}
        return await self._call_mcp_tool(tool_name, arguments)

    async def _get_behaviour_summary(self, file_hash: str) -> str:
        """Handles file behavioral analysis."""
        return await self._call_mcp_tool('get_file_behavior', {'file_hash': file_hash})

    def __del__(self):
        """Cleanup MCP connection on object destruction."""
        if self._session:
            try:
                if self.loop.is_running():
                    asyncio.create_task(self._cleanup())
                else:
                    self.loop.run_until_complete(self._cleanup())
            except Exception:
                pass
    
    async def _cleanup(self):
        """Async cleanup of MCP resources."""
        if self._session:
            await self._session.__aexit__(None, None, None)
