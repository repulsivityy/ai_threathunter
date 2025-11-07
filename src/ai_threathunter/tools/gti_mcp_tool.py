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
        def log(self, *args, **kwargs):
            pass

# Apply nest_asyncio to allow nested event loops
nest_asyncio.apply()


class GTIMCPToolInput(BaseModel):
    """Input schema for the unified GTI MCP Tool."""
    action: Literal['lookup_ioc', 'get_behaviour_summary', 'get_domain_relationships', 'get_ip_relationships'] = Field(..., description="The action to perform.")
    ioc: str = Field(..., description="The IOC to analyze (IP, domain, hash, or URL).")
    ioc_type: Optional[Literal['ip', 'domain', 'hash', 'url']] = Field(None, description="Type of IOC for 'lookup_ioc' action.")
    relationship: Optional[str] = Field(None, description="The relationship to query for 'get_domain_relationships' and 'get_ip_relationships' actions.")


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
        "Use action 'get_domain_relationships' to get relationships for a domain."
        "Use action 'get_ip_relationships' to get relationships for an IP address."
    )
    args_schema: Type[BaseModel] = GTIMCPToolInput
    mcp_command: Optional[str] = None
    mcp_args: Optional[list[str]] = None
    loop: Optional[Any] = None
    debug_manager: Optional[Any] = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.mcp_command = os.getenv('GTI_MCP_COMMAND', 'uv')
        gti_mcp_path = os.getenv('GTI_MCP_PATH', '')
        if not gti_mcp_path:
            raise ValueError("GTI_MCP_PATH environment variable must be set.")
        self.mcp_args = ['--directory', gti_mcp_path, 'run', 'server.py']
        self.loop = asyncio.get_event_loop()
        self.debug_manager = DebugManager()
        print(f"🔌 Unified GTI MCP Tool initialized.")

    async def _call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Generic method to call a tool on the MCP server."""
        self.debug_manager.log(f"[MCP TOOL] Calling tool: {tool_name} with arguments: {arguments}")
        start_time = time.time()
        request_info = {'tool': tool_name, 'arguments': arguments}
        
        try:
            self.debug_manager.log(f"🔌 Connecting to GTI MCP server...")
            api_key = os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
            if not api_key:
                raise ValueError("GTI_API_KEY or VIRUSTOTAL_API_KEY must be set.")
            
            server_params = StdioServerParameters(
                command=self.mcp_command,
                args=self.mcp_args,
                env={**os.environ, 'vt_apikey': api_key}
            )
            self.debug_manager.log(f"[MCP TOOL] Server params: {server_params}")
            
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    self.debug_manager.log(f"✅ Connected to GTI MCP.")
                    self.debug_manager.log(f"🔍 Calling MCP tool: {tool_name} with {arguments}")
                    result = await session.call_tool(tool_name, arguments)
                    self.debug_manager.log(f"[MCP TOOL] Result: {result}")
                    
                    text_content = [item.text for item in result.content if hasattr(item, 'text')]
                    response_text = '\n'.join(text_content)
                    self.debug_manager.log(f"[MCP TOOL] Response text: {response_text}")
                    
                    if self.debug_manager.debug_enabled:
                        self.debug_manager.log_api_call(
                            api_name='GTI_MCP', endpoint=tool_name, request_data=request_info,
                            response_data={'content': response_text[:1000], 'full_length': len(response_text)},
                            error=None, execution_time=time.time() - start_time
                        )
                    return response_text
        except Exception as e:
            error_msg = f"GTI MCP call failed for tool {tool_name}: {str(e)}"
            self.debug_manager.log(f"❌ {error_msg}")
            if self.debug_manager.debug_enabled:
                self.debug_manager.log_api_call(
                    api_name='GTI_MCP', endpoint=tool_name, request_data=request_info,
                    response_data={'error': str(e)}, error=e, execution_time=time.time() - start_time
                )
            return error_msg

    def _run(self, action: str, ioc: str, ioc_type: Optional[str] = None, relationship: Optional[str] = None) -> str:
        """Dispatches the action to the appropriate method."""
        try:
            if action == 'lookup_ioc':
                if not ioc_type:
                    return "Error: 'ioc_type' is required for the 'lookup_ioc' action."
                return self.loop.run_until_complete(self._lookup_ioc(ioc, ioc_type))
            elif action == 'get_behaviour_summary':
                return self.loop.run_until_complete(self._get_behaviour_summary(ioc))
            elif action == 'get_domain_relationships':
                if not relationship:
                    return "Error: 'relationship' is required for the 'get_domain_relationships' action."
                return self.loop.run_until_complete(self._get_domain_relationships(ioc, relationship))
            elif action == 'get_ip_relationships':
                if not relationship:
                    return "Error: 'relationship' is required for the 'get_ip_relationships' action."
                return self.loop.run_until_complete(self._get_ip_relationships(ioc, relationship))
            else:
                return f"Error: Invalid action '{action}'. Available actions are 'lookup_ioc', 'get_behaviour_summary', 'get_domain_relationships', 'get_ip_relationships'."
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
            'hash': 'hash', 'ip': 'ip_address',
            'domain': 'domain', 'url': 'url'
        }
        arguments = {arg_mapping[ioc_type]: ioc}
        return await self._call_mcp_tool(tool_name, arguments)

    async def _get_behaviour_summary(self, file_hash: str) -> str:
        """Handles file behavioral analysis."""
        return await self._call_mcp_tool('get_file_behavior_summary', {'hash': file_hash})

    async def _get_domain_relationships(self, domain: str, relationship: str) -> str:
        """Handles domain relationship lookups."""
        return await self._call_mcp_tool('get_domain_relationships', {'domain': domain, 'relationship': relationship})

    async def _get_ip_relationships(self, ip_address: str, relationship: str) -> str:
        """Handles IP address relationship lookups."""
        return await self._call_mcp_tool('get_ip_address_relationships', {'ip_address': ip_address, 'relationship': relationship})