"""
GTI MCP Tool - Connects to GTI MCP Server instead of direct API calls
Save this as: src/ai_threathunter/tools/gti_mcp_tool.py
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

# Apply nest_asyncio to allow nested event loops
nest_asyncio.apply()


class GTIMCPInput(BaseModel):
    """Input schema for GTI MCP Tool."""
    ioc: str = Field(..., description="The IOC to analyze - IP address, domain, hash, or URL.")
    ioc_type: str = Field(..., description="Type of IOC: 'ip', 'domain', 'hash', or 'url'.")


class GTIMCPTool(BaseTool):
    """
    Google Threat Intelligence (GTI) Analysis via MCP Server.
    Uses the official GTI MCP server for threat intelligence queries.
    """
    
    name: str = "GTI MCP Analyzer"
    description: str = (
        "Leverages the Google Threat Intelligence API via MCP server to provide deep analysis of IOCs. "
        "This tool extracts advanced threat attribution, including associated threat actors, campaigns, "
        "and malware families, in addition to comprehensive behavioral and infrastructure data."
    )
    args_schema: Type[BaseModel] = GTIMCPInput
    
    # MCP connection details
    mcp_command: str = Field(default="", exclude=True)
    mcp_args: list = Field(default_factory=list, exclude=True)
    _session: Optional[ClientSession] = None
    _read_stream = None
    _write_stream = None
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Get MCP server configuration from environment
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
        
        print(f"🔌 GTI MCP Tool initialized: {self.mcp_command} {' '.join(self.mcp_args)}")
    
    async def _ensure_connection(self):
        """Ensure MCP connection is established."""
        if self._session is not None:
            return
        
        print(f"🔌 Connecting to GTI MCP server...")
        
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
        
        # Create the connection
        self._read_stream, self._write_stream = await stdio_client(server_params).__aenter__()
        session_context = ClientSession(self._read_stream, self._write_stream)
        self._session = await session_context.__aenter__()
        
        # Initialize the session
        await self._session.initialize()
        
        # List available tools
        tools_result = await self._session.list_tools()
        available_tools = [tool.name for tool in tools_result.tools]
        print(f"✅ Connected to GTI MCP. Available tools: {available_tools}")
    
    async def _call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Call a GTI MCP tool."""
        debug_manager = DebugManager()
        start_time = time.time()
        
        try:
            await self._ensure_connection()
            
            print(f"🔍 Calling GTI MCP tool: {tool_name} with {arguments}")
            
            request_info = {
                'tool': tool_name,
                'arguments': arguments,
                'server': f"{self.mcp_command} {' '.join(self.mcp_args)}"
            }
            
            # Call the tool
            result = await self._session.call_tool(tool_name, arguments)
            
            # Extract text content
            text_content = []
            for item in result.content:
                if hasattr(item, 'text'):
                    text_content.append(item.text)
            
            response_text = '\n'.join(text_content)
            
            # Log successful call
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_MCP',
                    endpoint=tool_name,
                    request_data=request_info,
                    response_data={
                        'content': response_text[:1000],  # Truncate for logging
                        'full_length': len(response_text)
                    },
                    error=None,
                    execution_time=time.time() - start_time
                )
            
            return response_text
            
        except Exception as e:
            error_msg = f"GTI MCP call failed: {str(e)}"
            print(f"❌ {error_msg}")
            
            # Log failed call
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_MCP',
                    endpoint=tool_name,
                    request_data=request_info if 'request_info' in locals() else {'tool': tool_name},
                    response_data={'error': str(e)},
                    error=e,
                    execution_time=time.time() - start_time
                )
            
            return error_msg
    
    def _run(self, ioc: str, ioc_type: str) -> str:
        """
        Execute GTI analysis via MCP.
        
        Args:
            ioc: The indicator to analyze
            ioc_type: Type of IOC (ip, domain, hash, url)
            
        Returns:
            Formatted analysis results
        """
        try:
            print(f"🔍 GTI MCP Analysis: {ioc} ({ioc_type})")
            
            # Map IOC type to GTI MCP tool name
            tool_mapping = {
                'hash': 'get_file_report',
                'ip': 'get_ip_report',
                'domain': 'get_domain_report',
                'url': 'get_url_report'
            }
            
            tool_name = tool_mapping.get(ioc_type)
            if not tool_name:
                return f"Unsupported IOC type: {ioc_type}"
            
            # Prepare arguments based on tool
            if ioc_type == 'hash':
                arguments = {'file_hash': ioc}
            elif ioc_type == 'ip':
                arguments = {'ip_address': ioc}
            elif ioc_type == 'domain':
                arguments = {'domain': ioc}
            elif ioc_type == 'url':
                arguments = {'url': ioc}
            
            # Run async call
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(self._call_mcp_tool(tool_name, arguments))
            
            return result
            
        except Exception as e:
            return f"GTI MCP analysis failed for {ioc}: {str(e)}"
    
    def __del__(self):
        """Cleanup MCP connection."""
        if self._session:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Schedule cleanup
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
        if self._read_stream and self._write_stream:
            try:
                await stdio_client(None).__aexit__(None, None, None)
            except:
                pass