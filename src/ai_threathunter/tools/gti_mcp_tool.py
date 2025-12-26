"""
Unified GTI MCP Tool - Connects to GTI MCP Server for various actions.
"""

from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional, Literal, Union
from pydantic import BaseModel, Field, PrivateAttr
import asyncio
import os
import time
import json
import nest_asyncio
from urllib.parse import urlparse

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Import Unified Data Models
from ..core.models import IOCAnalysisResult, BehavioralSummary, IOCType, Attribution
from ..utils.report_formatter import ReportFormatter

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
    action: Literal[
        'lookup_ioc', 
        'get_behaviour_summary', 
    ] = Field(..., description="The action to perform.")
    ioc: str = Field(..., description="The IOC to analyze (IP, domain, hash, or URL).")
    ioc_type: Optional[Literal['ip', 'domain', 'hash', 'url']] = Field(None, description="Type of IOC for 'lookup_ioc' action.")
    
    # Keeping extra params although mostly for future use or specialized calls
    relationship_name: Optional[str] = Field(None, description="The name of the relationship to query for 'get_entities_related_to_a_domain' action.")
    descriptors_only: Optional[bool] = Field(None, description="Whether to return only descriptors for related entities.")
    limit: Optional[int] = Field(None, description="Maximum number of related entities to return.")


class GTIMCPTool(BaseTool):
    """
    A unified tool to interact with the Google Threat Intelligence (GTI) MCP server,
    returning structured data models for the Orchestrator.
    """
    
    name: str = "Unified GTI MCP Tool"
    description: str = (
        "Performs deep analysis using the GTI MCP server. "
        "Use action 'lookup_ioc' for general threat intelligence on an IP, domain, hash, or URL (returns IOCAnalysisResult). "
        "Use action 'get_behaviour_summary' for deep behavioral analysis of a file hash (returns BehavioralSummary)."
    )
    args_schema: Type[BaseModel] = GTIMCPToolInput
    mcp_command: Optional[str] = None
    mcp_args: Optional[list[str]] = None
    loop: Optional[Any] = None
    _debug_manager: 'DebugManager' = PrivateAttr()
    _investigation_graph: Any = PrivateAttr(default=None)
    
    def __init__(self, investigation_graph = None, **kwargs):
        super().__init__(**kwargs)
        self._investigation_graph = investigation_graph
        self.mcp_command = os.getenv('GTI_MCP_COMMAND', 'uv')
        gti_mcp_path = os.getenv('GTI_MCP_PATH', '')
        # We allow path to be optional if command doesn't need it, but generally it does for 'uv run server.py'
        
        if gti_mcp_path:
            self.mcp_args = ['--directory', gti_mcp_path, 'run', 'server.py']
        else:
            # Fallback or error - assuming environment is set correctly per user context
            self.mcp_args = []

        self.loop = asyncio.get_event_loop()
        self._debug_manager = DebugManager()
        print(f"🔌 Unified GTI MCP Tool initialized.")

    async def _call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Generic method to call a tool on the MCP server and return raw text."""
        self._debug_manager.log(f"[MCP TOOL] Calling tool: {tool_name} with arguments: {arguments}")
        start_time = time.time()
        request_info = {'tool': tool_name, 'arguments': arguments}
        
        try:
            self._debug_manager.log(f"🔌 Connecting to GTI MCP server...")
            api_key = os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
            if not api_key:
                raise ValueError("GTI_API_KEY or VIRUSTOTAL_API_KEY must be set.")
            
            if not self.mcp_args:
                 # If we have no args, assume command is self-sufficient or error
                 pass

            server_params = StdioServerParameters(
                command=self.mcp_command,
                args=self.mcp_args,
                env={**os.environ, 'vt_apikey': api_key}
            )
            
            async with stdio_client(server_params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool(tool_name, arguments)
                    
                    text_content = [item.text for item in result.content if hasattr(item, 'text')]
                    response_text = '\n'.join(text_content)
                    
                    if self._debug_manager.debug_enabled:
                        self._debug_manager.log_api_call(
                            api_name='GTI_MCP', endpoint=tool_name, request_data=request_info,
                            response_data={'content': response_text[:1000], 'full_length': len(response_text)},
                            error=None, execution_time=time.time() - start_time
                        )
                    return response_text
        except Exception as e:
            error_msg = f"GTI MCP call failed for tool {tool_name}: {str(e)}"
            self._debug_manager.log(f"❌ {error_msg}")
            return error_msg

    def _parse_ioc_response(self, text: str, ioc: str, ioc_type: str) -> IOCAnalysisResult:
        """Parse raw MCP text output into IOCAnalysisResult"""
        # Try to parse as JSON
        try:
            data_dict = json.loads(text)
            # Handle potential wrapping like {"data": {...}}
            if "data" in data_dict:
                data_dict = data_dict["data"]
            
            attrs = data_dict.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            
            # Extract common attributes
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) if stats else 0
            
            gti_assessment = attrs.get("gti_assessment", {})
            verdict = gti_assessment.get("verdict", {}).get("value", "See Description")
            score = gti_assessment.get("threat_score", {}).get("value", 0)
            
            related_iocs = []
            
            # Extract relationships (DNS for domains)
            if ioc_type == 'domain':
                for record in attrs.get('last_dns_records', []):
                    if record.get('type') == 'A' and record.get('value'):
                        ip_val = record.get('value')
                        related_iocs.append({
                            'type': 'ip',
                            'value': ip_val,
                            'relationship': 'RESOLVES_TO',
                            'description': f"Domain {ioc} resolves to IP {ip_val}"
                        })
            
            # Extract host for URLs
            elif ioc_type == 'url':
                try:
                    parsed = urlparse(ioc)
                    if parsed.hostname:
                        related_iocs.append({
                            'type': 'domain',
                            'value': parsed.hostname,
                            'relationship': 'HOSTED_ON',
                            'description': f"URL {ioc} is hosted on domain {parsed.hostname}"
                        })
                except Exception:
                    pass

            return IOCAnalysisResult(
                ioc=ioc,
                ioc_type=IOCType(ioc_type) if ioc_type in ['ip', 'domain', 'url', 'hash'] else IOCType.FILE,
                description=text if len(text) < 5000 else text[:5000] + "...", # Truncate very long raw JSON
                verdict=verdict,
                score=score,
                malicious_votes=malicious,
                total_votes=total,
                related_iocs=related_iocs,
                timestamp=time.time(),
                raw_data=attrs
            )
        except Exception:
            # Fallback to simple description if JSON parsing fails
            return IOCAnalysisResult(
                ioc=ioc,
                ioc_type=IOCType(ioc_type) if ioc_type in ['ip', 'domain', 'url', 'hash'] else IOCType.FILE,
                description=text,
                verdict="See Description", 
                timestamp=time.time()
            )

    def _parse_behavior_response(self, text: str, hash_val: str) -> BehavioralSummary:
        """Parse raw MCP text behavior into BehavioralSummary"""
        try:
            data = json.loads(text)
            if "data" in data:
                data = data["data"]
            
            # Extract network IOCs
            network_iocs = []
            ip_traffic = []
            for ip in data.get('ip_traffic', []):
                if isinstance(ip, dict):
                     val = f"{ip.get('destination_ip', 'N/A')}:{ip.get('destination_port', 'N/A')}"
                     ip_traffic.append(val)
                     if ip.get('destination_ip'):
                         ip_addr = ip.get('destination_ip')
                         port = ip.get('destination_port', 'unknown')
                         network_iocs.append({
                             'type': 'ip', 
                             'value': ip_addr,
                             'description': f"Traffic to {ip_addr}:{port} observed"
                         })

            dns_lookups = []
            for lookup in data.get('dns_lookups', []):
                if isinstance(lookup, dict) and lookup.get('hostname'):
                    hostname = lookup.get('hostname')
                    dns_lookups.append(hostname)
                    network_iocs.append({
                        'type': 'domain', 
                        'value': hostname,
                        'description': f"DNS Lookup for {hostname}"
                    })
                    
            http_requests = []
            for req in data.get('http_conversations', []):
                if isinstance(req, dict) and req.get('url'):
                    url_val = req.get('url')
                    http_requests.append(url_val)
                    network_iocs.append({
                        'type': 'url', 
                        'value': url_val,
                        'description': f"HTTP request to {url_val}"
                    })

            files_dropped = []
            for f in data.get('files_dropped', []):
                if isinstance(f, dict) and f.get('sha256'):
                    files_dropped.append(f.get('sha256'))

            return BehavioralSummary(
                hash=hash_val,
                processes_created=data.get('processes_created', []),
                files_dropped=files_dropped,
                files_written=data.get('files_written', []),
                dns_lookups=dns_lookups,
                ip_traffic=ip_traffic,
                http_requests=http_requests,
                network_iocs=network_iocs,
                command_executions=data.get('command_executions', [])
            )
        except Exception:
            return BehavioralSummary(
                hash=hash_val,
                processes_created=["See Raw Report for details"],
                command_executions=[text[:500] + "..."] # Truncate for summary
            )

    def _run(self, action: str, ioc: str, ioc_type: Optional[str] = None, **kwargs) -> Union[IOCAnalysisResult, BehavioralSummary]:
        """Dispatches the action and returns structured data."""
        try:
            if action == 'lookup_ioc':
                if not ioc_type:
                    # Return error as IOCAnalysisResult object
                    return IOCAnalysisResult(
                        ioc=ioc,
                        ioc_type=IOCType.FILE,
                        description="Error: 'ioc_type' is required for the 'lookup_ioc' action.",
                        verdict="ERROR",
                        timestamp=time.time()
                    )
                
                # Run Async Loop
                report_text = self.loop.run_until_complete(self._lookup_ioc(ioc, ioc_type))
                result = self._parse_ioc_response(report_text, ioc, ioc_type)
                
                # Save to graph
                if self._investigation_graph:
                    try:
                         self._investigation_graph.add_analysis_result(result)
                         # Mark node as analyzed
                         self._investigation_graph.mark_node_analyzed(ioc)
                    except Exception as e:
                         print(f"    ⚠️ Failed to save to investigation graph: {e}")
                
                return result

            elif action == 'get_behaviour_summary':
                report_text = self.loop.run_until_complete(self._get_behaviour_summary(ioc))
                result = self._parse_behavior_response(report_text, ioc)
                
                # Save to graph
                if self._investigation_graph:
                    try:
                         self._investigation_graph.add_behavior_summary(result)
                         # Mark hash as analyzed
                         self._investigation_graph.mark_node_analyzed(ioc)
                    except Exception as e:
                         print(f"    ⚠️ Failed to save to investigation graph: {e}")
                
                return result
            
            else:
                # Return error as IOCAnalysisResult object
                return IOCAnalysisResult(
                    ioc=ioc,
                    ioc_type=IOCType(ioc_type) if ioc_type and ioc_type in ['ip', 'domain', 'url', 'hash'] else IOCType.FILE,
                    description=f"Error: Action {action} not fully supported in V2 Structured Mode yet.",
                    verdict="ERROR",
                    timestamp=time.time()
                )

        except Exception as e:
            # Always return a proper model object with error details
            if action == 'get_behaviour_summary':
                return BehavioralSummary(
                    hash=ioc,
                    processes_created=[f"Error: {str(e)}"]
                )
            else:
                return IOCAnalysisResult(
                    ioc=ioc,
                    ioc_type=IOCType(ioc_type) if ioc_type and ioc_type in ['ip', 'domain', 'url', 'hash'] else IOCType.FILE,
                    description=f"An error occurred in the unified GTI MCP tool: {str(e)}",
                    verdict="ERROR",
                    timestamp=time.time()
                )

    async def _lookup_ioc(self, ioc: str, ioc_type: str) -> str:
        """Handles general IOC lookups."""
        tool_mapping = {
            'hash': 'get_file_report', 'ip': 'get_ip_address_report',
            'domain': 'get_domain_report', 'url': 'get_url_report'
        }
        tool_name = tool_mapping.get(ioc_type)
        if not tool_name:
            raise ValueError(f"Unsupported IOC type: {ioc_type}")
        
        arg_mapping = {
            'hash': 'hash', 'ip': 'ip_address',
            'domain': 'domain', 'url': 'url'
        }
        arguments = {arg_mapping[ioc_type]: ioc}
        return await self._call_mcp_tool(tool_name, arguments)

    async def _get_behaviour_summary(self, file_hash: str) -> str:
        """Handles file behavioral analysis."""
        return await self._call_mcp_tool('get_file_behavior_summary', {'hash': file_hash})
