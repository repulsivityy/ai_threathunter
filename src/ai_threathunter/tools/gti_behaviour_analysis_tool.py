from crewai.tools import BaseTool
from typing import Type, Dict, Any
from pydantic import BaseModel, Field
import requests
import os
import time

# Import the debug manager
try:
    from ..debug_manager import DebugManager
except ImportError:
    class DebugManager:
        def __init__(self):
            self.debug_enabled = False
        def log_api_call(self, *args, **kwargs):
            pass

class GTIBehaviourAnalysisInput(BaseModel):
    """Input schema for the GTI Behaviour Analysis Tool."""
    hash: str = Field(..., description="The file hash (SHA256) to analyze.")

class GTIBehaviourAnalysisTool(BaseTool):
    name: str = "GTI Behaviour Analysis Tool"
    description: str = (
        "Performs deep malware analysis by retrieving detailed behavioral summaries for a file hash from Google Threat Intelligence."
    )
    args_schema: Type[BaseModel] = GTIBehaviourAnalysisInput
    api_key: str = Field(default="", exclude=True)

    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            raise ValueError("GTI API key not found. Please set GTI_API_KEY or VIRUSTOTAL_API_KEY environment variable.")

    def _run(self, hash: str) -> str:
        """Execute the deep analysis."""
        try:
            print(f"🔍 GTI Deep Analysis: {hash}")
            return self._get_hash_behavior_summary(hash)
        except Exception as error:
            return f"GTI deep analysis failed for {hash}: {str(error)}"

    def _make_request(self, url: str) -> Dict[str, Any]:
        """Make GTI API request with debug logging."""
        debug_manager = DebugManager()
        start_time = time.time()
        try:
            headers = {'x-apikey': self.api_key, 'x-tool': "multi_agent_threathunting"}
            request_info = {
                'url': url,
                'method': 'GET',
                'headers': {k: v if k != 'x-apikey' else 'REDACTED' for k, v in headers.items()}
            }
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()
            response_data = response.json()
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_Deep_Analysis',
                    endpoint=url.replace('https://www.virustotal.com/api/v3/', ''),
                    request_data=request_info,
                    response_data={'status_code': response.status_code, 'data': response_data},
                    error=None,
                    execution_time=time.time() - start_time
                )
            return response_data
        except requests.exceptions.RequestException as e:
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI_Deep_Analysis',
                    endpoint=url.replace('https://www.virustotal.com/api/v3/', ''),
                    request_data=request_info if 'request_info' in locals() else {'url': url},
                    response_data={'error': str(e)},
                    error=e,
                    execution_time=time.time() - start_time
                )
            return {}

    def _format_behavior_summary(self, behavior_data: Dict) -> str:
        """Formats the behavior summary into a readable string."""
        if not behavior_data or 'data' not in behavior_data:
            return "\n\n=== BEHAVIORAL SUMMARY ===\nNo behavioral data found.\n"

        response = "\n\n=== BEHAVIORAL SUMMARY ===\n"
        data = behavior_data['data']

        def format_list(title, items, limit=None):
            res = f"\n{title}:\n"
            if items:
                for i, item in enumerate(items):
                    if limit and i >= limit:
                        res += f"- ... and {len(items) - limit} more\n"
                        break
                    res += f"- {item}\n"
            else:
                res += "- None\n"
            return res

        # Provide the full list of processes for the agent to analyze
        response += format_list("Processes Created", data.get('processes_created', []))
        response += format_list("Command Executions", data.get('command_executions', []))
        response += format_list("Process Injections", data.get('process_injections', []))
        response += format_list("Process Terminated", data.get('processes_terminated', []))
        
        # For other items, we can still limit them to keep the summary concise
        response += format_list("Files Opened", data.get('files_opened', []), limit=20)
        response += format_list("Files Written", data.get('files_written', []), limit=20)
        response += format_list("Registry Keys Set", [f"{reg.get('key', 'N/A')}: {reg.get('value', 'N/A')}" for reg in data.get('registry_keys_set', []) if isinstance(reg, dict)], limit=20)
        response += format_list("Registry Keys Opened", [f"{reg.get('key', 'N/A')}" for reg in data.get('registry_keys_opened', []) if isinstance(reg, dict)], limit=20)
        response += format_list("IP Traffic", [f"{ip.get('destination_ip', 'N/A')}:{ip.get('destination_port', 'N/A')}" for ip in data.get('ip_traffic', []) if isinstance(ip, dict)], limit=20)
        response += format_list("Memory Pattern IP", data.get('memory_pattern_ips', []), limit=20)
        response += format_list("HTTP/HTTPS Requests", [conv.get('url', 'N/A') for conv in data.get('http_conversations', []) if isinstance(conv, dict)], limit=20)
        response += format_list("DNS Lookups", [f"{lookup.get('hostname', 'N/A')}" for lookup in data.get('dns_lookups', []) if isinstance(lookup, dict)], limit=20)
        response += format_list("Mutexes Created", data.get('mutexes_created', []), limit=20)
        response += format_list("Mutexes Opened", data.get('mutexes_opened', []), limit=20)
        response += format_list("Files Attribute Changed", data.get('files_attribute_changed', []), limit=20)
        response += format_list("Windows Hidden", data.get('windows_hidden', []), limit=20)

        return response

    def _get_hash_behavior_summary(self, hash_value: str) -> str:
        """Get and format the behavior summary for a hash."""
        print(f"🔍 Getting behavior summary for hash: {hash_value}")
        behavior_url = f'https://www.virustotal.com/api/v3/files/{hash_value}/behaviour_summary'
        behavior_data = self._make_request(behavior_url)
        return self._format_behavior_summary(behavior_data)