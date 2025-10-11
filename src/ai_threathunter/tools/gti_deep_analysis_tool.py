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

class GTIDeepAnalysisInput(BaseModel):
    """Input schema for the GTI Deep Analysis Tool."""
    hash: str = Field(..., description="The file hash (SHA256) to analyze.")

class GTIDeepAnalysisTool(BaseTool):
    name: str = "GTI Deep Analysis Tool"
    description: str = (
        "Performs deep malware analysis by retrieving detailed behavioral summaries for a file hash from Google Threat Intelligence."
    )
    args_schema: Type[BaseModel] = GTIDeepAnalysisInput
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

        def format_list(title, items):
            res = f"\n{title}:\n"
            if items:
                for item in items[:10]:
                    res += f"- {item}\n"
            else:
                res += "- None\n"
            return res

        response += format_list("Processes Created", data.get('processes_created', []))
        response += format_list("Files Opened", data.get('files_opened', []))
        response += format_list("Registry Keys Opened", data.get('registry_keys_opened', []))
        response += format_list("IP Traffic", [f"{ip['destination_ip']}:{ip['destination_port']}" for ip in data.get('ip_traffic', [])])
        response += format_list("HTTP/HTTPS Requests", data.get('http_conversations', []))
        response += format_list("DNS Lookups", [f"{lookup['hostname']}" for lookup in data.get('dns_lookups', [])])
        response += format_list("Files Written", data.get('files_written', []))
        response += format_list("Registry Keys Set", [f"{reg['key']}: {reg['value']}" for reg in data.get('registry_keys_set', [])])
        response += format_list("Mutexes Created", data.get('mutexes_created', []))
        response += format_list("Mutexes Opened", data.get('mutexes_opened', []))
        
        return response

    def _get_hash_behavior_summary(self, hash_value: str) -> str:
        """Get and format the behavior summary for a hash."""
        print(f"🔍 Getting behavior summary for hash: {hash_value}")
        behavior_url = f'https://www.virustotal.com/api/v3/files/{hash_value}/behaviour_summary'
        behavior_data = self._make_request(behavior_url)
        return self._format_behavior_summary(behavior_data)
