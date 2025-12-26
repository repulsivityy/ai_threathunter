from crewai.tools import BaseTool
from typing import Type, Dict, Any, List
from pydantic import BaseModel, Field, PrivateAttr
import requests
import os
import time

from ..core.models import BehavioralSummary

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
        "Returns a structured summary of malicious behaviors including network traffic, file operations, and process injections."
    )
    args_schema: Type[BaseModel] = GTIBehaviourAnalysisInput
    api_key: str = Field(default="", exclude=True)
    _cache: 'CacheManager' = PrivateAttr()
    _investigation_graph: Any = PrivateAttr(default=None)

    def __init__(self, api_key: str = None, investigation_graph = None):
        super().__init__()
        self.api_key = api_key or os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        self._investigation_graph = investigation_graph
        if not self.api_key:
            raise ValueError("GTI API key not found. Please set GTI_API_KEY or VIRUSTOTAL_API_KEY environment variable.")
            
        from ..utils.cache_manager import CacheManager
        self._cache = CacheManager()

    def _save_to_graph(self, result: BehavioralSummary):
        """Helper to save behavior to graph if available"""
        if self._investigation_graph:
            try:
                self._investigation_graph.add_behavior_summary(result)
            except Exception as e:
                print(f"    ⚠️ Failed to save behavior to investigation graph: {e}")

    def _run(self, hash: str) -> BehavioralSummary:
        """Execute the deep analysis."""
        try:
            print(f"🔍 GTI Deep Analysis: {hash}")
            result = self._get_hash_behavior_summary(hash)
            
            # Save to graph
            if result:
                self._save_to_graph(result)
                
                # Mark the hash as analyzed to prevent re-analysis
                if self._investigation_graph:
                    try:
                        self._investigation_graph.mark_node_analyzed(hash)
                    except Exception as e:
                        print(f"    ⚠️ Failed to mark node as analyzed: {e}")
                
            return result
        except Exception as error:
             print(f"❌ GTI deep analysis failed for {hash}: {str(error)}")
             return BehavioralSummary(hash=hash)

    def _make_request(self, url: str) -> Dict[str, Any]:
        """Make GTI API request with debug logging and caching."""
        
        # Check cache
        cache_key = f"gti_behavior_{url}"
        cached = self._cache.get(cache_key)
        if cached:
            print(f"⚡ Using cached behavior for {url}")
            return cached
            
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
            
            # Save to cache
            self._cache.set(cache_key, response_data)
            
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

    def _get_hash_behavior_summary(self, hash_value: str) -> BehavioralSummary:
        """Get and format the behavior summary for a hash."""
        behavior_url = f'https://www.virustotal.com/api/v3/files/{hash_value}/behaviour_summary'
        behavior_data = self._make_request(behavior_url)
        
        if not behavior_data or 'data' not in behavior_data:
            return BehavioralSummary(hash=hash_value)
            
        data = behavior_data['data']
        
        # Extract network IOCs
        network_iocs = []
        ip_traffic = []
        for ip in data.get('ip_traffic', []):
            if isinstance(ip, dict):
                 val = f"{ip.get('destination_ip', 'N/A')}:{ip.get('destination_port', 'N/A')}"
                 ip_traffic.append(val)
                 if ip.get('destination_ip'):
                     network_iocs.append({'type': 'ip', 'value': ip.get('destination_ip')})

        dns_lookups = []
        for lookup in data.get('dns_lookups', []):
            if isinstance(lookup, dict) and lookup.get('hostname'):
                dns_lookups.append(lookup.get('hostname'))
                network_iocs.append({'type': 'domain', 'value': lookup.get('hostname')})
                
        http_requests = []
        for req in data.get('http_conversations', []):
            if isinstance(req, dict) and req.get('url'):
                http_requests.append(req.get('url'))
                network_iocs.append({'type': 'url', 'value': req.get('url')})

        files_dropped = []
        for f in data.get('files_dropped', []):
            if isinstance(f, dict) and f.get('sha256'):
                files_dropped.append(f.get('sha256'))

        # Helper to safely extract registry strings
        registry_set = [f"{reg.get('key', 'N/A')}: {reg.get('value', 'N/A')}" for reg in data.get('registry_keys_set', []) if isinstance(reg, dict)]
        
        return BehavioralSummary(
            hash=hash_value,
            processes_created=data.get('processes_created', []),
            files_dropped=files_dropped,
            files_written=data.get('files_written', []),
            registry_keys_set=registry_set,
            dns_lookups=dns_lookups,
            ip_traffic=ip_traffic,
            http_requests=http_requests,
            command_executions=data.get('command_executions', []),
            process_injections=data.get('process_injections', []),
            network_iocs=network_iocs
        )