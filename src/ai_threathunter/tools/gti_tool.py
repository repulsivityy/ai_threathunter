from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional, List
from pydantic import BaseModel, Field, PrivateAttr
import requests
import base64
import json
import os
from datetime import datetime
import time

from ..core.models import IOCAnalysisResult, IOCType, Attribution
from ..utils.report_formatter import ReportFormatter

# Import the debug manager - but don't store as instance variable
try:
    from ..debug_manager import DebugManager
except ImportError:
    # Fallback if debug_manager doesn't exist
    class DebugManager:
        def __init__(self):
            self.debug_enabled = False
        def log_api_call(self, *args, **kwargs):
            pass

class GTIInput(BaseModel):
    """Input schema for Google Threat Intelligence IOC Analysis Tool."""
    ioc: str = Field(..., description="The IOC to analyze - IP address, domain, hash, or URL.")
    ioc_type: str = Field(..., description="Type of IOC: 'ip', 'domain', 'hash', or 'url'.")


class GTITool(BaseTool):
    name: str = "Google Threat Intelligence (GTI) Analyzer"
    description: str = (
        "Leverages the Google Threat Intelligence API to provide deep analysis of IOCs. This tool extracts "
        "advanced threat attribution, including associated threat actors, campaigns, and malware families, "
        "in addition to comprehensive behavioral and infrastructure data. It is the primary tool for "
        "understanding the strategic context of a threat."
    )
    args_schema: Type[BaseModel] = GTIInput
    api_key: str = Field(default="", exclude=True)
    _cache: Any = PrivateAttr()

    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        
        if not self.api_key:
            raise ValueError("GTI API key not found. Please set GTI_API_KEY or VIRUSTOTAL_API_KEY environment variable.")
            
        from ..utils.cache_manager import CacheManager
        self._cache = CacheManager()

    def _run(self, ioc: str, ioc_type: str) -> IOCAnalysisResult:
        """Execute focused GTI analysis."""
        try:
            print(f"🔍 GTI Analysis: {ioc} ({ioc_type})")
            
            if ioc_type == 'hash':
                return self._analyze_hash(ioc)
            elif ioc_type == 'ip':
                return self._analyze_ip(ioc)
            elif ioc_type == 'domain':
                return self._analyze_domain(ioc)
            elif ioc_type == 'url':
                return self._analyze_url(ioc)
            else:
                raise ValueError(f"Unsupported IOC type: {ioc_type}")
                
        except Exception as error:
            # Fallback for now, though ideally we raise or return a failure object
            print(f"❌ GTI analysis failed for {ioc}: {str(error)}")
            return IOCAnalysisResult(
                ioc=ioc, 
                ioc_type=IOCType(ioc_type) if ioc_type in ['ip', 'domain', 'url', 'hash', 'file'] else IOCType.FILE,
                description=f"Analysis failed: {str(error)}"
            )

    def _make_request(self, url: str) -> Dict[str, Any]:
        """Make GTI API request with caching and debug logging."""
        # Calculate cache key
        cache_key = f"gti_{url}"
        cached = self._cache.get(cache_key)
        if cached:
            print(f"⚡ Using cached result for {url}")
            return cached

        # Create debug manager locally
        debug_manager = DebugManager()
        
        start_time = time.time()
        error = None
        response_data = {}
        
        try:
            headers = {'x-apikey': self.api_key, 'x-tool': "multi_agent_threathunting"}
            
            # Log the request details
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
            
            # Log successful response
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI',
                    endpoint=url.replace('https://www.virustotal.com/api/v3/', ''),
                    request_data=request_info,
                    response_data={
                        'status_code': response.status_code,
                        'data': response_data
                    },
                    error=None,
                    execution_time=time.time() - start_time
                )
            
            return response_data
            
        except requests.exceptions.RequestException as e:
            error = e
            print(f"API request failed: {e}")
            
            # Log failed request
            if debug_manager.debug_enabled:
                debug_manager.log_api_call(
                    api_name='GTI',
                    endpoint=url.replace('https://www.virustotal.com/api/v3/', ''),
                    request_data=request_info if 'request_info' in locals() else {'url': url},
                    response_data={'error': str(e)},
                    error=error,
                    execution_time=time.time() - start_time
                )
            
            return {}

    def _extract_common_attributes(self, ioc: str, ioc_type: IOCType, attrs: Dict, stats: Dict) -> IOCAnalysisResult:
        """Extract attributes common to all IOCs"""
        
        # Calculate votes
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values()) if stats else 0
        
        # Extract verdict
        gti_assessment = attrs.get('gti_assessment', {})
        verdict = gti_assessment.get('verdict', {}).get('value', 'N/A')
        severity = gti_assessment.get('severity', {}).get('value', 'N/A')
        score = gti_assessment.get('threat_score', {}).get('value', 0)
        description = gti_assessment.get('description')
        
        # Extract Attributions
        attributions = []
        for actor in attrs.get('threat_actors', []):
            attributions.append(Attribution(
                name=actor.get('name'), 
                confidence=actor.get('confidence', 'N/A'),
                description=actor.get('description'),
                type='threat_actor'
            ))
        for camp in attrs.get('campaigns', []):
            attributions.append(Attribution(
                name=camp.get('name'), 
                confidence=camp.get('confidence', 'N/A'),
                description=camp.get('description'),
                type='campaign'
            ))
        for mal in attrs.get('malware', []):
            attributions.append(Attribution(
                name=mal.get('name'), 
                confidence=mal.get('confidence', 'N/A'),
                type='malware'
            ))
            
        return IOCAnalysisResult(
            ioc=ioc,
            ioc_type=ioc_type,
            verdict=verdict,
            severity=severity,
            score=score if score else 0,
            malicious_votes=malicious,
            suspicious_votes=suspicious,
            total_votes=total,
            description=description,
            attributions=attributions,
            tags=attrs.get('tags', []),
            raw_data=attrs
        )

    def _analyze_hash(self, hash_value: str) -> IOCAnalysisResult:
        """Analyze hash with GTI data."""
        primary = self._make_request(f'https://www.virustotal.com/api/v3/files/{hash_value}')
        if not primary or not primary.get('data'):
            raise ValueError(f"Hash {hash_value} not found in GTI")
        
        attrs = primary['data']['attributes']
        result = self._extract_common_attributes(hash_value, IOCType.FILE, attrs, attrs.get('last_analysis_stats', {}))
        
        # Add hash specific context
        if attrs.get('first_submission_date'):
            result.first_seen = datetime.fromtimestamp(attrs.get('first_submission_date'))
            
        return result

    def _analyze_ip(self, ip: str) -> IOCAnalysisResult:
        """Analyze IP with GTI data."""
        primary = self._make_request(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')
        if not primary or not primary.get('data'):
            raise ValueError(f"IP {ip} not found in GTI")
            
        attrs = primary['data']['attributes']
        result = self._extract_common_attributes(ip, IOCType.IP, attrs, attrs.get('last_analysis_stats', {}))
        
        # Add IP specific context
        result.tags.append(f"ASN: {attrs.get('asn', 'N/A')}")
        result.tags.append(f"Owner: {attrs.get('as_owner', 'N/A')}")
        result.tags.append(f"Country: {attrs.get('country', 'N/A')}")
        
        return result

    def _analyze_domain(self, domain: str) -> IOCAnalysisResult:
        """Analyze domain with GTI data."""
        primary = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}')
        if not primary or not primary.get('data'):
             raise ValueError(f"Domain {domain} not found in GTI")

        attrs = primary['data']['attributes']
        result = self._extract_common_attributes(domain, IOCType.DOMAIN, attrs, attrs.get('last_analysis_stats', {}))
        
        # Add Domain specific context
        if attrs.get('creation_date'):
            result.first_seen = datetime.fromtimestamp(attrs.get('creation_date'))
        result.tags.append(f"Registrar: {attrs.get('registrar', 'N/A')}")
        
        return result

    def _analyze_url(self, url: str) -> IOCAnalysisResult:
        """Analyze URL with GTI data."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        primary = self._make_request(f'https://www.virustotal.com/api/v3/urls/{url_id}')
        if not primary or not primary.get('data'):
             raise ValueError(f"URL {url} not found in GTI")

        attrs = primary['data']['attributes']
        result = self._extract_common_attributes(url, IOCType.URL, attrs, attrs.get('last_analysis_stats', {}))
        
        result.tags.append(f"Title: {attrs.get('title', 'N/A')}")
        
        return result