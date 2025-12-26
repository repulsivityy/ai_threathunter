from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional, List
from urllib.parse import urlparse
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

# ============================================================================
# RATE LIMITER (CURRENTLY DISABLED)
# ============================================================================
# The rate limiter below is commented out because our current GTI license
# includes very high rate limits. However, this code is preserved for:
# 1. Future license changes that may require rate limiting
# 2. Reuse in other tools with stricter API quotas
# 
# To enable: Uncomment the class and the two lines in GTITool.__init__ and _make_request
# ============================================================================
# import threading
# 
# class RateLimiter:
#     """Simple rate limiter to prevent API quota exhaustion"""
#     def __init__(self, calls_per_minute=4):
#         self.calls_per_minute = calls_per_minute
#         self.lock = threading.Lock()
#         self.last_call = 0
#     
#     def wait_if_needed(self):
#         with self.lock:
#             now = time.time()
#             time_since_last = now - self.last_call
#             min_interval = 60.0 / self.calls_per_minute
#             if time_since_last < min_interval:
#                 time.sleep(min_interval - time_since_last)
#             self.last_call = time.time()
# ============================================================================

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
        
        # Rate limiter disabled - current GTI license has high limits
        # Uncomment if needed: self._rate_limiter = RateLimiter(calls_per_minute=50)

    def _save_to_graph(self, result: IOCAnalysisResult):
        """Helper to save result to graph if available"""
        if self._investigation_graph:
            try:
                self._investigation_graph.add_analysis_result(result)
            except (AttributeError, KeyError, ValueError) as e:
                print(f"    ⚠️ Failed to save to investigation graph: {e}")
            except Exception as e:
                # Unexpected error - log and re-raise for debugging
                print(f"    ❌ Unexpected error saving to graph: {e}")
                raise

    def _run(self, ioc: str, ioc_type: str) -> IOCAnalysisResult:
        """Execute focused GTI analysis."""
        try:
            print(f"🔍 GTI Analysis: {ioc} ({ioc_type})")
            
            result = None
            if ioc_type == 'hash':
                result = self._analyze_hash(ioc)
            elif ioc_type == 'ip':
                result = self._analyze_ip(ioc)
            elif ioc_type == 'domain':
                result = self._analyze_domain(ioc)
            elif ioc_type == 'url':
                result = self._analyze_url(ioc)
            else:
                raise ValueError(f"Unsupported IOC type: {ioc_type}")
            
            # Save to graph
            if result:
                self._save_to_graph(result)
                
                # Mark node as analyzed
                if self._investigation_graph:
                    try:
                        self._investigation_graph.mark_node_analyzed(ioc)
                    except (AttributeError, KeyError) as e:
                        print(f"    ⚠️ Failed to mark node as analyzed: {e}")

            return result
                
        except Exception as error:
            # Fallback for now, though ideally we raise or return a failure object
            print(f"❌ GTI analysis failed for {ioc}: {str(error)}")
            # Try to return partial results if possible, or a basic error object
            return IOCAnalysisResult(
                ioc=ioc, 
                ioc_type=IOCType(ioc_type) if ioc_type in ['ip', 'domain', 'url', 'hash', 'file'] else IOCType.FILE,
                description=f"Analysis failed: {str(error)}"
            )

    def _enrich_ioc_data(self, ioc: str, ioc_type: str) -> List[Attribution]:
        """
        Enrich IOC data by fetching associations (Campaigns, Threat Actors).
        
        Args:
            ioc: The IOC value (e.g., hash, IP, domain).
            ioc_type: The type of IOC ('files', 'ip_addresses', 'domains', 'urls').
            
        Returns:
            List of Attribution objects found in the associations.
        """
        attributions = []
        try:
            # Construct endpoint URL - using the user-specified '/associations' path
            # Note: For URLs, we need the base64 encoded ID which is passed in as 'ioc' for _analyze_url but not others
            # For _analyze_url, 'ioc' arg is the original URL string, but we need the ID.
            # However, this helper is called by _analyze_X methods.
            # _analyze_hash passes raw hash -> ioc_type='files'
            # _analyze_ip passes raw IP -> ioc_type='ip_addresses'
            # _analyze_domain passes raw domain -> ioc_type='domains'
            # _analyze_url will handle the ID conversion before calling this or pass the ID.
            # Let's standardize: pass the API-ready ID/Value as 'ioc'.

            url = f"https://www.virustotal.com/api/v3/{ioc_type}/{ioc}/associations"
            print(f"    🔎 Fetching associations for enrichment: {url}")
            
            response = self._make_request(url)
            
            if not response or 'data' not in response:
                print(f"    ⚠️ No association data found for {ioc}")
                return attributions

            # Parse the response data
            # Expecting a list of objects in 'data'
            for item in response.get('data', []):
                item_type = item.get('type')
                attrs = item.get('attributes', {})
                
                # Check for Campaigns (type: 'collection' or 'campaign')
                # The demo file shows type: "collection" with id starting with "campaign--"
                # we also support "campaign" type if API returns it.
                if item_type in ['collection', 'campaign'] or (item_type == 'collection' and 'campaign' in item.get('id', '')):
                    name = attrs.get('name')
                    if name:
                        attributions.append(Attribution(
                            name=name,
                            type='campaign',
                            description=attrs.get('description'),
                            confidence='high' # Inferred high confidence if linked by GTI
                        ))
                
                # Check for Threat Actors
                elif item_type == 'threat_actor':
                    name = attrs.get('name')
                    if name:
                        attributions.append(Attribution(
                            name=name,
                            type='threat_actor',
                            description=attrs.get('description'),
                            confidence='high'
                        ))

            print(f"    ✅ Found {len(attributions)} enriched attributions")

        except Exception as e:
            print(f"    ⚠️ Enrichment fetch failed: {e}")
        
        return attributions

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
        
        # Rate limiter disabled - uncomment if needed: self._rate_limiter.wait_if_needed()
        
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
        # [MODIFIED] Build Rich Description with Critical Signals
        base_desc = gti_assessment.get('description', 'No description available.')
        
        # Extract signals
        gti_confidence = gti_assessment.get('contributing_factors', {}).get('gti_confidence_score', 'N/A')
        sandbox_verdicts = attrs.get('sandbox_verdicts', {})
        malicious_sandboxes = [name for name, v in sandbox_verdicts.items() if v.get('category') == 'malicious']
        threat_label = attrs.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A')
        
        # Build description with Detection Ratio
        description = (
            f"{base_desc}\n\n"
            f"--- CRITICAL SIGNALS FOR TRIAGE ---\n"
            f"• GTI Confidence Score: {gti_confidence}/100\n"
            f"• Detection Ratio: {malicious}/{total} (Suspicious: {suspicious})\n"
            f"• Malicious Sandbox Executions: {', '.join(malicious_sandboxes) if malicious_sandboxes else 'None'}\n"
            f"• Suggested Threat Label: {threat_label}\n"
            f"-----------------------------------"
        )
        
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
        
        # [MODIFIED] Enrich with Campaigns/Associations
        enriched_attributions = self._enrich_ioc_data(hash_value, 'files')
        result.attributions.extend(enriched_attributions)
        
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
        
        # [MODIFIED] Enrich with Campaigns/Associations
        enriched_attributions = self._enrich_ioc_data(ip, 'ip_addresses')
        result.attributions.extend(enriched_attributions)
        
        # Note: IPs don't have explicit "resolves to" relationships in GTI
        # but could have "hosted domains" - we'd need to query /resolutions endpoint
        # For now, we'll leave IP relationships for when domains point to them
        
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

        # [MODIFIED] Enrich with Campaigns/Associations
        enriched_attributions = self._enrich_ioc_data(domain, 'domains')
        result.attributions.extend(enriched_attributions)
        
        # Extract relationships (DNS resolutions)
        last_dns_records = attrs.get('last_dns_records', [])
        for record in last_dns_records:
            if record.get('type') == 'A':  # IPv4 resolution
                ip_value = record.get('value')
                if ip_value:
                    result.related_iocs.append({
                        'type': 'ip',
                        'value': ip_value,
                        'relationship': 'RESOLVES_TO',
                        'description': f"Domain {domain} resolves to IP {ip_value}"
                    })
        
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
        
        # [MODIFIED] Enrich with Campaigns/Associations
        # Note: url_id is used for the API call
        enriched_attributions = self._enrich_ioc_data(url_id, 'urls')
        result.attributions.extend(enriched_attributions)
        
        # Extract host/domain relationship from URL
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname:
                result.related_iocs.append({
                    'type': 'domain',
                    'value': parsed.hostname,
                    'relationship': 'HOSTED_ON',
                    'description': f"URL {url} is hosted on domain {parsed.hostname}"
                })
        except Exception:
            pass
        
        result.tags.append(f"Title: {attrs.get('title', 'N/A')}")
        
        return result