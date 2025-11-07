from crewai.tools import BaseTool
from typing import Type, Dict, Any, Optional, List
from pydantic import BaseModel, Field
import requests
import base64
import json
import os
from datetime import datetime
import time

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

    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        
        if not self.api_key:
            raise ValueError("GTI API key not found. Please set GTI_API_KEY or VIRUSTOTAL_API_KEY environment variable.")

    def _run(self, ioc: str, ioc_type: str) -> str:
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
                return f"Unsupported IOC type: {ioc_type}"
                
        except Exception as error:
            return f"GTI analysis failed for {ioc}: {str(error)}"

    def _make_request(self, url: str) -> Dict[str, Any]:
        """Make GTI API request with debug logging."""
        # Create debug manager locally - not as instance variable
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

    def _format_attribution_details(self, attrs: Dict) -> str:
        """Formats the GTI-specific threat attribution details."""
        response = "\n\n=== GOOGLE THREAT INTELLIGENCE ATTRIBUTION ===\n"
        threat_actors = attrs.get('threat_actors', [])
        campaigns = attrs.get('campaigns', [])
        malware_families = attrs.get('malware', [])

        if not threat_actors and not campaigns and not malware_families:
            return response + "No specific threat attribution data found.\n"

        if threat_actors:
            response += f"\nTHREAT ACTORS ({len(threat_actors)} found):\n"
            for actor in threat_actors[:3]:
                actor_name = actor.get('name', 'N/A')
                confidence = actor.get('confidence', 'N/A')
                description = actor.get('description', 'No description available.')
                response += f"- {actor_name} (Confidence: {confidence})\n"
                response += f"  Description: {description[:150]}...\n"
        
        if campaigns:
            response += f"\nCAMPAIGNS ({len(campaigns)} found):\n"
            for campaign in campaigns[:3]:
                campaign_name = campaign.get('name', 'N/A')
                confidence = campaign.get('confidence', 'N/A')
                description = campaign.get('description', 'No description available.')
                response += f"- {campaign_name} (Confidence: {confidence})\n"
                response += f"  Description: {description[:150]}...\n"

        if malware_families:
            response += f"\nASSOCIATED MALWARE FAMILIES ({len(malware_families)} found):\n"
            for malware in malware_families[:5]:
                malware_name = malware.get('name', 'N/A')
                confidence = malware.get('confidence', 'N/A')
                response += f"- {malware_name} (Confidence: {confidence})\n"
        
        return response

    def _format_gti_assessment(self, attrs: Dict) -> str:
        """Formats the GTI Assessment block."""
        gti_assessment = attrs.get('gti_assessment')
        if not gti_assessment:
            return ''
        
        response = "\n\n=== GTI ASSESSMENT ===\n"
        verdict = gti_assessment.get('verdict', {}).get('value', 'N/A')
        severity = gti_assessment.get('severity', {}).get('value', 'N/A')
        threat_score = gti_assessment.get('threat_score', {}).get('value', 'N/A')
        description = gti_assessment.get('description', 'No description available.')

        response += f"- Verdict: {verdict}\n"
        response += f"- Severity: {severity}\n"
        response += f"- Threat Score: {threat_score}/100\n"
        response += f"- Description: {description}\n"
        return response

    def _format_threat_classification(self, attrs: Dict) -> str:
        """Formats the Popular Threat Classification block."""
        threat_class = attrs.get('popular_threat_classification')
        if not threat_class:
            return ''

        response = "\n\n=== POPULAR THREAT CLASSIFICATION ===\n"
        label = threat_class.get('suggested_threat_label', 'N/A')
        response += f"- Suggested Label: {label}\n"

        if threat_class.get('popular_threat_name'):
            response += "- Popular Names:\n"
            for name in threat_class['popular_threat_name'][:5]:
                response += f"  - {name.get('value')} ({name.get('count')} votes)\n"

        if threat_class.get('popular_threat_category'):
            response += "- Popular Categories:\n"
            for cat in threat_class['popular_threat_category'][:5]:
                response += f"  - {cat.get('value')} ({cat.get('count')} votes)\n"
        return response

    def _format_yara_results(self, attrs: Dict) -> str:
        """Formats the Crowdsourced YARA results."""
        yara_results = attrs.get('crowdsourced_yara_results')
        if not yara_results:
            return ''

        response = "\n\n=== CROWDSOURCED YARA RULES ===\n"
        for result in yara_results[:3]:
            response += f"- Rule: {result.get('rule_name', 'N/A')}\n"
            response += f"  Author: {result.get('author', 'N/A')}\n"
            response += f"  Source: {result.get('source', 'N/A')}\n"
            response += f"  Description: {result.get('description', 'N/A')}\n\n"
        return response

    def _analyze_hash(self, hash_value: str) -> str:
        """Analyze hash with GTI data."""
        print(f"🔍 Analyzing hash with GTI: {hash_value}")
        primary = self._make_request(f'https://www.virustotal.com/api/v3/files/{hash_value}')

        if not primary or not primary.get('data'):
            return f"Hash {hash_value} not found in GTI"
        
        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})
        pe_info = attrs.get('pe_info', {})
        
        response = f"""
=== GTI ANALYSIS: HASH ===
IOC: {hash_value}
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Undetected: {stats.get('undetected', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

FILE DETAILS:
- Names: {', '.join(attrs.get('names', ['N/A'])[:5])}
- Type: {attrs.get('type_description', 'N/A')}
- Size: {attrs.get('size', 'N/A')} bytes
- First Seen: {datetime.fromtimestamp(attrs.get('first_submission_date', 0)).strftime('%Y-%m-%d') if attrs.get('first_submission_date') else 'N/A'}
- Imphash: {pe_info.get('imphash', 'N/A')}
"""
        response += self._format_gti_assessment(attrs)
        response += self._format_threat_classification(attrs)
        response += self._format_attribution_details(attrs)
        response += self._format_yara_results(attrs)
        response += f"\nSource: https://www.virustotal.com/gui/file/{hash_value}"
        return response

    def _analyze_ip(self, ip: str) -> str:
        """Analyze IP with GTI data."""
        print(f"🔍 Analyzing IP with GTI: {ip}")
        primary = self._make_request(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')
        if not primary or not primary.get('data'):
            return f"IP {ip} not found in GTI"
            
        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})

        response = f"""
=== GTI ANALYSIS: IP ADDRESS ===
IOC: {ip}
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

INFRASTRUCTURE DETAILS:
- AS Owner: {attrs.get('as_owner', 'N/A')}
- ASN: {attrs.get('asn', 'N/A')}
- Country: {attrs.get('country', 'N/A')}
"""
        response += self._format_attribution_details(attrs)
        response += f"\nSource: https://www.virustotal.com/gui/ip-address/{ip}"
        return response

    def _analyze_domain(self, domain: str) -> str:
        """Analyze domain with GTI data."""
        print(f"🔍 Analyzing domain with GTI: {domain}")
        primary = self._make_request(f'https://www.virustotal.com/api/v3/domains/{domain}')
        if not primary or not primary.get('data'):
            return f"Domain {domain} not found in GTI"

        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})

        response = f"""
=== GTI ANALYSIS: DOMAIN ===
IOC: {domain}
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

DOMAIN DETAILS:
- Registrar: {attrs.get('registrar', 'N/A')}
- Creation Date: {datetime.fromtimestamp(attrs.get('creation_date', 0)).strftime('%Y-%m-%d') if attrs.get('creation_date') else 'N/A'}
- Categories: {', '.join(list(attrs.get('categories', {}).values())[:3]) if attrs.get('categories') else 'N/A'}
"""
        response += self._format_attribution_details(attrs)
        response += f"\nSource: https://www.virustotal.com/gui/domain/{domain}"
        return response

    def _analyze_url(self, url: str) -> str:
        """Analyze URL with GTI data."""
        print(f"🔍 Analyzing URL with GTI: {url}")
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        primary = self._make_request(f'https://www.virustotal.com/api/v3/urls/{url_id}')
        if not primary or not primary.get('data'):
            return f"URL {url} not found in GTI"

        attrs = primary['data']['attributes']
        stats = attrs.get('last_analysis_stats', {})

        response = f"""
=== GTI ANALYSIS: URL ===
IOC: {url}
Analysis Date: {datetime.now().isoformat()}

DETECTION SUMMARY:
- Malicious: {stats.get('malicious', 0)}
- Suspicious: {stats.get('suspicious', 0)}
- Total Engines: {sum(stats.values()) if stats else 0}

URL DETAILS:
- Final URL: {attrs.get('url', 'N/A')}
- Title: {attrs.get('title', 'N/A')}
"""
        response += self._format_attribution_details(attrs)
        response += f"\nSource: https://www.virustotal.com/gui/url/{url_id}"
        return response