from crewai.tools import BaseTool
import requests
import os
import hashlib
import base64
from pydantic import BaseModel, Field
from typing import Type, Optional

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

class GTIURLToolInput(BaseModel):
    """Input model for the GTIURLTool."""
    action: str = Field(..., description="The action to perform. Must be one of 'get_report' or 'get_relationship'.")
    url: str = Field(..., description="The URL to investigate.")
    relationship_type: Optional[str] = Field(None, description="The type of relationship to fetch (e.g., 'downloaded_files', 'contacted_domains'). Required when action is 'get_relationship'.")

class GTIURLTool(BaseTool):
    name: str = "Google Threat Intelligence URL Tool"
    description: str = "Performs lookups for URLs and their relationships using Google Threat Intelligence. Use 'get_report' to get a summary of a URL, and 'get_relationship' to explore its connections."
    args_schema: Type[BaseModel] = GTIURLToolInput
    api_key: str = Field(default="", exclude=True)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = os.getenv('GTI_API_KEY') or os.getenv("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            raise ValueError("GTI API key not found. Please set GTI_API_KEY or VIRUSTOTAL_API_KEY environment variable.")

    def _get_url_id(self, url: str) -> str:
        """Generates the VirusTotal URL ID."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _run(self, action: str, url: str, relationship_type: Optional[str] = None) -> str:
        if action == 'get_report':
            return self._get_url_report(url)
        elif action == 'get_relationship':
            if not relationship_type:
                return "Error: 'relationship_type' is required when action is 'get_relationship'."
            return self._get_url_relationship(url, relationship_type)
        else:
            return "Error: Invalid action. Must be one of 'get_report' or 'get_relationship'."

    def _make_api_request(self, api_url: str, url_for_log: str) -> dict:
        """Handles the common logic for making an API request."""
        debug_manager = DebugManager()
        headers = {"x-apikey": self.api_key}
        debug_manager.log(f"GTIURLTool: Fetching from {api_url}")
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        return response.json()

    def _get_url_report(self, url: str) -> str:
        try:
            url_id = self._get_url_id(url)
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            data = self._make_api_request(api_url, url)
            if 'data' in data:
                return self._format_url_report(data['data'])
            else:
                return f"Error: 'data' key not found in response for URL {url}"
        except requests.exceptions.HTTPError as e:
            debug_manager = DebugManager()
            debug_manager.log(f"GTIURLTool: HTTP Error for URL report {url}: {e}")
            if e.response.status_code == 404:
                return f"URL not found in VirusTotal: {url}"
            return f"Error fetching URL report: {e}"
        except Exception as e:
            debug_manager = DebugManager()
            debug_manager.log(f"GTIURLTool: Unexpected error for URL report {url}: {e}")
            return f"An unexpected error occurred: {e}"

    def _get_url_relationship(self, url: str, relationship: str) -> str:
        try:
            url_id = self._get_url_id(url)
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}/{relationship}"
            data = self._make_api_request(api_url, url)
            if 'data' in data:
                if not data['data']:
                    return f"No '{relationship}' data found for URL: {url}"
                
                formatter = getattr(self, f"_format_{relationship}", self._format_default_relationship)
                return formatter(data['data'])
            else:
                 return f"Error: 'data' key not found in relationship response for URL {url}"
        except requests.exceptions.HTTPError as e:
            debug_manager = DebugManager()
            debug_manager.log(f"GTIURLTool: HTTP Error for relationship {relationship} on {url}: {e}")
            if e.response.status_code == 404:
                return f"Relationship '{relationship}' not found for URL: {url}"
            return f"Error fetching relationship '{relationship}': {e}"
        except Exception as e:
            debug_manager = DebugManager()
            debug_manager.log(f"GTIURLTool: Unexpected error for relationship {relationship} on {url}: {e}")
            return f"An unexpected error occurred: {e}"

    def _format_url_report(self, data: dict) -> str:
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        report_parts = [
            f"URL: {attributes.get('url', 'N/A')}",
            f"Verdict: {stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious, {stats.get('harmless', 0)} harmless",
            f"Reputation: {attributes.get('reputation', 'N/A')}",
            f"Times Submitted: {attributes.get('times_submitted', 'N/A')}",
            f"Last Final URL: {attributes.get('last_final_url', 'N/A')}",
        ]
        return "\n".join(report_parts)

    def _format_downloaded_files(self, data: list) -> str:
        report_parts = ["--- Downloaded Files ---"]
        for item in data[:10]: # Limit to 10 for brevity
            attrs = item.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            verdict = f"{stats.get('malicious', 0)}/{stats.get('suspicious', 0)}"
            report_parts.append(
                f"  - SHA256: {attrs.get('sha256', 'N/A')} | Verdict (M/S): {verdict} | Type: {attrs.get('type_description', 'N/A')} | Size: {attrs.get('size', 'N/A')}"
            )
        if len(data) > 10:
            report_parts.append(f"  ... and {len(data) - 10} more.")
        return "\n".join(report_parts)

    def _format_contacted_domains(self, data: list) -> str:
        report_parts = ["--- Contacted Domains ---"]
        for item in data[:10]:
            attrs = item.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            verdict = f"{stats.get('malicious', 0)}/{stats.get('suspicious', 0)}"
            report_parts.append(
                f"  - Domain: {item.get('id', 'N/A')} | Verdict (M/S): {verdict}"
            )
        if len(data) > 10:
            report_parts.append(f"  ... and {len(data) - 10} more.")
        return "\n".join(report_parts)

    def _format_contacted_ips(self, data: list) -> str:
        report_parts = ["--- Contacted IPs ---"]
        for item in data[:10]:
            attrs = item.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            verdict = f"{stats.get('malicious', 0)}/{stats.get('suspicious', 0)}"
            report_parts.append(
                f"  - IP: {item.get('id', 'N/A')} | Verdict (M/S): {verdict} | Country: {attrs.get('country', 'N/A')}"
            )
        if len(data) > 10:
            report_parts.append(f"  ... and {len(data) - 10} more.")
        return "\n".join(report_parts)

    def _format_default_relationship(self, data: list) -> str:
        report_parts = [f"--- Relationship Data (Generic) ---"]
        for item in data[:5]: # Limit to 5 for brevity
            report_parts.append(f"  - ID: {item.get('id', 'N/A')} | Type: {item.get('type', 'N/A')}")
        if len(data) > 5:
            report_parts.append(f"  ... and {len(data) - 5} more.")
        return "\n".join(report_parts)
