from crewai.tools import BaseTool
from typing import Type, Dict, Any
from pydantic import BaseModel, Field
import requests
import os
import time

class GTIIpAddressToolInput(BaseModel):
    """Input schema for the GTI IP Address Tool."""
    ip_address: str = Field(..., description="The IP address to analyze.")
    relationship: str = Field("report", description="The relationship to query. Allowed values are 'report', 'communicating_files', 'downloaded_files', 'graphs', 'historical_whois', 'resolutions', 'urls'.")

class GTIIpAddressTool(BaseTool):
    name: str = "GTI IP Address Tool"
    description: str = (
        "Performs infrastructure analysis by retrieving detailed reports and relationships for an IP address from Google Threat Intelligence."
    )
    args_schema: Type[BaseModel] = GTIIpAddressToolInput
    api_key: str = Field(default="", exclude=True)

    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            raise ValueError("GTI API key not found. Please set GTI_API_KEY or VIRUSTOTAL_API_KEY environment variable.")

    def _run(self, ip_address: str, relationship: str = "report") -> str:
        """Execute the analysis."""
        try:
            print(f"🔍 GTI IP Address Analysis: {ip_address}, Relationship: {relationship}")
            if relationship == "report":
                return self._get_ip_address_report(ip_address)
            else:
                return self._get_ip_address_relationship(ip_address, relationship)
        except Exception as error:
            return f"GTI IP address analysis failed for {ip_address}: {str(error)}"

    def _make_request(self, url: str) -> str:
        """Make GTI API request."""
        headers = {
            'x-apikey': self.api_key,
            'x-tool': "multi_agent_threathunting"
        }
        try:
            response = requests.get(url, headers=headers, timeout=20)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            return f"An error occurred: {e}"

    def _get_ip_address_report(self, ip_address: str) -> str:
        """Get the report for an IP address."""
        print(f"🔍 Getting report for IP address: {ip_address}")
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        return self._make_request(url)

    def _get_ip_address_relationship(self, ip_address: str, relationship: str) -> str:
        """Get a specific relationship for an IP address."""
        print(f"🔍 Getting {relationship} for IP address: {ip_address}")
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/{relationship}'
        return self._make_request(url)