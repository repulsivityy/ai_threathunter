from crewai.tools import BaseTool
from typing import Type, Dict, Any
from pydantic import BaseModel, Field
import requests
import os
import time

class GTIDomainToolInput(BaseModel):
    """Input schema for the GTI Domain Tool."""
    domain: str = Field(..., description="The domain to analyze.")
    relationship: str = Field("report", description="The relationship to query. 'report' by default")

class GTIDomainTool(BaseTool):
    name: str = "GTI Domain Tool"
    description: str = (
        "Performs infrastructure analysis by retrieving detailed reports and relationships for a domain from Google Threat Intelligence."
    )
    args_schema: Type[BaseModel] = GTIDomainToolInput
    api_key: str = Field(default="", exclude=True)

    def __init__(self, api_key: str = None):
        super().__init__()
        self.api_key = api_key or os.getenv('GTI_API_KEY') or os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            raise ValueError("GTI API key not found. Please set GTI_API_KEY or VIRUSTOTAL_API_KEY environment variable.")

    def _run(self, domain: str, relationship: str = "report") -> str:
        """Execute the analysis."""
        try:
            print(f"🔍 GTI Domain Analysis: {domain}, Relationship: {relationship}")
            if relationship == "report":
                return self._get_domain_report(domain)
            else:
                return self._get_domain_relationship(domain, relationship)
        except Exception as error:
            return f"GTI domain analysis failed for {domain}: {str(error)}"

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

    def _get_domain_report(self, domain: str) -> str:
        """Get the report for a domain."""
        print(f"🔍 Getting report for domain: {domain}")
        url = f'https://www.virustotal.com/api/v3/domains/{domain}'
        return self._make_request(url)

    def _get_domain_relationship(self, domain: str, relationship: str) -> str:
        """Get a specific relationship for a domain."""
        print(f"🔍 Getting {relationship} for domain: {domain}")
        url = f'https://www.virustotal.com/api/v3/domains/{domain}/{relationship}'
        return self._make_request(url)