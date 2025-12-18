from typing import List, Dict, Optional, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    FILE = "file" # Alias for hash in some contexts

class AnalysisStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"

class Attribution(BaseModel):
    name: str
    confidence: str = "N/A"
    description: Optional[str] = None
    type: str = "threat_actor" # threat_actor, campaign, malware

class IOCAnalysisResult(BaseModel):
    """Standardized output for minimal IOC analysis"""
    ioc: str
    ioc_type: IOCType
    verdict: str = "N/A"
    severity: str = "N/A"
    score: int = 0
    malicious_votes: int = 0
    suspicious_votes: int = 0
    total_votes: int = 0
    description: Optional[str] = None
    
    # Context
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    # Enrichment
    tags: List[str] = []
    attributions: List[Attribution] = []
    
    # Raw data for fallback
    raw_data: Optional[Dict[str, Any]] = Field(default=None, exclude=True)

class BehavioralSummary(BaseModel):
    """Structured output for malware behavioral analysis"""
    hash: str
    processes_created: List[str] = []
    files_dropped: List[str] = [] # Hashes
    files_written: List[str] = [] # Paths
    registry_keys_set: List[str] = []
    dns_lookups: List[str] = []
    ip_traffic: List[str] = [] # list of ip:port
    http_requests: List[str] = [] # URLs
    
    command_executions: List[str] = []
    process_injections: List[str] = []
    
    # Network IOCs extracted from behavior
    network_iocs: List[Dict[str, str]] = [] # [{'type': 'ip', 'value': '1.2.3.4'}]

class InvestigationNode(BaseModel):
    """Node in the investigation graph"""
    id: str  # The IOC value
    type: IOCType
    data: Optional[IOCAnalysisResult] = None
    behavior: Optional[BehavioralSummary] = None
    depth: int = 0
    created_at: datetime = Field(default_factory=datetime.now)

class RelationshipType(str, Enum):
    RESOLVES_TO = "RESOLVES_TO" # Domain -> IP
    HOSTED_ON = "HOSTED_ON" # URL -> IP/Domain
    DROPPED = "DROPPED" # File -> File
    COMMUNICATES_WITH = "COMMUNICATES_WITH" # File -> IP/Domain/URL
    DOWNLOADED_FROM = "DOWNLOADED_FROM" # File -> URL
    ASSOCIATED_WITH = "ASSOCIATED_WITH" # Generic

class GraphEdge(BaseModel):
    source: str
    target: str
    type: RelationshipType
    description: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
