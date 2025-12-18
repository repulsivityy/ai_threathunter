from typing import Dict, Any, List
from datetime import datetime
from ..core.models import IOCAnalysisResult, BehavioralSummary, InvestigationNode, Attribution

class ReportFormatter:
    """Format structured data into human-readable Markdown reports"""

    @staticmethod
    def format_triage_report(data: IOCAnalysisResult) -> str:
        """Format IOCAnalysisResult into the Triage report format"""
        
        response = f"""
### IOC Threat Assessment: {data.ioc}

| Metric               | Value                                         |
| -------------------- | --------------------------------------------- |
| IOC Type             | {data.ioc_type.upper()}                       |
| GTI Verdict          | {data.verdict}                                |
| GTI Severity         | {data.severity}                               |
| Detection Ratio      | {data.malicious_votes}/{data.total_votes}     |
| Threat Names         | {', '.join([a.name for a in data.attributions if a.type == 'malware'][:3]) or 'N/A'} |
| Associations         | {', '.join([a.name for a in data.attributions if a.type != 'malware'][:3]) or 'N/A'} |
| Key Context          | {data.description[:100] + '...' if data.description else 'N/A'} |

## List of high-significant discoveries that requires specialist analysis
- {data.verdict} Verdict with score {data.score}/100
- {len(data.attributions)} attribution(s) found.

## Investigation foundation context for follow-on specialist analysis

---
**Verdict:** **{data.verdict}**
**Justification:** {data.description or 'No description provided.'}
**Recommended Action:** **{'Hand off to Malware Analysis Agent' if data.ioc_type == 'file' and data.malicious_votes > 0 else 'Hand off to Infrastructure Analysis Agent' if data.malicious_votes > 0 else 'Close Alert'}**
"""
        return response

    @staticmethod
    def format_behavior_report(result: BehavioralSummary) -> str:
        """Format BehavioralSummary into markdown"""
        
        def format_list(title, items, limit=None):
            if not items: return ""
            res = f"\n**{title}:**\n"
            for i, item in enumerate(items):
                if limit and i >= limit:
                    res += f"- ... and {len(items) - limit} more\n"
                    break
                res += f"- {item}\n"
            return res

        response = f"### Deep Malware Behavioral Analysis Report\n\n"
        response += f"- **Analyzed Hash**: {result.hash}\n\n"
        
        response += "--- \n**Key Behavioral Findings**:\n"
        response += format_list("Processes Created", result.processes_created, limit=10)
        response += format_list("Command Executions", result.command_executions, limit=10)
        response += format_list("Network Traffic", result.ip_traffic + result.dns_lookups + result.http_requests, limit=15)
        response += format_list("Files Dropped", result.files_dropped, limit=10)
        
        return response

    @staticmethod
    def format_attribution(attributions: List[Attribution]) -> str:
        if not attributions: return ""
        response = "\n**Attribution:**\n"
        for attr in attributions:
            response += f"- {attr.name} ({attr.type}) - Confidence: {attr.confidence}\n"
        return response
