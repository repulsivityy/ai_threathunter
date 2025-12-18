"""Utility functions for report generation and management"""

from pathlib import Path
from typing import Optional


def append_graph_to_report(
    investigation_graph,
    report_path: str = 'reports/final_intelligence_report.md'
) -> bool:
    """
    Append Mermaid graph visualization to the final intelligence report.
    
    Args:
        investigation_graph: InvestigationGraph instance containing the graph state
        report_path: Path to the report file (default: reports/final_intelligence_report.md)
    
    Returns:
        True if successful, False otherwise
    """
    try:
        mermaid_graph = investigation_graph.to_mermaid()
        
        # Ensure directory exists
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'a') as f:
            f.write("\n\n## Investigation Graph Visualization\n")
            f.write("```mermaid\n")
            f.write(mermaid_graph)
            f.write("\n```\n")
        
        print(f"📊 Graph visualization appended to {report_path}")
        return True
        
    except FileNotFoundError as e:
        print(f"❌ Report file not found: {e}. Ensure the crew completed successfully.")
        return False
    except PermissionError as e:
        print(f"❌ Permission denied when writing graph: {e}")
        return False
    except Exception as e:
        print(f"⚠️ Unexpected error appending graph: {e}")
        return False
