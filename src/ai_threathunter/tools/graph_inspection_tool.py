from crewai.tools import BaseTool
from typing import Type, Dict, Any, List, Optional
from pydantic import BaseModel, Field, PrivateAttr

class GraphInspectionInput(BaseModel):
    """Input for graph inspection."""
    query_type: str = Field(..., description="Type of query: 'summary' (stats), 'node_details' (specific IOC), 'neighbors' (connections), 'full_context' (all nodes).")
    ioc: Optional[str] = Field(default=None, description="IOC to query if query_type is 'node_details' or 'neighbors'. Optional for 'summary' and 'full_context'.")

class GraphInspectionTool(BaseTool):
    name: str = "Investigation Graph Inspector"
    description: str = (
        "Allows you to inspect the current state of the investigation graph. "
        "Use this to understand what has been found so far, identify gaps, and "
        "synthesize the final intelligence report. You can get a high-level summary, "
        "details on specific nodes, or trace connections."
    )
    args_schema: Type[BaseModel] = GraphInspectionInput
    _investigation_graph: Any = PrivateAttr()

    def __init__(self, investigation_graph):
        super().__init__()
        self._investigation_graph = investigation_graph

    def _run(self, query_type: str, ioc: str = None) -> Dict[str, Any]:
        """Execute graph inspection."""
        try:
            if not self._investigation_graph:
                return {"error": "Graph not initialized"}

            if query_type == "summary":
                summary = self._investigation_graph.get_summary()
                
                # Add human-readable analysis gaps for the Orchestrator
                gaps = []
                if summary.get('unanalyzed_hashes'):
                    gaps.append(f"{len(summary['unanalyzed_hashes'])} hashes need behavioral analysis: {', '.join(summary['unanalyzed_hashes'][:3])}...")
                if summary.get('unanalyzed_ips'):
                    gaps.append(f"{len(summary['unanalyzed_ips'])} IPs need infrastructure analysis: {', '.join(summary['unanalyzed_ips'][:3])}...")
                if summary.get('unanalyzed_domains'):
                    gaps.append(f"{len(summary['unanalyzed_domains'])} Domains need infrastructure analysis: {', '.join(summary['unanalyzed_domains'][:3])}...")
                
                summary['analysis_gaps'] = gaps
                return summary
            
            elif query_type == "node_details":
                if not ioc:
                    return {"error": "IOC required for node_details"}
                node = self._investigation_graph.get_node(ioc)
                if node:
                    # Convert to dict for JSON serialization if needed, or just return the dict
                    # The graph stores attributes in the node dict
                    return node
                return {"error": f"Node {ioc} not found"}
            
            elif query_type == "neighbors":
                if not ioc:
                    return {"error": "IOC required for neighbors"}
                neighbors = self._investigation_graph.get_neighbors(ioc)
                return {"ioc": ioc, "neighbors": neighbors}
            
            elif query_type == "full_context":
                # Be careful with size, but for now dump the simple graph data
                data = self._investigation_graph.export_graph_data()
                # Simplify for LLM consumption - list nodes and edges textually
                nodes = []
                for node in data['nodes']:
                    nodes.append(f"{node['id']} ({node.get('type')})")
                edges = []
                for edge in data['links']:
                    desc = f": {edge.get('description')}" if edge.get('description') else ""
                    edges.append(f"{edge['source']} -> {edge['target']} ({edge.get('type')}){desc}")
                
                return {
                    "summary": self._investigation_graph.get_summary(),
                    "nodes_list": nodes,
                    "edges_list": edges,
                    # "raw_data": data # Omit raw big data to save tokens
                }

            else:
                return {"error": f"Unknown query type: {query_type}"}

        except Exception as e:
            return {"error": str(e)}
