import networkx as nx
from typing import List, Dict, Optional, Any
from .models import InvestigationNode, GraphEdge, IOCType, RelationshipType, IOCAnalysisResult

class InvestigationGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.root_ioc = None

    def add_node(self, node: InvestigationNode):
        """Add a node to the graph"""
        if not self.root_ioc:
            self.root_ioc = node.id
            
        self.graph.add_node(node.id, 
                           type=node.type, 
                           data=node.data, 
                           behavior=node.behavior,
                           depth=node.depth,
                           created_at=node.created_at)

    def add_edge(self, edge: GraphEdge):
        """Add a relationship edge to the graph"""
        self.graph.add_edge(edge.source, edge.target, 
                           type=edge.type, 
                           description=edge.description,
                           timestamp=edge.timestamp)
    
    def get_node(self, ioc_value: str) -> Optional[Dict]:
        """Get node attributes"""
        if self.graph.has_node(ioc_value):
            return self.graph.nodes[ioc_value]
        return None

    def get_neighbors(self, ioc_value: str) -> List[str]:
        """Get connected IOCs"""
        if self.graph.has_node(ioc_value):
            return list(self.graph.neighbors(ioc_value))
        return []

    def get_summary(self) -> Dict[str, Any]:
        """Return a statistical summary of the graph"""
        return {
            "root_ioc": self.root_ioc,
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "nodes_by_type": self._count_nodes_by_type()
        }

    def _count_nodes_by_type(self) -> Dict[str, int]:
        counts = {}
        for _, attrs in self.graph.nodes(data=True):
            t = attrs.get('type')
            counts[t] = counts.get(t, 0) + 1
        return counts

    def export_graph_data(self) -> Dict[str, Any]:
        """Export graph for visualization or JSON dump"""
        return nx.node_link_data(self.graph)
