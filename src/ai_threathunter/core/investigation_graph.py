import networkx as nx
from typing import List, Dict, Optional, Any
from .models import InvestigationNode, GraphEdge, IOCType, RelationshipType, IOCAnalysisResult, BehavioralSummary
from datetime import datetime

class InvestigationGraph:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.root_ioc = None

    def add_behavior_summary(self, summary: BehavioralSummary):
        """
        Ingest a BehavioralSummary into the graph.
        """
        # We need to find the node or create it.
        # Since behavior is for a File/Hash, type is FILE/HASH.
        
        # Check if node exists
        if self.graph.has_node(summary.hash):
            # Update existing node
            self.graph.nodes[summary.hash]['behavior'] = summary
        else:
            # Create new node
            # We might not have IOCAnalysisResult yet, so just create with ID and Type
            node = InvestigationNode(
                id=summary.hash,
                type=IOCType.FILE, # Behavior is typically for files
                behavior=summary
            )
            self.add_node(node)
            
        print(f"    🕸️  Graph Update: Added behavior for {summary.hash}")
        
        # Add edges for network IOCs found in behavior
        for ioc in summary.network_iocs:
            target_value = ioc.get('value')
            target_type = ioc.get('type')
            description = ioc.get('description', f"Network connection observed during behavior analysis of {summary.hash}")
            
            if target_value and target_type:
                # Add the target node if it doesn't exist (lightweight)
                if not self.graph.has_node(target_value):
                    self.graph.add_node(target_value, type=target_type)
                
                # Add edge
                self.graph.add_edge(summary.hash, target_value, 
                                   type=RelationshipType.COMMUNICATES_WITH,
                                   description=description,
                                   timestamp=datetime.now())
                print(f"    🕸️  Graph Edge: {summary.hash} --[COMMUNICATES_WITH]--> {target_value} ({description})")
        
        # Add edges for dropped files
        for dropped_hash in summary.files_dropped:
             if not self.graph.has_node(dropped_hash):
                 self.graph.add_node(dropped_hash, type=IOCType.FILE)
             
             description = f"File dropped by {summary.hash} during execution"
             self.graph.add_edge(summary.hash, dropped_hash,
                                type=RelationshipType.DROPPED,
                                description=description,
                                timestamp=datetime.now())
             print(f"    🕸️  Graph Edge: {summary.hash} --[DROPPED]--> {dropped_hash} ({description})")

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
        # Check if edge exists and skip if identical
        if self.graph.has_edge(edge.source, edge.target):
            existing = self.graph[edge.source][edge.target]
            if existing.get('type') == edge.type:
                print(f"   ⚠️  Duplicate edge skipped: {edge.source} --[{edge.type}]--> {edge.target}")
                return
        
        self.graph.add_edge(edge.source, edge.target, 
                           type=edge.type, 
                           description=edge.description,
                           timestamp=edge.timestamp)

    def add_analysis_result(self, result: IOCAnalysisResult):
        """
        Ingest an IOCAnalysisResult into the graph as a Node and potentially Edges.
        This allows tools to automatically populate the graph.
        """
        # Create/Update the node for the main IOC
        node = InvestigationNode(
            id=result.ioc,
            type=result.ioc_type,
            data=result
        )
        self.add_node(node)
        
        # Create edges from related_iocs
        for related in result.related_iocs:
            target_value = related.get('value')
            target_type = related.get('type')
            relationship = related.get('relationship', 'ASSOCIATED_WITH')
            description = related.get('description')
            
            if target_value and target_type:
                # Add the target node if it doesn't exist (lightweight)
                if not self.graph.has_node(target_value):
                    try:
                        target_ioc_type = IOCType(target_type)
                    except ValueError:
                        target_ioc_type = IOCType.FILE  # fallback
                    self.graph.add_node(target_value, type=target_ioc_type)
                
                # Add edge with relationship type
                try:
                    rel_type = RelationshipType(relationship)
                except ValueError:
                    rel_type = RelationshipType.ASSOCIATED_WITH
                    
                self.graph.add_edge(result.ioc, target_value,
                                   type=rel_type,
                                   description=description,
                                   timestamp=datetime.now())
                print(f"    🕸️  Graph Edge: {result.ioc} --[{relationship}]--> {target_value} ({description or 'No detail'})")
        
        print(f"    🕸️  Graph Update: Added node {result.ioc} ({result.ioc_type})")
    
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
        return nx.node_link_data(self.graph, edges="links")
    
    def save_to_file(self, filepath: str):
        """Persist graph to JSON file"""
        import json
        data = self.export_graph_data()
        # Add metadata
        data['root_ioc'] = self.root_ioc
        
        with open(filepath, 'w') as f:
            json.dump(data, f, default=str, indent=2)
        
        print(f"💾 Investigation graph saved to {filepath}")
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'InvestigationGraph':
        """Restore graph from JSON file"""
        import json
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        graph = cls()
        graph.root_ioc = data.pop('root_ioc', None)
        graph.graph = nx.node_link_graph(data)
        
        print(f"📂 Investigation graph loaded from {filepath}")
        return graph

    def to_mermaid(self) -> str:
        """Convert graph to Mermaid.js diagram format"""
        if self.graph.number_of_nodes() == 0:
            return "graph TD;\n    Empty[No Data Available]"
            
        mermaid = "graph TD;\n"
        
        # Add styling
        mermaid += "    %% Node Styling\n"
        mermaid += "    classDef malicious fill:#ff4d4d,color:white,stroke:#333;\n"
        mermaid += "    classDef suspicious fill:#ffad33,color:white,stroke:#333;\n"
        mermaid += "    classDef clean fill:#4dff4d,color:black,stroke:#333;\n"
        mermaid += "    classDef unknown fill:#cccccc,color:black,stroke:#333;\n"

        # Sanitize ID function
        def safe_id(val):
            return val.replace('.', '_').replace(':', '_').replace('-', '_')[:30] # Truncate and clean

        # Add Nodes
        for node_id, attrs in self.graph.nodes(data=True):
            node_type = attrs.get('type', 'unknown')
            safe_node_id = safe_id(node_id)
            
            # Determine style (logic can be enhanced)
            style_class = "unknown"
            if attrs.get('data') and attrs['data'].malicious_votes > 0:
                style_class = "malicious"
            
            # Label with Type
            label = f"{node_id}\\n({node_type})"
            mermaid += f"    {safe_node_id}[\"{label}\"]:::{style_class};\n"

        # Add Edges
        for u, v, attrs in self.graph.edges(data=True):
            src = safe_id(u)
            dst = safe_id(v)
            rel = attrs.get('type', 'RELATED')
            desc = attrs.get('description', '')
            
            # Edge label
            edge_label = f"|{rel}|"
            if desc:
                # Add description as a click tooltip or just comment for now to keep diagram clean
                pass 
                
            mermaid += f"    {src}-->{edge_label}{dst};\n"
            
        return mermaid
