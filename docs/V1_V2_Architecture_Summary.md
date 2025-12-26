# V1 & V2 Architecture Summary
**Status**: Current Production State (pre-V3)
**Date**: Dec 2025

## 1. System Overview
The AI Threat Hunter is a modular, multi-agent system designed to automate IOC validation and infrastructure mapping. It has evolved from a linear script (V1) to a graph-backed, orchestrated system (V2).

### Core Components
| Component | Implementation | Role |
|-----------|----------------|------|
| **Orchestration** | `crewai.Process.sequential` | Manages agent execution flow (linear in V2). |
| **State Management** | `InvestigationGraph` (NetworkX) | Shared in-memory graph storing all IOCs and relationships. |
| **Data Layer** | Pydantic Models | Enforces strict typing for all analysis results and graph edges. |
| **Tooling** | GTI MCP Server | Provides structured threat intelligence via Model Context Protocol. |

---

## 2. Agent Architecture
Agents share a single `InvestigationGraph` instance, allowing "telepathic" context sharing.

| Agent | Role | Key Tools |
|-------|------|-----------|
| **Triage Specialist** | Initial IOC assessment (Verdict/Score). | `GTITool` (Direct API) |
| **Malware Specialist** | Behavioral analysis of files. | `GTIMCPTool` (Behavior) |
| **Infra. Hunter** | Pivoting (IP <-> Domain). | `GTIMCPTool` (Passive DNS) |
| **Orchestrator** | Synthesis & Reporting. | `GraphInspectionTool` |

---

## 3. Data Structures (`src/ai_threathunter/core/`)

### `InvestigationGraph`
- **Backing**: `networkx.DiGraph`
- **Nodes**: `InvestigationNode` (ID, Type, Data, Behavior)
- **Edges**: `GraphEdge` (Source, Target, RelationshipType, Description)
- **Persistence**: JSON load/save support.
- **Export**: Generates Mermaid.js diagrams for reports.

### `IOCAnalysisResult`
Standardized container for tool outputs:
```python
class IOCAnalysisResult(BaseModel):
    ioc: str
    ioc_type: IOCType
    verdict: str        # MALICIOUS, SUSPICIOUS, BENIGN
    score: int          # 0-100
    related_iocs: List[Dict] # Associated entities
```

---

## 4. Key Capabilities (V2)
1.  **MCP Integration**: Replaced unstructured API calls with structured MCP queries.
2.  **Graph Visualization**: Automatically renders investigation topology to Mermaid.js.
3.  **Deduplication**: Graph logic prevents duplicate edges/nodes from cluttering state.
4.  ** caching**: Filesystem cache for API responses to speed up dev cycles.

## 5. Current Limitations (Drivers for V3)
- **Linearity**: Execution is strictly A -> B -> C -> D.
- **No Feedback Loop**: If Infrastructure Hunter finds a new hash, the Malware Specialist cannot be recalled to analyze it.
- **Reactive Orchestrator**: The Orchestrator only summarizes at the end; it does not drive the investigation.
