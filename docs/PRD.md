# Product Requirements Document: AI Threat Hunter

## 1. Overview
AI Threat Hunter is an advanced, automated cybersecurity investigation system powered by a multi-agent AI architecture. It mimics the workflow of a high-functioning Security Operations Center (SOC) by employing specialized agents to triage, analyze, and correlate threat intelligence. The system aims to scale human expertise, reduce mean time to respond (MTTR), and uncover complex threat campaigns that might be missed by manual analysis.

## 2. Vision
To build an autonomous, Graph-RAG powered threat intelligence platform that not only investigates individual IOCs but proactively maps entire threat infrastructures, correlates disjointed campaigns, and provides actionable hunt hypotheses. The final system will be a scalable, cloud-native application on Google Cloud Platform (GCP) with a user-friendly frontend.

## 3. Current State (Version 1)
- **Architecture**: Sequential multi-agent system using `crewai`.
- **Agents**:
    - **Triage Specialist**: Initial assessment of IOCs (file, URL, domain, IP).
    - **Malware Analysis Specialist**: Deep behavioral analysis of files.
    - **Infrastructure Analysis Specialist**: Pivoting and relationship mapping for network IOCs.
- **Tools**: Google Threat Intelligence (GTI) API.
- **Interaction**: CLI-based.
- **Output**: Markdown reports.

## 4. Roadmap & Requirements

### Version 2: Orchestration & Two-Tier Memory (Completed)
**Objective**: Move from a linear workflow to a dynamic, intelligence-driven operation with structured memory.

*   **Two-Tier Memory Architecture**:
    *   **Tier 1: Short-Term Memory ("The Scratchpad")** [Done]:
        *   **Technology**: `NetworkX` In-memory Graph.
        *   **Purpose**: Acts as a dynamic workspace for the *current* investigation. Agents add nodes (IOCs) and edges (relationships) in real-time.
        *   **Benefit**: Allows the Orchestrator to "see" the investigation topology instantly.
    *   **Tier 2: Long-Term Memory (Persistent Graph)** [Planned]:
        *   **Technology**: Graph Database (Neo4j/ArangoDB) or Vector-augmented Graph.

*   **Orchestrator Agent** [Done]:
    *   **Role**: Acts as the mission commander. It monitors the **Scratchpad**, identifies intelligence gaps, and dynamically re-tasks agents.
    *   **Capabilities**:
        *   Inspects the graph via `InvestigationGraphInspector`.
        *   Identifying missing edges (e.g., Unresolved Domains).
        *   Synthesizes final intelligence reports with embedded visualizations.

*   **New Tooling Integration** [Done]:
    *   **MCP Integration**: Successfully integrated Google Threat Intelligence MCP Server for deep behavioral analysis.
    *   **Structured Parsing**: Tools now extract rich relationship data (e.g., "RESOLVES_TO") automatically.

### Version 3: The Knowledge Graph (Graph-RAG)
**Objective**: Transform isolated investigation data into a persistent, queryable knowledge base that enables historical correlation and "reuse" of intelligence.

*   **Graph Database Integration**:
    *   **Technology**: Neo4j or similar graph database.
    *   **Data Model**:
        *   Nodes: `IOC` (IP, Domain, Hash, URL), `Campaign`, `Actor`, `Tool`.
        *   Edges: `RESOLVES_TO`, `COMMUNICATES_WITH`, `DROPPED`, `ASSOCIATED_WITH`.
*   **Persistent Memory**:
    *   Instead of standard RAG (text chunks), we use Graph-RAG.
    *   Agents query the graph to see if an IOC has been seen in previous investigations.
    *   "Connect the dots" between investigations that happened months apart.
*   **Visualization**:
    *   Move beyond static Mermaid diagrams to interactive graph visualizations (e.g., using libraries like `cytoscape.js` or `react-force-graph` in the future frontend).

### Final Version: Scalable Cloud Platform
**Objective**: Production-grade, scalable, and accessible deployment.

*   **Google Cloud Platform (GCP) Architecture**:
    *   **Compute**: Cloud Run or GKE for hosting the agent runtime.
    *   **Storage**: Cloud SQL (PostgreSQL) for structured results, Firestore/Bigtable for high-speed lookups.
    *   **Queueing**: Cloud Pub/Sub for managing asynchronous investigation jobs.
*   **Frontend Interface**:
    *   **Stack**: Next.js / React.
    *   **Features**:
        *   Dashboard for active investigations.
        *   Interactive investigation graph.
        *   Chat interface to "talk" to the agents (e.g., "Why did you mark this IP as malicious?").
        *   Manual trigger input for new investigations.
*   **API Layer**:
    *   REST/GraphQL API to allow integration with other security tools (SOAR, SIEM).

## 5. Success Metrics
- **Accuracy**: Reduction in false positives in final verdicts.
- **Coverage**: Increase in the number of successfully mapped infrastructure nodes per investigation.
- **Autonomy**: Ability of the Orchestrator to resolve complex cases without human intervention (measured by successful completion of multi-step pivots).
- **Usability**: User satisfaction with the frontend and graph visualization.
