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

### Version 3: Iterative Investigation Workflow (Planned)
**Objective**: Transform the sequential workflow into an iterative, orchestrator-driven loop that mimics real threat intelligence analyst teams.

**Current Limitation**: V2 follows a fixed path (Triage → Malware → Infrastructure → Orchestrator) with no backtracking. If Infrastructure Agent finds new hashes, they cannot be re-analyzed.

**Proposed Solution**: Dynamic, multi-round investigation with Orchestrator as decision-maker.

*   **Orchestrator-Driven Routing**:
    *   After each specialist agent completes work, Orchestrator analyzes the `InvestigationGraph`.
    *   Identifies analysis gaps (e.g., unanalyzed hashes, unresolved IPs).
    *   Routes the next high-priority IOC to the appropriate specialist.

*   **Iterative Pivoting** (Max 3 Rounds):
    1.  **Round 1**: Triage Agent → Orchestrator decides if hash needs behavioral analysis.
    2.  **Round 2**: Malware Agent finds IPs → Orchestrator routes IPs to Infrastructure Agent.
    3.  **Round 3**: Infrastructure Agent finds new hash → Orchestrator routes to Malware Agent.
    *   If max rounds reached with remaining gaps, system recommends "Continue Investigation".

*   **InvestigationGraph Enhancements**:
    *   New methods: `find_unanalyzed_nodes()`, `get_analysis_gaps()`, `mark_node_analyzed()`.
    *   Orchestrator queries graph to drive decisions (e.g., "Which nodes lack behavioral analysis?").

*   **Implementation Approach**:
    *   **Option A**: CrewAI `Process.hierarchical` with Orchestrator as manager agent.
    *   **Option B**: Custom loop outside CrewAI with explicit round tracking (recommended for MVP).

*   **Stopping Conditions**:
    *   Round limit reached (3 rounds).
    *   No new IOCs discovered in last round.
    *   All nodes in graph analyzed.

**Detailed Design**: See [V3 Iterative Workflow Design Document](./V3_Iterative_Workflow_Design.md) for architecture diagrams, manager prompts, and migration path.

### Version 4: The Knowledge Graph (Graph-RAG)
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

## 6. Known Bugs & Optimization Backlog

### Performance Optimizations
- [ ] **Cache Cleanup Inefficiency**: `CacheManager._cleanup_expired()` runs on every write operation. Should implement batch cleanup (e.g., every 50 writes) to reduce I/O overhead by ~98%.
- [ ] **Mermaid ID Caching**: `InvestigationGraph.to_mermaid()` performs repeated string operations. Add caching for `safe_id()` conversions to optimize large graph exports.
- [ ] **Response Parsing**: `GTIMCPTool` parsing methods could be optimized with dict unpacking to reduce repeated `dict.get()` calls.

### Code Quality & Maintainability
- [ ] **Monolithic Parsing Methods**: `_parse_ioc_response` (69 lines) and `_parse_behavior_response` (67 lines) should be split into smaller, testable helper functions (e.g., `_extract_domain_resolutions`, `_extract_url_hosts`).
- [ ] **Configuration Management**: Hardcoded values (cache TTL, report paths, timeouts) should be moved to a centralized `config/settings.py` for easier configuration.
- [ ] **MCP Timeout Configuration**: Add configurable timeouts per tool action (e.g., 30s for `lookup_ioc`, 60s for `get_behaviour_summary`) instead of hardcoded 30s default.

### Testing & Documentation
- [ ] **Unit Test Coverage**: No unit tests currently exist. Priority: `InvestigationGraph`, `CacheManager`, `GTIMCPTool` parsing methods.
- [ ] **Missing Docstrings**: Many methods lack comprehensive docstrings explaining parameters and return values (e.g., `add_analysis_result`, `_parse_ioc_response`).

### Completed Optimizations
- [x] **Duplicate Edge Detection**: Added to `InvestigationGraph.add_edge()` with logging (prevents data loss).
- [x] **DRY Violation - Graph Export**: Created shared `append_graph_to_report()` helper in `utils/report_utils.py`, eliminated ~30 lines of duplicate code.
- [x] **Improved Error Handling**: Graph export now handles `FileNotFoundError` and `PermissionError` specifically.

