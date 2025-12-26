#!/usr/bin/env python3
"""
Smart Threat Hunting Crew - Clean CrewAI Implementation
Following official CrewAI patterns for simplicity and maintainability
"""

import os
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List, Any
from .core.investigation_graph import InvestigationGraph


@CrewBase
class ThreatHuntingCrew():
    """Smart Threat Hunting Crew with ReAct-based intelligent agents"""
    
    agents_config = os.path.join(os.path.dirname(__file__), 'config', 'agents.yaml')
    tasks_config = os.path.join(os.path.dirname(__file__), 'config', 'tasks.yaml')

    agents: List[BaseAgent]
    tasks: List[Task]

    def __init__(self):
        super().__init__()
        
        # Triage agent always uses the direct API
        from .core.investigation_graph import InvestigationGraph
        self.investigation_graph = InvestigationGraph()
        
        from .tools.gti_tool import GTITool
        self.gti_tool = GTITool(investigation_graph=self.investigation_graph)

        # Check if MCP mode is enabled
        use_mcp = os.getenv('USE_GTI_MCP', 'false').lower() == 'true'
        
        if use_mcp:
            print("🔌 Malware and Infrastructure agents using GTI MCP Server")
            try:
                from .tools.gti_mcp_tool import GTIMCPTool
                self.gti_behaviour_analysis_tool = GTIMCPTool(investigation_graph=self.investigation_graph)
                self.gti_infrastructure_tool = GTIMCPTool(investigation_graph=self.investigation_graph)
            except (ImportError, ValueError) as e:
                print(f"❌ Failed to import or configure MCP tools: {e}")
                print("📡 Falling back to Direct GTI API for malware and infrastructure analysis")
                from .tools.gti_behaviour_analysis_tool import GTIBehaviourAnalysisTool
                self.gti_behaviour_analysis_tool = GTIBehaviourAnalysisTool(investigation_graph=self.investigation_graph)
                from .tools.gti_ip_address_tool import GTIIpAddressTool
                from .tools.gti_domain_tool import GTIDomainTool
                self.gti_infrastructure_tool = [GTIIpAddressTool(investigation_graph=self.investigation_graph), GTIDomainTool(investigation_graph=self.investigation_graph)]
        else:
            print("📡 Malware and Infrastructure agents using Direct GTI API")
            from .tools.gti_behaviour_analysis_tool import GTIBehaviourAnalysisTool
            self.gti_behaviour_analysis_tool = GTIBehaviourAnalysisTool(investigation_graph=self.investigation_graph)
            from .tools.gti_ip_address_tool import GTIIpAddressTool
            from .tools.gti_domain_tool import GTIDomainTool
            self.gti_infrastructure_tool = [GTIIpAddressTool(investigation_graph=self.investigation_graph), GTIDomainTool(investigation_graph=self.investigation_graph)]


    @agent
    def triage_specialist(self) -> Agent:
        """Senior IOC Triage and Assessment Expert"""
        return Agent(
            config=self.agents_config['triage_specialist'],
            tools=[self.gti_tool],
            allow_delegation=False
        )

    @agent 
    def malware_specialist(self) -> Agent:
        """Elite Malware Behavioral Analysis Expert"""
        return Agent(
            config=self.agents_config['malware_analysis_specialist'],
            tools=[self.gti_behaviour_analysis_tool],
            allow_delegation=False
        )

    @agent
    def infrastructure_hunter(self) -> Agent:
        """Master Infrastructure Hunter and Campaign Correlation Expert"""
        tools = self.gti_infrastructure_tool if isinstance(self.gti_infrastructure_tool, list) else [self.gti_infrastructure_tool]
        return Agent(
            config=self.agents_config['infrastructure_analysis_specialist'],
            tools=tools,
            allow_delegation=False
        )

    @agent
    def lead_threat_hunter(self) -> Agent:
        """Lead Threat Hunter (Tier 3 Context Manager)"""
        from .tools.graph_inspection_tool import GraphInspectionTool
        # Granting access to ALL tools for deep verification and correlation
        all_tools = [
            GraphInspectionTool(investigation_graph=self.investigation_graph),
            self.gti_tool,
            self.gti_behaviour_analysis_tool
        ]
        
        # Flatten capability tools
        infra_tools = self.gti_infrastructure_tool if isinstance(self.gti_infrastructure_tool, list) else [self.gti_infrastructure_tool]
        all_tools.extend(infra_tools)

        return Agent(
            config=self.agents_config['lead_threat_hunter'],
            tools=all_tools,
            allow_delegation=False
        )

    @agent
    def orchestrator_manager(self) -> Agent:
        """Investigation Coordinator and Manager"""
        return Agent(
            config=self.agents_config['orchestrator_manager'],
            tools=[], # Manager relies on delegation and does not use tools directly
            allow_delegation=True,
            verbose=True
        )

    @task
    def iterative_investigation(self) -> Task:
        """High-level investigation task managed by orchestrator"""
        return Task(
            config=self.tasks_config['iterative_investigation'],
            agent=self.orchestrator_manager(),
            output_file='reports/final_intelligence_report.md'
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Smart Threat Hunting crew"""
        return Crew(
            agents=[
                self.orchestrator_manager(), # Manager is now a first-class citizen
                self.lead_threat_hunter(),
                self.triage_specialist(),
                self.malware_specialist(),
                self.infrastructure_hunter()
            ],
            tasks=[self.iterative_investigation()],
            process=Process.sequential, # Use sequential to allow Manager to execute its task and delegate
            verbose=True,
            memory=False
        )

    def investigate_ioc(self, ioc: str) -> dict:
        """
        Launch IOC investigation
        
        Args:
            ioc: The indicator of compromise to investigate
            
        Returns:
            Investigation results
        """
        print(f"🔍 Starting investigation for IOC: {ioc}")
        
        # CrewAI handles everything automatically!
        result = self.crew().kickoff(inputs={'ioc': ioc})
        
        print(f"✅ Investigation completed for IOC: {ioc}")
        
        # Append graph visualization to report
        from .utils.report_utils import append_graph_to_report
        append_graph_to_report(self.investigation_graph)
        
        # Read final report if it exists
        report_path = 'reports/final_intelligence_report.md'
        final_report_content = ""
        if os.path.exists(report_path):
            with open(report_path, 'r') as f:
                final_report_content = f.read()
        
        return {
            'status': 'completed',
            'ioc': ioc,
            'result': result,
            'final_report': final_report_content
        }



def main():
    """Example usage"""
    # Initialize crew
    threat_crew = ThreatHuntingCrew()
    
    # Investigate IOC
    results = threat_crew.investigate_ioc(ioc)
    
    print("\n" + "="*80)
    print("INVESTIGATION RESULTS")
    print("="*80)
    print(results['final_report'])


if __name__ == "__main__":
    main()