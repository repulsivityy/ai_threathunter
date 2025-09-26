#!/usr/bin/env python3
"""
Smart Threat Hunting Crew - Clean CrewAI Implementation
Following official CrewAI patterns for simplicity and maintainability
"""

import os
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai.agents.agent_builder.base_agent import BaseAgent
from typing import List

# Import your custom tools
from .tools.gti_tool import GTITool
from .tools.urlscan_tool import URLScanTool


@CrewBase
class ThreatHuntingCrew():
    """Smart Threat Hunting Crew with ReAct-based intelligent agents"""

    agents: List[BaseAgent]
    tasks: List[Task]

    def __init__(self):
        super().__init__()
        # Initialize tools
        self.gti_tool = GTITool()
        self.urlscan_tool = URLScanTool()

    @agent
    def triage_specialist(self) -> Agent:
        """Senior IOC Triage and Assessment Expert"""
        return Agent(
            config=self.agents_config['triage_specialist'],
            tools=[self.gti_tool]
        )

    @agent 
    def malware_specialist(self) -> Agent:
        """Elite Malware Behavioral Analysis Expert"""
        return Agent(
            config=self.agents_config['malware_analysis_specialist'],
            tools=[self.gti_tool]
        )

    @agent
    def infrastructure_hunter(self) -> Agent:
        """Master Infrastructure Hunter and Campaign Correlation Expert"""
        return Agent(
            config=self.agents_config['infrastructure_correlation_specialist'],
            tools=[self.urlscan_tool]
        )

    @agent
    def campaign_analyst(self) -> Agent:
        """Strategic Threat Campaign Assessment and Attribution Expert"""
        return Agent(
            config=self.agents_config['campaign_intelligence_analyst']
        )

    @agent
    def correlation_orchestrator(self) -> Agent:
        """Cross-Agent Intelligence Correlation and Investigation Orchestrator"""
        return Agent(
            config=self.agents_config['intelligence_correlation_orchestrator']
        )

    @task
    def initial_assessment(self) -> Task:
        """Initial IOC triage and priority assessment"""
        return Task(
            config=self.tasks_config['initial_ioc_assessment'],
            agent=self.triage_specialist(),
            output_file='reports/triage_assessment.md'
        )

    @task
    def malware_analysis(self) -> Task:
        """Deep malware behavioral analysis"""
        return Task(
            config=self.tasks_config['deep_malware_behavioral_analysis'],
            agent=self.malware_specialist(),
            context=[self.initial_assessment()],  # CrewAI handles context automatically
            output_file='reports/malware_analysis.md'
        )

    @task 
    def infrastructure_correlation(self) -> Task:
        """Infrastructure campaign correlation and mapping"""
        return Task(
            config=self.tasks_config['infrastructure_campaign_correlation'],
            agent=self.infrastructure_hunter(),
            context=[self.initial_assessment(), self.malware_analysis()],  # Full context
            output_file='reports/infrastructure_analysis.md'
        )

    
    @task
    def campaign_synthesis(self) -> Task:
        """Strategic campaign intelligence synthesis"""
        return Task(
            config=self.tasks_config['strategic_campaign_intelligence_synthesis'],
            agent=self.campaign_analyst(),
            context=[self.initial_assessment(), self.malware_analysis(), self.infrastructure_correlation(), self.intelligence_orchestration()],  # Include orchestrator context
            output_file='reports/campaign_intelligence.md'
        )

    @task
    def intelligence_orchestration(self) -> Task:
        """Continuous intelligence correlation and orchestration"""
        return Task(
            config=self.tasks_config['continuous_intelligence_correlation'],
            agent=self.correlation_orchestrator(),
            context=[self.initial_assessment(), self.malware_analysis(), 
                    self.infrastructure_correlation()],
            output_file='reports/final_intelligence_report.md'
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Smart Threat Hunting crew"""
        return Crew(
            agents=[self.triage_specialist(),self.malware_specialist(), self.infrastructure_hunter(),self.campaign_analyst(),self.correlation_orchestrator()],  # Automatically populated by @agent decorators
            tasks=[
                self.initial_assessment(),
                self.malware_analysis(),
                self.infrastructure_correlation(),
                self.intelligence_orchestration(),
                self.campaign_synthesis()
            ],    # Automatically populated by @task decorators
            process=Process.sequential,  # Sequential with automatic context passing
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
        
        return {
            'status': 'completed',
            'ioc': ioc,
            'result': result,
            'final_report': result.raw if hasattr(result, 'raw') else str(result)
        }


def main():
    """Example usage"""
    # Initialize crew
    threat_crew = ThreatHuntingCrew()
    
    # Investigate IOC
    results = threat_crew.investigate_ioc("rtmp.blog")
    
    print("\n" + "="*80)
    print("INVESTIGATION RESULTS")
    print("="*80)
    print(results['final_report'])


if __name__ == "__main__":
    main()
