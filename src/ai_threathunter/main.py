#!/usr/bin/env python
"""
Smart Threat Hunting Crew - Main Execution File
Intelligence-driven IOC analysis and campaign detection
"""

import sys
import warnings
import argparse
import os
from datetime import datetime
from typing import Optional
from pathlib import Path

from .crew import ThreatHuntingCrew
from .debug_manager import DebugManager

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")


def run_investigation(ioc: str, investigation_type: Optional[str] = None, debug: bool = False):
    """
    Run threat hunting investigation for a specific IOC.
    
    Args:
        ioc: The indicator of compromise to investigate
        investigation_type: Optional investigation focus (e.g., 'campaign', 'malware', 'infrastructure')
        debug: Enable debug mode to capture all API calls
    """
    # Load environment variables from .env file
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        print("Warning: python-dotenv not found. Skipping .env file loading.")

    # Set debug environment variable if debug flag is set
    if debug:
        os.environ['DEBUG_API_CALLS'] = 'true'
        print("🔍 DEBUG MODE ENABLED - All API calls will be logged")
    
    # Initialize debug manager
    debug_manager = DebugManager()
    
    inputs = {
        'ioc': ioc,
        'investigation_timestamp': datetime.now().isoformat(),
        'investigation_type': investigation_type or 'comprehensive'
    }
    
    print(f"🔍 Starting threat hunting investigation for IOC: {ioc}")
    print(f"📅 Investigation started at: {inputs['investigation_timestamp']}")
    if debug:
        print(f"📁 Debug logs will be saved to: {debug_manager.session_dir if debug_manager.session_dir else 'debugs/'}")
    print("=" * 80)
    
    try:
        result = ThreatHuntingCrew().crew().kickoff(inputs=inputs)
        
        print("\n" + "=" * 80)
        print("🎯 INVESTIGATION COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print(f"📊 Final Intelligence Report:")
        print(result)
        
        # Create investigation summary if debug is enabled
        if debug and debug_manager.debug_enabled:
            debug_manager.create_investigation_summary(ioc)
            print(f"\n📁 Debug logs saved to: {debug_manager.session_dir}")
            
            # Print API call summary
            summary_file = debug_manager.session_dir / 'summary' / 'api_calls_summary.json'
            if summary_file.exists():
                import json
                with open(summary_file, 'r') as f:
                    summary = json.load(f)
                print(f"\n📊 API Call Summary:")
                print(f"  - Total API Calls: {summary['total_calls']}")
                print(f"  - Successful: {summary['successful_calls']}")
                print(f"  - Failed: {summary['failed_calls']}")
                for api_name, api_stats in summary['apis'].items():
                    print(f"  - {api_name}: {api_stats['total']} calls ({api_stats['successful']} successful)")
        
        return result
        
    except Exception as e:
        print(f"❌ An error occurred during investigation: {e}")
        
        # Save error information if debug is enabled
        if debug and debug_manager.debug_enabled:
            error_file = debug_manager.session_dir / 'error.txt'
            with open(error_file, 'w') as f:
                f.write(f"Error during investigation of {ioc}:\n{str(e)}\n")
            print(f"❌ Error details saved to: {error_file}")
        
        raise Exception(f"Investigation failed for IOC {ioc}: {e}")


def run_batch_investigation(ioc_file: str, debug: bool = False):
    """
    Run investigations for multiple IOCs from a file.
    
    Args:
        ioc_file: Path to file containing IOCs (one per line)
        debug: Enable debug mode to capture all API calls
    """
    print(f"📁 Starting batch investigation from file: {ioc_file}")
    
    if debug:
        os.environ['DEBUG_API_CALLS'] = 'true'
        print("🔍 DEBUG MODE ENABLED - All API calls will be logged")
    
    try:
        with open(ioc_file, 'r') as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"🎯 Found {len(iocs)} IOCs to investigate")
        
        results = {}
        for i, ioc in enumerate(iocs, 1):
            print(f"\n{'='*20} IOC {i}/{len(iocs)} {'='*20}")
            try:
                result = run_investigation(ioc, debug=debug)
                results[ioc] = {'status': 'success', 'result': result}
            except Exception as e:
                print(f"❌ Failed to investigate {ioc}: {e}")
                results[ioc] = {'status': 'failed', 'error': str(e)}
        
        # Summary
        successful = sum(1 for r in results.values() if r['status'] == 'success')
        failed = len(results) - successful
        
        print(f"\n🏁 BATCH INVESTIGATION COMPLETE")
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        
        return results
        
    except FileNotFoundError:
        raise Exception(f"IOC file not found: {ioc_file}")
    except Exception as e:
        raise Exception(f"Batch investigation failed: {e}")


def view_debug_logs(session_dir: str = None):
    """
    View debug logs from a previous investigation session.
    
    Args:
        session_dir: Optional specific session directory. If not provided, lists available sessions.
    """
    debug_base = Path('debugs')
    
    if not debug_base.exists():
        print("No debug logs found. Run an investigation with --debug flag first.")
        return
    
    if session_dir:
        session_path = debug_base / session_dir
        if not session_path.exists():
            session_path = Path(session_dir)  # Try absolute path
            
        if not session_path.exists():
            print(f"Session directory not found: {session_dir}")
            return
            
        # Display session information
        print(f"\n📁 Debug Session: {session_path}")
        
        # Load and display summary
        summary_file = session_path / 'summary' / 'api_calls_summary.json'
        if summary_file.exists():
            import json
            with open(summary_file, 'r') as f:
                summary = json.load(f)
            
            print(f"\n📊 API Call Summary:")
            print(f"  Total API Calls: {summary['total_calls']}")
            print(f"  Successful: {summary['successful_calls']}")
            print(f"  Failed: {summary['failed_calls']}")
            
            print(f"\n📈 API Breakdown:")
            for api_name, api_stats in summary['apis'].items():
                print(f"  {api_name}:")
                print(f"    - Total: {api_stats['total']}")
                print(f"    - Successful: {api_stats['successful']}")
                print(f"    - Failed: {api_stats['failed']}")
                if api_stats['endpoints']:
                    print(f"    - Endpoints:")
                    for endpoint, stats in api_stats['endpoints'].items():
                        print(f"      • {endpoint}: {stats['count']} calls")
    else:
        # List available sessions
        sessions = sorted([d for d in debug_base.iterdir() if d.is_dir() and d.name.startswith('session_')])
        
        if not sessions:
            print("No debug sessions found.")
            return
        
        print(f"\n📁 Available Debug Sessions:")
        for session in sessions:
            session_info_file = session / 'session_info.json'
            if session_info_file.exists():
                import json
                with open(session_info_file, 'r') as f:
                    info = json.load(f)
                print(f"  - {session.name}: Started at {info.get('session_start', 'Unknown')}")
            else:
                print(f"  - {session.name}")
        
        print(f"\nTo view a specific session, run:")
        print(f"  python ai_threathunter.py debug-logs --session <session_name>")


def main():
    """Main entry point with command line argument parsing"""
    parser = argparse.ArgumentParser(
        description="Smart Threat Hunting Crew - IOC Investigation System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add global debug flag
    parser.add_argument('--debug', action='store_true', help='Enable debug mode to capture all API calls')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Run investigation command
    run_parser = subparsers.add_parser('investigate', help='Run investigation for single IOC')
    run_parser.add_argument('ioc', help='IOC to investigate (IP, domain, hash, etc.)')
    run_parser.add_argument('--type', choices=['comprehensive', 'malware', 'infrastructure', 'campaign'], 
                           default='comprehensive', help='Investigation focus type')
    
    # Batch investigation command
    batch_parser = subparsers.add_parser('batch', help='Run batch investigation from file')
    batch_parser.add_argument('file', help='File containing IOCs (one per line)')
    
    # Debug logs viewer command
    debug_parser = subparsers.add_parser('debug-logs', help='View debug logs from previous investigations')
    debug_parser.add_argument('--session', help='Specific session directory to view')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'investigate':
            run_investigation(args.ioc, args.type, debug=args.debug)
            
        elif args.command == 'batch':
            run_batch_investigation(args.file, debug=args.debug)
            
        elif args.command == 'debug-logs':
            view_debug_logs(args.session)
            
    except Exception as e:
        print(f"💥 Command failed: {e}")
        sys.exit(1)


# Simple run function for basic usage
def run():
    """
    Simple run function for basic IOC investigation
    Replace with the IOC you want to test with
    """
    # Enable debug mode programmatically
    debug_mode = True  # Set to True to enable debugging
    
    if debug_mode:
        os.environ['DEBUG_API_CALLS'] = 'true'
        print("🔍 DEBUG MODE ENABLED")
    
    sample_ioc = input("Enter IOC to investigate: ").strip()
    if not sample_ioc:
        print("IOC is required.")
        sys.exit(1)

    inputs = {
        'ioc': sample_ioc,
        'investigation_timestamp': datetime.now().isoformat(),
        'investigation_type': 'comprehensive'
    }
    
    try:
        crew = ThreatHuntingCrew()
        result = crew.crew().kickoff(inputs=inputs)
        
        # Create investigation summary if debug is enabled
        if debug_mode:
            debug_manager = DebugManager()
            if debug_manager.debug_enabled:
                debug_manager.create_investigation_summary(sample_ioc)
                print(f"\n📁 Debug logs saved to: {debug_manager.session_dir}")
        
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")


if __name__ == "__main__":
    # Check if command line arguments provided
    if len(sys.argv) > 1:
        main()  # Use CLI interface
    else:
        run()   # Use simple function for basic testing