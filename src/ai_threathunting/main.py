#!/usr/bin/env python
"""
Smart Threat Hunting Crew - Main Execution File
Intelligence-driven IOC analysis and campaign detection
"""

import sys
import warnings
import argparse
from datetime import datetime
from typing import Optional

from .crew import ThreatHuntingCrew

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")


def run_investigation(ioc: str, investigation_type: Optional[str] = None):
    """
    Run threat hunting investigation for a specific IOC.
    
    Args:
        ioc: The indicator of compromise to investigate
        investigation_type: Optional investigation focus (e.g., 'campaign', 'malware', 'infrastructure')
    """
    inputs = {
        'ioc': ioc,
        'investigation_timestamp': datetime.now().isoformat(),
        'investigation_type': investigation_type or 'comprehensive'
    }
    
    print(f"🔍 Starting threat hunting investigation for IOC: {ioc}")
    print(f"📅 Investigation started at: {inputs['investigation_timestamp']}")
    print("=" * 80)
    
    try:
        result = ThreatHuntingCrew().crew().kickoff(inputs=inputs)
        
        print("\n" + "=" * 80)
        print("🎯 INVESTIGATION COMPLETED SUCCESSFULLY")
        print("=" * 80)
        print(f"📊 Final Intelligence Report:")
        print(result)
        
        return result
        
    except Exception as e:
        print(f"❌ An error occurred during investigation: {e}")
        raise Exception(f"Investigation failed for IOC {ioc}: {e}")


def run_batch_investigation(ioc_file: str):
    """
    Run investigations for multiple IOCs from a file.
    
    Args:
        ioc_file: Path to file containing IOCs (one per line)
    """
    print(f"📁 Starting batch investigation from file: {ioc_file}")
    
    try:
        with open(ioc_file, 'r') as f:
            iocs = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print(f"🎯 Found {len(iocs)} IOCs to investigate")
        
        results = {}
        for i, ioc in enumerate(iocs, 1):
            print(f"\n{'='*20} IOC {i}/{len(iocs)} {'='*20}")
            try:
                result = run_investigation(ioc)
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


def main():
    """Main entry point with command line argument parsing"""
    parser = argparse.ArgumentParser(
        description="Smart Threat Hunting Crew - IOC Investigation System",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Run investigation command
    run_parser = subparsers.add_parser('investigate', help='Run investigation for single IOC')
    run_parser.add_argument('ioc', help='IOC to investigate (IP, domain, hash, etc.)')
    run_parser.add_argument('--type', choices=['comprehensive', 'malware', 'infrastructure', 'campaign'], 
                           default='comprehensive', help='Investigation focus type')
    
    # Batch investigation command
    batch_parser = subparsers.add_parser('batch', help='Run batch investigation from file')
    batch_parser.add_argument('file', help='File containing IOCs (one per line)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'investigate':
            run_investigation(args.ioc, args.type)
            
        elif args.command == 'batch':
            run_batch_investigation(args.file)
            
    except Exception as e:
        print(f"💥 Command failed: {e}")
        sys.exit(1)


# Simple run function for basic usage
def run():
    """
    Simple run function for basic IOC investigation
    Replace with the IOC you want to test with
    """
    sample_ioc = "rtmp.blog"  # Your example IOC
    
    inputs = {
        'ioc': sample_ioc,
        'investigation_timestamp': datetime.now().isoformat(),
        'investigation_type': 'comprehensive'
    }
    
    try:
        ThreatHuntingCrew().crew().kickoff(inputs=inputs)
    except Exception as e:
        raise Exception(f"An error occurred while running the crew: {e}")


if __name__ == "__main__":
    # Check if command line arguments provided
    if len(sys.argv) > 1:
        main()  # Use CLI interface
    else:
        run()   # Use simple function for basic testing