#!/usr/bin/env python
"""
Debug Runner for AI Threat Hunter
This script makes it easy to run investigations with debug mode enabled
"""

import os
import sys
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

def main():
    """Run investigation with debug mode enabled"""
    
    # Enable debug mode
    os.environ['DEBUG_API_CALLS'] = 'true'
    
    # Load environment variables
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    
    # Get IOC from command line or use default
    if len(sys.argv) > 1:
        ioc = sys.argv[1]
    else:
        ioc = input("Enter IOC to investigate: ").strip()
        if not ioc:
            print("IOC is required.")
            sys.exit(1)
    
    print(f"\n{'='*60}")
    print("🔍 AI THREAT HUNTER - DEBUG MODE")
    print(f"{'='*60}")
    print(f"IOC: {ioc}")
    print(f"Debug Mode: ENABLED")
    print(f"{'='*60}\n")
    
    # Import and run
    from src.ai_threathunter.main import run_investigation
    
    try:
        run_investigation(ioc, investigation_type='comprehensive', debug=True)
        print("\n✅ Investigation completed successfully!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Investigation interrupted by user")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n❌ Investigation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
