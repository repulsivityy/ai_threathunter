import os
import sys
from pathlib import Path

# Set up paths
project_root = Path(__file__).parent
os.chdir(project_root)  # Ensure we're in the right directory

# Load environment
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not required

# Add src to path
sys.path.insert(0, str(project_root / "src"))

# Now import and run
from src.ai_threathunting.main import main

import os

if __name__ == "__main__":
    main()
 