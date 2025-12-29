#!/usr/bin/env python3
"""
5G-Gibbon Launcher
==================
Run this from the project root directory.

Usage:
    Interactive mode: python run.py
    Direct mode:      python run.py <command> [options]
    
Examples:
    python run.py                     # Interactive menu
    python run.py discover            # Discover network
    python run.py audit               # Run security audit
    python run.py ultra-red           # Red team attack
    python run.py ultra-blue          # Blue team defense
    python run.py --help              # Show all commands
"""

import sys
import os

# Add core to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'core'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run CLI
from core.cli import main

if __name__ == "__main__":
    sys.exit(main())

