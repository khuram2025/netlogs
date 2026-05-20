"""Shared pytest configuration.

Ensures the repository root is on ``sys.path`` so tests can ``import
fastapi_app...`` regardless of where pytest is invoked from.
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
