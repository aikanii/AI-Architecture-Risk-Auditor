"""API router initialization."""
from . import scans
from . import findings
from . import graph
from . import reports

__all__ = ['scans', 'findings', 'graph', 'reports']
