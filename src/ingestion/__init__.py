"""
SIEM Ingestion Engine Module.
Handles log ingestion and security event detection.
"""

from .siem_engine import SIEMEngine, get_siem_engine

__all__ = ['SIEMEngine', 'get_siem_engine']
