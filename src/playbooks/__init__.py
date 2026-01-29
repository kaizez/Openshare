"""
SOAR Playbooks Module.
Handles manual security response actions.
"""

from .playbook_engine import PlaybookEngine, get_playbook_engine

__all__ = ['PlaybookEngine', 'get_playbook_engine']
