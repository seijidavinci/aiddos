"""
Base Mitigation Interface
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseMitigationEngine(ABC):
    @abstractmethod
    def block_ip(self, ip_address: str, duration: int = 60, reason: str = "DDoS Attack") -> bool:
        """Install a block rule for a source IP."""
        pass

    @abstractmethod
    def unblock_ip(self, ip_address: str) -> bool:
        """Remove a block rule for a source IP."""
        pass

    @abstractmethod
    def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked."""
        pass

    @abstractmethod
    def get_active_rules(self) -> Dict[str, Any]:
        """Return all active mitigation rules."""
        pass
