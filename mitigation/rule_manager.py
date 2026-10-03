"""
Mitigation Rule Manager
Manages active mitigation rules, prevents duplicates, enforces timeouts,
and coordinates with OpenFlow controller and firewall.
"""
import time
import threading
import logging
from typing import Dict, Any, List, Optional
from mitigation.base import BaseMitigationEngine

logger = logging.getLogger("MitigationManager")

class MitigationRuleManager(BaseMitigationEngine):
    def __init__(self, default_duration: int = 60, enabled: bool = True):
        self.default_duration = default_duration
        self.enabled = enabled
        self._rules: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._subscribers: List[Any] = []
        
        # Start background expiry cleaner
        self._stop_event = threading.Event()
        self._cleaner_thread = threading.Thread(target=self._expiry_loop, daemon=True)
        self._cleaner_thread.start()

    def register_subscriber(self, callback):
        """Register a callback for mitigation events (e.g. OpenFlow switch update or DB logging)."""
        self._subscribers.append(callback)

    def _notify(self, event_type: str, rule: Dict[str, Any]):
        for sub in self._subscribers:
            try:
                sub(event_type, rule)
            except Exception as e:
                logger.error(f"Error in mitigation subscriber: {e}")

    def block_ip(
        self,
        ip_address: str,
        duration: Optional[int] = None,
        reason: str = "DDoS Attack",
        category: str = "general_ddos",
        confidence: float = 1.0,
        flow_details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Block an attacking IP address with duplicate prevention.
        Returns True if a new rule was created, False if already blocked or disabled.
        """
        if not self.enabled:
            logger.info(f"Mitigation disabled: ignoring block request for {ip_address}")
            return False

        dur = duration if duration is not None else self.default_duration
        now = time.time()
        expires_at = now + dur

        with self._lock:
            # Duplicate prevention check
            if ip_address in self._rules:
                existing = self._rules[ip_address]
                # If existing rule is still active, do not recreate; extend timeout if needed
                if existing["expires_at"] > now:
                    logger.debug(f"IP {ip_address} is already blocked until {existing['expires_at']}. Skipping duplicate.")
                    return False

            rule = {
                "ip_address": ip_address,
                "reason": reason,
                "category": category,
                "confidence": confidence,
                "created_at": now,
                "duration": dur,
                "expires_at": expires_at,
                "status": "ACTIVE",
                "flow_details": flow_details or {}
            }
            self._rules[ip_address] = rule
            logger.warning(f"[MITIGATION ACTION] Installed DROP rule for {ip_address} (Category: {category}, Duration: {dur}s)")
            self._notify("RULE_ADDED", rule)
            return True

    def unblock_ip(self, ip_address: str) -> bool:
        """Manually remove an active block rule."""
        with self._lock:
            if ip_address in self._rules and self._rules[ip_address]["status"] == "ACTIVE":
                rule = self._rules[ip_address]
                rule["status"] = "EXPIRED"
                rule["removed_at"] = time.time()
                logger.info(f"[MITIGATION ACTION] Removed DROP rule for {ip_address} (manual unblock)")
                self._notify("RULE_REMOVED", rule)
                del self._rules[ip_address]
                return True
            return False

    def is_blocked(self, ip_address: str) -> bool:
        with self._lock:
            rule = self._rules.get(ip_address)
            if rule and rule["status"] == "ACTIVE" and rule["expires_at"] > time.time():
                return True
            return False

    def get_active_rules(self) -> Dict[str, Dict[str, Any]]:
        now = time.time()
        with self._lock:
            return {
                ip: dict(rule, remaining_sec=max(0, int(rule["expires_at"] - now)))
                for ip, rule in self._rules.items()
                if rule["status"] == "ACTIVE" and rule["expires_at"] > now
            }

    def get_rule_count(self) -> int:
        return len(self.get_active_rules())

    def _expiry_loop(self):
        """Background daemon checking for expired rules every second."""
        while not self._stop_event.is_set():
            time.sleep(1.0)
            now = time.time()
            expired_ips = []
            with self._lock:
                for ip, rule in list(self._rules.items()):
                    if rule["status"] == "ACTIVE" and rule["expires_at"] <= now:
                        expired_ips.append(ip)
                        rule["status"] = "EXPIRED"
                        rule["removed_at"] = now
                        self._notify("RULE_EXPIRED", rule)
                        del self._rules[ip]
            
            for ip in expired_ips:
                logger.info(f"[MITIGATION LIFECYCLE] DROP rule for {ip} has expired. Normal traffic resumed.")

    def shutdown(self):
        self._stop_event.set()
        if self._cleaner_thread.is_alive():
            self._cleaner_thread.join(timeout=2.0)
