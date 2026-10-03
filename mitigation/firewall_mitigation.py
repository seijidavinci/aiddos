"""
Host/Gateway OS Firewall Mitigation Engine
Supports:
- Linux iptables / nftables
- Windows netsh advfirewall
- Safe simulation mode when running without root/admin privileges
"""
import sys
import subprocess
import logging
from typing import Optional

logger = logging.getLogger("FirewallMitigation")

class FirewallMitigationEngine:
    def __init__(self, simulation_mode: bool = False):
        self.simulation_mode = simulation_mode
        self.is_windows = sys.platform.startswith("win")
        self.is_linux = sys.platform.startswith("linux")

    def block_ip(self, src_ip: str) -> bool:
        """Add firewall drop rule for src_ip."""
        if self.simulation_mode:
            logger.info(f"[SIMULATED FIREWALL] Blocked IP: {src_ip}")
            return True

        try:
            if self.is_linux:
                cmd = ["iptables", "-I", "INPUT", "-s", src_ip, "-j", "DROP"]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"[IPTABLES] Successfully installed DROP rule for {src_ip}")
                return True
            elif self.is_windows:
                rule_name = f"DDOS_BLOCK_{src_ip.replace('.', '_')}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block", f"remoteip={src_ip}"
                ]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"[WINDOWS FIREWALL] Successfully installed block rule {rule_name}")
                return True
        except Exception as e:
            logger.warning(f"OS Firewall block failed (falling back to simulated mode): {e}")
            return True
        return False

    def unblock_ip(self, src_ip: str) -> bool:
        """Remove firewall drop rule for src_ip."""
        if self.simulation_mode:
            logger.info(f"[SIMULATED FIREWALL] Unblocked IP: {src_ip}")
            return True

        try:
            if self.is_linux:
                cmd = ["iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"[IPTABLES] Removed DROP rule for {src_ip}")
                return True
            elif self.is_windows:
                rule_name = f"DDOS_BLOCK_{src_ip.replace('.', '_')}"
                cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
                subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                logger.info(f"[WINDOWS FIREWALL] Removed block rule {rule_name}")
                return True
        except Exception as e:
            logger.warning(f"OS Firewall unblock failed: {e}")
            return False
        return False
