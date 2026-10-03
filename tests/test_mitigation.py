"""
Unit Tests for Automated Mitigation, Duplicate Prevention, and Expiry
"""
import time
import pytest
from mitigation.rule_manager import MitigationRuleManager

def test_mitigation_duplicate_prevention():
    mgr = MitigationRuleManager(default_duration=5, enabled=True)
    ip = "192.168.100.5"

    # First block should succeed
    res1 = mgr.block_ip(ip, duration=5, category="syn_flood")
    assert res1 is True, "First block request should succeed"
    assert mgr.is_blocked(ip) is True

    # Immediate duplicate block should return False
    res2 = mgr.block_ip(ip, duration=5, category="syn_flood")
    assert res2 is False, "Duplicate block within active window must be rejected"

    # Only 1 rule should be active
    assert mgr.get_rule_count() == 1
    mgr.shutdown()

def test_mitigation_manual_unblock():
    mgr = MitigationRuleManager(default_duration=10, enabled=True)
    ip = "192.168.100.6"

    mgr.block_ip(ip, duration=10)
    assert mgr.is_blocked(ip) is True

    # Unblock
    unblocked = mgr.unblock_ip(ip)
    assert unblocked is True
    assert mgr.is_blocked(ip) is False
    mgr.shutdown()

def test_mitigation_automatic_expiry():
    mgr = MitigationRuleManager(default_duration=1, enabled=True)
    ip = "192.168.100.7"

    # 1 second duration
    mgr.block_ip(ip, duration=1)
    assert mgr.is_blocked(ip) is True

    # Wait for expiry
    time.sleep(1.5)
    assert mgr.is_blocked(ip) is False, "Rule should auto-expire after duration"
    mgr.shutdown()
