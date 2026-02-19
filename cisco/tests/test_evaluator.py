"""
test_evaluator.py
=================
Unit tests for cisco.evaluator — targeting >= 80% coverage as required
by the cahier des charges.

Run with:
    python -m pytest cisco/tests/test_evaluator.py -v
"""

import sys
import os

# Allow running from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest
from cisco.cisco_parser import CiscoConfigParser
from cisco.evaluator    import RuleEvaluator, RuleResult, Status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_cfg(text: str):
    return CiscoConfigParser().parse(text)


def make_rule(**kwargs) -> dict:
    """Build a minimal rule dict with sane defaults."""
    base = {
        "id":         "TEST-001",
        "title":      "Test Rule",
        "plane":      "management",
        "section":    "Test Section",
        "severity":   "HIGH",
        "check_type": "global_regex",
        "conditions": {},
    }
    base.update(kwargs)
    return base


ev = RuleEvaluator()


# ---------------------------------------------------------------------------
# Status + RuleResult helpers
# ---------------------------------------------------------------------------

class TestRuleResult:
    def test_passed_property(self):
        r = RuleResult("X", "t", "mgmt", "sec", "HIGH", Status.PASS)
        assert r.passed
        assert not r.failed

    def test_failed_property(self):
        r = RuleResult("X", "t", "mgmt", "sec", "HIGH", Status.FAIL)
        assert r.failed
        assert not r.passed


# ---------------------------------------------------------------------------
# applicable_if
# ---------------------------------------------------------------------------

class TestApplicableIf:
    def test_not_applicable_when_condition_absent(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(applicable_if=r"router bgp \d+")
        result = ev.evaluate(rule, cfg)
        assert result.status == Status.NOT_APPLICABLE

    def test_applicable_when_condition_present(self):
        cfg  = make_cfg("router bgp 65000\n neighbor 10.0.0.1 remote-as 65001\n")
        rule = make_rule(
            applicable_if=r"router bgp \d+",
            check_type="global_regex",
            conditions={"require": [{"pattern": r"router bgp \d+",
                                      "description": "BGP configured"}]},
        )
        result = ev.evaluate(rule, cfg)
        assert result.status == Status.PASS


# ---------------------------------------------------------------------------
# global_regex
# ---------------------------------------------------------------------------

class TestGlobalRegex:
    def test_pass_single_require(self):
        cfg  = make_cfg("ip ssh version 2\n")
        rule = make_rule(conditions={"require": [
            {"pattern": r"ip ssh version 2", "description": "SSH v2"}
        ]})
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_missing_require(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(conditions={"require": [
            {"pattern": r"ip ssh version 2", "description": "SSH v2"}
        ]})
        result = ev.evaluate(rule, cfg)
        assert result.status == Status.FAIL
        assert len(result.details) == 1
        assert not result.details[0].matched

    def test_pass_prohibit_absent(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(conditions={"prohibit": [
            {"pattern": r"service telnet", "description": "No Telnet"}
        ]})
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_prohibit_present(self):
        cfg  = make_cfg("service telnet\nhostname ROUTER\n")
        rule = make_rule(conditions={"prohibit": [
            {"pattern": r"service telnet", "description": "No Telnet"}
        ]})
        assert ev.evaluate(rule, cfg).status == Status.FAIL

    def test_multiple_require_all_pass(self):
        cfg  = make_cfg("service password-encryption\nenable secret 5 $1$X\n")
        rule = make_rule(conditions={"require": [
            {"pattern": r"service password-encryption"},
            {"pattern": r"enable secret"},
        ]})
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_multiple_require_one_fails(self):
        cfg  = make_cfg("service password-encryption\n")
        rule = make_rule(conditions={"require": [
            {"pattern": r"service password-encryption"},
            {"pattern": r"enable secret"},
        ]})
        assert ev.evaluate(rule, cfg).status == Status.FAIL


# ---------------------------------------------------------------------------
# multi_regex
# ---------------------------------------------------------------------------

class TestMultiRegex:
    def test_require_one_of_passes(self):
        cfg  = make_cfg("logging host 10.0.0.1\n")
        rule = make_rule(
            check_type="multi_regex",
            conditions={"require_one_of": [
                {"pattern": r"logging host", "description": "Syslog"},
                {"pattern": r"logging server", "description": "Alt Syslog"},
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_require_one_of_fails(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(
            check_type="multi_regex",
            conditions={"require_one_of": [
                {"pattern": r"logging host", "description": "Syslog"},
                {"pattern": r"logging server", "description": "Alt Syslog"},
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL


# ---------------------------------------------------------------------------
# regex_absent
# ---------------------------------------------------------------------------

class TestRegexAbsent:
    def test_pass_when_absent(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(
            check_type="regex_absent",
            conditions={"absent": [
                {"pattern": r"snmp-server community public", "description": "No public community"}
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_when_present(self):
        cfg  = make_cfg("snmp-server community public RO\n")
        rule = make_rule(
            check_type="regex_absent",
            conditions={"absent": [
                {"pattern": r"snmp-server community public", "description": "No public community"}
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL


# ---------------------------------------------------------------------------
# value_comparison
# ---------------------------------------------------------------------------

class TestValueComparison:
    # --- operator: le / <=, field names: extract / threshold ---
    def test_pass_le_threshold(self):
        cfg  = make_cfg("aaa local authentication attempts max-fail 3\n")
        rule = make_rule(
            check_type="value_comparison",
            conditions={
                "extract":   r"max-fail (\d+)",
                "threshold": 5,
                "operator":  "<=",
                "description": "Max fail <= 5",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_le_threshold(self):
        cfg  = make_cfg("aaa local authentication attempts max-fail 10\n")
        rule = make_rule(
            check_type="value_comparison",
            conditions={
                "extract":   r"max-fail (\d+)",
                "threshold": 5,
                "operator":  "<=",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL

    # --- operator: ge, field names: extract_pattern / expected_value ---
    def test_pass_ge_expected_value(self):
        cfg  = make_cfg("crypto key generate rsa modulus 2048\n")
        rule = make_rule(
            check_type="value_comparison",
            conditions={
                "extract_pattern": r"modulus (\d+)",
                "expected_value":  2048,
                "operator":        "ge",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_pattern_not_found(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(
            check_type="value_comparison",
            conditions={
                "extract":   r"max-fail (\d+)",
                "threshold": 5,
                "operator":  "<=",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL

    # --- symbolic operators ---
    def test_operator_gt(self):
        cfg  = make_cfg("ip ssh timeout 120\n")
        rule = make_rule(
            check_type="value_comparison",
            conditions={
                "extract": r"ip ssh timeout (\d+)",
                "threshold": 30,
                "operator": ">",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_operator_eq(self):
        cfg  = make_cfg("ip ssh version 2\n")
        rule = make_rule(
            check_type="value_comparison",
            conditions={
                "extract": r"ip ssh version (\d+)",
                "threshold": 2,
                "operator": "==",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS


# ---------------------------------------------------------------------------
# block_regex
# ---------------------------------------------------------------------------

class TestBlockRegex:
    def test_pass_block_contains_pattern(self):
        cfg  = make_cfg("control-plane\n service-policy input COPP-POLICY\n")
        rule = make_rule(
            check_type="block_regex",
            context={"block": r"control-plane"},
            conditions={"require": [
                {"pattern": r"service-policy input", "description": "CoPP policy"}
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_block_not_found(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(
            check_type="block_regex",
            context={"block": r"control-plane"},
            conditions={"require": [{"pattern": r"service-policy input"}]},
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL

    def test_fail_pattern_missing_in_block(self):
        cfg  = make_cfg("control-plane\n no service-policy\n")
        rule = make_rule(
            check_type="block_regex",
            context={"block": r"control-plane"},
            conditions={"require": [
                {"pattern": r"service-policy input", "description": "CoPP"}
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL


# ---------------------------------------------------------------------------
# block_all
# ---------------------------------------------------------------------------

class TestBlockAll:
    def test_pass_all_interfaces_comply(self):
        cfg  = make_cfg(
            "interface GigabitEthernet0/0\n no ip proxy-arp\n"
            "interface GigabitEthernet0/1\n no ip proxy-arp\n"
        )
        rule = make_rule(
            check_type="block_all",
            context={"blocks": [r"^interface "]},
            conditions={"require": [
                {"pattern": r"no ip proxy-arp", "description": "Proxy ARP disabled"}
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_one_interface_non_compliant(self):
        cfg  = make_cfg(
            "interface GigabitEthernet0/0\n no ip proxy-arp\n"
            "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n"
        )
        rule = make_rule(
            check_type="block_all",
            context={"blocks": [r"^interface "]},
            conditions={"require": [
                {"pattern": r"no ip proxy-arp", "description": "Proxy ARP disabled"}
            ]},
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL

    def test_not_applicable_no_blocks(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(
            check_type="block_all",
            context={"blocks": [r"^interface "]},
            conditions={"require": [{"pattern": r"no ip proxy-arp"}]},
        )
        assert ev.evaluate(rule, cfg).status == Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# acl_content
# ---------------------------------------------------------------------------

class TestAclContent:
    def test_pass_required_entry_present(self):
        cfg  = make_cfg(
            "ip access-list extended iACL-IN\n"
            " deny   ip any any fragments log\n"
            " permit icmp host 10.0.0.1 any\n"
        )
        rule = make_rule(
            check_type="acl_content",
            conditions={
                "acl_name_pattern":  r"iACL",
                "require_entries": [
                    {"pattern": r"deny.*fragments", "description": "Block fragments"}
                ],
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_no_matching_acl(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(
            check_type="acl_content",
            conditions={
                "acl_name_pattern": r"iACL",
                "require_entries": [{"pattern": r"deny.*fragments"}],
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL

    def test_fail_entry_missing(self):
        cfg  = make_cfg(
            "ip access-list extended iACL-IN\n"
            " permit ip any any\n"
        )
        rule = make_rule(
            check_type="acl_content",
            conditions={
                "acl_name_pattern": r"iACL",
                "require_entries": [
                    {"pattern": r"deny.*fragments", "description": "Block fragments"}
                ],
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL


# ---------------------------------------------------------------------------
# value_count
# ---------------------------------------------------------------------------

class TestValueCount:
    def test_pass_min_count(self):
        cfg  = make_cfg("tacacs server S1\n address ipv4 10.0.0.1\n"
                        "tacacs server S2\n address ipv4 10.0.0.2\n")
        rule = make_rule(
            check_type="value_count",
            conditions={
                "pattern":   r"tacacs server",
                "min_count": 2,
                "description": "At least 2 TACACS servers",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS

    def test_fail_below_min_count(self):
        cfg  = make_cfg("tacacs server S1\n address ipv4 10.0.0.1\n")
        rule = make_rule(
            check_type="value_count",
            conditions={
                "pattern":   r"tacacs server",
                "min_count": 2,
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.FAIL

    def test_pass_max_count(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(
            check_type="value_count",
            conditions={
                "pattern":   r"enable password ",
                "max_count": 0,
                "description": "No cleartext enable password",
            },
        )
        assert ev.evaluate(rule, cfg).status == Status.PASS


# ---------------------------------------------------------------------------
# Unknown check_type → ERROR
# ---------------------------------------------------------------------------

class TestUnknownCheckType:
    def test_error_on_unknown_check_type(self):
        cfg  = make_cfg("hostname ROUTER\n")
        rule = make_rule(check_type="nonexistent_type")
        result = ev.evaluate(rule, cfg)
        assert result.status == Status.ERROR
        assert "nonexistent_type" in result.message


# ---------------------------------------------------------------------------
# load_rules integration test (uses real YAML files)
# ---------------------------------------------------------------------------

class TestLoadRules:
    def test_loads_at_least_some_rules(self):
        rules_dir = os.path.join(
            os.path.dirname(__file__), "..", "rules"
        )
        if os.path.isdir(rules_dir):
            rules = ev.load_rules(rules_dir)
            assert len(rules) > 50, "Expected > 50 rules loaded from YAML files"
        else:
            pytest.skip("cisco/rules directory not found")

    def test_rule_has_required_fields(self):
        rules_dir = os.path.join(
            os.path.dirname(__file__), "..", "rules"
        )
        if os.path.isdir(rules_dir):
            rules = ev.load_rules(rules_dir)
            for rule in rules:
                assert "id"    in rule, f"Rule missing 'id': {rule}"
                assert "title" in rule, f"Rule missing 'title': {rule}"
        else:
            pytest.skip("cisco/rules directory not found")


# ---------------------------------------------------------------------------
# Standalone run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
