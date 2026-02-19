"""
test_cisco_parser.py
====================
Unit tests for cisco.cisco_parser — targeting >= 80% coverage as required
by the cahier des charges.

Run with:
    python -m pytest cisco/tests/test_cisco_parser.py -v
"""

import sys
import os

# Allow running from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest
from cisco.cisco_parser import CiscoConfigParser, CiscoBlock, ParsedConfig

# ---------------------------------------------------------------------------
# Shared minimal configs
# ---------------------------------------------------------------------------

MINIMAL_CONFIG = """\
hostname ROUTER-TEST-01
!
ip domain-name example.com
ip ssh version 2
no ip source-route
no ip http server
service password-encryption
service tcp-keepalives-in
service tcp-keepalives-out
!
enable secret 5 $1$ABCD$xxxxxxxxxxxxxxxxxxxxxxxxxxxx
!
interface GigabitEthernet0/0
 description WAN Uplink
 ip address 192.168.1.1 255.255.255.0
 no ip proxy-arp
 no ip redirects
 ip verify unicast source reachable-via rx
!
interface GigabitEthernet0/1
 description LAN Access
 ip address 10.0.1.1 255.255.255.0
 switchport mode access
 switchport port-security maximum 2
 switchport port-security
!
ip access-list extended MGMT-ACL
 permit tcp 10.0.0.0 0.0.0.255 any eq 22
 deny   ip any any log
!
ip access-list extended iACL-INBOUND
 deny   ip any any fragments log
 permit icmp host 10.0.0.1 host 192.168.1.1 echo
 deny   icmp any any log
!
router ospf 1
 area 0 authentication message-digest
 passive-interface default
 no passive-interface GigabitEthernet0/1
!
control-plane
 service-policy input COPP-POLICY
!
logging host 10.0.0.100
logging buffered 64000 informational
no logging console
"""

ACL_CONFIG = """\
ip access-list extended TEST-ACL
 permit ip 10.0.0.0 0.255.255.255 any
 permit tcp any host 192.168.1.1 eq 22
 deny   ip any any log
!
mac access-list extended MAC-FILTER
 permit host 0000.1111.2222 any
!
"""


# ---------------------------------------------------------------------------
# CiscoBlock tests
# ---------------------------------------------------------------------------

class TestCiscoBlock:
    def test_full_text(self):
        b = CiscoBlock(header="interface Gi0/0", lines=["ip address 10.0.0.1 255.255.255.0"])
        assert "interface Gi0/0" in b.full_text
        assert "ip address" in b.full_text

    def test_contains_true(self):
        b = CiscoBlock(header="interface Gi0/0",
                       lines=["no ip proxy-arp", "ip address 10.0.0.1 255.255.255.0"])
        assert b.contains("no ip proxy-arp")

    def test_contains_false(self):
        b = CiscoBlock(header="interface Gi0/0", lines=["ip address 10.0.0.1 255.255.255.0"])
        assert not b.contains("ip redirects")

    def test_contains_case_insensitive(self):
        b = CiscoBlock(header="control-plane", lines=["service-policy input COPP-POLICY"])
        assert b.contains("SERVICE-POLICY INPUT copp-policy")

    def test_find_all(self):
        b = CiscoBlock(header="router ospf 1",
                       lines=["network 10.0.0.0 0.255.255.255 area 0",
                               "network 192.168.0.0 0.0.0.255 area 1"])
        matches = b.find_all(r"network \S+")
        assert len(matches) == 2

    def test_get_lines_matching(self):
        b = CiscoBlock(header="line vty 0 4",
                       lines=["transport input ssh", "exec-timeout 10 0", "login authentication default"])
        result = b.get_lines_matching(r"transport")
        assert result == ["transport input ssh"]


# ---------------------------------------------------------------------------
# CiscoConfigParser / ParsedConfig tests
# ---------------------------------------------------------------------------

class TestCiscoConfigParser:
    @pytest.fixture
    def cfg(self):
        parser = CiscoConfigParser()
        return parser.parse(MINIMAL_CONFIG)

    @pytest.fixture
    def acl_cfg(self):
        return CiscoConfigParser().parse(ACL_CONFIG)

    # --- parse_file ---
    def test_parse_file(self, tmp_path):
        p = tmp_path / "router.txt"
        p.write_text("hostname TESTROUTER\n", encoding="utf-8")
        cfg = CiscoConfigParser().parse_file(str(p))
        assert cfg.has_global("hostname TESTROUTER")

    # --- has_global ---
    def test_has_global_present(self, cfg):
        assert cfg.has_global(r"ip ssh version 2")

    def test_has_global_absent(self, cfg):
        assert not cfg.has_global(r"telnet server")

    def test_has_global_case_insensitive(self, cfg):
        assert cfg.has_global(r"SERVICE PASSWORD-ENCRYPTION")

    def test_has_global_regex_pattern(self, cfg):
        assert cfg.has_global(r"enable secret \d+")

    # --- find_global ---
    def test_find_global_returns_matches(self, cfg):
        matches = cfg.find_global(r"interface \S+")
        assert len(matches) >= 2

    def test_find_global_all(self, cfg):
        results = cfg.find_global_all(r"interface \S+")
        assert any("GigabitEthernet" in r for r in results)

    # --- blocks ---
    def test_blocks_populated(self, cfg):
        assert len(cfg.blocks) > 0

    def test_get_blocks_matching(self, cfg):
        osp_blocks = cfg.get_blocks_matching(r"^router ospf")
        assert len(osp_blocks) == 1
        assert "passive-interface default" in osp_blocks[0].lines

    def test_get_block_first_match(self, cfg):
        block = cfg.get_block(r"^control-plane")
        assert block is not None
        assert block.contains("service-policy input COPP-POLICY")

    def test_get_block_none(self, cfg):
        assert cfg.get_block(r"router bgp") is None

    # --- interfaces ---
    def test_interfaces_parsed(self, cfg):
        assert len(cfg.interfaces) == 2

    def test_get_interfaces_all(self, cfg):
        ifaces = cfg.get_interfaces()
        assert len(ifaces) == 2

    def test_get_interfaces_pattern(self, cfg):
        wan = cfg.get_interfaces(r"GigabitEthernet0/0")
        assert len(wan) == 1
        assert wan[0].contains("ip address 192.168.1.1")

    def test_get_interfaces_no_match(self, cfg):
        assert cfg.get_interfaces(r"Loopback0") == []

    def test_is_switchport_access_true(self, cfg):
        lan = cfg.get_interfaces(r"GigabitEthernet0/1")[0]
        assert cfg.is_switchport_access(lan)

    def test_is_switchport_access_false(self, cfg):
        wan = cfg.get_interfaces(r"GigabitEthernet0/0")[0]
        assert not cfg.is_switchport_access(wan)

    # --- ACLs ---
    def test_acls_parsed(self, cfg):
        assert "MGMT-ACL" in cfg.acls
        assert "iACL-INBOUND" in cfg.acls

    def test_acl_contains_true(self, cfg):
        assert cfg.acl_contains(r"iACL-INBOUND", r"fragments log")

    def test_acl_contains_false(self, cfg):
        assert not cfg.acl_contains(r"MGMT-ACL", r"permit udp")

    def test_get_acls_matching(self, cfg):
        result = cfg.get_acls_matching(r"iACL")
        assert "iACL-INBOUND" in result

    def test_mac_acls_parsed(self, acl_cfg):
        assert "MAC-FILTER" in acl_cfg.mac_acls

    def test_named_acl_lines(self, acl_cfg):
        lines = acl_cfg.acls["TEST-ACL"]
        assert any("permit ip" in ln for ln in lines)
        assert any("deny" in ln for ln in lines)

    # --- global_lines ---
    def test_global_lines_returns_list(self, cfg):
        gl = cfg.global_lines()
        assert isinstance(gl, list)
        assert any("hostname" in ln for ln in gl)

    def test_global_lines_no_comments(self, cfg):
        gl = cfg.global_lines()
        assert all(not ln.startswith("!") for ln in gl)

    # --- edge cases ---
    def test_empty_config(self):
        cfg = CiscoConfigParser().parse("")
        assert cfg.blocks == []
        assert cfg.interfaces == {}
        assert cfg.acls == {}

    def test_config_comments_only(self):
        cfg = CiscoConfigParser().parse("!\n! This is a comment\n!\n")
        assert cfg.blocks == []

    def test_repr_returns_string(self):
        cfg = CiscoConfigParser().parse("hostname TEST\n")
        assert "ParsedConfig" in repr(cfg)


# ---------------------------------------------------------------------------
# Standalone run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
