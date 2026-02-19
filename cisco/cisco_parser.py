"""
cisco_parser.py
===============
Parse Cisco IOS / IOS-XE running-configurations into structured data
that the evaluator can query efficiently.

Supported constructs:
  - Global one-liners  (e.g.  "no ip source-route")
  - Block structures   (e.g.  "interface Gi0/0 / <indented lines>")
  - Named IP ACLs      (e.g.  "ip access-list extended NAME")
  - MAC ACLs           (e.g.  "mac access-list extended NAME")

Usage:
    from cisco_parser import CiscoConfigParser
    parser = CiscoConfigParser()
    cfg    = parser.parse_file("router.txt")
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CiscoBlock:
    """One configuration block: a header line + its indented children."""
    header: str
    lines: List[str] = field(default_factory=list)

    # ---- helpers --------------------------------------------------------

    @property
    def full_text(self) -> str:
        return self.header + "\n" + "\n".join(self.lines)

    def contains(self, pattern: str, flags: int = re.IGNORECASE) -> bool:
        """True if *pattern* matches anywhere inside this block."""
        return bool(re.search(pattern, self.full_text, flags | re.MULTILINE))

    def find_all(self, pattern: str, flags: int = re.IGNORECASE) -> List[str]:
        return re.findall(pattern, self.full_text, flags | re.MULTILINE)

    def get_lines_matching(self, pattern: str,
                           flags: int = re.IGNORECASE) -> List[str]:
        return [ln for ln in self.lines
                if re.search(pattern, ln, flags)]

    def __repr__(self) -> str:          # pragma: no cover
        return f"<CiscoBlock header={self.header!r} lines={len(self.lines)}>"


class ParsedConfig:
    """
    Structured representation of a Cisco running-config.

    Attributes
    ----------
    raw_text   : original config string (unchanged)
    blocks     : ALL top-level blocks in parse order
    interfaces : {name: CiscoBlock}  — e.g. {"GigabitEthernet0/0": block}
    acls       : {name: [lines]}     — named IP ACLs (extended + standard)
    mac_acls   : {name: [lines]}     — named MAC ACLs
    """

    def __init__(self, raw_text: str) -> None:
        self.raw_text: str = raw_text
        self.blocks:     List[CiscoBlock]       = []
        self.interfaces: Dict[str, CiscoBlock]  = {}
        self.acls:       Dict[str, List[str]]   = {}
        self.mac_acls:   Dict[str, List[str]]   = {}
        self._parse()

    # ---- internal parser ------------------------------------------------

    def _parse(self) -> None:
        current_header: Optional[str] = None
        current_lines:  List[str]     = []

        for raw_line in self.raw_text.splitlines():
            line = raw_line.rstrip()

            # Skip blank lines and comments — they mark block boundaries
            if not line or line.lstrip().startswith("!"):
                if current_header is not None:
                    self._commit(current_header, current_lines)
                    current_header = None
                    current_lines  = []
                continue

            is_indented = line[0] in (" ", "\t")

            if is_indented:
                if current_header is not None:
                    current_lines.append(line.strip())
                # else: orphaned indented line — ignore silently
            else:
                # New top-level directive
                if current_header is not None:
                    self._commit(current_header, current_lines)
                current_header = line.strip()
                current_lines  = []

        # Flush the last open block
        if current_header is not None:
            self._commit(current_header, current_lines)

    def _commit(self, header: str, lines: List[str]) -> None:
        block = CiscoBlock(header=header, lines=list(lines))
        self.blocks.append(block)
        self._register(block)

    def _register(self, block: CiscoBlock) -> None:
        """Populate specialised lookup dictionaries."""

        # Interfaces
        m = re.match(r"^interface\s+(\S.*)", block.header, re.IGNORECASE)
        if m:
            self.interfaces[m.group(1)] = block
            return

        # Named IP ACLs
        m = re.match(
            r"^ip\s+access-list\s+(?:extended|standard)\s+(\S+)",
            block.header, re.IGNORECASE)
        if m:
            self.acls[m.group(1)] = block.lines
            return

        # Named MAC ACLs
        m = re.match(
            r"^mac\s+access-list\s+extended\s+(\S+)",
            block.header, re.IGNORECASE)
        if m:
            self.mac_acls[m.group(1)] = block.lines

    # ---- public query API -----------------------------------------------

    def has_global(self, pattern: str,
                   flags: int = re.IGNORECASE) -> bool:
        """True if *pattern* matches anywhere in the raw config text."""
        return bool(re.search(pattern, self.raw_text,
                               flags | re.MULTILINE))

    def find_global(self, pattern: str,
                    flags: int = re.IGNORECASE) -> List[re.Match]:
        """Return all regex Match objects for *pattern* in the raw text."""
        return list(re.finditer(pattern, self.raw_text,
                                flags | re.MULTILINE))

    def find_global_all(self, pattern: str,
                        flags: int = re.IGNORECASE) -> List[str]:
        """Return all captured groups / full matches in the raw text."""
        return re.findall(pattern, self.raw_text, flags | re.MULTILINE)

    # --- Block queries ---

    def get_blocks_matching(self, header_pattern: str) -> List[CiscoBlock]:
        """All blocks whose *header* line matches *header_pattern*."""
        return [b for b in self.blocks
                if re.search(header_pattern, b.header, re.IGNORECASE)]

    def get_block(self, header_pattern: str) -> Optional[CiscoBlock]:
        """First block whose header matches (or None)."""
        results = self.get_blocks_matching(header_pattern)
        return results[0] if results else None

    # --- Interface queries ---

    def get_interfaces(self, name_pattern: str = "") -> List[CiscoBlock]:
        """Interfaces whose name matches *name_pattern* (empty → all)."""
        if not name_pattern:
            return list(self.interfaces.values())
        return [b for name, b in self.interfaces.items()
                if re.search(name_pattern, name, re.IGNORECASE)]

    def is_switchport_access(self, iface_block: CiscoBlock) -> bool:
        return iface_block.contains(r"switchport\s+mode\s+access")

    # --- ACL queries ---

    def get_acls_matching(self, name_pattern: str) -> Dict[str, List[str]]:
        """Return {name: lines} for all ACLs whose name matches pattern."""
        return {name: lines for name, lines in self.acls.items()
                if re.search(name_pattern, name, re.IGNORECASE)}

    def acl_contains(self, name_pattern: str, entry_pattern: str) -> bool:
        """True if at least one ACL matching name_pattern has an entry
        matching entry_pattern."""
        for name, lines in self.acls.items():
            if re.search(name_pattern, name, re.IGNORECASE):
                for ln in lines:
                    if re.search(entry_pattern, ln, re.IGNORECASE):
                        return True
        return False

    # --- Misc ---

    def global_lines(self) -> List[str]:
        """All non-indented, non-comment lines."""
        result = []
        for line in self.raw_text.splitlines():
            s = line.strip()
            if s and not s.startswith("!"):
                if not line[0:1] in (" ", "\t"):
                    result.append(s)
        return result

    def __repr__(self) -> str:          # pragma: no cover
        return (f"<ParsedConfig blocks={len(self.blocks)} "
                f"ifaces={len(self.interfaces)} acls={len(self.acls)}>")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

class CiscoConfigParser:
    """Thin wrapper — instantiate once, call parse() or parse_file()."""

    def parse(self, config_text: str) -> ParsedConfig:
        """Parse *config_text* string and return a ParsedConfig."""
        return ParsedConfig(config_text)

    def parse_file(self, filepath: str,
                   encoding: str = "utf-8") -> ParsedConfig:
        """Read *filepath* and return a ParsedConfig."""
        with open(filepath, "r", encoding=encoding, errors="replace") as fh:
            return self.parse(fh.read())
