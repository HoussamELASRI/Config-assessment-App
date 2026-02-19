"""
evaluator.py
============
Load YAML rule files and evaluate a ParsedConfig against every rule.

Supported check_type values
----------------------------
  global_regex      Search the entire config for require / prohibit patterns.
  multi_regex       Same as global_regex but allows require_one_of groups.
  regex_absent      A pattern must NOT be found anywhere in the config.
  value_comparison  Extract a numeric value and compare it (gt/lt/ge/le/eq/ne).
  block_regex       Find a single config block, check patterns inside it.
  block_all         Check ALL matching blocks contain required patterns.
  acl_content       Inspect named ACL entries with require_entries patterns.
  value_count       Count pattern occurrences and compare to a threshold.

Usage
-----
    from cisco_parser  import CiscoConfigParser
    from evaluator     import RuleEvaluator

    cfg     = CiscoConfigParser().parse_file("router.txt")
    results = RuleEvaluator().evaluate_all(cfg, rules_dir="cisco/rules")
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import yaml

from .cisco_parser import ParsedConfig


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class Status(str, Enum):
    PASS            = "PASS"
    FAIL            = "FAIL"
    WARN            = "WARN"
    NOT_APPLICABLE  = "NOT_APPLICABLE"
    ERROR           = "ERROR"


@dataclass
class CheckDetail:
    pattern:     str
    description: str
    matched:     bool
    match_text:  str = ""


@dataclass
class RuleResult:
    rule_id:     str
    title:       str
    plane:       str
    section:     str
    severity:    str
    status:      Status
    details:     List[CheckDetail] = field(default_factory=list)
    message:     str               = ""
    remediation: str               = ""
    reference:   str               = ""

    # Convenience
    @property
    def passed(self) -> bool:
        return self.status == Status.PASS

    @property
    def failed(self) -> bool:
        return self.status == Status.FAIL


# ---------------------------------------------------------------------------
# Evaluator core
# ---------------------------------------------------------------------------

class RuleEvaluator:

    # ---- Public API -------------------------------------------------------

    def load_rules(self, rules_dir: str) -> List[Dict]:
        """Load all YAML rule files from *rules_dir* and return merged list."""
        rules: List[Dict] = []
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith(".yaml") or fname.endswith(".yml"):
                fpath = os.path.join(rules_dir, fname)
                with open(fpath, "r", encoding="utf-8") as fh:
                    content = yaml.safe_load(fh)
                    if isinstance(content, list):
                        rules.extend(content)
        return rules

    def evaluate_all(self, cfg: ParsedConfig,
                     rules_dir: str = "cisco/rules") -> List[RuleResult]:
        """Evaluate *cfg* against every rule found in *rules_dir*."""
        rules = self.load_rules(rules_dir)
        return [self.evaluate(rule, cfg) for rule in rules]

    def evaluate(self, rule: Dict, cfg: ParsedConfig) -> RuleResult:
        """Evaluate a single rule dict against a ParsedConfig."""
        result = RuleResult(
            rule_id     = rule.get("id", "UNKNOWN"),
            title       = rule.get("title", ""),
            plane       = rule.get("plane", ""),
            section     = rule.get("section", ""),
            severity    = rule.get("severity", "MEDIUM"),
            status      = Status.PASS,
            remediation = (rule.get("remediation") or "").strip(),
            reference   = (rule.get("reference")   or "").strip(),
        )

        # --- 1. Check applicable_if -----------------------------------------
        applicable_if = rule.get("applicable_if")
        if applicable_if and not cfg.has_global(applicable_if):
            result.status  = Status.NOT_APPLICABLE
            result.message = (f"Condition applicable_if «{applicable_if}» "
                              f"not found in config — rule skipped.")
            return result

        # --- 2. Dispatch on check_type --------------------------------------
        check_type = (rule.get("check_type") or "global_regex").lower()
        conditions = rule.get("conditions") or {}

        try:
            handler = {
                "global_regex":     self._check_global_regex,
                "multi_regex":      self._check_multi_regex,
                "regex_absent":     self._check_regex_absent,
                "value_comparison": self._check_value_comparison,
                "block_regex":      self._check_block_regex,
                "block_all":        self._check_block_all,
                "acl_content":      self._check_acl_content,
                "value_count":      self._check_value_count,
            }.get(check_type)

            if handler is None:
                result.status  = Status.ERROR
                result.message = f"Unknown check_type: {check_type!r}"
                return result

            handler(cfg, rule, conditions, result)

        except Exception as exc:                        # pragma: no cover
            result.status  = Status.ERROR
            result.message = f"Evaluation error: {exc}"

        return result

    # ---- check_type handlers ----------------------------------------------

    # --- global_regex -------------------------------------------------------
    def _check_global_regex(self, cfg, rule, conditions, result):
        """
        All patterns in `require` must match somewhere in the config.
        All patterns in `prohibit` must NOT match.
        """
        self._apply_require_prohibit(cfg.raw_text, conditions, result)

    # --- multi_regex --------------------------------------------------------
    def _check_multi_regex(self, cfg, rule, conditions, result):
        """
        Same as global_regex plus supports `require_one_of`:
        at least one pattern in the list must match.
        """
        self._apply_require_prohibit(cfg.raw_text, conditions, result)

        require_one = conditions.get("require_one_of", [])
        if require_one and result.status != Status.FAIL:
            matched_any = False
            details: List[CheckDetail] = []
            for entry in require_one:
                pat  = entry.get("pattern", "")
                desc = entry.get("description", pat)
                m    = re.search(pat, cfg.raw_text, re.IGNORECASE | re.MULTILINE)
                hit  = bool(m)
                if hit:
                    matched_any = True
                details.append(CheckDetail(
                    pattern     = pat,
                    description = desc,
                    matched     = hit,
                    match_text  = m.group(0).strip() if m else "",
                ))
            result.details.extend(details)
            if not matched_any:
                result.status  = Status.FAIL
                result.message = "None of the require_one_of patterns matched."

    # --- regex_absent -------------------------------------------------------
    def _check_regex_absent(self, cfg, rule, conditions, result):
        """A pattern must be absent from the entire config."""
        for entry in conditions.get("absent", []):
            pat  = entry.get("pattern", "")
            desc = entry.get("description", pat)
            m    = re.search(pat, cfg.raw_text, re.IGNORECASE | re.MULTILINE)
            hit  = bool(m)
            result.details.append(CheckDetail(
                pattern     = pat,
                description = desc,
                matched     = not hit,   # found = bad
                match_text  = m.group(0).strip() if m else "",
            ))
            if hit:
                result.status = Status.FAIL
                result.message = f"Forbidden pattern found: {pat!r}"

    # --- value_comparison ---------------------------------------------------
    def _check_value_comparison(self, cfg, rule, conditions, result):
        """
        Extract a numeric (or string) value and compare it.

        Supports two field-name conventions (YAML compat):
          extract_pattern / expected_value / operator (ge/le/gt/lt/eq/ne)
          extract         / threshold      / operator (>=/<=/>/</==/!=)
        """
        # Support both field naming conventions
        extract_pat = (conditions.get("extract_pattern")
                       or conditions.get("extract", ""))
        expected    = (conditions.get("expected_value")
                       if conditions.get("expected_value") is not None
                       else conditions.get("threshold"))
        desc        = conditions.get("description", extract_pat)

        # Normalise operator: accept both symbolic and word forms
        raw_op = str(conditions.get("operator", "ge")).strip()
        op_map = {
            ">=": "ge", "<=": "le", ">": "gt", "<": "lt",
            "==": "eq", "!=": "ne", "=": "eq",
        }
        operator = op_map.get(raw_op, raw_op.lower())

        m = re.search(extract_pat, cfg.raw_text, re.IGNORECASE | re.MULTILINE)
        if not m:
            result.status = Status.FAIL
            result.details.append(CheckDetail(
                pattern=extract_pat, description=desc, matched=False))
            result.message = f"Pattern not found: {extract_pat!r}"
            return

        raw_val = m.group(1) if m.lastindex else m.group(0)

        # Try numeric comparison
        try:
            actual   = float(raw_val)
            expected = float(expected)
            ops = {
                "gt": actual > expected,
                "lt": actual < expected,
                "ge": actual >= expected,
                "le": actual <= expected,
                "eq": actual == expected,
                "ne": actual != expected,
            }
            passed = ops.get(operator, False)
        except (TypeError, ValueError):
            # String equality fallback
            passed = str(raw_val).lower() == str(expected).lower()

        result.details.append(CheckDetail(
            pattern     = extract_pat,
            description = desc,
            matched     = passed,
            match_text  = raw_val,
        ))
        if not passed:
            result.status  = Status.FAIL
            result.message = (f"Value {raw_val!r} does not satisfy "
                              f"{operator} {expected}")

    # --- block_regex --------------------------------------------------------
    def _check_block_regex(self, cfg, rule, conditions, result):
        """
        Find a single block matching context.block pattern,
        then run require / prohibit checks inside it.
        """
        ctx          = rule.get("context") or {}
        block_pat    = ctx.get("block", "")
        all_instances = ctx.get("all_instances", False)

        blocks = cfg.get_blocks_matching(block_pat)
        if not blocks:
            result.status  = Status.FAIL
            result.message = f"Block matching «{block_pat}» not found."
            result.details.append(CheckDetail(
                pattern=block_pat, description="Block header",
                matched=False))
            return

        text = "\n".join(b.full_text for b in (blocks if all_instances
                                                else [blocks[0]]))
        self._apply_require_prohibit(text, conditions, result)

    # --- block_all ----------------------------------------------------------
    def _check_block_all(self, cfg, rule, conditions, result):
        """
        Find ALL blocks matching context.blocks patterns and verify each
        one individually contains the required patterns.
        """
        ctx       = rule.get("context") or {}
        patterns  = ctx.get("blocks") or [ctx.get("block", "")]
        require   = conditions.get("require",  [])
        prohibit  = conditions.get("prohibit", [])

        all_blocks: List = []
        for pat in patterns:
            all_blocks.extend(cfg.get_blocks_matching(pat))

        if not all_blocks:
            result.status  = Status.NOT_APPLICABLE
            result.message = "No matching blocks found — rule not applicable."
            return

        failed_blocks: List[str] = []

        for block in all_blocks:
            block_fail = False
            for entry in require:
                pat  = entry.get("pattern", "")
                desc = entry.get("description", pat)
                hit  = bool(re.search(pat, block.full_text,
                                      re.IGNORECASE | re.MULTILINE))
                result.details.append(CheckDetail(
                    pattern     = pat,
                    description = f"[{block.header[:50]}] {desc}",
                    matched     = hit,
                    match_text  = block.header,
                ))
                if not hit:
                    block_fail = True

            for entry in prohibit:
                pat  = entry.get("pattern", "")
                desc = entry.get("description", pat)
                m    = re.search(pat, block.full_text,
                                 re.IGNORECASE | re.MULTILINE)
                hit  = bool(m)
                result.details.append(CheckDetail(
                    pattern     = pat,
                    description = f"[{block.header[:50]}] PROHIBIT: {desc}",
                    matched     = not hit,
                    match_text  = m.group(0).strip() if m else "",
                ))
                if hit:
                    block_fail = True

            if block_fail:
                failed_blocks.append(block.header)

        if failed_blocks:
            result.status  = Status.FAIL
            result.message = (f"{len(failed_blocks)} block(s) failed: "
                              + "; ".join(failed_blocks[:5]))

    # --- acl_content --------------------------------------------------------
    def _check_acl_content(self, cfg, rule, conditions, result):
        """
        Find named ACLs by acl_name_pattern and verify required entries
        are present.
        """
        acl_pat      = conditions.get("acl_name_pattern", ".*")
        require_ents = conditions.get("require_entries", [])

        matched_acls = cfg.get_acls_matching(acl_pat)
        if not matched_acls:
            result.status  = Status.FAIL
            result.message = (f"No ACL matching pattern «{acl_pat}» found. "
                              f"Create a named ACL and apply it.")
            return

        # Combine lines of all matching ACLs for pattern matching
        combined = "\n".join(
            "\n".join(lines) for lines in matched_acls.values()
        )

        for entry in require_ents:
            pat  = entry.get("pattern", "")
            desc = entry.get("description", pat)
            m    = re.search(pat, combined, re.IGNORECASE | re.MULTILINE)
            hit  = bool(m)
            result.details.append(CheckDetail(
                pattern     = pat,
                description = desc,
                matched     = hit,
                match_text  = m.group(0).strip() if m else "",
            ))
            if not hit:
                result.status = Status.FAIL
                result.message = f"Required ACL entry not found: {desc}"

    # --- value_count --------------------------------------------------------
    def _check_value_count(self, cfg, rule, conditions, result):
        """
        Count occurrences of a pattern and compare to min/max thresholds.
        """
        pat      = conditions.get("pattern", "")
        min_count = conditions.get("min_count")
        max_count = conditions.get("max_count")
        desc      = conditions.get("description", pat)

        matches = cfg.find_global(pat)
        count   = len(matches)

        passed = True
        if min_count is not None and count < int(min_count):
            passed = False
        if max_count is not None and count > int(max_count):
            passed = False

        result.details.append(CheckDetail(
            pattern     = pat,
            description = desc,
            matched     = passed,
            match_text  = f"found {count} occurrence(s)",
        ))
        if not passed:
            result.status  = Status.FAIL
            result.message = (f"Count {count} outside range "
                              f"[{min_count}, {max_count}]")

    # ---- shared helpers ---------------------------------------------------

    def _apply_require_prohibit(self, text: str,
                                 conditions: Dict,
                                 result: RuleResult) -> None:
        """Apply require / prohibit lists against *text*."""
        for entry in conditions.get("require", []):
            pat  = entry.get("pattern", "")
            desc = entry.get("description", pat)
            m    = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            hit  = bool(m)
            result.details.append(CheckDetail(
                pattern     = pat,
                description = desc,
                matched     = hit,
                match_text  = m.group(0).strip() if m else "",
            ))
            if not hit:
                result.status = Status.FAIL
                result.message = f"Required pattern not found: {desc}"

        for entry in conditions.get("prohibit", []):
            pat  = entry.get("pattern", "")
            desc = entry.get("description", pat)
            m    = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            hit  = bool(m)
            result.details.append(CheckDetail(
                pattern     = pat,
                description = f"PROHIBITED: {desc}",
                matched     = not hit,      # found = bad
                match_text  = m.group(0).strip() if m else "",
            ))
            if hit:
                result.status = Status.FAIL
                result.message = f"Forbidden pattern found: {desc}"
