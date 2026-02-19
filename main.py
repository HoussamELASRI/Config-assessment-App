"""
main.py
=======
Entry point for the Cisco IOS/IOS-XE Configuration Assessment Tool.

Usage
-----
    python main.py <config_file> [options]

Examples
--------
    python main.py router.txt
    python main.py router.txt --format html --output report.html
    python main.py router.txt --format json --output report.json
    python main.py router.txt --format text
    python main.py router.txt --hostname ROUTER-CORE-01 --rules cisco/rules
    python main.py router.txt --plane management
    python main.py router.txt --severity CRITICAL HIGH
"""

import argparse
import sys
import os

# Force UTF-8 output on Windows (handles ≤, —, ✔, ✘ etc.)
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

from cisco.cisco_parser import CiscoConfigParser
from cisco.evaluator    import RuleEvaluator, Status
from cisco.reporter     import Reporter


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Cisco IOS/IOS-XE Security Configuration Assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "config_file",
        help="Path to the Cisco running-config text file.",
    )
    p.add_argument(
        "--rules", default="cisco/rules",
        metavar="DIR",
        help="Directory containing YAML rule files (default: cisco/rules).",
    )
    p.add_argument(
        "--hostname", default=None,
        metavar="NAME",
        help="Device hostname to display in the report.",
    )
    p.add_argument(
        "--format", choices=["html", "json", "text"], default="html",
        dest="fmt",
        help="Output format (default: html).",
    )
    p.add_argument(
        "--output", default=None,
        metavar="FILE",
        help="Output file path. Defaults to <config_file>.<format>.",
    )
    p.add_argument(
        "--plane",
        choices=["management", "control", "data"],
        default=None,
        help="Evaluate only rules for this plane.",
    )
    p.add_argument(
        "--severity", nargs="+",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=None,
        metavar="SEV",
        help="Filter results to these severity levels only.",
    )
    p.add_argument(
        "--fail-only", action="store_true",
        help="Show only FAIL results in the report.",
    )
    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def extract_hostname(raw_text: str) -> str:
    """Try to extract hostname from config."""
    import re
    m = re.search(r"^hostname\s+(\S+)", raw_text, re.IGNORECASE | re.MULTILINE)
    return m.group(1) if m else "Unknown"


def print_summary(results) -> None:
    """Print a quick summary to stdout."""
    from collections import Counter
    counts = Counter(r.status for r in results)
    total  = len(results)
    scored = total - counts[Status.NOT_APPLICABLE]
    score  = round(counts[Status.PASS] / max(1, scored) * 100, 1)

    print()
    print("=" * 60)
    print(f"  COMPLIANCE SCORE  :  {score}%")
    print(f"  Total evaluated   :  {total}")
    print(f"  PASS              :  {counts[Status.PASS]}")
    print(f"  FAIL              :  {counts[Status.FAIL]}")
    print(f"  WARN              :  {counts[Status.WARN]}")
    print(f"  NOT APPLICABLE    :  {counts[Status.NOT_APPLICABLE]}")
    print(f"  ERROR             :  {counts[Status.ERROR]}")
    print("=" * 60)

    # List failures
    failures = [r for r in results if r.status == Status.FAIL]
    if failures:
        print(f"\n  FAILED RULES ({len(failures)}):")
        for r in failures:
            print(f"    [{r.severity:<8}] {r.rule_id}  —  {r.title}")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    args = build_parser().parse_args()

    # --- Validate inputs ---------------------------------------------------
    if not os.path.isfile(args.config_file):
        print(f"[ERROR] Config file not found: {args.config_file}", file=sys.stderr)
        return 1

    if not os.path.isdir(args.rules):
        print(f"[ERROR] Rules directory not found: {args.rules}", file=sys.stderr)
        return 1

    # --- Parse config ------------------------------------------------------
    print(f"[*] Parsing config : {args.config_file}")
    parser = CiscoConfigParser()
    cfg    = parser.parse_file(args.config_file)

    hostname = args.hostname or extract_hostname(cfg.raw_text)
    print(f"[*] Hostname       : {hostname}")
    print(f"[*] Blocks parsed  : {len(cfg.blocks)}")
    print(f"[*] Interfaces     : {len(cfg.interfaces)}")
    print(f"[*] Named ACLs     : {len(cfg.acls)}")

    # --- Evaluate ----------------------------------------------------------
    print(f"[*] Loading rules  : {args.rules}")
    evaluator = RuleEvaluator()
    results   = evaluator.evaluate_all(cfg, rules_dir=args.rules)
    print(f"[*] Rules checked  : {len(results)}")

    # --- Filter results ----------------------------------------------------
    if args.plane:
        results = [r for r in results if r.plane == args.plane]
    if args.severity:
        results = [r for r in results if r.severity in args.severity]
    if args.fail_only:
        results = [r for r in results
                   if r.status in (Status.FAIL, Status.ERROR)]

    # --- Console summary ---------------------------------------------------
    print_summary(results)

    # --- Generate report ---------------------------------------------------
    output = args.output or (
        os.path.splitext(args.config_file)[0] + f"_report.{args.fmt}"
    )

    reporter = Reporter(results, hostname=hostname)

    if args.fmt == "text":
        # Print to stdout and optionally save
        text = reporter.render_text()
        print(text)
        if args.output:
            with open(output, "w", encoding="utf-8") as fh:
                # Strip ANSI for file output
                import re
                fh.write(re.sub(r"\033\[[0-9;]*m", "", text))
            print(f"[*] Text report saved → {output}")
    else:
        reporter.save(output, fmt=args.fmt)
        print(f"[*] Report saved   : {output}")

    return 0 if all(r.status != Status.FAIL for r in results) else 2


if __name__ == "__main__":
    sys.exit(main())
