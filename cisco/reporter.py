"""
reporter.py
===========
Generate audit reports from a list of RuleResult objects.

Output formats
--------------
  text  — ANSI-coloured console summary + per-rule details
  json  — machine-readable JSON
  html  — self-contained HTML with a styled table and summary cards

Usage
-----
    from reporter import Reporter
    r = Reporter(results)
    r.save("report.html", fmt="html")
    r.save("report.json", fmt="json")
    print(r.render_text())
"""

import json
import os
from collections import Counter
from datetime import datetime
from typing import List

from .evaluator import RuleResult, Status

# ---------------------------------------------------------------------------
# ANSI colour helpers (text output)
# ---------------------------------------------------------------------------

_ANSI = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "red":    "\033[91m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "gray":   "\033[90m",
    "white":  "\033[97m",
}

def _c(text: str, *styles: str) -> str:
    """Wrap *text* with ANSI codes if stdout supports colour."""
    if not _supports_colour():
        return text
    codes = "".join(_ANSI.get(s, "") for s in styles)
    return f"{codes}{text}{_ANSI['reset']}"

def _supports_colour() -> bool:
    import sys
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

# Status → (ANSI style, HTML colour class)
_STATUS_STYLE = {
    Status.PASS:           ("green",  "pass"),
    Status.FAIL:           ("red",    "fail"),
    Status.WARN:           ("yellow", "warn"),
    Status.NOT_APPLICABLE: ("gray",   "na"),
    Status.ERROR:          ("cyan",   "error"),
}

# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

class Reporter:
    """
    Parameters
    ----------
    results  : list of RuleResult from RuleEvaluator
    hostname : optional device hostname to show in the report header
    """

    def __init__(self, results: List[RuleResult],
                 hostname: str = "Unknown Device") -> None:
        self.results  = results
        self.hostname = hostname
        self.ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---- public -----------------------------------------------------------

    def save(self, filepath: str, fmt: str = "html") -> None:
        """Write the report to *filepath* in the given *fmt*."""
        content = {
            "html": self.render_html,
            "json": self.render_json,
            "text": self.render_text,
        }.get(fmt.lower(), self.render_html)()

        mode = "w" if fmt.lower() != "json" else "w"
        with open(filepath, mode, encoding="utf-8") as fh:
            fh.write(content)
        print(f"[reporter] Saved {fmt.upper()} report → {filepath}")

    # ---- text -------------------------------------------------------------

    def render_text(self) -> str:
        lines: List[str] = []
        SEP = "─" * 72

        # Header
        lines += [
            "",
            _c(SEP, "cyan"),
            _c(f"  CISCO IOS/IOS-XE Security Assessment", "bold", "white"),
            _c(f"  Device  : {self.hostname}", "white"),
            _c(f"  Date    : {self.ts}", "white"),
            _c(SEP, "cyan"),
        ]

        # Summary
        counts = Counter(r.status for r in self.results)
        total  = len(self.results)
        lines += [
            "",
            _c("  SUMMARY", "bold"),
            f"  Total rules evaluated : {total}",
            _c(f"  ✔  PASS            : {counts[Status.PASS]}",  "green"),
            _c(f"  ✘  FAIL            : {counts[Status.FAIL]}",  "red"),
            _c(f"  ⚠  WARN            : {counts[Status.WARN]}",  "yellow"),
            _c(f"  –  NOT APPLICABLE  : {counts[Status.NOT_APPLICABLE]}", "gray"),
            _c(f"  ?  ERROR           : {counts[Status.ERROR]}",  "cyan"),
            "",
            _c(SEP, "cyan"),
        ]

        # Per-plane breakdown
        by_plane = {}
        for r in self.results:
            by_plane.setdefault(r.plane, []).append(r)

        lines.append(_c("  RESULTS BY PLANE", "bold"))
        lines.append("")

        for plane, plane_results in sorted(by_plane.items()):
            pc = Counter(r.status for r in plane_results)
            lines.append(
                _c(f"  [{plane.upper()} PLANE]", "bold", "blue") +
                f"  pass={pc[Status.PASS]}  fail={pc[Status.FAIL]}"
                f"  warn={pc[Status.WARN]}  n/a={pc[Status.NOT_APPLICABLE]}"
            )
            for r in plane_results:
                style, _ = _STATUS_STYLE.get(r.status, ("white", ""))
                tag      = f"[{r.status.value:<14}]"
                sev      = f"[{r.severity:<8}]"
                lines.append(
                    _c(f"    {tag}", style) +
                    _c(f" {sev}", "gray") +
                    f" {r.rule_id}  {r.title}"
                )
                if r.status in (Status.FAIL, Status.ERROR) and r.message:
                    lines.append(_c(f"             → {r.message}", "red"))
                if r.status == Status.FAIL and r.remediation:
                    lines.append(
                        _c("             Remediation:", "yellow") +
                        f"\n" +
                        "\n".join(
                            f"               {ln}"
                            for ln in r.remediation.splitlines()[:6]
                        )
                    )
            lines.append("")

        lines.append(_c(SEP, "cyan"))
        return "\n".join(lines)

    # ---- json -------------------------------------------------------------

    def render_json(self) -> str:
        def _serialise(r: RuleResult) -> dict:
            return {
                "id":         r.rule_id,
                "title":      r.title,
                "plane":      r.plane,
                "section":    r.section,
                "severity":   r.severity,
                "status":     r.status.value,
                "message":    r.message,
                "remediation": r.remediation,
                "reference":  r.reference,
                "details": [
                    {
                        "pattern":     d.pattern,
                        "description": d.description,
                        "matched":     d.matched,
                        "match_text":  d.match_text,
                    }
                    for d in r.details
                ],
            }

        counts = Counter(r.status for r in self.results)
        payload = {
            "meta": {
                "device":    self.hostname,
                "timestamp": self.ts,
                "total":     len(self.results),
                "pass":      counts[Status.PASS],
                "fail":      counts[Status.FAIL],
                "warn":      counts[Status.WARN],
                "na":        counts[Status.NOT_APPLICABLE],
                "error":     counts[Status.ERROR],
            },
            "results": [_serialise(r) for r in self.results],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    # ---- html -------------------------------------------------------------

    def render_html(self) -> str:
        counts    = Counter(r.status for r in self.results)
        total     = len(self.results)
        score_pct = round(counts[Status.PASS] /
                          max(1, total - counts[Status.NOT_APPLICABLE])
                          * 100, 1)

        rows = "\n".join(self._html_row(r) for r in self.results)

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Cisco Audit — {self.hostname}</title>
  <style>
    :root {{
      --cisco-blue  : #049FD9;
      --cisco-dark  : #005073;
      --pass-bg     : #d4edda; --pass-txt : #155724;
      --fail-bg     : #f8d7da; --fail-txt : #721c24;
      --warn-bg     : #fff3cd; --warn-txt : #856404;
      --na-bg       : #e9ecef; --na-txt   : #6c757d;
      --error-bg    : #cce5ff; --error-txt: #004085;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #f4f7fb; color: #212529;
      padding: 2rem;
    }}
    h1 {{ color: var(--cisco-dark); margin-bottom: .3rem; }}
    .meta {{ color: #6c757d; font-size: .9rem; margin-bottom: 2rem; }}

    /* --- summary cards --- */
    .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
    .card {{
      flex: 1 1 120px; min-width: 110px;
      border-radius: 8px; padding: 1rem 1.2rem;
      text-align: center; box-shadow: 0 2px 6px rgba(0,0,0,.08);
    }}
    .card-num  {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
    .card-lbl  {{ font-size: .75rem; text-transform: uppercase;
                  letter-spacing: .05em; margin-top: .3rem; }}
    .c-pass  {{ background: var(--pass-bg);  color: var(--pass-txt);  }}
    .c-fail  {{ background: var(--fail-bg);  color: var(--fail-txt);  }}
    .c-warn  {{ background: var(--warn-bg);  color: var(--warn-txt);  }}
    .c-na    {{ background: var(--na-bg);    color: var(--na-txt);    }}
    .c-score {{ background: var(--cisco-dark); color: #fff; }}

    /* --- filter bar --- */
    .filters {{
      display: flex; gap: .6rem; flex-wrap: wrap; margin-bottom: 1.2rem;
    }}
    .filters button {{
      border: 1px solid #dee2e6; border-radius: 20px;
      padding: .35rem .9rem; cursor: pointer;
      font-size: .85rem; background: #fff;
      transition: background .15s;
    }}
    .filters button:hover, .filters button.active {{
      background: var(--cisco-blue); color: #fff; border-color: var(--cisco-blue);
    }}
    #search {{
      padding: .35rem .8rem; border: 1px solid #dee2e6;
      border-radius: 20px; font-size: .85rem; min-width: 220px;
    }}

    /* --- table --- */
    .tbl-wrap {{ overflow-x: auto; border-radius: 8px;
                 box-shadow: 0 2px 8px rgba(0,0,0,.1); }}
    table {{ border-collapse: collapse; width: 100%;
             background: #fff; font-size: .88rem; }}
    thead {{ background: var(--cisco-dark); color: #fff; }}
    th, td {{ padding: .6rem .8rem; text-align: left;
              border-bottom: 1px solid #e9ecef; }}
    tr:hover {{ background: #f0f4f8; }}
    tr.hidden {{ display: none; }}

    /* status badges */
    .badge {{
      display: inline-block; padding: .2em .65em;
      border-radius: 20px; font-size: .78rem; font-weight: 600;
    }}
    .PASS  {{ background: var(--pass-bg);  color: var(--pass-txt);  }}
    .FAIL  {{ background: var(--fail-bg);  color: var(--fail-txt);  }}
    .WARN  {{ background: var(--warn-bg);  color: var(--warn-txt);  }}
    .NOT_APPLICABLE {{ background: var(--na-bg); color: var(--na-txt); }}
    .ERROR {{ background: var(--error-bg); color: var(--error-txt); }}

    .sev-CRITICAL {{ color: #721c24; font-weight:700; }}
    .sev-HIGH     {{ color: #856404; font-weight:700; }}
    .sev-MEDIUM   {{ color: #0c5460; }}
    .sev-LOW      {{ color: #6c757d; }}

    /* detail row */
    .detail-row td {{
      background: #fafafa; font-size: .82rem;
      padding: .4rem .8rem .4rem 2.5rem; color: #444;
    }}
    .detail-row code {{
      background: #e9ecef; border-radius: 3px;
      padding: .1em .4em; font-size: .8rem;
    }}
    details summary {{ cursor: pointer; color: var(--cisco-blue); }}

    /* remediation */
    .remediation {{
      background: #fff8e1; border-left: 3px solid #ffc107;
      margin-top: .4rem; padding: .4rem .6rem;
      font-family: monospace; font-size: .8rem;
      white-space: pre-wrap; border-radius: 0 4px 4px 0;
    }}
  </style>
</head>
<body>

<h1>&#128273; Cisco IOS/IOS-XE Security Assessment</h1>
<p class="meta">Device: <strong>{self.hostname}</strong> &nbsp;|&nbsp;
  Generated: {self.ts} &nbsp;|&nbsp; Rules evaluated: {total}</p>

<!-- Summary cards -->
<div class="cards">
  <div class="card c-score">
    <div class="card-num">{score_pct}%</div>
    <div class="card-lbl">Compliance Score</div>
  </div>
  <div class="card c-pass">
    <div class="card-num">{counts[Status.PASS]}</div>
    <div class="card-lbl">Pass</div>
  </div>
  <div class="card c-fail">
    <div class="card-num">{counts[Status.FAIL]}</div>
    <div class="card-lbl">Fail</div>
  </div>
  <div class="card c-warn">
    <div class="card-num">{counts[Status.WARN]}</div>
    <div class="card-lbl">Warn</div>
  </div>
  <div class="card c-na">
    <div class="card-num">{counts[Status.NOT_APPLICABLE]}</div>
    <div class="card-lbl">N/A</div>
  </div>
</div>

<!-- Filters -->
<div class="filters">
  <input id="search" type="text" placeholder="&#128269; Search rule ID or title…" oninput="applyFilters()"/>
  <button class="active" onclick="setFilter('ALL',this)">All</button>
  <button onclick="setFilter('FAIL',this)">&#10007; Fail</button>
  <button onclick="setFilter('PASS',this)">&#10003; Pass</button>
  <button onclick="setFilter('WARN',this)">&#9888; Warn</button>
  <button onclick="setFilter('NOT_APPLICABLE',this)">— N/A</button>
</div>

<!-- Results table -->
<div class="tbl-wrap">
<table id="results-table">
  <thead>
    <tr>
      <th>#</th>
      <th>Rule ID</th>
      <th>Title</th>
      <th>Plane</th>
      <th>Severity</th>
      <th>Status</th>
      <th>Details</th>
    </tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
</div>

<br/><p style="color:#aaa;font-size:.8rem;text-align:center">
  Config Assessment App — Cisco IOS/IOS-XE Hardening Audit
</p>

<script>
  let activeFilter = 'ALL';

  function setFilter(f, btn) {{
    activeFilter = f;
    document.querySelectorAll('.filters button')
      .forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }}

  function applyFilters() {{
    const q = document.getElementById('search').value.toLowerCase();
    document.querySelectorAll('#results-table tbody tr.data-row').forEach(row => {{
      const status = row.dataset.status;
      const text   = row.textContent.toLowerCase();
      const show   = (activeFilter === 'ALL' || status === activeFilter)
                   && (!q || text.includes(q));
      row.classList.toggle('hidden', !show);
      const nxt = row.nextElementSibling;
      if (nxt && nxt.classList.contains('detail-row')) {{
        nxt.classList.toggle('hidden', !show);
      }}
    }});
  }}
</script>
</body>
</html>"""

    # ---- HTML row helper --------------------------------------------------

    def _html_row(self, r: RuleResult) -> str:
        idx = self.results.index(r) + 1
        _, cls = _STATUS_STYLE.get(r.status, ("white", "na"))

        # Build check details
        detail_items = ""
        for d in r.details:
            icon = "✔" if d.matched else "✘"
            ic   = "green" if d.matched else "red"
            snip = (f" → <code>{self._esc(d.match_text[:80])}</code>"
                    if d.match_text else "")
            detail_items += (
                f'<li style="color:{ic}">{icon} '
                f'{self._esc(d.description)}{snip}</li>'
            )

        remediation_html = ""
        if r.status == Status.FAIL and r.remediation:
            remediation_html = (
                f'<div class="remediation">'
                f'{self._esc(r.remediation[:600])}</div>'
            )

        detail_cell = ""
        if r.details or r.message or r.remediation:
            summary_txt = (self._esc(r.message[:120]) if r.message
                           else "Click for details")
            detail_cell = (
                f'<details><summary>{summary_txt}</summary>'
                f'<ul style="margin:.4rem 0 .2rem 1rem">{detail_items}</ul>'
                f'{remediation_html}'
                f'</details>'
            )
        elif r.status == Status.NOT_APPLICABLE:
            detail_cell = f'<span style="color:#aaa">{self._esc(r.message[:100])}</span>'

        return (
            f'<tr class="data-row" data-status="{r.status.value}">'
            f'<td>{idx}</td>'
            f'<td><code>{self._esc(r.rule_id)}</code></td>'
            f'<td>{self._esc(r.title)}</td>'
            f'<td>{self._esc(r.plane.capitalize())}</td>'
            f'<td class="sev-{r.severity}">{r.severity}</td>'
            f'<td><span class="badge {r.status.value}">{r.status.value}</span></td>'
            f'<td>{detail_cell}</td>'
            f'</tr>'
        )

    @staticmethod
    def _esc(text: str) -> str:
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))
