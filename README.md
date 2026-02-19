# Cisco IOS / IOS-XE Security Configuration Assessment Tool

Offline security audit tool for Cisco IOS/IOS-XE devices based on the
[Cisco Harden IOS/IOS-XE Devices Guide](https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html).

---

## Quick Start

**Step 1 — Export your Cisco config** (on the device):
```
show running-config
```
Copy the output and save it as a `.txt` file, e.g. `myrouter.txt`, in the project folder.

**Step 2 — Install the dependency:**
```bash
pip install -r requirements.txt
```

**Step 3 — Run the audit:**
```bash
python main.py myrouter.txt --format html --output output/report.html --hostname MY-ROUTER
```

**Step 4 — Open the report:**

The file `output/report.html` will be generated — open it in any browser to see the full compliance dashboard with score, pass/fail results, and remediation steps.

---

## Overview

This tool analyses a `show running-config` text file and evaluates it against
a library of YAML rules covering the three Cisco security planes:

| Plane | Rules | Focus |
|---|---|---|
| Management Plane | ~39 | Passwords, SSH, AAA, SNMP, Logging, NTP |
| Control Plane | ~12 | CoPP, BGP/IGP authentication, FHRP |
| Data Plane | ~12 | uRPF, ACLs, anti-spoofing, NetFlow |

## Project Structure

```
config-assessment-tool/
├── cisco/
│   ├── __init__.py
│   ├── cisco_parser.py          # Parses show running-config
│   ├── evaluator.py             # Rule engine (8 check types)
│   ├── reporter.py              # HTML + JSON report generator
│   ├── rules/
│   │   ├── management_plane.yaml
│   │   ├── control_plane.yaml
│   │   └── data_plane.yaml
│   ├── samples/
│   │   └── sample_running_config.txt
│   └── tests/
│       ├── test_cisco_parser.py
│       └── test_evaluator.py
├── output/
│   ├── report.html              # Generated HTML report
│   └── report.json              # Generated JSON report
├── main.py                      # CLI entry point
├── requirements.txt
└── README.md
```

## Installation

```bash
pip install -r requirements.txt
```

**Requirements:** Python 3.10+ · pyyaml >= 6.0

## Usage

### Basic usage — generate HTML report

```bash
python main.py cisco/samples/sample_running_config.txt --format html --output output/report.html
```

### JSON report

```bash
python main.py cisco/samples/sample_running_config.txt --format json --output output/report.json
```

### Terminal output (coloured)

```bash
python main.py cisco/samples/sample_running_config.txt --format text
```

### Filter by plane or severity

```bash
python main.py router.txt --plane management --severity CRITICAL HIGH
```

### Show only failures

```bash
python main.py router.txt --fail-only
```

## CLI Reference

```
usage: main.py <config_file> [options]

positional:
  config_file            Path to show running-config text file

options:
  --rules DIR            Rules directory (default: cisco/rules)
  --hostname NAME        Override device hostname in report
  --format html|json|text  Output format (default: html)
  --output FILE          Output file path
  --plane PLANE          Filter: management | control | data
  --severity SEV [SEV…]  Filter: CRITICAL HIGH MEDIUM LOW
  --fail-only            Show only FAIL results
```

## Rule Format

Each YAML rule uses the following structure:

```yaml
- id: CISCO-MGT-SSH-001
  title: "SSHv2 must be enabled"
  plane: management
  section: Management Plane
  subsection: Secure Interactive Management Sessions
  severity: CRITICAL
  check_type: global_regex
  conditions:
    require:
      - pattern: "ip ssh version 2"
        description: "SSHv2 directive present"
    prohibit:
      - pattern: "transport input telnet"
        description: "Telnet must not be allowed"
  remediation: "Configure: ip ssh version 2"
  reference: "Cisco Harden IOS-XE - SSHv2"
```

### Supported `check_type` values

| check_type | Description |
|---|---|
| `global_regex` | require / prohibit patterns in the full config |
| `multi_regex` | Same + `require_one_of` groups |
| `regex_absent` | Pattern must NOT appear in config |
| `value_comparison` | Extract a number and compare (>=, <=, >, <, ==, !=) |
| `block_regex` | Check patterns inside a specific config block |
| `block_all` | Check patterns in ALL matching blocks (e.g. every interface) |
| `acl_content` | Named ACL must contain specific entries |
| `value_count` | Count pattern occurrences vs min/max threshold |

## Compliance Statuses

| Status | Meaning |
|---|---|
| ✅ PASS | Rule is satisfied |
| ❌ FAIL | Rule violated or command absent |
| ⚠️ WARN | Partial match or indeterminate |
| ⬜ NOT_APPLICABLE | Rule does not apply to this device |
| 🔴 ERROR | Evaluation error (bad rule syntax) |

## Running Tests

```bash
# Install pytest first
pip install pytest

# Run all tests
python -m pytest cisco/tests/ -v

# With coverage
pip install pytest-cov
python -m pytest cisco/tests/ -v --cov=cisco --cov-report=term-missing
```

Expected coverage: **>= 80%**

## Extending Rules

To add new rules, create or edit YAML files in `cisco/rules/`.
No Python changes are needed — the engine loads all `.yaml` files from the
rules directory automatically.

## Reference

- Cisco Systems, *Harden IOS/IOS-XE Devices* — https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html
- CIS Cisco IOS XE Benchmark
- ANSSI — Recommandations de sécurité pour les architectures réseau
