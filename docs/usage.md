# Usage Manual

## Overview

`http_header_validator.py` is a rule-driven HTTP header security analyzer. It reads
JSON-formatted HTTP log entries line by line, evaluates each response's headers against
a set of YAML rules, and emits a notification whenever a header's security posture
changes relative to the previous run for that URL. Results are cached per URL so only
state transitions produce output — a rule firing for the first time, a previously
failing rule starting to pass, or vice versa.

---

## Prerequisites

- Python 3.10 or later
- `pyyaml` and `jsonschema` Python packages installed

---

## Command-line interface

```
python3 http_header_validator.py --rules <file> [<file> ...] [--cache <file>] [--log-file <file>]
```

### Arguments

| Argument | Required | Default | Description |
|---|---|---|---|
| `--rules` | Yes | — | One or more YAML rule files. All files are merged into a single ruleset. Rule IDs must be unique across all files. |
| `--cache` | No | `cache.json` | Path to the JSON cache file. Created automatically on first run. |
| `--log-file` | No | — | Path to a log file to scan. Each line must be a valid JSON log entry. If omitted, the program exits after loading rules. |

### Example invocations

Run against a log file with the OWASP ruleset:

```bash
python3 http_header_validator.py \
  --rules ruleset/owasp.yaml \
  --log-file data/http_logs.json
```

Run with multiple rule files and a custom cache location:

```bash
python3 http_header_validator.py \
  --rules ruleset/owasp.yaml ruleset/custom.yaml \
  --cache /var/cache/http_validator.json \
  --log-file /var/log/http_monitor.jsonl
```

---

## Log file format

Each line of the log file must be a self-contained JSON object. Blank lines are skipped.
The required structure is:

```json
{
  "Meta": {
    "Timestamp": "2026-06-03T12:00:00Z",
    "TestId": "run-001"
  },
  "Config": {
    "target_url": "https://example.com",
    "follow_redirects": true,
    "timeout": 30.0,
    "http_version": 1.1
  },
  "Result": {
    "headers": {
      "strict-transport-security": "max-age=63072000; includeSubDomains",
      "content-type": "text/html; charset=UTF-8",
      "x-frame-options": "DENY"
    }
  }
}
```

| Field | Type | Description |
|---|---|---|
| `Meta.Timestamp` | string | ISO 8601 timestamp of the log entry |
| `Meta.TestId` | string | Identifier for the monitoring run |
| `Config.target_url` | string | The URL that was probed — used as the cache key |
| `Config.follow_redirects` | boolean | Whether redirects were followed |
| `Config.timeout` | number | Request timeout in seconds |
| `Config.http_version` | number | HTTP version used (e.g. `1.1`, `2`) |
| `Result.headers` | object | Map of lowercase header names to their values |

If `Result.headers` is absent, the entry is processed (updating cache) but produces no
output. Entries that fail JSON parsing or schema validation are logged as errors and
skipped.

---

## Output format

Each notification is printed to stdout as a single line:

```
<timestamp> <url> <state> HTTP Header: [<header>] [<value>] [<severity>] [<rule_id>] <info>
```

| Field | Description |
|---|---|
| `<timestamp>` | ISO 8601 timestamp of when the rule was evaluated |
| `<url>` | Target URL from `Config.target_url` |
| `<state>` | `Active` when the rule fired; `Inactive` when it stopped firing |
| `<header>` | HTTP header name |
| `<value>` | Header value, or empty string if the header was absent |
| `<severity>` | `CRITICAL`, `WARNING`, `INFO`, or `NONE` |
| `<rule_id>` | ID of the rule that produced the notification |
| `<info>` | Human-readable description from the rule |

Example output:

```
2026-06-03T12:34:56.123456 https://example.com Active HTTP Header: [strict-transport-security] [] [CRITICAL] [hsts_missing] The Strict-Transport-Security header is absent. ...
2026-06-03T12:34:56.124001 https://example.com Active HTTP Header: [x-frame-options] [] [WARNING] [xfo_missing] The X-Frame-Options header is absent. ...
```

A notification is emitted only when a rule's `active` state differs from the cached
value for that URL. On the first run against a URL every rule that fires will produce
output. On subsequent runs only changes produce output.

---

## The `/generate-ruleset` skill

The project ships a Claude Code skill that automates ruleset creation and maintenance
using an AI model. It is invoked as a slash command inside a Claude Code session.

### Prerequisites

- Claude Code installed and running in the project directory
- The command file present at `.claude/commands/generate-ruleset.md`

### Invocation

```
/generate-ruleset [use-case] [output-path]
```

Both arguments are optional. If omitted, the skill asks for them interactively.

| Argument | Values |
|---|---|
| `use-case` | `from-url` \| `update` \| `endpoint` \| `audit` |
| `output-path` | Path where the generated `.yaml` file should be written |

### Use cases

**`from-url`** — Fetch a best-practices page (e.g. the OWASP HTTP Headers Cheat Sheet)
and generate a ruleset that covers every recommendation found on that page. The model
fetches only the single URL provided and derives rules exclusively from its content.

**`update`** — Compare an existing ruleset against the current content of its source URL
and produce a change plan (add / update / remove / keep per rule). A plan where every
row is `keep` is a valid result — no changes are introduced without evidence from the page.

**`endpoint`** — Generate a ruleset from a JSON snapshot of HTTP response headers
observed on a specific endpoint. Covers both security findings and stability monitoring
(stability rules fire when an expected header value changes).

**`audit`** — Review an existing ruleset against structural and stylistic criteria
(naming, dependency guards, severity assignments, regex style, coverage gaps) and
produce a corrected version.

### Interactive flow

1. The skill asks for any missing inputs (URL, existing YAML path, or headers JSON).
2. If context-dependent rules are found, the skill presents them separately and asks
   whether to provide endpoint context or skip them.
3. The skill enters Claude Code's Plan mode to present the proposed rule list for
   review. The plan can be modified before approval.
4. After plan approval the YAML is generated and written to the output path.

### Example session

```
/generate-ruleset from-url ruleset/my_headers.yaml

> Which URL should I fetch?
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

[Plan mode opens with the proposed rule table]
[User approves]

✓ Written to ruleset/my_headers.yaml — 34 rules covering OWASP HTTP security headers.
```
