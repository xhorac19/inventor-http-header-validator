# HTTP Header Security Analyzer

## Overview

`http_header_validator.py` is a rule-driven HTTP header analyzer. It ingests HTTP monitor data, evaluates the response headers found within them against a configurable set of YAML rules, and emits notifications when a header's security posture changes relative to a previous run. Results are cached per URL so only state transitions (a header appearing, disappearing, or changing compliance) produce output.

---

## Architecture

### Components

**1. Rule loading (`load_rules`)**

Rules are read from one or more YAML files and compiled into a `RuleSet`. Each rule is parsed into a `HeaderRule` dataclass, which holds the header name, match constraints, dependency references, severity, and notification flag. Before the ruleset is used, all dependency references are validated and the rules are topologically sorted using Kahn's algorithm so that rules depending on the outcome of other rules are always evaluated after their prerequisites. Regular expressions within the loaded rules are pre-compiled and stored in a `re.Pattern` structure.

**2. Log ingestion (`HTTPLogAnalyzer.ingest_log`)**

The analyzer accepts a raw JSON string representing a single HTTP log entry. The entry is validated against a fixed JSON Schema (`HTTP_LOG_SCHEMA`) that requires `Meta`, `Config`, and `Result` fields. If valid, the headers found in `Result.headers` are forwarded to the header checker.

**3. Header evaluation (`HTTPLogAnalyzer.check_headers`)**

Headers are normalized to lowercase and matched against the ruleset. For each rule, `_evaluate_rule` walks through the rule's constraints in the following order:
 - dependencies
 - existence check
 - positive regex
 - negative regex

It then returns an active or inactive `HTTPHeaderInfo` result. Rules that fire (go active) have their ID recorded in `matched_ids`, which the rules with dependencies can later inspect.

**4. Cache and notification (`HTTPLogAnalyzer._handle_cache`)**

Every result is compared against the on-disk JSON cache keyed by target URL. A result is only appended to the output list when its active/inactive state differs from the cached value *and* the rule has `notify: true`. The cache is written back to disk at the end of each `ingest_log` call.

### Data flow
![dataflow.png](dataflow.png)

### Key classes and dataclasses

| Name | Role |
|---|---|
| `HeaderRule` | Compiled representation of one YAML rule |
| `RuleSet` | Holds rules indexed by header name and rule ID |
| `Dependency` | References another rule's outcome as a prerequisite |
| `HTTPLogAnalyzer` | Stateful analyzer that owns the ruleset and the cache |
| `HTTPHeaderInfo` | A single rule evaluation result, active or inactive |
| `Severity` | Enum: `CRITICAL`, `WARNING`, `INFO` |

### Topological sort

Rules with dependencies must be sorted so they evaluate after their prerequisites. The loader uses Kahn's algorithm on the dependency graph. If a cycle is detected, loading fails with an error listing the involved rule IDs.

```python
# Sort in load_rules()
sorted_rules = _dependency_sort(ruleset.by_id)
for rule in sorted_rules:
    ruleset.by_header.setdefault(rule.header, []).append(rule)
```

### Cache mechanics

The cache is a JSON file keyed by target URL, then by rule ID, storing the last known `active` boolean:

```json
{
  "https://example.com": {
    "headers": {
      "hsts_missing": true,
      "csp_missing": false
    }
  }
}
```

A notification is emitted only when the stored value differs from the current evaluation result. This means the first run against a URL always notifies (no prior state), and subsequent runs notify only on changes.

---

## Rule Syntax

Rules are defined in YAML as a list of objects. Each object configures one rule.

### Full structure

```yaml
- header: <string>          # HTTP header name (case-insensitive)
  id: <string>              # Unique rule identifier
  severity: <string>        # CRITICAL | WARNING | INFO
  notify: <bool>            # Whether to emit output on state change
  info: <string>            # Human-readable description shown in output
  constraints:              # All constraint fields are optional
    exists: <bool>          # true = header must be present; false = must be absent
    regex: <string>         # Rule fires if header value matches this pattern
    regex_neg: <string>     # Rule fires if header value does NOT match this pattern
    dependencies:           # List of prerequisite rule outcomes
      - id: <string>        # ID of the rule that must have been evaluated
        activated: <bool>   # true = that rule must have fired; false = must NOT have fired
```

### Field reference

#### `header`
Mandatory. The HTTP response header this rule inspects. Matching is case-insensitive.

```yaml
header: strict-transport-security
```

#### `id`
Mandatory. A unique string identifier for the rule. Used in dependency references and in the cache. Must be unique across all loaded rule files.

```yaml
id: hsts_missing
```

#### `severity`
Optional. Defaults to `NONE`. Attached to the output object for log information value. Does not affect whether a rule fires. Valid values: `CRITICAL`, `WARNING`, `INFO`.

```yaml
severity: CRITICAL
```

#### `notify`
Optional. Defaults to `false`. Controls whether a state change produces output. Set to `true` for rules you want reported. Rules with `notify: false` still participate in dependency checks and are cached, but their results are never printed.

```yaml
notify: true
```

#### `info`
Optional. Defaults to empty string. A human-readable string included in the output. Explain what the finding means and what action to take.

```yaml
info: >
  Strict-Transport-Security is missing. Browsers will not be instructed
  to exclusively use HTTPS, leaving users vulnerable to downgrade attacks.
```

---

### Constraints

All constraint fields are optional and can be combined. A rule fires (goes **active**) only if every specified constraint is satisfied.

#### `exists`

Checks whether the header is present in the response.

- `exists: true` - the rule fires only if the header **is present**
- `exists: false` - the rule fires only if the header **is absent**

```yaml
# Fires (notifies) when HSTS is missing entirely
- header: strict-transport-security
  id: hsts_missing
  severity: CRITICAL
  notify: true
  constraints:
    exists: false
  info: HSTS header is absent.
```

#### `regex`

A regular expression matched against the header's value. The rule fires only if the value **matches** the pattern. Uses `re.search`, so the pattern does not need to match the full string unless anchored with `^` and `$`.

```yaml
# Fires when Access-Control-Allow-Origin is exactly "*"
constraints:
  exists: true
  regex: "^\\*$"
```

#### `regex_neg`

The inverse of `regex`. The rule fires only if the value **does not match** the pattern. Useful for allowlisting known-good values and firing on anything else.

```yaml
# Fires when X-Frame-Options is present but not DENY or SAMEORIGIN
constraints:
  exists: true
  regex_neg: "(?i)^(DENY|SAMEORIGIN)$"
```

`regex` and `regex_neg` can be combined. Both must pass for the rule to fire.

#### `dependencies`

A list of prerequisite rule outcomes. Before evaluating its own constraints, a rule checks that each dependency has (or has not) fired as required. If any dependency condition is not met, the rule immediately goes inactive.

Each dependency entry has two required fields:

 - `id` - the rule ID to check
 - `activated` - `true` means that rule must have fired; `false` means it must not have fired

```yaml
# Only fires when x-xss-protection IS present (the "missing" rule did not fire)
# and the value is not "0"
- header: x-xss-protection
  id: x_xss_protection_enabled
  severity: CRITICAL
  notify: true
  constraints:
    dependencies:
      - id: x_xss_protection_missing
        activated: false
    regex_neg: "^0$"
  info: >
    X-XSS-Protection is enabled. Set it to 0 or remove it entirely.
```

Because the loader sorts rules topologically, a dependency's outcome is always known before the dependent rule runs. Circular dependencies cause loading to fail.

---

### Constraint evaluation order

When a rule is evaluated, constraints are checked in this fixed order. The rule goes inactive and stops at the first failing check:

 1. **Dependencies** - all `dependency.activated` conditions must match the actual outcomes of referenced rules.
 2. **`exists: true`** - header must be present.
 3. **`exists: false`** - header must be absent. If absent, `regex` and `regex_neg` are skipped (no value to match).
 4. **`regex`** - value must match the pattern.
 5. **`regex_neg`** - value must not match the pattern.

If all checks pass, the rule fires (active). Its ID is added to `matched_ids` so dependent rules can reference it.

---

### Complete examples

**Flag a missing security header:**
```yaml
- header: content-security-policy
  id: csp_missing
  severity: WARNING
  notify: true
  constraints:
    exists: false
  info: Content-Security-Policy is missing.
```

**Flag an information-disclosure header that is present:**
```yaml
- header: x-powered-by
  id: x_powered_by_present
  severity: WARNING
  notify: true
  constraints:
    exists: true
  info: X-Powered-By reveals technology stack details. Remove it.
```

**Flag a header with an invalid value (allowlist approach):**
```yaml
- header: referrer-policy
  id: referrer_policy_missing_or_unsafe
  severity: WARNING
  notify: true
  constraints:
    exists: true
    regex_neg: "(?i)^(no-referrer|no-referrer-when-downgrade|strict-origin|strict-origin-when-cross-origin)$"
  info: Referrer-Policy is set to an insufficiently strict value.
```

**Dependent rule - only fires when a sibling rule did not:**
```yaml
- header: x-xss-protection
  id: x_xss_protection_missing
  severity: WARNING
  notify: true
  constraints:
    exists: false
  info: X-XSS-Protection is absent; explicitly set it to 0.

- header: x-xss-protection
  id: x_xss_protection_enabled
  severity: CRITICAL
  notify: true
  constraints:
    dependencies:
      - id: x_xss_protection_missing
        activated: false   # only runs when the header IS present
    regex_neg: "^0$"       # fires when the value is anything other than "0"
  info: X-XSS-Protection is enabled; this is dangerous. Set to 0.
```

## LLM Rules Generation

Rulesets can be generated and maintained with the help of an LLM. Two paths are available depending on your tooling.

### `/generate-ruleset` — Claude Code skill (recommended)

The project ships a Claude Code slash command that automates the full generation workflow. It handles fetching source pages, building a plan for review, generating rule YAML, and writing the output file.

**Prerequisites**: [Claude Code](https://claude.ai/code) installed and a session opened in this project directory.

**Invocation**:

```
/generate-ruleset [use-case] [output-path]
```

Both arguments are optional — the skill asks for them if not provided.

| Use case | What it does |
|---|---|
| `from-url` | Fetch a best-practices page (e.g. OWASP) and generate a ruleset from its recommendations |
| `update` | Compare an existing ruleset against the current content of its source URL and apply changes |
| `endpoint` | Generate a ruleset from a JSON snapshot of headers observed on a specific endpoint |
| `audit` | Review an existing ruleset for structural issues and coverage gaps, then output a corrected version |

**Interactive flow**:

1. The skill collects any missing inputs (URL, existing YAML path, or headers JSON).
2. If rules that depend on endpoint context are found (e.g. rules that only apply to HTML pages or authenticated endpoints), the skill presents them separately and asks whether to provide context or skip them.
3. The skill opens Claude Code's **Plan mode** showing the proposed rule list as a table. Review it, request changes if needed, then approve.
4. The YAML is generated and written to the output path.

**Example**:

```
/generate-ruleset from-url ruleset/my_rules.yaml
```

The skill source file is at [`skill/generate-ruleset.md`](skill/generate-ruleset.md). It is self-contained — the JSON schema and all generation constraints are embedded directly so it works without any external dependencies. See [`docs/deployment.md`](docs/deployment.md) for installation instructions.

For the full prompt library (suitable for use with any LLM outside Claude Code) see [`prompts.md`](prompts.md).

---

### Manual prompts (any LLM)

The file `rules_schema.json` contains a draft-07 schema that defines the valid structure of a ruleset. Provide it in the LLM context alongside the prompts in [`prompts.md`](prompts.md). The following are quick-reference examples; the full prompt library with structured constraints is in `prompts.md`.

#### System prompt prefix

```
You are a YAML file generator. Your task is to generate a set of YAML rules that are meant to validate HTTP headers on an arbitrary HTTP endpoint. Use the provided JSON draft-07 schema as a guideline on how the rule structure is defined.

[include rules_schema.json]
```

#### OWASP Cheat Sheet Generation
This prompt will generate a new set of rules based on the OWASP HTTP Header Cheat Sheet.
```
Your task is to generate a set of rules that are meant to ensure that an HTTP endpoint adheres to security best practices as written by the OWASP Foundation at HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
```

#### OWASP Cheat Sheet Update

This prompt will update the OWASP rules.

```
Your task is to update the provided YAML ruleset. The ruleset is meant to ensure that an HTTP endpoint adheres to security best practices as written by the OWASP Foundation at HTTP Headers cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html. Make sure the ruleset is up-to-date with current practices. Provide recommendations on improvements of the ruleset. Provide an updated ruleset from the recommendations you found.

[include existing owasp_headers.yml]
```

#### Rules specific for an endpoint

This prompt will generate rules that ensure validity of HTTP headers on a given endpoint, based off of existing list of HTTP headers.

```
Provided below is a set of HTTP headers in a JSON format. Your task is to generate a set of rules that maintain stability and security of these headers. 
Construct rules only for headers that it makes sense to monitor. Provide an explanation for each rule.

[JSON Headers, e.g.: {"x-served-by":"cache-vie6344-vie","x-cache":"hit","x-cache-hits":"0","x-timer":"s1749081863.560052,vs0,ve3"...}]
```

### System Prompt
Used prompts should be prefixed by this string.
```
You are a YAML file generator. Your task is to generate a set of YAML rules that are meant to validate HTTP headers on an arbitrary HTTP endpoint. Use the provided JSON draft-07 schema as a guideline on how the rule structure is defined.

[include rules_schema.json]
```

### User Prompts
Following are few use-cases examples for ruleset generation.

#### OWASP Cheat Sheet Generation
This prompt will generate a new set of rules based on the OWASP HTTP Header Cheet Sheet.
```
Your task is to generate a set of rules that are meant to ensure that an HTTP endpoint adheres to security best practices as written by the OWASP Foundation at HTTP Headers Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
```

#### OWASP Cheat Sheet Update

This prompt will update the OWASP rules.

```
Your task is to update the provided YAML ruleset. The ruleset is meant to ensure that an HTTP endpoint adheres to security best practices as written by the OWASP Foundation at HTTP Headers cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html. Make sure the ruleset is up-to-date with current practices. Provide recommendations on improvements of the ruleset. Provide an updated ruleset from the recommendations you found.

[include existing owasp_headers.yml]
```

#### Rules specific for an endpoint

This prompt will generate rules that ensure validity of HTTP headers on a given endpoint, based off of existing list of HTTP headers.

```
Provided below is a set of HTTP headers in a JSON format. Your task is to generate a set of rules that maintain stability and security of these headers. 
Construct rules only for headers that it makes sense to monitor. Provide an explanation for each rule.

[JSON Headers, e.g.: {"x-served-by":"cache-vie6344-vie","x-cache":"hit","x-cache-hits":"0","x-timer":"s1749081863.560052,vs0,ve3"...}]
```

## Script running

The script file `http_header_validator.py` accepts the following parameters:
 
 - `--rules` - One or more files with YAML rules. At least one file must be provided.
 - `--cache` - A json file for cached states. Defaults to `cache.json`.
 - `--log-file` - Log file to scan.

Example run:
```bash
python3 http_header_validator.py \ 
--rules owasp_headers.yml \ 
--log-file data/http_logs.json \
--cache /tmp/http_validator_cache.json
```
