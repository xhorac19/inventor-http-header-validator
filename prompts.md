# HTTP Header Validator – LLM Prompt Library

This file contains prompts for generating and maintaining YAML rulesets consumed by `http_header_validator.py`. The prompts embed structural and stylistic constraints to reduce variability in LLM output.

## How to use

Each use case is split into two phases:

- **Phase 1 (Plan)** — the LLM enumerates what it will generate as a table. Review and correct the plan before continuing.
- **Phase 2 (Generate)** — the LLM generates the YAML based on the confirmed plan.

All use cases share the same **System Prompt**. Set it once per conversation before sending any Phase 1 message.

Substitute all `[PLACEHOLDER]` tokens with your actual values before sending.

For the most deterministic output, set the model temperature to **0**.

---

## System Prompt

Set this as the system prompt, or prepend it verbatim to your first user message.

---

You are a YAML file generator. Your task is to generate or update a set of YAML rules for an HTTP header security analyzer. Each rule is compiled at load time; malformed or logically inconsistent rules cause runtime errors or false positives. Precision and consistency are required.

The output must be a valid YAML list that conforms to the JSON Schema (draft-07) provided below. Treat the schema as a hard constraint — any output that fails schema validation is incorrect.

[include rules_schema.json]

---

### Naming convention

Rule IDs must follow the pattern `{header_token}_{finding}`.

**`header_token`** — the header name with hyphens replaced by underscores. Use the standard abbreviation where one exists:

| Header | Token |
|---|---|
| `strict-transport-security` | `hsts` |
| `content-security-policy` | `csp` |
| `x-content-type-options` | `xcto` |
| `x-frame-options` | `xfo` |
| `cross-origin-opener-policy` | `coop` |
| `cross-origin-embedder-policy` | `coep` |
| `cross-origin-resource-policy` | `corp` |
| `access-control-allow-origin` | `cors` |
| All others | full header name with `-` replaced by `_` |

**`finding`** — a short descriptor for the specific problem. Use one of: `missing`, `present`, `invalid_value`, `unsafe_{directive}`, `no_{directive}`, `wildcard`, or a term that names the exact finding.

Examples: `hsts_missing`, `hsts_max_age_too_low`, `csp_unsafe_inline_script`, `xcto_not_nosniff`, `cors_wildcard`, `x_powered_by_present`.

---

### Dependency pattern — mandatory

Whenever a rule checks a header's *value* (uses `regex`, `regex_neg`, or `exists: true`), it must be guarded by a `_missing` rule for the same header:

1. First create a rule with `exists: false` and id `{header_token}_missing`.
2. Then create the value-checking rule with `exists: true` and a dependency: `id: {header_token}_missing, activated: false`.

Never evaluate a regex against a header that might be absent. The dependency guard prevents false positives when the header is not present in the response.

---

### Severity rubric

| Severity | When to use |
|---|---|
| `CRITICAL` | Absence or misconfiguration directly enables a well-known, easily exploitable attack (XSS, MITM, session hijacking, CSRF). |
| `WARNING` | Weak configuration, missing defence-in-depth, or information disclosure that requires attacker-controlled preconditions to exploit. |
| `INFO` | Advisory only; not directly exploitable. Represents a hygiene or best-practice gap. |

---

### Notify rubric

| `notify` | When to use |
|---|---|
| `true` | Severity is `CRITICAL` or `WARNING` **and** the finding is high-confidence, actionable, and not context-dependent. |
| `false` | Severity is `INFO`, the finding is advisory, or the rule's applicability depends on context (e.g. whether the response is HTML, JSON, or binary). |

---

### `info` field format

The `info` field must contain exactly **three sentences**:

1. What the finding is — name the header and the missing or invalid condition.
2. Why it matters — name the attack class or risk it enables.
3. The recommended remediation with a concrete example header value in quotes.

---

### Regex style

- Use `(?i)` for case-insensitive matching.
- Use `^` and `$` anchors for full-value checks; omit them for substring searches.
- Do not use lookaheads, lookbehinds, or backreferences.
- Prefer simple alternation and character classes over complex constructs.

---

### Reference example

The following shows the correct structure for a header that can be either absent or present with an invalid value. Use it as a structural and stylistic template.

```yaml
- header: x-content-type-options
  id: xcto_missing
  severity: WARNING
  notify: true
  info: >
    The X-Content-Type-Options header is absent. Without it, browsers may
    perform MIME-type sniffing and interpret a response as a different content
    type than declared, enabling MIME-confusion and XSS attacks. Set
    "X-Content-Type-Options: nosniff".
  constraints:
    exists: false

- header: x-content-type-options
  id: xcto_not_nosniff
  severity: WARNING
  notify: true
  info: >
    The X-Content-Type-Options header is present but its value is not "nosniff".
    Only "nosniff" is recognised by browsers; any other value provides no
    MIME-sniffing protection and may be silently ignored. Set it to exactly
    "nosniff".
  constraints:
    exists: true
    regex_neg: "(?i)^\\s*nosniff\\s*$"
    dependencies:
      - id: xcto_missing
        activated: false
```

---

### Self-validation checklist

Before producing any YAML output, verify every rule against this checklist and fix all violations:

- [ ] `id` is unique, matches `^[a-z][a-z0-9_]*$`, and follows the naming convention.
- [ ] `header` is lowercase and uses only hyphens as word separators.
- [ ] `severity` matches the severity rubric for the finding described.
- [ ] `notify` matches the notify rubric.
- [ ] `info` contains exactly three sentences: finding, risk, remediation with a quoted example value.
- [ ] Every regex uses `(?i)` where case-insensitivity is needed.
- [ ] Exact-value patterns use `^` and `$` anchors.
- [ ] No regex uses lookaheads, lookbehinds, or backreferences.
- [ ] Every value-checking rule has a `_missing` dependency with `activated: false`.
- [ ] No rule ID appears more than once.
- [ ] The output is valid YAML and passes the provided JSON Schema.

---

## Use Case 1: Generate ruleset from a best-practices URL

Generates a fresh ruleset from the security recommendations published at a URL (e.g. the OWASP HTTP Headers Cheat Sheet).

> **Note**: this use case requires a model with web browsing capability. If the model cannot fetch URLs, paste the page content directly into the Phase 1 message in place of the URL.

### Phase 1 — Plan

```
Fetch and read the content of the following URL:

[URL]

Identify every HTTP response header recommendation on that page. For each distinct finding you will generate a rule for, produce a planning table with one row per rule:

| rule_id | header | finding | severity | notify | constraints used |
|---|---|---|---|---|---|

Do not generate any YAML yet. Wait for my confirmation before proceeding.
```

### Phase 2 — Generate

```
Generate the complete YAML ruleset for all rules in the confirmed table above.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```

---

## Use Case 2: Update an existing ruleset from its source URL

Synchronises an existing ruleset with the current content of the URL it was originally generated from. Identifies rules to add, update, or remove.

> **Note**: this use case requires a model with web browsing capability.

### Phase 1 — Change plan

```
I have an existing YAML ruleset that was originally generated from the URL below.
Fetch and read the current content of that URL.
Compare it against the existing ruleset and determine what has changed.

Source URL: [URL]

Existing ruleset:

[paste existing YAML here]

Produce a change plan as a table. Do not generate any YAML yet.

| action | rule_id | reason |
|---|---|---|
| `add` | new_rule_id | A recommendation exists at the URL not covered by any existing rule. |
| `update` | existing_rule_id | The recommendation changed — describe what changed. |
| `remove` | existing_rule_id | The recommendation was removed or superseded at the URL. |
| `keep` | existing_rule_id | No change needed. |

Wait for my confirmation before proceeding.
```

### Phase 2 — Updated ruleset

```
Apply all changes from the confirmed plan and output the complete updated YAML ruleset.
Output the full file — not just the changed rules.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```

---

## Use Case 3: Endpoint-specific stability and security ruleset

Generates a ruleset from a snapshot of headers observed on a specific endpoint. Covers two concerns:

- **Security** — flags misconfigured, missing, or disclosure-prone headers.
- **Stability** — flags headers with well-defined expected values so that unexpected changes are detected.

### Phase 1 — Plan

```
The following JSON object contains HTTP response headers captured from an endpoint I want to monitor:

[paste headers JSON here, e.g.: {"strict-transport-security": "max-age=63072000", "x-frame-options": "DENY", ...}]

Generate a planning table for a ruleset that covers two concerns:

1. Security — flag headers that are misconfigured, missing, or expose sensitive information.
   Apply the severity and notify rubrics from the system prompt.

2. Stability — flag headers that have a well-defined expected value so that unexpected
   changes are detected. Stability rules use severity: INFO and notify: true.
   The rule fires when the header deviates from the observed value.

Only include headers where monitoring adds value. Exclude generic infrastructure headers
with no security or stability significance (e.g. `date`, `content-length`,
`transfer-encoding`) unless their value is relevant.

For each rule, produce a planning table:

| rule_id | header | concern (security/stability) | finding | severity | notify | justification |
|---|---|---|---|---|---|---|

Wait for my confirmation before proceeding.
```

### Phase 2 — Generate

```
Generate the complete YAML ruleset for all rules in the confirmed table.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```

---

## Use Case 4: Audit and correct an existing ruleset

Reviews an existing ruleset for structural, stylistic, and logical issues — including naming, dependency guards, severity assignments, regex style, and coverage gaps — then outputs a corrected version.

### Phase 1 — Findings

```
Audit the following YAML ruleset against the constraints in the system prompt.

[paste existing YAML here]

Check every rule against each criterion below. Produce a findings table containing
only rules that violate at least one criterion. If a rule passes all criteria, omit it.

| rule_id | criterion violated | issue | recommended fix |
|---|---|---|---|

Criteria:

1. Naming — does the id follow the {header_token}_{finding} convention?
2. Dependency guard — does every value-checking rule have a _missing dependency
   with activated: false?
3. Severity — does the severity match the rubric for the finding described?
4. Notify — does the notify flag match the notify rubric?
5. Info format — does info contain exactly three sentences (finding, risk, remediation
   with a quoted example value)?
6. Regex style — does each pattern use (?i) where needed? Do exact-value patterns
   use ^ and $ anchors? Are there lookaheads, lookbehinds, or backreferences?
7. Coverage gaps — are there well-known security findings for the monitored headers
   that are entirely absent from the ruleset?

Wait for my confirmation before proceeding.
```

### Phase 2 — Corrected ruleset

```
Apply all fixes from the confirmed findings table and output the complete corrected
YAML ruleset. Add new rules for any coverage gaps identified in the findings.
Output the full file — not just the changed rules.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```
