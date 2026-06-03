---
description: Generate or update a YAML ruleset for http_header_validator.py. Supports four use cases: from-url (generate from a best-practices URL), update (sync existing ruleset with its source URL), endpoint (generate from an observed headers snapshot), audit (review and correct an existing ruleset).
argument-hint: "[from-url|update|endpoint|audit] [output-path]"
---

## Arguments

Received arguments: $ARGUMENTS

Parse as `[use-case] [output-path]` where both are optional.

Valid values for `use-case`: `from-url`, `update`, `endpoint`, `audit`.

---

## Ruleset schema

Every rule you generate must conform to this JSON Schema (draft-07). Treat it as a hard
constraint — required fields, disallowed extra properties, allowed enum values, and
the `id`/`header` patterns are all enforced here. Any output that fails validation is
incorrect.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "HTTP Header Ruleset",
  "definitions": {
    "rule_id": {
      "type": "string",
      "minLength": 1,
      "pattern": "^[a-z][a-z0-9_]*$"
    },
    "header": {
      "type": "string",
      "minLength": 1,
      "pattern": "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
    },
    "severity": {
      "type": "string",
      "enum": ["CRITICAL", "WARNING", "INFO"]
    },
    "notify": {
      "type": "boolean"
    },
    "regex_pattern": {
      "type": "string",
      "minLength": 1
    },
    "info": {
      "type": "string",
      "minLength": 1
    },
    "constraints": {
      "type": "object",
      "additionalProperties": false,
      "minProperties": 1,
      "properties": {
        "exists": { "type": "boolean" },
        "regex": { "$ref": "#/definitions/regex_pattern" },
        "regex_neg": { "$ref": "#/definitions/regex_pattern" },
        "dependencies": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object",
            "required": ["id", "activated"],
            "additionalProperties": false,
            "properties": {
              "id": { "$ref": "#/definitions/rule_id" },
              "activated": { "type": "boolean" }
            }
          }
        }
      }
    }
  },
  "type": "array",
  "minItems": 1,
  "items": {
    "type": "object",
    "additionalProperties": false,
    "required": ["header", "id", "severity", "notify", "constraints", "info"],
    "properties": {
      "header":      { "$ref": "#/definitions/header" },
      "id":          { "$ref": "#/definitions/rule_id" },
      "severity":    { "$ref": "#/definitions/severity" },
      "notify":      { "$ref": "#/definitions/notify" },
      "constraints": { "$ref": "#/definitions/constraints" },
      "info":        { "$ref": "#/definitions/info" }
    }
  }
}
```

---

## Generation constraints

Apply these constraints to every rule you generate.

### Naming convention

Rule IDs must follow the pattern `{header_token}_{finding}`.

**`header_token`** — the header name with hyphens replaced by underscores. Use the
standard abbreviation where one exists:

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

**`finding`** — a short descriptor for the specific problem. Use one of: `missing`,
`present`, `invalid_value`, `unsafe_{directive}`, `no_{directive}`, `wildcard`, or
a term that names the exact finding.

Examples: `hsts_missing`, `hsts_max_age_too_low`, `csp_unsafe_inline_script`,
`xcto_not_nosniff`, `cors_wildcard`, `x_powered_by_present`.

### Dependency pattern — mandatory

Whenever a rule checks a header's *value* (uses `regex`, `regex_neg`, or `exists: true`),
it must be guarded by a `_missing` rule for the same header:

1. First create a rule with `exists: false` and id `{header_token}_missing`.
2. Then create the value-checking rule with `exists: true` and a dependency:
   `id: {header_token}_missing, activated: false`.

Never evaluate a regex against a header that might be absent. The dependency guard
prevents false positives when the header is not present in the response.

### Severity rubric

| Severity | When to use |
|---|---|
| `CRITICAL` | Absence or misconfiguration directly enables a well-known, easily exploitable attack (XSS, MITM, session hijacking, CSRF). |
| `WARNING` | Weak configuration, missing defence-in-depth, or information disclosure that requires attacker-controlled preconditions. |
| `INFO` | Advisory only; not directly exploitable. Represents a hygiene or best-practice gap. |

### Notify rubric

| `notify` | When to use |
|---|---|
| `true` | Severity is `CRITICAL` or `WARNING` **and** the finding is high-confidence, actionable, and not context-dependent. |
| `false` | Severity is `INFO`, the finding is advisory, or applicability depends on context (e.g. whether the response is HTML vs JSON). |

### `info` field format

The `info` field must contain exactly **three sentences**:

1. What the finding is — name the header and the missing or invalid condition.
2. Why it matters — name the attack class or risk it enables.
3. The recommended remediation with a concrete example header value in quotes.

### Regex style

- Use `(?i)` for case-insensitive matching.
- Use `^` and `$` anchors for full-value checks; omit them for substring searches.
- Do not use lookaheads, lookbehinds, or backreferences.
- Prefer simple alternation and character classes over complex constructs.

### Reference example

```yaml
- header: x-content-type-options
  id: xcto_missing
  severity: WARNING
  notify: true
  info: >
    The X-Content-Type-Options header is absent. Without it, browsers may perform
    MIME-type sniffing and interpret a response as a different content type than
    declared, enabling MIME-confusion and XSS attacks. Set
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

### Self-validation checklist

Before producing any YAML output, verify every rule against this checklist and fix
all violations:

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
- [ ] The output is valid YAML and passes the schema above.

---

## Planning table syntax

Use these exact value formats in every planning table. Consistent syntax makes plans
comparable across multiple runs. Do not use free-form prose in any column.

**`constraints`** column (used in `from-url`, `endpoint` tables):
Comma-separated tokens in this fixed order, include only those that apply:
`exists:false` | `exists:true` | `regex` | `regex_neg` | `dep:<rule_id>`
Examples: `exists:false` — `exists:true, regex_neg, dep:hsts_missing`

**`action`** column (used in `update` table):
One of exactly: `add` | `update` | `remove` | `keep`

**`reason`** column (used in `update` table), fixed prefix per action:
- `add — <one sentence: what recommendation was found on the page>`
- `update — <field>: <old> → <new>`
- `remove — deprecated` | `remove — superseded by <rule_id>` | `remove — no longer on source`
- `keep — no change`

**`concern`** column (used in `endpoint` table):
One of exactly: `security` | `stability`

**`justification`** column (used in `endpoint` table):
- For security: `security: <attack class>`
- For stability: `stability: expected=<value or pattern>`

**`criterion`** column (used in `audit` table):
One of exactly: `naming` | `dep-guard` | `severity` | `notify` | `info-format` | `regex-style` | `coverage`

---

## Step 1 — Determine use case

If `use-case` was not provided in the arguments, ask the user to choose:

> Which use case do you want to run?
> 1. `from-url` — Generate a fresh ruleset from a best-practices URL (e.g. OWASP)
> 2. `update`   — Sync an existing ruleset with the current content of its source URL
> 3. `endpoint` — Generate a ruleset from a snapshot of headers on a specific endpoint
> 4. `audit`    — Review and correct an existing ruleset

---

## Step 2 — Collect inputs

Gather all required inputs for the chosen use case before starting Phase 1.
Ask for each missing input one at a time.

| Use case   | Required inputs |
|------------|-----------------|
| `from-url` | Source URL |
| `update`   | Source URL; path to the existing YAML file (read it with the Read tool) |
| `endpoint` | Headers JSON — ask the user to paste it, or provide a file path (read with Read tool) |
| `audit`    | Path to the existing YAML file (read it with the Read tool) |

---

## Step 3 — Phase 1: Plan

Build the planning table for the chosen use case (details below). Before entering Plan
mode, check for context-dependent rules (see below). Only enter Plan mode using the
`EnterPlanMode` tool after context-dependent rules are resolved. Do not generate any
YAML before Plan mode is approved.

### Context-dependent rules

While building the plan, identify any rules whose applicability depends on facts about
the monitored endpoint that have not been provided — for example:

- Rules for `Content-Type` charset that only apply to HTML responses
- `Cache-Control: no-store` rules that only apply to authenticated or sensitive endpoints
- CSP rules that only apply to pages serving executable content
- Cookie attribute rules that only apply if the site sets session cookies
- CORS rules whose risk depends on whether the API handles credentials

If any such rules are found:

1. Do not add them to the main plan table.
2. Build a separate **Conditional rules** table:

   | rule_id | header | finding | condition needed |
   |---|---|---|---|

   The `condition needed` column must complete the sentence "This rule applies if…"
   using one of these fixed phrases: `response is HTML` | `endpoint is authenticated` |
   `endpoint sets cookies` | `endpoint serves user-supplied files` |
   `CORS is used with credentials` | `endpoint serves executable content` |
   or a short free-form phrase when none of the above fits.

3. Ask the user before continuing:

   > The following rules depend on context about your endpoint. You can:
   > - Provide details (e.g. "this is an HTML app", "all endpoints require login") and
   >   I will move the applicable rules into the main plan.
   > - Reply `skip` to proceed without them. They will be listed as notes in the plan
   >   but not generated.

4. Wait for the user's response and update the main plan accordingly before entering
   Plan mode.

If no context-dependent rules are found, proceed directly to building the plan and
entering Plan mode.

**For `from-url`**: Use WebFetch to retrieve the full content of the URL. Identify every
HTTP response header recommendation on that page. Build the following table as the plan:

| rule_id | header | finding | severity | notify | constraints used |
|---|---|---|---|---|---|

Rules must be derived exclusively from what is written on the fetched page. Do not
supplement with internal knowledge, prior training, or assumptions about what the source
typically recommends. If a recommendation is not explicitly stated on the page, do not
include it. Fetch only the single URL provided — do not follow links or fetch other pages
autonomously. If a linked page appears necessary, ask the user whether to fetch it.

**For `update`**: Use WebFetch to retrieve the full content of the URL. Compare it against
the existing ruleset. Build the following table as the plan:

Changes must be derived exclusively from what is written on the fetched page. Do not
supplement with internal knowledge, prior training, or assumptions about what the source
typically recommends. If a change is not evidenced by the page content, do not include it.
Fetch only the single URL provided — do not follow links or fetch other pages
autonomously. If a linked page appears necessary, ask the user whether to fetch it.

A plan where every row is `keep` is a correct and complete result. It means the existing
ruleset is already consistent with the source. Do not introduce `add`, `update`, or
`remove` actions to justify the exercise — only use them when the page content explicitly
requires it. When in doubt, use `keep`.

| action | rule_id | reason |
|---|---|---|
| `add` | new_rule_id | Recommendation at the URL not covered by any existing rule. |
| `update` | existing_rule_id | Recommendation changed — describe what changed. |
| `remove` | existing_rule_id | Recommendation removed or superseded at the URL. |
| `keep` | existing_rule_id | No change needed. |

**For `endpoint`**: Analyse the provided headers JSON. Build the following table as the
plan, covering both security findings and stability monitoring (stability rules use
`severity: INFO`, `notify: true`, and fire when the header deviates from its observed
value). Exclude headers with no monitoring value (`date`, `content-length`,
`transfer-encoding`, etc.):

| rule_id | header | concern (security/stability) | finding | severity | notify | justification |
|---|---|---|---|---|---|---|

**For `audit`**: Analyse the provided ruleset against every criterion in the self-validation
checklist. Build the following table as the plan — omit rules that pass all criteria.
Also flag coverage gaps (well-known findings for monitored headers that are entirely absent):

| rule_id | criterion violated | issue | recommended fix |
|---|---|---|---|

---

## Step 4 — Phase 2: Generate

After Plan mode is approved, generate the YAML output.

- `from-url`: output the complete new ruleset.
- `update`: output the full updated file incorporating all add/update/remove actions.
- `endpoint`: output the complete new ruleset.
- `audit`: output the complete corrected file with all violations fixed and gap rules added.

Apply every constraint in the **Generation constraints** section. Run the self-validation
checklist mentally before writing the file. Fix all violations before proceeding.

Output only valid YAML — no prose, no markdown fences, no commentary.

---

## Step 5 — Write output

If `output-path` was not provided in the arguments, ask the user where to save the file.
Suggest `ruleset/` as the default directory.

Write the generated YAML to the specified path using the Write tool.

Confirm with:
- The file path written
- The total number of rules generated
- A one-line summary of what the ruleset covers
