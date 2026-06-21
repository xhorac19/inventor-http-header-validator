# Developer Manual

## Project structure

```
http_header_validator.py          # entire analyzer — single file, no dependencies beyond stdlib + pyyaml + jsonschema
rules_schema.json                 # JSON Schema (draft-07) for YAML rule files
ruleset/
  owasp.yaml                      # bundled OWASP HTTP Headers ruleset
skill/
  generate-ruleset.md             # canonical source for the Claude Code slash command
.claude/
  commands/
    generate-ruleset.md           # installed copy of skill/generate-ruleset.md (Claude Code reads this)
docs/
  usage.md
  deployment.md
  developer.md
```

The analyzer is intentionally a single self-contained Python file with no internal
package structure.

---

## Codebase overview

### Data classes

| Class | Purpose |
|---|---|
| `Severity` | Enum: `CRITICAL`, `WARNING`, `INFO` |
| `Dependency` | A prerequisite reference: another rule's ID and whether it must have fired |
| `HeaderRule` | Compiled representation of one YAML rule — holds all parsed and pre-compiled fields |
| `RuleSet` | Container with two indexes: `by_header` (header name → ordered list of rules) and `by_id` (rule ID → rule) |
| `HTTPInfo` | Base class for evaluation results; holds URL, timestamp, and active flag |
| `HTTPHeaderInfo` | Concrete result for a single rule evaluation; extends `HTTPInfo` with header name, value, severity, rule ID, and info text |

### Entry points

| Function / Class | Role |
|---|---|
| `load_rules(paths)` | Parses YAML files, validates structure, resolves dependencies, topologically sorts, returns a `RuleSet` |
| `HTTPLogAnalyzer.__init__` | Loads the ruleset and opens (or creates) the cache file |
| `HTTPLogAnalyzer.ingest_log` | Validates one JSON log entry, delegates to `check_headers`, writes the cache |
| `HTTPLogAnalyzer.check_headers` | Evaluates all rules against a header dict, returns changed notifications |
| `main()` | CLI entry point — parses args, builds analyzer, iterates log file lines |

---

## Rule loading pipeline

`load_rules(paths)` runs in four stages:

### 1. YAML parsing

Each file is loaded with `yaml.safe_load`. The top-level value must be a list; any
other type raises `ValueError`. Fields are read and each rule is constructed into a
`HeaderRule` dataclass. Regex strings are compiled with `re.compile` at load time —
this surfaces bad patterns immediately rather than at evaluation time.

### 2. Duplicate ID check

Rule IDs must be globally unique across all loaded files. A duplicate raises
`ValueError` naming the conflicting ID and the file where it was found.

### 3. Dependency reference validation

Before sorting, every dependency reference is checked against `ruleset.by_id`. A
reference to an unknown rule ID raises `ValueError` naming the referencing rule and
the missing ID.

### 4. Topological sort (Kahn's algorithm)

Rules with dependencies must be evaluated after their prerequisites. The sort builds
an in-degree counter and adjacency list from the dependency graph, then repeatedly
pulls zero-in-degree rules into the sorted output. If the sorted list is shorter than
the total rule count, at least one cycle exists — the loader raises `ValueError` listing
the involved rule IDs.

After sorting, `ruleset.by_header` is populated in topological order. This guarantees
that within a single header's rule list, any rule that depends on another rule for the
same header appears after it.

---

## Rule evaluation engine

### `check_headers(headers)`

Normalises all header names to lowercase, then iterates `ruleset.by_header` in
insertion order (which is topological order after loading). For each header:

1. Looks up the header's value in the normalised dict (`None` if absent).
2. Calls `_evaluate_rule` for each rule registered for that header.
3. If the rule fired (`info.active is True`), adds the rule ID to `matched_ids`.
4. Calls `_handle_cache` — if the active state changed and `rule.notify` is `True`,
   appends the result to the output list.

`matched_ids` is a `set[str]` scoped to the current `check_headers` call. It is the
mechanism by which dependent rules know whether their prerequisites fired.

### `_evaluate_rule(rule, value, matched_ids)`

Checks constraints in this fixed order, returning an inactive result at the first
failure:

1. **Dependencies** — for each dependency, checks `(dep.id in matched_ids) == dep.activated`. If not, returns inactive.
2. **`exists: true`** — if set and the header is absent, returns inactive.
3. **`exists: false`** — if set and the header is present, returns inactive.
4. **`regex`** — if set and the value does not match, returns inactive.
5. **`regex_neg`** — if set and the value matches (negated), returns inactive.

If all checks pass, returns an active `HTTPHeaderInfo`.

---

## Cache mechanics

The cache is a JSON file with the structure:

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

The outer key is `Config.target_url`. The inner key is the rule ID. The value is the
last known `active` boolean for that rule on that URL.

`_handle_cache` returns `True` (meaning "notify") in two cases:

- The rule ID is not yet in the cache for this URL (first evaluation — always notify).
- The stored value differs from the current evaluation result (state changed — notify).

In both cases the cache is updated in memory. `write_cache` flushes the entire cache
dict to disk as JSON at the end of each `ingest_log` call.

---

## Writing rules

Rules are YAML objects contained in lists defined by draft-07 schema written in `rules_schema.json`.
The analyzer itself does not re-validate YAML against the schema at load time — it only
parses the fields it knows about and raises `ValueError` on structural problems it detects
(duplicates, unknown dependency IDs, cycles).

### Cross-header dependencies

Dependencies are not limited to the same header. A rule on header B can depend on a
rule on header A, as long as A's rule appears earlier in topological order. This is
used in the bundled ruleset for cases like checking `Content-Type` only when
`Content-Disposition` is also absent.

---

## The `/generate-ruleset` skill

### File and format

The canonical skill source is `skill/generate-ruleset.md`. It is copied to
`.claude/commands/generate-ruleset.md` during installation (see `docs/deployment.md`);
Claude Code reads it from that location. When modifying the skill, edit
`skill/generate-ruleset.md` and re-copy to `.claude/commands/`.
Custom commands are Markdown files with YAML frontmatter. The frontmatter keys used are:

| Key | Purpose |
|---|---|
| `description` | Shown in the skill list and used to auto-trigger the skill |
| `argument-hint` | Displayed in the command palette as a hint for expected arguments |

The Markdown body is the instruction set Claude follows when the command is invoked.
`$ARGUMENTS` is replaced at invocation time with everything the user typed after
`/generate-ruleset`.

### Self-contained design

The command file inlines both the JSON schema and all generation constraints. This
means the skill works without reading any other project files at invocation time and
continues to work correctly even if the user renames or moves `rules_schema.json`.
The trade-off is that changes to the schema or constraints must be manually 
reflected in the command file.

### Execution flow

When `/generate-ruleset` is invoked Claude Code executes the instructions in the
command file in order. The skill is structured in five steps:

```
Step 1 — Determine use case
  ↓  (ask if not in $ARGUMENTS)
Step 2 — Collect inputs
  ↓  (URL / existing YAML / headers JSON, depending on use case)
Step 3 — Phase 1: Plan
  ├── Check for context-dependent rules
  │     ↓  (ask user if any found)
  ├── Build planning table
  └── EnterPlanMode  ←── user reviews and approves here
Step 4 — Phase 2: Generate
  └── Write YAML (applying schema + all generation constraints)
Step 5 — Write output
  └── Write tool → output file
```

### Plan mode integration

Step 3 calls the `EnterPlanMode` tool, which surfaces the planning table in Claude
Code's native plan approval UI. The user can request changes to the table before
approval. `ExitPlanMode` is called implicitly when the user approves; Step 4 then
executes.

This replaces the earlier manual "reply yes to continue" pattern with native UI support,
and provides a clear gate between research (fetching, analysing) and generation
(writing files).

### Context-dependent rules

Before entering Plan mode, Step 3 identifies rules whose applicability depends on
facts not yet provided (e.g. whether the endpoint serves HTML, whether it sets session
cookies). These are split into a separate Conditional rules table and the user is
offered the choice to provide context or skip them. This prevents the model from either
silently omitting valid rules or generating rules that do not apply to the actual
endpoint.

### Generation constraints

The command file defines all constraints inline in the **Generation constraints**
section. These include:

- **Naming convention**: `{header_token}_{finding}` with an abbreviation table for
  well-known headers
- **Dependency pattern**: mandatory `_missing` guard for all value-checking rules
- **Severity and notify rubrics**: decision tables for assigning these fields
- **`info` field format**: exactly three sentences (finding, attack class, remediation
  with example)
- **Regex style**: `(?i)` for case-insensitivity, anchors for exact-value checks, no
  lookaheads or backreferences
- **Self-validation checklist**: run mentally before producing any YAML output

The full text of all constraints is documented in [Generating rulesets with external LLMs](#generating-rulesets-with-external-llms). When constraints change, update both the command file and that section.

### Planning table syntax

The command file defines fixed column value formats for all planning tables to ensure
consistent output across runs. Column values are constrained to enumerated tokens
rather than free-form prose, making successive plans directly comparable.

### Relationship to external LLM usage

The same constraints and use-case prompts used by this skill can be applied manually
with any external LLM. See [Generating rulesets with external LLMs](#generating-rulesets-with-external-llms)
for the full system prompt and per-use-case prompts. The command file is authoritative
for the Claude Code skill; that section is authoritative for external LLM usage.

---

## Generating rulesets with external LLMs

The same two-phase workflow used by the `/generate-ruleset` skill can be run manually
with any LLM that has chat or API access (e.g. ChatGPT, the Anthropic API). This section
provides the system prompt and use-case prompts needed to do so.

### Workflow

Each use case splits work into two phases:

- **Phase 1 (Plan)** — the LLM produces a planning table; review and adjust it before continuing.
- **Phase 2 (Generate)** — the LLM generates YAML from the confirmed plan.

Set the system prompt once per conversation before sending any Phase 1 message. Substitute
all `[PLACEHOLDER]` tokens before sending. For the most deterministic output, set the model
temperature to **0**.

### System prompt

Set this as the system prompt, or prepend it verbatim to your first user message. Replace
the `[include rules_schema.json]` placeholder with the full contents of `rules_schema.json`.

```
You are a YAML file generator. Your task is to generate or update a set of YAML rules for
an HTTP header security analyzer. Each rule is compiled at load time; malformed or logically
inconsistent rules cause runtime errors or false positives. Precision and consistency are required.

The output must be a valid YAML list that conforms to the JSON Schema (draft-07) provided
below. Treat the schema as a hard constraint — any output that fails schema validation is incorrect.

[include rules_schema.json]
```

Append all constraint sections below (through and including the self-validation checklist)
after the schema to complete the system prompt.

#### Naming convention

Rule IDs must follow the pattern `{header_token}_{finding}`.

**`header_token`** — the header name with hyphens replaced by underscores. Use the standard
abbreviation where one exists:

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

**`finding`** — a short descriptor for the specific problem. Use one of: `missing`, `present`,
`invalid_value`, `unsafe_{directive}`, `no_{directive}`, `wildcard`, or a term that names the
exact finding.

Examples: `hsts_missing`, `hsts_max_age_too_low`, `csp_unsafe_inline_script`,
`xcto_not_nosniff`, `cors_wildcard`, `x_powered_by_present`.

#### Dependency pattern — mandatory

Whenever a rule checks a header's *value* (uses `regex`, `regex_neg`, or `exists: true`),
it must be guarded by a `_missing` rule for the same header:

1. First create a rule with `exists: false` and id `{header_token}_missing`.
2. Then create the value-checking rule with `exists: true` and a dependency:
   `id: {header_token}_missing, activated: false`.

Never evaluate a regex against a header that might be absent. The dependency guard prevents
false positives when the header is not present in the response.

#### Severity rubric

| Severity | When to use |
|---|---|
| `CRITICAL` | Absence or misconfiguration directly enables a well-known, easily exploitable attack (XSS, MITM, session hijacking, CSRF). |
| `WARNING` | Weak configuration, missing defence-in-depth, or information disclosure that requires attacker-controlled preconditions to exploit. |
| `INFO` | Advisory only; not directly exploitable. Represents a hygiene or best-practice gap. |

#### Notify rubric

| `notify` | When to use |
|---|---|
| `true` | Severity is `CRITICAL` or `WARNING` **and** the finding is high-confidence, actionable, and not context-dependent. |
| `false` | Severity is `INFO`, the finding is advisory, or the rule's applicability depends on context (e.g. whether the response is HTML, JSON, or binary). |

#### `info` field format

The `info` field must contain exactly **three sentences**:

1. What the finding is — name the header and the missing or invalid condition.
2. Why it matters — name the attack class or risk it enables.
3. The recommended remediation with a concrete example header value in quotes.

#### Regex style

- Use `(?i)` for case-insensitive matching.
- Use `^` and `$` anchors for full-value checks; omit them for substring searches.
- Do not use lookaheads, lookbehinds, or backreferences.
- Prefer simple alternation and character classes over complex constructs.

#### Reference example

The following shows the correct structure for a header that can be either absent or present
with an invalid value:

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

#### Self-validation checklist

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

### Use case 1: Generate ruleset from a best-practices URL

Generates a fresh ruleset from the security recommendations published at a URL
(e.g. the OWASP HTTP Headers Cheat Sheet).

> **Note**: this use case requires a model with web browsing capability. If the model
> cannot fetch URLs, paste the page content directly into the Phase 1 message in place of the URL.

**Phase 1 — Plan**

```
Fetch and read the content of the following URL:

[URL]

Identify every HTTP response header recommendation on that page. For each distinct
finding you will generate a rule for, produce a planning table with one row per rule:

| rule_id | header | finding | severity | notify | constraints used |
|---|---|---|---|---|---|

Do not generate any YAML yet. Wait for my confirmation before proceeding.
```

**Phase 2 — Generate**

```
Generate the complete YAML ruleset for all rules in the confirmed table above.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```

---

### Use case 2: Update an existing ruleset from its source URL

Synchronises an existing ruleset with the current content of the URL it was originally
generated from. Identifies rules to add, update, or remove.

> **Note**: this use case requires a model with web browsing capability.

**Phase 1 — Change plan**

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

**Phase 2 — Updated ruleset**

```
Apply all changes from the confirmed plan and output the complete updated YAML ruleset.
Output the full file — not just the changed rules.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```

---

### Use case 3: Endpoint-specific stability and security ruleset

Generates a ruleset from a snapshot of headers observed on a specific endpoint. Covers
two concerns:

- **Security** — flags misconfigured, missing, or disclosure-prone headers.
- **Stability** — flags headers with well-defined expected values so that unexpected changes are detected.

**Phase 1 — Plan**

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

**Phase 2 — Generate**

```
Generate the complete YAML ruleset for all rules in the confirmed table.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```

---

### Use case 4: Audit and correct an existing ruleset

Reviews an existing ruleset for structural, stylistic, and logical issues — including
naming, dependency guards, severity assignments, regex style, and coverage gaps — then
outputs a corrected version.

**Phase 1 — Findings**

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

**Phase 2 — Corrected ruleset**

```
Apply all fixes from the confirmed findings table and output the complete corrected
YAML ruleset. Add new rules for any coverage gaps identified in the findings.
Output the full file — not just the changed rules.
Apply all constraints from the system prompt without exception.
Output only valid YAML — no prose, no markdown fences, no commentary.
```
