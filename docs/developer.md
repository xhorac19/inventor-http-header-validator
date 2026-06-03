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
  prompts.md                      # LLM prompt library for external ruleset generation
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

Rules are YAML lists validated against `rules_schema.json` (draft-07) at generation
time by the skill. The analyzer itself does not re-validate YAML against the schema at
load time — it only parses the fields it knows about and raises `ValueError` on
structural problems it detects (duplicates, unknown dependency IDs, cycles).

### Constraint evaluation order

When writing rules that check a header's value, always pair them with a `_missing`
guard rule:

```yaml
# 1. The guard — fires when the header is absent
- header: example-header
  id: example_missing
  severity: WARNING
  notify: true
  info: >
    The Example header is absent. This enables attack X. Set
    "Example: recommended-value".
  constraints:
    exists: false

# 2. The value check — only runs when the header is present
- header: example-header
  id: example_bad_value
  severity: WARNING
  notify: true
  info: >
    The Example header is present but set to an insecure value. This enables
    attack X. Set "Example: recommended-value".
  constraints:
    exists: true
    regex_neg: "(?i)^recommended-value$"
    dependencies:
      - id: example_missing
        activated: false
```

Without the dependency guard, `regex_neg` on an absent header would trivially fire
(there is no value to match), producing a false positive.

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
continues to work correctly even if the user renames or moves `rules_schema.json` or
`prompts.md`. The trade-off is that changes to the schema or constraints must be
manually reflected in the command file.

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

### Planning table syntax

The command file defines fixed column value formats for all planning tables to ensure
consistent output across runs. Column values are constrained to enumerated tokens
rather than free-form prose, making successive plans directly comparable.

### Relationship to `docs/prompts.md`

`docs/prompts.md` contains the same constraints and use-case prompts formatted for use
with external LLMs (e.g. ChatGPT, API calls). It is the human-facing companion to the
command file. The two documents serve the same purpose in different contexts and should
be kept in sync when constraints change. The command file is authoritative for the
Claude Code skill; `docs/prompts.md` is authoritative for external LLM usage.
