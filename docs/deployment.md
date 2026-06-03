# Deployment Manual

## Requirements

| Requirement | Minimum version |
|---|---|
| Python | 3.10 |
| pyyaml | any recent |
| jsonschema | any recent |

Install dependencies:

```bash
pip install pyyaml jsonschema
```

---

## File layout

The minimal set of files needed to run the analyzer:

```
http_header_validator.py   # the analyzer
ruleset/                   # one or more YAML rule files
  owasp.yaml
cache.json                 # created automatically on first run
```

The script has no package structure and no installation step — copy the files to
the target location and run directly with `python3`.

---

## Deploying the analyzer

### 1. Copy the script and ruleset

Place `http_header_validator.py` and the `ruleset/` directory on the target machine.
No build step is required.

### 2. Choose a cache file location

The cache file persists state between runs. Choose a path that:

- Survives process restarts (not `/tmp` unless you want a clean state on reboot)
- Is writable by the process running the analyzer
- Is not shared between monitoring targets that should have independent state

Specify it with `--cache`:

```bash
python3 http_header_validator.py \
  --rules ruleset/owasp.yaml \
  --cache /var/lib/http_validator/cache.json \
  --log-file /var/log/http_monitor.jsonl
```

### 3. Wire it into your HTTP monitoring pipeline

The analyzer expects one JSON log entry per line on stdin or from a file. Feed it the
output of whatever HTTP monitoring tool you use by writing entries in the format
described in the usage manual.

**Continuous log tail** — if your monitoring tool appends to a log file in real time,
run the analyzer as a log processor that tails the file:

```bash
tail -F /var/log/http_monitor.jsonl | while IFS= read -r line; do
  echo "$line" | python3 http_header_validator.py \
    --rules ruleset/owasp.yaml \
    --cache /var/lib/http_validator/cache.json \
    --log-file /dev/stdin
done
```

**Batch processing** — run the analyzer periodically against a rotated log file:

```bash
python3 http_header_validator.py \
  --rules ruleset/owasp.yaml \
  --cache /var/lib/http_validator/cache.json \
  --log-file /var/log/http_monitor.$(date +%Y%m%d).jsonl
```

### 4. Handle output

The analyzer writes notifications to stdout. Route them to your alerting system:

```bash
python3 http_header_validator.py \
  --rules ruleset/owasp.yaml \
  --cache /var/lib/http_validator/cache.json \
  --log-file /var/log/http_monitor.jsonl \
  | tee -a /var/log/http_validator_alerts.log
```

To suppress `CRITICAL`-only noise during initial deployment (the first run against a
URL always notifies), allow one pass to warm the cache before connecting output to
alerting.

---

## Resetting state

To force all rules to re-evaluate from scratch for all URLs, delete or empty the cache
file:

```bash
echo '{}' > /var/lib/http_validator/cache.json
```

To reset state for a single URL only, remove its key from the cache JSON manually.

---

## Deploying the `/generate-ruleset` skill

The skill is a Claude Code custom command. It is used interactively by developers to
generate and maintain rulesets — it is not part of the runtime monitoring pipeline.

### Source file

The canonical skill file is kept at:

```
skill/generate-ruleset.md
```

This is the file to edit when changing skill behaviour. It is a self-contained Markdown
file with YAML frontmatter — no build step is required.

### Prerequisites

- Claude Code 2.x installed (`claude --version` to verify)
- A Claude Code session opened in the project directory

### Installation

Claude Code discovers custom commands from `.claude/commands/` inside the project
directory. Copy the skill file there:

```bash
mkdir -p .claude/commands
cp skill/generate-ruleset.md .claude/commands/generate-ruleset.md
```

If you are working directly from a clone of this repository, the file at
`.claude/commands/generate-ruleset.md` is already present and no copy is needed.

### Verification

Start a Claude Code session in the project directory and type `/generate-ruleset`.
The skill should appear as a recognized command. If it shows "Unknown command", confirm
that `.claude/commands/generate-ruleset.md` exists and that the session was started
from inside the project directory.

### Updating the skill

The command file is self-contained — the JSON schema and all generation constraints are
inlined. To change generation behaviour, edit
`.claude/commands/generate-ruleset.md` directly. Changes take effect in the next
Claude Code session (no restart required within the same session if the file is reloaded).

The file `prompts.md` at the project root is a companion document containing the same
constraints formatted for use with external LLMs outside Claude Code. Keep it in sync
with the command file when making significant constraint changes.
