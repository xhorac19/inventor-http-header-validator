import re
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

import yaml
import jsonschema.exceptions
from jsonschema import validate

logger = logging.getLogger(__name__)

HTTP_LOG_SCHEMA = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "properties": {
        "Meta": {
            "type": "object",
            "properties": {
                "Timestamp": {"type": "string", "minLength": 1},
                "TestId":    {"type": "string", "minLength": 1},
            },
            "required": ["Timestamp", "TestId"],
        },
        "Config": {
            "type": "object",
            "properties": {
                "target_url":       {"type": "string",  "minLength": 1},
                "follow_redirects": {"type": "boolean"},
                "timeout":          {"type": "number"},
                "http_version":     {"type": "number"},
            },
            "required": ["target_url", "follow_redirects", "timeout", "http_version"],
        },
        "Result": {"type": "object"},
    },
    "required": ["Meta", "Config", "Result"],
}

class Severity(Enum):
    CRITICAL = "CRITICAL"
    WARNING  = "WARNING"
    INFO     = "INFO"

@dataclass
class Dependency:
    id:        str   # rule id that must have been evaluated first
    activated: bool  # True = that rule must have fired; False = must NOT have fired

@dataclass
class HeaderRule:
    id:           str
    header:       str                   # lowercased header name
    must_exist:   Optional[bool]        # True = must exist, False = must NOT exist, None = don't care
    regex:        Optional[re.Pattern]  # fires when value matches
    regex_neg:    Optional[re.Pattern]  # fires when value does NOT match
    dependencies: list[Dependency]      # checks another rule's outcome
    notify:       bool
    severity:     Optional[Severity]
    info:         str

@dataclass
class RuleSet:
    by_header: dict[str, list[HeaderRule]] = field(default_factory=dict)
    by_id:     dict[str, HeaderRule]       = field(default_factory=dict)

def _parse_severity(raw: Optional[str]) -> Optional[Severity]:
    if raw is None:
        return None
    try:
        return Severity[raw.upper()]
    except KeyError:
        raise ValueError(f"Unknown severity '{raw}'. Valid values: {[s.name for s in Severity]}")

def _parse_dependency(raw: dict) -> Dependency:
    if not isinstance(raw, dict):
        raise ValueError(
            f"dependency must be a mapping with 'id' and 'activated' keys, got: {raw!r}"
        )
    missing = [k for k in ("id", "activated") if k not in raw]
    if missing:
        raise ValueError(f"dependency is missing required keys: {missing}")
    if not isinstance(raw["activated"], bool):
        raise ValueError(
            f"dependency.activated must be a boolean, got: {raw['activated']!r}"
        )
    return Dependency(id=raw["id"], activated=raw["activated"])

def _parse_dependencies(raw: list[dict]) -> list[Dependency]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(
            f"dependencies must be a list, got: {type(raw)}"
        )
    dependencies = [_parse_dependency(dep) for dep in raw]
    return dependencies

def _dependency_sort(rules: dict[str, HeaderRule]) -> list[HeaderRule]:
    # See Kahn's algorithm

    in_degree: dict[str, int] = {rid: 0 for rid in rules}
    dependents: dict[str, list[str]] = {rid: [] for rid in rules}

    for rule in rules.values():
        if len(rule.dependencies) > 0:
            in_degree[rule.id] += 1
            for dep in rule.dependencies:
                dependents[dep.id].append(rule.id)

    # Start with rules that have no dependency
    queue: list[str] = [rid for rid, deg in in_degree.items() if deg == 0]
    sorted_rules: list[HeaderRule] = []

    while queue:
        rid = queue.pop(0)
        sorted_rules.append(rules[rid])
        for dependent_id in dependents[rid]:
            in_degree[dependent_id] -= 1
            if in_degree[dependent_id] == 0:
                queue.append(dependent_id)

    if len(sorted_rules) != len(rules):
        # Some rules were never reached, they form a cycle
        cycle_ids = [rid for rid, deg in in_degree.items() if deg > 0]
        raise ValueError(
            f"Cycle detected in rule dependencies, involved rule ids: {cycle_ids}"
        )

    return sorted_rules


def load_rules(paths: list[str]) -> RuleSet:
    ruleset = RuleSet()

    for path in paths:
        with open(path) as f:
            raw_yaml = yaml.safe_load(f)

        if not isinstance(raw_yaml, list):
            raise ValueError(f"{path}: expected a YAML list")

        for item in raw_yaml:
            rule_id = item["id"]
            if rule_id in ruleset.by_id:
                raise ValueError(f"Duplicate rule id '{rule_id}' found in {path}")

            header      = item["header"].lower()
            constraints = item.get("constraints", {})

            raw_regex     = constraints.get("regex")
            raw_regex_neg = constraints.get("regex_neg")

            rule = HeaderRule(
                id           = rule_id,
                header       = header,
                must_exist   = constraints.get("exists"),
                regex        = re.compile(raw_regex) if raw_regex else None,
                regex_neg    = re.compile(raw_regex_neg) if raw_regex_neg else None,
                dependencies = _parse_dependencies(constraints.get("dependencies")),
                notify       = item.get("notify", False),
                severity     = _parse_severity(item.get("severity")),
                info         = item.get("info", "").rstrip(),
            )

            ruleset.by_id[rule_id] = rule

    # Validate all dependency references before sorting
    for rule in ruleset.by_id.values():
        for dep in rule.dependencies:
            if dep.id not in ruleset.by_id:
                raise ValueError(
                    f"Rule '{rule.id}' references unknown dependency '{dep.id}'"
                )

    sorted_rules = _dependency_sort(ruleset.by_id)
    for rule in sorted_rules:
        ruleset.by_header.setdefault(rule.header, []).append(rule)

    return ruleset

class HTTPInfo:
    class Type(Enum):
        HEADER = 1

    def __init__(self, timestamp: datetime, url: str, info_type: "HTTPInfo.Type", active: bool):
        self.url        = url
        self.timestamp  = timestamp
        self.event_type = info_type
        self.active     = active

    def __str__(self):
        return f"{self.timestamp.isoformat()} {self.url} {'Active' if self.active else 'Inactive'} "


class HTTPHeaderInfo(HTTPInfo):
    def __init__(self, timestamp: datetime, url: str, active: bool,
                 header: str, value: str, severity: Optional[Severity],
                 key: str, info: str):
        super().__init__(timestamp, url, HTTPInfo.Type.HEADER, active)
        self.header   = header
        self.value    = value
        self.key      = key
        self.info     = info
        self.severity = severity

    def __str__(self):
        sev = self.severity.name if self.severity else "NONE"
        return (
            f"{super().__str__()}"
            f"HTTP Header: [{self.header}] [{self.value}] [{sev}] [{self.key}] {self.info}"
        )

class HTTPLogAnalyzer:
    def __init__(self, ruleset: RuleSet, cache_path: str):
        self.ruleset      = ruleset
        self.ingested_log = None

        if not cache_path.endswith(".json"):
            cache_path += ".json"
        self.cache_path = Path(cache_path)

        if not self.cache_path.exists():
            self.cache_path.write_text(json.dumps({}))
        try:
            with open(cache_path) as f:
                self.cache = json.load(f)
        except json.JSONDecodeError:
            self.cache_path.write_text(json.dumps({}))
            self.cache = {}

    def write_cache(self):
        with self.cache_path.open("w") as f:
            json.dump(self.cache, f)

    def _check_cached_header(self, info: HTTPHeaderInfo) -> bool:
        cached_url = self.cache[self.ingested_log["Config"]["target_url"]]
        cached_url.setdefault("headers", {})
        cached_headers = cached_url["headers"]

        if info.key not in cached_headers:
            cached_headers[info.key] = info.active
            return True

        if cached_headers[info.key] != info.active:
            cached_headers[info.key] = info.active
            return True

        return False

    def _handle_cache(self, http_info: HTTPInfo) -> bool:
        url = self.ingested_log["Config"]["target_url"]
        self.cache.setdefault(url, {})
        if isinstance(http_info, HTTPHeaderInfo):
            return self._check_cached_header(http_info)
        return False

    def _evaluate_rule(
        self,
        rule: HeaderRule,
        value: Optional[str],
        matched_ids: set[str],
    ) -> HTTPHeaderInfo:
        url       = self.ingested_log["Config"]["target_url"]
        header_present = value is not None

        for dep in rule.dependencies:
            if (dep.id in matched_ids) != dep.activated:
                return self._inactive(url, rule, value)

        if rule.must_exist is True and not header_present:
            return self._inactive(url, rule, value)

        if rule.must_exist is False and header_present:
            return self._inactive(url, rule, value)

        if header_present:
            if rule.regex and not bool(rule.regex.search(value)):
                return self._inactive(url, rule, value)

            if rule.regex_neg and bool(rule.regex_neg.search(value)):
                return self._inactive(url, rule, value)

        return HTTPHeaderInfo(
            timestamp=datetime.now(),
            url=url,
            active=True,
            header=rule.header,
            value=value or "",
            severity=rule.severity,
            key=rule.id,
            info=rule.info,
        )

    @staticmethod
    def _inactive(url: str, rule: HeaderRule, value: Optional[str]) -> HTTPHeaderInfo:
        """Return an inactive HTTPHeaderInfo for a rule that did not fire."""
        return HTTPHeaderInfo(
            timestamp = datetime.now(),
            url = url,
            active = False,
            header = rule.header,
            value = value or "",
            severity = rule.severity,
            key = rule.id,
            info = rule.info,
        )

    def check_headers(self, headers: dict[str, str]) -> list[HTTPHeaderInfo]:
        output: list[HTTPHeaderInfo] = []
        matched_ids: set[str] = set()

        # Normalize headers
        headers = {k.lower(): v for k, v in headers.items()}

        for header_name, rules in self.ruleset.by_header.items():
            value = headers.get(header_name)  # None if header is absent

            for rule in rules:
                info = self._evaluate_rule(rule, value, matched_ids)

                if info.active:
                    matched_ids.add(rule.id)

                # Only surface results whose active state changed since last run
                if self._handle_cache(info) and rule.notify:
                    output.append(info)

        return output

    def ingest_log(self, log_str: str) -> list[HTTPHeaderInfo]:
        try:
            log = json.loads(log_str)
            validate(instance=log, schema=HTTP_LOG_SCHEMA)
        except jsonschema.exceptions.ValidationError:
            logger.error("Invalid log format: %s", log_str)
            return []
        except json.JSONDecodeError:
            logger.error("Invalid JSON format: %s", log_str)
            return []

        self.ingested_log = log
        output: list[HTTPHeaderInfo] = []

        if "headers" in log["Result"]:
            output.extend(self.check_headers(log["Result"]["headers"]))

        self.write_cache()
        return output

def main():
    parser = argparse.ArgumentParser(description="HTTP header security analyzer")
    parser.add_argument(
        "--rules",
        nargs="+",
        help="One or more YAML rule files to load",
    )
    parser.add_argument(
        "--cache",
        default="cache.json",
        help="Path to the JSON cache file (default: cache.json)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Path to a log file to scan",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    ruleset  = load_rules(args.rules)
    analyzer = HTTPLogAnalyzer(ruleset, args.cache)

    if args.log_file:
        with open(args.log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                results = analyzer.ingest_log(line)
                for result in results:
                    print(result)
    else:
        logger.info("No --log-file provided, nothing to scan.")


if __name__ == "__main__":
    main()