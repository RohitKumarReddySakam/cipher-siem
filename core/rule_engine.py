"""Sigma-like YAML detection rule engine for CIPHER SIEM."""
import os
import yaml
import re
import logging

logger = logging.getLogger(__name__)


class SIEMRuleEngine:
    def __init__(self, rules_dir: str):
        self._rules = []
        self._load(rules_dir)

    def _load(self, rules_dir: str):
        if not os.path.isdir(rules_dir):
            return
        for fname in os.listdir(rules_dir):
            if not fname.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(rules_dir, fname)
            try:
                with open(path) as f:
                    docs = list(yaml.safe_load_all(f))
                for doc in docs:
                    if isinstance(doc, dict) and doc.get("enabled", True):
                        self._rules.append(doc)
            except Exception as e:
                logger.warning("Failed to load rule %s: %s", fname, e)
        logger.info("SIEM rule engine loaded %d rules", len(self._rules))

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def evaluate(self, event: dict) -> list[dict]:
        matches = []
        for rule in self._rules:
            if self._matches(rule, event):
                matches.append({
                    "rule_id": rule.get("id", ""),
                    "rule_name": rule.get("name", ""),
                    "severity": rule.get("severity", "MEDIUM"),
                    "description": rule.get("description", ""),
                    "mitre_tactic": rule.get("mitre_tactic", ""),
                    "mitre_technique": rule.get("mitre_technique", ""),
                    "tags": rule.get("tags", []),
                })
        return matches

    def _matches(self, rule: dict, event: dict) -> bool:
        detection = rule.get("detection", {})
        if not detection:
            return False

        condition = detection.get("condition", "all")
        checks = {k: v for k, v in detection.items() if k != "condition"}

        results = {}
        for check_name, criteria in checks.items():
            results[check_name] = self._check_criteria(criteria, event)

        if condition == "all":
            return all(results.values())
        if condition == "any":
            return any(results.values())
        # named: "selection and not filter"
        return self._eval_condition_expr(condition, results)

    def _check_criteria(self, criteria: dict, event: dict) -> bool:
        if not isinstance(criteria, dict):
            return False
        for field, expected in criteria.items():
            actual = event.get(field, "")
            if actual is None:
                actual = ""
            actual_str = str(actual).lower()
            if isinstance(expected, list):
                if not any(str(e).lower() in actual_str for e in expected):
                    return False
            elif isinstance(expected, str):
                if expected.startswith("re:"):
                    if not re.search(expected[3:], actual_str, re.IGNORECASE):
                        return False
                else:
                    if expected.lower() not in actual_str:
                        return False
            elif isinstance(expected, (int, float)):
                try:
                    if float(actual) != expected:
                        return False
                except (ValueError, TypeError):
                    return False
        return True

    def _eval_condition_expr(self, expr: str, results: dict) -> bool:
        tokens = expr.lower().split()
        result = True
        negate = False
        op = "and"
        for token in tokens:
            if token == "not":
                negate = True
                continue
            if token in ("and", "or"):
                op = token
                continue
            val = results.get(token, False)
            if negate:
                val = not val
                negate = False
            if op == "and":
                result = result and val
            else:
                result = result or val
        return result
