import json
from pathlib import Path

from analyzer import analyze_policy

FIXTURES = Path(__file__).parent.parent / "fixtures" / "policies"


def load(name):
    with open(FIXTURES / name) as f:
        return json.load(f)


def severities(name):
    return [finding["severity"] for finding in analyze_policy(load(name))]


def test_full_admin_is_critical():
    assert severities("admin_full.json") == ["CRITICAL"]


def test_iam_wildcard_is_critical():
    assert severities("iam_full.json") == ["CRITICAL"]


def test_s3_wildcard_is_high():
    assert severities("s3_full.json") == ["HIGH"]


def test_wildcard_hidden_in_list_is_high():
    assert severities("list_actions.json") == ["HIGH"]


def test_least_privilege_has_no_findings():
    assert severities("invoices_readonly.json") == []


def test_deny_is_not_flagged():
    assert severities("deny_all.json") == []