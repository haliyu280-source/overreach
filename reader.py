import json
import sys

from analyzer import analyze_policy, as_list

ICONS = {"CRITICAL": "🚨", "HIGH": "⚠️ "}

policy_file = sys.argv[1]

with open(policy_file) as f:
    policy = json.load(f)

for statement in as_list(policy["Statement"]):
    print("Effect:", statement["Effect"])
    print("Action:", ", ".join(as_list(statement["Action"])))
    print("Resource:", ", ".join(as_list(statement["Resource"])))

findings = analyze_policy(policy)

for finding in findings:
    icon = ICONS[finding["severity"]]
    print(f"{icon} {finding['severity']}: {finding['message']}")

if not findings:
    print("✅ No findings.")