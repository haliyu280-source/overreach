import json
import sys


def as_list(value):
    """Turn a single value into a list, so we can always loop over it."""
    if isinstance(value, list):
        return value
    return [value]


policy_file = sys.argv[1]

with open(policy_file) as f:
    policy = json.load(f)

findings = 0

for statement in policy["Statement"]:
    effect = statement["Effect"]
    actions = as_list(statement["Action"])
    resources = as_list(statement["Resource"])

    print("Effect:", effect)
    print("Action:", ", ".join(actions))
    print("Resource:", ", ".join(resources))

    # Deny statements block access, so they are never a permission risk
    if effect != "Allow":
        continue

    # Rule 1: full admin access (every action on every resource)
    if "*" in actions and "*" in resources:
        print("🚨 CRITICAL: Full admin access. This policy allows every action on every resource.")
        findings += 1
        continue

    # Rule 2: every action in one service, on every resource
    for action in actions:
        if action.endswith(":*") and "*" in resources:
            print(f"⚠️  HIGH: Service-wide wildcard '{action}' on all resources. Full control of that service.")
            findings += 1

if findings == 0:
    print("✅ No findings.")