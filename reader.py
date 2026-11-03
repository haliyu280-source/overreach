import json
import sys

# Get the policy file path from the command line
policy_file = sys.argv[1]

with open(policy_file) as f:
    policy = json.load(f)

for statement in policy["Statement"]:
    print("Effect:", statement["Effect"])
    print("Action:", statement["Action"])
    print("Resource:", statement["Resource"])

    # Rule 1: full admin access (every action on every resource)
    if statement["Action"] == "*" and statement["Resource"] == "*":
        print("🚨 CRITICAL: Full admin access. This policy allows every action on every resource.")