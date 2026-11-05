def as_list(value):
    """Turn a single value into a list, so we can always loop over it."""
    if isinstance(value, list):
        return value
    return [value]


def analyze_policy(policy):
    """Check an IAM policy and return a list of findings."""
    findings = []

    for statement in as_list(policy["Statement"]):
        effect = statement["Effect"]
        actions = as_list(statement["Action"])
        resources = as_list(statement["Resource"])

        # Deny statements block access, so they are never a permission risk
        if effect != "Allow":
            continue

        # Rule 1: full admin access (every action on every resource)
        if "*" in actions and "*" in resources:
            findings.append({
                "severity": "CRITICAL",
                "rule": "full-admin",
                "message": "Full admin access. This policy allows every action on every resource.",
            })
            continue

        # Rule 2: every action in one service, on every resource
        for action in actions:
            if action.endswith(":*") and "*" in resources:
                if action == "iam:*":
                    findings.append({
                        "severity": "CRITICAL",
                        "rule": "iam-wildcard",
                        "message": "'iam:*' on all resources. Can grant itself full admin (privilege escalation).",
                    })
                else:
                    findings.append({
                        "severity": "HIGH",
                        "rule": "service-wildcard",
                        "message": f"Service-wide wildcard '{action}' on all resources. Full control of that service.",
                    })

    return findings