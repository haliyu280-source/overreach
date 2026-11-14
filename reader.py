import json
import sys

from analyzer import analyze_policy

ICONS = {"CRITICAL": "🚨", "HIGH": "⚠️ "}


def scan_file(path):
    """Scan one policy file, print its findings, and return how many there were."""
    with open(path) as f:
        policy = json.load(f)

    findings = analyze_policy(policy)

    print(f"\n📄 {path}")
    for finding in findings:
        icon = ICONS[finding["severity"]]
        print(f"  {icon} {finding['severity']}: {finding['message']}")
    if not findings:
        print("  ✅ No findings.")

    return len(findings)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 reader.py <policy.json> [more files...]")
        sys.exit(2)

    total = 0
    for path in sys.argv[1:]:
        total += scan_file(path)

    print(f"\nTotal findings: {total}")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()