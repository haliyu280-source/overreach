# Overreach

A command-line tool that scans AWS IAM policies for overly permissive access, ranks findings by severity, and runs as a CI gate that blocks dangerous policies before they reach production.

## Why

Most cloud breaches come from customer-side misconfiguration, and overly broad permissions are one of the most common. Overreach checks IAM policy JSON files for the riskiest patterns and fails the build when it finds them.

I built Overreach to understand systems better, to understand how permissions and iam work and also to improve my skills as a Cloud Security Engineer.

## What it detects

| Rule | Pattern | Severity | Why it matters |
|---|---|---|---|
| `full-admin` | `"Action": "*"` on `"Resource": "*"` | CRITICAL | Every action on every resource: full account takeover if credentials leak |
| `iam-wildcard` | `iam:*` on `*` | CRITICAL | Can grant itself any permission (privilege escalation) |
| `service-wildcard` | Any other `service:*` on `*` | HIGH | Full control of one service, such as reading or deleting every S3 bucket |

`Deny` statements are ignored, since they restrict access. Actions written as lists are fully supported, and `Statement` can be a single object or a list.

## Quick start

Requires Python 3.

```bash
python3 reader.py policies/*.json
```

| Exit code | Meaning |
|---|---|
| `0` | No findings |
| `1` | At least one finding (fails the pipeline) |
| `2` | No file given |

## Run with Docker

```bash
docker build -t overreach .
docker run --rm -v "$PWD/policies:/policies" overreach /policies/invoice_reader.json
```

The image is based on `python:3.12-slim` and runs as a non-root user.

## Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -v
```

The test suite checks that each rule fires on the right policies **and** that safe policies (least privilege, Deny statements) are not flagged.

## CI security gates

Every push to `main` and every pull request runs three jobs in GitHub Actions:

1. **Unit tests**: pytest
2. **Overreach IAM policy scan**: scans everything in `policies/` and fails on any finding
3. **Trivy image scan**: builds the Docker image and fails on critical vulnerabilities that have a fix available

The workflow token is limited to `contents: read`.

## Project structure

```
analyzer.py              Detection rules (returns findings as data)
reader.py                Command-line interface and exit codes
policies/                Policies this project would deploy (scanned by CI)
fixtures/policies/       Deliberately safe and unsafe test policies
tests/                   pytest suite
Dockerfile               Non-root container image
.github/workflows/       CI security gates
```

## Limitations

Overreach is a learning project with a deliberately small scope. It does **not**:

- Evaluate `NotAction`, `NotResource`, or `Condition` blocks
- Detect privilege escalation through individual IAM actions such as `iam:PassRole`, `iam:AttachUserPolicy`, or `iam:CreatePolicyVersion` (only `iam:*`)
- Consider how multiple policies combine, or account for SCPs, permission boundaries, or resource-based policies
- Pull policies from a live AWS account
- Handle malformed input gracefully (invalid JSON or missing keys currently cause a crash)

For production use, see mature tools such as Cloudsplaining and Prowler.

## Roadmap

- Error handling for malformed policies
- Rules for single-action privilege escalation paths
- `NotAction` detection
- JSON output for other tools to consume

## What I learned

## What I learned

- **A container is only as secure as its base image.** If the base image has a vulnerable package, every container built from it inherits that problem. Smaller images like `slim` or Alpine mean fewer packages and less to attack, which is why I compared `python:3.12-slim` against the full image with Trivy.
- **Containers should never run as root unless they have to.** If someone exploits the app inside, they get whatever user it runs as. Overreach only reads JSON files, so it runs as a normal user.
- **A scan reports problems. A gate stops them.** The difference is the exit code: Overreach and Trivy exit with a non-zero code when they find something, and that's what makes the pipeline fail and block the change.
- **The pipeline needs least privilege too.** Limiting the workflow token to read-only means that even if a step in the pipeline were compromised, it couldn't push code or change the repo.
- **Not every vulnerability can be fixed right away.** Ignoring unfixed vulnerabilities keeps the gate focused on what can actually be fixed, but those issues are still there, so they need to be tracked and revisited when a patch comes out.
- **Catch problems before they're merged.** The gates run on pull requests so a dangerous policy gets blocked before it ever reaches `main`, not after.
- **A vulnerability and a misconfiguration aren't the same thing.** Trivy finds flaws in software. Overreach finds risky choices people make in their settings.