# BlastRadius GitHub Action

Automatically analyze Terraform plans for destruction risk on every PR.

## Usage

```yaml
name: Terraform Risk Check
on:
  pull_request:
    paths: ['**/*.tf']

jobs:
  blast-radius:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3

      - name: Terraform Plan
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > plan.json

      - uses: rickyruima/blastradius/github-action@main
        with:
          plan-file: plan.json
          threshold: high
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `plan-file` | Path to `terraform show -json` output | required |
| `threshold` | Minimum level to fail: low, medium, high, critical | `high` |
| `comment` | Post markdown report as PR comment | `true` |
| `github-token` | Token for PR comments | `${{ github.token }}` |

## Outputs

| Output | Description |
|--------|-------------|
| `level` | Risk level: LOW, MEDIUM, HIGH, CRITICAL |
| `score` | Numeric score (0-10) |

## Behavior

- Posts/updates a comment on the PR with the full risk report
- Fails the check if risk level meets or exceeds threshold
- Updates existing comment on re-runs (no spam)
