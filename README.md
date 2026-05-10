# BlastRadius

> Infracost tells you how much it costs. We tell you how dangerous it is.

Terraform plan blast radius analyzer. Scores every `terraform apply` by destruction risk — catches database replacements, public security groups, IAM escalations, and more.

## Install

```bash
go install github.com/rickyruima/blastradius/cmd/blastradius@latest
```

## Quick Start

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
blastradius scan plan.json
```

Output:
```
  Blast Radius: CRITICAL (10.0/10)

  Summary
    6 resources affected (1 create, 3 update, 1 destroy, 1 replace)

  Risks
    [CRITICAL] aws_db_instance.prod_main
               Database instance will be REPLACED — causes downtime and potential data loss
    [HIGH]     aws_security_group_rule.public_pg
               Security group rule opens access to 0.0.0.0/0
    [HIGH]     aws_s3_bucket.logs
               S3 bucket will be deleted — all objects lost
```

## Output Formats

```bash
blastradius scan plan.json              # terminal (default, colored)
blastradius scan plan.json -f json      # JSON (for CI pipelines)
blastradius scan plan.json -f markdown  # Markdown (for PR comments)
```

## CI Integration

Exit code 2 when risk is HIGH or CRITICAL:
```yaml
- run: blastradius scan plan.json
  continue-on-error: false
```

## Configuration

Create `.blastradius.yaml` in your repo root:

```yaml
production_tags:
  - "env:prod"
critical_resources:
  - "aws_db_instance.main"
ignore_rules:
  - "iam_role_change"
weights:
  destruction: 1.5
```

See `.blastradius.yaml.example` for full options.

## Built-in Rules

24 rules across 4 categories:
- **Destruction** — database replacement/deletion, S3 bucket deletion, EKS/ECS deletion
- **Security** — IAM changes, KMS deletion, public security groups, secrets deletion
- **Network** — VPC deletion, route changes, NAT gateway, load balancer deletion
- **Stateful** — DynamoDB, EBS, EFS, SQS, SNS deletion

## Status

v0.1 — functional CLI with risk scoring. See `PRD.md` for roadmap.
