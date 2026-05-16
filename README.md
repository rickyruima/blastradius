# BlastRadius

> Infracost tells you how much it costs. BlastRadius tells you how dangerous it is.

Your teammate runs `terraform apply` on a Friday. 200 resources change. Buried in the diff: an RDS instance replacement that will cause 4 hours of downtime. Terraform gave it the same weight as a tag update.

BlastRadius is a Go CLI that analyzes Terraform plan JSON for destruction risk. It scores every plan on a 0-10 scale across dimensions like destruction, security surface, network topology, and stateful resource impact.

---

## Demo Output

```
  Blast Radius: CRITICAL (9.2/10)

  Summary
    12 resources affected (3 create, 5 update, 2 destroy, 2 replace)

  Findings
    [CRITICAL] aws_db_instance.prod_main
               Database instance will be REPLACED — causes downtime and potential data loss

    [CRITICAL] aws_dynamodb_table.sessions
               DynamoDB table will be deleted — all data lost

    [HIGH]     aws_security_group_rule.public_pg
               Security group rule opens access to 0.0.0.0/0

    [HIGH]     aws_s3_bucket.logs
               S3 bucket will be deleted — all objects lost

    [HIGH]     aws_route_table.main
               Route table modified — may break network connectivity

  Safe Changes
    7 resources are routine updates with low risk
```

---

## What It Catches

**Destruction** — RDS instance replacement/deletion, S3 bucket deletion, EKS cluster deletion, ECS service removal, ElastiCache deletion, Lambda deletion

**Security** — IAM policy/role changes, public security group ingress (0.0.0.0/0), KMS key deletion, Secrets Manager deletion, security group removal

**Network** — VPC deletion, route table changes, NAT gateway removal, load balancer deletion, VPC peering changes, subnet modifications

**Stateful** — DynamoDB table deletion, EBS volume removal, EFS filesystem deletion, SQS queue deletion, SNS topic deletion

---

## Quick Start

```bash
# Install
go install github.com/rickyruima/blastradius/cmd/blastradius@latest

# Generate plan JSON
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

# Scan
blastradius scan plan.json
```

### CLI Flags

```
blastradius scan <plan.json> [flags]

Flags:
  -c, --config string      path to config file (default ".blastradius.yaml")
  -f, --format string      output format: terminal, json, markdown (default "terminal")
  -t, --threshold string   minimum risk level to fail: low, medium, high, critical (default "high")
```

Exit code 2 is returned when the detected risk level meets or exceeds the threshold.

---

## CI/CD Integration

### GitHub Action

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

      - uses: rickyruima/blastradius@main
        with:
          plan-file: plan.json
          threshold: high
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `plan-file` | Path to `terraform show -json` output | required |
| `threshold` | Minimum level to fail: `low`, `medium`, `high`, `critical` | `high` |
| `comment` | Post markdown report as PR comment | `true` |
| `github-token` | Token for PR comments | `${{ github.token }}` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `level` | Risk level: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `score` | Numeric score (0-10) |

The action posts a markdown report as a PR comment (updates on subsequent pushes) and fails the check if the risk level exceeds the threshold.

### Generic CI

```yaml
# Any CI system — just check the exit code
- run: blastradius scan plan.json -t high
```

Exit code 0 = risk below threshold. Exit code 2 = risk at or above threshold.

---

## Configuration

Create `.blastradius.yaml` in your repo root:

```yaml
# Tag resources as production (increases risk score)
production_tags:
  - "env:prod"
  - "environment:production"

# Always flag these resources regardless of operation
critical_resources:
  - "aws_db_instance.main"
  - "aws_kms_key.master"

# Disable specific rules (by rule ID)
ignore_rules:
  - "iam_role_change"

# Adjust scoring weights (default: 1.0)
weights:
  destruction: 1.5
  security: 1.2
  network: 1.0
  stateful: 1.3
```

---

## Scoring

BlastRadius evaluates plans across multiple dimensions and produces a single 0-10 score:

| Score | Level | Meaning |
|-------|-------|---------|
| 0-2 | LOW | Routine changes, no dangerous operations |
| 3-5 | MEDIUM | Some risk present, review recommended |
| 6-8 | HIGH | Dangerous operations detected, careful review required |
| 9-10 | CRITICAL | Destructive operations on production/stateful resources |

The score accounts for:
- Number and severity of rule violations
- Resource types affected (stateful resources score higher)
- Dependency graph impact (downstream resources at risk)
- Production tag presence

---

## All Rules

24 built-in rules across 4 categories:

### Destruction

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `rds_replacement` | critical | Database instance will be REPLACED — causes downtime and potential data loss |
| `rds_deletion` | critical | Database instance will be DELETED |
| `s3_bucket_deletion` | high | S3 bucket will be deleted — all objects lost |
| `eks_cluster_deletion` | critical | EKS cluster will be deleted — all workloads lost |
| `ecs_service_deletion` | high | ECS service will be deleted — service interruption |
| `elasticache_deletion` | high | ElastiCache cluster will be deleted — cache data lost |
| `lambda_deletion` | medium | Lambda function will be deleted |

### Security

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `iam_policy_change` | high | IAM policy modified — review permission scope |
| `iam_role_change` | medium | IAM role modified |
| `sg_public_ingress` | high | Security group rule opens access to 0.0.0.0/0 |
| `sg_deletion` | medium | Security group will be deleted — dependent resources may lose access |
| `kms_key_deletion` | critical | KMS key will be deleted — encrypted data becomes unrecoverable |
| `secrets_manager_deletion` | high | Secret will be deleted |

### Network

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `vpc_deletion` | critical | VPC will be deleted — all contained resources affected |
| `subnet_change` | medium | Subnet modified — may affect resource placement |
| `route_table_change` | high | Route table modified — may break network connectivity |
| `nat_gateway_change` | high | NAT gateway modified — private subnet internet access affected |
| `lb_deletion` | high | Load balancer will be deleted — service interruption |
| `vpc_peering_change` | high | VPC peering connection modified — cross-VPC communication affected |

### Stateful

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `dynamodb_table_deletion` | critical | DynamoDB table will be deleted — all data lost |
| `ebs_volume_deletion` | high | EBS volume will be deleted — data loss |
| `efs_deletion` | high | EFS file system will be deleted — shared data lost |
| `sqs_queue_deletion` | medium | SQS queue will be deleted — queued messages lost |
| `sns_topic_deletion` | medium | SNS topic will be deleted — subscribers disconnected |

---

## Output Formats

### Terminal (default)

```bash
blastradius scan plan.json
```

Colored output with risk level, summary, and findings grouped by severity.

### JSON

```bash
blastradius scan plan.json -f json
```

```json
{
  "level": "HIGH",
  "overall": 7.4,
  "summary": {
    "total": 8,
    "create": 2,
    "update": 3,
    "destroy": 2,
    "replace": 1
  },
  "findings": [
    {
      "severity": "critical",
      "rule_id": "rds_replacement",
      "resource": "aws_db_instance.prod_main",
      "message": "Database instance will be REPLACED — causes downtime and potential data loss"
    }
  ]
}
```

### Markdown

```bash
blastradius scan plan.json -f markdown
```

Produces a markdown report suitable for PR comments. The GitHub Action uses this format automatically.

---

## What BlastRadius Is Not

- Not a security scanner (use Checkov/Snyk for compliance rules)
- Not a cost tool (use Infracost for spend analysis)
- Not a policy engine (use OPA/Sentinel for allow/deny logic)
- Not drift detection (use driftctl for state drift)

BlastRadius answers one question: **"How bad will it be if this apply goes wrong?"**

---

## License

MIT
