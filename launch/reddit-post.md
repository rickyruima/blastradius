# r/Terraform post

**Title:** I built a CLI that scores terraform plans by destruction risk (not cost, not compliance — danger)

After watching a team accidentally replace a production RDS instance because nobody caught it in a 200-line plan diff, I built BlastRadius.

It reads your `terraform show -json` output and gives you a risk score (0-10) based on what could go wrong:

- Database replacements/deletions
- Security groups opening to 0.0.0.0/0
- IAM policy escalations
- VPC/route table changes
- S3 bucket deletions
- KMS key deletions

The key insight: not all terraform changes are equal. Creating a CloudWatch log group is not the same risk as replacing a production database. But `terraform plan` shows them the same way.

**Quick demo:**
```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
blastradius scan plan.json
```

Outputs colored risk report. Exits with code 2 for HIGH/CRITICAL (great for CI).

GitHub Action included — posts risk report on PRs and blocks merge when threshold exceeded.

Open source, single Go binary, runs in <1s: https://github.com/rickyruima/blastradius

---

# r/devops post

**Title:** Open source terraform plan risk scoring — catches the dangerous changes reviewers miss

We've all been there: 47 resource changes in a plan, reviewer approves, and the one database replacement buried in line 183 takes down prod.

I built BlastRadius to solve this. It's a Go CLI that:
1. Reads `terraform show -json` output
2. Matches against 24 risk rules (database ops, IAM, security groups, networking, stateful resources)
3. Builds a dependency graph to assess impact scope
4. Outputs a 0-10 risk score with specific findings

Different from Infracost (cost) or Checkov (compliance). This answers "how bad could this apply go?"

GitHub Action included for PR gating. Configurable threshold, YAML rules, exit codes for CI.

Single binary, <1s execution, MIT licensed: https://github.com/rickyruima/blastradius

What rules would you add? What incidents would this have caught for you?
