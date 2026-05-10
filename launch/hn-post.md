# Show HN: BlastRadius – Terraform plan risk analyzer (like Infracost, but for danger)

**Link:** https://github.com/rickyruima/blastradius

Infracost tells you how much a terraform apply costs. BlastRadius tells you how dangerous it is.

It reads `terraform show -json` output and scores your plan on a 0-10 destruction risk scale — catching database replacements, public security groups, IAM escalations, and other high-risk changes that reviewers miss in 200-line plan diffs.

**Example:**

```
$ blastradius scan plan.json

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

**Why I built this:**

I've seen teams lose production databases to terraform applies that "looked fine" in review. The plan output treats all 47 resource changes equally — a routine tag update gets the same visual weight as a database replacement. Reviewers skim, approve, and sometimes the wrong thing gets destroyed.

Existing tools solve adjacent problems:
- Infracost → cost ("this will cost $X/month")
- Checkov/tfsec → compliance ("this violates rule Y")
- BlastRadius → risk ("this could take down prod")

**How it works:**

1. Parse plan JSON
2. Match 24 built-in rules against resource changes (YAML-defined, extensible)
3. Build dependency graph to assess blast radius
4. Score across dimensions: destruction, security, network, stateful data
5. Output colored terminal / JSON / markdown

**CI integration:**

Exit code 2 when risk exceeds threshold. GitHub Action posts risk report as PR comment and blocks merge on HIGH/CRITICAL.

```yaml
- uses: rickyruima/blastradius/github-action@v0.1.0
  with:
    plan-file: plan.json
    threshold: high
```

**Install:**

```bash
go install github.com/rickyruima/blastradius/cmd/blastradius@latest
```

Single binary, no dependencies, runs in <1s. Open source (MIT).

Looking for feedback on:
- What rules are missing that would catch real incidents you've seen?
- Would you want this integrated with Atlantis / Spacelift / Terraform Cloud?
- Is the scoring model intuitive or would you prefer a different approach?
