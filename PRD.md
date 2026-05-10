# PRD：Terraform Blast Radius Analyzer

**产品代号**：BlastRadius
**版本**：v1.0
**作者**：Ricky
**最后更新**：2026-05

---

## 1. 一句话定位

> **Infracost tells you how much it costs. We tell you how dangerous it is.**

为 Terraform / OpenTofu plan 提供"破坏半径"分析——不是回答"花多少钱"或"违反哪条 best practice"，而是回答"这次 apply 出错会有多严重"。

---

## 2. 问题陈述

### 2.1 用户痛点

每周都有团队因为 Terraform 误操作付出代价：
- 一个 `terraform apply` 误删生产数据库
- IAM policy 改动意外授权过宽
- 安全组改动暴露内网端口
- 跨环境引用导致 staging 改动污染生产
- 资源 replace（而非 update）导致服务中断

**当前缓解方案的不足**：
- **Infracost** 回答成本问题，但成本低不等于风险低（删除一个数据库实例反而省钱）
- **Snyk IaC / Checkov / tfsec** 回答"违反规则"，但不告诉你这次改动多重要
- **terraform plan 文本输出** 给所有改动同等权重，reviewer 在 200 行 diff 里找关键改动靠肉眼

### 2.2 LLM 时代为什么变得更紧迫

AI agent / Cursor / Claude Code 越来越多地生成 Terraform 代码。AI 生成的 IaC 经常"看起来对、细节有偏差"——错的资源名、错的 lifecycle 配置、意外触发 replace。reviewer 注意力 scale 不上来。

### 2.3 用户画像

**核心用户**：DevOps / Platform Engineer / SRE
**典型场景**：
- 每天审 5-20 个 Terraform PR
- 团队规模 10-200 人工程师
- 已经在用 Terraform Cloud / GitHub Actions / Atlantis 跑 plan
- 出过至少一次 IaC 相关事故

**反向画像**（不是目标用户）：
- 个人项目 / 小团队不出生产事故的
- 完全不用 IaC 的（点 console 配置）
- 已经有完善 GitOps + policy framework 的超大型企业（他们自建）

---

## 3. 解决方案

### 3.1 核心机制

输入：`terraform plan -out=tfplan` + `terraform show -json tfplan` 输出的 JSON
输出：结构化的风险报告

### 3.2 风险评分维度

每个 plan 在以下维度独立评分（0-10），最终聚合为整体 Blast Radius Score：

| 维度 | 信号 |
|------|------|
| **Production Touch** | 资源是否带 prod / production tag、是否在 prod account、是否在 prod workspace |
| **Destruction Risk** | replace / destroy 操作数量、被销毁资源类型 |
| **Stateful Resource** | 数据库、storage bucket、persistent volume、KMS key |
| **Security Surface** | IAM policy / role / security group / NACL / KMS / secrets 改动 |
| **Network Topology** | VPC / subnet / route / peering / Transit Gateway 改动 |
| **Blast Radius** | 依赖图中下游影响的资源数量 |
| **Cross-Environment** | 是否跨 workspace / account / region 引用 |
| **Critical Tags** | 用户自定义的关键标签（如 `criticality:tier-0`） |

### 3.3 输出格式

**CLI 输出**（v0.1）：
```
Blast Radius: HIGH (8.4/10)

Summary
  47 resources affected (12 create, 31 update, 4 destroy)
  3 production resources touched
  1 database REPLACEMENT detected
  4 IAM policy changes
  2 networking changes

Top Risks
  [CRITICAL] aws_db_instance.prod_main will be REPLACED
             → 4 hours estimated downtime, snapshot recommended
  [HIGH]     aws_iam_policy.admin_policy permissions broadened
             → New: s3:*, was: s3:GetObject only
  [HIGH]     aws_security_group.public_ingress opens port 5432
             → PostgreSQL exposed to 0.0.0.0/0

Safe Changes
  39 resources are routine updates with low risk
```

**GitHub Action 输出**：自动 PR 评论，HIGH/CRITICAL 时可配置阻塞 merge

**JSON 输出**：供 CI/CD pipeline 集成

### 3.4 关键设计决策

**为什么不做 proxy / runtime 拦截**：
- Plan-time 分析足够（这是 IaC 的标准 review 流程）
- Proxy 带来部署 friction，企业接入慢
- 让用户保留对 apply 的最终控制

**为什么不重新发明 OPA**：
- BlastRadius 不是 policy engine，是 risk scorer
- Policy 是"允许/不允许"，risk score 是"多严重"
- v2 可以集成 OPA 让用户自定义规则，v1 不需要

**为什么从 AWS + Terraform 开始**：
- AWS 占 IaC 市场 60%+
- 比 GCP / Azure 资源生态更复杂（也意味着事故更多）
- Terraform 比 Pulumi / CDK 用户基数大 5-10 倍

---

## 4. v1.0 Scope

### 4.1 In Scope

- **CLI 工具**：`blastradius scan plan.json`
- **AWS 资源支持**：覆盖 50 个最常见资源类型（RDS、EC2、IAM、S3、Lambda、VPC、SG、ELB、ECS、EKS 核心资源）
- **GitHub Action**：自动评论、可配置 threshold blocking
- **JSON / Markdown / Terminal 三种输出格式**
- **依赖图分析**：基于 plan 中的 references 字段
- **基础规则集**：30 条预定义风险规则
- **配置文件**（`.blastradius.yaml`）：自定义 production tag、忽略某些资源、调整权重

### 4.2 Out of Scope（v1 明确不做）

- ❌ Pulumi / OpenTofu / CDK 支持（v2）
- ❌ GCP / Azure 支持（v2）
- ❌ 自定义 policy DSL（用户用 OPA 就好）
- ❌ Web dashboard（v1.5）
- ❌ Slack 集成（v1.5）
- ❌ 历史 trend 分析（v1.5）
- ❌ 与 Terraform Cloud / Spacelift 深度集成（v2）
- ❌ Cost 分析（让 Infracost 做）
- ❌ Compliance reporting（让 Snyk / Checkov 做）

### 4.3 显式非目标

**BlastRadius 不是**：
- 不是另一个 IaC security scanner（不替代 Snyk/Checkov）
- 不是成本工具（不替代 Infracost）
- 不是 policy enforcement engine（不替代 OPA/Sentinel）
- 不是 drift detection（不替代 driftctl）

---

## 5. 技术架构

### 5.1 技术栈

- **语言**：Go（CLI 性能、单二进制分发、Terraform 生态主流语言）
- **核心依赖**：
  - `github.com/hashicorp/terraform-json`：解析 plan JSON
  - `github.com/dominikbraun/graph`：依赖图分析
- **前端**（v1.5 dashboard）：暂不投入

### 5.2 核心模块

```
blastradius/
├── cmd/blastradius/        # CLI entry
├── pkg/
│   ├── parser/             # plan JSON → 内部模型
│   ├── graph/              # 依赖图构建
│   ├── rules/              # 风险规则集
│   ├── scorer/             # 评分聚合
│   └── reporter/           # 输出格式（terminal/json/markdown）
├── rules/                  # YAML 规则定义
└── github-action/          # GH Action wrapper
```

### 5.3 规则定义示例

```yaml
- id: aws_rds_replacement
  severity: critical
  match:
    resource_type: aws_db_instance
    action: replace
  message: "Database REPLACEMENT will cause downtime"
  context:
    estimate_downtime: true
    suggest: "Use create_before_destroy or migration plan"

- id: security_group_public_ingress
  severity: high
  match:
    resource_type: aws_security_group_rule
    action: [create, update]
    attribute_changes:
      cidr_blocks: ["0.0.0.0/0"]
  message: "Security group opens to public internet"
```

---

## 6. 用户旅程

### 6.1 首次安装（CLI）

```bash
# 安装
brew install blastradius
# 或
curl -sSL https://blastradius.dev/install.sh | sh

# 第一次运行
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
blastradius scan plan.json

# 输出风险报告，<3 秒完成
```

### 6.2 GitHub Action 集成

```yaml
# .github/workflows/terraform.yml
- uses: blastradius/action@v1
  with:
    plan-file: plan.json
    threshold: high  # block PR if risk >= high
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

PR 自动得到评论，HIGH 风险阻塞 merge。

### 6.3 团队配置

```yaml
# .blastradius.yaml
production_tags:
  - "env:prod"
  - "environment:production"

critical_resources:
  - "aws_db_instance.main"
  - "aws_kms_key.master"

ignore_rules:
  - "aws_iam_role_change"  # 我们有专门 IAM review process

custom_weights:
  destruction: 1.5
  iam: 2.0
```

---

## 7. 商业模式

### 7.1 定价

| Tier | 价格 | 功能 |
|------|------|------|
| **OSS / Free** | $0 | CLI、基础规则集、本地使用、public repo GitHub Action |
| **Team** | $99/repo/month | Private repo GitHub Action、Slack 集成、历史 trend、自定义规则 |
| **Business** | $499/team/month | 跨多 repo 聚合、approval workflow、SSO、audit log |
| **Enterprise** | Custom | 自部署、SLA、专属支持、合规报告 |

### 7.2 GTM 策略

**Phase 1（0-3 个月）：建立 awareness**
- CLI + GitHub Action 完全开源（MIT）
- Hacker News 发布（"Show HN: BlastRadius"）
- r/devops、r/Terraform 发布
- 写 3 篇技术博客："How we caught 47 production database replacements"
- 目标：1000 GitHub stars、500 active CLI users

**Phase 2（3-6 个月）：转化付费**
- 接触前 50 个深度用户，访谈痛点
- 推出 Team tier，前 20 客户给 50% 折扣终身
- 目标：30 paid teams、$3k MRR

**Phase 3（6-12 个月）：扩 scope**
- 加 OpenTofu、Pulumi 支持
- 加 GCP、Azure 资源
- 加 web dashboard
- 目标：$30k MRR

---

## 8. 成功指标

### 8.1 v1 发布指标（前 90 天）

| 指标 | 目标 |
|------|------|
| GitHub stars | 1000+ |
| CLI 周活用户 | 500+ |
| GitHub Action 安装数 | 200+ |
| 付费 team 数 | 10+ |
| MRR | $1k+ |

### 8.2 长期北极星指标

**"Caught dangerous changes per week per active team"**
这个数字越高，产品 ROI 越清晰。目标：每个活跃团队每周至少 catch 1 个 HIGH 风险变更。

### 8.3 反向指标（监控 false positive）

- False positive rate（用户标记"这不是真问题"的比例）：必须 < 15%
- Override rate（用户配置 ignore 的规则比例）：监控规则质量

---

## 9. 风险与对策

| 风险 | 概率 | 影响 | 对策 |
|------|------|------|------|
| HashiCorp 自建类似功能 | 中 | 高 | 12-18 个月窗口期内建立品牌 + 客户。深度做"AI 生成 IaC"angle 形成差异 |
| Snyk / Checkov 扩展到 risk scoring | 中 | 中 | 保持定位清晰：他们做 "what's wrong"，我们做 "how dangerous"。不正面竞争 |
| False positive 太多失去信任 | 中 | 高 | 严格控制规则质量，每条规则有 false positive rate 上限。允许用户调权重 |
| AWS 资源覆盖不全 | 高 | 中 | 优先覆盖最常用 50 个，长尾用通用规则降级处理 |
| 用户不愿意改 CI 流程 | 低 | 中 | GitHub Action 5 分钟集成。提供 Atlantis / Spacelift 适配 |

---

## 10. 时间线

| 阶段 | 时间 | 里程碑 |
|------|------|--------|
| **v0.1（私测）** | 第 1 个月 | CLI 跑通、AWS 30 资源、5 个 alpha 用户 |
| **v0.5（公测）** | 第 2 个月 | GitHub Action、50 资源、规则集成熟 |
| **v1.0（GA）** | 第 3 个月 | HN 发布、文档完善、定价上线 |
| **v1.5** | 第 6 个月 | Web dashboard、Slack、历史 trend |
| **v2.0** | 第 12 个月 | OpenTofu/Pulumi、GCP/Azure、enterprise features |

---

## 11. Open Questions

1. 是否要在 v1 支持 Terragrunt？（增加复杂度但 Terragrunt 用户重叠度高）
2. 定价 $99/repo 还是 $99/team？（影响价格感知）
3. 是否提供 SaaS scan 模式（用户上传 plan，我们 scan）？还是只做 self-hosted CLI？
4. 自定义规则用 YAML 还是 Rego（OPA）？（YAML 简单，Rego 更强大但学习曲线）
