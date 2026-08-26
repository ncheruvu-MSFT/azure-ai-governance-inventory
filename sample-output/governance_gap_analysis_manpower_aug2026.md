# ManpowerGroup — AI Governance Gap Analysis

**Generated:** 2026-08-26 07:50
**Source:** Inventory collected ai_inventory_20260818_091903
**Subscriptions Scanned:** 1
**Total AI Resources:** 4

---

## Overall Governance Grade: D C B (Score: 7/10)

> ⚠️ **Significant governance gaps exist.** Critical items require immediate remediation before production AI workloads scale.

---

## Risk Dashboard

| # | Risk Area | Finding | Severity | Remediation |
|---|-----------|---------|----------|-------------|
| 1 | **No Managed Identity** | 1 resource(s) using key-based auth: oaia3shp001 | CRITICAL | Enable managed identity; rotate and disable access keys |
| 2 | **Zero AI Policies** | No AI-specific Azure Policy assignments found | CRITICAL | Deploy MCSB-aligned AI policy initiative: deny public access, require managed identity, enforce tagging, require diagnostics |
| 3 | **No AI-Scoped RBAC** | No resource-level RBAC assignments on AI resources | HIGH | Implement least-privilege RBAC at resource group level; use PIM for admin roles |
| 4 | **Limited Scan Coverage** | Only 1 subscription scanned — customer has 7+ subscriptions | HIGH | Run inventory across all subscriptions: EU Prod, EU Non-Prod, Americas Non-Prod, Management, Ejento |
| 5 | **Tag Non-Compliance** | 4/4 resources missing governance tags | MEDIUM | Map existing tags to governance schema; add missing tags (cost-center, ai-service-tier) |
| 6 | **OpenAI Config Gap** | OpenAI account(s) exist but 0 model deployments captured | MEDIUM | Verify model deployments exist; confirm content filter policies are applied |
| 7 | **No GPU Compute** | All 3 ML computes are CPU-only (no GPU) | INFO | Expected — GPU quota requests are pending. Monitor capacity tracker. |


---

## Resource Inventory

### Resources by Type

| Resource Type | Count |
|---------------|-------|
| Microsoft.CognitiveServices/accounts | 2 |
| Microsoft.MachineLearningServices/workspaces | 2 |


### Resources by Region

| Region | Count |
|--------|-------|
| eastus2 | 3 |
| eastus | 1 |


### Resources by Kind

| Kind | Count |
|------|-------|
| Default | 2 |
| AIServices | 1 |
| OpenAI | 1 |


### Subscriptions Scanned

| Subscription ID | Name |
|-----------------|------|
| 997d5129-0e09-43dc-bb00-eb82ffaaea9e | MSP-SUB-A3-SH-PRD |


---

## Detailed Findings

### 1. Network Isolation

| Resource | Public Access | Private Endpoints | Isolated |
|----------|-------------|-------------------|----------|
| aifa3shp001 | Disabled | 1 | Yes |
| oaia3shp001 | Disabled | 1 | Yes |
| amla5shp001 | Disabled | 1 | Yes |
| amla3shp001 | Disabled | 1 | Yes |


**Assessment:** ✅ All resources have public access disabled.
✅ All resources have private endpoint isolation.

### 2. Identity & Access

| Resource | Managed Identity | Risk |
|----------|-----------------|------|
| aifa3shp001 | SystemAssigned | ✅ SystemAssigned |
| oaia3shp001 | None | 🔴 KEY-BASED AUTH |
| amla5shp001 | UserAssigned | ✅ UserAssigned |
| amla3shp001 | UserAssigned | ✅ UserAssigned |


**Assessment:** 1 resource(s) without managed identity. These are using API keys — rotate keys and enable managed identity immediately.

**RBAC:** 🔴 No resource-scoped RBAC assignments found. All access is inherited from subscription level. Implement least-privilege roles.

### 3. Azure Policy Enforcement

🔴 **No AI-specific Azure Policies are assigned.**

This means:
- Anyone can create AI resources with public endpoints
- No enforcement of managed identity
- No tag requirements enforced at deployment
- No guardrails on region, SKU, or configuration

**Recommended Policy Initiative:**

| Policy | Effect | Purpose |
|--------|--------|---------|
| Deny public network access on Cognitive Services | Deny | Prevent public-facing AI endpoints |
| Deny public network access on ML workspaces | Deny | Prevent public ML workspace access |
| Require managed identity on Cognitive Services | Deny | Eliminate key-based authentication |
| Require diagnostic settings on AI resources | DeployIfNotExists | Ensure logging |
| Require specific tags on AI resources | Deny | Enforce governance tags at deployment |
| Restrict AI resources to approved regions | Deny | Control data residency |
| Restrict allowed VM SKUs for ML compute | Deny | Control GPU spend |

### 4. Tagging Compliance

**Existing Tag Schema (customer-defined):**

| Tag Key | Resources Using It |
|---------|--------------------|
| BrandName | 4 |
| Description | 4 |
| SupportedBy | 4 |
| BusinessOwner | 4 |
| BusinessHours | 4 |
| Customer | 4 |
| CreationDate | 4 |
| Replication | 4 |
| LBName | 4 |
| BusinessCriticality | 4 |
| Environment | 4 |
| ApplicationOwner | 4 |
| Application | 4 |
| MPGTicketRef | 4 |
| DataClassification | 4 |
| module | 3 |


**Missing Governance Tags:**

| Resource | Missing Tags |
|----------|-------------|
| aifa3shp001 | owner, cost-center, data-classification, ai-service-tier |
| oaia3shp001 | owner, cost-center, data-classification, ai-service-tier |
| amla5shp001 | owner, cost-center, data-classification, ai-service-tier |
| amla3shp001 | owner, cost-center, data-classification, ai-service-tier |


**Tag Mapping Recommendation:**

| Customer Tag | Governance Tag | Action |
|-------------|---------------|--------|
| ApplicationOwner / SupportedBy | owner | ✅ Accept — no change needed |
| _(not present)_ | cost-center | ➕ Add — required for chargeback |
| DataClassification | data-classification | ✅ Accept — rename in governance schema |
| _(not present)_ | ai-service-tier | ➕ Add — Tier 1/2/3 classification |
| Environment | environment | ✅ Already present |
| BusinessCriticality | _(bonus)_ | ✅ Keep — adds governance value |

### 5. Diagnostic Settings

✅ **No diagnostic gaps found.** All scanned AI resources have diagnostic settings configured.

### 6. ML Compute Resources

| Compute | VM Size | Type | GPU? | Workspace |
|---------|---------|------|------|-----------|
| mlvma3shpx002 | Standard_D8ds_v4 | computeinstance | ❌ CPU only | amla3shp001 |
| mlvma3shpx001 | Standard_D8ds_v4 | computeinstance | ❌ CPU only | amla3shp001 |
| mlvma3shpx003 | Standard_D4ds_v4 | computeinstance | ❌ CPU only | amla3shp001 |


### 7. OpenAI Deployments

⚠️ **1 OpenAI account(s) exist but 0 model deployments were captured.**

Verify:
- Are models deployed? (check Azure Portal → OpenAI → Model deployments)
- Are content filter policies applied?
- Script may need Cognitive Services Contributor role to list deployments

---

## Governance Maturity Assessment

| Domain | Maturity | Evidence |
|--------|----------|----------|
| **Network Security** | 🟢 Advanced | Private endpoints on all resources, public access disabled |
| **Identity & Access** | 🟡 Partial | Managed identity on 3/4 resources; OpenAI uses keys; no RBAC at resource level |
| **Policy Enforcement** | 🔴 None | Zero AI-specific policies deployed |
| **Tagging & Cost** | 🟡 Partial | Rich custom tags exist but missing cost-center and ai-service-tier |
| **Monitoring & Logging** | 🟢 Good | Diagnostic settings configured on scanned resources |
| **AI Service Catalog** | 🔴 Incomplete | Only 1 of 7+ subscriptions scanned |
| **Lifecycle Management** | 🔴 Not Implemented | No formal request/approval/retire process in Azure |
| **Operational Runbooks** | 🔴 Not Started | No standardized runbooks for AI operations |

---

## Recommended Remediation Roadmap

### Week 1 — Critical Security

- [ ] Enable managed identity on OpenAI account `oaia3shp001`
- [ ] Run inventory on ALL 7 subscriptions (EU Prod, Non-Prod, Mgmt, Ejento)
- [ ] Deploy Azure Policy: deny public endpoints on Cognitive Services + ML
- [ ] Deploy Azure Policy: require managed identity on Cognitive Services

### Week 2 — Governance Foundation

- [ ] Map customer tags to governance schema (table above)
- [ ] Deploy tag enforcement policies (cost-center, ai-service-tier)
- [ ] Implement RBAC model per AI Governance RBAC Personas document
- [ ] Configure diagnostic settings policy (DeployIfNotExists)

### Week 3 — Operational Governance

- [ ] Build AI service catalog from full inventory scan
- [ ] Define lifecycle management process (IaC templates + approval gates)
- [ ] Create operational runbooks for AI Foundry and ML workspaces
- [ ] Set up cost governance dashboards (tag-based chargeback)

### Week 4 — Continuous Compliance

- [ ] Enable Azure Policy compliance dashboard for AI resources
- [ ] Schedule monthly governance review cadence
- [ ] Configure alerts for policy violations
- [ ] Document exception/waiver process

---

## Appendix: Subscriptions Not Yet Scanned

| Subscription | Purpose | Action |
|-------------|---------|--------|
| MSP-SUB-A3-SH-NONPRD | Americas Non-Prod | Run inventory |
| MSP-SUB-A4-SH-NONPRD | Americas Non-Prod (Central US) | Run inventory |
| MSP-SUB-E5-SH-PRD | Europe Prod | Run inventory |
| MSP-SUB-E5-SH-NONPRD | Europe Non-Prod | Run inventory |
| MSP-SUB-E4-GS-MGMT | Global Management | Run inventory |
| MSP-SUB-GS-Ejento | Foundry / Ejento | Run inventory |
| MSP-SUB-A3-CX-PRD | Americas CX Prod | Run inventory |

---

*Report generated by Azure AI Governance Inventory Analysis Tool*
*GitHub: https://github.com/ncheruvu-MSFT/azure-ai-governance-inventory*
