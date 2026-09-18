<#
.SYNOPSIS
    AI Governance Gap Analysis — reads inventory output, generates Markdown report
.DESCRIPTION
    Analyzes the output from AI_Inventory.ps1 and produces a governance gap
    analysis with risk scores, findings, and remediation steps.
    
    Read-only — analyzes existing CSV/JSON files, writes only the report.

.PARAMETER InputPath
    Path to the ai_inventory_* folder containing CSV/JSON output files.
.PARAMETER OutputFile
    Path for the Markdown report. Default: governance_gap_analysis.md in InputPath.

.EXAMPLE
    .\Governance_Analysis.ps1 -InputPath ./ai_inventory_20260818_091903
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$InputPath,
    [string]$OutputFile
)

$ErrorActionPreference = "Continue"
if (-not $OutputFile) { $OutputFile = Join-Path $InputPath "governance_gap_analysis.md" }

# ── Load data ────────────────────────────────────────────────────────────
Write-Host "[INFO] Loading inventory from: $InputPath" -ForegroundColor Cyan

$inventory = @()
$openai = @()
$computes = @()
$network = @()
$tags = @()
$diag = @()
$rbac = @()
$policy = @()

$f = Join-Path $InputPath "ai_asset_inventory.csv"
if (Test-Path $f) { $inventory = Import-Csv $f }

$f = Join-Path $InputPath "openai_deployments.csv"
if (Test-Path $f) { $openai = Import-Csv $f }

$f = Join-Path $InputPath "ml_computes.csv"
if (Test-Path $f) { $computes = Import-Csv $f }

$f = Join-Path $InputPath "network_audit.csv"
if (Test-Path $f) { $network = Import-Csv $f }

$f = Join-Path $InputPath "tag_audit.csv"
if (Test-Path $f) { $tags = Import-Csv $f }

$f = Join-Path $InputPath "diagnostic_gaps.csv"
if (Test-Path $f) { $diag = Import-Csv $f }

$f = Join-Path $InputPath "rbac_ai_assignments.csv"
if (Test-Path $f) { $rbac = Import-Csv $f }

$f = Join-Path $InputPath "policy_assignments.csv"
if (Test-Path $f) { $policy = Import-Csv $f }

Write-Host "[ OK ] Loaded: $($inventory.Count) resources, $($openai.Count) OpenAI deployments, $($computes.Count) computes" -ForegroundColor Green

# ── Analyze ──────────────────────────────────────────────────────────────

# Network
$pubAccess = @($network | Where-Object { $_.PublicAccess -eq "Enabled" })
$privateOk = @($network | Where-Object { $_.NetworkIsolation -eq "Yes" })
$noPrivate = @($network | Where-Object { $_.NetworkIsolation -ne "Yes" -and $_.PublicAccess -ne "N/A" })

# Identity
$noIdentity = @($inventory | Where-Object { $_.ManagedIdentity -eq "None" -or $_.ManagedIdentity -eq "" })
$sysAssigned = @($inventory | Where-Object { $_.ManagedIdentity -eq "SystemAssigned" })
$userAssigned = @($inventory | Where-Object { $_.ManagedIdentity -eq "UserAssigned" })

# Tags — analyze what they HAVE vs what's missing
$allTagStrings = $inventory | Where-Object { $_.Tags } | ForEach-Object { $_.Tags }
$existingTagKeys = @{}
foreach ($ts in $allTagStrings) {
    $pairs = $ts -split ";\s*"
    foreach ($p in $pairs) {
        $key = ($p -split "=")[0].Trim()
        if ($key) {
            if (-not $existingTagKeys.ContainsKey($key)) { $existingTagKeys[$key] = 0 }
            $existingTagKeys[$key]++
        }
    }
}

# GPU vs CPU computes
$gpuComputes = @($computes | Where-Object { $_.VMSize -match "Standard_N" })
$cpuComputes = @($computes | Where-Object { $_.VMSize -notmatch "Standard_N" -and $_.VMSize -ne "Managed" -and $_.VMSize -ne "N/A" })

# Subscriptions scanned
$subList = $inventory | Select-Object -Property SubscriptionId, SubscriptionName -Unique

# Resource types
$typeBreakdown = $inventory | Group-Object ResourceType | Sort-Object Count -Descending

# Regions
$regionBreakdown = $inventory | Group-Object Location | Sort-Object Count -Descending

# Kinds
$kindBreakdown = $inventory | Group-Object Kind | Sort-Object Count -Descending

# ── Risk scoring ─────────────────────────────────────────────────────────
$risks = @()

# Network risk
if ($pubAccess.Count -gt 0) {
    $risks += [PSCustomObject]@{ Area="Public Network Access"; Finding="$($pubAccess.Count) resources with public access enabled"; Severity="CRITICAL"; Score=10; Remediation="Deploy Azure Policy to deny public endpoints on CognitiveServices and MachineLearningServices" }
}
if ($noPrivate.Count -gt 0 -and $pubAccess.Count -eq 0) {
    $risks += [PSCustomObject]@{ Area="Network Isolation Gaps"; Finding="$($noPrivate.Count) resources without full private endpoint isolation"; Severity="HIGH"; Score=8; Remediation="Configure private endpoints for all AI resources" }
}

# Identity risk
if ($noIdentity.Count -gt 0) {
    $names = ($noIdentity | ForEach-Object { $_.ResourceName }) -join ", "
    $risks += [PSCustomObject]@{ Area="No Managed Identity"; Finding="$($noIdentity.Count) resource(s) using key-based auth: $names"; Severity="CRITICAL"; Score=10; Remediation="Enable managed identity; rotate and disable access keys" }
}

# Policy risk
if ($policy.Count -eq 0) {
    $risks += [PSCustomObject]@{ Area="Zero AI Policies"; Finding="No AI-specific Azure Policy assignments found"; Severity="CRITICAL"; Score=10; Remediation="Deploy MCSB-aligned AI policy initiative: deny public access, require managed identity, enforce tagging, require diagnostics" }
}

# RBAC risk
if ($rbac.Count -eq 0) {
    $risks += [PSCustomObject]@{ Area="No AI-Scoped RBAC"; Finding="No resource-level RBAC assignments on AI resources"; Severity="HIGH"; Score=8; Remediation="Implement least-privilege RBAC at resource group level; use PIM for admin roles" }
}

# Diagnostics risk
if ($diag.Count -gt 0) {
    $risks += [PSCustomObject]@{ Area="Missing Diagnostics"; Finding="$($diag.Count) resources without diagnostic settings"; Severity="HIGH"; Score=7; Remediation="Configure diagnostic settings to Log Analytics workspace on all AI resources" }
}

# Tag risk
if ($tags.Count -gt 0) {
    $risks += [PSCustomObject]@{ Area="Tag Non-Compliance"; Finding="$($tags.Count)/$($inventory.Count) resources missing governance tags"; Severity="MEDIUM"; Score=5; Remediation="Map existing tags to governance schema; add missing tags (cost-center, ai-service-tier)" }
}

# OpenAI deployments
if ($openai.Count -eq 0 -and ($inventory | Where-Object { $_.Kind -eq "OpenAI" }).Count -gt 0) {
    $risks += [PSCustomObject]@{ Area="OpenAI Config Gap"; Finding="OpenAI account(s) exist but 0 model deployments captured"; Severity="MEDIUM"; Score=5; Remediation="Verify model deployments exist; confirm content filter policies are applied" }
}

# GPU
if ($gpuComputes.Count -eq 0 -and $computes.Count -gt 0) {
    $risks += [PSCustomObject]@{ Area="No GPU Compute"; Finding="All $($cpuComputes.Count) ML computes are CPU-only (no GPU)"; Severity="INFO"; Score=3; Remediation="Expected — GPU quota requests are pending. Monitor capacity tracker." }
}

# Coverage
if ($subList.Count -le 1) {
    $risks += [PSCustomObject]@{ Area="Limited Scan Coverage"; Finding="Only $($subList.Count) subscription scanned — customer has 7+ subscriptions"; Severity="HIGH"; Score=8; Remediation="Run inventory across all subscriptions: EU Prod, EU Non-Prod, Americas Non-Prod, Management, Ejento" }
}

$risks = $risks | Sort-Object Score -Descending

# Overall grade
$avgScore = if ($risks.Count -gt 0) { [math]::Round(($risks | Measure-Object Score -Average).Average, 1) } else { 0 }
$grade = switch ([int]$avgScore) {
    { $_ -ge 9 } { "F" }
    { $_ -ge 7 } { "D" }
    { $_ -ge 5 } { "C" }
    { $_ -ge 3 } { "B" }
    default { "A" }
}

# ── Generate report ──────────────────────────────────────────────────────
Write-Host "[INFO] Generating governance gap analysis..." -ForegroundColor Cyan

$report = @"
# Contoso — AI Governance Gap Analysis

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm")
**Source:** Inventory collected $(Split-Path $InputPath -Leaf)
**Subscriptions Scanned:** $($subList.Count)
**Total AI Resources:** $($inventory.Count)

---

## Overall Governance Grade: $grade (Score: $avgScore/10)

$(if ($grade -eq "F" -or $grade -eq "D") { "> ⚠️ **Significant governance gaps exist.** Critical items require immediate remediation before production AI workloads scale." }
  elseif ($grade -eq "C") { "> 🟡 **Moderate governance maturity.** Foundation exists but key controls are missing." }
  else { "> 🟢 **Good governance posture.** Minor improvements recommended." })

---

## Risk Dashboard

| # | Risk Area | Finding | Severity | Remediation |
|---|-----------|---------|----------|-------------|
$($risks | ForEach-Object { $i++; "| $i | **$($_.Area)** | $($_.Finding) | $($_.Severity) | $($_.Remediation) |" } | Out-String)

---

## Resource Inventory

### Resources by Type

| Resource Type | Count |
|---------------|-------|
$($typeBreakdown | ForEach-Object { "| $($_.Name) | $($_.Count) |" } | Out-String)

### Resources by Region

| Region | Count |
|--------|-------|
$($regionBreakdown | ForEach-Object { "| $($_.Name) | $($_.Count) |" } | Out-String)

### Resources by Kind

| Kind | Count |
|------|-------|
$($kindBreakdown | ForEach-Object { "| $($_.Name) | $($_.Count) |" } | Out-String)

### Subscriptions Scanned

| Subscription ID | Name |
|-----------------|------|
$($subList | ForEach-Object { "| $($_.SubscriptionId) | $($_.SubscriptionName) |" } | Out-String)

---

## Detailed Findings

### 1. Network Isolation

| Resource | Public Access | Private Endpoints | Isolated |
|----------|-------------|-------------------|----------|
$($network | ForEach-Object { "| $($_.ResourceName) | $($_.PublicAccess) | $($_.PrivateEndpoints) | $($_.NetworkIsolation) |" } | Out-String)

**Assessment:** $(if ($pubAccess.Count -eq 0) { "✅ All resources have public access disabled." } else { "🔴 $($pubAccess.Count) resources have public access ENABLED." })
$(if ($privateOk.Count -eq $network.Count) { "✅ All resources have private endpoint isolation." } else { "$($privateOk.Count)/$($network.Count) resources fully isolated." })

### 2. Identity & Access

| Resource | Managed Identity | Risk |
|----------|-----------------|------|
$($inventory | ForEach-Object {
    $risk = if ($_.ManagedIdentity -eq "None" -or $_.ManagedIdentity -eq "") { "🔴 KEY-BASED AUTH" } else { "✅ $($_.ManagedIdentity)" }
    "| $($_.ResourceName) | $($_.ManagedIdentity) | $risk |"
} | Out-String)

**Assessment:** $($noIdentity.Count) resource(s) without managed identity. $(if ($noIdentity.Count -gt 0) { "These are using API keys — rotate keys and enable managed identity immediately." })

**RBAC:** $(if ($rbac.Count -eq 0) { "🔴 No resource-scoped RBAC assignments found. All access is inherited from subscription level. Implement least-privilege roles." } else { "$($rbac.Count) role assignments found on AI resources." })

### 3. Azure Policy Enforcement

$(if ($policy.Count -eq 0) {
"🔴 **No AI-specific Azure Policies are assigned.**

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
| Restrict allowed VM SKUs for ML compute | Deny | Control GPU spend |"
} else {
"$($policy.Count) AI policies found:

$($policy | ForEach-Object { "- **$($_.PolicyName)** (Enforcement: $($_.Enforcement), Effect: $($_.Effect))" } | Out-String)"
})

### 4. Tagging Compliance

**Existing Tag Schema (customer-defined):**

| Tag Key | Resources Using It |
|---------|--------------------|
$($existingTagKeys.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "| $($_.Key) | $($_.Value) |" } | Out-String)

**Missing Governance Tags:**

| Resource | Missing Tags |
|----------|-------------|
$($tags | ForEach-Object { "| $($_.ResourceName) | $($_.MissingTags) |" } | Out-String)

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

$(if ($diag.Count -eq 0) {
"✅ **No diagnostic gaps found.** All scanned AI resources have diagnostic settings configured."
} else {
"🔴 **$($diag.Count) resources without diagnostic settings:**

$($diag | ForEach-Object { "- $($_.ResourceName) ($($_.ResourceType))" } | Out-String)"
})

### 6. ML Compute Resources

$(if ($computes.Count -eq 0) {
"No ML compute resources found in scanned subscriptions."
} else {
"| Compute | VM Size | Type | GPU? | Workspace |
|---------|---------|------|------|-----------|
$($computes | ForEach-Object {
    $isGpu = if ($_.VMSize -match 'Standard_N') { '✅ GPU' } else { '❌ CPU only' }
    "| $($_.ComputeName) | $($_.VMSize) | $($_.ComputeType) | $isGpu | $($_.WorkspaceName) |"
} | Out-String)"
})

### 7. OpenAI Deployments

$(if ($openai.Count -eq 0) {
    $oaiAccounts = @($inventory | Where-Object { $_.Kind -eq "OpenAI" })
    if ($oaiAccounts.Count -gt 0) {
"⚠️ **$($oaiAccounts.Count) OpenAI account(s) exist but 0 model deployments were captured.**

Verify:
- Are models deployed? (check Azure Portal → OpenAI → Model deployments)
- Are content filter policies applied?
- Script may need Cognitive Services Contributor role to list deployments"
    } else { "No OpenAI accounts found." }
} else {
"| Account | Deployment | Model | Version | SKU | Capacity | Content Filter |
|---------|-----------|-------|---------|-----|----------|----------------|
$($openai | ForEach-Object { "| $($_.AccountName) | $($_.DeploymentName) | $($_.ModelName) | $($_.ModelVersion) | $($_.SKU) | $($_.Capacity) | $($_.ContentFilter) |" } | Out-String)"
})

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

- [ ] Enable managed identity on OpenAI account ``oaia3shp001``
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
"@

$report | Out-File $OutputFile -Encoding utf8
Write-Host "`n[ OK ] Governance gap analysis saved to: $OutputFile" -ForegroundColor Green
Write-Host "[ OK ] Found $($risks.Count) risk areas, grade: $grade ($avgScore/10)" -ForegroundColor Green
