<#
.SYNOPSIS
    Azure AI/ML Asset Inventory (Read-Only)

.DESCRIPTION
    Discovers all AI-related resources across Azure subscriptions for
    governance workshops. Uses ONLY read operations — requires Reader RBAC.

    Works in: Azure Cloud Shell (PowerShell) | Local with 'az login'

.PARAMETER SubscriptionIds
    Specific subscription IDs. Default: all enabled subscriptions.
.PARAMETER OutputPath
    Output directory. Default: ./ai_inventory_<timestamp>
.PARAMETER IncludeSupporting
    Include supporting infra (Storage, KeyVault, ACR, AKS). Default: $false

.EXAMPLE
    .\AI_Inventory.ps1
    .\AI_Inventory.ps1 -SubscriptionIds "id1","id2"
    .\AI_Inventory.ps1 -IncludeSupporting $true
#>

param(
    [string[]]$SubscriptionIds,
    [string]$OutputPath,
    [bool]$IncludeSupporting = $false
)

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $OutputPath) { $OutputPath = "./ai_inventory_$timestamp" }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# ── Required governance tags (configurable) ─────────────────────────────
$requiredTags = @("owner", "cost-center", "environment", "data-classification", "ai-service-tier")

# ── Preflight ───────────────────────────────────────────────────────────
Write-Host "`n[INFO] Preflight checks..." -ForegroundColor Cyan

# Azure CLI
$azVersion = az version 2>$null | ConvertFrom-Json
if (-not $azVersion) {
    Write-Host "[ERR] Azure CLI not found. Install: https://aka.ms/install-azure-cli" -ForegroundColor Red
    exit 1
}
Write-Host "[ OK ] Azure CLI $($azVersion.'azure-cli')" -ForegroundColor Green

# Auth
try {
    $account = az account show 2>$null | ConvertFrom-Json
    Write-Host "[ OK ] Authenticated as: $($account.user.name)" -ForegroundColor Green
} catch {
    Write-Host "[ERR] Not authenticated. Run 'az login' or open Cloud Shell." -ForegroundColor Red
    exit 1
}

# ML extension
$mlExt = az extension show -n ml 2>$null | ConvertFrom-Json
if (-not $mlExt) {
    Write-Host "[INFO] Installing Azure ML CLI extension..." -ForegroundColor Cyan
    az extension add -n ml --yes 2>$null
    Write-Host "[ OK ] ML extension installed" -ForegroundColor Green
} else {
    Write-Host "[ OK ] ML extension v$($mlExt.version)" -ForegroundColor Green
}

# ── Get subscriptions ───────────────────────────────────────────────────
if (-not $SubscriptionIds) {
    Write-Host "[INFO] Discovering all enabled subscriptions..." -ForegroundColor Cyan
    $subs = az account list --query "[?state=='Enabled'].{id:id, name:name}" -o json 2>$null | ConvertFrom-Json
} else {
    $subs = @()
    foreach ($sid in $SubscriptionIds) {
        $s = az account show --subscription $sid --query "{id:id, name:name}" -o json 2>$null | ConvertFrom-Json
        $subs += $s
    }
}
Write-Host "[INFO] Found $($subs.Count) subscription(s) to scan`n" -ForegroundColor Cyan

# ── Resource type filter ────────────────────────────────────────────────
$aiFilter = "type=='Microsoft.CognitiveServices/accounts' || type=='Microsoft.MachineLearningServices/workspaces' || type=='Microsoft.MachineLearningServices/registries' || type=='Microsoft.Search/searchServices' || type=='Microsoft.BotService/botServices'"

if ($IncludeSupporting) {
    $aiFilter += " || type=='Microsoft.Storage/storageAccounts' || type=='Microsoft.KeyVault/vaults' || type=='Microsoft.ContainerRegistry/registries' || type=='Microsoft.ContainerService/managedClusters' || type=='Microsoft.Network/privateEndpoints' || type=='Microsoft.Insights/components'"
}

# ── Initialize collections ──────────────────────────────────────────────
$masterInventory   = [System.Collections.ArrayList]::new()
$openaiDeployments = [System.Collections.ArrayList]::new()
$mlComputes        = [System.Collections.ArrayList]::new()
$networkAudit      = [System.Collections.ArrayList]::new()
$tagAudit          = [System.Collections.ArrayList]::new()
$diagnosticGaps    = [System.Collections.ArrayList]::new()
$rbacEntries       = [System.Collections.ArrayList]::new()
$policyData        = [System.Collections.ArrayList]::new()

# ── Scan each subscription ──────────────────────────────────────────────
foreach ($sub in $subs) {
    $subId   = $sub.id
    $subName = $sub.name

    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "[INFO] Scanning: $subName ($subId)" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan

    # ── 1. Core AI Resources (read-only: az resource list + show) ───────
    Write-Host "  [SCAN] AI/ML Resources..." -ForegroundColor Yellow

    $resources = az resource list --subscription $subId `
        --query "[$([char]63)$aiFilter]" -o json 2>$null | ConvertFrom-Json

    foreach ($res in $resources) {
        # Read-only detail fetch
        $detail = $null
        try {
            $detail = az resource show --ids $res.id `
                --query "{sku:sku.name, provState:properties.provisioningState, pubAccess:properties.publicNetworkAccess, identity:identity.type, endpoint:properties.endpoint}" `
                -o json 2>$null | ConvertFrom-Json
        } catch { }

        # Private endpoints (read-only list)
        $peCount = 0
        try {
            $peCount = az network private-endpoint-connection list --id $res.id `
                --query "length(@)" -o tsv 2>$null
            if (-not $peCount) { $peCount = 0 }
        } catch { $peCount = 0 }

        # Tag analysis
        $tagStr = ""
        $missingTags = @()
        if ($res.tags) {
            $tagKeys = ($res.tags | Get-Member -MemberType NoteProperty).Name
            $tagStr = ($tagKeys | ForEach-Object { "$_=$($res.tags.$_)" }) -join "; "
            $lowerKeys = $tagKeys | ForEach-Object { $_.ToLower() }
            foreach ($rt in $requiredTags) {
                if ($rt -notin $lowerKeys) { $missingTags += $rt }
            }
        } else {
            $missingTags = $requiredTags
        }

        $netIsolation = "No"
        if ($detail.pubAccess -eq "Disabled" -and [int]$peCount -gt 0) { $netIsolation = "Yes" }

        [void]$masterInventory.Add([PSCustomObject]@{
            SubscriptionId      = $subId
            SubscriptionName    = $subName
            ResourceGroup       = $res.resourceGroup
            ResourceName        = $res.name
            ResourceType        = $res.type
            Kind                = $(if ($res.kind) { $res.kind } else { "N/A" })
            SKU                 = $(if ($detail.sku) { $detail.sku } else { "N/A" })
            Location            = $res.location
            ProvisioningState   = $(if ($detail.provState) { $detail.provState } else { "N/A" })
            PublicNetworkAccess = $(if ($detail.pubAccess) { $detail.pubAccess } else { "N/A" })
            PrivateEndpoints    = [int]$peCount
            ManagedIdentity     = $(if ($detail.identity) { $detail.identity } else { "None" })
            Endpoint            = $(if ($detail.endpoint) { $detail.endpoint } else { "N/A" })
            Tags                = $tagStr
            MissingTags         = $($missingTags -join ", ")
        })

        [void]$networkAudit.Add([PSCustomObject]@{
            SubscriptionId = $subId; ResourceGroup = $res.resourceGroup
            ResourceName = $res.name; ResourceType = $res.type
            Kind = $(if ($res.kind) { $res.kind } else { "N/A" })
            PublicAccess = $(if ($detail.pubAccess) { $detail.pubAccess } else { "N/A" })
            PrivateEndpoints = [int]$peCount; NetworkIsolation = $netIsolation
        })

        if ($missingTags.Count -gt 0) {
            [void]$tagAudit.Add([PSCustomObject]@{
                SubscriptionId = $subId; ResourceGroup = $res.resourceGroup
                ResourceName = $res.name; ResourceType = $res.type
                MissingTags = $($missingTags -join ", ")
            })
        }

        Write-Host "  [ OK ] $($res.name) ($($res.type) - $($res.kind)) [$($res.location)]" -ForegroundColor Green
    }

    # ── 2. OpenAI Deployments (read-only: deployment list) ──────────────
    Write-Host "  [SCAN] Azure OpenAI Deployments..." -ForegroundColor Yellow

    $oaiAccounts = az cognitiveservices account list --subscription $subId `
        --query "[?kind=='OpenAI'].{name:name, rg:resourceGroup}" -o json 2>$null | ConvertFrom-Json

    foreach ($acct in $oaiAccounts) {
        $deps = az cognitiveservices account deployment list `
            --subscription $subId -g $acct.rg -n $acct.name -o json 2>$null | ConvertFrom-Json

        foreach ($dep in $deps) {
            [void]$openaiDeployments.Add([PSCustomObject]@{
                SubscriptionId = $subId
                ResourceGroup  = $acct.rg
                AccountName    = $acct.name
                DeploymentName = $dep.name
                ModelName      = $dep.properties.model.name
                ModelVersion   = $dep.properties.model.version
                ModelFormat    = $(if ($dep.properties.model.format) { $dep.properties.model.format } else { "N/A" })
                SKU            = $dep.sku.name
                Capacity       = $dep.sku.capacity
                ContentFilter  = $(if ($dep.properties.raiPolicyName) { $dep.properties.raiPolicyName } else { "Default" })
            })
            Write-Host "  [ OK ] OpenAI: $($dep.name) ($($dep.properties.model.name) v$($dep.properties.model.version)) cap=$($dep.sku.capacity)" -ForegroundColor Green
        }
    }

    # ── 3. ML Computes & Endpoints (read-only: list) ────────────────────
    Write-Host "  [SCAN] Azure ML Workspaces & Computes..." -ForegroundColor Yellow

    $wsList = az ml workspace list --subscription $subId `
        --query "[].{name:name, rg:resource_group, kind:kind}" -o json 2>$null | ConvertFrom-Json

    foreach ($ws in $wsList) {
        # Compute targets
        $computes = az ml compute list --subscription $subId -g $ws.rg -w $ws.name -o json 2>$null | ConvertFrom-Json
        foreach ($c in $computes) {
            $vmSize = "N/A"; $nodes = "N/A"
            if ($c.type -eq "amlcompute") { $vmSize = $c.size; $nodes = "$($c.min_instances)-$($c.max_instances)" }
            elseif ($c.type -eq "computeinstance") { $vmSize = $c.size; $nodes = "1" }

            [void]$mlComputes.Add([PSCustomObject]@{
                SubscriptionId = $subId; ResourceGroup = $ws.rg
                WorkspaceName = $ws.name; WorkspaceKind = $(if ($ws.kind) { $ws.kind } else { "Default" })
                ComputeName = $c.name; ComputeType = $c.type; VMSize = $vmSize
                Nodes = $nodes; State = $c.provisioning_state
            })
            Write-Host "  [ OK ] Compute: $($c.name) ($($c.type) - $vmSize)" -ForegroundColor Green
        }

        # Online endpoints
        $eps = az ml online-endpoint list --subscription $subId -g $ws.rg -w $ws.name `
            --query "[].{name:name, state:provisioning_state}" -o json 2>$null | ConvertFrom-Json
        foreach ($ep in $eps) {
            [void]$mlComputes.Add([PSCustomObject]@{
                SubscriptionId = $subId; ResourceGroup = $ws.rg
                WorkspaceName = $ws.name; WorkspaceKind = $(if ($ws.kind) { $ws.kind } else { "Default" })
                ComputeName = $ep.name; ComputeType = "ManagedOnlineEndpoint"
                VMSize = "Managed"; Nodes = "Auto"; State = $ep.state
            })
            Write-Host "  [ OK ] Endpoint: $($ep.name) (Online)" -ForegroundColor Green
        }

        # Batch endpoints
        $beps = az ml batch-endpoint list --subscription $subId -g $ws.rg -w $ws.name `
            --query "[].{name:name, state:provisioning_state}" -o json 2>$null | ConvertFrom-Json
        foreach ($bep in $beps) {
            [void]$mlComputes.Add([PSCustomObject]@{
                SubscriptionId = $subId; ResourceGroup = $ws.rg
                WorkspaceName = $ws.name; WorkspaceKind = $(if ($ws.kind) { $ws.kind } else { "Default" })
                ComputeName = $bep.name; ComputeType = "BatchEndpoint"
                VMSize = "Managed"; Nodes = "Auto"; State = $bep.state
            })
            Write-Host "  [ OK ] Endpoint: $($bep.name) (Batch)" -ForegroundColor Green
        }
    }

    # ── 4. Diagnostics (read-only: diagnostic-settings list) ────────────
    Write-Host "  [SCAN] Diagnostic settings..." -ForegroundColor Yellow

    $aiRes = az resource list --subscription $subId `
        --query "[?type=='Microsoft.CognitiveServices/accounts' || type=='Microsoft.MachineLearningServices/workspaces' || type=='Microsoft.Search/searchServices'].{id:id, name:name, type:type}" `
        -o json 2>$null | ConvertFrom-Json

    foreach ($r in $aiRes) {
        $diagCount = 0
        try {
            $diagCount = az monitor diagnostic-settings list --resource $r.id `
                --query "length(value)" -o tsv 2>$null
            if (-not $diagCount) { $diagCount = 0 }
        } catch { }

        if ([int]$diagCount -eq 0) {
            [void]$diagnosticGaps.Add([PSCustomObject]@{
                SubscriptionId = $subId; ResourceName = $r.name
                ResourceType = $r.type; Issue = "No diagnostic settings"
            })
            Write-Host "  [WARN] No diagnostics: $($r.name)" -ForegroundColor Yellow
        } else {
            Write-Host "  [ OK ] Diagnostics: $($r.name) ($diagCount settings)" -ForegroundColor Green
        }
    }

    # ── 5. RBAC (read-only: role assignment list) ───────────────────────
    Write-Host "  [SCAN] RBAC on AI resources..." -ForegroundColor Yellow

    $rbac = az role assignment list --subscription $subId --all `
        --query "[?contains(scope,'Microsoft.CognitiveServices') || contains(scope,'Microsoft.MachineLearningServices') || contains(scope,'Microsoft.Search')].{principal:principalName, role:roleDefinitionName, scope:scope, type:principalType}" `
        -o json 2>$null | ConvertFrom-Json

    foreach ($r in $rbac) {
        [void]$rbacEntries.Add([PSCustomObject]@{
            SubscriptionId = $subId; Principal = $r.principal
            Role = $r.role; PrincipalType = $r.type; Scope = $r.scope
        })
    }
    if ($rbac.Count -gt 0) { Write-Host "  [ OK ] $($rbac.Count) AI RBAC assignments" -ForegroundColor Green }

    # ── 6. Policies (read-only: policy assignment list) ─────────────────
    Write-Host "  [SCAN] AI policy assignments..." -ForegroundColor Yellow

    $pols = az policy assignment list --subscription $subId `
        --query "[?contains(displayName,'Cognitive') || contains(displayName,'AI') || contains(displayName,'Machine Learning') || contains(displayName,'OpenAI') || contains(displayName,'Search')].{name:displayName, enforcement:enforcementMode, effect:parameters.effect.value}" `
        -o json 2>$null | ConvertFrom-Json

    foreach ($p in $pols) {
        [void]$policyData.Add([PSCustomObject]@{
            SubscriptionId = $subId; PolicyName = $p.name
            Enforcement = $p.enforcement; Effect = $(if ($p.effect) { $p.effect } else { "N/A" })
        })
    }
    if ($pols.Count -gt 0) { Write-Host "  [ OK ] $($pols.Count) AI policies" -ForegroundColor Green }
    else { Write-Host "  [WARN] No AI-specific policies" -ForegroundColor Yellow }

    Write-Host ""
}

# ── Export ────────────────────────────────────────────────────────────────
Write-Host "[INFO] Exporting results..." -ForegroundColor Cyan

$masterInventory   | Export-Csv "$OutputPath/ai_asset_inventory.csv" -NoTypeInformation
$openaiDeployments | Export-Csv "$OutputPath/openai_deployments.csv" -NoTypeInformation
$mlComputes        | Export-Csv "$OutputPath/ml_computes.csv" -NoTypeInformation
$networkAudit      | Export-Csv "$OutputPath/network_audit.csv" -NoTypeInformation
$tagAudit          | Export-Csv "$OutputPath/tag_audit.csv" -NoTypeInformation
$diagnosticGaps    | Export-Csv "$OutputPath/diagnostic_gaps.csv" -NoTypeInformation
$rbacEntries       | Export-Csv "$OutputPath/rbac_ai_assignments.csv" -NoTypeInformation
$policyData        | Export-Csv "$OutputPath/policy_assignments.csv" -NoTypeInformation

$masterInventory   | ConvertTo-Json -Depth 5 | Out-File "$OutputPath/ai_asset_inventory.json"
$openaiDeployments | ConvertTo-Json -Depth 5 | Out-File "$OutputPath/openai_deployments.json"

# ── Governance Summary ──────────────────────────────────────────────────
$pubCount  = ($networkAudit | Where-Object { $_.PublicAccess -eq "Enabled" }).Count
$noIdCount = ($masterInventory | Where-Object { $_.ManagedIdentity -eq "None" }).Count

$summary = @"
# Azure AI/ML Asset Inventory — Governance Report

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Scanned by:** $($account.user.name)
**Subscriptions:** $($subs.Count)
**Mode:** Read-only (Reader RBAC)

---

## Executive Summary

| Metric | Count |
|--------|-------|
| AI/ML Resources | $($masterInventory.Count) |
| OpenAI Deployments | $($openaiDeployments.Count) |
| ML Computes & Endpoints | $($mlComputes.Count) |
| RBAC Assignments | $($rbacEntries.Count) |
| Policy Assignments | $($policyData.Count) |

---

## Governance Risk Dashboard

| Risk Area | Finding | Severity |
|-----------|---------|----------|
| Public Network Access | $pubCount resources exposed | $(if($pubCount -gt 0){"🔴 HIGH"}else{"🟢 OK"}) |
| Missing Tags | $($tagAudit.Count) non-compliant | $(if($tagAudit.Count -gt 0){"🟡 MEDIUM"}else{"🟢 OK"}) |
| No Managed Identity | $noIdCount using keys | $(if($noIdCount -gt 0){"🔴 HIGH"}else{"🟢 OK"}) |
| Missing Diagnostics | $($diagnosticGaps.Count) without logging | $(if($diagnosticGaps.Count -gt 0){"🟡 MEDIUM"}else{"🟢 OK"}) |
| AI Policies | $($policyData.Count) active | $(if($policyData.Count -eq 0){"🔴 HIGH"}else{"🟢 OK"}) |

---

## Breakdown by Type

| Resource Type | Count |
|---------------|-------|
$($masterInventory | Group-Object ResourceType | Sort-Object Count -Descending | ForEach-Object { "| $($_.Name) | $($_.Count) |" } | Out-String)

## Breakdown by Region

| Location | Count |
|----------|-------|
$($masterInventory | Group-Object Location | Sort-Object Count -Descending | ForEach-Object { "| $($_.Name) | $($_.Count) |" } | Out-String)

## OpenAI Models

| Model | Deployments |
|-------|-------------|
$($openaiDeployments | Group-Object ModelName | Sort-Object Count -Descending | ForEach-Object { "| $($_.Name) | $($_.Count) |" } | Out-String)

## GPU Computes

| Compute | VM Size | Nodes | Workspace |
|---------|---------|-------|-----------|
$(($mlComputes | Where-Object { $_.VMSize -match "Standard_N" }) | ForEach-Object { "| $($_.ComputeName) | $($_.VMSize) | $($_.Nodes) | $($_.WorkspaceName) |" } | Out-String)

---

## Output Files

| File | Description |
|------|-------------|
| ai_asset_inventory.csv/json | Master resource inventory |
| openai_deployments.csv/json | Model deployments, capacity, content filters |
| ml_computes.csv | Compute targets, GPU VMs, endpoints |
| network_audit.csv | Public vs private access per resource |
| tag_audit.csv | Missing governance tags |
| diagnostic_gaps.csv | Resources without diagnostic settings |
| rbac_ai_assignments.csv | Role assignments on AI resources |
| policy_assignments.csv | AI-related policy assignments |

---

## Recommended Actions

1. **🔴 CRITICAL** — Disable public access on all AI resources; enforce via Policy (Deny)
2. **🔴 CRITICAL** — Enable managed identity; eliminate key-based auth
3. **🟡 HIGH** — Apply required governance tags to all AI resources
4. **🟡 HIGH** — Configure diagnostic settings to Log Analytics
5. **🟡 MEDIUM** — Assign MCSB-aligned AI-specific policies
6. **🟡 MEDIUM** — Audit RBAC for least-privilege on AI resources
7. **🟢 LOW** — Validate content filter policies on OpenAI deployments
"@

$summary | Out-File "$OutputPath/governance_summary.md"

# ── Done ─────────────────────────────────────────────────────────────────
Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "[ OK ] SCAN COMPLETE" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "`nOutput: $OutputPath" -ForegroundColor Cyan
Get-ChildItem $OutputPath | Format-Table Name, @{N="Size";E={"{0:N0} bytes" -f $_.Length}}, LastWriteTime -AutoSize
Write-Host "Start with: Get-Content '$OutputPath/governance_summary.md'`n" -ForegroundColor Cyan
