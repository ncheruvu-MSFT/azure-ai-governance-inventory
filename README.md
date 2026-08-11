# Azure AI Governance Inventory

Discover and audit all AI/ML resources across Azure subscriptions for governance workshops. Generates a comprehensive inventory with security, compliance, and cost governance findings.

## What it collects

| Area | Details |
|------|---------|
| **AI/ML Resources** | Cognitive Services (OpenAI, Doc Intelligence, Speech, etc.), ML Workspaces, AI Foundry Hubs/Projects, AI Search, Bot Service |
| **OpenAI Deployments** | Model name, version, capacity (TPM), SKU, content filter policy |
| **ML Computes & Endpoints** | Compute clusters, instances, managed online endpoints, batch endpoints, VM sizes, GPU types |
| **Network Posture** | Public access status, private endpoint count, network isolation assessment |
| **Tag Compliance** | Missing required governance tags per resource |
| **Diagnostic Coverage** | Resources without diagnostic settings (no audit logging) |
| **RBAC Assignments** | Role assignments scoped to AI resources |
| **Azure Policy** | AI-related policy assignments and enforcement mode |

## Prerequisites

- **Azure CLI** (`az`) v2.50+ — [Install](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
- **Azure ML CLI extension** — `az extension add -n ml`
- **RBAC** — `Reader` role on target subscriptions (no write permissions needed)
- **Environment** — Azure Cloud Shell (Bash or PowerShell) **or** local terminal with `az login`

> **Read-only guarantee:** These scripts use only `az ... list`, `az ... show`, and `az resource show` commands. No resources are created, modified, or deleted.

## Quick Start

### Option 1: Azure Cloud Shell (recommended)

```bash
# Upload or clone the repo
git clone <repo-url>
cd azure-ai-governance-inventory

# Bash — scan all subscriptions
chmod +x scripts/ai_inventory.sh
./scripts/ai_inventory.sh

# PowerShell — scan all subscriptions
./scripts/AI_Inventory.ps1
```

### Option 2: Local machine

```bash
# Login first
az login

# Bash
./scripts/ai_inventory.sh

# PowerShell
.\scripts\AI_Inventory.ps1
```

### Target specific subscriptions

```bash
# Bash
./scripts/ai_inventory.sh -s "sub-id-1,sub-id-2"

# PowerShell
.\scripts\AI_Inventory.ps1 -SubscriptionIds "sub-id-1","sub-id-2"
```

### Include supporting infrastructure

```bash
# Also scan Storage, Key Vault, ACR, AKS linked to AI resources
./scripts/ai_inventory.sh -i

.\scripts\AI_Inventory.ps1 -IncludeSupporting $true
```

## Output

Scripts create a timestamped folder `ai_inventory_<YYYYMMDD_HHMMSS>/` with:

| File | Format | Description |
|------|--------|-------------|
| `ai_asset_inventory.csv` | CSV | Master inventory of all AI/ML resources |
| `ai_asset_inventory.json` | JSON | Same data in JSON |
| `openai_deployments.csv` | CSV | OpenAI model deployments, capacity, content filters |
| `ml_computes.csv` | CSV | ML compute targets, endpoints, VM sizes, GPU info |
| `network_audit.csv` | CSV | Network isolation status per resource |
| `tag_audit.csv` | CSV | Resources missing required governance tags |
| `diagnostic_gaps.csv` | CSV | Resources without diagnostic settings |
| `rbac_ai_assignments.csv` | CSV | RBAC role assignments on AI resources |
| `policy_assignments.csv` | CSV | AI-related Azure Policy assignments |
| `governance_summary.md` | Markdown | Executive summary with risk dashboard |

## Required RBAC Permissions

The scripts require **only read permissions**. The minimum built-in role is:

| Role | Scope | Purpose |
|------|-------|---------|
| **Reader** | Subscription | List and read all resource properties |

For a custom least-privilege role, the required actions are:

```json
{
  "actions": [
    "*/read",
    "Microsoft.CognitiveServices/accounts/deployments/read",
    "Microsoft.MachineLearningServices/workspaces/computes/read",
    "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
    "Microsoft.MachineLearningServices/workspaces/batchEndpoints/read",
    "Microsoft.Authorization/roleAssignments/read",
    "Microsoft.Authorization/policyAssignments/read",
    "Microsoft.Insights/diagnosticSettings/read",
    "Microsoft.Network/privateEndpointConnections/read"
  ],
  "notActions": [],
  "dataActions": [],
  "notDataActions": []
}
```

## Governance Tags

The scripts check for these required tags (configurable in the script):

| Tag | Purpose |
|-----|---------|
| `owner` | Resource owner for accountability |
| `cost-center` | Chargeback and cost allocation |
| `environment` | Dev / Test / UAT / Production |
| `data-classification` | Public / Internal / Confidential / Restricted |
| `ai-service-tier` | Tier 1 (Core) / Tier 2 (Standard) / Tier 3 (Specialty) |

## Sample Governance Summary Output

```
## Governance Risk Dashboard

| Risk Area               | Finding                       | Severity |
|-------------------------|-------------------------------|----------|
| Public Network Access   | 3 resources exposed           | HIGH     |
| Missing Governance Tags | 12 resources non-compliant    | MEDIUM   |
| No Managed Identity     | 2 resources using keys        | HIGH     |
| Missing Diagnostics     | 5 resources without logging   | MEDIUM   |
| No AI Policies          | No AI-specific policies found | HIGH     |
```

## Contributing

1. Fork this repository
2. Create a feature branch
3. Submit a pull request

## License

MIT
