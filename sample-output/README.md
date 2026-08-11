# Sample Governance Summary Output

This folder shows example output from the inventory scripts.
Run the scripts against your own subscriptions to generate real data.

## Sample Risk Dashboard

| Risk Area | Finding | Severity |
|-----------|---------|----------|
| Public Network Access | 3 resources exposed | 🔴 HIGH |
| Missing Tags | 12 resources non-compliant | 🟡 MEDIUM |
| No Managed Identity | 2 resources using keys | 🔴 HIGH |
| Missing Diagnostics | 5 resources without logging | 🟡 MEDIUM |
| AI Policies | 0 assignments | 🔴 HIGH |

## Sample CSV Headers

### ai_asset_inventory.csv
```
SubscriptionId, SubscriptionName, ResourceGroup, ResourceName, ResourceType, Kind, SKU, Location, ProvisioningState, PublicNetworkAccess, PrivateEndpoints, ManagedIdentity, Endpoint, Tags, MissingTags
```

### openai_deployments.csv
```
SubscriptionId, ResourceGroup, AccountName, DeploymentName, ModelName, ModelVersion, ModelFormat, SKU, Capacity, ContentFilter
```

### ml_computes.csv
```
SubscriptionId, ResourceGroup, WorkspaceName, WorkspaceKind, ComputeName, ComputeType, VMSize, Nodes, State
```
