#!/bin/bash
###############################################################################
# Azure AI/ML Asset Inventory (Read-Only)
#
# Discovers all AI-related resources across Azure subscriptions for
# governance workshops. Uses ONLY read operations — requires Reader RBAC.
#
# Works in: Azure Cloud Shell (Bash) | Local terminal with 'az login'
#
# Usage:
#   ./ai_inventory.sh                     # All subscriptions
#   ./ai_inventory.sh -s "id1,id2"        # Specific subscriptions
#   ./ai_inventory.sh -i                  # Include supporting infra
#   ./ai_inventory.sh -h                  # Help
#
# Required: Azure CLI 2.50+, az ml extension, Reader role on subscriptions
###############################################################################

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./ai_inventory_${TIMESTAMP}"
SUBSCRIPTIONS=""
INCLUDE_SUPPORTING=false
REQUIRED_TAGS=("owner" "cost-center" "environment" "data-classification" "ai-service-tier")

# ── Parse args ──────────────────────────────────────────────────────────
while getopts "s:ih" opt; do
  case $opt in
    s) SUBSCRIPTIONS="$OPTARG" ;;
    i) INCLUDE_SUPPORTING=true ;;
    h)
      echo "Azure AI/ML Asset Inventory (Read-Only)"
      echo ""
      echo "Usage: $0 [-s subscription_ids] [-i] [-h]"
      echo "  -s  Comma-separated subscription IDs (default: all accessible)"
      echo "  -i  Include supporting infrastructure (Storage, KeyVault, ACR, AKS)"
      echo "  -h  Show this help"
      echo ""
      echo "Required RBAC: Reader on target subscriptions"
      echo "Output: Timestamped folder with CSV, JSON, and Markdown reports"
      exit 0
      ;;
    *) echo "Invalid option. Use -h for help."; exit 1 ;;
  esac
done

mkdir -p "$OUTPUT_DIR"

# ── Logging ─────────────────────────────────────────────────────────────
log()  { echo -e "\033[0;36m[INFO]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }
ok()   { echo -e "\033[0;32m[ OK ]\033[0m $1"; }
err()  { echo -e "\033[0;31m[ERR ]\033[0m $1"; }

# ── Preflight checks ───────────────────────────────────────────────────
log "Preflight checks..."

# Azure CLI
if ! command -v az &> /dev/null; then
  err "Azure CLI (az) not found. Install: https://aka.ms/install-azure-cli"
  exit 1
fi

# jq (available in Cloud Shell by default)
if ! command -v jq &> /dev/null; then
  err "jq not found. Install: https://jqlang.github.io/jq/download/"
  exit 1
fi

# Auth check
if ! az account show > /dev/null 2>&1; then
  err "Not authenticated. Run 'az login' or open Azure Cloud Shell."
  exit 1
fi

CURRENT_USER=$(az account show --query "user.name" -o tsv 2>/dev/null)
ok "Authenticated as: $CURRENT_USER"

# ML extension check
if ! az extension show -n ml > /dev/null 2>&1; then
  log "Installing Azure ML CLI extension..."
  az extension add -n ml --yes 2>/dev/null
  ok "ML extension installed"
fi

# ── Get subscriptions ─────────────────────────────────────────────────
if [ -z "$SUBSCRIPTIONS" ]; then
  log "Discovering all enabled subscriptions..."
  SUB_JSON=$(az account list --query "[?state=='Enabled'].{id:id, name:name}" -o json 2>/dev/null)
else
  SUB_JSON="["
  FIRST=true
  for sid in $(echo "$SUBSCRIPTIONS" | tr ',' ' '); do
    if [ "$FIRST" = true ]; then FIRST=false; else SUB_JSON+=","; fi
    SUB_JSON+=$(az account show --subscription "$sid" --query "{id:id, name:name}" -o json 2>/dev/null)
  done
  SUB_JSON+="]"
fi

SUB_COUNT=$(echo "$SUB_JSON" | jq 'length')
log "Found $SUB_COUNT subscription(s) to scan"

# ── Initialize CSV headers ──────────────────────────────────────────────
MASTER="$OUTPUT_DIR/ai_asset_inventory.csv"
OPENAI="$OUTPUT_DIR/openai_deployments.csv"
MLCOMP="$OUTPUT_DIR/ml_computes.csv"
NETAUDIT="$OUTPUT_DIR/network_audit.csv"
TAGAUDIT="$OUTPUT_DIR/tag_audit.csv"
DIAGGAPS="$OUTPUT_DIR/diagnostic_gaps.csv"
RBACFILE="$OUTPUT_DIR/rbac_ai_assignments.csv"
POLICYFILE="$OUTPUT_DIR/policy_assignments.csv"
JSONFILE="$OUTPUT_DIR/ai_asset_inventory.json"

echo '"SubscriptionId","SubscriptionName","ResourceGroup","ResourceName","ResourceType","Kind","SKU","Location","ProvisioningState","PublicNetworkAccess","PrivateEndpoints","ManagedIdentity","Endpoint","Tags","MissingTags"' > "$MASTER"
echo '"SubscriptionId","ResourceGroup","AccountName","DeploymentName","ModelName","ModelVersion","ModelFormat","SKU","Capacity","ContentFilter"' > "$OPENAI"
echo '"SubscriptionId","ResourceGroup","WorkspaceName","WorkspaceKind","ComputeName","ComputeType","VMSize","Nodes","State"' > "$MLCOMP"
echo '"SubscriptionId","ResourceGroup","ResourceName","ResourceType","Kind","PublicAccess","PrivateEndpoints","NetworkIsolation"' > "$NETAUDIT"
echo '"SubscriptionId","ResourceGroup","ResourceName","ResourceType","MissingTags"' > "$TAGAUDIT"
echo '"SubscriptionId","ResourceName","ResourceType","Issue"' > "$DIAGGAPS"
echo '"SubscriptionId","Principal","Role","PrincipalType","Scope"' > "$RBACFILE"
echo '"SubscriptionId","PolicyName","Enforcement","Effect"' > "$POLICYFILE"

# JSON accumulator
echo "[" > "$JSONFILE"
JSON_FIRST=true

# Counters
TOTAL_RESOURCES=0
TOTAL_OPENAI=0
TOTAL_COMPUTES=0
TOTAL_TAG_ISSUES=0
TOTAL_NET_ISSUES=0
TOTAL_NO_IDENTITY=0
TOTAL_DIAG_GAPS=0
TOTAL_RBAC=0
TOTAL_POLICIES=0

# ── Resource type filter ────────────────────────────────────────────────
AI_TYPES="type=='Microsoft.CognitiveServices/accounts' || type=='Microsoft.MachineLearningServices/workspaces' || type=='Microsoft.MachineLearningServices/registries' || type=='Microsoft.Search/searchServices' || type=='Microsoft.BotService/botServices'"

if [ "$INCLUDE_SUPPORTING" = true ]; then
  AI_TYPES="$AI_TYPES || type=='Microsoft.Storage/storageAccounts' || type=='Microsoft.KeyVault/vaults' || type=='Microsoft.ContainerRegistry/registries' || type=='Microsoft.ContainerService/managedClusters' || type=='Microsoft.Network/privateEndpoints' || type=='Microsoft.Insights/components'"
fi

# ── Scan functions ───────────────────────────────────────────────────────

scan_resources() {
  local sub_id="$1" sub_name="$2"
  log "  Scanning AI/ML resources..."

  local resources
  resources=$(az resource list --subscription "$sub_id" \
    --query "[?${AI_TYPES}].{name:name, type:type, rg:resourceGroup, location:location, kind:kind, tags:tags, id:id}" \
    -o json 2>/dev/null)

  local count
  count=$(echo "$resources" | jq 'length')

  for i in $(seq 0 $((count - 1))); do
    local item
    item=$(echo "$resources" | jq ".[$i]")

    local name rtype rg location kind tags_str rid
    name=$(echo "$item" | jq -r '.name')
    rtype=$(echo "$item" | jq -r '.type')
    rg=$(echo "$item" | jq -r '.rg')
    location=$(echo "$item" | jq -r '.location')
    kind=$(echo "$item" | jq -r '.kind // "N/A"')
    tags_str=$(echo "$item" | jq -r '.tags // {} | to_entries | map("\(.key)=\(.value)") | join("; ")')
    rid=$(echo "$item" | jq -r '.id')

    # Detail (read-only show)
    local detail sku prov_state pub_access identity endpoint
    detail=$(az resource show --ids "$rid" \
      --query "{sku:sku.name, provState:properties.provisioningState, pubAccess:properties.publicNetworkAccess, identity:identity.type, endpoint:properties.endpoint}" \
      -o json 2>/dev/null || echo '{}')

    sku=$(echo "$detail" | jq -r '.sku // "N/A"')
    prov_state=$(echo "$detail" | jq -r '.provState // "N/A"')
    pub_access=$(echo "$detail" | jq -r '.pubAccess // "N/A"')
    identity=$(echo "$detail" | jq -r '.identity // "None"')
    endpoint=$(echo "$detail" | jq -r '.endpoint // "N/A"')

    # Private endpoints (read-only list)
    local pe_count
    pe_count=$(az network private-endpoint-connection list --id "$rid" \
      --query "length(@)" -o tsv 2>/dev/null || echo "0")
    [ -z "$pe_count" ] && pe_count=0

    # Tag compliance
    local missing_tags=""
    local tag_keys
    tag_keys=$(echo "$item" | jq -r '.tags // {} | keys[]' 2>/dev/null | tr '[:upper:]' '[:lower:]')
    for rt in "${REQUIRED_TAGS[@]}"; do
      if ! echo "$tag_keys" | grep -qx "$rt"; then
        [ -n "$missing_tags" ] && missing_tags="$missing_tags, "
        missing_tags="$missing_tags$rt"
      fi
    done

    # Network isolation
    local net_isolation="No"
    if [ "$pub_access" = "Disabled" ] && [ "$pe_count" -gt 0 ]; then
      net_isolation="Yes"
    fi

    # Write master CSV
    echo "\"$sub_id\",\"$sub_name\",\"$rg\",\"$name\",\"$rtype\",\"$kind\",\"$sku\",\"$location\",\"$prov_state\",\"$pub_access\",\"$pe_count\",\"$identity\",\"$endpoint\",\"$tags_str\",\"$missing_tags\"" >> "$MASTER"

    # Network audit
    echo "\"$sub_id\",\"$rg\",\"$name\",\"$rtype\",\"$kind\",\"$pub_access\",\"$pe_count\",\"$net_isolation\"" >> "$NETAUDIT"

    # Tag audit
    if [ -n "$missing_tags" ]; then
      echo "\"$sub_id\",\"$rg\",\"$name\",\"$rtype\",\"$missing_tags\"" >> "$TAGAUDIT"
      TOTAL_TAG_ISSUES=$((TOTAL_TAG_ISSUES + 1))
    fi

    # Counters
    TOTAL_RESOURCES=$((TOTAL_RESOURCES + 1))
    [ "$pub_access" = "Enabled" ] && TOTAL_NET_ISSUES=$((TOTAL_NET_ISSUES + 1))
    [ "$identity" = "None" ] && TOTAL_NO_IDENTITY=$((TOTAL_NO_IDENTITY + 1))

    # JSON
    if [ "$JSON_FIRST" = true ]; then JSON_FIRST=false; else echo "," >> "$JSONFILE"; fi
    cat >> "$JSONFILE" <<-JEOF
  {"subscriptionId":"$sub_id","subscriptionName":"$sub_name","resourceGroup":"$rg","name":"$name","type":"$rtype","kind":"$kind","sku":"$sku","location":"$location","provisioningState":"$prov_state","publicNetworkAccess":"$pub_access","privateEndpoints":$pe_count,"managedIdentity":"$identity","endpoint":"$endpoint","missingTags":"$missing_tags"}
JEOF

    ok "    $name ($rtype - $kind) [$location]"
  done
}

scan_openai() {
  local sub_id="$1"
  log "  Scanning Azure OpenAI deployments..."

  local accounts
  accounts=$(az cognitiveservices account list --subscription "$sub_id" \
    --query "[?kind=='OpenAI'].{name:name, rg:resourceGroup}" -o json 2>/dev/null)

  local acct_count
  acct_count=$(echo "$accounts" | jq 'length')

  for i in $(seq 0 $((acct_count - 1))); do
    local rg acct_name
    rg=$(echo "$accounts" | jq -r ".[$i].rg")
    acct_name=$(echo "$accounts" | jq -r ".[$i].name")

    local deployments
    deployments=$(az cognitiveservices account deployment list \
      --subscription "$sub_id" -g "$rg" -n "$acct_name" -o json 2>/dev/null)

    local dep_count
    dep_count=$(echo "$deployments" | jq 'length')

    for j in $(seq 0 $((dep_count - 1))); do
      local dep dep_name model version format dep_sku capacity content_filter
      dep=$(echo "$deployments" | jq ".[$j]")
      dep_name=$(echo "$dep" | jq -r '.name')
      model=$(echo "$dep" | jq -r '.properties.model.name // "N/A"')
      version=$(echo "$dep" | jq -r '.properties.model.version // "N/A"')
      format=$(echo "$dep" | jq -r '.properties.model.format // "N/A"')
      dep_sku=$(echo "$dep" | jq -r '.sku.name // "N/A"')
      capacity=$(echo "$dep" | jq -r '.sku.capacity // "N/A"')
      content_filter=$(echo "$dep" | jq -r '.properties.raiPolicyName // "Default"')

      echo "\"$sub_id\",\"$rg\",\"$acct_name\",\"$dep_name\",\"$model\",\"$version\",\"$format\",\"$dep_sku\",\"$capacity\",\"$content_filter\"" >> "$OPENAI"
      TOTAL_OPENAI=$((TOTAL_OPENAI + 1))
      ok "    OpenAI: $dep_name ($model v$version) cap=$capacity"
    done
  done
}

scan_ml() {
  local sub_id="$1"
  log "  Scanning Azure ML workspaces & computes..."

  local workspaces
  workspaces=$(az ml workspace list --subscription "$sub_id" \
    --query "[].{name:name, rg:resource_group, kind:kind}" -o json 2>/dev/null || echo "[]")

  local ws_count
  ws_count=$(echo "$workspaces" | jq 'length')

  for i in $(seq 0 $((ws_count - 1))); do
    local rg ws_name ws_kind
    rg=$(echo "$workspaces" | jq -r ".[$i].rg")
    ws_name=$(echo "$workspaces" | jq -r ".[$i].name")
    ws_kind=$(echo "$workspaces" | jq -r ".[$i].kind // \"Default\"")

    # Compute targets (read-only list)
    local computes
    computes=$(az ml compute list --subscription "$sub_id" -g "$rg" -w "$ws_name" -o json 2>/dev/null || echo "[]")

    local comp_count
    comp_count=$(echo "$computes" | jq 'length')

    for j in $(seq 0 $((comp_count - 1))); do
      local comp comp_name comp_type vm_size nodes state
      comp=$(echo "$computes" | jq ".[$j]")
      comp_name=$(echo "$comp" | jq -r '.name')
      comp_type=$(echo "$comp" | jq -r '.type // "N/A"')
      vm_size=$(echo "$comp" | jq -r '.size // .properties.vmSize // "N/A"')
      nodes=$(echo "$comp" | jq -r '(.min_instances // "?") + "-" + (.max_instances // "?")')
      state=$(echo "$comp" | jq -r '.provisioning_state // "N/A"')

      echo "\"$sub_id\",\"$rg\",\"$ws_name\",\"$ws_kind\",\"$comp_name\",\"$comp_type\",\"$vm_size\",\"$nodes\",\"$state\"" >> "$MLCOMP"
      TOTAL_COMPUTES=$((TOTAL_COMPUTES + 1))
      ok "    Compute: $comp_name ($comp_type - $vm_size)"
    done

    # Online endpoints (read-only list)
    local endpoints
    endpoints=$(az ml online-endpoint list --subscription "$sub_id" -g "$rg" -w "$ws_name" \
      --query "[].{name:name, state:provisioning_state}" -o json 2>/dev/null || echo "[]")

    local ep_count
    ep_count=$(echo "$endpoints" | jq 'length')

    for j in $(seq 0 $((ep_count - 1))); do
      local ep_name ep_state
      ep_name=$(echo "$endpoints" | jq -r ".[$j].name")
      ep_state=$(echo "$endpoints" | jq -r ".[$j].state // \"N/A\"")
      echo "\"$sub_id\",\"$rg\",\"$ws_name\",\"$ws_kind\",\"$ep_name\",\"ManagedOnlineEndpoint\",\"Managed\",\"Auto\",\"$ep_state\"" >> "$MLCOMP"
      TOTAL_COMPUTES=$((TOTAL_COMPUTES + 1))
      ok "    Endpoint: $ep_name (Online)"
    done

    # Batch endpoints (read-only list)
    local batch_eps
    batch_eps=$(az ml batch-endpoint list --subscription "$sub_id" -g "$rg" -w "$ws_name" \
      --query "[].{name:name, state:provisioning_state}" -o json 2>/dev/null || echo "[]")

    local bep_count
    bep_count=$(echo "$batch_eps" | jq 'length')

    for j in $(seq 0 $((bep_count - 1))); do
      local bep_name bep_state
      bep_name=$(echo "$batch_eps" | jq -r ".[$j].name")
      bep_state=$(echo "$batch_eps" | jq -r ".[$j].state // \"N/A\"")
      echo "\"$sub_id\",\"$rg\",\"$ws_name\",\"$ws_kind\",\"$bep_name\",\"BatchEndpoint\",\"Managed\",\"Auto\",\"$bep_state\"" >> "$MLCOMP"
      TOTAL_COMPUTES=$((TOTAL_COMPUTES + 1))
      ok "    Endpoint: $bep_name (Batch)"
    done
  done
}

scan_diagnostics() {
  local sub_id="$1"
  log "  Checking diagnostic settings..."

  local ai_resources
  ai_resources=$(az resource list --subscription "$sub_id" \
    --query "[?type=='Microsoft.CognitiveServices/accounts' || type=='Microsoft.MachineLearningServices/workspaces' || type=='Microsoft.Search/searchServices'].{id:id, name:name, type:type}" \
    -o json 2>/dev/null)

  local res_count
  res_count=$(echo "$ai_resources" | jq 'length')

  for i in $(seq 0 $((res_count - 1))); do
    local res_id res_name res_type diag_count
    res_id=$(echo "$ai_resources" | jq -r ".[$i].id")
    res_name=$(echo "$ai_resources" | jq -r ".[$i].name")
    res_type=$(echo "$ai_resources" | jq -r ".[$i].type")

    diag_count=$(az monitor diagnostic-settings list --resource "$res_id" \
      --query "length(value)" -o tsv 2>/dev/null || echo "0")
    [ -z "$diag_count" ] && diag_count=0

    if [ "$diag_count" -eq 0 ]; then
      echo "\"$sub_id\",\"$res_name\",\"$res_type\",\"No diagnostic settings\"" >> "$DIAGGAPS"
      TOTAL_DIAG_GAPS=$((TOTAL_DIAG_GAPS + 1))
      warn "    No diagnostics: $res_name"
    else
      ok "    Diagnostics OK: $res_name ($diag_count settings)"
    fi
  done
}

scan_rbac() {
  local sub_id="$1"
  log "  Checking RBAC on AI resources..."

  local assignments
  assignments=$(az role assignment list --subscription "$sub_id" --all \
    --query "[?contains(scope,'Microsoft.CognitiveServices') || contains(scope,'Microsoft.MachineLearningServices') || contains(scope,'Microsoft.Search')].{principal:principalName, role:roleDefinitionName, scope:scope, type:principalType}" \
    -o json 2>/dev/null || echo "[]")

  local rbac_count
  rbac_count=$(echo "$assignments" | jq 'length')

  for i in $(seq 0 $((rbac_count - 1))); do
    local principal role ptype scope
    principal=$(echo "$assignments" | jq -r ".[$i].principal")
    role=$(echo "$assignments" | jq -r ".[$i].role")
    ptype=$(echo "$assignments" | jq -r ".[$i].type")
    scope=$(echo "$assignments" | jq -r ".[$i].scope")
    echo "\"$sub_id\",\"$principal\",\"$role\",\"$ptype\",\"$scope\"" >> "$RBACFILE"
    TOTAL_RBAC=$((TOTAL_RBAC + 1))
  done

  [ "$rbac_count" -gt 0 ] && ok "    Found $rbac_count AI RBAC assignments"
}

scan_policies() {
  local sub_id="$1"
  log "  Checking AI policy assignments..."

  local policies
  policies=$(az policy assignment list --subscription "$sub_id" \
    --query "[?contains(displayName,'Cognitive') || contains(displayName,'AI') || contains(displayName,'Machine Learning') || contains(displayName,'OpenAI') || contains(displayName,'Search')].{name:displayName, enforcement:enforcementMode, effect:parameters.effect.value}" \
    -o json 2>/dev/null || echo "[]")

  local pol_count
  pol_count=$(echo "$policies" | jq 'length')

  for i in $(seq 0 $((pol_count - 1))); do
    local pol_name enforcement effect
    pol_name=$(echo "$policies" | jq -r ".[$i].name")
    enforcement=$(echo "$policies" | jq -r ".[$i].enforcement // \"N/A\"")
    effect=$(echo "$policies" | jq -r ".[$i].effect // \"N/A\"")
    echo "\"$sub_id\",\"$pol_name\",\"$enforcement\",\"$effect\"" >> "$POLICYFILE"
    TOTAL_POLICIES=$((TOTAL_POLICIES + 1))
  done

  if [ "$pol_count" -gt 0 ]; then
    ok "    Found $pol_count AI policy assignments"
  else
    warn "    No AI-specific policies found"
  fi
}

# ── Main loop ────────────────────────────────────────────────────────────
echo ""
log "Starting AI/ML Asset Inventory (read-only scan)"
log "Output: $OUTPUT_DIR"
echo ""

for i in $(seq 0 $((SUB_COUNT - 1))); do
  sub_id=$(echo "$SUB_JSON" | jq -r ".[$i].id")
  sub_name=$(echo "$SUB_JSON" | jq -r ".[$i].name")

  echo ""
  echo "══════════════════════════════════════════════════════════"
  log "Scanning: $sub_name ($sub_id)"
  echo "══════════════════════════════════════════════════════════"

  scan_resources "$sub_id" "$sub_name"
  scan_openai "$sub_id"
  scan_ml "$sub_id"
  scan_diagnostics "$sub_id"
  scan_rbac "$sub_id"
  scan_policies "$sub_id"
done

echo "]" >> "$JSONFILE"

# ── Generate summary ─────────────────────────────────────────────────────
log "Generating governance summary..."

cat > "$OUTPUT_DIR/governance_summary.md" <<SUMMARY
# Azure AI/ML Asset Inventory — Governance Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S %Z')
**Scanned by:** $CURRENT_USER
**Subscriptions:** $SUB_COUNT
**Mode:** Read-only (Reader RBAC)

---

## Executive Summary

| Metric | Count |
|--------|-------|
| AI/ML Resources | $TOTAL_RESOURCES |
| OpenAI Deployments | $TOTAL_OPENAI |
| ML Computes & Endpoints | $TOTAL_COMPUTES |
| RBAC Assignments on AI | $TOTAL_RBAC |
| AI Policy Assignments | $TOTAL_POLICIES |

---

## Governance Risk Dashboard

| Risk Area | Finding | Severity |
|-----------|---------|----------|
| Public Network Access | $TOTAL_NET_ISSUES resources exposed | $([ $TOTAL_NET_ISSUES -gt 0 ] && echo "🔴 HIGH" || echo "🟢 OK") |
| Missing Tags | $TOTAL_TAG_ISSUES resources non-compliant | $([ $TOTAL_TAG_ISSUES -gt 0 ] && echo "🟡 MEDIUM" || echo "🟢 OK") |
| No Managed Identity | $TOTAL_NO_IDENTITY resources using keys | $([ $TOTAL_NO_IDENTITY -gt 0 ] && echo "🔴 HIGH" || echo "🟢 OK") |
| Missing Diagnostics | $TOTAL_DIAG_GAPS without logging | $([ $TOTAL_DIAG_GAPS -gt 0 ] && echo "🟡 MEDIUM" || echo "🟢 OK") |
| AI Policies | $TOTAL_POLICIES assignments | $([ $TOTAL_POLICIES -eq 0 ] && echo "🔴 HIGH" || echo "🟢 OK") |

---

## Output Files

| File | Description |
|------|-------------|
| ai_asset_inventory.csv/json | Master resource inventory |
| openai_deployments.csv | Model deployments, capacity, content filters |
| ml_computes.csv | Compute targets, GPU VMs, endpoints |
| network_audit.csv | Public vs private access per resource |
| tag_audit.csv | Missing governance tags |
| diagnostic_gaps.csv | Resources without diagnostic settings |
| rbac_ai_assignments.csv | Role assignments on AI resources |
| policy_assignments.csv | AI-related Azure Policy assignments |

---

## Recommended Actions

1. **🔴 CRITICAL** — Disable public access on all AI resources, enforce via Azure Policy (Deny)
2. **🔴 CRITICAL** — Enable managed identity, eliminate key-based authentication
3. **🟡 HIGH** — Apply required governance tags to all AI resources
4. **🟡 HIGH** — Configure diagnostic settings to Log Analytics
5. **🟡 MEDIUM** — Assign MCSB-aligned AI policies
6. **🟡 MEDIUM** — Audit RBAC for least-privilege on AI resources
7. **🟢 LOW** — Validate content filter policies on all OpenAI deployments
SUMMARY

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════"
ok "SCAN COMPLETE"
echo "══════════════════════════════════════════════════════════"
echo ""
log "Output: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"
echo ""
log "Start with: cat $OUTPUT_DIR/governance_summary.md"
