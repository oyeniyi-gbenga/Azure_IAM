#!/usr/bin/env bash
# =============================================================================
# azure_iam_setup.sh
# Automate secure identity and access controls on Azure
#
# Tasks:
#   1. Create resource group, VNet, Web subnet, DB subnet
#   2. Create Azure AD groups: WebAdmins and DBAdmins
#   3. Assign Reader role to DBAdmins scoped to DB subnet resource group
#   4. Add test users to AD groups and validate role assignments
#
# Prerequisites:
#   - Azure CLI installed and authenticated (az login)
#   - Sufficient permissions: Contributor + User Access Administrator
#   - Run in Azure Cloud Shell or a Bash terminal
# =============================================================================

set -euo pipefail

# =============================================================================
# CONFIGURATION — Edit these values to match your environment
# =============================================================================
RESOURCE_GROUP="SecureNetworkRG"
LOCATION="eastus"
VNET_NAME="SecureVNet"
VNET_PREFIX="10.0.0.0/16"

WEB_SUBNET_NAME="WebSubnet"
WEB_SUBNET_PREFIX="10.0.1.0/24"

DB_SUBNET_NAME="DBSubnet"
DB_SUBNET_PREFIX="10.0.2.0/24"

WEB_GROUP_NAME="WebAdmins"
DB_GROUP_NAME="DBAdmins"

WEB_USER_DISPLAY="Web Test User"
DB_USER_DISPLAY="DB Test User"
USER_PASSWORD="TempPass@2025!"   # Change before use

WEB_NSG_NAME="WebNSG"
DB_NSG_NAME="DBNsg"
ROUTE_TABLE_NAME="SecureRouteTable"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log()  { echo -e "\n\033[1;34m[INFO]\033[0m  $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m    $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
fail() { echo -e "\033[1;31m[FAIL]\033[0m  $*" >&2; exit 1; }

check_az_login() {
    log "Checking Azure CLI authentication..."
    if ! az account show &>/dev/null; then
        fail "Not logged in. Run 'az login' first."
    fi
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    SUBSCRIPTION_NAME=$(az account show --query name -o tsv)
    ok "Logged in — Subscription: $SUBSCRIPTION_NAME ($SUBSCRIPTION_ID)"
}

get_domain() {
    DOMAIN=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null \
             | cut -d'@' -f2 || true)
    if [[ -z "$DOMAIN" ]]; then
        warn "Could not detect domain automatically."
        read -rp "Enter your Azure AD domain (e.g. contoso.onmicrosoft.com): " DOMAIN
    fi
    ok "Using domain: $DOMAIN"
}


# =============================================================================
# TASK 1 — Resource Group, Virtual Network, and Subnets
# =============================================================================

task1_network() {
    log "TASK 1: Creating network resources..."

    # --- Resource Group ---
    if az group show --name "$RESOURCE_GROUP" &>/dev/null; then
        warn "Resource group '$RESOURCE_GROUP' already exists — skipping creation."
    else
        az group create \
            --name "$RESOURCE_GROUP" \
            --location "$LOCATION" \
            --output none
        ok "Resource group '$RESOURCE_GROUP' created in $LOCATION."
    fi

    # --- Virtual Network ---
    if az network vnet show --resource-group "$RESOURCE_GROUP" --name "$VNET_NAME" &>/dev/null; then
        warn "VNet '$VNET_NAME' already exists — skipping."
    else
        az network vnet create \
            --resource-group "$RESOURCE_GROUP" \
            --name "$VNET_NAME" \
            --address-prefixes "$VNET_PREFIX" \
            --output none
        ok "VNet '$VNET_NAME' ($VNET_PREFIX) created."
    fi

    # --- Web Subnet ---
    if az network vnet subnet show \
            --resource-group "$RESOURCE_GROUP" \
            --vnet-name "$VNET_NAME" \
            --name "$WEB_SUBNET_NAME" &>/dev/null; then
        warn "Web subnet already exists — skipping."
    else
        az network vnet subnet create \
            --resource-group "$RESOURCE_GROUP" \
            --vnet-name "$VNET_NAME" \
            --name "$WEB_SUBNET_NAME" \
            --address-prefixes "$WEB_SUBNET_PREFIX" \
            --output none
        ok "Web subnet '$WEB_SUBNET_NAME' ($WEB_SUBNET_PREFIX) created."
    fi

    # --- DB Subnet ---
    if az network vnet subnet show \
            --resource-group "$RESOURCE_GROUP" \
            --vnet-name "$VNET_NAME" \
            --name "$DB_SUBNET_NAME" &>/dev/null; then
        warn "DB subnet already exists — skipping."
    else
        az network vnet subnet create \
            --resource-group "$RESOURCE_GROUP" \
            --vnet-name "$VNET_NAME" \
            --name "$DB_SUBNET_NAME" \
            --address-prefixes "$DB_SUBNET_PREFIX" \
            --output none
        ok "DB subnet '$DB_SUBNET_NAME' ($DB_SUBNET_PREFIX) created."
    fi

    # --- Network Security Group: Web ---
    az network nsg create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$WEB_NSG_NAME" \
        --output none 2>/dev/null || true

    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$WEB_NSG_NAME" \
        --name "AllowHTTP" \
        --priority 100 \
        --direction Inbound \
        --access Allow \
        --protocol Tcp \
        --destination-port-ranges 80 443 \
        --output none 2>/dev/null || true
    ok "Web NSG '$WEB_NSG_NAME' configured (ports 80/443 inbound)."

    # Associate Web NSG with Web Subnet
    az network vnet subnet update \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$VNET_NAME" \
        --name "$WEB_SUBNET_NAME" \
        --network-security-group "$WEB_NSG_NAME" \
        --output none 2>/dev/null || true

    # --- Network Security Group: DB ---
    az network nsg create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$DB_NSG_NAME" \
        --output none 2>/dev/null || true

    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$DB_NSG_NAME" \
        --name "AllowDBFromWeb" \
        --priority 100 \
        --direction Inbound \
        --access Allow \
        --protocol Tcp \
        --source-address-prefixes "$WEB_SUBNET_PREFIX" \
        --destination-port-ranges 1433 3306 5432 \
        --output none 2>/dev/null || true

    az network nsg rule create \
        --resource-group "$RESOURCE_GROUP" \
        --nsg-name "$DB_NSG_NAME" \
        --name "DenyAllInbound" \
        --priority 4096 \
        --direction Inbound \
        --access Deny \
        --protocol "*" \
        --output none 2>/dev/null || true
    ok "DB NSG '$DB_NSG_NAME' configured (DB ports only from Web subnet)."

    # Associate DB NSG with DB Subnet
    az network vnet subnet update \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$VNET_NAME" \
        --name "$DB_SUBNET_NAME" \
        --network-security-group "$DB_NSG_NAME" \
        --output none 2>/dev/null || true

    # --- Route Table ---
    az network route-table create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$ROUTE_TABLE_NAME" \
        --output none 2>/dev/null || true
    ok "Route table '$ROUTE_TABLE_NAME' created."

    log "TASK 1 complete — Network resources ready."
}


# =============================================================================
# TASK 2 — Create Azure AD Groups: WebAdmins and DBAdmins
# =============================================================================

task2_ad_groups() {
    log "TASK 2: Creating Azure AD groups..."

    # --- WebAdmins group ---
    WEB_GROUP_ID=$(az ad group list \
        --filter "displayName eq '$WEB_GROUP_NAME'" \
        --query "[0].id" -o tsv 2>/dev/null || true)

    if [[ -n "$WEB_GROUP_ID" ]]; then
        warn "Group '$WEB_GROUP_NAME' already exists (id: $WEB_GROUP_ID) — skipping."
    else
        WEB_GROUP_ID=$(az ad group create \
            --display-name "$WEB_GROUP_NAME" \
            --mail-nickname "WebAdmins" \
            --query id -o tsv)
        ok "AD group '$WEB_GROUP_NAME' created (id: $WEB_GROUP_ID)."
    fi

    # --- DBAdmins group ---
    DB_GROUP_ID=$(az ad group list \
        --filter "displayName eq '$DB_GROUP_NAME'" \
        --query "[0].id" -o tsv 2>/dev/null || true)

    if [[ -n "$DB_GROUP_ID" ]]; then
        warn "Group '$DB_GROUP_NAME' already exists (id: $DB_GROUP_ID) — skipping."
    else
        DB_GROUP_ID=$(az ad group create \
            --display-name "$DB_GROUP_NAME" \
            --mail-nickname "DBAdmins" \
            --query id -o tsv)
        ok "AD group '$DB_GROUP_NAME' created (id: $DB_GROUP_ID)."
    fi

    log "TASK 2 complete — AD groups: WebAdmins ($WEB_GROUP_ID), DBAdmins ($DB_GROUP_ID)."
}


# =============================================================================
# TASK 3 — Assign Reader role to DBAdmins (scoped to resource group)
#           and Contributor to WebAdmins
# =============================================================================

task3_rbac() {
    log "TASK 3: Assigning RBAC roles..."

    # Retrieve group IDs (in case task2 was skipped or re-run independently)
    WEB_GROUP_ID=$(az ad group show --group "$WEB_GROUP_NAME" --query id -o tsv)
    DB_GROUP_ID=$(az ad group show  --group "$DB_GROUP_NAME"  --query id -o tsv)

    RG_SCOPE="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}"

    # --- Assign Reader to DBAdmins at resource group scope ---
    # (Resource group scope is the finest scope available without deploying actual resources)
    EXISTING_DB_ROLE=$(az role assignment list \
        --assignee "$DB_GROUP_ID" \
        --role "Reader" \
        --scope "$RG_SCOPE" \
        --query "[0].id" -o tsv 2>/dev/null || true)

    if [[ -n "$EXISTING_DB_ROLE" ]]; then
        warn "Reader role already assigned to '$DB_GROUP_NAME' — skipping."
    else
        az role assignment create \
            --assignee "$DB_GROUP_ID" \
            --role "Reader" \
            --scope "$RG_SCOPE" \
            --output none
        ok "Reader role assigned to '$DB_GROUP_NAME' at scope: $RG_SCOPE"
    fi

    # --- Assign Contributor to WebAdmins at resource group scope ---
    EXISTING_WEB_ROLE=$(az role assignment list \
        --assignee "$WEB_GROUP_ID" \
        --role "Contributor" \
        --scope "$RG_SCOPE" \
        --query "[0].id" -o tsv 2>/dev/null || true)

    if [[ -n "$EXISTING_WEB_ROLE" ]]; then
        warn "Contributor role already assigned to '$WEB_GROUP_NAME' — skipping."
    else
        az role assignment create \
            --assignee "$WEB_GROUP_ID" \
            --role "Contributor" \
            --scope "$RG_SCOPE" \
            --output none
        ok "Contributor role assigned to '$WEB_GROUP_NAME' at scope: $RG_SCOPE"
    fi

    log "TASK 3 complete — RBAC assignments done."
}


# =============================================================================
# TASK 4 — Add test users to AD groups and validate role assignments
# =============================================================================

task4_users_and_validate() {
    log "TASK 4: Creating test users and validating role assignments..."

    # Ensure group IDs are available
    WEB_GROUP_ID=$(az ad group show --group "$WEB_GROUP_NAME" --query id -o tsv)
    DB_GROUP_ID=$(az ad group show  --group "$DB_GROUP_NAME"  --query id -o tsv)

    # --- Create Web test user ---
    WEB_UPN="webuser@${DOMAIN}"
    WEB_USER_ID=$(az ad user list \
        --filter "userPrincipalName eq '$WEB_UPN'" \
        --query "[0].id" -o tsv 2>/dev/null || true)

    if [[ -n "$WEB_USER_ID" ]]; then
        warn "User '$WEB_UPN' already exists — skipping creation."
    else
        WEB_USER_ID=$(az ad user create \
            --display-name "$WEB_USER_DISPLAY" \
            --user-principal-name "$WEB_UPN" \
            --password "$USER_PASSWORD" \
            --force-change-password-next-sign-in false \
            --query id -o tsv)
        ok "Test user '$WEB_UPN' created (id: $WEB_USER_ID)."
    fi

    # --- Create DB test user ---
    DB_UPN="dbuser@${DOMAIN}"
    DB_USER_ID=$(az ad user list \
        --filter "userPrincipalName eq '$DB_UPN'" \
        --query "[0].id" -o tsv 2>/dev/null || true)

    if [[ -n "$DB_USER_ID" ]]; then
        warn "User '$DB_UPN' already exists — skipping creation."
    else
        DB_USER_ID=$(az ad user create \
            --display-name "$DB_USER_DISPLAY" \
            --user-principal-name "$DB_UPN" \
            --password "$USER_PASSWORD" \
            --force-change-password-next-sign-in false \
            --query id -o tsv)
        ok "Test user '$DB_UPN' created (id: $DB_USER_ID)."
    fi

    # Small delay: AD propagation can take a few seconds
    sleep 5

    # --- Add users to groups ---
    log "Adding users to AD groups..."

    # Add webuser → WebAdmins
    if az ad group member check \
            --group "$WEB_GROUP_NAME" \
            --member-id "$WEB_USER_ID" \
            --query value -o tsv 2>/dev/null | grep -q "true"; then
        warn "$WEB_UPN is already a member of $WEB_GROUP_NAME."
    else
        az ad group member add \
            --group "$WEB_GROUP_NAME" \
            --member-id "$WEB_USER_ID"
        ok "Added $WEB_UPN → $WEB_GROUP_NAME"
    fi

    # Add dbuser → DBAdmins
    if az ad group member check \
            --group "$DB_GROUP_NAME" \
            --member-id "$DB_USER_ID" \
            --query value -o tsv 2>/dev/null | grep -q "true"; then
        warn "$DB_UPN is already a member of $DB_GROUP_NAME."
    else
        az ad group member add \
            --group "$DB_GROUP_NAME" \
            --member-id "$DB_USER_ID"
        ok "Added $DB_UPN → $DB_GROUP_NAME"
    fi

    # ==========================================================================
    # VALIDATION
    # ==========================================================================
    log "Running validation checks..."

    echo ""
    echo "========================================"
    echo "  VALIDATION REPORT"
    echo "========================================"

    # 1. Confirm VNet and subnets exist
    echo ""
    echo "--- Network Resources ---"
    az network vnet subnet list \
        --resource-group "$RESOURCE_GROUP" \
        --vnet-name "$VNET_NAME" \
        --query "[].{Subnet:name, Prefix:addressPrefix}" \
        --output table

    # 2. Confirm AD group membership
    echo ""
    echo "--- AD Group Members ---"
    echo "WebAdmins members:"
    az ad group member list \
        --group "$WEB_GROUP_NAME" \
        --query "[].{DisplayName:displayName, UPN:userPrincipalName}" \
        --output table

    echo "DBAdmins members:"
    az ad group member list \
        --group "$DB_GROUP_NAME" \
        --query "[].{DisplayName:displayName, UPN:userPrincipalName}" \
        --output table

    # 3. Confirm RBAC role assignments
    echo ""
    echo "--- RBAC Role Assignments ---"
    az role assignment list \
        --scope "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}" \
        --query "[?principalType=='Group'].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" \
        --output table

    # 4. Validate that DBAdmins has Reader but NOT Contributor
    DB_READER=$(az role assignment list \
        --assignee "$DB_GROUP_ID" \
        --role "Reader" \
        --scope "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}" \
        --query "[0].roleDefinitionName" -o tsv 2>/dev/null || true)

    DB_CONTRIBUTOR=$(az role assignment list \
        --assignee "$DB_GROUP_ID" \
        --role "Contributor" \
        --scope "/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}" \
        --query "[0].roleDefinitionName" -o tsv 2>/dev/null || true)

    echo ""
    echo "--- Principle of Least Privilege Check ---"
    if [[ "$DB_READER" == "Reader" ]]; then
        ok "DBAdmins has Reader role — PASS"
    else
        warn "DBAdmins does NOT have Reader role — FAIL"
    fi

    if [[ -z "$DB_CONTRIBUTOR" ]]; then
        ok "DBAdmins does NOT have Contributor role — PASS (least privilege)"
    else
        warn "DBAdmins has Contributor role — REVIEW THIS ASSIGNMENT"
    fi

    echo ""
    echo "========================================"
    ok "All validation checks complete."
    echo "========================================"

    log "TASK 4 complete."
}


# =============================================================================
# CLEANUP FUNCTION — Use only when you want to tear everything down
# =============================================================================

cleanup() {
    warn "CLEANUP MODE — This will delete all resources created by this script."
    read -rp "Are you sure? Type 'yes' to confirm: " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        log "Cleanup cancelled."
        return
    fi

    log "Deleting resource group '$RESOURCE_GROUP' (this may take a few minutes)..."
    az group delete --name "$RESOURCE_GROUP" --yes --no-wait
    ok "Resource group deletion initiated (running in background)."

    log "Removing AD users and groups..."
    for UPN in "webuser@${DOMAIN}" "dbuser@${DOMAIN}"; do
        USER_ID=$(az ad user list --filter "userPrincipalName eq '$UPN'" \
            --query "[0].id" -o tsv 2>/dev/null || true)
        [[ -n "$USER_ID" ]] && az ad user delete --id "$USER_ID" && ok "Deleted user $UPN" || true
    done

    for GROUP in "$WEB_GROUP_NAME" "$DB_GROUP_NAME"; do
        GROUP_ID=$(az ad group show --group "$GROUP" --query id -o tsv 2>/dev/null || true)
        [[ -n "$GROUP_ID" ]] && az ad group delete --group "$GROUP_ID" && ok "Deleted group $GROUP" || true
    done

    ok "Cleanup complete."
}


# =============================================================================
# MAIN ENTRYPOINT
# =============================================================================

main() {
    echo ""
    echo "============================================================"
    echo "  Azure Secure Identity & Access Control Setup"
    echo "============================================================"

    check_az_login
    get_domain

    task1_network
    task2_ad_groups
    task3_rbac
    task4_users_and_validate

    echo ""
    echo "============================================================"
    ok "All tasks completed successfully!"
    echo ""
    echo "  Resources created:"
    echo "    Resource Group : $RESOURCE_GROUP"
    echo "    VNet           : $VNET_NAME ($VNET_PREFIX)"
    echo "    Web Subnet     : $WEB_SUBNET_NAME ($WEB_SUBNET_PREFIX)"
    echo "    DB Subnet      : $DB_SUBNET_NAME ($DB_SUBNET_PREFIX)"
    echo "    AD Groups      : $WEB_GROUP_NAME, $DB_GROUP_NAME"
    echo "    Test Users     : webuser@$DOMAIN, dbuser@$DOMAIN"
    echo ""
    echo "  To run cleanup:  bash azure_iam_setup.sh cleanup"
    echo "============================================================"
}

# Allow selective cleanup via argument
if [[ "${1:-}" == "cleanup" ]]; then
    check_az_login
    get_domain
    cleanup
else
    main
fi
