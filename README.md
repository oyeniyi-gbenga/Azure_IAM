# Azure IAM
# Azure Secure Identity & Access Control Automation

Automate the full lifecycle of Azure network and identity setup using **Azure CLI** and **Bash scripting** — eliminating manual portal clicks, enforcing least-privilege access, and producing a repeatable, auditable deployment script.

---

## Overview

This project provisions a complete secure Azure environment in a single script run:

- A **Resource Group**, **Virtual Network**, and two **Subnets** (Web + DB)
- **Network Security Groups** enforcing traffic isolation between tiers
- **Microsoft Entra ID (Azure AD) groups** — `WebAdmins` and `DBAdmins`
- **RBAC role assignments** scoped to the resource group (Contributor → WebAdmins, Reader → DBAdmins)
- **Test users** added to their respective groups
- An automated **validation report** confirming all assignments and least-privilege posture

---

## Architecture

```
Azure Subscription
└── Resource Group: SecureNetworkRG  (East US)
    └── Virtual Network: SecureVNet  (10.0.0.0/16)
        ├── WebSubnet  (10.0.1.0/24)
        │   ├── NSG: Allow inbound 80, 443
        │   └── Web Servers (VM tier)
        └── DBSubnet   (10.0.2.0/24)
            ├── NSG: Allow inbound 1433/3306/5432 from WebSubnet only
            ├── NSG: Deny all other inbound (priority 4096)
            └── DB Servers (VM tier)

Microsoft Entra ID
├── WebAdmins  →  Contributor  →  SecureNetworkRG
└── DBAdmins   →  Reader       →  SecureNetworkRG
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Azure CLI | v2.40+ — [Install guide](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) |
| Active Azure subscription | [Create a free account](https://azure.microsoft.com/free) |
| Bash | v4+ (Linux, macOS, or Azure Cloud Shell) |
| Required roles | `Contributor` **+** `User Access Administrator` on the target subscription |

> **Tip:** Azure Cloud Shell at [shell.azure.com](https://shell.azure.com) has Azure CLI pre-installed and pre-authenticated — the fastest way to get started.

---

## Quick Start

```bash
# 1. Clone or download the script
curl -O https://your-repo/azure_iam_setup.sh

# 2. Make it executable
chmod +x azure_iam_setup.sh

# 3. Authenticate (skip if using Cloud Shell)
az login

# 4. Run
bash azure_iam_setup.sh
```

To tear everything down cleanly:

```bash
bash azure_iam_setup.sh cleanup
```

---

## Configuration

Edit the variables block at the top of `azure_iam_setup.sh` before running:

```bash
RESOURCE_GROUP="SecureNetworkRG"     # Resource group name
LOCATION="eastus"                    # Azure region
VNET_NAME="SecureVNet"               # Virtual network name
VNET_PREFIX="10.0.0.0/16"           # VNet address space

WEB_SUBNET_NAME="WebSubnet"          # Web tier subnet name
WEB_SUBNET_PREFIX="10.0.1.0/24"     # Web subnet CIDR

DB_SUBNET_NAME="DBSubnet"            # DB tier subnet name
DB_SUBNET_PREFIX="10.0.2.0/24"      # DB subnet CIDR

WEB_GROUP_NAME="WebAdmins"           # Azure AD group for web admins
DB_GROUP_NAME="DBAdmins"             # Azure AD group for DB admins

USER_PASSWORD="TempPass@2025!"       # Initial password for test users
```

---

## What the Script Does

### Task 1 — Network Infrastructure

- Creates the resource group in the specified region
- Provisions the virtual network with the defined address space
- Creates **WebSubnet** and **DBSubnet** with their respective CIDRs
- Attaches a **Web NSG** (allows ports 80/443 inbound)
- Attaches a **DB NSG** (allows DB ports only from WebSubnet; denies everything else)
- Creates a route table for controlled routing

### Task 2 — Azure AD Groups

- Creates the `WebAdmins` security group in Microsoft Entra ID
- Creates the `DBAdmins` security group in Microsoft Entra ID
- Both groups use idempotency checks — safe to re-run

### Task 3 — RBAC Role Assignments

| Group | Role | Scope |
|---|---|---|
| WebAdmins | Contributor | `/resourceGroups/SecureNetworkRG` |
| DBAdmins | Reader | `/resourceGroups/SecureNetworkRG` |

> Subnet-level scope is intentionally avoided — Azure subnets are sub-resources of VNets and do not expose a standalone ARM scope for RBAC assignment without a deployed resource.

### Task 4 — Users & Validation

- Creates `webuser@<domain>` and `dbuser@<domain>` as test users
- Adds each user to their respective AD group
- Runs a full **validation report**:
  - Lists all subnets and their address prefixes
  - Lists all AD group members
  - Lists all RBAC role assignments at resource group scope
  - Confirms DBAdmins holds `Reader` but **not** `Contributor` (least-privilege audit)

---

## Validation Output (example)

```
--- Network Resources ---
Subnet        Prefix
WebSubnet     10.0.1.0/24
DBSubnet      10.0.2.0/24

--- AD Group Members ---
WebAdmins members:
DisplayName      UPN
Web Test User    webuser@contoso.onmicrosoft.com

DBAdmins members:
DisplayName     UPN
DB Test User    dbuser@contoso.onmicrosoft.com

--- RBAC Role Assignments ---
Principal     Role           Scope
WebAdmins     Contributor    /subscriptions/.../SecureNetworkRG
DBAdmins      Reader         /subscriptions/.../SecureNetworkRG

--- Principle of Least Privilege Check ---
[OK]  DBAdmins has Reader role — PASS
[OK]  DBAdmins does NOT have Contributor role — PASS (least privilege)
```

---

## Security Design Decisions

| Practice | Implementation |
|---|---|
| **Least privilege** | DBAdmins gets `Reader` only — cannot create or modify any resource |
| **Group-based RBAC** | Roles assigned to AD groups, not individuals — access scales automatically |
| **Network isolation** | DB NSG blocks all traffic except from WebSubnet IP range |
| **Defense in depth** | Network controls (NSG) + identity controls (RBAC) are independent layers |
| **Idempotency** | Every `az ... create` is guarded by an `az ... show` existence check |
| **Auth guard** | Script verifies active Azure CLI session before any operation |
| **Auditability** | Validation report runs at the end of every execution |

---

## Challenges Encountered & Resolutions

### Authentication & Permissions

| # | Challenge | Fix |
|---|---|---|
| 1 | `az login` token expired mid-script (~60 min) | Auth pre-check via `az account show` at start + service principal login for unattended runs |
| 2 | `AuthorizationFailed` on role assignment | Added `User Access Administrator` role to the running identity at subscription scope |
| 3 | Newly created users returned empty Object ID | `sleep 5` after user creation + retry loop (3 attempts, 3 s apart) before aborting |

### NSG, Idempotency & Scope

| # | Challenge | Fix |
|---|---|---|
| 4 | NSG rule priority 100 already exists on re-run | Existence check before creation (`az network nsg rule show`) + `\|\| true` guard |
| 5 | RBAC assignment failed at subnet scope | Moved scope to resource group level — subnet scope is not a valid ARM RBAC target |
| 6 | Re-running a partial script caused new errors | Wrapped every `az ... create` with `az ... show` + `set -euo pipefail` — fully idempotent |

---

## File Structure

```
.
├── azure_iam_setup.sh       # Main automation script
├── README.md                # This file
└── Azure_IAM_Automation.pptx  # Presentation deck (10 slides)
```

---

## Recommended Next Steps

- **CI/CD integration** — Run via Azure DevOps pipeline or GitHub Actions for automated deployments
- **Azure Policy** — Enforce NSG compliance and naming conventions at scale
- **Conditional Access** — Add MFA enforcement via Entra ID Conditional Access policies
- **Custom RBAC roles** — Replace built-in roles with fine-grained custom definitions
- **Azure Monitor alerts** — Trigger alerts on any role assignment change for a full audit trail

---

## Resources

| Resource | Link |
|---|---|
| Azure CLI docs | [learn.microsoft.com/cli/azure](https://learn.microsoft.com/en-us/cli/azure/) |
| Azure RBAC overview | [learn.microsoft.com/azure/role-based-access-control](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview) |
| Assign roles via CLI | [learn.microsoft.com — role-assignments-cli](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-cli) |
| Microsoft Entra ID groups | [learn.microsoft.com/entra/fundamentals](https://learn.microsoft.com/en-us/entra/fundamentals/groups-view-azure-portal) |
| NSG overview | [learn.microsoft.com/azure/virtual-network/network-security-groups](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview) |

---

## License

This project is provided for educational and demonstration purposes.
