# LLMNR and NBT-NS Hardening

## Overview

LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are legacy name-resolution protocols used by Windows systems.

These protocols can be abused in poisoning attacks, where an attacker responds to name-resolution requests with malicious information to capture authentication credentials.

## Objective

Reduce the risk of LLMNR and NBT-NS poisoning by disabling unnecessary name-resolution protocols on domain-joined Windows workstations.

## Environment

- Domain: `MARVEL.LOCAL`
- Domain Controller: `HYDRA-DC`
- Target OU: `Workstations`
- Target Workstations: `HEAVEN` and `PETER`
- Operating System: Windows 10 Pro 22H2

## 1. Disable LLMNR Through Group Policy

On the Domain Controller:

1. Open Group Policy Management (`gpmc.msc`).
2. Create or edit a workstation security GPO.
3. Navigate to:

   `Computer Configuration > Policies > Administrative Templates > Network > DNS Client`

4. Open **Turn off multicast name resolution**.
5. Set the policy to **Enabled**.
6. Apply the GPO to the `Workstations` OU.

## 2. Disable NBT-NS (NetBIOS over TCP/IP)

NetBIOS over TCP/IP was manually disabled through Windows Network Adapter Properties.

### Configuration Steps

1. Open **Network Connections** (`ncpa.cpl`).
2. Right-click the active network adapter and select **Properties**.
3. Select **Internet Protocol Version 4 (TCP/IPv4)**.
4. Click **Properties**.
5. Select **Advanced**.
6. Open the **WINS** tab.
7. Under NetBIOS setting, select **Disable NetBIOS over TCP/IP**.
8. Click **OK** to apply the changes.

## 3. Additional Security Recommendations

If LLMNR or NBT-NS cannot be disabled due to business or application requirements:

- Require Network Access Control (NAC).
- Enforce strong user passwords, preferably longer than 14 characters.
- Avoid common and easily guessable passwords.
- Review network authentication and access controls.
