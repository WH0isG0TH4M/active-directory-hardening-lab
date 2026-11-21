# LDAP, Print Spooler, and Legacy Protocols

## Overview

These checks focus on reducing Active Directory attack surfaces involving LDAP communication, Print Spooler abuse, and legacy authentication protocols.

Environment:
- Domain: `MARVEL.local`
- Domain Controller: `HYDRA-DC.MARVEL.local`
- Windows Server: Windows Server 2025

---

## LDAP Signing and Channel Binding

### Objective

Require LDAP signing and enforce LDAP channel binding to protect LDAP authentication against tampering and relay attacks.

### Initial Assessment

The initial configuration on `HYDRA-DC` was:

| Registry Setting | Initial Value | Meaning |
|---|---:|---|
| LDAPServerIntegrity | 1 | Negotiate signing |
| LdapEnforceChannelBinding | Not configured | Windows default behavior |

LDAP diagnostic logging was initially disabled.

### Diagnostic Logging

Enabled LDAP Interface Events diagnostic logging:

```powershell
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" `
    -Name "16 LDAP Interface Events" `
    -Value 2
```

Verification:

```powershell
Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" |
Select-Object "16 LDAP Interface Events"
```

Result: `2`

No Event ID 2889 was observed after generating normal domain activity from the workstations.

### Remediation

**1. Require LDAP Signing**

```powershell
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" `
    -Value 2
```

Final value: `2` – Require signing.

**2. Enforce LDAP Channel Binding**

```powershell
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LdapEnforceChannelBinding" `
    -Value 2
```

Final value: `2` – Always.

### Verification

```powershell
Get-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" |
Select-Object LDAPServerIntegrity, LdapEnforceChannelBinding
```

Final configuration:

| Setting | Value | Status |
|---|---:|---|
| LDAPServerIntegrity | 2 | Require signing |
| LdapEnforceChannelBinding | 2 | Always |

No matching events were found for Event IDs 2889, 3039, 3040, and 3041 during the final event query.

**Assessment:** LDAP signing and channel binding are configured. No relevant LDAP compatibility errors were observed in the queried events, but compatibility with every LDAP client has not been established.

---

## Print Spooler on Domain Controllers

### Objective

Disable the Print Spooler service on Domain Controllers to reduce exposure to forced authentication attacks and Print Spooler abuse.

### Initial Assessment

The Print Spooler service on `HYDRA-DC` was:

| Setting | Initial Value |
|---|---|
| Service Status | Running |
| Startup Type | Automatic |

### Remediation

Stopped the service and disabled its startup:

```powershell
Stop-Service -Name Spooler -Force

Set-Service -Name Spooler -StartupType Disabled
```

### Verification

```powershell
Get-Service -Name Spooler |
Select-Object Name, Status, StartType
```

Final result:

| Setting | Final Value |
|---|---|
| Service Status | Stopped |
| Startup Type | Disabled |

**Assessment:** Successfully disabled Print Spooler on the Domain Controller.

---

## Legacy Protocols

### Objective

Reduce the use of outdated authentication and file-sharing protocols by:
- Refusing LM and NTLMv1 authentication.
- Disabling SMBv1.
- Auditing NTLM authentication activity before applying broader restrictions.

### 1. LAN Manager Authentication Level

#### Initial Assessment

The `LmCompatibilityLevel` registry value was initially not configured.

The applied `Default Domain Controllers Policy` was found to control the LAN Manager authentication setting.

#### Remediation

Configured the following Group Policy:

**GPO:** Default Domain Controllers Policy

**Path:**

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`

**Policy:**

`Network security: LAN Manager authentication level`

**Configured value:**

`Send NTLMv2 response only. Refuse LM & NTLM`

Equivalent registry configuration:

```powershell
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" `
    -Type DWord `
    -Value 5
```

Applied Group Policy:

```powershell
gpupdate /force
```

#### Verification

```powershell
Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" |
Select-Object LmCompatibilityLevel
```

Final value: `5`

| Protocol | Configuration |
|---|---|
| LM | Refused |
| NTLMv1 | Refused |
| NTLMv2 | Allowed |

**Assessment:** Successfully configured through the Default Domain Controllers Policy.

### 2. SMBv1

#### Initial Assessment

Checked whether the SMBv1 Windows feature was installed:

```powershell
Get-WindowsFeature FS-SMB1 |
Select-Object Name, InstallState
```

Result: `Available` – not installed.

Checked SMB server configuration:

```powershell
Get-SmbServerConfiguration |
Select-Object EnableSMB1Protocol
```

Result: `False`

| Setting | Result |
|---|---|
| SMBv1 Windows Feature | Not installed |
| EnableSMB1Protocol | False |

**Assessment:** SMBv1 was already unavailable and disabled. No additional remediation was necessary.

### 3. NTLM Auditing

#### Initial Assessment

Verified the NTLM Operational event log:

```powershell
Get-WinEvent -ListLog "*NTLM*" |
Format-Table LogName, IsEnabled -AutoSize
```

Result:

`Microsoft-Windows-NTLM/Operational` – Enabled.

Initial event counts:

| Event ID | Count |
|---|---:|
| 4022 | 21 |
| 4023 | 149 |
| 4032 | 9 |
| 4033 | 49 |
| 8004 | 2 |

Event ID 8004 recorded NTLM authentication audit activity involving:

| Field | Recorded Value |
|---|---|
| Secure Channel | HEAVEN |
| User | hdimla |
| Domain | marvel.local |
| Event ID | 8004 |

The event indicated NTLM authentication that would be affected if domain-wide NTLM restrictions were enforced.

No Event ID 8004 was returned when checking the most recent seven days during the November 21, 2026 assessment.

#### Outgoing NTLM Audit Configuration

Inspected the following registry setting:

```powershell
Get-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" |
Select-Object RestrictSendingNTLMTraffic
```

Final value:

`RestrictSendingNTLMTraffic = 1`

Meaning: **Audit all outgoing NTLM traffic.**

| Value | Meaning |
|---|---|
| 0 | Allow all outgoing NTLM traffic |
| 1 | Audit all outgoing NTLM traffic |
| 2 | Deny all outgoing NTLM traffic |

The configuration remains in audit mode. NTLM authentication has not been completely disabled.

**Assessment:** NTLM auditing is enabled. Broader NTLM restrictions remain pending identification of remaining authentication dependencies.

---

## Workstation Compatibility Validation

Tested the domain secure channel on both domain-joined workstations.

Command:

```powershell
Test-ComputerSecureChannel -Verbose
```

Results:

| Workstation | Secure Channel |
|---|---|
| HEAVEN | True |
| PETER | True |

Both workstations reported healthy secure channels with `MARVEL.local`.

SMB connection checks using `Get-SmbConnection` returned no active connections at the time of testing.

---

## Final Assessment

| Check | Result |
|---|---|
| LDAP Signing | Configured – Require signing |
| LDAP Channel Binding | Configured – Always |
| Print Spooler | Stopped and Disabled |
| LAN Manager Authentication | Level 5 – Refuse LM and NTLMv1 |
| SMBv1 | Not installed and disabled |
| NTLM Auditing | Enabled – Audit mode |

### Remaining Considerations

- Continue monitoring LDAP diagnostic events and test LDAP-over-TLS client compatibility.
- Continue monitoring NTLM authentication activity.
- Identify applications and services that still depend on NTLM before enforcing broader NTLM restrictions.
- Do not deny all NTLM traffic until remaining dependencies have been assessed.
