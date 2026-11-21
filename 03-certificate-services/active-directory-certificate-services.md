# Active Directory Certificate Services
## Overview

Active Directory Certificate Services (AD CS) provides certificate-based authentication and identity management in an Active Directory environment.

A misconfigured Certificate Authority (CA) or certificate template can allow attackers to request certificates that may be used to impersonate other domain identities.

This assessment focuses on the following escalation paths:

- ESC1 – Misconfigured certificate templates allowing requester-supplied subject names
- ESC4 – Weak certificate template permissions
- ESC5 – Weak permissions on AD PKI objects
- ESC6 – CA allows requester-supplied Subject Alternative Names (SAN)
- ESC7 – Excessive CA administrative permissions
- ESC8 – NTLM relay against HTTP-based certificate enrollment

## Environment

| Component | Configuration |
|---|---|
| Domain | `MARVEL.local` |
| Domain Controller | `HYDRA-DC.MARVEL.local` |
| Certificate Authority | `MARVEL-HYDRA-DC-CA` |
| CA Host | `HYDRA-DC.MARVEL.local` |
| CA Role | Active Directory Certificate Services |
| Enumeration Tool | Certipy |
| Supplementary Tools | PowerShell, `dsacls`, `certutil` |

---

## Treat Certificate Authority Servers as Tier 0

### Objective

Certificate Authority servers should be treated as Tier 0 assets because they can issue certificates used to authenticate domain identities.

Compromising a CA can potentially allow an attacker to issue certificates for privileged accounts and compromise the Active Directory environment.

### Enumeration

Verified the installed AD CS role:

```powershell
Get-WindowsFeature -Name ADCS*
```

Verified the Certificate Services service:

```powershell
Get-Service -Name CertSvc
```

Verified the CA registration in Active Directory:

```powershell
Get-ADObject `
  -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=MARVEL,DC=local" `
  -Filter * `
  -Properties dNSHostName, certificateTemplates |
Select-Object Name, dNSHostName, certificateTemplates
```

### Findings

- AD CS Certification Authority role is installed on `HYDRA-DC`.
- `CertSvc` service is running.
- CA name: `MARVEL-HYDRA-DC-CA`.
- CA DNS name: `HYDRA-DC.MARVEL.local`.
- The CA is hosted on the Domain Controller.

### Assessment

**Status: Identified – Tier 0 asset**

The CA and Domain Controller are hosted on the same server. The CA must therefore be protected as a Tier 0 component.

This is an architectural observation, not an identified vulnerability by itself.

---

## Prevent ESC1 Certificate Template Misconfiguration

### Objective

Prevent low-privileged users from requesting certificates that allow them to authenticate as another user.

ESC1 commonly involves the combination of:

- Client Authentication capability.
- Enrollee Supplies Subject enabled.
- Enrollment permissions granted to low-privileged users.
- No additional approval or authorized signature requirement that prevents exploitation.

### Enumeration

Used Certipy to enumerate the CA and certificate templates:

```bash
certipy find \
  -u 'hdimla@MARVEL.local' \
  -target 'HYDRA-DC.MARVEL.local' \
  -dc-ip 192.168.50.50 \
  -stdout
```

### Findings

Certipy identified:

- 33 certificate templates.
- 1 Certificate Authority.
- 11 enabled certificate templates.

Relevant template observations:

| Template | Client Authentication | Enrollee Supplies Subject | Enrollment Rights |
|---|---|---|---|
| User | True | False | Domain Users, Domain Admins, Enterprise Admins |
| WebServer | False | True | Domain Admins, Enterprise Admins |
| SubCA | True | True | Domain Admins, Enterprise Admins |

The `User` template allows Domain Users to enroll, but does not allow the requester to supply the subject.

The `WebServer` template allows the requester to supply the subject, but does not provide Client Authentication and is restricted to privileged enrollment groups.

The `SubCA` template has powerful certificate capabilities, but its enrollment permissions are restricted to Domain Admins and Enterprise Admins.

### Assessment

**Status: No ESC1 vulnerability identified**

Based on the enabled templates and their enrollment permissions, no template was identified with the required ESC1 combination available to low-privileged users.

The `SubCA` template should remain under administrative review because of its powerful capabilities, even though its current enrollment permissions are restricted.

---

## Review Certificate Template, CA, and PKI Object Permissions

### Objective

Review permissions on certificate templates, the Certificate Authority, and AD PKI objects.

Misconfigured permissions can allow low-privileged users to modify certificate templates or PKI configuration.

Relevant escalation paths:

- ESC4 – Weak certificate template permissions.
- ESC5 – Weak permissions on AD PKI objects.
- ESC7 – Excessive CA administrative permissions.

### 1. Certificate Template Permissions – ESC4

Certipy output showed the following pattern in the inspected template permissions:

- Owner: Enterprise Admins.
- Full Control: Domain Admins and Enterprise Admins.
- Write Owner: Domain Admins and Enterprise Admins.
- Write DACL: Domain Admins and Enterprise Admins.

Domain Users appeared in enrollment-related permissions on certain templates, but were not identified as having Full Control, Write Owner, or Write DACL.

### 2. CA Administrative Permissions – ESC7

Certipy reported:

| Permission | Principals |
|---|---|
| Manage CA | Administrators, Domain Admins, Enterprise Admins |
| Manage Certificates | Administrators, Domain Admins, Enterprise Admins |
| Enroll | Authenticated Users |

No unexpected low-privileged principal was identified with CA administrative permissions.

### 3. Public Key Services Container – ESC5

Inspected the Public Key Services container:

```powershell
dsacls "CN=Public Key Services,CN=Services,CN=Configuration,DC=MARVEL,DC=local"
```

Observed permissions:

- Authenticated Users: Read and List permissions.
- Enterprise Admins: Administrative permissions.
- Domain Admins: Inherited administrative permissions.
- SYSTEM: Full Control.

### 4. PKI Child Containers

Enumerated the child containers:

```powershell
$base = "CN=Public Key Services,CN=Services,CN=Configuration,DC=MARVEL,DC=local"

Get-ADObject -SearchBase $base -SearchScope OneLevel -Filter * |
ForEach-Object {
    Write-Host "`n========== $($_.Name) ==========" -ForegroundColor Cyan
    dsacls $_.DistinguishedName
}
```

The following containers were inspected:

| PKI Container | Observed Permissions |
|---|---|
| AIA | Enterprise Admins, Domain Admins, SYSTEM, Cert Publishers |
| CDP | Enterprise Admins, Domain Admins, SYSTEM |
| Certificate Templates | Enterprise Admins, Domain Admins, SYSTEM |
| Certification Authorities | Enterprise Admins, Domain Admins, SYSTEM |
| Enrollment Services | Enterprise Admins, Domain Admins, SYSTEM |
| KRA | Enterprise Admins, Domain Admins, SYSTEM |
| NTAuthCertificates | Domain Admins, Enterprise Admins, BUILTIN\Administrators |
| OID | Enterprise Admins, Domain Admins, SYSTEM |

Authenticated Users and Everyone were observed with read/list permissions only where present.

### 5. Cert Publishers Membership

The AIA container grants Full Control to Cert Publishers.

Checked its membership:

```powershell
Get-ADGroupMember -Identity "Cert Publishers" |
Select-Object Name, SamAccountName, ObjectClass
```

Result:

| Name | SamAccountName | Object Class |
|---|---|---|
| HYDRA-DC | HYDRA-DC$ | computer |

Only the CA server's computer account was returned.

### Assessment

**Status: No unexpected low-privileged permissions identified in inspected ACLs**

- No low-privileged Full Control, Write DACL, or Write Owner permissions were identified in the inspected template and CA permissions.
- Public Key Services container permissions were restricted to administrative principals for write operations.
- Cert Publishers membership contained only `HYDRA-DC$`.

**Limitation:** The checks inspected the reported container ACLs and Certipy template/CA permissions. They do not independently prove that every individual PKI object and descendant has secure permissions.

---

## Remove EDITF_ATTRIBUTESUBJECTALTNAME2 CA Flag

### Objective

Prevent requesters from supplying arbitrary Subject Alternative Names (SAN) through CA-wide configuration.

The `EDITF_ATTRIBUTESUBJECTALTNAME2` flag can introduce an ESC6 escalation risk when enabled.

### Enumeration

Used Certipy to inspect CA configuration:

```bash
certipy find \
  -u 'hdimla@MARVEL.local' \
  -target 'HYDRA-DC.MARVEL.local' \
  -dc-ip 192.168.50.50 \
  -stdout
```

### Findings

Certipy reported:

```text
User Specified SAN : Disabled
```

### Assessment

**Status: No ESC6 exposure identified**

The CA's User Specified SAN setting was reported as Disabled.

No remediation was required based on this finding.

---

## Protect or Remove HTTP Web Enrollment

### Objective

Prevent NTLM relay attacks against AD CS Web Enrollment.

An attacker may relay NTLM authentication to an HTTP-based certificate enrollment endpoint and potentially obtain a certificate using another user's identity.

Recommended protections include:

- Disable Web Enrollment if it is not required.
- Use HTTPS instead of HTTP.
- Enable Extended Protection for Authentication (EPA).
- Disable NTLM where feasible.

### Enumeration

Checked installed AD CS features:

```powershell
Get-WindowsFeature -Name ADCS*
```

Used Certipy to inspect Web Enrollment:

```bash
certipy find \
  -u 'hdimla@MARVEL.local' \
  -target 'HYDRA-DC.MARVEL.local' \
  -dc-ip 192.168.50.50 \
  -stdout
```

### Findings

Certipy reported:

```text
Web Enrollment
  HTTP
    Enabled : False
  HTTPS
    Enabled : False
```

The Web Enrollment feature was also not installed according to the Windows feature enumeration.

However, Certipy reported a timeout while checking Web Enrollment connectivity.

### Assessment

**Status: No Web Enrollment endpoint identified**

- HTTP Web Enrollment: Disabled.
- HTTPS Web Enrollment: Disabled.
- Web Enrollment Windows feature: Not installed.
- Certipy connectivity check: Timed out.

The timeout is documented as an enumeration limitation. The CA configuration and installed feature results indicate that Web Enrollment is not enabled.

---

## Summary

| Check | Result |
|---|---|
| CA Tier 0 Classification | CA identified as Tier 0 |
| ESC1 – Certificate Template Misconfiguration | No ESC1 identified |
| ESC4 / ESC5 / ESC7 – PKI Permissions | No unexpected low-privileged permissions identified in inspected ACLs |
| ESC6 – User-Specified SAN | Disabled |
| ESC8 – Web Enrollment Relay | Web Enrollment not installed or enabled |

## Overall Assessment

The AD CS assessment did not identify an exploitable ESC1, ESC4, ESC5, ESC6, ESC7, or ESC8 configuration based on the evidence collected.

The CA is hosted on the Domain Controller and must be treated as a Tier 0 asset.

The following limitations remain documented:

- Not every individual PKI object and descendant ACL was independently inspected.
- Certipy's Web Enrollment connectivity check timed out.
- The assessment reflects the configuration observed during enumeration and may change if templates, permissions, or CA settings are modified.

