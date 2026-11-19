## Delegation and machine accounts

These review Active Directory delegation settings and machine account creation permissions. The goal is to identify unnecessary delegation privileges, restrict service-to-service impersonation, and prevent ordinary domain users from freely creating computer accounts.

---

### Unconstrained Delegation

**Objective:** Identify user and computer accounts configured for unconstrained Kerberos delegation.

Unconstrained delegation allows a service running on a trusted computer to receive and potentially reuse Kerberos tickets belonging to users who authenticate to it. This can expose privileged users' credentials and make the affected computer a high-value target.

#### Initial Assessment

Queried Active Directory for accounts with unconstrained delegation enabled:

```powershell
Get-ADUser -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation

Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation
```

**Findings:**

- No user accounts were configured for unconstrained delegation.
- `HYDRA-DC` was the only computer account identified with `TrustedForDelegation=True`.
- No other domain computers were identified with this setting.

The Domain Controller's unconstrained delegation setting was retained as part of the lab's existing configuration. Domain Controllers commonly require this behavior for certain authentication and domain operations.

#### Assessment

No unexpected unconstrained delegation was identified outside the Domain Controller.

---

### Constrained Delegation and Resource-Based Constrained Delegation

**Objective:** Identify and review traditional constrained delegation (KCD) and resource-based constrained delegation (RBCD).

Unlike unconstrained delegation, constrained delegation limits which services an account can delegate authentication to.

There are two delegation models:

**Traditional Constrained Delegation (KCD)**

The frontend service account controls which backend services it is allowed to delegate to. The allowed services are configured through the `msDS-AllowedToDelegateTo` attribute.

**Resource-Based Constrained Delegation (RBCD)**

The backend resource controls which frontend accounts are allowed to delegate to it. The permissions are configured on the backend computer or service account through the `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor.

#### Initial Assessment

Queried Active Directory for traditional constrained delegation entries:

```powershell
Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' `
    -Properties msDS-AllowedToDelegateTo
```

Queried computer accounts for RBCD configuration:

```powershell
Get-ADComputer -Filter * `
    -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object {
    $_.msDS-AllowedToActOnBehalfOfOtherIdentity
}
```

**Initial Findings:**

- No traditional constrained delegation entries were identified.
- No RBCD entries were identified on the queried computer accounts.

#### Traditional Constrained Delegation Lab

A controlled frontend-to-backend IIS environment was established to demonstrate Kerberos-only constrained delegation.

**Lab Components:**

| Component | Configuration |
|---|---|
| Frontend | HEAVEN |
| Frontend IP | `192.168.50.49` |
| Backend | PETER |
| Backend IP | `192.168.50.51` |
| Domain Controller | HYDRA-DC |
| Domain | `MARVEL.LOCAL` |
| Frontend service account | `WebFrontend` |
| Frontend application | `DelegationFrontend` |
| Backend application | `DelegationTest` |

**Frontend Service Account**

A dedicated domain account named `WebFrontend` was configured with the following HTTP Service Principal Names (SPNs):

```text
HTTP/heaven
HTTP/heaven.MARVEL.local
```

The account was configured as the identity for the frontend IIS application pool.

The frontend Windows Authentication configuration used application pool credentials.

**Backend IIS Configuration**

IIS was installed on PETER, and a backend application named `DelegationTest` was created.

Windows Authentication was enabled, while Anonymous Authentication was disabled.

The application was configured to display:

- Authenticated IIS user
- Authentication status
- Authentication type
- Execution identity

ASP.NET impersonation was enabled, and a dedicated Classic application pool was used to avoid the HTTP 500.24 configuration issue encountered with the Integrated pipeline.

**Constrained Delegation Configuration**

The `WebFrontend` account was configured to delegate only to:

```text
HTTP/peter.MARVEL.local
```

The resulting Active Directory configuration was verified:

```text
SamAccountName             : WebFrontend
ServicePrincipalName       : {HTTP/heaven, HTTP/heaven.MARVEL.local}
msDS-AllowedToDelegateTo   : {HTTP/peter.MARVEL.local}
TrustedToAuthForDelegation : False
TrustedForDelegation       : False
```

This configuration uses Kerberos-only constrained delegation.

- `TrustedToAuthForDelegation=False` means protocol transition is disabled.
- `TrustedForDelegation=False` confirms unconstrained delegation is not enabled on the service account.
- `msDS-AllowedToDelegateTo` restricts the configured delegation target to the PETER HTTP service.

#### Kerberos Delegation Validation

The frontend application on HEAVEN was accessed using the domain account `MARVEL\hdimla`.

The frontend then made an HTTP request to the backend application on PETER using default credentials.

The backend response showed:

```text
IIS Authenticated User: MARVEL\hdimla
Authenticated: True
Authentication Type: Negotiate
Execution Identity: MARVEL\hdimla
```

This demonstrated that the authenticated user's identity reached the backend application through the frontend request.

**Security Event Validation**

On PETER, Event ID 4624 recorded a successful network logon:

| Field | Recorded Value |
|---|---|
| Event ID | 4624 |
| Account | `MARVEL.LOCAL\hdimla` |
| Logon Type | 3 – Network |
| Source IP | `192.168.50.49` |
| Authentication Package | Kerberos |
| Logon Process | Kerberos |
| Impersonation Level | Impersonation |
| Logon GUID | `{bd54cb1f-66e9-07bd-9eb2-5573e869c0f4}` |

On HYDRA-DC, Event ID 4769 recorded a successful Kerberos service-ticket request with the following details:

| Field | Recorded Value |
|---|---|
| Event ID | 4769 |
| Account | `hdimla@MARVEL.LOCAL` |
| Service Name | `PETER$` |
| Client Address | `192.168.50.49` |
| Ticket Encryption | AES-256 (`0x12`) |
| Failure Code | `0x0` |
| Logon GUID | `{bd54cb1f-66e9-07bd-9eb2-5573e869c0f4}` |

The matching Logon GUID correlates the Domain Controller's Kerberos service-ticket event with the successful backend logon recorded on PETER.

The service name `PETER$` represents the backend computer account associated with the requested service SPN.

**Assessment**

The frontend-to-backend test successfully authenticated the user through Kerberos. The Active Directory configuration was also verified, and the matching security events provide strong evidence that the constrained delegation scenario is operational.

The event records do not independently provide an explicit S4U2Proxy confirmation, so the conclusion is based on the combined configuration, application behavior, and correlated security events.

**Status: Validated – Kerberos-only Constrained Delegation**

#### Resource-Based Constrained Delegation (RBCD)

The initial assessment found no RBCD entries on the queried computer accounts.

---

### Check 17 – Machine Account Quota

**Objective:** Review and restrict the number of computer accounts ordinary authenticated domain users can create.

Active Directory uses the `ms-DS-MachineAccountQuota` attribute to control how many computer accounts a regular domain user can create by default.

The default value is commonly `10`. This can allow ordinary domain users to create computer accounts, which may be abused in certain Active Directory attack paths.

#### Initial Assessment

Queried the current domain machine account quota:

```powershell
Get-ADDomain | Select-Object DistinguishedName, DNSRoot
```

Then inspected the domain object:

```powershell
Get-ADObject (Get-ADDomain).DistinguishedName `
    -Properties 'ms-DS-MachineAccountQuota' |
Select-Object DistinguishedName, 'ms-DS-MachineAccountQuota'
```

**Initial Finding:**

```text
ms-DS-MachineAccountQuota : 10
```

The domain allowed authenticated users to create up to ten computer accounts by default.

#### Remediation

Changed the machine account quota to zero:

```powershell
Set-ADDomain -Identity MARVEL.LOCAL `
    -Replace @{'ms-DS-MachineAccountQuota'=0}
```

#### Verification

Queried the domain object again:

```powershell
Get-ADObject (Get-ADDomain).DistinguishedName `
    -Properties 'ms-DS-MachineAccountQuota' |
Select-Object DistinguishedName, 'ms-DS-MachineAccountQuota'
```

**Final Finding:**

```text
ms-DS-MachineAccountQuota : 0
```

#### Assessment

The default machine account creation quota was successfully reduced from 10 to 0.

This prevents ordinary authenticated users from creating computer accounts through the default machine-account quota mechanism. It does not prevent authorized administrators or users with explicitly delegated computer-account creation permissions from joining machines to the domain.

---

### Summary – Checks 15 to 17

| Check | Assessment | Final Status |
|---|---|---|
| 15 – Unconstrained Delegation | Only HYDRA-DC identified with unconstrained delegation | Passed |
| 16 – Traditional Constrained Delegation | Configured and tested using HEAVEN and PETER | Validated |
| 16 – Resource-Based Constrained Delegation | No initial entries; separate lab scenario not yet implemented | Pending |
| 17 – Machine Account Quota | Reduced from 10 to 0 | Remediated |

**Overall Assessment**

The delegation and machine account review identified no unexpected unconstrained delegation outside the Domain Controller. Traditional constrained delegation was configured with a dedicated frontend service account and a restricted backend target, then tested through an IIS frontend-to-backend authentication scenario.

The initial RBCD assessment found no configured entries. RBCD remains a separate item for future testing. Finally, the domain machine account quota was reduced to zero to restrict default computer-account creation by ordinary authenticated users.
