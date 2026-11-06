# Active Directory Hardening Lab

A hands-on cybersecurity project focused on securing Windows Active Directory environments against common attack techniques through security configurations, Group Policy, PowerShell, and security best practices.

## Overview

This project documents my hands-on experience implementing and validating security hardening measures in a Windows Active Directory environment.

The lab uses my existing `MARVEL.LOCAL` domain to explore different security configurations, reduce common attack risks, and improve the overall security posture of an Active Directory infrastructure.

## Lab Environment

| Component | Configuration |
|---|---|
| Hypervisor | Proxmox VE |
| Domain | `MARVEL.LOCAL` |
| Domain Controller | `HYDRA-DC` |
| Server OS | Windows Server 2025 Standard Evaluation |
| Client Workstations | Windows 10 Pro 22H2 |
| Virtualization | Virtual Machines |

## Hardening Scope

### 1. Network Security
- LLMNR Hardening
- IPv6 Security
- SMB Security

### 2. Identity and Access Management
- LDAP Security
- Credential Protection
- Kerberos Hardening
- Privileged Account Security
- Token Security

### 3. Endpoint Security
- Windows Defender Configuration
- PowerShell Security
- Application Control

### 4. Active Directory Security
- Domain Controller Hardening
- Group Policy Security
- Active Directory Certificate Services (AD CS) Hardening
- NTDS.dit and Backup Protection
- File and Share Permissions

### 5. Monitoring and Detection
- Windows Security Auditing
- Event Logging
- Security Monitoring
- Attack Detection

## Documentation Format

Each hardening topic will include:

- **Overview** – Explanation of the security issue.
- **Security Objective** – What the configuration aims to protect.
- **Configuration** – Actual hardening steps using Group Policy, PowerShell, or Windows settings.
- **Validation** – Commands and procedures to verify the configuration.
- **Expected Results** – The expected security outcome.
- **References** – Relevant documentation and security guidelines.

## Project Objectives

- Improve Active Directory security through practical hardening.
- Understand common weaknesses in Windows domain environments.
- Implement security configurations using Group Policy and PowerShell.
- Apply least privilege and secure authentication practices.
- Improve monitoring and detection capabilities.
- Develop practical Windows Server and Active Directory security skills.

## Disclaimer

This project is intended for educational purposes and authorized laboratory environments. All configurations and testing are performed within my own virtualized Active Directory lab.

## Progress

This repository is continuously updated as new hardening configurations are implemented, tested, and documented.
