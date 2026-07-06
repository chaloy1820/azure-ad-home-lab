Azure Active Directory Home Lab
Overview
A self-directed home lab built in Microsoft Azure to develop hands-on skills in
Windows Server administration, Active Directory Domain Services, and Group
Policy — built alongside my Certificate III/IV in Cyber Security studies.
Objective
To understand how enterprise identity and access management works in practice,
not just in theory: domain controllers, organisational units, security groups,
and policy enforcement across client machines.
Environment

Platform: Microsoft Azure (Australia East region)
Domain Controller: Windows Server 2025, Standard B2als_v2
Domain: carlonlab.local
Resource Group: AD-Lab-RG

What I Built

Domain Controller Setup
Deployed a Windows Server 2025 VM and promoted it to a domain controller,
establishing carlonlab.local as the Active Directory domain.
Organisational Structure
Created Organisational Units (OUs) to logically separate users and
resources, reflecting how a real business might structure departments.
Users & Security Groups
Created user accounts (e.g. Alice Carter, Bob Carter) and a security group
(IT_Team) to manage permissions by role rather than by individual account —
following the principle of least privilege.
Group Policy (in progress)
Applying Group Policy Objects (GPOs) to enforce settings across the domain,
such as password policies and restricted access, and understanding how
policy inheritance works across OUs.
Client Domain Join (complete)
Joined CLIENT01 to the domain and
verified a domain user (Alice Carter) can log in and authenticate. Confirmed via whoami, which returned carlonlab\alice.carter
Why This Matters
Understanding AD is foundational for many entry-level security roles — SOC
analysts, IT support, and security administrators all need to understand how
identity, access, and policy enforcement work in a Windows enterprise
environment. This lab let me learn by doing rather than just reading.
Challenges & Lessons Learned

Managing Azure for Students credit carefully — I stop (deallocate) the VM
after every session rather than leaving it running, which keeps monthly
cost to roughly $7–8 USD instead of much more.
Learning the difference between RBAC (Azure-level access control) and
Group Policy (domain-level control) — related concepts that are easy to
confuse at first.

Next Steps

 Apply Group Policy Objects for password and access control
 Document policy testing results with before/after screenshots

Screenshots
<img width="1710" height="1107" alt="whoami alice carter" src="https://github.com/user-attachments/assets/c527114a-1ba2-4b13-ae96-c98046d48346" />

Built as part of my Cyber Security studies (Cert III → Cert IV) and ongoing
Azure learning (AZ-900).
## 🔍 Security Finding: External RDP Brute-Force Attempts on DC01

**Date discovered:** July 2026
**Tool used:** Windows Event Viewer (Security Log, Event ID 4625)

### Finding
While reviewing the Security event log on DC01 for an Account Lockout Policy exercise, 
I discovered repeated Event ID 4625 ("An account failed to log on") entries originating 
from an external IP address (80.94.95.221), not from any internal lab machine.

- **Logon Type:** 3 (Network)
- **Authentication Package:** NTLM
- **Failure Reason:** Unknown user name or bad password
- **Source IP:** 80.94.95.221 — registered to UNMANAGED LTD, a data center/hosting 
  provider based in Timișoara, Romania (ASN 204428)
- **Context:** This IP falls in a data center range with a documented history of RDP 
  brute-force reports on AbuseIPDB (573 reports from 48 sources historically, though 
  current abuse confidence is 0%, most recent report 9 months old)

### Root Cause
DC01's Network Security Group (DC01-nsg) allowed inbound RDP (port 3389) from **Any** 
source, exposing the VM directly to internet-wide scanning bots.

### Remediation
Updated the DC01-nsg inbound rule to restrict RDP access to a single trusted IP 
address, blocking the connection at the network layer before Windows authentication 
is ever reached.

### Takeaway
Even a lab environment with no real data is a target for automated scanning the 
moment it has a public IP. Locking down NSG source ranges is a baseline control.
<img width="1358" height="729" alt="abuseipdb-80 94 95 223" src="https://github.com/user-attachments/assets/c0767d15-848d-4c87-ad82-4d8bd4230056" />

