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
Client Domain Join (in progress)
Joining a client VM to the domain to test how policies and permissions
apply to end-user machines.

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
 Join and test a client VM against domain policies
 Document policy testing results with before/after screenshots

Screenshots
(Add redacted screenshots here — remove public IP addresses and any
personal information before uploading)

Built as part of my Cyber Security studies (Cert III → Cert IV) and ongoing
Azure learning (AZ-900).
