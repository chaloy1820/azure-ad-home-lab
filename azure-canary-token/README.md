# Azure Canary Token — Cloud Honeyfile Detection Lab

**Detecting unauthorized access to a decoy credentials file in Azure, end to end: bait → logging → detection → automated alerting.**

> Part of my [azure-ad-home-lab](https://github.com/chaloy1820/azure-ad-home-lab) — a series of hands-on labs building toward SOC Analyst / Blue Team skills.

---

## TL;DR

I built a **canary token** (a honeyfile) in Azure: a fake `company_passwords.txt` sitting in a decoy storage account. Any read of that file is, by definition, suspicious — no legitimate process should ever touch it. I wired up diagnostic logging into a Log Analytics workspace, wrote a **KQL detection query** that caught a real test download, and deployed an **Azure Monitor alert rule** that now emails me automatically whenever the bait is accessed.

This is a complete detection-and-response loop — signal source, log ingestion, detection logic, and automated notification — the same shape that runs in a production SOC.

---

## Why canary tokens matter

A canary token is a deliberately planted trap. It has no legitimate use, so it produces **zero false positives from normal activity** — if it ever fires, something is wrong. Placing a file named `company_passwords.txt` in a "backups" container is exactly the kind of thing an attacker who has gained access will grab. The moment they do, the defender knows:

- **that** an intrusion happened,
- **when** it happened,
- **who** (source IP) did it,
- and **what** they touched.

Canaries are high-signal, low-cost, and catch attackers *after* they're already inside — where many other controls have already failed.

---

## Architecture

```
┌────────────────────────┐
│  Decoy Storage Account │   corpbackupstorage1820
│  /backups/             │
│   company_passwords.txt│  ← the bait (honeyfile)
└───────────┬────────────┘
            │ every blob read/write/delete
            │ (Diagnostic Settings → StorageRead)
            ▼
┌────────────────────────┐
│  Log Analytics         │   law-canary-lab
│  workspace             │   table: StorageBlobLogs
└───────────┬────────────┘
            │ KQL query evaluates every 5 min
            ▼
┌────────────────────────┐
│  Azure Monitor         │   "Canary - Bait File Accessed"
│  Alert Rule            │   fires when row count > 0
└───────────┬────────────┘
            │ action group: canary-email-alert
            ▼
        📧  Email to analyst
```

**Environment:** Azure for Students subscription · Resource group `ad-lab-rg` · Region Australia East

---

## Build walkthrough

### 1. The decoy storage account and bait file

A standard blob storage account (`corpbackupstorage1820`) with a `backups` container was used to make the trap look like a real backup location. A plain-text file named `company_passwords.txt` was uploaded as the bait. The name is intentionally irresistible and the location plausible — the whole point is that it looks worth stealing while being completely fake.

### 2. Diagnostic logging → Log Analytics

Diagnostic Settings were enabled on the storage account to forward **StorageRead** (and write/delete) events to the `law-canary-lab` Log Analytics workspace. This populates the `StorageBlobLogs` table, which records every blob operation with its timestamp, caller IP, operation type, request URI, and status.

> Note: Azure storage diagnostic logs are near-real-time but not instant — expect a **5–15 minute** delay before events land in the workspace.

### 3. The detection query (KQL)

The detection logic isolates reads of the bait file specifically:

```kql
StorageBlobLogs
| where OperationName == "GetBlob"
| where Uri contains "company_passwords"
| project TimeGenerated, CallerIpAddress, OperationName, Uri, StatusText
| sort by TimeGenerated desc
```

- `OperationName == "GetBlob"` → a download/read
- `Uri contains "company_passwords"` → the bait file only
- `project` → keep just the fields that matter for triage
- `sort by TimeGenerated desc` → most recent hit first

### 4. Detection confirmed — real caught event

I ran a test download of the bait file and the query caught it cleanly:

| Field | Value |
|---|---|
| **TimeGenerated (UTC)** | 2026-07-12 04:48:45 |
| **CallerIpAddress** | 115.70.61.149 (port 13289) |
| **OperationName** | GetBlob |
| **StatusText** | Success |
| **Uri** | `https://corpbackupstorage1820.blob.core.windows.net/.../backups/company_passwords.txt?sv=2026-02-06&...&srt=sco&sp=rw...` |

**Analyst observation:** the SAS token in the request URI carried `sp=rw` (read **+ write**) permissions. In a real environment, a download link scoped with write access is over-permissioned and would be flagged as a secondary finding — least privilege would demand read-only (`sp=r`).

### 5. Automated alerting

A scheduled query (log search) alert rule turns the detection into an automatic response:

| Setting | Value |
|---|---|
| **Alert rule name** | Canary - Bait File Accessed |
| **Severity** | 1 - Error |
| **Signal** | Custom log search (the KQL above) |
| **Measure** | Table rows, aggregated by Count |
| **Operator / Threshold** | Greater than `0` |
| **Evaluation frequency** | Every 5 minutes |
| **Action group** | `canary-email-alert` → email notification |

Because the query only ever returns rows when the bait is touched, "row count > 0" is a clean trigger with no tuning required. When it fires, the action group emails the analyst within roughly 5–10 minutes.

---

## Skills demonstrated

- **Cloud logging & telemetry:** Azure Diagnostic Settings, Log Analytics workspaces, the `StorageBlobLogs` schema
- **Detection engineering:** writing and validating a KQL query against real telemetry, not just theory
- **Alerting & automation:** Azure Monitor scheduled-query alert rules and action groups
- **Deception / honeypot concepts:** canary tokens as a high-signal, low-false-positive detection strategy
- **Security analysis:** spotting the over-permissioned SAS token as a secondary finding

---

## MITRE ATT&CK mapping

| Tactic | Technique | How the canary relates |
|---|---|---|
| Credential Access | **T1552 — Unsecured Credentials** | The bait mimics a credentials file an attacker would seek; access to it is the detected behavior |
| Collection | **T1530 — Data from Cloud Storage** | The read of a cloud storage object is exactly what the `GetBlob` detection captures |

---

## Cost note

The alert rule runs at roughly **$1.50/month** (a log-search alert evaluated every 5 minutes). The storage account and workspace ingestion are negligible at this volume. Any compute VMs in the broader lab are the real credit burn and should be stopped when idle.

---

## Next steps / possible extensions

- Add a **second canary** in a different service (e.g., a fake Key Vault secret or a decoy SQL row) to broaden coverage
- Route the alert to a **Logic App** to auto-post into Teams/Slack instead of email
- Feed the workspace into **Microsoft Sentinel** and build this as a proper analytics rule with an incident + investigation graph
- Track repeat offenders by `CallerIpAddress` over time and enrich with geo-IP
