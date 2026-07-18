# Linux & Networking Fundamentals — Lab Notes

**Author:** Carlon Madriaga
**Date:** 18 July 2026
**Environment:** Azure VM `Ubuntu-lab` (Ubuntu 24.04 LTS), accessed via SSH from macOS Terminal
**Goal:** Practice core Linux commands and networking fundamentals relevant to a SOC / Blue Team analyst role.

---

## 1. Connecting to the lab

Connected to the Azure Linux VM over SSH:

```
ssh azureuser@<public-ip>
```

- Reached the prompt `azureuser@Ubuntu-lab:~$`
- The prompt shows: **user** @ **hostname** : **location** **$**
- `$` = normal user (limited rights) · `#` = root (admin)
- Use `sudo <command>` to run a single command as admin rather than staying as root.

---

## 2. Linux fundamentals practised

| Command | What it does | SOC relevance |
|---|---|---|
| `pwd` | Print working directory (where am I) | Orientation on a machine |
| `ls` | List files in current folder | Basic navigation |
| `ls -la` | List **all** files (incl. hidden `.` files) with details | Attackers hide files with a leading `.` |
| `whoami` | Show current user | First thing both admins and attackers check |

### Reading permissions (from `ls -la`)

Example: `-rw-------` on `.bash_history`

```
-        rw-        ---        ---
type     owner      group      others
```

- **1st char:** `-` = file, `d` = directory
- **3 groups of 3:** owner / group / others, each `r` (read) `w` (write) `x` (execute)
- Security example: `.ssh` shows `drwx------` (owner-only) — correct, because it holds login keys. Wide-open permissions on sensitive files = red flag.

---

## 3. Investigating authentication logs

```
sudo tail -n 20 /var/log/auth.log
```

- `/var/log/auth.log` records logins, failed logins, and sudo usage.
- **Finding:** repeated failed SSH logins from **213.232.204.130**, trying invalid usernames (`RPM`, `sshd`, `monitor`) within seconds.
- Pattern = automated **SSH brute-force attack**. Key phrases:
  - `Invalid user` = username doesn't exist
  - `Failed password` = login rejected
  - `[preauth]` = dropped before authenticating
- **Outcome:** every attempt failed — no breach. Defences held.
- Also observed my own `sudo tail` command recorded in the log — logs capture the investigator too.

**Count failed attempts:**
```
sudo grep "Failed password" /var/log/auth.log | wc -l
```
- `grep` = filter lines containing a phrase · `|` = pipe output to next command · `wc -l` = count lines.

---

## 4. Networking fundamentals

### 4.1 View network addresses
```
ip a
```
Interfaces seen:
- **`lo`** (loopback) → `127.0.0.1` = "this machine itself" (localhost)
- **`eth0`** → `10.1.0.4` = the VM's **private IP** (inside Azure's network)
- Azure adds an accelerated-networking interface (`enP...`) — can be ignored.

**Key concept — two IPs:**

| IP | Type | Reachable by |
|---|---|---|
| `10.1.0.4` | Private | Only machines inside the Azure network |
| `<public-ip>` | Public | Anyone on the internet (incl. attacker bots) |

The brute-force bots reached the VM via the **public** IP.

### 4.2 See listening ports (open doors)
```
sudo ss -tlnp
```
Flags: `-t` TCP · `-l` listening · `-n` numeric · `-p` show program.

- **`0.0.0.0:22` → sshd** = SSH open to the whole internet (expected, but why fail2ban matters)
- **`127.0.0.53:53` / `127.0.0.54:53` → systemd-resolve** = DNS, local only (safe)

**Read the Local Address:**
- `0.0.0.0` = exposed to the whole internet ⚠️
- `127.0.0.x` = local only, safe from outside ✅

Result: only SSH (22) is internet-exposed → small, tight attack surface. All listeners are known, legitimate programs.

### 4.3 See active connections
```
sudo ss -tnp
```
(dropped `-l` → shows **established** connections, not just listening)

- Found my own live session:
  `ESTAB  10.1.0.4:22  <my-home-public-ip>:xxxxx  sshd`
- Cross-checked: the same IP appears in the `Last login: ... from <ip>` banner. Login record + live socket both confirm it's my machine.

**LISTEN vs ESTAB:**

| State | Meaning |
|---|---|
| `LISTEN` | Door open, waiting for a connection |
| `ESTAB` | Active conversation happening now |

SOC use: scan the **Peer Address** of established connections. A connection to an unrecognised foreign IP you didn't initiate = possible live intruder or malware phoning home.

---

## 5. Good operational habits reinforced
- **Deallocate (Stop) the VM when finished** — stops billing *and* removes it as an attack target.
- Start order for the AD lab: **DC01 first** (standalone Ubuntu-lab can start on its own).
- Keep secrets (passwords, Subscription/Tenant IDs) out of screenshots and public repos.

---

## 6. Next steps
- Install and configure **fail2ban** to auto-ban IPs (like 213.232.204.130) after repeated failures.
- Read `/var/log/auth.log` again after fail2ban to confirm bans.
- Continue TryHackMe **SOC Level 1** path.

---

*Skills demonstrated: SSH remote access · Linux CLI navigation · file permissions · log analysis (auth.log) · brute-force detection · `grep`/pipes · network interface inspection · port/socket analysis · public vs private IP · listening vs established connections.*
