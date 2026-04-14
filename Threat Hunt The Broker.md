# 🛡️ Threat Hunt Report – “The Broker”

## 📌 Scenario Overview

This investigation analyzes a multi-stage intrusion across an enterprise environment:

* `as-pc1` – Initial compromised workstation
* `as-pc2` – Secondary workstation
* `as-srv` – File server (target for sensitive data)

Primary user of interest:

```
sophie.turner
```

Initial execution originated from a **malicious payload disguised as a PDF**:

```
daniel_richardson_cv.pdf.exe
```



---

## 🚨 Executive Summary

An attacker successfully:

* Gained initial access via user execution
* Established persistence via account creation
* Leveraged remote access tooling (AnyDesk)
* Accessed and staged sensitive payroll data
* Cleared logs to evade detection
* Executed a **fileless credential theft attack (SharpChrome)**
* Injected payload into a legitimate process (`notepad.exe`)
* Maintained C2 communication using **multi-IP infrastructure**

**Severity:** 🔴 Critical
**Confidence:** High
**Attack Type:** Fileless + Credential Theft + Data Exfiltration

---

## 🧭 Timeline of Attack

| Time (UTC)    | Event                                        |
| ------------- | -------------------------------------------- |
| ~05:00        | User executes `daniel_richardson_cv.pdf.exe` |
| Shortly after | PowerShell activity initiated                |
| + Minutes     | AnyDesk deployed for remote access           |
| + Minutes     | Account `svc_backup` created                 |
| + Minutes     | Lateral movement to `as-srv`                 |
| + Minutes     | Payroll file accessed + modified             |
| + Minutes     | Archive created (data staging)               |
| + Minutes     | Logs cleared (`wevtutil`)                    |
| + Minutes     | Reflective .NET payload loaded               |
| + Minutes     | SharpChrome executed (credential theft)      |
| + Minutes     | Injection into `notepad.exe`                 |
| Ongoing       | C2 communication via multi-IP domain         |

---

## 🔍 Key Findings (By Attack Phase)

---

### 🧨 Initial Access

**Payload Execution**

```
daniel_richardson_cv.pdf.exe
```

Masquerading as a resume file—classic social engineering lure.

**MITRE:** T1204 – User Execution

---

### 🧠 Execution

PowerShell used immediately after payload execution.

**MITRE:**

* T1059.001 – PowerShell

---

### 🕸️ Command & Control

* External communication initiated from malicious process
* Domain resolves to **multiple IP addresses**

➡️ Indicator of resilient infrastructure (load balancing / fallback nodes)

**MITRE:**

* T1071.001 – Web Protocols
* T1573 – Encrypted Channel

---

### 🧰 Remote Access Tooling

```
AnyDesk.exe
```

Used for persistent remote control of host.



**MITRE:** T1219 – Remote Access Software

---

### 👤 Persistence

```
net user svc_backup /add
```

Backdoor account created.

**MITRE:** T1136.001 – Local Account Creation

---

### 📁 Discovery & Collection

Target:

```
\\AS-SRV\Payroll\
```

File accessed:

```
BACS_Payments_Dec2025.ods
```

Lock file confirms editing:

```
.~lock.BACS_Payments_Dec2025.ods#
```

**MITRE:**

* T1039 – Network Share Discovery
* T1074 – Data Staging

---

### 📦 Data Staging

Compressed archive created (.zip / .rar / .7z observed)



**MITRE:** T1560 – Archive Collected Data

---

### 🧹 Defense Evasion

Log clearing observed:

```
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Windows PowerShell"
```

**Confirmed logs cleared:**

```
Security, System
```

**MITRE:** T1070.001 – Clear Windows Event Logs

---

### 🧬 Fileless Execution (Critical)

Detection:

```
ActionType: ClrUnbackedModuleLoaded
```

This indicates:

* .NET assembly loaded directly into memory
* No file written to disk

---

### 🔐 Credential Theft

Tool identified:

```
SharpChrome
```

From telemetry:

```
ModuleILPathOrName: SharpChrome
```

Behavior:

* Extracts Chrome credentials via DPAPI
* Runs fully in memory

**MITRE:** T1555.003 – Credentials from Web Browsers

---

### 🧠 Process Injection

Malicious assembly hosted inside:

```
notepad.exe
```

Legitimate binary used as a cloak.

**MITRE:** T1055 – Process Injection

---

## 🧬 MITRE ATT&CK Mapping

| Phase             | Technique                  | ID        |
| ----------------- | -------------------------- | --------- |
| Initial Access    | User Execution             | T1204     |
| Execution         | PowerShell                 | T1059.001 |
| Persistence       | Account Creation           | T1136.001 |
| Lateral Movement  | Remote Tool (AnyDesk)      | T1219     |
| Discovery         | File/Share Access          | T1039     |
| Collection        | Data Staging               | T1074     |
| Exfil Prep        | Archive Data               | T1560     |
| Defense Evasion   | Log Clearing               | T1070.001 |
| Execution         | Reflective Loading         | T1055     |
| Credential Access | Browser Credential Dumping | T1555.003 |
| Command & Control | Web Protocols              | T1071.001 |
| Command & Control | Encrypted Channel          | T1573     |

---

## 🔍 Detection Queries (KQL)

### 🔹 Reflective Loading

```kql
DeviceEvents
| where ActionType == "ClrUnbackedModuleLoaded"
```

---

### 🔹 Log Clearing

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "wevtutil cl"
```

---

### 🔹 Credential Theft Indicators

```kql
DeviceEvents
| where ActionType == "ClrUnbackedModuleLoaded"
| extend Module=parse_json(AdditionalFields)
| project TimeGenerated, DeviceName, Module.ModuleILPathOrName
```

---

### 🔹 Multi-IP C2 Detection

```kql
DeviceNetworkEvents
| summarize IP_Count = dcount(RemoteIP) by RemoteUrl
| where IP_Count > 1
```

---

## ⚠️ Impact Assessment

* Payroll data accessed and modified
* Browser credentials compromised
* Persistence established via backdoor account
* Logs tampered (loss of forensic visibility)
* Multi-host compromise confirmed

---

## 🛑 Recommendations

### Immediate Actions

* Disable `svc_backup`
* Reset all credentials
* Isolate `as-pc1`, `as-pc2`, `as-srv`
* Block malicious domain + associated IPs

---

### Long-Term Hardening

* Monitor:

  * `ClrUnbackedModuleLoaded`
  * `wevtutil`
* Restrict PowerShell execution
* Audit browser credential storage policies
* Implement EDR alerts for process injection

---

## 🧠 Lessons Learned

* Fileless malware leaves **behavioral traces, not files**
* `ClrUnbackedModuleLoaded` = **gold signal**
* Legitimate binaries (`notepad.exe`) are often weaponized
* Multi-IP domains are strong indicators of **resilient C2**

---

## 🏁 Conclusion

This hunt reveals a **full adversary lifecycle**:

> Initial Access → Execution → Persistence → Lateral Movement → Data Theft → Anti-Forensics → C2

The attacker operated with **stealth, speed, and intent**—but left enough signal in telemetry to reconstruct the entire operation.

---

## 📂 Suggested Repo Structure

```
/threat-hunt-the-broker
│
├── README.md
├── queries/
│   ├── log_clearing.kql
│   ├── reflective_loading.kql
│   ├── c2_detection.kql
│
├── screenshots/
│   ├── sharpchrome.png
│   ├── wevtutil.png
│   ├── injection.png
│
└── timeline/
    └── attack_timeline.md
```

---
