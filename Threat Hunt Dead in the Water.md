Threat Hunt - Dead in the Water

---

# Incident Response Report

**Ransomware Attack – Azuki Logistics Network**

**Prepared by:** Security Operations  
**Frameworks Referenced:**

- NIST SP 800-53 Rev. 5
- MITRE ATT&CK (Enterprise)

**Incident Classification:** High Impact – Ransomware  
**Incident Type:** Data Encrypted for Impact  
**Status:** Contained (Lab Scenario)

---

## 1. Executive Summary

On **November 25, 2025**, Azuki Logistics experienced a coordinated ransomware attack impacting Windows and Linux systems within the enterprise network. The adversary gained administrative access, performed lateral movement via SMB admin shares, disabled backup and recovery mechanisms, deployed ransomware payloads across multiple hosts, and executed extensive anti-forensic actions prior to encrypting data.

The attack demonstrated **deliberate preparation**, **environment awareness**, and **defense evasion**, consistent with modern human-operated ransomware activity.

The incident was successfully reconstructed using endpoint telemetry and process execution logs.

---

## 2. Affected Assets

| Hostname       | Role              | OS                  | IP Address |
| -------------- | ----------------- | ------------------- | ---------- |
| AZUKI-AdminPC  | Admin Workstation | Windows 11          | 10.1.0.108 |
| AZUKI-SL       | User Workstation  | Windows 11          | 10.1.0.204 |
| AZUKI-FS01     | File Server       | Windows Server 2022 | 10.1.0.188 |
| AZUKI-BackupSv | Backup Server     | Ubuntu 22.04        | 10.1.0.189 |

---

## 3. Attack Timeline (Condensed)

|Phase|Description|
|---|---|
|Initial Access|External tool transfer onto Linux backup server|
|Credential Access|Plaintext credential file accessed|
|Lateral Movement|SMB admin shares via PsExec|
|Execution|Ransomware payload deployed remotely|
|Impact Preparation|Backup services stopped, recovery disabled|
|Anti-Forensics|Logs and journals deleted|
|Encryption|Files encrypted, ransom note deployed|
|Persistence|Registry autorun and scheduled task created|

---

## 4. Technical Analysis (Mapped to MITRE ATT&CK)

### 4.1 Initial Access – Tool Transfer

**Technique:** Ingress Tool Transfer

- External tool retrieved using `curl`
- Pivot confirmed via network telemetry on backup server

---

### 4.2 Credential Access – Credentials in Files

**Technique:** Unsecured Credentials  
**Command Observed:**

`cat /backups/configs/all-credentials.txt`

**Impact:** Enabled privilege escalation and lateral movement.

---

### 4.3 Lateral Movement – SMB Admin Shares

**Technique:** SMB / Windows Admin Shares  
**Tool Identified:**

`PsExec64.exe`

**Deployment Command:**

`PsExec64.exe \\10.1.0.188 -u fileadmin -p ******** -c C:\Windows\Temp\cache\silentlynx.exe`

---

### 4.4 Execution – Malicious Payload

**Payload Executed:**

`silentlynx.exe`

Payload execution occurred on:

- Admin PC
- File Server
- Workstation

---

## 5. Impact Analysis (NIST 800-53 – CP / IR / SI)

### 5.1 Backup and Recovery Inhibition

|Action|Command|
|---|---|
|Shadow Copies Deleted|`vssadmin delete shadows /all /quiet`|
|Backup Engine Stopped|`net stop wbengine /y`|
|VSS Service Stopped|`net stop VSS /y`|
|Recovery Disabled|`bcdedit /set {default} recoveryenabled No`|
|Storage Limited|`vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB`|
|Backup Catalog Deleted|`wbadmin delete catalog -quiet`|

**NIST Controls Impacted:**

- CP-9 (System Backup)
    
- CP-10 (System Recovery)
    
- IR-4 (Incident Handling)
    

---

### 5.2 Defense Evasion – Process Termination

**Command Observed:**

`taskkill /F /IM sqlservr.exe`

Purpose: Unlock files prior to encryption.

---

### 5.3 Anti-Forensics – Evidence Destruction

**Command Observed:**

`fsutil usn deletejournal /D C:`

**NIST Controls Impacted:**

- AU-6 (Audit Review)
    
- AU-11 (Audit Retention)
    

---

## 6. Persistence Mechanisms

### 6.1 Registry Autorun

**Registry Value Name:**

`WindowsSecurityHealth`

Used to masquerade as a legitimate Windows component.

---

### 6.2 Scheduled Task Creation

**Task Created:**

`Microsoft\Windows\Security\SecurityHealthService`

**Creation Command:**

`schtasks /create /tn "Microsoft\Windows\Security\SecurityHealthService" /tr "C:\Windows\Temp\cache\silentlynx.exe" /sc onlogon /rl highest /f`

**NIST Controls Impacted:**

- SI-7 (Integrity Monitoring)
    
- CM-7 (Least Functionality)
    

---

## 7. Final Impact – Ransomware Success

### 7.1 Ransom Note

**Filename:**

`SILENTLYNX_README.txt`

Confirms successful encryption and attacker intent.

---

## 8. Root Cause Analysis

**Primary Root Causes:**

- Excessive privilege exposure
    
- Plaintext credentials stored in backup locations
    
- Lack of monitoring for admin share abuse
    
- Inadequate alerting on backup and recovery manipulation
    

---

## 9. Control Gaps (NIST 800-53 Mapping)

|Control|Gap|
|---|---|
|AC-6|Privileged access misuse not detected|
|IA-5|Credential protection failures|
|CP-9|Backup integrity not enforced|
|SI-4|Insufficient detection of destructive commands|
|AU-12|Logging deletion not alerted|

---

## 10. Recommendations

### Immediate

- Remove plaintext credentials from backup systems
    
- Restrict PsExec usage via application control
    
- Alert on backup and recovery modification commands
    

### Strategic

- Implement least-privilege service accounts
    
- Enforce immutable backups
    
- Add behavioral detections for ransomware kill chains
    
- Harden backup servers as Tier-0 assets
    

---

## 11. Conclusion

This incident represents a **textbook ransomware operation** executed with precision and awareness of enterprise defenses. The attacker’s actions aligned closely with known ransomware playbooks, demonstrating how quickly recovery options can be neutralized once administrative control is achieved.

While this was a controlled scenario, the techniques observed mirror real-world incidents and provide valuable insight for strengthening detection, response, and recovery capabilities.
