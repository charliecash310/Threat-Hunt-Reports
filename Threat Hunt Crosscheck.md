
# 🛡️ Incident Response Report

**Case:** Threat Hunt – Unauthorized Access & HR Data Misuse  
**Environment:** Microsoft Defender for Endpoint  
**Date Range Investigated:** 2025-12-01 → 2025-12-31  
**Analyst Role:** Threat Hunter / Incident Responder

---

## 1. Incident Overview

Routine year-end monitoring identified irregular access patterns during compensation and performance review workflows. What initially appeared to be legitimate administrative activity escalated into a **multi-stage abuse of legitimate credentials**, involving:

- PowerShell execution
    
- Host and identity reconnaissance
    
- Sensitive HR data access
    
- Data staging and compression
    
- Persistence mechanisms
    
- Outbound connectivity testing
    
- Log tampering
    
- Lateral activity across endpoints
    

This report documents **every investigative step**, mapped flag-by-flag, with full KQL visibility and analyst reasoning.

---

## 2. Flag-by-Flag Investigation

---

## 🚩 Flag 1 – Initial Endpoint Association

**Question:**  
Which endpoint first shows activity tied to the user context involved in the chain?

**Objective:**  
Identify the first device associated with the suspicious account.

**KQL Query Used:**

```
DeviceProcessEvents 
| where AccountName contains "5y51-d3p7" 
| project TimeGenerated, AccountName, AccountDomain, DeviceName, ProcessCommandLine, FileName, InitiatingProcessFileName
```


**Finding:**
- **Device Identified:** `sys1-dept`

**Analyst Reasoning:**  
Process telemetry shows repeated activity under the same user context on a single endpoint. This establishes `sys1-dept` as the **initial execution surface**.

---

## 🚩 Flag 2 – Remote Session Source Attribution

**Question:**  
What is the IP address of the remote session accessing the system?

**KQL Query Used:**

```
DeviceNetworkEvents 
| where DeviceName == "sys1-dept" 
| where InitiatingProcessAccountName == "5y51-d3p7" 
| where InitiatingProcessRemoteSessionIP == "192.168.0.110" 
| sort by TimeGenerated asc 
| project TimeGenerated, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, DeviceName, RemoteIP, InitiatingProcessRemoteSessionIP, RemotePort, Protocol
```


**Finding:**

- **Remote Session IP:** `192.168.0.110`

**Analyst Reasoning:**  
Confirms activity originated from a remote interactive session rather than a local console, increasing the likelihood of credential misuse.

---

## 🚩 Flag 3 – Support Script Execution Confirmation

**Question:**  
What command was used to execute the PowerShell program?

**KQL Query Used:**
```
DeviceProcessEvents 
| where AccountName contains "5y51-d3p7" 
| where FileName == "powershell.exe" 
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine
```
**Finding:**

`powershell.exe -ExecutionPolicy Bypass -File C:\Users\...\PayrollSupport.ps1`

**Analyst Reasoning:**  
ExecutionPolicy bypass strongly suggests intentional script execution outside standard administrative workflows.

---

## 🚩 Flag 4 – System Reconnaissance Initiation

**Question:**  
What was the first reconnaissance command attempted?

**KQL Query Used:**

```
DeviceProcessEvents 
| where AccountName contains "5y51-d3p7" 
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine, InitiatingProcessCommandLine`
```

**Finding:**

`whoami.exe /all`

**Analyst Reasoning:**  
This is a classic post-access recon command used to enumerate privileges, group memberships, and token context.

---

## 🚩 Flag 5 – Sensitive Bonus-Related File Exposure

**Question:**  
Which sensitive file was likely targeted?

**KQL Query Used:**

```
DeviceFileEvents 
| where DeviceName == "sys1-dept" 
| where FileName contains "bonus"
```

**Finding:**

- **File:** `BonusMatrix_Draft_v3.xlsx`

**Analyst Reasoning:**  
File discovery shortly after recon indicates deliberate searching for sensitive HR material.

---

## 🚩 Flag 6 – Data Staging Activity Confirmation

**Question:**  
What is the initiating unique process ID for archive creation?

**KQL Query Used:**

```
DeviceFileEvents 
| where DeviceName == "sys1-dept" 
| where FileName endswith ".zip"  
	 or FileName endswith ".rar" 
	 or FileName endswith ".7z" 
	 or FileName endswith ".cab" 
| sort by TimeGenerated asc 
| project TimeGenerated, FileName, ActionType, InitiatingProcessUniqueId, InitiatingProcessFileName, InitiatingProcessCommandLine
```


**Finding:**

- **Process ID:** `2533274790396713`

**Analyst Reasoning:**  
Archive creation confirms **data staging**, a precursor to exfiltration.

---

## 🚩 Flag 7 – Outbound Connectivity Test

**Question:**  
When was the first outbound connection attempt initiated?

**KQL Query Used:**

```
DeviceNetworkEvents 
| where DeviceName == "sys1-dept" 
| where InitiatingProcessAccountName == "5y51-d3p7" 
| where InitiatingProcessFileName == "powershell.exe" 
| where RemoteIP == "23.215.0.136" 
| where RemoteIPType == "Public" 
| sort by TimeGenerated asc 
| project TimeGenerated, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
```

**Finding:**

- **Timestamp:** `2025-12-03T06:27:31.1857940Z`

**Analyst Reasoning:**  
Outbound connectivity tests are commonly performed before actual data transfer to validate egress paths.

---

## 🚩 Flag 8 – Registry-Based Persistence

**Question:**  
What registry key was modified?

**KQL Query Used:**

```
DeviceRegistryEvents 
| where DeviceName == "sys1-dept" 
| where InitiatingProcessAccountName == "5y51-d3p7" 
| where InitiatingProcessFileName == "powershell.exe" 
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```

**Finding:**

`HKEY_CURRENT_USER\S-1-5-21-805396`

**Analyst Reasoning:**  
User-level Run keys enable persistence across logons without elevated privileges.

---

## 🚩 Flag 9 – Scheduled Task Persistence

**Question:**  
What task name was created?

**KQL Query Used:**
```
`DeviceProcessEvents 
| where DeviceName == "sys1-dept" 
| where AccountName == "5y51-d3p7" 
| where FileName in ("schtasks.exe", "powershell.exe") 
| where ProcessCommandLine has "schtasks" | sort by TimeGenerated asc | project TimeGenerated, FileName, ProcessCommandLine`
```


**Finding:**

- **Task Name:** `BonusReviewAssist`
    

**Analyst Reasoning:**  
Redundant persistence mechanisms indicate planning for continued access.

---

## 🚩 FLAG 10 – Secondary Access to Employee Scorecard Artifact

**Question:**  
Which other remote session user attempted access to employee-related files?

**KQL Query:**

```
DeviceFileEvents 
| where FileName has_any ("scorecard", "Scorecard", "review", "performance") 
| where DeviceName == "sys1-dept" 
| where InitiatingProcessFileName == "powershell.exe" 
| sort by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessRemoteSessionDeviceName
```

**Answer:**  
`YE-HELPDESKTECH`

**Analyst Reasoning:**  
Indicates cross-department access inconsistent with job role.

---

## 🚩 FLAG 11 – Bonus Matrix Activity by New Remote Session

**Question:**  
Which department attempted access to bonus payout files?

**KQL Query:**

```
DeviceFileEvents 
| where InitiatingProcessRemoteSessionIP == "192.168.0.110" 
| where DeviceName == "sys1-dept" 
| sort by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessRemoteSessionIP, FileName, FolderPath, InitiatingProcessRemoteSessionDeviceName
```

**Answer:**  
`YE-HRPLANNER`

**Analyst Reasoning:**  
Shows expansion of access scope under the same remote IP.

---

## 🚩 FLAG 12 – Performance Review Access Validation

**Question:**  
Identify the timestamp of access to performance review material.

**KQL Query:**

```
DeviceProcessEvents 
| where DeviceName == "sys1-dept" 
| where InitiatingProcessRemoteSessionIP == "192.168.0.110" 
| where ProcessRemoteSessionDeviceName == "YE-HRPLANNER" 
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessRemoteSessionDeviceName
```

**Answer:**  
`2025-12-03T07:25:15.6288106Z`

**Analyst Reasoning:**  
Confirms repeated access patterns across departments and file types.

---

## 🚩 FLAG 13 – Approved/Final Bonus Artifact Access

**Question:**  
When was the finalized bonus artifact accessed?

**KQL Query:**

```
DeviceEvents 
| where ActionType == "SensitiveFileRead"
```

**Answer:**  
`2025-12-03T07:25:39.1653621Z`

**Analyst Reasoning:**  
Finalized documents represent higher business risk than drafts.

---

## 🚩 FLAG 14 – Candidate Archive Creation Location

**Question:**  
Which directory was the ZIP file created in?

**KQL Query:**

```
DeviceFileEvents 
| where DeviceName == "sys1-dept" 
| where ActionType == "FileCreated" 
| where FileName endswith ".zip" 
| sort by TimeGenerated asc 
| project TimeGenerated, FileName, FolderPath
```

**Answer:**  
`C:\Users\5y51-d3p7\Documents\Q4Can`

**Analyst Reasoning:**  
User-space staging directory avoids administrative detection.

---

## 🚩 FLAG 15 – Outbound Transfer Attempt Timestamp

**Question:**  
Was outbound transfer attempted, and when?

**KQL Query:**

```
DeviceNetworkEvents 
| where DeviceName == "sys1-dept" 
| where InitiatingProcessFileName == "powershell.exe" 
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine
```

**Answer:**  
`2025-12-03T07:26:28.5959592Z`

**Analyst Reasoning:**  
Timing aligns closely with archive creation, reinforcing intent.

---

## 🚩 FLAG 16 – Local Log Clearing Attempt

**Question:**  
What command was used to clear logs?

**KQL Query:**

```
DeviceProcessEvents 
| where DeviceName == "sys1-dept" 
| where InitiatingProcessRemoteSessionDeviceName == "YE-HRPLANNER" 
| where FileName == "wevtutil.exe" 
| sort by TimeGenerated asc 
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
```

**Answer:**

`wevtutil.exe cl Microsoft-Windows-PowerShell/Operational`

**Analyst Reasoning:**  
Defense evasion confirms malicious intent beyond accidental misuse.

---

## 🚩 FLAG 17 – Second Endpoint Scope Confirmation

**Question:**  
What other compromised machine was identified?

**KQL Query:**

```
DeviceProcessEvents 
| where ProcessRemoteSessionIP == "192.168.0.110" 
| where AccountDomain == "main1-srvr"
```

**Answer:**  
`main1-srvr`

**Analyst Reasoning:**  
Confirms lateral scope expansion.

---

## 🚩 FLAG 18 – Approved Bonus Artifact Access on Second Endpoint

**Question:**  
When was the approved bonus artifact accessed on the second system?

**KQL Query:**

```
DeviceEvents 
| where DeviceName == "main1-srvr" 
| where ActionType == "SensitiveFileRead" 
| where FileName contains "bonus"
```

**Answer:**  
`2025-12-04T03:11:58.6027690Z`

**Analyst Reasoning:**  
Repetition across endpoints confirms intent.

---

## 🚩 FLAG 19 – Scorecard Access via Notepad

**Question:**  
What process was used to access employee scorecards?

**KQL Query:**

```
DeviceProcessEvents 
| where DeviceName == "main1-srvr" 
| where FileName == "notepad.exe" 
| where InitiatingProcessRemoteSessionDeviceName == "YE-FINANCEREVIE"
```

**Answer:**  
`notepad.exe`

**Analyst Reasoning:**  
Use of Notepad suggests quiet, manual review.

---

## 🚩 FLAG 20 – Year-End File Consolidation

**Question:**  
Which year-end files were accessed or consolidated?

**KQL Query:**

```
DeviceFileEvents 
| where DeviceName contains "main1-srvr" 
| where FileName contains "year"
```

**Answer:**  
Multiple year-end review artifacts.

**Analyst Reasoning:**  
Consolidation is consistent with final staging.

---

## 🚩 FLAG 21 – Consolidation Timing Validation

**Question:**  
When did consolidation occur relative to prior access?

**KQL Query:**  
_(Same as Flag 20, sorted by TimeGenerated)_

**Answer:**  
Occurred after validated sensitive file access.

**Analyst Reasoning:**  
Chronology confirms deliberate workflow.

---

## 🚩 FLAG 22 – Final Outbound Connection Attempt

**Question:**  
Did the second system attempt outbound communication?

**KQL Query:**

```
DeviceNetworkEvents 
| where DeviceName contains "main1-srvr" 
| where InitiatingProcessFileName == "powershell.exe" 
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessRemoteSessionDeviceName
```

**Answer:**  
Outbound connection observed.

**Analyst Reasoning:**  
Completes the exfiltration chain.

---

## 3. Incident Conclusion

This investigation confirms **intentional misuse of legitimate access** with behaviors consistent with insider threat or compromised internal credentials. No malware was required; all activity leveraged built-in tools (LOLBins).

---

## 4. Final Severity Assessment

|Category|Rating|
|---|---|
|Data Sensitivity|High|
|Scope|Multi-endpoint|
|Intent|Confirmed|
|Severity|🔴 High|
