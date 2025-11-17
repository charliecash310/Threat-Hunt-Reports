# Threat-Hunt-Event-Assistance
Threat Hunt Event: Assistance


# 🛡️ Threat Hunt Report – Assistance Incident (October 2025)

**Analyst:** Grisham DelRosario 
**Environment:** Log Analytics Workspace   
**Host Investigated:** `gab-intern-vm`  
**Time Window:** **October 1 – October 15, 2025**

---

# 📌 Scenario

A routine support request should have ended with a reset and reassurance. Instead, the so- called "help" left behind a trail of anomalies that don't add up. 
What was framed as troubleshooting looked more like an audit of the system itself probing, cataloging, leaving subtle traces in its wake. Actions chained together in 
suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended. And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny. 
This wasn't remote assistance. It was a misdirection.


---

# 🎯 Objective

Your mission this time is to reconstruct the timeline, connect the scattered remnants of this "support session", and decide what was legitimate, and what was staged. The evidence is here. The question is whether you'll see through the story or believe it.
****
---

# 🏁 Starting Point

Suspicious machine identified:

**`gab-intern-vm`**

Using keyword analysis:
- desk  
- help  
- support  
- tool  

And detection of processes originating in **Downloads**.



---

# 🧠 Scenario Summary

The attacker impersonated support activity, leveraging:

- LOLBins  
- Deception artifacts  
- Short-lived PowerShell commands  
- Staged ZIP archives  
- Outbound network tests  
- Persistence mechanisms  

…to create the illusion of legitimate assistance while performing reconnaissance and staging operations.

---

# ⚑ Flag-by-Flag Analysis

## Flag 1 — ExecutionPolicy Bypass  
Suspicious PowerShell launched with:

### Suspicious PowerShell Execution
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest", "/S", "-ExecutionPolicy Bypass", "-NoProfile")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```
```
-ExecutionPolicy Bypass
```

## Flag 2 — Tamper Artifact  
Real artifact:  
**DefenderTamperArtifact.lnk**

## Flag 3 — Clipboard Query  
Command:
```
Get-Clipboard | Out-Null
```

## Flag 4 — Session Discovery  
Execution:
```
qwinsta.exe
```

## Flag 5 — Disk Recon  
```
wmic logicaldisk get name,freespace,size
```

## Flag 6 — Outbound Connectivity  
PowerShell DNS + HTTP tests.

## Flag 7 — Recon Parent PID  
**2533274790397065**

## Flag 8 — Process Enumeration  
`tasklist.exe`

## Flag 9 — Privilege Discovery  
`whoami /priv`

## Flag 10 — First Outbound Contact  
`www.msftconnecttest.com`

## Flag 11 — Data Staging  
`ReconArtifacts.zip`

## Flag 12 — Exfil Attempt  
Outbound IP lookup.

## Flag 13 — Persistence (Scheduled Task)  
Support-themed task created.

## Flag 14 — Persistence (Registry Run Key)  
`RemoteAssistUpdater`  
(no results—failed/misdirection)

## Flag 15 — Final Deception Artifact  
Support-themed LNK left behind.

---

# 🕒 Timeline Reconstruction

```
05:22 AM — Earliest PowerShell activity  
06:00 AM — ExecutionPolicy bypass  
12:22 PM — SupportTool.ps1  
12:50 PM — Clipboard + Network scans  
12:51 PM — qwinsta, wmic, artifact creation  
12:55 PM — Outbound connectivity test  
12:56 PM — ReconArtifacts.zip staged  
12:57 PM — Exfil attempt  
12:58 PM — Scheduled task persistence  
12:59 PM — Registry persistence attempt  
1:00 PM — Final LNK deception file  
```

---

# 🔍 Key Findings

- Full LOTL tradecraft  
- Deception artifacts to obscure activity  
- Data staging and exfil attempt  
- Persistence artifacts  
- Support narrative planted intentionally  

---

# 📁 Repo Structure

```
/
├── README.md
├── evidence/
├── kql/
├── timeline/
└── report/
```

---

# ✔ End of Report
