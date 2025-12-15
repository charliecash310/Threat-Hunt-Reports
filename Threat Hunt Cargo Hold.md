
## 🛡️ Threat Hunt Report

- **Operation:** Cargo Hold 
- **Environment:** Josh Madakor Cyber Range  - Microsoft Azure - Microsoft Defender
- **Analyst:** Grisham DelRosario
- **Date:** December 6th, 2025
- **Incident:** November 19th - 24th, 2025

----
## 🧩 Executive Summary

An external attacker used a previously compromised workstation (` azuki-sl `) as a beachhead, pivoted via RDP to the file server (**azuki-fileserver01**), performed discovery and credential harvesting, staged sensitive data in a hidden directory, compressed it, and exfiltrated it to **file.io** using `curl.exe`.

They then established persistence via a `Run` registry key that launches a masqueraded PowerShell beacon (`svchost.ps1`) and finally attempted to cover their tracks by deleting the PowerShell history file.

Impact in plain terms:
- **Confidentiality:** Highly impacted (password CSV, archives, LSASS dump exfiltrated).
- **Integrity:** No direct tampering observed, but credentials compromise enables future modification.
- **Availability:** Not impacted in this scenario.

![[Pasted image 20251206170521.png]]

------
##  🌎 Environment / Scope

- **Port of entry:** `azuki-sl` (workstation)
- **Primary target:** `azuki-fileserver01` (file server)
- **Key accounts:**
    - `kenji.sato` (used for RDP into azuki-sl)
    - `fileadmin` (file server admin, used for lateral movement and data theft)
- **Key directories:**
    - Staging: `C:\Windows\Logs\CBS\`
    - Credential stash: `C:\Windows\Logs\CBS\it-admin\IT-Admin-Passwords.csv`
    - Archives: `C:\Windows\Logs\CBS\*.tar.gz`
    - LSASS dump: `C:\Windows\Logs\CBS\lsass.dmp`

----
## 🛠️ **Attack Chain Overview (Kill Chain)**

| **Phase**                  | **Description**                                                                                                                                      |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Initial Access**         | Attacker authenticated via RDP to _azuki-fileserver01_ using valid credentials.                                                                      |
| **Execution**              | Executed malicious PowerShell payload delivered via **certutil** (`ex.ps1`).                                                                         |
| **Discovery**              | Enumerated system info, privileges, users, shares, and network configuration (`whoami`, `whoami /all`, `ipconfig /all`, `net view`, `net share`).    |
| **Privilege Escalation**   | Leveraged elevated token privileges discovered via `whoami /all`; prepared for LSASS memory access.                                                  |
| **Defense Evasion**        | Created hidden directory under `C:\Windows\Logs\CBS\` using file attribute abuse; renamed tools (e.g., **pd.exe**) to blend with system binaries.    |
| **Persistence**            | Added autorun entry under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` with masqueraded value **FileShareSync** pointing to **svchost.ps1**. |
| **Credential Access**      | Dumped credentials by creating LSASS process dump (`lsass.dmp`) using renamed dumper (`pd.exe -ma`).                                                 |
| **Collection**             | Copied sensitive directories (Admin, Shipping, Financial) using **xcopy**; staged data locally in hidden folders.                                    |
| **Collection (Archiving)** | Compressed stolen data using **tar.exe** into multiple `.tar.gz` archives.                                                                           |
| **Exfiltration**           | Exfiltrated compressed archives using **curl.exe** with `-F file=@...` to **file.io** over HTTPS.                                                    |
| **Anti-Forensics**         | Deleted PowerShell command history (`ConsoleHost_history.txt`) to remove traces of attacker activity.                                                |
| **Command & Control**      | C2 not explicitly shown; exfil channel served as anonymous outbound communication path.                                                              |
| **Lateral Movement**       | Not observed beyond initial RDP entry, but tools and discovery indicate preparation for internal movement.                                           |

----
## FLAG 1

![[Pasted image 20251206173504.png]]

```

DeviceLogonEvents
| where DeviceName contains "azuki"
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-26))
| where ActionType contains "success"
| project Timestamp, DeviceName, ActionType, LogonType, AccountDomain, AccountName, RemoteIP

```

![[Pasted image 20251207125048.png]]

----

## FLAG 2

![[Pasted image 20251206181932.png]]

```
//FLAG 2 // 10.1.0.188 / 10.1.0.108
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName contains "mstsc.exe"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-26))
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
```

![[Pasted image 20251206182237.png]]

```
// FLAG 2 / 10.1.0.108
DeviceLogonEvents
| where DeviceName contains "azuki"
| where RemoteIP contains "10.1.0.108" //Remote IP from 'DeviceProcessEvents' Table
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-26))
| project Timestamp, DeviceName, ActionType, LogonType, AccountDomain, AccountName, RemoteIP
```

![[Pasted image 20251206182748.png]]

----

## FLAG 3

![[Pasted image 20251206182929.png]]

```
Refer to KQL Query for Flag 2
```


![[Pasted image 20251206183512.png]]


----

## FLAG 4

![[Pasted image 20251206190319.png]]

```
// FLAG 4
DeviceProcessEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-20) .. datetime(2025-11-26))
| where ProcessCommandLine contains "share"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
```

![[Pasted image 20251206190446.png]]


----

## FLAG 5

![[Pasted image 20251206192255.png]]

```
//FLAG 5 - Remote Share Enumeration
DeviceProcessEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-21) .. datetime(2025-11-26))
| where ProcessCommandLine contains "net.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
```

![[Pasted image 20251206192658.png]]
![[Pasted image 20251206192718.png]]


----

## FLAG 6

![[Pasted image 20251206192749.png]]

```
//FLAG 6 - Enumerate User Privilege
DeviceProcessEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-21) .. datetime(2025-11-26))
| where ProcessCommandLine contains "whoami"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
```

![[Pasted image 20251206192927.png]]

----

## FLAG 7

![[Pasted image 20251206194533.png]]

```
//FLAG 7 - Discovery - Network Configuration Command
DeviceProcessEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-21) .. datetime(2025-11-26))
| where ProcessCommandLine contains "ipconfig.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
```

![[Pasted image 20251206194708.png]]


----

## FLAG 8

![[Pasted image 20251206194736.png]]

```
//FLAG 8 - Defense Evasion - Directory Hiding Command
DeviceProcessEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-21) .. datetime(2025-11-26))
| where ProcessCommandLine contains "attrib"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine
```

![[Pasted image 20251206194840.png]]

----

## FLAG 9

![[Pasted image 20251206194916.png]]

```
Refer to Flag 8
```

----

## FLAG 10

![[Pasted image 20251206195114.png]]

![[Pasted image 20251206195100.png]]

----

## FLAG 11

![[Pasted image 20251206211055.png]]


```
//FLAG 11 - Collection - Credential File Discovery
DeviceFileEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-24))
| where FileName contains "csv"
| where FolderPath startswith @"C:\Windows\Logs\CBS"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```

![[Pasted image 20251206211108.png]]


-----

## FLAG 12

![[Pasted image 20251206211333.png]]

![[Pasted image 20251206211108.png]]

----

## FLAG 13

![[Pasted image 20251206212014.png]]

```
//FLAG 13 - Collection - Compression Command
DeviceFileEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-24))
| where FolderPath startswith @"C:\Windows\Logs\CBS"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessCommandLine
```

![[Pasted image 20251206212102.png]]


-----

## FLAG 14

![[Pasted image 20251206212244.png]]

```
Refer to Flag 13
```


![[Pasted image 20251206212214.png]]


-----

## FLAG 15

![[Pasted image 20251206212743.png]]

```
Refer to Flag 13
```

![[Pasted image 20251206212854.png]]

----

## FLAG 16

![[Pasted image 20251206220949.png]]

```
//FLAG 16: Exfiltration - Upload Command
DeviceNetworkEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-26))
| where InitiatingProcessCommandLine contains "C:\\Windows\\Logs\\CBS\\"
| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp asc
```

![[Pasted image 20251206221028.png]]
![[Pasted image 20251206221050.png]]

----

## FLAG 17

![[Pasted image 20251206223645.png]]

```
Refer to Flag 16
```

![[Pasted image 20251206221050.png]]

----

## FLAG 18

![[Pasted image 20251206223757.png]]

```
// Flag 18
DeviceRegistryEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-26))
| where ActionType == "RegistryValueSet"
| where RegistryKey contains @"HKEY_LOCAL_MACHINE\SOFTWARE"
| where RegistryKey contains "run"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

![[Pasted image 20251206223745.png]]


-----

## FLAG 19

![[Pasted image 20251206224121.png]]

```
Refer to Flag 18
```

`"reg.exe" add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v FileShareSync /t REG_SZ /d "powershell -NoP -W Hidden -File C:\Windows\System32\svchost.ps1" /f`

----

## FLAG 20

![[Pasted image 20251206224610.png]]

```
//Flag 20
DeviceFileEvents
| where DeviceName == @"azuki-fileserver01"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-26))
| where ActionType == @"FileDeleted"
| where FileName contains "txt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

![[Pasted image 20251206224640.png]]

----
# 🗂️ **Full MITRE ATT&CK Mapping Table (Flags 1–20)**

Each flag mapped to the exact ATT&CK technique used by the adversary.

------
## MITRE ATT&CK Mapping

| Time                         | **Flag #** | **Flag Title / Event**                                      | **Adversary Behavior**                                     | **MITRE Technique Name**                        | **Technique ID** | **TACTIC**                       |
| ---------------------------- | ---------- | ----------------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------------- | ---------------- | -------------------------------- |
| 2025-11-22T00:27:53.7487323Z | **1**      | Initial Suspicious Logon<br><br>` 159.26.106.98 `           | Adversary used legitimate credentials to access the system | Valid Accounts                                  | **T1078**        | Initial Access                   |
| 2025-11-19T10:22:32.2366695Z | **2**      | RDP Interactive Logon<br><br>` azuki-fileserver01 `         | Attacker used Remote Desktop Protocol to access host       | Remote Services: RDP                            | **T1021.001**    | Lateral Movement                 |
| 2025-11-19T10:22:32.2366695Z | **3**      | User Discovery<br><br>` fileadmin `                         | Attacker queried logged-in users / account context         | System Owner/User Discovery                     | **T1033**        | Discovery                        |
| 2025-11-22T00:40:54.8271951Z | **4**      | Network Configuration Discovery<br><br>` "net.exe" share `  | Used `ipconfig` to enumerate network interfaces            | System Network Configuration Discovery          | **T1016**        | Discovery                        |
| 2025-11-22T00:42:01.9579347Z | **5**      | Network Share Enumeration                                   | Enumerated file shares (`net view`, `net share`)           | Network Share Discovery                         | **T1135**        | Discovery                        |
| 2025-11-22T00:42:24.1217046Z | **6**      | Privilege Enumeration<br><br><br>` "whoami.exe" /all `      | Used `whoami /all` to review token privileges              | Permission Groups Discovery: Domain Groups      | **T1069.002**    | Discovery                        |
| 2025-11-22T00:42:46.3655894Z | **7**      | Hidden Directory for Staging<br><br>` "ipconfig.exe" /all ` | Created hidden directory with `attrib +h +s`               | Hide Artifacts: Hidden Files & Directories      | **T1564.001**    | Defense Evasion                  |
| 2025-11-22T00:55:43.9986049Z | **8**      | Tool Download via certutil                                  | Used certutil to download `ex.ps1`                         | Ingress Tool Transfer                           | **T1105**        | Command & Control                |
|                              |            |                                                             |                                                            | Signed Binary Proxy Execution: certutil         | **T1218.010**    | Defense Evasion                  |
| 2025-11-22T00:55:43.9986049Z | **9**      | Execution of Downloaded Script                              | Executed PowerShell payload                                | Command-Line Interface: PowerShell              | **T1059.001**    | Execution                        |
| 2025-11-22T00:56:47.4100711Z | **10**     | Access to Password CSV                                      | Extracted readable credentials stored in files             | Unsecured Credentials: Credentials in Files     | **T1552.001**    | Credential Access                |
| 2025-11-22T01:07:53.6746323Z | **11**     | Data Staging                                                | Staged files in `C:\Windows\Logs\CBS`                      | Data Staged (Local)                             | **T1074.001**    | Collection                       |
| 2025-11-22T01:07:53.6746323Z | **12**     | Mass File Collection (xcopy)                                | Used xcopy to recursively collect data                     | Data from Network Shares                        | **T1039**        | Collection                       |
| 2025-11-22T01:30:10.1421235Z | **13**     | Compression via tar                                         | Used tar.exe to archive staged data                        | Archive via Utility                             | **T1560.001**    | Collection                       |
| 2025-11-22T02:03:19.9845969Z | **14**     | Credential Dump Tool Renamed                                | Renamed Mimikatz-like tool (`pd.exe`)                      | Masquerading: Match Legitimate Name or Location | **T1036.005**    | Defense Evasion                  |
| 2025-11-22T02:24:47.6967458Z | **15**     | LSASS Memory Dump                                           | Dumped LSASS to extract credentials                        | OS Credential Dumping: LSASS Memory             | **T1003.001**    | Credential Access                |
| 2025-11-22T01:59:54.4790127Z | **16**     | Data Exfiltration via curl                                  | Uploaded archive using curl with `-F`                      | Exfiltration to Cloud Storage                   | **T1567.002**    | Exfiltration                     |
| 2025-11-22T01:59:54.4790127Z | **17**     | Cloud Service Used                                          | Exfiltration occurred to file.io                           | Exfiltration to Cloud Storage                   | **T1567.002**    | Exfiltration                     |
| 2025-11-22T02:10:50.8253766Z | **18**     | Registry Persistence                                        | Added Run key value `FileShareSync`                        | Boot or Logon Autostart: Registry Run Keys      | **T1547.001**    | Persistence                      |
| 2025-11-22T02:10:50.8253766Z | **19**     | Beacon Masquerading                                         | Persistence script disguised as `svchost.ps1`              | Masquerading: Match Legitimate Name or Location | **T1036.005**    | Defense Evasion                  |
| 2025-11-22T02:26:01.1661095Z | **20**     | PowerShell History Deletion                                 | Removed `ConsoleHost_history.txt` to erase traces          | Indicator Removal: Clear Command History        | **T1070.003**    | Defense Evasion / Anti-Forensics |

------

## Recommended Mitigations (Practical, Prioritized)

**1. Lock down RDP and admin access**
- Move RDP behind VPN/jump host; no direct internet RDP.
- Limit which hosts admins can RDP into.
- Enforce **MFA** for all privileged accounts.

**2. Hardening against LOLBins & PowerShell abuse**
- AppLocker/WDAC to:
    - Block `certutil.exe`, `curl.exe`, `tar.exe` for non-system processes or non-admins.
    - Block execution from `C:\Windows\Logs\CBS\` and other log paths.
- Enable:
    - PowerShell **Constrained Language Mode** for non-admins.
    - Script Block Logging & Transcription.
- Detections for:
    - `powershell.exe` with `-NoP`, `-W Hidden`, or from unusual paths.
    - Execution of `svchost.ps1` or any `.ps1` from `System32`.

**3. Detection content (what you just hunted, turned into rules)**

Create SIEM/EDR alerts for:
- **RDP + privilege combo**
    - Remote Interactive logons from external IPs or from unusual internal sources.

- **Suspicious discovery**
    - `net.exe share`, `net.exe view \\*`, `whoami.exe /all`, `ipconfig.exe /all` issued in tight sequence.
    
- **Staging and archiving**
    - `xcopy` or `robocopy` copying from `C:\FileShares\*` into OS directories.
    - `tar.exe` or other archivists writing into `C:\Windows\Logs\CBS\` or temp paths.
    
- **Credential dumping**
    - Creation of `lsass.dmp` or handle access to LSASS by non-system processes.
    - Execution of known dump tools, renamed or not (hash & behaviour-based).

- **Exfiltration**
    - `curl.exe` or browsers uploading to `file.io`, `pastebin`, etc.
    - Unusual large outbound transfers to new domains.

- **Persistence**
    - New `Run` key values with PowerShell commands.
    - Scripts created under `System32` that are not signed or part of baseline.

**4. Fix sensitive data handling**

- Eliminate or tightly control files like `IT-Admin-Passwords.csv`.
    - Replace with a password vault (e.g., PAM solution).
    - If CSVs must exist, keep them encrypted and accessible only via vault tooling.

**5. User & admin training**
- Admins should recognize that storing plaintext passwords and doing ad-hoc PowerShell on production servers increases blast radius.
- Training to report unusual RDP prompts, slow sessions, or unexplained new files.

------

## Lessons Learned

Short version: the attacker did nothing magical. They rode on:

- **Valid credentials**,
- **Standard Windows binaries**, and
- **Predictable human shortcuts** (password CSVs, broad RDP, no egress control).

Key takeaways:

1. **Access is everything.**  
    Once `fileadmin` was compromised, the rest was just typing. JIT admin, strong auth, and segmented access would have turned this from a full compromise into a noisy failed attempt.

2. **LOLBins are still living off the land.**  
    `certutil`, `net`, `tar`, `curl`, `reg`, `attrib`—none of them are inherently evil, but their _patterns of usage_ scream attacker. Your detections should focus on _how_ they are used, not just _if_ they run.

3. **Data staging is a giant red flag.**  
    Copying whole shares into a hidden directory under `C:\Windows\Logs\CBS` is not something a legitimate admin should be doing casually. Baseline “normal” for your servers and flag when someone drags an entire department’s worth of data into a log folder.

4. **Cloud exfil is the new USB stick.**  
    Anonymous services like file.io are cheap exfil channels. Treat outbound traffic to these as high-severity until proven otherwise.

5. **Persistence & anti-forensics leave fingerprints.**  
    A new `Run` key pointing at hidden PowerShell, plus deletion of `ConsoleHost_history.txt`, is classic “I’m coming back later, and I don’t want you to know what I did.” These should be high-priority alerts, not curiosities.

6. **Your hunt logic is reusable.**  
    The KQL you wrote for each flag can be turned into:
    - Always-on detections, and
    - Hunt playbooks for other servers.  
