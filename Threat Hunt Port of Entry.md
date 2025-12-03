
# 🛡️ Threat Hunt Report

**Operation:** _Port of Entry_  
**Environment:** Josh Madakor Cyber Range  - Microsoft Azure
**Analyst:** Grisham DelRosario
**Date:** November 22nd-23rd, 2025

-----
# 🧩 Executive Summary

Between November 19–20, 2025, a threat actor gained unauthorized access to the workstation **azuki-sl** via a compromised RDP credential. The attacker conducted network reconnaissance, disabled security controls, staged malware, dumped credentials using Mimikatz, created persistence mechanisms, archived sensitive data, exfiltrated it to **Discord**, and attempted lateral movement to **10.1.0.188**.

This was a **hands-on-keyboard intrusion** leveraging “living off the land” binaries (LOLBins), showing sophistication and intentional anti-forensic behavior. The attacker used renamed binaries, scheduled tasks, and cloud exfiltration channels to remain stealthy and minimize detection.

The following report outlines the **attack chain**, **MITRE ATT&CK mapping**, **timeline**, **indicators**, **recommendations**, and **lessons learned**.

-----
# 🛠️ Attack Chain Overview (Kill Chain)

| **Phase**                | **Description**                                              |
| ------------------------ | ------------------------------------------------------------ |
| **Initial Access**       | Attacker logged in over RDP using stolen credentials.        |
| **Discovery**            | Performed ARP-based host discovery.                          |
| **Execution**            | Executed malicious PowerShell script (`wupdate.ps1`).        |
| **Persistence**          | Created scheduled task + backdoor admin account.             |
| **Privilege Escalation** | Used SeDebugPrivilege to access LSASS.                       |
| **Defense Evasion**      | Modified Defender exclusions, hid directories, cleared logs. |
| **Credential Access**    | Dumped credentials using Mimikatz (`mm.exe`).                |
| **Collection**           | Archived stolen data (`export-data.zip`).                    |
| **Exfiltration**         | Uploaded archive to Discord (encrypted HTTPS).               |
| **Command & Control**    | Communication with C2 at `78.141.196.6:443`.                 |
| **Lateral Movement**     | Attempted to RDP into `10.1.0.188` using `mstsc.exe`         |

---------

<img width="786" height="729" alt="image" src="https://github.com/user-attachments/assets/f8a54c56-3420-444c-aaa3-d95575837f10" />

----
# FLAG 1

<img width="814" height="836" alt="image" src="https://github.com/user-attachments/assets/cad80f6b-c072-4564-bcab-fdbae51a5f7c" />



KQL Query Used

**Query 1 - Initial Access: Remote Access Source**

```
//Flag 1
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where RemoteIP == @"88.97.178.12"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, ActionType, LogonType, AccountDomain, AccountName, Protocol, RemoteDeviceName, RemoteIP, RemotePort
```

**Results:** ________________

Upon looking the logs and the `ActionType` column there was a particular activity that showed `LogonSuccess` and the protocol for this logon was `Negotiate` this particular protocol is normal to RDP process where `a client and server exchange information to determine the most secure security method for their connection.` This stood out for the IP address, `88.97.178.12`. 


**Screenshot:** 

<img width="1682" height="228" alt="Pasted image 20251122162436" src="https://github.com/user-attachments/assets/065c9892-dc60-4ca4-95de-cc23b2791a6e" />


-----

# FLAG 2

<img width="631" height="559" alt="Pasted image 20251122164202" src="https://github.com/user-attachments/assets/403ebd7b-4699-4164-9996-09b37aba95f6" />


KQL Query Used

**Query 2 - Initial Access: Compromised User Account**

```
//Flag 2
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where AccountName == @"kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, ActionType, LogonType, AccountDomain, AccountName, Protocol, RemoteDeviceName, RemoteIP, RemotePort
```

**Results:**

```
Based on the results from the Flag 1, the information was logs was very noticeable 
```


**Screenshot:** 

<img width="1682" height="228" alt="Pasted image 20251122164509" src="https://github.com/user-attachments/assets/f4718bf5-b688-4327-acc0-b863317a23c4" />



---

# FLAG 3

![[Pasted image 20251122165602.png]]

KQL Query Used

**Query 3 - Initial Access: Compromised User Account**

```
//Flag 3
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName == @"kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
the process `arp.exe` was executed with the argument `-a`, indicating that the attacker enumerated the ARP cache to identify local network neighbors. This action reveals IP-to-MAC address mappings for recently communicated hosts, enabling an adversary to map accessible systems for potential lateral movement. The execution of `arp.exe -a` immediately followed other reconnaissance commands (`ipconfig.exe /all`, `hostname.exe`, `whoami.exe`), consistent with **MITRE ATT&CK T1016: System Network Configuration Discovery**. This behavior strongly suggests post-compromise network reconnaissance.
```



**Screenshot:** ☐ Attached

![[Pasted image 20251122165501.png]]

![[Pasted image 20251122170132.png]]

-----
# FLAG 4

![[Pasted image 20251122181530.png]]

KQL Query Used

**Query 4 - Defence Evasion - Malware Staging Directory**

```
//Flag 4

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName == @"kenji.sato"
| where ProcessCommandLine contains "attrib"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The directory `C:\ProgramData\WindowsCache` was identified as the primary malware staging location because it does not normally exist within a standard Windows installation, was created during the intrusion window, and was subsequently modified using `attrib` to hide its presence. Multiple malicious binaries—including the scheduled task payload—were written to this directory, confirming it as the central location where the attacker stored and executed their tools.
```



**Screenshot:** ☐ Attached

![[Pasted image 20251122181806.png]]


# FLAG 5

![[Pasted image 20251122221300.png]]

KQL Query Used

**Query 5 - Defence Evasion - File Extension Exclusions**

```
//Flag 5

DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where ActionType in ("RegistryValueSet", "RegistryValueCreated", "RegistryKeyCreated")
| where RegistryKey has_any (
    @"\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
    @"\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions"
)
| project Timestamp, ActionType, RegistryKey, RegistryValueName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
| count
```

**Results:**

```
During the attack, the adversary modified the Windows Defender exclusion policy by adding three new file extension exclusions under the `Windows Defender\Exclusions\Extensions` registry key. These modifications effectively blinded Defender from scanning malicious files using those extensions. This technique aligns with MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools). The intentional addition of three extensions indicates that the attacker relied on specific file types for payload staging, malware execution, and evasion, reflecting a structured and deliberate defense-evasion strategy.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251122221214.png]]

Results without the `| count`

![[Pasted image 20251122223719.png]]

----
# FLAG 6

![[Pasted image 20251122224317.png]]


KQL Query Used

**Query 6 - Defence Evasion - Temporary Folder Exclusion**

```
//FLAG 6
DeviceRegistryEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where RegistryKey contains "Windows Defender\\Exclusions\\Paths"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Results:**

```
The attacker added a Windows Defender path exclusion for the directory `C:\Users\KENJI~1.SAT\AppData\Local\Temp`, effectively preventing antivirus scanning within the user’s Temp folder. This allowed the adversary to download, store, and execute malicious files without detection. The use of the short-path 8.3 naming format (`KENJI~1`) is intentional and indicates an effort to avoid detection rules and ensure compatibility with LOLBins and scripted payloads. This technique aligns with MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools), and confirms active defense evasion during the intrusion.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251122225102.png]]

----
# FLAG 7



![[Pasted image 20251122232354.png]]


KQL Query Used

**Query 7 - Defence Evasion - Download Utility Abuse**

```
//FLAG 7
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountDomain == @"azuki-sl"
| where ProcessCommandLine contains ".exe"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The attacker abused the built-in Windows tool `certutil.exe` to download malicious payloads to the system. Because `certutil.exe` is a trusted, signed Microsoft binary with native network and file-writing capabilities, it is frequently leveraged in Living-Off-The-Land (LOLBIN) attacks to evade antivirus detection. Its presence in the attack timeline with URL parameters strongly indicates deliberate defense evasion and ingress tool transfer. This behavior maps to MITRE ATT&CK T1105 (Ingress Tool Transfer) and T1218 (Signed Binary Proxy Execution).
```


**Screenshot:** ☐ Attached

![[Pasted image 20251122232306.png]]


----

# FLAG 8

![[Pasted image 20251122232634.png]]

**Query 8 - Persistence - Scheduled Task Name**

```
//FLAG 8
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountDomain == @"azuki-sl"
| where ProcessCommandLine contains "schtasks.exe"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The attacker created a scheduled task named “Windows Update Check” to establish persistence on the compromised host. This name was deliberately chosen to mimic legitimate Windows maintenance tasks, reducing the likelihood of detection. The task was created using `schtasks.exe /create` and configured to execute the malicious payload stored in `C:\ProgramData\WindowsCache\svchost.exe` upon a defined schedule. This technique aligns with MITRE ATT&CK T1053.005 (Scheduled Task) and demonstrates the attacker’s intent to maintain long-term access through stealthy and reliable post-compromise persistence.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251122233041.png]]


----

# FLAG 9

![[Pasted image 20251122235110.png]]

**Query 9 - Persistence - Scheduled Task Target**

```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountDomain == @"azuki-sl"
| where ProcessCommandLine contains ".exe"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The scheduled task was configured to execute a malicious binary located at `C:\ProgramData\WindowsCache\svchost.exe`. Although named after a legitimate Windows system process, this file resides outside any legitimate system directory, indicating deliberate masquerading. The attacker placed the payload within a hidden staging folder (`WindowsCache`) under ProgramData and used a scheduled task to ensure consistent persistence across reboots. This behavior aligns with MITRE ATT&CK T1036 (Masquerading) and T1053.005 (Scheduled Task), highlighting a stealthy, persistent access mechanism within the compromised environment.
```


**Screenshot:** ☐ Attached

----

# FLAG 10

![[Pasted image 20251123000138.png]]

**Query 10 - Command & Control - C2 Server Address**

```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountDomain == @"azuki-sl"
| where ProcessCommandLine contains ".exe"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The command-and-control (C2) server contacted by the malicious payload was `78.141.196.6`. This external IP address was identified in `DeviceProcessEvents` as the destination for outbound HTTPS traffic initiated by the malicious `svchost.exe` executable immediately after it was staged and executed. Communication occurred over TCP port 443, indicating an attempt to blend malicious C2 traffic with legitimate encrypted web traffic. This behavior aligns with MITRE ATT&CK T1071 (Application Layer Protocol) and provides a clear indicator of the attacker’s remote control infrastructure.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123113508.png]]

----

# FLAG 11

![[Pasted image 20251123000203.png]]

**Query 11 - Command & Control - C2 Communication Port**

```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where RemoteIP == @"78.141.196.6"
```

**Results:**

```
The attacker used TCP port 443 for command-and-control communication. This port is commonly associated with HTTPS traffic, allowing the adversary to blend their C2 traffic with legitimate encrypted web traffic. By routing malware communications through port 443, the attacker evaded basic firewall rules, avoided network inspection, and leveraged encryption to conceal commands and exfiltrated data. This activity aligns with MITRE ATT&CK T1071.001 (Web Protocols) and demonstrates the attacker’s intent to remain stealthy during remote control operations.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123113508.png]]


----

# FLAG 12

![[Pasted image 20251123124433.png]]

**Query 12 - Credential Access = Credential Theft Tool**

```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountDomain == @"azuki-sl"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, FolderPath, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The credential dumping tool used by the attacker was a renamed executable identified as `mm.exe`. This binary appeared in the malicious staging directory shortly before LSASS memory access events and was executed with elevated privileges. The filename’s minimal form strongly indicates an attempt to evade signature-based detection of known tools such as Mimikatz. Its execution correlates directly with subsequent logon password extraction activity, confirming its role as the credential theft mechanism. This aligns with MITRE ATT&CK T1003 (OS Credential Dumping) and demonstrates deliberate obfuscation and defense evasion by the attacker.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123124959.png]]

----

# FLAG 13

![[Pasted image 20251123125226.png]]


**Query 13 - Credential Access - Memory Extraction Module**

```
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountDomain == @"azuki-sl"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, FolderPath, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The attacker executed the Mimikatz module `sekurlsa::logonpasswords` using a renamed credential dumping binary (`mm.exe`). This module accesses LSASS memory to extract logon credentials including NTLM hashes, cleartext passwords (when available), Kerberos tickets, and token information. The command-line usage (`privilege::debug sekurlsa::logonpasswords exit`) confirms that the attacker escalated privileges to obtain SeDebugPrivilege and executed the module with precision. This behavior corresponds to MITRE ATT&CK T1003.001 (LSASS Memory) and represents the point at which the adversary gained the ability to perform lateral movement and escalate access across the environment.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123125343.png]]


----

# FLAG 14

![[Pasted image 20251123125811.png]]


**Query 14 - Collection - Data Staging Archive**

```
//FLAG 14
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountName == @"kenji.sato"
| where ProcessCommandLine contains ".zip"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, FolderPath, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The attacker created a ZIP archive named `export-data.zip` to package stolen files prior to exfiltration. The archive appeared within the staging directory used by the attacker and was generated shortly before outbound data transfers to the C2 server. Using ZIP compression is a common technique to combine multiple files, reduce size, and mask malicious content. This activity aligns with MITRE ATT&CK T1560 (Archive Collected Data) and represents the transition between the Collection and Exfiltration phases of the intrusion.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123125952.png]]


---
# FLAG 15

![[Pasted image 20251123130649.png]]


**Query 15 - Exfiltration - Exfiltration Channel**

```
//FLAG 15
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where RemotePort == "443"
| project Timestamp, DeviceName, ActionType, RemoteIP, InitiatingProcessFileName, Protocol, RemoteUrl, RemotePort
```

**Results:**

```
The attacker used Discord as the exfiltration channel, leveraging its file upload capabilities and globally distributed content delivery network (CDN). DeviceNetworkEvents showed outbound HTTPS connections to Discord domains immediately after the creation of `export-data.zip`, confirming the file was uploaded to Discord’s infrastructure. Using Discord provides attackers with encrypted transmission, benign-looking traffic, and persistent cloud storage, making it an effective and stealthy exfiltration method. This behavior aligns with MITRE ATT&CK T1567.002 (Exfiltration to Cloud Storage).
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123130817.png]]


----

# FLAG 16

![[Pasted image 20251123133232.png]]


**Query 16 - Anti-Forensics - Log Tampering**

```
//FLAG 16
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountName == @"kenji.sato"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, FolderPath, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The attacker cleared the Windows Security event log using `wevtutil.exe`, indicating a deliberate attempt to remove forensic evidence and impede incident investigation. The Security log contains critical entries such as authentication events, privilege escalation, and process creation, making it the primary log defenders rely on to reconstruct an intrusion timeline. Clearing this log first demonstrates the attacker’s sophistication and understanding of Windows logging mechanisms. This behavior aligns with MITRE ATT&CK T1070.001 (Clear Windows Event Logs) and signifies intentional anti-forensic activity near the end of the attack sequence.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123133620.png]]


----

# FLAG 17


![[Pasted image 20251123134403.png]]

**Query 17 - IMPACT - Persistence Account**

```
//FLAG 17
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where AccountName == @"kenji.sato"
| where ProcessCommandLine contains "/add"
| project Timestamp, DeviceName, ActionType, AccountDomain, AccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, FolderPath, ProcessId, ProcessVersionInfoInternalFileName, ProcessVersionInfoOriginalFileName
```

**Results:**

```
The attacker created a backdoor user account named `support` using the `net user /add` command, followed by adding the account to the local Administrators group. This provided the adversary with an alternative method of privileged access that persists independently of malware or scheduled task mechanisms. The use of a benign-sounding name such as “support” helps conceal the account within legitimate system user lists. This activity aligns with MITRE ATT&CK T1136.001 (Create Account: Local Account) and T1098 (Account Manipulation), and represents a deliberate attempt to maintain long-term access even if other components of the intrusion are remediated.
```


**Screenshot:** ☐ Attached


![[Pasted image 20251123134643.png]]



----

# FLAG 18

![[Pasted image 20251123140318.png]]


**Query 18 - EXECUTION - Malicious Script**

```
//FLAG 18
DeviceFileEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| where InitiatingProcessFileName == @"powershell.exe"
| where FileName contains ".ps1"\
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFolderPath, InitiatingProcessFileName, FileSize
```

**Results:**

```
The attacker utilized a malicious PowerShell script named `wupdate.ps1` to automate key stages of the intrusion. The filename imitates legitimate Windows Update activity, enabling the script to blend into common administrative workflows. Analysis of DeviceFileEvents and DeviceProcessEvents indicates that this script was created and executed shortly after initial access, serving as an automation mechanism for actions such as malware staging, defender evasion, payload execution, and preparation for data exfiltration. This behavior aligns with MITRE ATT&CK T1059.001 (PowerShell) and T1036 (Masquerading).
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123140543.png]]


----

# FLAG 19

![[Pasted image 20251123141926.png]]

**Query 19 - LATERAL MOVEMENT - Secondary Target**

```
//FLAG 19 / 20
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LocalIP, LocalIPType, InitiatingProcessCommandLine, InitiatingProcessFileName, Protocol, RemoteUrl, RemotePort
```

**Results:**

```
**The attacker attempted lateral movement to the internal system at `10.1.0.188`. DeviceNetworkEvents showed outbound network connections from the compromised host (`azuki-sl`) to this IP shortly after credential dumping activity, indicating the attacker was using stolen credentials or authentication material to expand their access. This behavior aligns with MITRE ATT&CK T1021 (Remote Services) and T1550 (Use of Alternate Authentication Material), and marks the transition from a single-host compromise to an attempted multi-host intrusion within the network.**
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123142240.png]]

----

# FLAG 20

![[Pasted image 20251123141949.png]]

**Query 20 - LATERAL MOVEMENT - Remote Access Tool**

```
//FLAG 19 / 20
DeviceNetworkEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == @"azuki-sl"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LocalIP, LocalIPType, InitiatingProcessCommandLine, InitiatingProcessFileName, Protocol, RemoteUrl, RemotePort
```

**Results:**

```
The attacker used `mstsc.exe`, the native Windows Remote Desktop client, to initiate lateral movement toward the internal system at `10.1.0.188`. This technique leverages a legitimate administrative tool to blend malicious activity with normal network behavior, making detection more difficult. The use of RDP following credential dumping indicates the attacker attempted to use stolen authentication material to expand access across the environment. This activity aligns with MITRE ATT&CK T1021.001 (Remote Services: Remote Desktop Protocol) and demonstrates hands-on-keyboard lateral movement by the adversary.
```


**Screenshot:** ☐ Attached

![[Pasted image 20251123142248.png]]


-----

# 🗂️ **Full MITRE ATT&CK Mapping Table (Flags 1–20)**

Each flag mapped to the exact ATT&CK technique used by the adversary.

---

## **MITRE ATT&CK Framework Mapping Table**

| Time | **Flag #** | **Stage**                   | **Action Identified**                           | **MITRE Technique**                      | **ID**      |
| ---- | ---------- | --------------------------- | ----------------------------------------------- | ---------------------------------------- | ----------- |
|      | **1**      | Initial Access              | RDP login from external IP                      | Valid Accounts: Remote Services          | `T1078.002` |
|      | **2**      | Initial Access              | Compromised user account (`kenji.sato`)         | Valid Accounts                           | `T1078`     |
|      | **3**      | Discovery                   | ARP sweep (`arp.exe -a`)                        | System Network Configuration Discovery   | `T1016`     |
|      | **4**      | Defense Evasion             | Hidden malware staging directory                | Hide Artifacts                           | `T1564`     |
|      | **5**      | Defense Evasion             | File extension exclusions added to Defender     | Impair Defenses: Disable or Modify Tools | `T1562.001` |
|      | **6**      | Defense Evasion             | Folder (Temp) exclusion created                 | Indicator Blocking / Impair Defenses     | `T1562.006` |
|      | **7**      | Execution / Defense Evasion | `certutil.exe` used to download malware         | Signed Binary Proxy Execution (LOLBIN)   | `T1218`     |
|      | **8**      | Persistence                 | Scheduled Task created                          | Scheduled Task                           | `T1053.005` |
|      | **9**      | Persistence                 | Malicious payload executed via Scheduled Task   | Scheduled Task / Execution               | `T1053.005` |
|      | **10**     | C2                          | External C2 server (`78.141.196.6`)             | Application Layer Protocol (HTTPS)       | `T1071.001` |
|      | **11**     | C2                          | C2 communication over port 443                  | Encrypted Channel / Web Protocol         | `T1071.001` |
|      | **12**     | Credential Access           | Credential dumping tool (`mm.exe`)              | OS Credential Dumping                    | `T1003`     |
|      | **13**     | Credential Access           | LSASS extraction via `sekurlsa::logonpasswords` | Credential Dumping: LSASS                | `T1003.001` |
|      | **14**     | Collection                  | Stolen data archived (`export-data.zip`)        | Archive Collected Data                   | `T1560`     |
|      | **15**     | Exfiltration                | Data uploaded via Discord CDN                   | Exfiltration to Cloud Storage            | `T1567.002` |
|      | **16**     | Anti-Forensics              | Security Log cleared                            | Clear Windows Event Logs                 | `T1070.001` |
|      | **17**     | Impact / Persistence        | Backdoor account (`support`) created            | Create Account (Local)                   | `T1136.001` |
|      | **18**     | Execution                   | Malicious PowerShell script (`wupdate.ps1`)     | PowerShell                               | `T1059.001` |
|      | **19**     | Lateral Movement            | Lateral movement target (`10.1.0.188`)          | Remote Services                          | `T1021`     |
|      | **20**     | Lateral Movement            | `mstsc.exe` used for RDP pivot                  | Remote Services: RDP                     | `T1021.001` |

----

# 🔍 Indicators of Compromise (IoCs)

### **Network**

- `88.97.178.12` – RDP intrusion source
    
- `78.141.196.6:443` – C2 server
    
- Discord CDN domains (exfil)
    
### **Files**

- `C:\ProgramData\WindowsCache\svchost.exe`
    
- `C:\ProgramData\WindowsCache\mm.exe`
    
- `wupdate.ps1`
    
- `export-data.zip`

### **Persistence**

- Backdoor user: `support`
    
- Scheduled task: `Windows Update Check`
    

---

# 📘 Lessons Learned

1. **Credentials are keys to the kingdom.**  
    One leaked password gave the attacker full interactive access.
    
2. **Logs must be centralized.**  
    Once logs were cleared locally, only external log collectors could save evidence.
    
3. **Cloud exfiltration is now standard.**  
    Discord, Slack, and Telegram are the new exfiltration channels.
    
4. **Living-Off-The-Land tools are dangerous.**  
    Every stage of this attack used built-in Windows binaries.
    
5. **Lateral movement attempts define attacker intent.**  
    Pivot to `10.1.0.188` shows this wasn’t random — it was targeted.
    

---

# 🔒 Mitigation Recommendations

## **Identity Security**

- Enforce MFA for RDP (non-negotiable)
    
- Disable public RDP entirely
    
- Rotate passwords & local admin accounts
    
- Enforce LAPS
    

## **Endpoint Hardening**

- Enable Credential Guard + RunAsPPL
    
- Disable WDigest
    
- Restrict PowerShell → Constrained Language Mode
    
- Enforce AppLocker/WDAC to block LOLBins
    

## **Network Controls**

- Block Discord CDN and similar exfil channels
    
- Restrict outbound egress (deny by default)
    
- Monitor abnormal port 443 destinations
    

## **Monitoring & Logging**

- Forward all logs to SIEM
    
- Enable:
    
    - PowerShell Operational logging
        
    - Task Scheduler logging
        
    - Sysmon
        
- Alert on:
    
    - New local accounts
        
    - Defender exclusions
        
    - Scheduled tasks
        
    - LSASS access
        
    - Log clearing
        

## **Incident Preparedness**

- Maintain offline backups
    
- Run quarterly tabletop IR exercises
    
- Maintain and test IR runbooks

------

Color coded by severity of impact:

- 🔴 **Critical** — Credential Access, Lateral Movement, Exfiltration
    
- 🟠 **High** — Persistence, Priv Esc, C2
    
- 🟡 **Medium** — Discovery, Defense Evasion
    
- 🟢 **Low** — Benign/Noise-level activity

| Flag | Technique                              | ID        | Severity |
| ---- | -------------------------------------- | --------- | -------- |
| 1    | Valid Accounts: Remote Services        | T1078.002 | 🔴       |
| 2    | Valid Accounts                         | T1078     | 🔴       |
| 3    | System Network Configuration Discovery | T1016     | 🟡       |
| 4    | Hide Artifacts                         | T1564     | 🟡       |
| 5    | Impair Defenses                        | T1562.001 | 🟠       |
| 6    | Indicator Blocking                     | T1562.006 | 🟠       |
| 7    | Signed Binary Proxy Execution          | T1218     | 🟡       |
| 8    | Scheduled Task/Job                     | T1053.005 | 🟠       |
| 9    | Scheduled Task Execution               | T1053.005 | 🟠       |
| 10   | Application Layer Protocol (HTTPS)     | T1071.001 | 🟠       |
| 11   | Encrypted Channel                      | T1071.001 | 🟠       |
| 12   | OS Credential Dumping                  | T1003     | 🔴       |
| 13   | LSASS Credential Dumping               | T1003.001 | 🔴       |
| 14   | Archive Collected Data                 | T1560     | 🟠       |
| 15   | Exfiltration to Cloud Storage          | T1567.002 | 🔴       |
| 16   | Clear Windows Event Logs               | T1070.001 | 🟠       |
| 17   | Create Account (Local)                 | T1136.001 | 🟠       |
| 18   | PowerShell Execution                   | T1059.001 | 🟠       |
| 19   | Remote Services                        | T1021     | 🔴       |
| 20   | RDP Lateral Movement                   | T1021.001 | 🔴       |

