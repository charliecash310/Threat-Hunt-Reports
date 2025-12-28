# 🛡️ Threat Hunt Report

**Incident Name:** Bridge Takeover  
**Framework Alignment:** NIST SP 800-53  
**Environment:** Windows Endpoint (azuki-adminpc)  
**Date of Activity:** Nov 24, 2025  
**Prepared by:** Grisham DelRosario  
**Confidence Level:** High (Endpoint + Network Telemetry Correlated)

---------

## 🧩Executive Summary

The **Bridge Takeover** incident represents a **full-spectrum intrusion** that progressed from **credential compromise** to **lateral movement**, **persistent C2 access**, **privilege escalation**, **credential harvesting**, **data staging**, and **successful exfiltration** to a cloud-based storage provider.

The adversary demonstrated:

- Strong **living-off-the-land** tradecraft
- Credential reuse and privilege chaining
- Deliberate staging and compression of sensitive financial and credential data
- Multiple fallback persistence mechanisms
- Cloud-based exfiltration designed to bypass domain-based controls

The attack was **methodical, deliberate, and quiet**—not smash-and-grab, but surgical theft.

<img width="608" height="431" alt="image" src="https://github.com/user-attachments/assets/4a0a56a4-5d6d-41fd-8dbc-91265cf6d0c6" />

---------
## 🛠️ **Attack Chain Overview (Kill Chain)**

| **Phase**                              | **Description**                                                                                                                                    |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Initial Access**                     | Attacker authenticated to **azuki-adminpc** using **valid credentials** (`yuki.tanaka`) via RemoteInteractive logon, bypassing perimeter defenses. |
| **Lateral Movement**                   | Compromised credentials reused from source host **10.1.0.204** to access the high-value administrative workstation **azuki-adminpc**.              |
| **Execution**                          | Downloaded malicious payload using **curl.exe** from external hosting service **litter.catbox.moe**, masquerading as a Windows update archive.     |
| **Execution (Extraction)**             | Extracted password-protected archive using **7z.exe**, evading basic inspection and application allowlisting controls.                             |
| **Persistence**                        | Deployed **Meterpreter-based C2 implant (meterpreter.exe)** and established IPC using a malicious named pipe **\Device\NamedPipe\msf-pipe-5902**.  |
| **Privilege Escalation**               | Executed Base64-encoded PowerShell commands to create backdoor account **yuki.tanaka2** and added it to the **local Administrators** group.        |
| **Discovery (Sessions)**               | Enumerated active RDP sessions using **qwinsta.exe** to identify logged-on users and avoid detection.                                              |
| **Discovery (Trusts)**                 | Enumerated domain trust relationships using **nltest /domain_trusts /all_trusts** to assess lateral movement paths.                                |
| **Discovery (Network)**                | Enumerated active network connections and owning processes using **netstat -ano**.                                                                 |
| **Credential Access (Files)**          | Searched for password databases using *_where /r C:\Users _.kdbx__ and discovered plaintext credential file **OLD-Passwords.txt**.                 |
| **Credential Access (Browser)**        | Extracted Chrome browser credentials using **m.exe** with **DPAPI decryption** against the Chrome Login Data database.                             |
| **Credential Access (Password Store)** | Extracted KeePass master password, writing sensitive output to **KeePass-Master-Password.txt**.                                                    |
| **Collection (Staging)**               | Created masqueraded staging directory **C:\ProgramData\Microsoft\Crypto\staging** to organize stolen data.                                         |
| **Collection (Automation)**            | Used **robocopy.exe** with retry logic to copy financial and banking documents into the staging directory.                                         |
| **Collection (Archiving)**             | Compressed collected data into **8 distinct archives** (`.zip`, `.tar.gz`) using **tar.exe** and compression tooling.                              |
| **Exfiltration**                       | Exfiltrated archives via HTTPS POST requests using **curl.exe** to anonymous cloud storage **gofile.io**.                                          |
| **Exfiltration (Destination)**         | Data transferred to cloud infrastructure endpoint **45.112.123.227** over TCP/443, blending with normal web traffic.                               |
| **Anti-Forensics**                     | Deleted **ConsoleHost_history.txt** to remove traces of PowerShell command execution.                                                              |
| **Command & Control**                  | Maintained interactive control via **Meterpreter C2**, using named pipes and outbound HTTPS traffic for covert communication.                      |

-----------
## FLAG 1

<img width="632" height="527" alt="image" src="https://github.com/user-attachments/assets/b5fb915d-43af-4fc6-bee9-002ab585efb6" />



```
// FLAG 1: Lateral Movement - Source System
DeviceLogonEvents
| where DeviceName contains "azuki"
| where LogonType == @"RemoteInteractive"
| project Timestamp, DeviceName, ActionType, LogonType, AccountDomain, AccountName, Protocol, LogonId, InitiatingProcessAccountDomain, RemoteIP
```

Results: 

2025-11-25T04:06:52.7572947Z

<img width="1845" height="643" alt="image" src="https://github.com/user-attachments/assets/8b50bf91-9b33-464c-a5b0-83ad22dfa84b" />



-------

## FLAG 2

<img width="630" height="525" alt="image" src="https://github.com/user-attachments/assets/480e74c1-d88a-47d4-ba2d-1d64a1d62ff8" />


```
// FLAG 2: Lateral Movement - Source System
DeviceLogonEvents
| where DeviceName contains "azuki"
| where LogonType == @"RemoteInteractive"
| project Timestamp, DeviceName, ActionType, LogonType, AccountDomain, AccountName, Protocol, LogonId, InitiatingProcessAccountDomain, RemoteIP
```

Results:

<img width="460" height="322" alt="image" src="https://github.com/user-attachments/assets/5d32d1e2-b482-45d1-8241-5767be095bff" />



-------

## FLAG 3

<img width="631" height="525" alt="image" src="https://github.com/user-attachments/assets/673425be-5470-45c0-93d5-6d969ae21396" />


```
// FLAG 3: Lateral Movement - Target Device
DeviceLogonEvents
| where DeviceName contains "azuki"
| where LogonType == @"RemoteInteractive"
| project Timestamp, DeviceName, ActionType, LogonType, AccountDomain, AccountName, Protocol, LogonId, InitiatingProcessAccountDomain, RemoteIP
```


Results:

<img width="460" height="322" alt="image" src="https://github.com/user-attachments/assets/99123aa9-ea51-443e-86e6-3f5e67c24d28" />



-------

## FLAG 4

<img width="626" height="531" alt="image" src="https://github.com/user-attachments/assets/0bec7712-78b4-4c17-b5ba-6868f5c998fe" />


```
//FLAG 4: Execution - Payload Hosting Service
DeviceNetworkEvents
| where DeviceName contains "azuki"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, LocalIP, LocalPort, Protocol, LocalIPType, RemoteIPType

```

2025-11-25T04:21:12.0783558Z

<img width="2251" height="392" alt="image" src="https://github.com/user-attachments/assets/79b32121-3f10-4374-a423-d7932379b947" />



-------

## FLAG 5

<img width="631" height="558" alt="image" src="https://github.com/user-attachments/assets/264cc493-59d4-4582-976b-1adfaac401c6" />


```
//FLAG 5: Malware Download Command
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "KB"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine, ProcessCommandLine, FolderPath, FileSize
```


Results:

2025-11-25T04:21:11.7917432Z

<img width="1623" height="334" alt="image" src="https://github.com/user-attachments/assets/20871783-4cfe-4461-b720-707c9ed1957e" />


--------

## FLAG 6

<img width="628" height="530" alt="image" src="https://github.com/user-attachments/assets/3ac59788-e36d-4a39-84df-0f88a60956f3" />


```
//FLAG 6: Execution - Archive Extraction Command
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "KB"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine, ProcessCommandLine, FolderPath, FileSize
```

Results:

2025-11-25T04:21:32.2579357Z

<img width="2104" height="303" alt="image" src="https://github.com/user-attachments/assets/b1255d52-aa1e-4a4e-a86a-4852623fcba1" />



-------

## FLAG 7

<img width="590" height="520" alt="image" src="https://github.com/user-attachments/assets/19695102-dfe2-4d78-8927-ab6dee440c61" />


```
//FLAG 7: Persistence - C2 Impant
DeviceFileEvents
| where DeviceName contains "azuki"
| where ActionType contains "FileCreated"
| where InitiatingProcessCommandLine has "Temp" or FolderPath has "Cache"=
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, FolderPath, FileSize
| order by Timestamp asc
```


2025-11-25T04:21:33.118662Z

Results:

<img width="2092" height="665" alt="image" src="https://github.com/user-attachments/assets/1be75696-46e9-4572-842c-85a16235ea76" />




----------

## FLAG 8

<img width="626" height="493" alt="image" src="https://github.com/user-attachments/assets/43d6c2d6-8d6b-41bd-8066-3fd556d1039b" />


```
//FLAG 8: Persistence - Named Pipe
DeviceEvents
| where DeviceName contains "azuki"
| where ActionType contains "NamedPipeEvent"
| where InitiatingProcessFileName contains "meterpreter.exe"
| project Timestamp, DeviceName, ActionType, FileName, AdditionalFields, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId, AccountName
| order by Timestamp asc
```


Results:

2025-11-25T04:24:35.3398583Z

<img width="2066" height="306" alt="image" src="https://github.com/user-attachments/assets/1e5f2e67-fbd6-4b36-895e-97fa382df92c" />



--------
## FLAG 9

<img width="597" height="575" alt="image" src="https://github.com/user-attachments/assets/ebe2c580-744d-4938-bca3-69fb9880a2c4" />


```
//FLAG 9: Credential Access - Decoded Account Creation
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "EncodedCommand"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

Results:
<img width="2308" height="266" alt="image" src="https://github.com/user-attachments/assets/63aa794f-d3b3-4d68-979a-20f5588e2ede" />


<img width="682" height="413" alt="image" src="https://github.com/user-attachments/assets/3343ab93-2aea-49aa-bcea-aaa2bb25f909" />


----------

## FLAG 10

<img width="590" height="481" alt="image" src="https://github.com/user-attachments/assets/0b6dbccb-45e2-4a59-ac1d-7a4a8f458c31" />



```
//FLAG 10: Persistence - Backdoor Account
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "EncodedCommand"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```

Results:

<img width="682" height="413" alt="image" src="https://github.com/user-attachments/assets/e3c18c13-03b0-407f-8bb8-0291b4d30d0d" />


---------


## FLAG 11

<img width="596" height="606" alt="image" src="https://github.com/user-attachments/assets/e96eaf94-8490-47c0-aa5e-74811b6e0ea9" />


```
//FLAG 11: Persistence - Decoded Privilege Escalation Command
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "-enc" or ProcessCommandLine contains "EncodedCommand"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp asc
```


Results:

<img width="2319" height="380" alt="image" src="https://github.com/user-attachments/assets/55e894d0-61dd-4a8c-a723-e96044add16b" />


<img width="682" height="398" alt="image" src="https://github.com/user-attachments/assets/5f77b648-cacf-41e7-b4ea-3c5055525776" />


--------

## FLAG 12

<img width="574" height="464" alt="image" src="https://github.com/user-attachments/assets/9811b21f-993d-44a0-aec6-b7f41f6e3c0f" />



```
//FLAG 12 Discovery - Session Enumeration
DeviceProcessEvents
| where ProcessCommandLine has_any ("quser", "query user", "qwinsta", "query session")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```


Results:

<img width="1163" height="275" alt="Pasted image 20251216202951" src="https://github.com/user-attachments/assets/c0d5155d-13e1-4b41-831e-0f6954bea1da" />



-----

## FLAG 13

<img width="607" height="457" alt="image" src="https://github.com/user-attachments/assets/705c5aba-b24a-4f65-86b8-fa6215b7be34" />


```
//FLAG 13 Discovery - Domain Trust Enumeration
DeviceProcessEvents
| where ProcessCommandLine has "nltest"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

Results:

<img width="1449" height="304" alt="image" src="https://github.com/user-attachments/assets/48212dcb-9ff6-42d8-867f-b17c8af34866" />



-------

## FLAG 14

<img width="612" height="477" alt="image" src="https://github.com/user-attachments/assets/2021951f-b260-4fc8-b2e5-f47572b39573" />


```
//FLAG 14: Discovery - Network Connection Enumeration
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "netstat"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

2025-11-25T04:10:07.805432Z

<img width="1302" height="268" alt="image" src="https://github.com/user-attachments/assets/5171a7a0-01fa-4c8e-943d-818c672b66be" />




-------

## FLAG 15

<img width="613" height="448" alt="image" src="https://github.com/user-attachments/assets/196d4f7f-70e3-4d0f-b496-e2021501f744" />


```
//FLAG 15: Discovery - Password Database Search
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine has_any ("kdbx", "psafe", "keepass")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

2025-11-25T04:13:45.8171756Z

Results:

<img width="1748" height="304" alt="image" src="https://github.com/user-attachments/assets/b2945294-ecd3-42a6-b56c-69660c849e82" />


---------
## FLAG 16

<img width="626" height="508" alt="image" src="https://github.com/user-attachments/assets/84f08b82-d848-443c-a459-edc0d5aa0626" />


```
//FLAG 16: Discovery - Credential File
DeviceFileEvents
| where DeviceName contains "azuki"
| where FileName contains ".txt" or FileName contains ".lnk"
| project Timestamp, ActionType, DeviceName, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

2025-11-25T04:15:57.3989346Z

Results:

<img width="1195" height="538" alt="image" src="https://github.com/user-attachments/assets/1ca553c7-c5e4-4dad-ba86-52a314263307" />



-------

## FLAG 17

<img width="614" height="442" alt="image" src="https://github.com/user-attachments/assets/8cd2e9e3-7ee1-4314-9843-102828db6934" />



```
//FLAG 17: Collection - Data Staging Directory
DeviceFileEvents
| where DeviceName contains "azuki"
| where ActionType in ("FolderCreated", "FileCreated")
| where FolderPath has_any ("ProgramData", "Windows", "System32")
| where FolderPath startswith "C:\\"
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

2025-11-25T04:37:03.3036917Z

Results:

<img width="1900" height="262" alt="image" src="https://github.com/user-attachments/assets/1fb7a9a4-e06d-41bb-aedb-6744d3a5d44d" />



----------

## FLAG 18

<img width="605" height="466" alt="image" src="https://github.com/user-attachments/assets/c486ac7d-eba4-4058-8064-76dde0029e50" />



```
//FLAG 18: Collection - Automated Data Collection Command
DeviceFileEvents
| where DeviceName contains "azuki"
| where ActionType in ("FolderCreated", "FileCreated")
| where FolderPath has_any ("ProgramData", "Windows", "System32")
| where FolderPath startswith "C:\\"
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

2025-11-25T04:37:03.3036917Z

Results:

<img width="1864" height="263" alt="image" src="https://github.com/user-attachments/assets/29ad963b-8b44-490c-bd25-153f0cd17433" />


-----

## FLAG 19

<img width="619" height="480" alt="image" src="https://github.com/user-attachments/assets/3e946aa6-2b60-4450-823b-f6ab29a25763" />



```
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath startswith @"C:\ProgramData\Microsoft\Crypto\staging"
| where FileName matches regex @"\.(zip|7z|rar|cab|tar|gz)$"
| summarize TotalArchives = dcount(FileName)
```

<img width="2351" height="322" alt="image" src="https://github.com/user-attachments/assets/5f415e52-2918-450a-9c9f-0ffac51be2a0" />



--------

## FLAG 20

<img width="629" height="464" alt="image" src="https://github.com/user-attachments/assets/c003236f-a347-4d6f-921e-4dc537b7d4b2" />


```
//FLAG 20: Credential Access - Credential Theft Tool Download
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "curl"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc
```

<img width="1902" height="235" alt="image" src="https://github.com/user-attachments/assets/a903c98d-3d49-4dc4-9fee-3655ab573074" />



------------

## FLAG 21

<img width="589" height="444" alt="image" src="https://github.com/user-attachments/assets/7233ea38-1668-4eaf-b149-0c98534df2ff" />


```
//FLAG 20: Credential Access - Credential Theft Tool Download
DeviceProcessEvents
| where DeviceName contains "azuki"
| where FileName contains "m.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

2025-11-25T05:55:54.858525Z

Results:

<img width="1843" height="232" alt="image" src="https://github.com/user-attachments/assets/5c2d5f5d-661b-48ab-b541-7d93bde14528" />



-------

## FLAG 22

<img width="624" height="455" alt="image" src="https://github.com/user-attachments/assets/4d28b93d-3afe-4dcc-bee3-a9370ca6c803" />


```
//FLAG 22: Exfiltration - Data Upload Command
DeviceProcessEvents
| where DeviceName contains "azuki"
| where ProcessCommandLine contains "curl"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp asc

```

2025-11-25T04:41:51.7723427Z

Results:

<img width="1790" height="229" alt="image" src="https://github.com/user-attachments/assets/4b2740ba-82da-4977-8683-7b86a98f5d9f" />



-------

## FLAG 23

<img width="620" height="487" alt="image" src="https://github.com/user-attachments/assets/23cd9743-2c09-4f1a-82cc-4d400c2bf648" />


```
Refer to FLAG 22

```


<img width="699" height="196" alt="image" src="https://github.com/user-attachments/assets/f5bc8a57-3d81-493f-96c5-a9be14b518ab" />



------

## FLAG 24

<img width="613" height="492" alt="image" src="https://github.com/user-attachments/assets/726b89ea-edc4-485a-af06-49e0eeda4f39" />


```
//FLAG 24: Exfiltration - Destination Server
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where RemoteUrl contains "gofile"
| project Timestamp, DeviceName, ActionType, Protocol, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId
| order by Timestamp asc
```

2025-11-25T04:41:52.2330729Z

Results:

<img width="1717" height="407" alt="image" src="https://github.com/user-attachments/assets/87b884f9-1212-46f5-96f1-3eba5a448d1f" />




--------

<img width="609" height="539" alt="image" src="https://github.com/user-attachments/assets/cc56db14-34fb-4754-bb48-e67ab893cf93" />


## FLAG 25

```
//FLAG 25: Credential Access - Master Password Extraction
DeviceFileEvents
| where DeviceName contains "azuki-adminpc"
//| where ActionType == "FileCreated"
//| where FileName contains ".txt"
| where InitiatingProcessCommandLine contains ".txt"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessId
| order by Timestamp asc
```

<img width="1792" height="302" alt="image" src="https://github.com/user-attachments/assets/b560447a-77e8-446f-857d-179ea4a38f55" />



--------------------

| **Time (UTC)** | **Flag** | **Event**               | **Adversary Behavior**       | **MITRE Technique**       |
| -------------- | -------- | ----------------------- | ---------------------------- | ------------------------- |
| 04:06:52       | 1        | Lateral Movement Source | RDP login using stolen creds | Lateral Movement (TA0008) |
| 04:06:52       | 2        | Compromised Credentials | Reused `yuki.tanaka`         | Valid Accounts            |
| 04:06:52       | 3        | Target Device           | Accessed admin workstation   | System Info Discovery     |
| 04:21:11       | 4        | Payload Hosting         | Connected to Catbox          | Ingress Tool Transfer     |
| 04:21:11       | 5        | Malware Download        | `curl.exe` download          | Ingress Tool Transfer     |
| 04:21:32       | 6        | Archive Extraction      | `7z.exe` passworded extract  | Deobfuscate Files         |
| 04:21:33       | 7        | C2 Implant              | Meterpreter deployed         | Command & Control         |
| 04:24:35       | 8        | Named Pipe              | IPC channel created          | Internal Proxy            |
| 04:51:08       | 9        | Encoded Command         | Account creation             | Obfuscated Files          |
| 04:51:08       | 10       | Backdoor Account        | `yuki.tanaka2`               | Create Account            |
| 04:51:23       | 11       | Priv Esc                | Added to Admins              | Privilege Escalation      |
| 04:08:58       | 12       | Session Enum            | `qwinsta`                    | Account Discovery         |
| 04:09:25       | 13       | Trust Enum              | `nltest`                     | Domain Trust Discovery    |
| 04:09:30       | 14       | Net Enum                | `netstat -ano`               | Network Discovery         |
| 04:13:45       | 15       | File Search             | KeePass DB hunt              | Credentials in Files      |
| 04:15:57       | 16       | Plaintext Creds         | `OLD-Passwords.txt`          | Unsecured Credentials     |
| 04:37:03       | 17       | Staging Dir             | Crypto masquerade            | Local Data Staging        |
| 04:37:03       | 18       | Automated Copy          | `robocopy`                   | Automated Collection      |
| 04:40:30       | 19       | Archiving               | 8 archives created           | Archive Collected Data    |
| 05:55:34       | 20       | Tool Download           | Credential tool              | Ingress Tool Transfer     |
| 05:55:54       | 21       | Browser Theft           | Chrome DPAPI dump            | Browser Credential Theft  |
| 04:41:51       | 22       | Exfil Command           | HTTPS POST                   | Exfil Over Web Service    |
| 04:41:51       | 23       | Cloud Service           | gofile.io                    | Exfil to Cloud Storage    |
| 04:41:52       | 24       | Destination IP          | 45.112.123.227               | Exfiltration Channel      |
| 04:39:16       | 25       | Master Password         | KeePass password             | Password Store Theft      |

--------

## 🧬 Incident Timeline (Condensed Narrative)

1. **Initial Access**
    - Valid RDP logon from `10.1.0.204` using `yuki.tanaka`
2. **Execution**
    - Malware downloaded via `curl.exe` from `litter.catbox.moe`
    - Archive extracted with `7z.exe`
3. **Persistence**
    - `meterpreter.exe` deployed
    - Named pipe `\\Device\\NamedPipe\\msf-pipe-5902` created
4. **Privilege Escalation**
    - Encoded PowerShell creates `yuki.tanaka2`
    - Added to `Administrators` group
5. **Discovery**
    - RDP sessions (`qwinsta`)
    - Domain trusts (`nltest`)
    - Network connections (`netstat`)
6. **Credential Access**
    - Chrome DPAPI decryption
    - KeePass master password extracted
7. **Collection**
    - Banking and financial documents copied via `robocopy`
    - Data staged in `C:\ProgramData\Microsoft\Crypto\staging`
8. **Exfiltration**
    - 8 archives created
    - Uploaded via HTTPS POST to `gofile.io`
9. **Anti-Forensics**
    - PowerShell history deleted



---

## 🛡️ Recommended Mitigations

1. Enforce **conditional access + MFA** on RDP
2. Block **unsigned PowerShell encoded commands**
3. Monitor **ProgramData write activity**
4. Alert on **named pipe creation by non-system binaries**
5. Disable or restrict **curl / tar / robocopy** on endpoints
6. Block anonymous file-hosting domains at egress
7. Enforce **password manager hardening & vault protection**

---------

## 🔍 Lessons Learned

- **Valid accounts remain the most dangerous attack vector**
- **Encoded PowerShell is still under-detected**
- **Cloud file hosts are ideal exfil paths**
- **Password hygiene failures cascade rapidly**
- **Staging directories disguised as system paths evade notice**
