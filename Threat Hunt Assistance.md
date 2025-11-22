# Threat Hunt Scenario - Assistance

<img width="647" height="551" alt="image" src="https://github.com/user-attachments/assets/3dbc54c7-3132-4ed4-8601-b339dcc1483f" />

# Table of Contents

Detection and Analysis:
- [🕵️Flag 1 - Initial Execution Detection](#flag-1---initial-execution-detection)
- [🏰Flag 2 - Defense Disabling](#flag-2---defense-disabling)
- [🔍Flag 3 - Quick Data Probe](#flag-3---quick-data-probe)
- [👁️Flag 4 - Host Context Recon](#flag-4---host-context-recon)
- [🗺️Flag 5 - Storage Surface Mapping](#flag-5---storage-surface-mapping)
- [⇄  Flag 6 - Connectivity & Name Resolution Check](#flag-6---connectivity--name-resolution-check)
- [👀Flag 7 - Interactive Session Discovery](#flag-7---interactive-session-discovery)
- [📦Flag 8 - Runtime Application Inventory](#flag-8---runtime-application-inventory)
- [🏠︎ Flag 9 - Privilege Surface Check](#flag-9---privilege-surface-check)
- [↩Flag 10 - Proof-of-Access & Egress Validation](#flag-10---proof-of-access--egress-validation)
- [📦Flag 11 - Bundling / Staging Artifacts](#flag-11---bundling--staging-artifacts)
- [📬Flag 12 - Outbound Transfer Attempt](#flag-12---outbound-transfer-attempt)
- [🕘Flag 13 - Scheduled Re-Execution Persistence](#flag-13---scheduled-re-execution-persistence)
- [🌐Flag 14 - Autorun Fallback Persistence](#flag-14---autorun-fallback-persistence)
- [🌿Flag 15 - Planted Narrative / Cover Artifact](#flag-15---planted-narrative--cover-artifact)
- [✨Logical Flow & Analyst Reasoning](#logical-flow--analyst-reasoning)
- [📜Final Notes / Findings](#final-notes--findings)

MITRE ATT&CK Framework:
- [🚩 Flags → MITRE ATT&CK Mapping Table](#flags--mitre-attck-mapping-table)
- [🌍 Summary of ATT&CK Categories Used](#summary-of-attck-categories-used)

Lessons Learned:
- [🔒 1. Strengthen PowerShell Logging & Restrictions](#-1-strengthen-powershell-logging--restrictions)
- [📁 2. Restrict Execution from User Download Folders](#-2-restrict-execution-from-user-download-folders)
- [🔍 3. Harden Scheduled Task Abuse](#-3-harden-scheduled-task-abuse)
- [🚫 4. Prevent Registry Run Key Persistence](#-4-prevent-registry-run-key-persistence)
- [🌐 5. Improve Network Egress Controls](#-5-improve-network-egress-controls)
- [🛡 6. Enable/Improve Endpoint Security Controls](#-6-enableimprove-endpoint-security-controls)
- [🧩 7. Block Living-off-the-Land Binaries (LOLBins)](#-7-block-living-off-the-land-binaries-lolbins)
- [🔐 8. Least Privilege Enforcement](#-8-least-privilege-enforcement)
- [📦 9. User Education & Phishing Awareness](#-9-user-education--phishing-awareness)
- [🧵 10. Improve SOC Detection Logic](#-10-improve-soc-detection-logic)
- [🗂 11. File System Hardening](#-11-file-system-hardening)
- [⭐ Top 5 Quick-Win Mitigations to Implement Immediately](#-top-5-quick-win-mitigations-to-implement-immediately)


---
# Report By

`**Date:** October 1st - 15th, 2025`  
`**Analyst:** Grisham DelRosario`  
`**Environment:** Microsoft - Log Analytics Workspace (LAW - Cyber Range)`  
`**Attack Type:** Fake Remote Session/Malicious Help Desk`

---------------------------------------------------

# **Scenario**
`A routine support request should have ended with a reset and reassurance. Instead, the so- called "help" left behind a trail of anomalies that don't add up. What was framed as troubleshooting looked more like an audit of the system itself probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended. And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny. This wasn't remote assistance. It was a misdirection. Your mission this time is to reconstruct the timeline, connect the scattered remnants of  this "support session", and decide what was legitimate, and what was staged. The evidence is here. The question is whether you'll see through the story or believe it.`

---------------------------------------------------
# **Preparation**

<img width="657" height="309" alt="image" src="https://github.com/user-attachments/assets/8942b8bf-b907-47bc-9334-ea9f6ffc6f16" />

<img width="655" height="151" alt="image" src="https://github.com/user-attachments/assets/a763f5e7-4426-4ee3-b02f-beaa98be81a5" />

---------------------------------------------------
### KQL Query Used

```
//---------------------------------------------------------
let start = datetime(2025-10-01T00:00:00Z);
let end   = datetime(2025-10-31T23:59:59Z);
let keywords = dynamic(["desk", "help", "support", "tool"]);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where FileName has_any (keywords)
| project TimeGenerated, DeviceName, FileName, FolderPath,
          InitiatingProcessAccountDomain, InitiatingProcessFolderPath, InitiatingProcessId,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by TimeGenerated desc
```

---------------------------------------------------

1. Spawning process originating from the download folder. Occurred in the first half of October, so sometime between October 1st -15th?

2. Similar executables, naming patterns, and other traits.

3. Common keywords, `"desk", "help", "support", and "tool"`


<img width="1450" height="575" alt="image" src="https://github.com/user-attachments/assets/f0c6c24a-97fd-4884-8613-8c23a803a964" />

- In order to identify the most suspicious machine based on the given conditions I decided to set a variable called `'keywords'` with `"desk", "help", "support", and "tool"` in order to set up the query. 

- First table I checked to start this hunt was `DeviceFileEvents.` 

- The keyword `support` also allowed me to find this suspicious filename, `Support_701.txt` that was unusual as I was going through the logs but it allowed me to find the suspicious machine. I kept focus as it was mentioned at starting point several machines were found to share the same types of files - similar executables, naming patterns, and other traits -
---------------------------------------------------
### KQL Query Used
```
//---------------------------------------------------------
let start = datetime(2025-10-01T00:00:00Z);
let end   = datetime(2025-10-31T23:59:59Z);
let keywords = dynamic(["desk", "help", "support", "tool"]);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where FileName has_any (keywords)
| project TimeGenerated, DeviceName, FileName, FolderPath,
          InitiatingProcessAccountDomain, InitiatingProcessFolderPath, InitiatingProcessId,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by TimeGenerated desc
```


- Ideally, another way I could have found this device without having to think so hard was to have queried the term 
`Intern` for `DeviceName` in order to find the suspicious device, 
`gab-intern-vm`
- This too would have been an easier method to find in order to narrow down the suspicious device.

<img width="1864" height="509" alt="image" src="https://github.com/user-attachments/assets/681a4d63-6f41-4598-82de-2ecb95c6332c" />


---------------------------------------------------
# **Detection and Analysis**

# Flag 1 - Initial Execution Detection  
[Table of Contents](#table-of-contents)

<img width="593" height="515" alt="image" src="https://github.com/user-attachments/assets/f13fbe06-37cb-423d-841a-77c07063faba" />

- Throughout the threat hunt, the table `DeviceProcessEvents` was very key in order to examine the logs.

- For Flag 1, we're looking at Initial Execution Detection

- When I read what to hunt and saw 'script', the first thing that came to mind was PowerShell and Command Prompt. Further on, the question asked 

`"What was the first CLI (command line interface) parameter name used during the execution of the suspicious program?"`

- After looking back and forth at was being asked of the flag and examining logs `"unusual execution"` was key in order to find this flag.

- The earliest anomalous execution of powershell being executed was `2025-10-06T06:00:48.7549551Z`

---------------------------------------------------
### KQL Query Used
```
//---------------FLAG 1-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where FileName == "powershell.exe"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-31T23:59:59Z))
| project TimeGenerated, ActionType, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
```

<img width="2075" height="384" alt="image" src="https://github.com/user-attachments/assets/87d0806a-00b6-4c40-89f1-1ff60438bee9" />


- Upon looking at the log activity for powershell executables we can see the first CLI parameter is set to `-ExecutionPolicy`.  First time it was executed was on October 6th, 2025 at 6:00:48 AM

- This eventually occurred again for a powershell.exe process called `SupportTool.ps1` for `2025-10-09T12:22:27.6588913Z`


---------------------------------------------------

# Flag 2 - Defense Disabling 
[Table of Contents](#table-of-contents)

<img width="663" height="519" alt="image" src="https://github.com/user-attachments/assets/59d134ae-2232-4d6a-8bd9-ba32fd18d0e3" />

----------------------------------------------------------------------

- Further on, I decided to pivot back into `DeviceProcessEvents` table and look back into more power shell activity.

- I kept noticing this command scrolling through the logs and noticed the string when querying for  `Artifact` and `Out-File -FilePath 'C:\Users\Public\DefenderTamperArtifact.txt'`

- The query used in Flag 1 to understand the CLI parameter `-ExecutionPolicy`, was key into understanding the timeline of events that showed another powershell command outputting a file called `DefenderTamperArtifact.txt`

- As I kept querying for the term artifact and I kept on encountering the file name `ReconArtifacts.zip.`

- It was the closest thing I can find but it was not the official tampered artifact.

- Still needed to find something related to either this or the `DefenderTamperArtifact.txt` file. Somehow I knew these were related to Defense Disabling but could not make the linkage as to how it was all connected.

<img width="2144" height="514" alt="image" src="https://github.com/user-attachments/assets/c910c494-6961-4dcc-9f2e-c6ce4407400b" />

<img width="1448" height="219" alt="image" src="https://github.com/user-attachments/assets/708a3d33-4ba1-4454-a265-006bfc370ff6" />

- I decided to check `DeviceFileEvents` table and query for `Artifact` in the `FileName` column.

---------------------------------------------------
### KQL Query Used
```
//---------------FLAG 2-----------------------
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where ActionType == "FileCreated"
| where FileName contains "Artifact"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| project TimeGenerated, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName
```

- For the query, I kept using `Artifact` and used this information to see if there was another file name related to the term.

- I found `ReconArtifacts.zip` and then saw that there was a `DefenderTamperArtifact.lnk` file. 

- The timestamp matches with process creation from the `DeviceProcessEvents` table

- The  `.lnk`  file extension is a shortcut of the filename. Upon researching `.LNK` files, they are often the trigger for malicious scripts and  can be used for malicious purposes.


<img width="1863" height="771" alt="image" src="https://github.com/user-attachments/assets/3a8b87d6-a9f5-4f7b-8a7b-5b2e6369bbf9" />

<img width="1978" height="595" alt="image" src="https://github.com/user-attachments/assets/98852f93-905e-482f-8ab7-6a9cd60ea677" />


---------------------------------------------------

# Flag 3 - Quick Data Probe 
[Table of Contents](#table-of-contents)

<img width="605" height="519" alt="image" src="https://github.com/user-attachments/assets/87ce3e70-eaf9-4e99-9c58-e50ab8ae0637" />


- For this flag I imagined the command value had something to do with copy and paste actions as it is a common short-lived action.

- The other part to this was the term `query`

- I decided to check the `InitiateProcessCommandLine` column and find syntax and flags that looked like it was written as a query.

- Upon looking I kept my focus on the timeline of the script and tried to match up the time .

- The `InitiatingProcessCommandLine` showed this command below when querying for `'clip'`

The Answer:

`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null }    catch { }"` 


- This specific activity related to `powershell` has the syntax for a query such as 

`"try { Get-Clipboard | Out-Null } catch { }"`

---------------------------------------------------
### KQL Query Used
```
//---------------FLAG 3-----------------------
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessCommandLine contains "clip"
| where TimeGenerated between (datetime(2025-10-09T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessParentFileName
```

<img width="1429" height="354" alt="image" src="https://github.com/user-attachments/assets/95c4faef-340d-47f3-b76d-2fb9694019c4" />

---------------------------------------------------

# Flag 4 - Host Context Recon 
[Table of Contents](#table-of-contents)

<img width="660" height="510" alt="image" src="https://github.com/user-attachments/assets/bfaec963-a973-44e1-b905-5ee9395f2399" />


- While going through the logs, and reading this flag I recall seeing an executable called ' qwinsta.exe ' I had to look up this program and it is a command on windows that can: `Display information about sessions on a Remote Desktop Session Host server`

- This made sense in terms of gathering host and user context information.

- Working within the timestamp of `2025-10-09T12:51:44.3425653Z` we can see that this was the last recon attempt for the query session for the attacker to enumerate.


---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 4-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where ProcessCommandLine contains "qwi"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-20T23:59:59Z))
| project TimeGenerated, AccountDomain, AccountName, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName
```

<img width="1855" height="84" alt="image" src="https://github.com/user-attachments/assets/4a85f06f-890f-4671-a5b7-0925eff8dcb9" />


---------------------------------------------------

# Flag 5 - Storage Surface Mapping 
[Table of Contents](#table-of-contents)

<img width="677" height="503" alt="image" src="https://github.com/user-attachments/assets/823b8907-4acd-4922-a58e-9010bccace05" />


- After looking at the `qwinsta.exe` process that was created in the logs.I noticed the command prompt executable that showed logical disk that comes after the `qwinsta.exe` executable.

- This made sense in terms of data as to where it lives and the data that can be discovered such as 'storage'. 

- Decided to search for 'WMIC.exe' command and found out that the 'logical disk' is `used to query Windows for information about a computer's local drives`. 

- We can see the `TimeGenerated` column is still within 12:50:00 PM-12:51:00 PM.

	- `Time Generated @ 2025-10-09T12:51:18.3848072Z`
	- `"cmd.exe" /c wmic logicaldisk get name,freespace,size`

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 5-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where FileName contains "cmd"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-20T23:59:59Z))
| project TimeGenerated, AccountDomain, AccountName, ActionType, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
```

<img width="1190" height="715" alt="image" src="https://github.com/user-attachments/assets/0d1966d1-68e4-4a74-9437-f87e71ca951b" />



---------------------------------------------------

# Flag 6 - Connectivity & Name Resolution Check 
[Table of Contents](#table-of-contents)

<img width="659" height="502" alt="image" src="https://github.com/user-attachments/assets/e6c62aa4-f755-4c5b-95cd-0683ea774d05" />

- What was key to this question was network related events. Especially when it comes to DNS and outbound connections.

- I decided to check the `InitiatingProcessParentFileName` column in the `DeviceNetworkEvents` table and try to narrow down unusual PowerShell activity.

- I made sure to stay focused on October 9th 2025 during the time of `12:50-12:55 PM` as other events from `DeviceProcessEvents` and `DeviceFileEvents` were very important in relation to `SupportToolScript.ps1`. `Powershell` executables have been very prevalent throughout the hunt. 

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 6-----------------------
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName == "powershell.exe"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-20T23:59:59Z))
| project TimeGenerated, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessId, InitiatingProcessParentFileName, Protocol, RemoteIP
```

<img width="2114" height="679" alt="image" src="https://github.com/user-attachments/assets/5abdd300-1878-4300-a79c-894ab1ab0bd8" />


---------------------------------------------------

# Flag 7 - Interactive Session Discovery 
[Table of Contents](#table-of-contents)

<img width="661" height="467" alt="image" src="https://github.com/user-attachments/assets/ac36c23e-8e4a-4ece-a14f-3938832b6061" />


`Keywords: Session, Initiate Process, Unique`

- Had to get a little help with this one from another user without having to give away the answer and eventually I had a lightbulb moment.

- It was actually really simple. When I read the question "What is the unique ID of the initiating process?" I kept focusing for the column `InitiatingProcessID`

- I was so stumped that I feel the process identification task number was staring at me.  I had to pivot and got the hint from a user to project `InitiatingProcessUniqueId`

- I should have considered the term `unique` in order to find the number of `InitiatingProcessUniqueId`

	`2533274790397065`

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 7-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where TimeGenerated between (datetime(2025-10-09T00:00:00Z) .. datetime(2025-10-10T23:59:59Z))
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId, ProcessId, InitiatingProcessId, InitiatingProcessCommandLine
```

<img width="2278" height="711" alt="image" src="https://github.com/user-attachments/assets/955a3d47-e687-433e-aa54-33abd7a9bc92" />


```
//---------------FLAG 7-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where InitiatingProcessUniqueId == "2533274790397065"
| where TimeGenerated between (datetime(2025-10-09T00:00:00Z) .. datetime(2025-10-10T23:59:59Z))
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId, ProcessId, InitiatingProcessId, InitiatingProcessCommandLine
```

<img width="1962" height="483" alt="image" src="https://github.com/user-attachments/assets/56d4dfd4-4c65-4d5d-8a49-6b36a0bc5765" />

---------------------------------------------------

# Flag 8 - Runtime Application Inventory 
[Table of Contents](#table-of-contents)

<img width="663" height="546" alt="image" src="https://github.com/user-attachments/assets/89f36f9a-1f78-407f-bc8a-6b1dfc05fcc3" />

They want the _file name_ of the process that shows:
- `“runtime process enumeration”
- `“process-list snapshots”
- `“queries of running services”

And the hint:
1. `Task
2. `List
3. `Last

This is pointing directly at:

 **`tasklist.exe`**
 
---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 8-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where ProcessCommandLine contains "tasklist"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId, InitiatingProcessId, InitiatingProcessParentId
```

<img width="1966" height="90" alt="image" src="https://github.com/user-attachments/assets/8c02e582-4206-4e10-a113-0e41902e4d42" />

---------------------------------------------------

# Flag 9 - Privilege Surface Check 
[Table of Contents](#table-of-contents)

<img width="661" height="481" alt="image" src="https://github.com/user-attachments/assets/3a2938db-b2da-4917-8231-c763cb7314ae" />

**Objective**
> Detect attempts to understand privileges available to the current actor.

This means: **we’re hunting for commands that ask “who am I?” or “what privileges do I have?”**

**What to Hunt**
> Queries of group membership, token properties, or privilege listings.

That’s `whoami` territory.

**Hint:**
1. Who

> **Identify the timestamp of the very first attempt.**
    The timestamp of the earliest privilege-checking event.

`TimeGenerated`
`2025-10-09T12:52:14.3135459Z`

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 9-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where ProcessCommandLine contains "who"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId, InitiatingProcessId, InitiatingProcessParentId
```

<img width="1189" height="229" alt="image" src="https://github.com/user-attachments/assets/5af37ea0-29ff-48df-99a1-973891d8b14b" />

---------------------------------------------------

# Flag 10 - Proof-of-Access & Egress Validation 
[Table of Contents](#table-of-contents)

<img width="661" height="543" alt="image" src="https://github.com/user-attachments/assets/07da97ad-943d-4fa6-a665-c2722bf59a47" />

Outbound Contact = Anything the host reaches OUT to

In other words:
- `DNS lookups
- `HTTP(S) requests
- `TCP/IP connections to external hosts
- `Ping / ICMP echo requests
- `Anything that leaves the VM and touches the internet or another host

Defender logs this as `DeviceNetworkEvents.`
	Decided to check the `RemoteUrl` column for outbound connections that were being tested with powershell.exe results below were the only existing domains to an unusual destination.

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 10-----------------------
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where InitiatingProcessFileName == "powershell.exe"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemoteUrl, InitiatingProcessFolderPath, InitiatingProcessUniqueId
| order by TimeGenerated asc
```

<img width="1586" height="117" alt="image" src="https://github.com/user-attachments/assets/ed079127-1942-4d24-a3f4-1d00ee82b28a" />



---------------------------------------------------

# Flag 11 - Bundling / Staging Artifacts 
[Table of Contents](#table-of-contents)

<img width="650" height="515" alt="image" src="https://github.com/user-attachments/assets/d121712d-5a56-4949-bab5-de21e3561f48" />


Dropped at: 

**`C:\Users\Public\ReconArtifacts.zip`**

And the logs confirm it perfectly:
- First created → **`12:58:17.436 PM`**, in _Public_
- Then copied or moved → _Documents_
- But they specifically ask for "first dropped", meaning the public directory.

Exactly the kind of staging behavior attackers love:

- `Public is world-writable
- `No elevation required
- `No user desktop pop-ups
- `Easy to exfiltrate quietly

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 11-----------------------
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where FolderPath contains "artifact"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath
| order by TimeGenerated asc
```

<img width="1343" height="121" alt="image" src="https://github.com/user-attachments/assets/cfb6ee2f-f8f1-4309-b523-37b0043bb94f" />

---------------------------------------------------

# Flag 12 - Outbound Transfer Attempt 
[Table of Contents](#table-of-contents)


<img width="649" height="519" alt="image" src="https://github.com/user-attachments/assets/bff3f5f3-a630-4ab1-8d8c-496b3e2b82da" />



- Recall the same query from Flag 10. The IP of the last unusual outbound connection was listed to a website called `httpbin.org` .

- The `RemoteIP` column showed the IP, `100.29.147.161`, of the outbound connection

---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 12-----------------------
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where InitiatingProcessAccountName == "g4bri3lintern"
| where InitiatingProcessFileName == "powershell.exe"
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIP, RemoteUrl
| order by TimeGenerated asc
```

<img width="1564" height="118" alt="image" src="https://github.com/user-attachments/assets/898d9787-38a5-44c4-a660-2f68cf4c3172" />


---------------------------------------------------

# Flag 13 - Scheduled Re-Execution Persistence
[Table of Contents](#table-of-contents)

<img width="648" height="475" alt="image" src="https://github.com/user-attachments/assets/e1b1dd04-64f4-4e69-96e8-66d8803e1e82" />



- The question asks for `task name`


---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 13-----------------------
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where AccountName == "g4bri3lintern"
| where InitiatingProcessUniqueId contains "2533274790397065"
| where TimeGenerated between (datetime(2025-10-09T00:00:00Z) .. datetime(2025-10-10T23:59:59Z))
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId, InitiatingProcessId, InitiatingProcessParentId
| order by TimeGenerated asc
```

<img width="2143" height="482" alt="image" src="https://github.com/user-attachments/assets/02ca3943-1b5b-4338-8a72-e336423fe802" />



- We can see in the output of `schtasks.exe` that the task name `/TN` flag is part of the process command line. 

- We can see the value of the task name is `SupportToolUpdater`

---------------------------------------------------

# Flag 14 - Autorun Fallback Persistence
[Table of Contents](#table-of-contents)

<img width="648" height="559" alt="image" src="https://github.com/user-attachments/assets/daa04793-cfa7-4559-94e6-a7f1cd1acc60" />


- The table `RemoteAssistUpdater` returned nothing. 


---------------------------------------------------

# Flag 15 - Planted Narrative / Cover Artifact
[Table of Contents](#table-of-contents)

<img width="659" height="523" alt="image" src="https://github.com/user-attachments/assets/2a834215-ef61-46ec-afbd-1c895984cd43" />



- The actor **left a cover story behind**, and the hint gives it away:

	> **Hint:** The actor opened it for some reason.

- That means we’re hunting for a file the attacker **manually opened**, likely something meant to _explain_ or _justify_ what they were doing. 

- The attacker delivered `SupportTool.ps1` to the victim’s Downloads folder and then executed it via the Windows shell, causing Explorer to create `SupportTool.lnk` in the Recent items directory.

- This ties the script to an interactive session (likely the `g4bri3Intern` profile) and demonstrates user-level execution (MITRE ATT&CK T1204 – User Execution).


---------------------------------------------------
### KQL Query Used

```
//---------------FLAG 15-----------------------
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where FileName contains "Support"
| where TimeGenerated between (datetime(2025-10-09T11:58:00Z) .. datetime(2025-10-09T13:03:59Z))
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by TimeGenerated asc
```

<img width="808" height="559" alt="image" src="https://github.com/user-attachments/assets/427a3960-63ed-4958-b1f7-79eacb384ac1" />

---------------------------------------------------

# Logical Flow & Analyst Reasoning
[Table of Contents](#table-of-contents)

<img width="660" height="939" alt="image" src="https://github.com/user-attachments/assets/a7c631cc-c3df-4090-af5e-ccfa777325cb" />

<img width="650" height="889" alt="image" src="https://github.com/user-attachments/assets/dd20c29b-8db8-47ab-b673-1ed667b0c615" />

---------------------------------------------------

# Final Notes / Findings
[Table of Contents](#table-of-contents)

This incident simulated a realistic multi-stage intrusion:

- Initial foothold
- Reconnaissance
- Privilege assessment
- Local staging
- Persistence
- Attempted exfiltration
- Narrative manipulation

And every step was traceable using **Log Analytics KQL**, primarily through:

- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceNetworkEvents`

---------------------------------------------------

# Flags → MITRE ATT&CK Mapping Table
[Table of Contents](#table-of-contents)

| Time Stamp - UTC             | **Flag #** | **Flag Title**                       | **Observed Activity**                                                                                                                                                        | **MITRE ATT&CK Technique**                                 | **Technique ID**      |
| ---------------------------- | ---------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- | --------------------- |
| 2025-10-09T12:22:27.6588913Z | **1**      | Initial Execution Detection          | PowerShell execution using         <br><br>`-ExecutionPolicy`                                                                                                                | Command & Scripting Interpreter: PowerShell                | **T1059.001**         |
| 2025-10-09T12:34:59.1260624Z | **2**      | Defense Disabling Indicator          | Creation of malicious file <br><br>`DefenderTamperArtifact.lnk`                                                                                                              | Defense Evasion: Masquerading / Indirect Execution via LNK | **T1036 / T1204.002** |
| 2025-10-09T12:50:40.0325062Z | **3**      | Quick Data Probe                     | Clipboard access using  <br>`"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard \| Out-Null } catch { }"`<br><br>                                                | Input Capture: Clipboard Data                              | **T1115**             |
| 2025-10-09T12:51:44.3272076Z | **4**      | Host Context Recon                   | Session enumeration (`qwinsta.exe`)<br><br>`InitiatingProcessCommandLine`<br>`"cmd.exe" /c query session `<br><br>`Time Generated`<br>`2025-10-09T12:51:44.3272076Z`<br><br> | Account Discovery / System Owner-User Discovery            | **T1087 / T1033**     |
| 2025-10-09T12:51:18.3848072Z | **5**      | Storage Surface Mapping              | Disk/volume enumeration via <br><br>`"cmd.exe" /c wmic logicaldisk get name,freespace,size`<br><br>                                                                          | System Information Discovery                               | **T1082**             |
| 2025-10-09T12:55:05.7658713Z | **6**      | Connectivity & Name Resolution Check | Outbound DNS / connectivity testing via PowerShell <br><br>`RuntimeBroker.exe`<br><br>                                                                                       | Application Layer Protocol / DNS                           | **T1071 / T1071.004** |
| 2025-10-09T12:51:44.3081129Z | **7**      | Interactive Session Discovery        | Interactive session state checked (`query session`)<br><br>`InitiatingProcessUniqueId`<br><br>`2533274790397065`<br><br>                                                     | System Information Discovery / Remote Services Discovery   | **T1082 / T1035**     |
| 2025-10-09T12:51:57.6866149Z | **8**      | Runtime Application Inventory        | Process listing using <br><br>`tasklist.exe`<br><br>                                                                                                                         | Process Discovery                                          | **T1057**             |
| 2025-10-09T12:52:14.3135459Z | **9**      | Privilege Surface Check              | Privilege/user enumeration <br>(`whoami /priv`, `/groups`)<br><br>`TimeGenerated`<br>`2025-10-09T12:52:14.3135459Z`<br><br><br>                                              | Permission Group Discovery                                 | **T1069**             |
| 2025-10-09T12:55:05.7658713Z | **10**     | Proof-of-Access & Egress Validation  | Outbound contact to <br><br>`msftconnecttest.com`                                                                                                                            | Exfiltration Test / Application Layer Protocol             | **T1041 / T1071**     |
| 2025-10-09T12:58:17.4364257Z | **11**     | Bundling / Staging Artifacts         | Staging of `ReconArtifacts.zip` in Public directory folderpath<br><br>`C:\Users\Public\ReconArtifacts.zip`<br><br>                                                           | Archive Collected Data                                     | **T1560**             |
| 2025-10-09T13:00:40.045127Z  | **12**     | Outbound Transfer Attempt            | Outbound HTTP traffic to <br><br>`100.29.147.161`<br><br>                                                                                                                    | Exfiltration Over Web Services                             | **T1567.002**         |
| 2025-10-09T13:01:29.7815532Z | **13**     | Scheduled Re-Execution Persistence   | Scheduled Task: <br><br>`SupportToolUpdater`                                                                                                                                 | Scheduled Task/Job: Scheduled Task                         | **T1053.005**         |
|-----------N/A----------      | **14**     | Autorun Fallback Persistence         | Registry persistence value <br><br>`RemoteAssistUpdater`<br><br>                                                                                                             | Registry Run Keys / Startup Folder                         | **T1547.001**         |
| 2025-10-09T13:02:41.5698148Z | **15**     | Planted Narrative / Cover Artifact   | Fake support file: <br><br>`SupportChat_log.lnk`                                                                                                                             | Masquerading (Fake File / Cover Story)                     | **T1036**             |


---------------------------------------------------

# Summary of ATT&CK Categories Used
[Table of Contents](#table-of-contents)

| Category                          | Techniques Used            |
| --------------------------------- | -------------------------- |
| **Execution**                     | T1059.001                  |
| **Defense Evasion**               | T1036, T1204.002           |
| **Credential Access**             | T1115                      |
| **Discovery**                     | T1033, T1082, T1057, T1069 |
| **Lateral Movement Prep / Recon** | T1035                      |
| **Command & Control / Network**   | T1071, T1071.004           |
| **Collection**                    | T1560                      |
| **Exfiltration**                  | T1041, T1567.002           |
| **Persistence**                   | T1053.005, T1547.001       |


---------------------------------------------------

# Lessons Learned
[Table of Contents](#table-of-contents)

Mitigations for This Threat Hunt

Each mitigation is mapped to the techniques observed in the hunt, prioritized by impact and feasibility.

---
## 🔒 **1. Strengthen PowerShell Logging & Restrictions**
[Table of Contents](#table-of-contents)

**Why:** Nearly all malicious activity in this scenario involved PowerShell:

- ExecutionPolicy bypass
    
- Hidden windows
    
- Script execution from Downloads
    
- Clipboard scraping attempts
    
- File staging and exfil tests
  
**Mitigations:**

- Enable **PowerShell Script Block Logging** (4104)
    
- Enable **Module Logging**
    
- Enable **PowerShell Transcription**
    
- Enforce **Constrained Language Mode** for non-admins
    
- Block **ExecutionPolicy Bypass** via GPO:
    
`Computer Configuration → Administrative Templates → Windows Components → PowerShell   "Turn on Script Execution" → Allow only signed scripts`

- Deploy **AppLocker** or **Windows Defender Application Control (WDAC)** rules to block PowerShell.exe for standard users
---
## 📁 **2. Restrict Execution from User Download Folders**
[Table of Contents](#table-of-contents)

**Why:** Initial execution occurred from:  
`C:\Users\<intern>\Downloads\SupportTool.ps1`

**Mitigations:**

- Block execution in Downloads, Desktop, Temp using WDAC / AppLocker
    
- Monitor for executions where:
    
    - Process.CommandLine contains `C:\Users\*\Downloads\`
        
    - FileCreated events appear in Downloads with *.ps1 / *.exe / *.lnk
---
## 🔍 **3. Harden Scheduled Task Abuse**
[Table of Contents](#table-of-contents)

**Why:** Persistence was created via:  
`Schtasks.exe /Create /SC ONLOGON /TN SupportToolUpdater ...`

**Mitigations:**

- Restrict scheduled task creation to admins
    
- Monitor for schtasks.exe spawning from PowerShell
    
- Enable Windows Event Logs for Scheduled Tasks (Operational channel)
    
- Alert on task names with benign-sounding names (`*Updater`, `*Support*`, etc.)
---
## 🚫 **4. Prevent Registry Run Key Persistence**
[Table of Contents](#table-of-contents)

**Why:** A fallback autorun mechanism was created (Flag 14).

**Mitigations:**

- Monitor & block modifications to:
    
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
        
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
        
- Use Sysmon Event ID 13 (RegistryValueSet)
    
- Lock down autorun entries via GPO
---
## 🌐 **5. Improve Network Egress Controls**
[Table of Contents](#table-of-contents)

**Why:** The attacker performed:

- DNS checks
    
- Egress validation
    
- An outbound exfil attempt
    
    - (Flag 12: unusual destination IP `100.29.147.161`)

**Mitigations:**

- Block outbound traffic to non-approved external IPs
    
- Require egress via proxy with TLS inspection
    
- Implement DNS filtering (block non-corp resolvers)
    
- Alert on:
    
    - PowerShell making outbound connections
        
    - Nslookup being used with suspicious hostnames
        
    - Requests to unknown external IPs
---
## 🛡 **6. Enable/Improve Endpoint Security Controls**
[Table of Contents](#table-of-contents)

**Why:** Defender was tampered with (Flag 2).

**Mitigations:**

- Turn on Tamper Protection in Microsoft Defender
    
- Prevent users from stopping/reconfiguring Defender services
    
- Monitor for:
    
    - Write operations to `Set-MpPreference`
        
    - Unusual Defender artifacts like `DefenderTamperArtifact.txt/.lnk`
---
## 🧩 **7. Block Living-off-the-Land Binaries (LOLBins)**
[Table of Contents](#table-of-contents)

The attacker used LOLBins such as:

- **whoami.exe**
    
- **ipconfig.exe**
    
- **qwinsta.exe / query session**
    
- **WMIC.exe**
    
- **cmd.exe /c tasklist /v**
    

**Mitigations:**

- Restrict unused LOLBins (via AppLocker/WDAC)
    
- Log and alert on suspicious commands:
    
    - `query session`
        
    - `wmic logicaldisk`
        
    - `tasklist /v`
        
    - `whoami /priv`
---
## 🔐 **8. Least Privilege Enforcement**
[Table of Contents](#table-of-contents)

**Why:** The user was allowed to do:

- PowerShell script execution
    
- Create scheduled tasks
    
- Modify autorun entries
**Mitigations:**

- Remove local admin privileges
    
- Restrict scripting capability for interns and non-technical staff
    
- Apply LAPS to rotate local admin creds
---
## 📦 **9. User Education & Phishing Awareness**
[Table of Contents](#table-of-contents)

**Why:** The initial malicious "support tool" masqueraded as a legitimate file.

**Mitigations:**

- Train users not to run unknown scripts/tools
    
- Warn about .ps1 files in downloads
    
- Highlight risks of “helpdesk tools” sent externally
---
## 🧵 **10. Improve SOC Detection Logic**
[Table of Contents](#table-of-contents)

Create detection rules for:
### Indicators of Execution

- PowerShell with `ExecutionPolicy Bypass`
    
- Cmd launching PowerShell
    
- PowerShell launching NSLookup
    
- Creation of `.lnk` files outside standard directories
    
### Indicators of Persistence

- schtasks.exe creating new tasks
    
- Registry Run key modifications
    
### Indicators of Exfiltration

- Outbound connections from PowerShell
    
- Repeated DNS lookups to untrusted domains
---
## 🗂 **11. File System Hardening**
[Table of Contents](#table-of-contents)

**Why:** The attacker staged artifacts in:  
`C:\Users\Public\ReconArtifacts.zip`

**Mitigations:**

- Restrict write permissions to the Public directory
    
- Alert when ZIPs or archives are created unexpectedly
    
- Block creation of artifacts in:
    
    - Public
        
    - Temp
        
    - Downloads
---
# ⭐ **Top 5 Quick-Win Mitigations to Implement Immediately**
[Table of Contents](#table-of-contents)

1. **Enable PowerShell logging + restrict script execution**
    
2. **Enforce WDAC / AppLocker rules on Downloads & Temp execution**
    
3. **Block suspicious outbound connections via DNS filtering + egress firewall**
    
4. **Enable Tamper Protection in Microsoft Defender**
    
5. **Detect + alert on Scheduled Task creation from PowerShell**


