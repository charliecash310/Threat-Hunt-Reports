# Threat Hunt Scenario - Assistance

<img width="647" height="551" alt="image" src="https://github.com/user-attachments/assets/3dbc54c7-3132-4ed4-8601-b339dcc1483f" />

# Table of Contents

Detection and Analysis:
- [Flag 1 - Initial Execution Detection](#flag-1---initial-execution-detection) 
- [Flag 2 - Defense Disabling]()
- [Flag 3 - Quick Data Probe]()
- [Flag 4 - Host Context Recon]()
- [Flag 5 - Storage Surface Mapping]()
- [Flag 6 - Connectivity & Name Resolution Check]()
- [Flag 7 - Interactive Session Discovery]()
- [Flag 8 - Runtime Application Inventory]()
- [Flag 9 - Privilege Surface Check]()
- [Flag 10 - Proof-of-Access & Egress Validation]()
- [Flag 11 - Bundling / Staging Artifacts]()
- [Flag 12 - Outbound Transfer Attempt]()
- [Flag 13 - Scheduled Re-Execution Persistence]()
- [Flag 14 - Autorun Fallback Persistence]()
- [Flag 15 - Planted Narrative / Cover Artifact]()
- [Logical Flow & Analyst Reasoning]()
- [Final Notes / Findings]()

MITRE ATT&CK Framework:
- [Flags → MITRE ATT&CK Mapping Table]()
- [Summary of ATT&CK Categories Used]()

Lessons Learned:
- [🔒 1. Strengthen PowerShell Logging & Restrictions]()
- [📁 2. Restrict Execution from User Download Folders]()
- [🔍 3. Harden Scheduled Task Abuse]()
- [🚫 4. Prevent Registry Run Key Persistence]()
- [🌐 5. Improve Network Egress Controls]()
- [🛡 6. Enable/Improve Endpoint Security Controls]()
- [🧩 7. Block Living-off-the-Land Binaries (LOLBins)]()
- [🔐 8. Least Privilege Enforcement]()
- [📦 9. User Education & Phishing Awareness]()
- [🧵 10. Improve SOC Detection Logic]()
- [🗂 11. File System Hardening]()


---
# Report By

`**Date:** October 1st - 15th, 2025`  
`**Analyst:** Grisham DelRosario`  
`**Environment:** Microsoft - Log Analytics Workspace (LAW - Cyber Range)`  
`**Attack Type:** Fake Remote Session/Malicious Help Desk`

---------------

# **Scenario**
`A routine support request should have ended with a reset and reassurance. Instead, the so- called "help" left behind a trail of anomalies that don't add up. What was framed as troubleshooting looked more like an audit of the system itself probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended. And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny. This wasn't remote assistance. It was a misdirection. Your mission this time is to reconstruct the timeline, connect the scattered remnants of  this "support session", and decide what was legitimate, and what was staged. The evidence is here. The question is whether you'll see through the story or believe it.`

---------------------------------------------------
# **Preparation**

<img width="657" height="309" alt="image" src="https://github.com/user-attachments/assets/8942b8bf-b907-47bc-9334-ea9f6ffc6f16" />

<img width="655" height="151" alt="image" src="https://github.com/user-attachments/assets/a763f5e7-4426-4ee3-b02f-beaa98be81a5" />

<img width="715" height="199" alt="image" src="https://github.com/user-attachments/assets/c1dce20f-a108-4b62-a762-2682c38e28e3" />

---

1. Spawning process originating from the download folder. Occurred in the first half of October, so sometime between October 1st -15th?

2. Similar executables, naming patterns, and other traits.

3. Common keywords, `"desk", "help", "support", and "tool"`


<img width="1450" height="575" alt="image" src="https://github.com/user-attachments/assets/f0c6c24a-97fd-4884-8613-8c23a803a964" />

- In order to identify the most suspicious machine based on the given conditions I decided to set a variable called 'keywords' with "desk", "help", "support", and "tool" in order to set up the query. 

- First table I checked to start this hunt was 'DeviceFileEvents.' 

- The keyword "support" also allowed me to find this suspicious filename, " Support_701.txt " that was unusual as I was going through the logs but it allowed me to find the suspicious machine. I kept focus as it was mentioned at starting point several machines were found to share the same types of files - similar executables, naming patterns, and other traits - 


<img width="704" height="217" alt="image" src="https://github.com/user-attachments/assets/ff72c95f-5ce7-43fa-b020-ff28861dc1ae" />



- Ideally, another way I could have found this device without having to think so hard was to have queried the term 
`Intern` for `DeviceName` in order to find the suspicious device, 
`gab-intern-vm`
- This too would have been an easier method to find in order to narrow down the suspicious device.

<img width="1864" height="509" alt="image" src="https://github.com/user-attachments/assets/681a4d63-6f41-4598-82de-2ecb95c6332c" />


---------------------------------------------------
# **Detection and Analysis**

# Flag 1 - Initial Execution Detection


- Throughout the threat hunt, the table `DeviceProcessEvents` was very key in order to examine the logs.

- For Flag 1, we're looking at Initial Execution Detection

- When I read what to hunt and saw 'script', the first thing that came to mind was PowerShell and Command Prompt. Further on, the question asked 

`"What was the first CLI (command line interface) parameter name used during the execution of the suspicious program?"`

- After looking back and forth at was being asked of the flag and examining logs `"unusual execution"` was key in order to find this flag.

- The earliest anomalous execution of powershell being executed was October 9th, 2025 @ 12:22 PM `

<img width="1196" height="127" alt="image" src="https://github.com/user-attachments/assets/ecbd8370-1de8-4876-9cad-4ba3b1dd5cb5" />

<img width="2075" height="384" alt="image" src="https://github.com/user-attachments/assets/87d0806a-00b6-4c40-89f1-1ff60438bee9" />


- Upon looking at the log activity for powershell executables we can see the first CLI parameter is set to `-ExecutionPolicy`.  First time it was executed was on October 6th, 2025 at 6:00:48 AM

- This eventually occurred again for a powershell.exe process called `SupportTool.ps1` for October 9th, 2025 during 12:22:27 PM UTC


---------------------------------------------------

# Flag 2 - Defense Disabling

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


<img width="1252" height="124" alt="image" src="https://github.com/user-attachments/assets/ec4632fa-5264-428d-b380-b6be28e62c1e" />



- For the query, I kept using `Artifact` and used this information to see if there was another file name related to the term.

- I found `ReconArtifacts.zip` and then saw that there was a `DefenderTamperArtifact.lnk` file. 

- The timestamp matches with process creation from the `DeviceProcessEvents` table

- The  `.lnk`  file extension is a shortcut of the filename. Upon researching `.LNK` files, they are often the trigger for malicious scripts and  can be used for malicious purposes.


<img width="1863" height="771" alt="image" src="https://github.com/user-attachments/assets/3a8b87d6-a9f5-4f7b-8a7b-5b2e6369bbf9" />

<img width="1978" height="595" alt="image" src="https://github.com/user-attachments/assets/98852f93-905e-482f-8ab7-6a9cd60ea677" />


---------------------------------------------------

# Flag 3 - Quick Data Probe

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

<img width="1469" height="112" alt="image" src="https://github.com/user-attachments/assets/d85e1e11-089d-4bc3-8dd6-54f963f2c43c" />

<img width="1429" height="354" alt="image" src="https://github.com/user-attachments/assets/95c4faef-340d-47f3-b76d-2fb9694019c4" />

---------------------------------------------------

# Flag 4 - Host Context Recon

<img width="660" height="510" alt="image" src="https://github.com/user-attachments/assets/bfaec963-a973-44e1-b905-5ee9395f2399" />


- While going through the logs, and reading this flag I recall seeing an executable called ' qwinsta.exe ' I had to look up this program and it is a command on windows that can: `Display information about sessions on a Remote Desktop Session Host server`

- This made sense in terms of gathering host and user context information.

- Working within the timestamp of `2025-10-09T12:51:44.3425653Z` we can see that this was the last recon attempt for the query session for the attacker to enumerate.

<img width="1111" height="121" alt="image" src="https://github.com/user-attachments/assets/fa7b7d31-3378-4812-836c-ae1b89161b7b" />

<img width="1855" height="84" alt="image" src="https://github.com/user-attachments/assets/4a85f06f-890f-4671-a5b7-0925eff8dcb9" />


---------------------------------------------------

# Flag 5 - Storage Surface Mapping

<img width="677" height="503" alt="image" src="https://github.com/user-attachments/assets/823b8907-4acd-4922-a58e-9010bccace05" />


- After looking at the `qwinsta.exe` process that was created in the logs.I noticed the command prompt executable that showed logical disk that comes after the `qwinsta.exe` executable.

- This made sense in terms of data as to where it lives and the data that can be discovered such as 'storage'. 

- Decided to search for 'WMIC.exe' command and found out that the 'logical disk' is `used to query Windows for information about a computer's local drives`. 

- We can see the `TimeGenerated` column is still within 12:50:00 PM-12:51:00 PM.

	`Time Generated @ 2025-10-09T12:51:18.3848072Z`
	`"cmd.exe" /c wmic logicaldisk get name,freespace,size`

<img width="1168" height="107" alt="image" src="https://github.com/user-attachments/assets/1da00a3b-5db3-42bd-95e9-e45a6a2416a9" />

<img width="1190" height="715" alt="image" src="https://github.com/user-attachments/assets/0d1966d1-68e4-4a74-9437-f87e71ca951b" />



---------------------------------------------------

# Flag 6 - Connectivity & Name Resolution Check

<img width="659" height="502" alt="image" src="https://github.com/user-attachments/assets/e6c62aa4-f755-4c5b-95cd-0683ea774d05" />

- What was key to this question was network related events. Especially when it comes to DNS and outbound connections.

- I decided to check the `InitiatingProcessParentFileName` column in the `DeviceNetworkEvents` table and try to narrow down unusual PowerShell activity.

- I made sure to stay focused on October 9th 2025 during the time of `12:50-12:55 PM` as other events from `DeviceProcessEvents` and `DeviceFileEvents` were very important in relation to `SupportToolScript.ps1`. `Powershell` executables have been very prevalent throughout the hunt. 

<img width="1993" height="122" alt="image" src="https://github.com/user-attachments/assets/e832c5a8-2319-488c-8701-fa37526d84ab" />

<img width="2114" height="679" alt="image" src="https://github.com/user-attachments/assets/5abdd300-1878-4300-a79c-894ab1ab0bd8" />


---------------------------------------------------

# Flag 7 - Interactive Session Discovery

<img width="661" height="467" alt="image" src="https://github.com/user-attachments/assets/ac36c23e-8e4a-4ece-a14f-3938832b6061" />


`Keywords: Session, Initiate Process, Unique`

- Had to get a little help with this one from another user without having to give away the answer and eventually I had a lightbulb moment.

- It was actually really simple. When I read the question "What is the unique ID of the initiating process?" I kept focusing for the column `InitiatingProcessID`

- I was so stumped that I feel the process identification task number was staring at me.  I had to pivot and got the hint from a user to project `InitiatingProcessUniqueId`

- I should have considered the term `unique` in order to find the number of `InitiatingProcessUniqueId`

	`2533274790397065`


<img width="1723" height="95" alt="image" src="https://github.com/user-attachments/assets/19b3f1f5-c130-4b66-a178-7ff16cc32dc1" />

<img width="2278" height="711" alt="image" src="https://github.com/user-attachments/assets/955a3d47-e687-433e-aa54-33abd7a9bc92" />

<img width="1715" height="104" alt="image" src="https://github.com/user-attachments/assets/4c05e29f-a378-42a3-a41e-f4ad7f244d28" />

<img width="1962" height="483" alt="image" src="https://github.com/user-attachments/assets/56d4dfd4-4c65-4d5d-8a49-6b36a0bc5765" />

---------------------------------------------------

# Flag 8 - Runtime Application Inventory

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

<img width="1506" height="132" alt="image" src="https://github.com/user-attachments/assets/68b42c61-03bd-41ed-b717-3b7dd0af90c1" />

<img width="1966" height="90" alt="image" src="https://github.com/user-attachments/assets/8c02e582-4206-4e10-a113-0e41902e4d42" />

---------------------------------------------------

# Flag 9 - Privilege Surface Check

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

<img width="1494" height="121" alt="image" src="https://github.com/user-attachments/assets/39465d67-1977-4d65-84be-9bab3e458317" />

<img width="1189" height="229" alt="image" src="https://github.com/user-attachments/assets/5af37ea0-29ff-48df-99a1-973891d8b14b" />

---------------------------------------------------

# Flag 10 - Proof-of-Access & Egress Validation

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

<img width="1651" height="138" alt="image" src="https://github.com/user-attachments/assets/fcd73d08-c31c-47df-bd31-454177670959" />

<img width="1586" height="117" alt="image" src="https://github.com/user-attachments/assets/ed079127-1942-4d24-a3f4-1d00ee82b28a" />



---------------------------------------------------

# Flag 11 - Bundling / Staging Artifacts

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

<img width="768" height="123" alt="image" src="https://github.com/user-attachments/assets/281b5337-bd69-44c2-8b6c-5b42be4d9c67" />

<img width="1343" height="121" alt="image" src="https://github.com/user-attachments/assets/cfb6ee2f-f8f1-4309-b523-37b0043bb94f" />

---------------------------------------------------

# Flag 12 - Outbound Transfer Attempt


<img width="649" height="519" alt="image" src="https://github.com/user-attachments/assets/bff3f5f3-a630-4ab1-8d8c-496b3e2b82da" />



- Recall the same query from Flag 10. The IP of the last unusual outbound connection was listed to a website called `httpbin.org` .

- The `RemoteIP` column showed the IP, `100.29.147.161`, of the outbound connection

<img width="1220" height="137" alt="image" src="https://github.com/user-attachments/assets/48d39b74-91cc-4325-a9bc-84d3860c8bbe" />

<img width="1564" height="118" alt="image" src="https://github.com/user-attachments/assets/898d9787-38a5-44c4-a660-2f68cf4c3172" />


---------------------------------------------------

# Flag 13 - Scheduled Re-Execution Persistence

<img width="648" height="475" alt="image" src="https://github.com/user-attachments/assets/e1b1dd04-64f4-4e69-96e8-66d8803e1e82" />


- The question asks for `task name`

<img width="1492" height="134" alt="image" src="https://github.com/user-attachments/assets/cd510383-0c72-4356-a8ec-d4355db571b0" />

<img width="2143" height="482" alt="image" src="https://github.com/user-attachments/assets/02ca3943-1b5b-4338-8a72-e336423fe802" />



- We can see in the output of `schtasks.exe` that the task name `/TN` flag is part of the process command line. 

- **We can see the value of the task name is `SupportToolUpdater`

---------------------------------------------------

# Flag 14 - Autorun Fallback Persistence

<img width="648" height="559" alt="image" src="https://github.com/user-attachments/assets/daa04793-cfa7-4559-94e6-a7f1cd1acc60" />

- The table `RemoteAssistUpdater` returned nothing. 


---------------------------------------------------

# Flag 15 - Planted Narrative / Cover Artifact

<img width="659" height="523" alt="image" src="https://github.com/user-attachments/assets/2a834215-ef61-46ec-afbd-1c895984cd43" />

- The actor **left a cover story behind**, and the hint gives it away:

> **Hint:** The actor opened it for some reason.

- That means we’re hunting for a file the attacker **manually opened**, likely something meant to _explain_ or _justify_ what they were doing. 

- The attacker delivered `SupportTool.ps1` to the victim’s Downloads folder and then executed it via the Windows shell, causing Explorer to create `SupportTool.lnk` in the Recent items directory.

- This ties the script to an interactive session (likely the `g4bri3Intern` profile) and demonstrates user-level execution (MITRE ATT&CK T1204 – User Execution).

---------------------------------------------------

# Logical Flow & Analyst Reasoning

<img width="660" height="939" alt="image" src="https://github.com/user-attachments/assets/a7c631cc-c3df-4090-af5e-ccfa777325cb" />

<img width="650" height="889" alt="image" src="https://github.com/user-attachments/assets/dd20c29b-8db8-47ab-b673-1ed667b0c615" />

---------------------------------------------------

# Final Notes / Findings

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

---------------------------------------------------

# Summary of ATT&CK Categories Used

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

Mitigations for This Threat Hunt

Each mitigation is mapped to the techniques observed in the hunt, prioritized by impact and feasibility.

---
## 🔒 **1. Strengthen PowerShell Logging & Restrictions**

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

**Why:** Initial execution occurred from:  
`C:\Users\<intern>\Downloads\SupportTool.ps1`

**Mitigations:**

- Block execution in Downloads, Desktop, Temp using WDAC / AppLocker
    
- Monitor for executions where:
    
    - Process.CommandLine contains `C:\Users\*\Downloads\`
        
    - FileCreated events appear in Downloads with *.ps1 / *.exe / *.lnk
---
## 🔍 **3. Harden Scheduled Task Abuse**

**Why:** Persistence was created via:  
`Schtasks.exe /Create /SC ONLOGON /TN SupportToolUpdater ...`

**Mitigations:**

- Restrict scheduled task creation to admins
    
- Monitor for schtasks.exe spawning from PowerShell
    
- Enable Windows Event Logs for Scheduled Tasks (Operational channel)
    
- Alert on task names with benign-sounding names (`*Updater`, `*Support*`, etc.)
---
## 🚫 **4. Prevent Registry Run Key Persistence**

**Why:** A fallback autorun mechanism was created (Flag 14).

**Mitigations:**

- Monitor & block modifications to:
    
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
        
    - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
        
- Use Sysmon Event ID 13 (RegistryValueSet)
    
- Lock down autorun entries via GPO
---
## 🌐 **5. Improve Network Egress Controls**

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

**Why:** Defender was tampered with (Flag 2).

**Mitigations:**

- Turn on Tamper Protection in Microsoft Defender
    
- Prevent users from stopping/reconfiguring Defender services
    
- Monitor for:
    
    - Write operations to `Set-MpPreference`
        
    - Unusual Defender artifacts like `DefenderTamperArtifact.txt/.lnk`
---
## 🧩 **7. Block Living-off-the-Land Binaries (LOLBins)**

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

**Why:** The initial malicious "support tool" masqueraded as a legitimate file.

**Mitigations:**

- Train users not to run unknown scripts/tools
    
- Warn about .ps1 files in downloads
    
- Highlight risks of “helpdesk tools” sent externally
---
## 🧵 **10. Improve SOC Detection Logic**

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

1. **Enable PowerShell logging + restrict script execution**
    
2. **Enforce WDAC / AppLocker rules on Downloads & Temp execution**
    
3. **Block suspicious outbound connections via DNS filtering + egress firewall**
    
4. **Enable Tamper Protection in Microsoft Defender**
    
5. **Detect + alert on Scheduled Task creation from PowerShell**


