![[Pasted image 20260117202240.png]]

------
## FLAG 0 - Identify the device

<img width="653" height="471" alt="image" src="https://github.com/user-attachments/assets/f6bb48af-6ac4-411e-b7c3-4aa59e003854" />


------
## FLAG 1 - Unique Maintenance File

<img width="630" height="542" alt="image" src="https://github.com/user-attachments/assets/3fc8bc1f-aaa0-451c-a19b-25103daf0a09" />


```
//FLAG 1 2025-11-23T03:44:06.0351762Z
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where FileName matches regex @"\.(ps1|cmd|bat|vbs|js)$"
| where FolderPath contains "maintenance"
| project TimeGenerated, ActionType, DeviceName, FileName, FileSize, FolderPath, InitiatingProcessAccountDomain
```

<img width="1616" height="214" alt="image" src="https://github.com/user-attachments/assets/2f52c612-12c6-4aba-9147-a1ab22473ef4" />


------

## FLAG 2 - Outbound Beacon Indicator

<img width="618" height="501" alt="image" src="https://github.com/user-attachments/assets/76c9afba-b97d-48cc-98e2-14060780ca73" />


```
//FLAG 2
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "maintenance"
| project TimeGenerated, InitiatingProcessCommandLine
```

<img width="873" height="227" alt="image" src="https://github.com/user-attachments/assets/d870f700-3359-4ca6-9556-3f5316d99f20" />


----

## FLAG 3 - Identify the beacon destination

<img width="624" height="569" alt="image" src="https://github.com/user-attachments/assets/f67ea849-cc93-404e-99ed-cfb5ba231909" />


```
//FLAG 3 2025-11-23T03:46:08.400686Z
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "maintenance"
| project TimeGenerated, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessCommandLine
```

<img width="1629" height="165" alt="image" src="https://github.com/user-attachments/assets/5b6ec9be-ea53-412e-a809-d9be4de7dfea" />



----

## FLAG 4 - Confirm the Successful Beacon Timestamp

<img width="619" height="735" alt="image" src="https://github.com/user-attachments/assets/1ed4d6cd-d2e1-4ad5-9fe0-67559cb14a05" />


```
//FLAG 4
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessCommandLine contains "maintenance"
| project TimeGenerated, ActionType, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<img width="2048" height="742" alt="image" src="https://github.com/user-attachments/assets/558152e2-34a4-4f38-8548-6a5f0057675e" />



------

## FLAG 5 - Unexpected Staging Activity Detected

<img width="619" height="530" alt="image" src="https://github.com/user-attachments/assets/271be1bf-99d4-41d8-8dfb-8ea1136f6ee0" />


```
//FLAG 5
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where DeviceName == "ch-ops-wks02"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains "inventory"
| project TimeGenerated, ActionType, SHA256, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="2048" height="744" alt="image" src="https://github.com/user-attachments/assets/0311a13c-250b-42cd-baff-e7622ccbed8a" />


----
## FLAG 6 - Confirm the Staged File's Integrity

<img width="600" height="556" alt="image" src="https://github.com/user-attachments/assets/06764f6b-d48c-4d89-95e4-c6b64a6d495b" />


```
//FLAG 6
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where DeviceName == "ch-ops-wks02"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains "inventory"
| project TimeGenerated, ActionType, SHA256, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="1870" height="227" alt="image" src="https://github.com/user-attachments/assets/49698048-f5ac-4f80-9c2b-bc3c176ee7fe" />


-----
## FLAG 7 - Identify the Duplicate Staged Artifact

<img width="611" height="774" alt="image" src="https://github.com/user-attachments/assets/1c7ed295-cadd-418f-aa30-2c46ac9d93bf" />


```
//FLAG 7
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where DeviceName == "ch-ops-wks02"
| where ActionType in ("FileCreated", "FileModified")
| where FolderPath contains "inventory"
| project TimeGenerated, ActionType, SHA256, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="1914" height="716" alt="image" src="https://github.com/user-attachments/assets/717fcab6-f61a-455e-a20c-93a972c106f4" />


-----
## FLAG 8 - Suspicious Registry Activity

<img width="622" height="498" alt="Pasted image 20260130075510" src="https://github.com/user-attachments/assets/be21ca41-f7c5-4466-9a99-899818aa4857" />


```
//FLAG 8 2025-11-25T04:14:40.9857945Z
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-25T04:14:00Z) .. datetime(2025-11-25T04:17:00Z))
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="1191" height="224" alt="image" src="https://github.com/user-attachments/assets/6d58f9f3-80c7-4c2a-a21a-85d5a6bde342" />


---
## FLAG 9 - Scheduled Task Persistence

<img width="613" height="460" alt="image" src="https://github.com/user-attachments/assets/0b19f275-704a-4090-97e8-07ac040ca9cd" />

```
//FLAG 9 2025-11-25T04:15:26.9010509Z
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-25T04:14:00Z) .. datetime(2025-11-25T04:17:00Z))
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="1319" height="199" alt="image" src="https://github.com/user-attachments/assets/03794421-d53a-49fa-9bbc-269abb0a0856" />


-----

## FLAG 10 - Registry-based Persistence

<img width="601" height="614" alt="image" src="https://github.com/user-attachments/assets/4ff1c1ac-2fc9-4408-9f8b-b10694339f4e" />

```
//FLAG 10 2025-11-25T04:24:48.8957038Z
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-25T04:14:00Z) .. datetime(2025-11-25T04:17:00Z))
| where InitiatingProcessFileName contains "powershell"
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet")
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="1660" height="253" alt="image" src="https://github.com/user-attachments/assets/27c4d7b5-3dc1-41f9-9823-846f169ae315" />

-----

## FLAG 11 - Privilege Escalation Event Timestamp

<img width="614" height="433" alt="image" src="https://github.com/user-attachments/assets/31ed2d1e-0936-4e3c-96df-ce0551380e40" />

```
//FLAG 11
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated  between (datetime(2025-11-05T01:00:00Z) .. datetime(2025-12-05T01:10:00Z))
| where AdditionalFields contains "ConfigAdjust"
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    AdditionalFields,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="1261" height="535" alt="image" src="https://github.com/user-attachments/assets/4c149268-43b3-4bcb-8f71-febd3feb328d" />

-----
## FLAG 12 - Identify the AV Exclusion Attempt

<img width="618" height="251" alt="image" src="https://github.com/user-attachments/assets/b46c12bb-5cda-43d5-ba5f-2f75981b426b" />

```
//FLAG 12 - 2025-11-30T01:03:54.2666391Z
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-05T00:00:00Z) .. datetime(2025-12-05T23:59:59Z))
| project TimeGenerated, ActionType, AdditionalFields, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| where InitiatingProcessCommandLine contains "Exclusion"
```

<img width="2021" height="320" alt="image" src="https://github.com/user-attachments/assets/eb3c4a4b-ecc5-40c8-8009-a20f46447099" />

----

## FLAG 13 - PowerShell Encoded Command Execution

<img width="609" height="598" alt="image" src="https://github.com/user-attachments/assets/cfc716fe-809d-40fd-b09f-f39d756922be" />

```
//FLAG 13
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where AccountName == "ops.maintenance"
| where TimeGenerated between (datetime(2025-11-05T00:00:00Z) .. datetime(2025-12-05T23:59:59Z))
| where ProcessCommandLine contains "-EncodedCommand"
| project TimeGenerated, AccountName, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
```

<img width="2048" height="701" alt="image" src="https://github.com/user-attachments/assets/0f6727a7-1d04-4101-919a-57073cc1c305" />

-----

## FLAG 14 - Privilege Token Modification

<img width="615" height="517" alt="image" src="https://github.com/user-attachments/assets/2e70c1ca-9927-457a-b45b-075fcb9a9e0a" />

```
//FLAG 14 
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where AdditionalFields contains "tokenChangeDescription"
//| where FileName matches regex @"\.(ps1|cmd|bat|vbs|js)$"
//| where FolderPath contains "maintenance"
//| where FileName == "MaintenanceRunner_Distributed.ps1"
| project
    TimeGenerated,
    DeviceName,
    ActionType,
    AdditionalFields,
    InitiatingProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
```

<img width="2101" height="222" alt="image" src="https://github.com/user-attachments/assets/4d9bae80-f50a-465e-bc3a-4408c5a99630" />

-----

## FLAG 15 - Whose Token Was Modified?

<img width="619" height="846" alt="image" src="https://github.com/user-attachments/assets/240ce3b7-6e50-4fdd-80b4-f05291c70959" />

```
//FLAG 15
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where AdditionalFields contains "tokenChangeDescription"
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
```

<img width="972" height="606" alt="image" src="https://github.com/user-attachments/assets/3be37290-2f5e-49af-9426-5024bf8ae831" />

-------

## FLAG 16 - Ingress Tool Transfer from External Dynamic Tunnel

<img width="605" height="335" alt="Pasted image 20260119223502" src="https://github.com/user-attachments/assets/3f740bc7-dd4a-4bd3-b3e0-7f3518947e65" />

```
//FLAG 16
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where ProcessCommandLine contains "curl"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1301" height="515" alt="image" src="https://github.com/user-attachments/assets/52ac6c84-f525-44dc-a3c4-4a5530a43c86" />

-----

## FLAG 17 - Identify the External Download Source

<img width="613" height="356" alt="image" src="https://github.com/user-attachments/assets/8e9df3a1-7e08-45ed-a713-2e6d2ee71963" />

```
//FLAG 17
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where ProcessCommandLine contains "curl"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

<img width="1190" height="337" alt="image" src="https://github.com/user-attachments/assets/34f381f9-3158-4c71-9506-4e5c02052978" />

-----

## FLAG 18 - Execution of the Staged Unsigned Binary

<img width="590" height="446" alt="image" src="https://github.com/user-attachments/assets/7b543f24-a656-4a9b-8d28-4446f6a268ba" />

```
//FLAG 16 / 17 / 18
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where AccountName == "chadmin"
| where ProcessCommandLine contains "curl.exe"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<img width="1380" height="369" alt="image" src="https://github.com/user-attachments/assets/74857b76-2e42-4974-9fc7-851783e18f53" />

-----

## FLAG 19 - Identify the External IP Contacted by the Executable

<img width="598" height="366" alt="image" src="https://github.com/user-attachments/assets/0a1057e7-9bdf-45bf-96e3-e984670c2b4f" />

```
//FLAG 19
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where ActionType == "ConnectionFailed"
| where RemotePort == 11746
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol, LocalIP, LocalPort, InitiatingProcessAccountName
| order by TimeGenerated asc
```

<img width="437" height="310" alt="image" src="https://github.com/user-attachments/assets/4bb45859-4d43-40f2-8e08-cea30f3b3532" />

-----

## FLAG 20 - Persistence via Startup Folder Placement

<img width="605" height="374" alt="image" src="https://github.com/user-attachments/assets/6ed482e1-ff03-4df7-8d2e-97f1b5116a2f" />

```
//FLAG 20
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where FolderPath contains @"C:\ProgramData\Microsoft\Windows\Start"
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

<img width="1633" height="616" alt="image" src="https://github.com/user-attachments/assets/72d8bd0a-d363-4683-a794-9f6737b9dc25" />

-----

## FLAG 21 - Identify the Remote Session Source Device

![](file:///C:/Users/Wickens/Pictures/Screenshots/Screenshot%202026-01-19%20235845.png)

```
//FLAG 21
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where AccountName == "chadmin"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName
| order by TimeGenerated asc
```

![](file:///C:/Users/Wickens/Pictures/Screenshots/Screenshot%202026-01-19%20235858.png)

----

## FLAG 22 - Identify the Remote Session IP Address

<img width="607" height="396" alt="image" src="https://github.com/user-attachments/assets/a61ed42c-6709-4daf-81e7-77f3ec4dcb40" />

```
//FLAG 22
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where AccountName == "chadmin"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
```

<img width="1773" height="623" alt="image" src="https://github.com/user-attachments/assets/367fbc5f-9c05-4157-bf4e-54a5e0aac601" />


-----

## FLAG 23 - Identify the Internal Pivot Host Used by the Attacker

<img width="601" height="394" alt="image" src="https://github.com/user-attachments/assets/fe22cc34-e261-4b1e-bebf-e587315c0c28" />

```
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| order by TimeGenerated asc
| where InitiatingProcessRemoteSessionIP == "10.168.0.6"
```

<img width="804" height="229" alt="image" src="https://github.com/user-attachments/assets/7abe6d2e-92d9-478a-b0c1-32bb318bce9a" />

----

## FLAG 24 - Identify the First Suspicious Logon Event

<img width="556" height="624" alt="image" src="https://github.com/user-attachments/assets/7d21fdcc-167b-4697-b80a-e81cc0bf34ba" />

```
//FLAG 24
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where RemoteDeviceName == "对手"
| project
    TimeGenerated,
    AccountName,
    LogonType,
    RemoteIP,
    RemotePort,
    RemoteDeviceName
| order by TimeGenerated asc
```

<img width="1071" height="225" alt="image" src="https://github.com/user-attachments/assets/c1de1632-b51b-4b83-b65b-3bd2fa4db1e1" />


-------------

## FLAG 25 - IP Address Used During the First Suspicious Logon

<img width="624" height="379" alt="image" src="https://github.com/user-attachments/assets/4ff8ae33-cb15-4b2a-8674-b4581e164f0c" />

```
//FLAG 25
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where RemoteDeviceName == "对手"
| project
    TimeGenerated,
    AccountName,
    LogonType,
    RemoteIP,
    RemotePort,
    RemoteDeviceName
| order by TimeGenerated asc
```

<img width="1071" height="225" alt="image" src="https://github.com/user-attachments/assets/8aeac57c-a844-4ec2-8874-28973150d305" />

----

## FLAG 26 - Account Used During the First Suspicious Logon

<img width="609" height="431" alt="image" src="https://github.com/user-attachments/assets/61344456-e58a-4803-a235-00394f658e12" />

```
//FLAG 26
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where RemoteDeviceName == "对手"
| project
    TimeGenerated,
    AccountName,
    LogonType,
    RemoteIP,
    RemotePort,
    RemoteDeviceName
| order by TimeGenerated asc
```

<img width="1071" height="225" alt="image" src="https://github.com/user-attachments/assets/6efead65-020e-43e1-85f7-812c01f51204" />

----

## FLAG 27 - Determine the Attacker's Geographic Region

<img width="613" height="525" alt="image" src="https://github.com/user-attachments/assets/0de4b686-57cf-4806-9586-88ec68f2d7e0" />

```
//FLAG 27
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where RemoteIP == "104.164.168.17"
| extend geo = geo_info_from_ip_address(RemoteIP)
| project TimeGenerated, RemoteIP, geo.country, geo.region, geo.city
```

<img width="910" height="595" alt="image" src="https://github.com/user-attachments/assets/fadc6873-406c-42ad-8911-8278bb560b8b" />

----

## FLAG 28 - First Process Launched After the Attacker Logged In

<img width="601" height="564" alt="image" src="https://github.com/user-attachments/assets/56eedf74-464d-41aa-bd41-fb2a73a355b3" />

```
//FLAG 28 / 29
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| where TimeGenerated > datetime(2025-11-23 03:08:31.184)
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| sort by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName
```

<img width="1087" height="595" alt="image" src="https://github.com/user-attachments/assets/c41ffaf5-fe8a-4f66-ac95-630d10f867bf" />


-----

## FLAG 29 - Identify the First File the Attacker Accessed

<img width="605" height="469" alt="image" src="https://github.com/user-attachments/assets/7c145bfa-77b5-477a-baef-b72bc2ec2ac6" />

```
//FLAG 29
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| where TimeGenerated > datetime(2025-11-23 03:08:31.184)
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| sort by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName
```

<img width="1414" height="200" alt="image" src="https://github.com/user-attachments/assets/7a9b7446-6f8d-478f-85ea-a290cf336b7f" />

-------

## FLAG 30 - Determine the Attacker's Next Action After Reading the File

<img width="599" height="548" alt="image" src="https://github.com/user-attachments/assets/f362497b-890f-407d-bd5f-9896f9971c4d" />

```
//FLAG 30
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where AccountName == "chadmin"
| where InitiatingProcessRemoteSessionDeviceName == "对手"
| where TimeGenerated > datetime(2025-11-23 03:08:31.184)
| sort by TimeGenerated asc
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
```

<img width="1343" height="307" alt="image" src="https://github.com/user-attachments/assets/130964e0-f238-4cfa-87c4-abc056b0879a" />

-----

## FLAG 31 - Identify the Next Account Accessed After Recon

<img width="606" height="542" alt="image" src="https://github.com/user-attachments/assets/2297db80-135a-40f9-b33e-ef48d994501f" />

```
//FLAG 31
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-01) .. datetime(2025-12-5))
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated > datetime(2025-11-23 03:08:31.184)
| where RemoteIP == "104.164.168.17"
| sort by TimeGenerated asc
| project TimeGenerated, AccountName, LogonType, RemoteIP
```

<img width="751" height="595" alt="image" src="https://github.com/user-attachments/assets/0147424d-dc33-4e45-9ba7-dab3e7eaf212" />

-----

After working backward through the attacker’s activity — from persistence artifacts to reconnaissance actions, then retracing their initial access — the full intrusion chain becomes clear. Each flag guided the analyst through identifying how the adversary entered the system, which accounts they leveraged, how they enumerated the host, and how they established outbound control via a reverse shell delivered through an ngrok tunnel.

By rebuilding the timeline from the _inside out_, the investigation not only surfaced the attacker’s tooling and behavior, but clarified intent: credential harvesting, situational awareness, and staging for remote command-and-control. Indicators such as remote session IPs, logon patterns, suspicious processes, and persistence paths provided the necessary context to confirm deliberate malicious access rather than benign administrative activity.

**Logical Flow & Analyst Reasoning**

**0 → 1 🔍**  
A suspicious activity window is identified on CH-OPS-WKS02. Analysts anchor the starting point by validating host identity and establishing the timeframe of abnormal behavior.

**1 → 2 🔍**  
Unusual maintenance activity and script execution stand out. Analysts question whether this was legitimate IT work or the beginning of attacker tooling.

**2 → 3 🔍**  
Outbound connectivity attempts expose a nonstandard external destination. This raises concern that the script is beaconing rather than performing diagnostics.

**3 → 4 🔍**  
Successful outbound traffic confirms a live connection. Analysts pivot to identify the destination and whether this aligns with corporate endpoints — it does not.

**4 → 5 🔍**  
Disk activity follows shortly after beaconing. A new file appears, suggesting staging or tool transfer. Analysts catalog file properties and hashes.

**5 → 6 🔍**  
Hash mismatch comparisons reveal differing versions of staged files. This raises suspicion of modification or deception during upload.

**6 → 7 🔍**  
Additional staging artifacts appear in multiple directories. The attacker seems to be preparing the environment for future operations.

**7 → 8 🔍**  
Registry queries indicate that the attacker is exploring credential or privilege-related keys. Analysts question whether escalation is being attempted.

**8 → 9 🔍**  
Privilege manipulation events, including token modifications, confirm the attacker probed escalation pathways. This validates the earlier registry activity.

**9 → 10 🔍**  
Shortly after escalation attempts, the attacker reaches out externally to download a new payload. This establishes the transition from recon to tool deployment.

**10 → 11 🔍**  
Execution of the downloaded file marks a significant shift. Analysts inspect command-line arguments to determine purpose.

**11 → 12 🔍**  
Network events reveal that the binary establishes outbound connectivity via an ngrok TCP tunnel. This confirms external control infrastructure.

**12 → 13 🔍**  
Persistence emerges: the file is placed in the Startup folder. This ensures automatic execution on future logons and confirms foothold intent.

**13 → 14 🔍**  
Analysts backtrack the origin of execution. Remote session metadata identifies the suspicious device name used for initial access.

**14 → 15 🔍**  
That device name is tied to several internal IPs, hinting at pivoting or multiple session attempts. Analysts extract all related IPs for correlation.

**15 → 16 🔍**  
Sorting by timestamp reveals which internal IP connected first. This establishes the earliest footprint inside the network.

**16 → 17 🔍**  
Pivoting to logon events, analysts identify the earliest suspicious logon timestamp linked to the malicious device or IP.

**17 → 18 🔍**  
The RemoteIP associated with the first logon reveals the attacker’s initial entry vector.

**18 → 19 🔍**  
The corresponding account used during this logon surfaces the credentials the attacker leveraged to enter the environment.

**19 → 20 🔍**  
Analysts correlate all accounts used across the attacker’s activity. This helps identify lateral movement or credential testing.

**20 → 21 🔍**  
The first process launched immediately after logon exposes the attacker’s priority — reconnaissance, validation, or environment orientation.

**21 → 22 🔍**  
Following that, the attacker opens a file containing credentials. Analysts understand this as targeted harvesting behavior.

**22 → 23 🔍**  
The subsequent action reveals whether the attacker attempted to use those credentials or continued recon — showcasing tactical decision-making.

**23 → 24 🔍**  
Events around remote IP geolocation help determine the attacker’s likely region or hosting provider, adding intelligence context.

**24 → 25 🔍**  
Outbound HTTP/TCP attempts show whether the attacker established control channels beyond the ngrok tunnel.

**25 → 26 🔍**  
Analysts review session lifecycles to identify active persistence channels and whether any were redundant or contingency mechanisms.

**26 → 27 🔍**  
Registry-based Run keys or startup file placements point toward deliberate re-entry capability — the attacker prepared for repeated access.

**27 → 28 🔍**  
Subtle cleanup behaviors appear. Analysts determine whether the attacker attempted to blend into system logs or overwrite artifacts.

**28 → 29 🔍**  
File modification timestamps and process sequences help analysts reconstruct staging order and validate whether exfiltration occurred.

**29 → 30 🔍**  
Outbound DNS or HTTP queries reveal whether the attacker validated external reachability for future exfil movements.

**30 → 31 🔍**  
Analysts confirm whether compression or aggregation behavior occurred — attackers often bundle evidence before exfil attempts.

**31 → 32 🔍**  
Finally, analysts correlate all elements — recon, credential access, payload deployment, persistence, and outbound C2 — closing out the narrative and reconstructing the full attack chain.

![[Pasted image 20260120162640.png]]

