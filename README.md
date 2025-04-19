# Threat-Hunting-Scenario-Persistence
## Detection of Unauthorized Browser Persistence ##

## 🧪 Example Scenario

A user reported that each time their system starts up, Microsoft Edge automatically opens to coinbase.com. This behavior was not configured by the user and persisted across reboots. A deeper investigation was initiated on the britt-windows10 device using Microsoft Defender for Endpoint advanced hunting. Findings suggested unauthorized registry-based persistence and suspicious PowerShell activity. Additionally, port scanning activity originating from internal IPs was observed.

## 📊 Query Metadata Table

| Parameter    | Description                                                                   |
|-------------|-------------------------------------------------------------------------------|
| **Name**    | `DeviceRegistryEvents`, `DeviceProcessEvents`, `DeviceNetworkEvents`         |
| **Info**    | MDE Advanced Hunting - Persistence, Network, Process Analysis                |
| **Purpose** | Detect unauthorized browser persistence and suspicious internal port scanning |


## 📅 Timeline Overview

🔍 Persistence and Edge Redirection Activity

Observed Behavior: Microsoft Edge launched with coinbase.com set as the homepage on every reboot.

## 🧩 Detection Queries and Reasoning

1. Registry Persistence Search (Homepage Change)

To detect changes to Microsoft Edge startup behavior, I investigated if the registry was modified to include coinbase.com as a startup parameter:

```kql
DeviceRegistryEvents
| where DeviceName == "britt-windows10"
| where (RegistryKey has "CurrentVersion\\Run" or RegistryKey has "RunOnce")
| where RegistryValueData has "coinbase.com"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc

```


Result: Registry key modified on `2025-04-15T21:38:28Z`, adding a persistence entry launching Edge to coinbase.com.


<img width="1212" alt="image" src="https://github.com/user-attachments/assets/7c9bc7cd-d130-4ea7-a8f4-ddc043fbe261">

2. Process Execution Involving Coinbase

To confirm if the browser was launched via script or manual action, I searched for process executions containing coinbase.com:

```kql
DeviceProcessEvents
| where DeviceName == "britt-windows10"
| where ProcessCommandLine has "coinbase.com"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| order by Timestamp desc

```

Result: Showed the actual PowerShell or browser processes launching the page, confirming automation.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/3c01f088-4862-4d25-97d9-6a3b5d54025b">

3. Broader Registry Change Window

Ran a time-filtered registry query to find if the attacker added other persistence mechanisms post-homepage modification, as attackers often layer persistence to maintain access.

```kql
DeviceRegistryEvents
| where DeviceName == "britt-windows10"
| where RegistryKey has "Run" or RegistryKey has "RunOnce"
| where Timestamp between(datetime(2025-04-15T18:36:23Z) .. datetime(2025-04-17T23:36:23Z))
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc

```

Result: One follow-up registry entry appeared a day later.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/484cda72-b699-43c9-9fe9-502f16d545ef">


📡 Suspicious Network Activity and Exfiltration Check

4. PowerShell-Based Exfiltration/Recon Check

I checked for PowerShell use that might indicate data exfiltration or reconnaissance attempts over non-standard ports to filter out normal web activity and detect possible outbound exfiltration using PowerShell.

```kql
DeviceNetworkEvents
| where DeviceName == "britt-windows10"
| where RemoteIP != "internal_network_range"
| where RemotePort !in (80, 443)
| where InitiatingProcessCommandLine has "powershell.exe"
| where Timestamp between(datetime(2025-04-15T18:36:23Z)..datetime(2025-04-17T23:36:23Z))
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

```

Result: Did not show any unusual exfiltration activity, however, internal port scanning behavior was observed. There were no PowerShell-driven connections to suspicious remote IPs on non-standard ports that would indicate outbound data theft.  THe port scanning was likely an attempt at lateral recon from an attacker.

<img width="1212" alt="image" src="https://github.com/user-attachments/assets/8d5f4f0d-d42b-43f8-9465-586ef36f0864">


## 🧠 What to Watch Out for Next

🔄 Registry Monitoring: Continue monitoring for changes to Run or RunOnce keys.

🧠 Script Launches: Track additional PowerShell executions, especially those downloading from external URLs or accessing internal ports.

🕑 Scheduled Tasks: Even without specific times, tasks set to launch at startup can be suspicious.

👤 Account Persistence: Check for new user accounts or privilege escalation attempts.

| TTP ID | TTP Name                          | Description                                    | Detection Relevance                                  |
|--------|-----------------------------------|------------------------------------------------|------------------------------------------------------|
| T1053  | Scheduled Task                    | Persistence through scheduled tasks            | Even at startup without time trigger, it counts      |
| T1547  | Boot or Logon Autostart Execution | Registry Run key used for persistence          | Detected in coinbase homepage modification           |
| T1059  | Command and Scripting Interpreter | PowerShell execution observed                  | Used for launching suspicious browser activity       |
| T1071  | Application Layer Protocol        | Observing traffic over HTTP/S and custom ports | Helps identify abnormal exfiltration                 |
| T1046  | Network Service Scanning          | Detected scanning from internal devices        | Indicates lateral movement or recon                  |
| T1218  | Signed Binary Proxy Execution     | `powershell.exe` used for evasion              | Signed binary was used to execute hidden behaviors   |

## ✅ Response Actions

🕵️ Identified and confirmed unauthorized persistence via Registry Run key

🔍 Inspected PowerShell executions launching coinbase.com

🌐 Verified internal PowerShell-based port scanning activity

🔒 Blocked inbound connections at the firewall

🧯 Recommended isolating britt-windows10 

🛠️ Future Actions: Audit scheduled tasks and run full malware scan/reimage the device.


## 🧾  **Created By Britt Parks**

**Contact: linkedin.com/in/brittaparks**

**Date: April 18, 2025**

