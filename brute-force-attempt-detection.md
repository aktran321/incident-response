# Alert

Below is the KQL query used to generate the brute-force detection alert.

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberofFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberofFailures >= 50
```

Create the Scheduled Query Rule in:  
**Sentinel → Analytics → Scheduled Query Rule**

## Analytics Rule Settings

- Enable the Rule  
- Map to MITRE ATT&CK: **T1110 – Brute Force**  
- Run query every 4 hours  
- Lookup data from last 5 hours (defined in query)  
- Stop running query after alert is generated (24 hours)  
- Configure Entity Mappings:
  - `RemoteIP` → IP Entity  
  - `DeviceName` → Host Entity  
- Automatically create an Incident  
- Group all alerts into a single Incident per 24 hours  

---

# Detection and Analysis

After the rule was created, the alert triggered successfully.

<img src="https://github.com/aktran321/incident-response/blob/main/images-bf/alert-detection.png" alt="alert detection" width="400">

The incident was reviewed in Sentinel, assigned to the analyst, and set to **Active**.

<img src="https://github.com/aktran321/incident-response/blob/main/images-bf/assign-incident.png" alt="alert assigned" width="400">

Clicking **Investigate** displays a visual diagram of the related entities.

<img src="https://github.com/aktran321/incident-response/blob/main/images-bf/investigate.png" alt="investigate" width="700">

Analysis revealed:

- 3 external public IP addresses  
- 1 internal private IP (10.0.0.8 – confirmed Tenable Cloud Scanner)  
- 1 device with failed logons where no RemoteIP was recorded  

<img src="https://github.com/aktran321/incident-response/blob/main/images-bf/table-overview.png" alt="table overview" width="700">

The missing RemoteIP likely indicates either:
- Local logon failures  
- Telemetry not capturing the source IP  

---

# Containment, Eradication, and Recovery

## Device Response (Microsoft Defender for Endpoint)

- Navigate to **Assets → Devices**
- Select affected device
- Click `...` → **Isolate Device**
- Run **Antivirus Scan**

## Network Hardening

- Lock down NSG rules to prevent public login attempts  
- Allow inbound RDP (Port 3389) only from authorized internal IP addresses  
- Remove broad public exposure  

<img src="https://github.com/aktran321/incident-response/blob/main/images-bf/nsg-rule.png" alt="nsg rule" width="700">

---

## Verification of Successful Logons

To verify that none of the brute-force attempts resulted in successful authentication:

```kql
let TargetDevice = "windows-target-1"; // Replace with target VM
let SuspectIP = "185.218.138.3"; // Replace with suspect IP
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
```

After analyzing the results, none of the brute-force attempts were successful.

---

## Activity Log Update

Add the following entry to the Sentinel incident activity log:

```
Multiple brute-force logon attempts were identified against several virtual machines. The activity originated from the external IP addresses 185.218.138.3 targeting srini-edr-test, 187.195.79.118 targeting bigp, and 144.31.152.46 targeting jh-linux-angentscan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net. Additionally, failed logon attempts were observed against figfinallabvm, though no source IP was recorded for those events.

An internal IP address, 10.0.0.8, generated failed logon attempts against ridge-vm-test and josh-linux-practice.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net; this IP was confirmed to be the authorized Tenable cloud vulnerability scanner.

A review of LogonSuccess events during and after the timeframe of the failed attempts found no successful logins associated with any of the external IP addresses, and no evidence of credential compromise or post-authentication malicious activity was identified. The observed activity is consistent with automated internet-based brute-force scanning against exposed services.
```

---

# Post-Incident Activities

- Document findings and lessons learned  
- Update policies and hardening standards  
- Implement stricter NSG baselines to prevent publicly exposed management ports  
- Consider enabling Just-in-Time (JIT) VM access and account lockout policies  

---

# Closure

- Review and confirm incident resolution  
- Verify containment measures are active  
- Close the incident in Sentinel  
- Label as: **True Positive – Brute Force Attempt (No Successful Logon)**  
