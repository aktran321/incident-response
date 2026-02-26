# Create Alert
```
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberofFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberofFailures >= 50
```
Create the Schedule Query Rule in: Sentinel → Analytics → Schedule Query Rule

Analytics Rule Settings:
- Enable the Rule
- Use ChatGPT to set Mitre ATT&CK Framework Categories based on the query
- Run query every 4 hours
- Lookup data for last 5 hours (can define in query)
- Stop running query after alert is generated == Yes
- Configure Entity Mappings for the Remote IP and DeviceName
- Automatically create an Incident if the rule is triggered
- Group all alerts into a single Incident per 24 hours
- Stop running query after alert is generated (24 hours)

# Detection and Analysis
After the rule is created, we see the alert was triggered.
![Alert Detection](/images-bf/alert-detection.png)

We can see it in Sentinel and assign the incident to ourselves and set it to active. 
![Alert Detection](/images-bf/assign-incident.png)

Clicking investigate will show a visual diagram of the entities involved in the alertt.
![Alert Detection](/images-bf/investigate.png)

It looks like the alerts were triggered by 3 public IPs and 1 private IP (10.0.0.8 associated with tenable cloud scanner). One alert did not have a remote IP indicating that
the failed logins happened on the machine itself or the remote IP was somehow not captured.
![Alert Detection](/images-bf/table-overview.png)



# Containment, Eradication, Recovery
Navigate to Microsoft Defender for Endpoint, search the affected devices and isolate them.
- Assets -> Devices -> Click the affected device -> click "..." -> Isolate Device
- Run an AV scan by clicking "Run Antivirus Scan"
- Lockdown NSG to prevent login attemps from the public internet. We will only allow inbound traffic to port 3389 (RDP) on the affected VMs from our own IP.
![NSG Lockdown](/images-bf/nsg-rule.png)
- Check to make sure none of the IPs trying to brute force actually logged in. (Besides the IP coming from the Tenable Cloud Scanner)
```
// Highlight to show query 👇
let TargetDevice = "windows-target-1"; // Replace with target VM
let SuspectIP = "185.218.138.3"; // Replace with suspect IP
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
```
After analyzing the results, none of the brute force attempts were successful.

Navigate to the alert in Sentinel and Update the activity log with the following.
```
Multiple brute-force logon attempts were identified against several virtual machines. The activity originated from the external IP addresses 185.218.138.3 targeting srini-edr-test, 187.195.79.118 targeting bigp, and 144.31.152.46 targeting jh-linux-angentscan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net. Additionally, failed logon attempts were observed against figfinallabvm, though no source IP was recorded for those events.

An internal IP address, 10.0.0.8, generated failed logon attempts against ridge-vm-test and josh-linux-practice.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net; this IP was confirmed to be the authorized Tenable cloud vulnerability scanner.

A review of LogonSuccess events during and after the timeframe of the failed attempts found no successful logins associated with any of the external IP addresses, and no evidence of credential compromise or post-authentication malicious activity was identified. The observed activity is consistent with automated internet-based brute-force scanning against exposed services.
```
Close out the alert in Sentinel and label the incident as a true positive. Brute force was attempted but there was no successful logon.





