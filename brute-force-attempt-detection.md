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




   
