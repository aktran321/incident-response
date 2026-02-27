# Explanation
Sometimes corporations have policies against working outside of designated geographic regions, account sharing (this should be standard), or use of non-corporate VPNs. The following scenario will be used to detect unusual logon behavior by creating an incident if a user's login patterns are too erratic. “Too erratic” can be defined as logging in from multiple geographic regions within a given time period.

Whenever a user logs into Azure or authenticates with their main Azure account, logs will be created in the “SigninLogs” table, which is being forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, our SIEM. Within Sentinel, we will define an alert to trigger whenever a user logs into more than one location in a 7 day time period. Not all triggers will be true positives, but it will give us a chance to investigate.

## Alert Creation
```
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
Analytics Rule Settings:
Name: 
Description: 
Enable the Rule
Use ChatGPT to set Mitre ATT&CK Framework Categories based on the query
Run query every 4 hours
Lookup data for last 5 hours (can define in query)
Stop running query after alert is generated == Yes
Configure Entity Mappings:	
Account
Identifier: AadUserId, Value: UserId
Identifier: DisplayName, Value: UserPrincipalName	
Automatically create an Incident if the rule is triggered
Group all alerts into a single Incident per 24 hours
Stop running query after alert is generated (24 hours)

## Incident
An incident has appeared in Microsoft Sentinel related to the alert created above. 

<img src="incident" alt="incident creation" width="400">

I assigned the incident to myself and mark it as active.

<img src="" alt="investigation visual" width="400">

The incident involves over 30 entities with potential impossible time travel. For this exercise I will focus on two entities.

## Detection and Analysis
I investigate each of the UserPrincipalNames with the query below. 
```
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "5516e674dd5f510acb1143bc61b03226157b77a96149d175567fa28ff5141059@lognpacific.com"; // (UserPrincipalName)
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

<img src="" alt="First user sign in" width="400">

In just the first couple logs, the user `5516e674dd5f510acb1143bc61b03226157b77a96149d175567fa28ff5141059@lognpacific.com` logged in from Boydton, Virginia and New York, New York within seconds of each other. 
This is of course not physically possible.

Another user `b0f7738e0e146afe1560ee169046022c1a9a8c6ca9e77307571a8e3990e121f4@lognpacific.com` logged in from 4 different cities located on opposite ends of the US in a span of 12 hours.

<img src="" alt="Second user sign in" width="400">

Given the evidence, this incident is labeled a true positive.

## Containment, Eradication and Recovery

The two user accounts in question have been disabled from Entra ID and management was contacted.

There is currently no threat to remove the systems in place, but further direction is pending from management.

## Post-Incident Activities
Explored the option of creating a geo-fencing policy in Azure to prevent logins from certain regions.

## Closure
Updated the activity log for the incident and labeled it a true positive.

<img src="" alt="Second user sign in" width="400">

<img src="" alt="Second user sign in" width="400">
