# Incident Response Report  
## Potential Impossible Travel – Azure Sign-In Anomaly

---

# 1. Preparation

The organization enforces policies restricting authentication from unauthorized geographic regions, prohibiting account sharing, and limiting the use of non-corporate VPN services.

To support these controls, authentication events from Microsoft Entra ID are forwarded to Microsoft Sentinel through the `SigninLogs` table in the Log Analytics Workspace. An analytic rule was created to detect anomalous login behavior commonly referred to as **“impossible travel.”**

Impossible travel occurs when a user account authenticates from geographically distant locations within a timeframe that is not physically possible.

---

# 2. Detection and Analysis

## Alert Creation

The following KQL query was developed to identify users authenticating from more than two distinct geographic locations within a 7-day period:

```kql
// Locate Instances of Potential Impossible Travel
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId,
    City = tostring(parse_json(LocationDetails).city),
    State = tostring(parse_json(LocationDetails).state),
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

### Analytics Rule Configuration

- Query runs every 4 hours  
- Looks back 5 hours of data  
- Automatically creates an incident when triggered  
- Groups alerts into a single incident per 24 hours  
- Stops running after alert generation (24 hours)  
- Entity mapping configured for:
  - `AadUserId → UserId`
  - `DisplayName → UserPrincipalName`

---

## Incident

An incident was generated in Microsoft Sentinel based on the analytic rule.

<img src="https://github.com/aktran321/incident-response/blob/main/images-it/incident.png" alt="incident creation" width="400">

The incident was assigned and marked as **Active** for investigation.

<img src="https://github.com/aktran321/incident-response/blob/main/images-it/investigate.png" alt="investigation visual" width="400">

The incident contained over 30 entities flagged for potential impossible travel. Two users were prioritized for investigation.

---

## Investigation

The following query was used to analyze each flagged user:

```kql
// Investigate Potential Impossible Travel Instances
let TargetUserPrincipalName = "5516e674dd5f510acb1143bc61b03226157b77a96149d175567fa28ff5141059@lognpacific.com"; // (UserPrincipalName)
let TimePeriodThreshold = timespan(7d); // Change to how far back you want to look
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName,
    City = tostring(parse_json(LocationDetails).city),
    State = tostring(parse_json(LocationDetails).state),
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

<img src="https://github.com/aktran321/incident-response/blob/main/images-it/user1-log.png" alt="First user sign in" width="700">

### Findings – User 1

User `5516e674dd5f510acb1143bc61b03226157b77a96149d175567fa28ff5141059@lognpacific.com` authenticated from Boydton, Virginia and New York, New York within seconds of each other. This pattern is not physically possible and indicates highly anomalous login behavior.

---

### Findings – User 2

User `b0f7738e0e146afe1560ee169046022c1a9a8c6ca9e77307571a8e3990e121f4@lognpacific.com` authenticated from four geographically distant U.S. cities within a 12-hour period, spanning opposite regions of the country.

<img src="https://github.com/aktran321/incident-response/blob/main/images-it/user2-log.png" alt="Second user sign in" width="700">

The geographic dispersion and compressed timeframe strongly suggest potential credential compromise, VPN misuse, or account sharing.

Based on the evidence collected, the incident was classified as a **True Positive**.

---

# 3. Containment

- Both user accounts were disabled in Entra ID.
- Management was notified of the findings.
- Monitoring was increased for related authentication activity.

---

# 4. Eradication and Recovery

- Awaiting direction from management regarding credential resets.
- Recommended enforcing password resets and validating MFA configurations.
- No evidence of lateral movement or additional malicious activity was identified.
- Business operations remain unaffected.

---

# 5. Post-Incident Activities (Lessons Learned)

- Evaluated implementation of Conditional Access policies.
- Explored geo-fencing restrictions to prevent authentication from unauthorized regions.
- Reviewed alert thresholds to balance detection capability and false positives.
- Updated the incident activity log and documentation.

---

# Closure

The incident record was updated to reflect findings and response actions.

<img src="https://github.com/aktran321/incident-response/blob/main/images-it/close.png" alt="activity log" width="400">

The incident was marked:

**Closed – True Positive**

<img src="https://github.com/aktran321/incident-response/blob/main/images-it/activity-log.png" alt="incident closed" width="400">
