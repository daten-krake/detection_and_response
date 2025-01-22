# Detect Malicious Application Registrations

## Goal

Identify unauthorized or malicious application registrations in your Entra environment to prevent potential abuse, data exfiltration, or compromise of your organization's security posture.

## Categorization

- Tactic: Persistence  
- Technique: Application Deployment (T1059)  

## Strategy Abstract

This detection strategy leverages Entra audit logs to monitor application registration activities. By filtering for known malicious applications using a dynamic list or watchlist, it helps identify potential risks. The detection logic pinpoints actions such as the addition of applications to the environment and identifies the initiator of these actions to facilitate rapid response.

## Technical Context

- Data Source: Entra Audit Logs  
- Log Category: ApplicationManagement  
- Relevant Operations: Add Application  
- Fields Monitored:
  - `TargetResources.[0].displayName` (identifies the application's display name)  
  - `InitiatedBy.user.userPrincipalName` (identifies the actor who initiated the action)  

## Detection Query

```kql
let knownMalicousApps = dynamic([
    "eM Client", 
    "Newsletter Software Supermailer", 
    "CloudSponge", 
    "rclone", 
    "PERFECTDATA SOFTWARE", 
    "SigParser", 
    "Fastmail", 
    "ZoomInfo Login & ZoomInfo Communitiez Login"
]); // Replace with a watchlist for scalability
AuditLogs
| where Category == "ApplicationManagement"  // Focus on app management events
| where OperationName == "Add application"   // Target application registrations
| extend 
    Name = TargetResources[0].displayName,
    Actor = InitiatedBy.user.userPrincipalName
| where Name in (knownMalicousApps)          // Check against known malicious apps
| project TimeGenerated, TargetResources, Actor, OperationName, Name
```

## Blind Spots and Assumptions
- Assumptions
    - The `TargetResources[0].displayName` field accurately captures the name of the registered application.  
    - The list of known malicious applications is comprehensive and up-to-date.

- Blind Spots
    - Reliance on accurate and complete Entra audit logs; if logging is disabled or incomplete, detection will be impaired.  
    - Newly identified malicious applications not included in the dynamic list will not trigger alerts.

## False Positives
- Known Scenarios
    - Legitimate applications with similar names may trigger alerts.

- Mitigation Strategies
    - Use a watchlist for malicious applications, regularly updated with vetted sources.  
    - Confirm alerts by cross-referencing application metadata with threat intelligence feeds.

## Validation
- Testing Process
    1. Simulate Malicious App Registrations: Register applications matching the names in the `knownMalicousApps` list.  
    1. Verify Alerts: Confirm that the detection logic identifies these events.  
    1. Test False Positives: Ensure legitimate application registrations do not trigger unnecessary alerts.

- Review Logs: Examine captured audit logs to validate event coverage and detection accuracy.

## Priority

- Priority Level: High  
- Justification: Unauthorized or malicious application registrations can introduce vulnerabilities, enable data breaches, or lead to security policy violations. Prompt detection and response are critical to safeguard the environment.

## Response

1. Investigate Alert:  
   - Review alert details to confirm the nature of the application registration and the user involved.  
2. Verify Legitimacy:  
   - Contact the initiator or relevant stakeholders to determine if the registration was authorized.  
3. Revoke Malicious Applications:  
   - Remove the application from your environment if deemed malicious.  
4. Audit Access Controls:  
   - Evaluate and adjust access controls to reduce the likelihood of future unauthorized actions.  
5. Document Incident:  
   - Record the incident, response actions, and lessons learned to refine detection and response strategies.

## Additional Resources

- [MITRE ATT&CK Framework - Application Deployment (T1059)](https://attack.mitre.org)  

