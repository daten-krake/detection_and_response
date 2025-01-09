# Creation of Temporary Access Pass (TAP) for Administrator

## Goal

Detect the creation of a Temporary Access Pass (TAP) for administrator accounts in Microsoft Entra ID, which may indicate potential security risks or policy violations.

## Categorization

- Tactic: Persistence
- Technique: Account Manipulation (T1098)

## Strategy Abstract

This detection strategy monitors Microsoft Entra ID audit logs for events where a Temporary Access Pass is registered for users with administrative privileges. By filtering these logs for specific operations and focusing on privileged accounts, the rule identifies actions that may introduce security vulnerabilities. The detection logic can be customized to include or exclude specific administrators as needed.

## Technical Context

- Data Sources: Entra Audit Logs
- Log Category: User Management
- Relevant Operations:
    - Admin registered temporary access pass method for user
- Fields Monitored:
    - Identity
    - TargetResources.[0].userPrincipalName

## Detection Query

```kql
let admin_users = dynamic(["admin1@domain.com", "admin2@domain.com"]);  // Replace with the UPNs of the administrators you want to monitor //or better usage of Watchlist
AuditLogs
| where OperationName == "Admin registered security info"
| where ResultDescription == "Admin registered temporary access pass method for user"
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| where Initiator in (admin_users)
| project TimeGenerated, Initiator, TargetUser = tostring(TargetResources[0].userPrincipalName), ResultReason
| order by TimeGenerated desc
```

## Blind Spots and Assumptions

- Assumptions: 
    - Assumes that the InitiatedBy.user.userPrincipalName field accurately represents the administrator performing the action and that the list of monitored administrators is up to date.
- Blind Spots:
    - This rule depends on the accuracy and completeness of Microsoft Entra ID audit logs. If logging is disabled or incomplete, some TAP creation events may not be detected.

## False Positives

- Porential Scenarios:
    - Legitimate administrative actions involving TAP creation for valid purposes may trigger the alert.
- Mitigation Strategies:
    - Regularly review and update the list of administrators being monitored and establish clear policies regarding TAP usage to differentiate between authorized and unauthorized activities.

## Validation

- Testing Process:
    1. Simulate TAP Creation: Have an administrator create a Temporary Access Pass for a user account.
    1. Monitor Alerts: Verify that the detection rule generates an alert for this activity.
    1. Review Logs: Ensure that the audit logs accurately capture the TAP creation event and that the detection logic processes it correctly.


## Priority

- Priority Level: Medium
- Justification: While TAP creation by administrators can be part of legitimate operations, unauthorized or unexpected TAP creation may pose security risks. Monitoring these events helps maintain security integrity.

## Response

1. Investigate Alert: 
    - Examine the details of the alert to determine the context of the TAP creation, including the initiating administrator and the target user.
2. Verify Authorization: 
    - Confirm with the initiating administrator whether the TAP creation was authorized and for a legitimate purpose.
3. Assess Impact:
    - Evaluate any potential security implications resulting from the TAP creation.
4. Document Findings: 
    - Record the incident details, including the outcome of the investigation and any remedial actions taken.
5. Review Policies:     
    - Ensure that policies regarding TAP usage are clear and communicated to all administrators to prevent unauthorized use.

## Additional Resources
[Configure a Temporary Access Pass in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
[Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
