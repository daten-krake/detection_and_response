# Change on Priviledged Group

## Goal

Detect unauthorized or unexpected modifications to designated Entra groups, including the creation, deletion, and membership changes, to ensure the integrity of group configurations and prevent potential security risks.

## Categorization

- Tactic: Persistence
- Technique: Account Manipulation (T1098)

## Strategy Abstract

This detection strategy utilizes Entra audit logs to monitor specific group management activities. By filtering these logs for operations such as adding or removing group members, and focusing on a predefined list of critical groups, the rule identifies changes that may indicate unauthorized access or policy violations. The detection logic excludes actions performed by known automation accounts to reduce false positives.

## Technical Context

- Data Srouce: Entra Audit Logs
- Log Category: GroupManagement 
- Relevant Operations:
    - Add Group
    - Delete Group
    - Add Member to Group
    - Remove Member to Group
    - Add owner to Group
    - Remove owner to Group
- Fiels Monitored:
    - InitiatedBy.user.userPrincipalName (identifies the actor)
    - TargetResources.[0].displayName (name of the group)


## Detection Query

```kql
let target_groups = dynamic(["Group1", "Group2", "Group3"]);  // Replace with the display names of the groups you want to monitor
let automation_accounts = dynamic(["automation1@domain.com", "automation2@domain.com"]);  // Replace with the UPNs of your automation accounts
AuditLogs
| where Category == "GroupManagement"
| where OperationName in ("Add group", "Delete group", "Add member to group", "Remove member from group", "Add owner to group", "Remove owner from group")
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| extend GroupName = tostring(TargetResources[0].displayName)
| where GroupName in (target_groups)
| where not(Initiator in (automation_accounts))
| project TimeGenerated, OperationName, GroupName, Initiator, TargetResources
| order by TimeGenerated desc
```


## Blind Spots and Assumptions

- Assumptions:
    - Assumes that the InitiatedBy.user.userPrincipalName field accurately represents the user performing the action and that automation accounts are correctly identified and listed.
- Blind Spots: 
    - This rule relies on the accuracy and completeness of Entra audit logs. If logging is disabled or incomplete, some changes may not be detected.

## False Positives

- Known Scenarios:
    - Legitimate administrative actions by authorized personnel may trigger the alert if they are not listed in the automation accounts.
- Mitigation Strategies:
    - Regularly update the list of authorized users and automation accounts to reflect current administrative personnel and service accounts.

## Validation

- Testing Process:
    1. Simulate Changes: Perform test modifications on the target groups, such as adding or removing members, using both authorized and unauthorized accounts.
    1. Monitor Alerts: Verify that the rule generates alerts for unauthorized changes and does not trigger for authorized actions.
    1. Review Logs: Examine the audit logs to ensure that all relevant events are captured and processed by the detection logic.

## Priority

- Priority Level: High
- Justification: Changes to critical Entra groups can have significant security implications, including unauthorized access to resources and potential data breaches. Prompt detection and response are essential to maintain security posture.


## Response

1. Investigate Alert:   
    - Review the details of the alert to identify the nature of the change and the user account involved.
2. Verify Legitimacy:
    - Contact the initiator or relevant stakeholders to confirm whether the change was authorized.
3. Revert Unauthorized Changes:
    - If the change is determined to be unauthorized, promptly revert it to restore the original group configuration.
4. Audit Access Controls:
    - Assess and update access controls to prevent future unauthorized modifications.
5. Document Incident:
    - Record the incident details, response actions taken, and any lessons learned to improve future detection and response efforts.

Additional Resources

[Entra Audit Logs Documentation](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/concept-audit-logs)
[Microsoft Sentinel Analytics Rules](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)
[MITRE ATT&CK Framework - Account Manipulation (T1098)](https://attack.mitre.org/techniques/T1098/)
