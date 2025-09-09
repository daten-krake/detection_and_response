# Changes to Conditional Access by Non-Approved Admin


## Goal
Detect and alert on any modifications to Conditional Access policies made by administrators who are not on the approved list. Such unauthorized changes can weaken security postures and may indicate malicious activity.
## Categorization
- Tactic: Defense Evasion
- Technique: Modify Authentication Process (T1556)
- Sub-technique: Conditional Access Policies (T1556.009)

## Strategy Abstract
This detection strategy monitors Entra audit logs for any additions, deletions, or updates to Conditional Access policies. It identifies the administrators who performed these actions and checks them against a predefined list of approved admins. If an unapproved admin makes a change, the system generates an alert.
## Technical Context
- Data Source: Entra Audit Logs
- Log Category: Policy
- Relevant Operations:
    - Update conditional access policy
    - Add conditional access policy
    - Delete conditional access policy
- Fields Monitored:
    - InitiatedBy.user.userPrincipalName (identifies the admin)
    - TargetResources[0].displayName (name of the policy)
## Detection Query

```kql
let approved_admins = dynamic(["approvedAdmin1@yourdomain.com", "approvedAdmin2@yourdomain.com"] );  // Replace with approved admin UPNs // or you can use a watchlist here aswell
AuditLogs
| where Category == "Policy"
| where OperationName has "Update conditional access policy" or OperationName has "Add conditional access policy" or OperationName has "Delete conditional access policy"
| extend ModifiedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend  PolicyName = tostring(TargetResources[0].displayName)
| where not(ModifiedBy in (approved_admins))
| project TimeGenerated, PolicyName, ModifiedBy, TargetResources
```

## Blind Spots and Assumptions
- Assumptions:
    - The list of approved admins (approved_admins) is current and accurately reflects authorized personnel.
- Blind Spots:
    - If the approved_admins list is outdated, legitimate changes by new admins may trigger false positives.
    - Changes made by compromised accounts of approved admins will not be detected.
## False Positives
- Potential Scenarios:
    - Newly appointed admins who haven't been added to the approved_admins list making legitimate changes.
- Mitigation Strategies:
    - Regularly update the approved_admins list to reflect current authorized personnel.
    - Implement a process to quickly add new admins to the approved list.
## Validation
- Testing Process:
    1. Simulate Changes: Have a non-approved admin make a change to a Conditional Access policy.
    1. Monitor Alerts: Verify that the alert is triggered as expected.
    1. Approve Admin: Add the admin to the approved_admins list.
    1. Repeat Change: Have the now-approved admin make another change.
    1. Monitor Alerts: Ensure no alert is triggered for the approved admin.
- Sample Data: Utilize Azure AD audit logs containing historical policy changes for testing.
## Priority
- Priority Level: High
- Justification: Unauthorized changes to Conditional Access policies can significantly compromise organizational security, potentially allowing adversaries to bypass critical authentication controls.
## Response
1. Immediate Action:
    - Disable or revert the unauthorized policy change to its previous state.
2. Investigate:
    - Identify the individual who made the change and determine their intent.
    - Check for other suspicious activities associated with the user's account.
3. Remediation:
    - If malicious intent is confirmed, follow incident response procedures, including possible account suspension and password resets.
    - Review and enhance security measures to prevent future unauthorized changes.
4. Documentation:
    - Record the incident, actions taken, and lessons learned.
5. Review:
    - Assess the effectiveness of the detection and response process and make necessary improvements.

By implementing this alert and following the outlined response plan, organizations can proactively detect and address unauthorized modifications to Conditional Access policies, thereby maintaining a robust security posture.

## Additional Resources
[Mitre](https://attack.mitre.org/techniques/T1556/009/)
[Use audit logs to troubleshoot CA policy changes](https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-policy-changes-audit-log)
