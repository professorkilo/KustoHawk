$Query = "let Upn = '{UserPrincipalName}';
let TimeFrame = {TimeFrame};
CloudAppEvents
| where Timestamp > ago(TimeFrame)
| where RawEventData.UserId =~ Upn
| where Application == 'Microsoft Exchange Online'
| where ActionType == 'New-InboxRule'
| mv-apply p=todynamic(ActivityObjects) on 
(
where p.Name == 'Name'
| extend RuleName=p.Value
)
| where isnotempty(RuleName)
| where RuleName matches regex @'^[^a-zA-Z0-9]*$'
| extend AccountUpn=tostring(RawEventData.UserId)
| extend SessionId=tostring(RawEventData.SessionId)
| project Timestamp, Application, ActionType, AccountUpn, RuleName, SessionId, IPAddress"
$Output = $Query -replace '\r','\r' -replace '\n','\n'
Write-Output $Output