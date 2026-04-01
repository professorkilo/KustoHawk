$Query = "let Upn = '{UserPrincipalName}';
let TimeFrame = {TimeFrame};
CloudAppEvents
| where RawEventData.UserId =~ Upn
| where Timestamp > ago(TimeFrame)
| extend parsed = parse_json(RawEventData)
| where Application == 'Microsoft Exchange Online' and  ActionType in ('New-InboxRule', 'Set-InboxRule', 'Set-Mailbox', 'New-TransportRule', 'Set-TransportRule')
| extend parsed = parse_json(RawEventData)
| extend UPN = tostring(parsed.UserId)
| extend Parameters = parsed.Parameters
| mv-expand Parameters
| extend Name = tostring(Parameters.Name)
| extend Value = tostring(Parameters.Value)
| extend packed = pack(Name, Value)
| summarize PackedInfo = make_bag(packed), ActionType=any(ActionType) by ReportId, UPN
| evaluate bag_unpack(PackedInfo))"
$Output = $Query -replace '\r','\r' -replace '\n','\n'
Write-Output $Output