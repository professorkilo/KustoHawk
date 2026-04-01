# KustoHawk 🦅

KustoHawk is an incident triage and response tool for Microsoft Defender XDR and Microsoft Sentinel environments. The script collects common indicators of compromise and returns a complete picture of the activities performed by an device of account. The tool leverages Graph API to run the hunting queries across your unified XDR environment. Bases on a [tiering permission](#authentication-tiers-and-permissions) model additional data can be collected via Graph API calls. The queries that are executed are listed in the [Resources](./Resources/) folder.

![Alt text](./Images/Logo-NoBackground.png)

## Architecture
KustoHawk is based on the [KustoHawk.ps1](./KustoHawk.ps1) PowerShell script that connects to the Graph API to run hunting queries and collect relevant data. The output is shared in the commandline and presented in HTML exports.

![Alt text](./Images/KustoHawk.png)

## Usage
The script supports multiple authentication options to connect the script to the Graph API. Set one of the below options in the *AuthenticationMethod* parameter, in case of ServicePrincipal signins you have to add application configuration in the script.

- User
- ServicePrincipalSecret
- ServicePrincipalCertificate

By default the data from the last 7 days is collected, this can be adjusted using the *[-TimeFrame] <String>* parameter.

### Authentication Tiers And Permissions

Tiers are defined in [Resources/AuthenticationTiers.yaml](./Resources/AuthenticationTiers.yaml).

| Tier | Permissions |
| --- | --- |
| Tier1 | `ThreatHunting.Read.All` |
| Tier2 | `ThreatHunting.Read.All`, `UserAuthenticationMethod.Read.All` |
| Tier3 | `ThreatHunting.Read.All`, `UserAuthenticationMethod.Read.All` |

- Minimum required permission is `ThreatHunting.Read.All`.
- If the requested tier cannot be met, KustoHawk attempts a lower tier automatically.

### Prerequisites
KustoHawk requires the Microsoft Graph Security PowerShell module:

```powershell
Install-Module Microsoft.Graph.Security
```

### Parameters

```powershell
KustoHawk.ps1 [[-DeviceId] <String>] [[-UserPrincipalName] <String>] [-VerboseOutput] [-Export]
        [-IncludeSampleSet] [[-TimeFrame] <String>] [[-CertificateThumbprint] <String>]
        [[-AuthenticationTier] <String>] [-AuthenticationMethod] <String> [<CommonParameters>]
```

Key parameters:

- `-DeviceId`: 40-character hexadecimal DeviceId.
- `-UserPrincipalName` or `-upn`: user account to investigate.
- `-TimeFrame` or `-t`: query timeframe (default `7d`).
- `-IncludeSampleSet` or `-s`: include up to 10 sample rows per query in HTML reports.
- `-VerboseOutput` or `-v`: print full query results in terminal.
- `-Export` or `-e`: export query result tables to CSV.
- `-AuthenticationMethod`: `User`, `ServicePrincipalSecret`, or `ServicePrincipalCertificate`.
- `-AuthenticationTier`: `Tier1`, `Tier2`, or `Tier3`.
- `-CertificateThumbprint`: optional thumbprint for certificate auth.

To view help and examples:

```powershell
Get-Help .\KustoHawk.ps1
```

### Examples

![Alt text](./Images/ExampleOutputDevice.png)

**Example 1: Collecting Device and Idenity information with user authentication**

```PowerShell
.\KustoHawk.ps1 -DeviceId 2694a7cc2225f3b66f7cf8b6388a78b1857fadca -upn user@contonso.com -AuthenticationMethod User -AuthenticationTier Tier1
```

**Example 2: Collecting Device information with csv exports enabled with a set timeframe of 14 days**

```PowerShell
.\KustoHawk.ps1 -DeviceId 2694a7cc2225f3b66f7cf8b6388a78b1857fadca -AuthenticationMethod User -TimeFrame 14d -e -AuthenticationTier Tier1
```

**Example 3: Collecting Idenity information with sample results and authentication methods (tier2) with a set timeframe of 14 days**

```PowerShell
.\KustoHawk.ps1 -upn bert-jan@kqlquery.com -AuthenticationTier Tier2 -TimeFrame 14d -IncludeSampleSet -AuthenticationMethod User
```

## Table Requirements
Missing tables do not break KustoHawk, but fewer detections are returned.

### Device Triage
- Unified Security Platform Alerts (AlertEvidence, AlertInfo) 
- Defender For Endpoint (DeviceFileEvents, DeviceEvents, DeviceTvmSoftwareVulnerabilities, DeviceRegistryEvents, DeviceNetworkEvents, DeviceProcessEvents, DeviceInfo)

### Identity Triage
- Unified Security Platform Alerts (AlertEvidence, AlertInfo)
- Sentinel UEABA (Anomalies) 
- Entra ID Logs (AADUserRiskEvents, SigninLogs, AuditLogs, AADSignInEventsBeta)
- AzureActivity
- Defender For Identity (IdentityInfo)
- GraphAPIAuditEvents
- Defender For Cloud Apps (CloudAppEvents, BehaviorEntities, BehaviorInfo)

## Contribute
Contributions are highly appriciated! You can contribute by adding new queries to the JSON files in the [Resources](./Resources/) folder. Create a pull request for the new queries.

The JSON has three required fields:
- "Name": Name of the query.
- "Query": The query to execute. The PowerShell script replaces the variables *{DeviceId}*, *{TimeFrame}* and *{UserPrincipalName}* in the KQL to the input values of the script.
- "Source": The source of the query, credit should be given where credit is due. 
- "ResultCount": Number of hits last run
```JSON
{
    "Name": "Triage query one",
    "Query": "let Device = '{DeviceId}';\r\nAlertEvidence\r\n| where DeviceId =~ Device\r\n| where Timestamp > ago({TimeFrame})\r\n| where EntityType == 'Machine'\r\n| summarize arg_max(Timestamp, *) by AlertId\r\n| project AlertId\r\n| join kind=inner AlertInfo on AlertId\r\n| extend AlertLink = strcat('https://security.microsoft.com/alerts/', AlertId)\r\n| project-reorder Timestamp, Title, Category, Severity, DetectionSource, AlertLink\r\n| sort by Timestamp desc",
    "Source": "https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/DFIR/XDR%20-%20DeviceAlerts.md",
    "ResultCount":  22
}
```

**Translate KQL query to single line string**

The query field in the json should be a single line string, the PowerShell script below can be used to translate the query to the right format.

```PowerShell
$Query = "let Upn = '{UserPrincipalName}';
let TimeFrame = {TimeFrame};
AADUserRiskEvents
| where TimeGenerated > ago(TimeFrame)
| where UserPrincipalName =~ Upn
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
| project TimeGenerated, UserPrincipalName, RiskState, RiskLevel, RiskDetail, RiskEventType"
$Output = $Query -replace '\r','\r' -replace '\n','\n'
Write-Output $Output
```

# Credits
he queries of the authors below are used in KustoHawk.

| Name | Source |
| --- | --- |
| @reprise99 | [Sentinel-Queries](https://github.com/reprise99/Sentinel-Queries) |
| Kijo Girardi | [AiTM & BEC Threat Hunting with KQL](https://techcommunity.microsoft.com/blog/azuredataexplorer/aitm--bec-threat-hunting-with-kql/3885166) |