<#
.SYNOPSIS
    Automates incident triage for Unified XDR platform for devices and identities.

.DESCRIPTION
    KustoHawk.ps1 is a PowerShell script for incident triage using Microsoft Graph Security API and Kusto Query Language (KQL).
    The script retrieves and summarizes key information about devices and/or users, executes relevant KQL queries from JSON files,
    and exports results to CSV and HTML reports. Output can be customized using parameters.
    Authentication supports User, Service Principal (Secret), or Service Principal (Certificate).

.PARAMETER DeviceId
    The DeviceId of the device to investigate. DeviceId can be retrieved from the device page in the security.microsoft.com portal or from Advanced Hunting in the DeviceId column. 

.PARAMETER UserPrincipalName
    The user's UPN (username@domain.com) to investigate.

.PARAMETER AuthenticationMethod
    The authentication method to use for Microsoft Graph API. Required. Must be one of: User, ServicePrincipalSecret, ServicePrincipalCertificate.

.PARAMETER CertificateThumbprint
    Optional certificate thumbprint used when -AuthenticationMethod ServicePrincipalCertificate is selected.
    If not specified, the script uses $DefaultCertificateThumbprint from the service principal variables section.
    The certificate must exist in Cert:\CurrentUser\My or Cert:\LocalMachine\My.

.PARAMETER VerboseOutput
    [Switch] Enables verbose output to the terminal for detailed results.

.PARAMETER Export
    [Switch] Exports query results to CSV files.

.PARAMETER IncludeSampleSet
    [Switch] Adds a sample set of up to 10 rows per query to the generated HTML report.

.PARAMETER TimeFrame
    The time range for KQL queries (e.g., "7d", "14d", "24h"). Optional. Default is "7d".

.EXAMPLE
    Investigate a device interactively with verbose output:
    .\KustoHawk.ps1 -DeviceId "abcdef1234567890abcdef1234567890abcdef12" -AuthenticationMethod User -VerboseOutput

.EXAMPLE
    Investigate a user account and export all results:
    .\KustoHawk.ps1 -UserPrincipalName "user@contoso.com" -AuthenticationMethod ServicePrincipalSecret -Export

.EXAMPLE
    Run triage for both a device and a user:
    .\KustoHawk.ps1 -DeviceId 2694a7cc2225f3b66f7cf8b6388a78b1857fadca -upn user@contoso.com -AuthenticationMethod User -TimeFrame 7d -v

.EXAMPLE
    Include up to 10 sample rows per query in the HTML report:
    .\KustoHawk.ps1 -DeviceId 2694a7cc2225f3b66f7cf8b6388a78b1857fadca -AuthenticationMethod User -IncludeSampleSet

.LINK
    https://github.com/Bert-JanP/KustoHawk

.NOTES
    - Either -DeviceId or -UserPrincipalName (or both) must be provided.
    - For Service Principal authentication, configure $AppID, $TenantID, and $Secret at the top of the script.
    - KQL queries are loaded from Resources Folder
    - Results are output as tables, CSV, and HTML reports in the current directory.
    - Requires Microsoft.Graph.Security PowerShell module.
#>
#Requires -Modules Microsoft.Graph.Security

param (
        [Parameter(Mandatory=$false)][Alias('host')][string]$DeviceId,
        [Parameter(Mandatory=$false)][Alias('upn')][string]$UserPrincipalName,
        [Parameter(Mandatory = $false)][Alias('v')][switch]$VerboseOutput,
        [Parameter(Mandatory = $false)][Alias('e')][switch]$Export,
        [Parameter(Mandatory = $false)][Alias('s')][switch]$IncludeSampleSet,
        [Parameter(Mandatory = $false)][Alias('t')][string]$TimeFrame = "7d",
        [Parameter(Mandatory = $false)][string]$CertificateThumbprint,
        [Parameter(Mandatory = $true)][ValidateSet("User", "ServicePrincipalSecret", "ServicePrincipalCertificate")][string]$AuthenticationMethod
    )


# Import Modules
Import-Module Microsoft.Graph.Security

# Set Service Principal Variables
$AppID = "<AppID>"
$TenantID = "<TentantID>"
$Secret = "<Secret>" #Certificate Authentication is recommended.
$DefaultCertificateThumbprint = "2AFAC22579550A51D9F875E3B86A1420D1BFAC7D"
$SecureClientSecret = ConvertTo-SecureString -String $Secret -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AppID, $SecureClientSecret

function Connect-GraphAPI-ServicePrincipalSecret {
    Write-Host "Connecting to Microsoft Graph API with AppId $AppID..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential
}

function Connect-GraphAPI-ServicePrincipalCertificate {
    $EffectiveThumbprint = if ([string]::IsNullOrWhiteSpace($CertificateThumbprint)) { $DefaultCertificateThumbprint } else { $CertificateThumbprint }

    if ([string]::IsNullOrWhiteSpace($EffectiveThumbprint) -or $EffectiveThumbprint -like "<*>") {
        Write-Host "Certificate authentication selected, but no valid thumbprint is configured." -ForegroundColor Red
        Write-Host "Set -CertificateThumbprint or update the placeholder value in the script." -ForegroundColor Yellow
        return
    }

    $cert = Get-Item -Path "Cert:\CurrentUser\My\$EffectiveThumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) {
        $cert = Get-Item -Path "Cert:\LocalMachine\My\$EffectiveThumbprint" -ErrorAction SilentlyContinue
    }

    if (-not $cert) {
        Write-Host "Certificate with thumbprint '$EffectiveThumbprint' was not found in CurrentUser or LocalMachine personal stores." -ForegroundColor Red
        return
    }

    Write-Host "Connecting to Microsoft Graph API with AppId $AppID using certificate thumbprint $EffectiveThumbprint..." -ForegroundColor Cyan
    Connect-MgGraph -ClientId $AppID -TenantId $TenantID -CertificateThumbprint $EffectiveThumbprint -NoWelcome
}

function Connect-GraphAPI-User {
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "ThreatHunting.Read.All" -NoWelcome
}

function Connect-GraphAPI {
    switch ($AuthenticationMethod) {
        "User" {
            Write-Host "You selected User Authentication.`nConnecting with Connect-GraphAPI-User..." -ForegroundColor Cyan
            Connect-GraphAPI-User
        }
        "ServicePrincipalSecret" {
            Write-Host "You selected Service Principal Authentication using an Application Secret.`nConnecting with Connect-GraphAPI-ServicePrincipal..." -ForegroundColor Cyan
            Connect-GraphAPI-ServicePrincipalSecret
        }
        "ServicePrincipalCertificate" {
            Write-Host "You selected Service Principal Authentication using an Application Certificate.`nConnecting with Connect-GraphAPI-ServicePrincipal..." -ForegroundColor Cyan
            Connect-GraphAPI-ServicePrincipalCertificate
        }
        default {
            Write-Host "No authentication method found. Use -AuthenticationMethod User or -AuthenticationMethod ServicePrincipal to connect to the Graph API" -ForegroundColor Red
        }
    }
}

function ValidateInputParameters {
    $DeviceIdPattern = '^[a-fA-F0-9]{40}$'
    if ($DeviceId) {
        if ($DeviceId -match $DeviceIdPattern) {
            Write-Host "DeviceId set to: $DeviceId" -ForegroundColor Cyan
        } else {
            Write-Host "DeviceId is INVALID. Must be a 40-character hexadecimal string." -ForegroundColor Red
            $DeviceId = $null
        }
    }

    $UPNPattern = '^[^@]+@[^@]+\.[^@]+$'
    if ($UserPrincipalName) {
        if ($UserPrincipalName -match $UPNPattern) {
            Write-Host "UserPrincipalName set to: $UserPrincipalName" -ForegroundColor Cyan
        } else {
            Write-Host "UserPrincipalName is INVALID. Must be in the format username@domain.com." -ForegroundColor Red
            $UserPrincipalName = $null
        }
    }

    return @{
        DeviceId = $DeviceId
        UserPrincipalName = $UserPrincipalName
    }
}

function RunKQLQuery {
    param (
        [string]$Query,
        [bool]$WriteResultsToTerminal,
        [bool]$ExportResults,
        [string]$FileName,
        [string]$TimeFrame,
        [bool]$IncludeSampleSet
    )
    $params = @{
        Query = $Query
        Timespan = "P180D"
    }
    
    $Results = Start-MgSecurityHuntingQuery -BodyParameter $params
    $rows = @($Results.Results)
    $allKeys = $rows | ForEach-Object { $_.AdditionalProperties.Keys } | Select-Object -Unique

    $table = @()
    foreach ($row in $rows) {
        $obj = New-Object PSObject
        foreach ($key in $allKeys) {
            $value = $row.AdditionalProperties[$key]
            # Optionally, flatten arrays or objects to strings
            if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
                $obj | Add-Member -NotePropertyName $key -NotePropertyValue ($value -join ", ")
            } else {
                $obj | Add-Member -NotePropertyName $key -NotePropertyValue $value
            }
        }
        $table += $obj
    }

    if ($WriteResultsToTerminal){
        $table | Format-Table -Property $allKeys -AutoSize | Out-Host
    }
    if ($ExportResults -And $table.count -ne 0){
        $ExportName = $FileName + ".csv"
        $table | Export-CSV .\$ExportName -NoTypeInformation
    }

    $sampleRows = @()
    if ($IncludeSampleSet) {
        $sampleRows = @($table | Select-Object -First 10)
    }

    return @{
        ResultCount = $table.count
        SampleRows = $sampleRows
    }

}

function GetEntityInfo {
    param (
        [string]$DeviceId,
        [string]$UserPrincipalName
    )
    $UserInfo = "IdentityInfo
        | where AccountUpn =~ '$UserPrincipalName'
        | where Timestamp > ago(14d)
        | summarize arg_max(Timestamp, *) by AccountUpn
        | project Timestamp, AccountUpn, AccountObjectId, AccountName, RiskLevel, Department, JobTitle, Manager, PriviligedRoles = tostring(PrivilegedEntraPimRoles)"
    $DeviceInfo = "DeviceInfo
        | where DeviceId == '$DeviceId'
        | where Timestamp > ago(14d)
        | summarize arg_max(Timestamp, *) by DeviceId
        | project Timestamp, DeviceName, PublicIP, OSPlatform, JoinType, AadDeviceId, MachineGroup, ExposureLevel"
    if ($DeviceId){
            $params = @{
            Query = $DeviceInfo
            Timespan = "P180D"
        }
        $Results = Start-MgSecurityHuntingQuery -BodyParameter $params
        $Results.Results | ForEach-Object {
        $data = [PSCustomObject]@{
            Timestamp = $_.AdditionalProperties["Timestamp"]
            DeviceName = $_.AdditionalProperties["DeviceName"]
            PublicIP = $_.AdditionalProperties["PublicIP"]
            OSPlatform = $_.AdditionalProperties["OSPlatform"]
            JoinType = $_.AdditionalProperties["JoinType"]
            AadDeviceId = $_.AdditionalProperties["AadDeviceId"]
            MachineGroup = $_.AdditionalProperties["MachineGroup"]
            ExposureLevel = $_.AdditionalProperties["ExposureLevel"]
        }
    }
    Write-Host "Host information for $DeviceId" -ForegroundColor Cyan
    # Table borders and headers
    $border = "+-------------------+------------------------------------------------------------------------------------+"
    $header = "| Details           | Values                                                                             |"

    Write-Host $border -ForegroundColor Cyan
    Write-Host $header -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Cyan

    foreach ($prop in $data.PSObject.Properties) {
        $row = "| " + $prop.Name.PadRight(18) + "| " + $prop.Value.ToString().PadRight(83) + "|"
        Write-Host $row -ForegroundColor Cyan
    }

    Write-Host $border -ForegroundColor Cyan
    }
    if ($UserPrincipalName){
            $params = @{
            Query = $UserInfo
            Timespan = "P180D"
        }
        $Results = Start-MgSecurityHuntingQuery -BodyParameter $params
        $Results.Results | ForEach-Object {
        $data = [PSCustomObject]@{
            Timestamp = $_.AdditionalProperties["Timestamp"]
            AccountUpn = $_.AdditionalProperties["AccountUpn"]
            AccountName = $_.AdditionalProperties["AccountName"]
            RiskLevel = $_.AdditionalProperties["RiskLevel"]
            Department = $_.AdditionalProperties["Department"]
            JobTitle = $_.AdditionalProperties["JobTitle"]
            Manager = $_.AdditionalProperties["Manager"]
            PriviligedRoles = $_.AdditionalProperties["PriviligedRoles"]
        }
    }
    Write-Host "Identity information for $UserPrincipalName" -ForegroundColor Cyan
    # Table borders and headers
    $border = "+-------------------+------------------------------------------------------------------------------------+"
    $header = "| Details           | Values                                                                             |"

    Write-Host $border -ForegroundColor Cyan
    Write-Host $header -ForegroundColor Cyan
    Write-Host $border -ForegroundColor Cyan

    foreach ($prop in $data.PSObject.Properties) {
        $row = "| " + $prop.Name.PadRight(18) + "| " + $prop.Value.ToString().PadRight(83) + "|"
        Write-Host $row -ForegroundColor Cyan
    }

    Write-Host $border -ForegroundColor Cyan
    }
}   

function RunQueriesFromFile {
    param (
        [string]$FileName,
        [string]$DeviceId,
        [string]$UserPrincipalName,
        [bool]$IncludeSampleSet
    )
    # Load the queries from the JSON file
    $KQLQueries = Get-Content -Raw -Path $FileName | ConvertFrom-Json

    foreach ($q in $KQLQueries) {
        $queryText = $q.Query -replace '\{DeviceId\}', $DeviceId -replace '\{TimeFrame\}', $TimeFrame -replace '\{UserPrincipalName\}', $UserPrincipalName
        $Results = RunKQLQuery -Query $queryText -WriteResultsToTerminal $VerboseOutput -ExportResults $Export -FileName $q.Name -IncludeSampleSet $IncludeSampleSet

        # Ensure ResultCount property is added/updated on the query object
        if ($null -ne $q.PSObject) {
            $q | Add-Member -NotePropertyName ResultCount -NotePropertyValue $Results.ResultCount -Force
            $q | Add-Member -NotePropertyName SampleResults -NotePropertyValue @($Results.SampleRows) -Force
        } else {
            # Fallback: create property directly
            $q.ResultCount = $Results.ResultCount
            $q.SampleResults = @($Results.SampleRows)
        }

        if ($Results.ResultCount -eq 0){
            Write-Host "[0] Results for $($q.Name)" -ForegroundColor Green
        }
        else {
            $Count = $Results.ResultCount
            Write-Host "[$Count] Results for $($q.Name)" -ForegroundColor Red
        }
    }

    # Write the updated JSON back to the same file (no backup)
    try {
        $persistQueries = $KQLQueries | Select-Object * -ExcludeProperty SampleResults
        # Convert updated object back to JSON. Increase depth in case Query objects contain nested structures.
        $jsonOut = $persistQueries | ConvertTo-Json -Depth 10
        $jsonOut | Set-Content -Path $FileName -Encoding UTF8
        Write-Host "Updated '$FileName' with ResultCount values." -ForegroundColor Cyan
    } catch {
        Write-Warning "Failed to write updated queries back to '$FileName': $_"
    }

    return $KQLQueries
}

function GenerateQueryReport {
    param (
        [string]$FileName,
        [string]$QueryType,
        [bool]$IncludeSampleSet,
        [object[]]$QueryData
    )
    if ($null -ne $QueryData -and $QueryData.Count -gt 0) {
        $KQLQueries = $QueryData
    } else {
        $KQLQueries = Get-Content -Raw -Path ".\$FileName" | ConvertFrom-Json
    }
    switch($QueryType) {
            'Device' {
        $Entity = $DeviceId
        break
        }
        'Identity' {
            $Entity = $UserPrincipalName
            break
        }
        Default {
            $Entity = $null
            Write-Warning "Unknown QueryType '$QueryType'. Entity set to `$null."
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <title>Executed Queries Report</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
        :root {
            --neutral-bg-1: #ffffff;
            --neutral-bg-2: #faf9f8;
            --neutral-bg-3: #f3f2f1;
            --neutral-stroke-1: #edebe9;
            --neutral-stroke-2: #e1dfdd;
            --neutral-foreground-1: #242424;
            --neutral-foreground-2: #605e5c;
            --brand-foreground-1: #0f6cbd;
            --brand-bg-1: #0f6cbd;
            --brand-bg-2: #deecf9;
        }
        body {
            font-family: 'Segoe UI', 'Arial', sans-serif;
            background: linear-gradient(180deg, #f6f8fb 0%, #eef2f7 100%);
            margin: 0;
            padding: 0;
            color: var(--neutral-foreground-1);
        }
        .container {
            max-width: 1200px;
            margin: 40px auto 0 auto;
            background: var(--neutral-bg-1);
            border-radius: 12px;
            border: 1px solid var(--neutral-stroke-1);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.06);
            padding: 32px;
            min-height: 70vh;
        }
        h1 {
            text-align: center;
            color: var(--neutral-foreground-1);
            margin-top: 0;
            margin-bottom: 32px;
            font-size: 2.1em;
            letter-spacing: 1px;
        }

        .report-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background: var(--neutral-bg-1);
            border: 1px solid var(--neutral-stroke-1);
            border-radius: 8px;
            overflow: hidden;
            table-layout: fixed;
        }

        .report-table thead th {
            background: var(--neutral-bg-3);
            color: var(--neutral-foreground-1);
            border-bottom: 1px solid var(--neutral-stroke-2);
            text-align: left;
            font-weight: 600;
            font-size: 0.95rem;
            padding: 12px;
        }

        .report-table tbody td {
            border-bottom: 1px solid var(--neutral-stroke-1);
            padding: 12px;
            vertical-align: top;
            color: var(--neutral-foreground-1);
        }

        .report-table tbody tr.query-row:hover {
            background: var(--neutral-bg-2);
        }

        .col-name { width: 24%; }
        .col-query { width: 46%; }
        .col-hits { width: 10%; text-align: center; }
        .col-source { width: 20%; }

        .cell-name,
        .cell-source {
            word-break: break-word;
        }

        .query-pre {
            background: #111827;
            color: #f9fafb;
            font-size: 0.92em;
            padding: 12px;
            border-radius: 6px;
            margin: 0;
            overflow-x: auto;
            white-space: pre-wrap;
            max-height: 280px;
        }

        .cell-hits {
            text-align: center;
        }

        .hits-pill {
            display: inline-block;
            min-width: 28px;
            padding: 3px 10px;
            border-radius: 999px;
            font-weight: 700;
            font-size: 0.86rem;
            color: #ffffff;
            background: var(--brand-bg-1);
        }

        .hits-pill.zero {
            background: #8a8886;
        }

        .sample-row td {
            background: var(--neutral-bg-2);
            border-bottom: 1px solid var(--neutral-stroke-1);
        }

        .sample-details {
            margin-top: 2px;
        }

        .sample-details summary {
            cursor: pointer;
            color: var(--brand-foreground-1);
            font-weight: 600;
            padding: 4px 0;
        }

        .sample-json {
            margin: 8px 0 0 0;
            padding: 10px;
            background: #ffffff;
            border: 1px solid var(--neutral-stroke-2);
            border-radius: 6px;
            overflow: auto;
            max-height: 320px;
            white-space: pre-wrap;
            word-break: break-word;
            font-size: 0.9em;
        }

        .sample-empty {
            margin-top: 8px;
            color: var(--neutral-foreground-2);
            font-size: 0.92em;
        }

        @media (max-width: 900px) {
            .container { padding: 16px; }
            .report-table,
            .report-table thead,
            .report-table tbody,
            .report-table tr,
            .report-table th,
            .report-table td {
                display: block;
                width: 100%;
            }
            .report-table thead { display: none; }
            .report-table tbody td { border-bottom: none; padding: 10px 12px; }
            .report-table tbody tr.query-row,
            .report-table tbody tr.sample-row {
                border-bottom: 1px solid var(--neutral-stroke-1);
                padding-bottom: 8px;
                margin-bottom: 8px;
            }
            .cell-hits { text-align: left; }
            .query-pre { max-height: 220px; }
        }
        .footer {
            text-align: center;
            color: #8d99ae;
            font-size: 1em;
            padding: 18px 0 12px 0;
            margin-top: 24px;
            background: #eaf0fa;
            border-top: 1px solid #d4dbe7;
            border-radius: 0 0 18px 18px;
            letter-spacing: 0.5px;
            font-family: 'Segoe UI', 'Arial', sans-serif;
        }
        a {
            color: #0077cc;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover { text-decoration: underline; color: #005fa3; }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Executed Queries ($QueryType - $Entity)</h1>
        <table class='report-table' aria-label='Executed queries'>
            <thead>
                <tr>
                    <th class='col-name'>Name</th>
                    <th class='col-query'>Query</th>
                    <th class='col-hits'>Hits</th>
                    <th class='col-source'>Source</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($q in $KQLQueries) {
        $queryText = $q.Query -replace '\{DeviceId\}', $DeviceId -replace '\{TimeFrame\}', $TimeFrame -replace '\{UserPrincipalName\}', $UserPrincipalName
        $name = [System.Web.HttpUtility]::HtmlEncode($q.Name)
        $queryRendered = [System.Web.HttpUtility]::HtmlEncode($queryText)
        $hits = if ($q.PSObject.Properties.Match('ResultCount')) { $q.ResultCount } else { 0 }
        $source = $q.Source
        $sourceLink = if ($source -match '^https?://') {
            $sourceUrl = [System.Web.HttpUtility]::HtmlEncode($source)
            "<a href='$sourceUrl' target='_blank' rel='noopener noreferrer'>Query Link</a>"
        } else {
            [System.Web.HttpUtility]::HtmlEncode($source)
        }

        $hitsClass = if ($hits -eq 0) { 'hits-pill zero' } else { 'hits-pill' }
        $html += "<tr class='query-row'><td class='cell-name'>$name</td><td><pre class='query-pre'>$queryRendered</pre></td><td class='cell-hits'><span class='$hitsClass'>$hits</span></td><td class='cell-source'>$sourceLink</td></tr>`n"

        if ($IncludeSampleSet) {
            $sampleRows = @()
            if ($q.PSObject.Properties.Match('SampleResults')) {
                $sampleRows = @($q.SampleResults)
            }

            if ($sampleRows.Count -gt 0) {
                $sampleJson = [System.Web.HttpUtility]::HtmlEncode(($sampleRows | ConvertTo-Json -Depth 8))
                $sampleBody = "<pre class='sample-json'>$sampleJson</pre>"
            } else {
                $sampleBody = "<div class='sample-empty'>No sample rows available.</div>"
            }

            $html += "<tr class='sample-row'><td colspan='4'><details class='sample-details'><summary>View sample results (max 10)</summary>$sampleBody</details></td></tr>`n"
        }
    }

$html += @"
            </tbody>
        </table>
    </div>
    <div class='footer' style='padding:12px 16px; text-align:center; font-size:0.9rem; color:#444;'>
        &copy; 2025 <span class='trademark'>Bert-Jan Pals &trade;</span> — All rights reserved.
        <div class='social' style='margin-top:8px; display:inline-flex; gap:12px; align-items:center;'>
            <a href='https://github.com/bert-janp' target='_blank' rel='noopener noreferrer' aria-label='GitHub' title='GitHub' style='color:inherit; text-decoration:none;'>
                <svg width='20' height='20' viewBox='0 0 16 16' fill='currentColor' xmlns='http://www.w3.org/2000/svg' style='vertical-align:middle;'>
                    <path fill-rule='evenodd' d='M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82A7.65 7.65 0 0 1 8 4.6c.68.003 1.37.092 2.01.27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.19 0 .21.15.46.55.38A8.001 8.001 0 0 0 16 8c0-4.42-3.58-8-8-8z'/>
                </svg>
            </a>
            <a href='https://www.linkedin.com/in/bert-janpals/' target='_blank' rel='noopener noreferrer' aria-label='LinkedIn' title='LinkedIn' style='color:inherit; text-decoration:none;'>
                <svg width='20' height='20' viewBox='0 0 24 24' fill='currentColor' xmlns='http://www.w3.org/2000/svg' style='vertical-align:middle;'>
                    <path d='M4.98 3.5C4.98 4.88071 3.87 6 2.5 6 1.12 6 0 4.88 0 3.5 0 2.12 1.12 1 2.5 1 3.87 1 4.98 2.12 4.98 3.5zM.24 8.98h4.52V24H.24zM8.98 8.98h4.34v2.05h.06c.6-1.14 2.06-2.34 4.24-2.34 4.54 0 5.37 2.99 5.37 6.88V24h-4.52v-7.03c0-1.68-.03-3.85-2.35-3.85-2.35 0-2.71 1.84-2.71 3.73V24H8.98z'/>
                </svg>
            </a>
            <a href='https://x.com/BertJanCyber' target='_blank' rel='noopener noreferrer' aria-label='X (Twitter)' title='X (Twitter)' style='color:inherit; text-decoration:none;'>
                <svg width='20' height='20' viewBox='0 0 24 24' fill='currentColor' xmlns='http://www.w3.org/2000/svg' style='vertical-align:middle;'>
                    <path d='M23.77 2.28a1 1 0 0 0-1.4-.14L13 10.34 1.63 2.12A1 1 0 0 0 .2 3.47l10.9 8.18L1.8 20.03a1 1 0 0 0 .55 1.82c.22 0 .44-.06.63-.18L13 13.66l9.1 8.01c.25.22.59.32.92.26.35-.06.66-.3.81-.63.14-.33.1-.71-.12-1.01L13.96 11.7l9.8-8.08a1 1 0 0 0 .01-1.34z'/>
                </svg>
            </a>
        </div>
    </div>
</body>
</html>
"@

    $outputDir = Join-Path -Path (Get-Location) -ChildPath 'Reports'

    if (-not (Test-Path -Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory | Out-Null
    }

    $outFile = Join-Path -Path $outputDir -ChildPath "$QueryType-ExecutedQueries-$Entity.html"
    $html | Set-Content $outFile
    Write-Host "Report saved to $outFile"
}

$Version = '2.0.0'
$ASCIIBanner = @"
 _   __          _        _   _                _    
| | / /         | |      | | | |              | |   
| |/ / _   _ ___| |_ ___ | |_| | __ ___      _| | __
|    \| | | / __| __/ _ \|  _  |/ _` \ \ /\ / / |/ /
| |\  \ |_| \__ \ || (_) | | | | (_| |\ V  V /|   < 
\_| \_/\__,_|___/\__\___/\_| |_/\__,_| \_/\_/ |_|\_\`n
"@
Write-Host $ASCIIBanner -ForegroundColor Cyan
Write-Host "Version: $Version" -ForegroundColor Cyan
Write-Host "Developed by Bert-Jan Pals | Twitter: @BertJanCyber | Github: Bert-JanP" -ForegroundColor Cyan

if (-not $DeviceId -And -not $UserPrincipalName) {
         Write-Host "No DeviceId or UserPrincipalName found." -ForegroundColor Red
         exit 
}

if ($VerboseOutput) {
    Write-Host "[*] Verbose mode enabled." -ForegroundColor Cyan
}

Connect-GraphAPI
$info = ValidateInputParameters
GetEntityInfo $info.DeviceId $info.UserPrincipalName
if ($DeviceId){
    $json = Get-Content -Raw -Path '.\Resources\DeviceQueries.json' | ConvertFrom-Json
    $count = $json.Count
    Write-Host "Starting $count triage queries for $DeviceId" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    $deviceQueryResults = RunQueriesFromFile .\Resources\DeviceQueries.json  $info.DeviceId $info.UserPrincipalName $IncludeSampleSet
    GenerateQueryReport .\Resources\DeviceQueries.json Device $IncludeSampleSet $deviceQueryResults
}
if ($UserPrincipalName){
    $json = Get-Content -Raw -Path '.\Resources\IdentityQueries.json' | ConvertFrom-Json
    $count = $json.Count
    Write-Host "Starting $count traige queries for $UserPrincipalName" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    $identityQueryResults = RunQueriesFromFile .\Resources\IdentityQueries.json  $info.DeviceId $info.UserPrincipalName $IncludeSampleSet
    GenerateQueryReport .\Resources\IdentityQueries.json Identity $IncludeSampleSet $identityQueryResults
}