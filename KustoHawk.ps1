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

.PARAMETER AuthenticationTier
    The authentication permission tier to use. Tiers are defined in Resources\AuthenticationTiers.yaml.
    Supported values: Tier1, Tier2, Tier3.

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

param (
        [Parameter(Mandatory=$false)][Alias('host')][string]$DeviceId,
        [Parameter(Mandatory=$false)][Alias('upn')][string]$UserPrincipalName,
        [Parameter(Mandatory = $false)][Alias('v')][switch]$VerboseOutput,
        [Parameter(Mandatory = $false)][Alias('e')][switch]$Export,
        [Parameter(Mandatory = $false)][Alias('s')][switch]$IncludeSampleSet,
        [Parameter(Mandatory = $false)][Alias('t')][string]$TimeFrame = "7d",
        [Parameter(Mandatory = $false)][string]$CertificateThumbprint,
        [Parameter(Mandatory = $false)][ValidateSet("Tier1", "Tier2", "Tier3")][string]$AuthenticationTier = "Tier1",
        [Parameter(Mandatory = $true)][ValidateSet("User", "ServicePrincipalSecret", "ServicePrincipalCertificate")][string]$AuthenticationMethod
    )

# Set Service Principal Variables
$AppID = "<AppID>"
$TenantID = "<TentantID>"
$Secret = "<Secret>" #Certificate Authentication is recommended.
$DefaultCertificateThumbprint = "" # The certificate must exist in Cert:\CurrentUser\My or Cert:\LocalMachine\My
$SecureClientSecret = ConvertTo-SecureString -String $Secret -AsPlainText -Force
$ClientSecretCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AppID, $SecureClientSecret
$AuthTierConfigPath = Join-Path -Path $PSScriptRoot -ChildPath 'Resources\AuthenticationTiers.yaml'
$script:SelectedAuthTierConfig = $null

function Check-InstalledGraphModules {
    $moduleName = 'Microsoft.Graph.Security'

    if (Get-Module -ListAvailable -Name $moduleName) {
        Import-Module $moduleName -ErrorAction Stop
        return $true
    }

    Write-Host "$moduleName is not installed. Attempting install for CurrentUser..." -ForegroundColor Yellow

    try {
        Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Import-Module $moduleName -ErrorAction Stop
        Write-Host "$moduleName installed and imported." -ForegroundColor Green
        return $true
    } catch {
        Write-Host "Failed to install/import $moduleName. Install it manually with: Install-Module Microsoft.Graph.Security -Scope CurrentUser" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        return $false
    }
}

function Get-TierRoles {
    param (
        [string[]]$Lines
    )

    $tiers = @{}
    $currentTier = $null
    $inPermissions = $false

    foreach ($rawLine in $Lines) {
        $line = $rawLine -replace "`t", '    '
        if ($line -match '^\s*$' -or $line -match '^\s*#') {
            continue
        }

        if ($line -match '^\s*tiers\s*:\s*$') {
            continue
        }

        if ($line -match '^\s{2}([A-Za-z0-9_-]+)\s*:\s*$') {
            $currentTier = $matches[1].ToLower()
            $tiers[$currentTier] = @{ permissions = @() }
            $inPermissions = $false
            continue
        }

        if ($line -match '^\s{4}permissions\s*:\s*$') {
            $inPermissions = $true
            continue
        }

        if ($line -match '^\s{6}-\s*(.+?)\s*$') {
            if ($currentTier -and $inPermissions) {
                $tiers[$currentTier]['permissions'] += $matches[1]
            }
            continue
        }
    }

    return @{ tiers = $tiers }
}

function Get-AuthenticationTierConfig {
    param (
        [string]$ConfigPath,
        [string]$TierName
    )

    if (-not (Test-Path -Path $ConfigPath)) {
        throw "Authentication tier config file was not found at '$ConfigPath'."
    }

    $yamlText = Get-Content -Raw -Path $ConfigPath
    if ([string]::IsNullOrWhiteSpace($yamlText)) {
        throw "Authentication tier config file '$ConfigPath' is empty."
    }

    $parsed = $null
    if (Get-Command -Name ConvertFrom-Yaml -ErrorAction SilentlyContinue) {
        $parsed = $yamlText | ConvertFrom-Yaml
    } else {
        $parsed = Get-TierRoles -Lines (Get-Content -Path $ConfigPath)
    }

    if (-not $parsed -or -not $parsed.tiers) {
        throw "Authentication tier config file '$ConfigPath' does not contain a 'tiers' section."
    }

    $tierKey = $TierName.ToLower()
    $tierData = $null

    if ($parsed.tiers -is [System.Collections.IDictionary]) {
        $tierData = $parsed.tiers[$tierKey]
    } elseif ($parsed.tiers.PSObject.Properties.Match($tierKey).Count -gt 0) {
        $tierData = $parsed.tiers.$tierKey
    }

    if (-not $tierData) {
        throw "Authentication tier '$TierName' was not found in '$ConfigPath'."
    }

    $permissions = @($tierData.permissions | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | Select-Object -Unique)

    return [PSCustomObject]@{
        Name        = $TierName
        Permissions = $permissions
    }
}

function Get-EffectiveTierScopes {
    param (
        [PSObject]$TierConfig
    )

    $scopes = @($TierConfig.Permissions)

    # Only request auth method permissions when a UPN investigation is in scope.
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) {
        $scopes = @($scopes | Where-Object { $_ -ne 'UserAuthenticationMethod.Read.All' })
    }

    return @($scopes | Select-Object -Unique)
}

function Test-AuthMethodsScopeEnabled {
    if (-not $script:SelectedAuthTierConfig) {
        return $false
    }

    return @($script:SelectedAuthTierConfig.Permissions | Where-Object { $_ -eq 'UserAuthenticationMethod.Read.All' }).Count -gt 0
}

function Connect-GraphAPI-ServicePrincipalSecret {
    Write-Host "Connecting to Microsoft Graph API with AppId $AppID..." -ForegroundColor Cyan
    $requiredPermissions = Get-EffectiveTierScopes -TierConfig $script:SelectedAuthTierConfig
    if ($requiredPermissions.Count -gt 0) {
        Write-Host "Selected authentication tier: $($script:SelectedAuthTierConfig.Name)" -ForegroundColor Cyan
        Write-Host "Required permissions: $($requiredPermissions -join ', ')" -ForegroundColor DarkCyan
    }
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential -NoWelcome
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
    $requiredPermissions = Get-EffectiveTierScopes -TierConfig $script:SelectedAuthTierConfig
    if ($requiredPermissions.Count -gt 0) {
        Write-Host "Selected authentication tier: $($script:SelectedAuthTierConfig.Name)" -ForegroundColor Cyan
        Write-Host "Required permissions: $($requiredPermissions -join ', ')" -ForegroundColor DarkCyan
    }
    Connect-MgGraph -ClientId $AppID -TenantId $TenantID -CertificateThumbprint $EffectiveThumbprint -NoWelcome
}

function Connect-GraphAPI-User {
    Write-Host "Connecting to Microsoft Graph API..." -ForegroundColor Cyan
    $scopes = Get-EffectiveTierScopes -TierConfig $script:SelectedAuthTierConfig
    if ($scopes.Count -eq 0) {
        throw "No permissions remain after evaluating tier '$($script:SelectedAuthTierConfig.Name)'."
    }

    Write-Host "Selected authentication tier: $($script:SelectedAuthTierConfig.Name)" -ForegroundColor Cyan
    Write-Host "Required permissions: $($scopes -join ', ')" -ForegroundColor DarkCyan

    Connect-MgGraph -Scopes $scopes -NoWelcome
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

function Resolve-EffectiveTier {
    param (
        [string]$RequestedTier
    )

    $ctx = Get-MgContext
    if (-not $ctx) {
        Write-Host "No active Microsoft Graph session found after authentication." -ForegroundColor Red
        return $null
    }

    # Normalise granted scopes 
    $grantedScopes = @($ctx.Scopes | Where-Object { $_ } | ForEach-Object { $_.ToLower().Trim() })

    # Build fallback list from requested tier down to Tier1
    $allTiers = @('Tier3', 'Tier2', 'Tier1')
    $startIndex = [array]::IndexOf($allTiers, $RequestedTier)
    if ($startIndex -lt 0) { $startIndex = $allTiers.Count - 1 }
    $tiersToTry = $allTiers[$startIndex..($allTiers.Count - 1)]

    $hasIndividualScopes = ($grantedScopes | Where-Object { $_ -match '\.' -and $_ -notlike '*graph.microsoft.com*' }).Count -gt 0

    if ($hasIndividualScopes) {
        foreach ($tier in $tiersToTry) {
            try {
                $tierConfig = Get-AuthenticationTierConfig -ConfigPath $AuthTierConfigPath -TierName $tier
            } catch {
                continue
            }

            $required = @($tierConfig.Permissions | ForEach-Object { $_.ToLower() })
            $missing  = @($required | Where-Object { $grantedScopes -notcontains $_ })

            if ($missing.Count -eq 0) {
                if ($tier -ne $RequestedTier) {
                    Write-Host "Requested tier '$RequestedTier' could not be satisfied. Falling back to tier '$tier'." -ForegroundColor Yellow
                } else {
                    Write-Host "Permission check passed for tier '$tier'." -ForegroundColor Green
                }
                return $tierConfig
            } else {
                Write-Host "Tier '$tier' requires permissions not granted: $($missing -join ', ')." -ForegroundColor Yellow
                if ($tiersToTry.Count -gt 1 -and $tier -eq $RequestedTier) {
                    Write-Host "Attempting fallback to a lower tier..." -ForegroundColor Yellow
                }
            }
        }

        Write-Host "No usable tier found. At minimum 'ThreatHunting.Read.All' (Tier1) must be granted." -ForegroundColor Red
        Write-Host "Granted scopes: $($grantedScopes -join ', ')" -ForegroundColor Red
        return $null
    }

    Write-Host "Individual scopes not enumerable (Service Principal auth). Probing API access for minimum Tier1 permissions..." -ForegroundColor Yellow
    try {
        Start-MgSecurityHuntingQuery -BodyParameter @{ Query = 'DeviceInfo | take 1'; Timespan = 'P1D' } -ErrorAction Stop | Out-Null
        Write-Host "API probe succeeded. Proceeding with tier '$RequestedTier'." -ForegroundColor Green
        return Get-AuthenticationTierConfig -ConfigPath $AuthTierConfigPath -TierName $RequestedTier
    } catch {
        Write-Host "API probe failed: ThreatHunting.Read.All (Tier1 minimum) is not accessible." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
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

function ConvertTo-WrappedConsoleLines {
    param (
        [string]$Text,
        [int]$Width
    )

    if ($Width -lt 1) {
        return @('')
    }

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @('')
    }

    $lines = @()
    $sourceLines = "$Text" -split "`r?`n"

    foreach ($sourceLine in $sourceLines) {
        if ([string]::IsNullOrEmpty($sourceLine)) {
            $lines += ''
            continue
        }

        $remaining = $sourceLine
        while ($remaining.Length -gt $Width) {
            $breakIndex = $remaining.LastIndexOf(' ', $Width - 1)
            if ($breakIndex -lt 1) {
                $breakIndex = $Width
            }

            $lines += $remaining.Substring(0, $breakIndex).TrimEnd()
            $remaining = $remaining.Substring($breakIndex).TrimStart()
        }

        $lines += $remaining
    }

    return $lines
}

function Write-ConsoleDetailsTable {
    param (
        [string]$Title,
        [PSObject]$Data,
        [int]$DetailWidth,
        [int]$ValueWidth,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )

    if (-not $Data) {
        return
    }

    $properties = @($Data.PSObject.Properties)

    if (-not $PSBoundParameters.ContainsKey('DetailWidth')) {
        $maxDetailLength = ('Details').Length
        foreach ($prop in $properties) {
            $nameLength = "$($prop.Name)".Length
            if ($nameLength -gt $maxDetailLength) {
                $maxDetailLength = $nameLength
            }
        }
        $DetailWidth = [Math]::Max(12, $maxDetailLength)
    }

    if (-not $PSBoundParameters.ContainsKey('ValueWidth')) {
        $maxValueLength = ('Values').Length
        foreach ($prop in $properties) {
            $rawValue = if ([string]::IsNullOrWhiteSpace("$($prop.Value)")) { '' } else { "$($prop.Value)" }
            foreach ($line in ($rawValue -split "`r?`n")) {
                if ($line.Length -gt $maxValueLength) {
                    $maxValueLength = $line.Length
                }
            }
        }

        $consoleWidth = 120
        try {
            if ($Host -and $Host.UI -and $Host.UI.RawUI -and $Host.UI.RawUI.WindowSize.Width -gt 0) {
                $consoleWidth = $Host.UI.RawUI.WindowSize.Width
            }
        } catch {
            $consoleWidth = 120
        }

        # Account for separators and cell padding: "| " + Detail + " | " + Value + " |"
        $maxAvailableValueWidth = [Math]::Max(20, $consoleWidth - ($DetailWidth + 7))
        $ValueWidth = [Math]::Max(20, [Math]::Min($maxValueLength, $maxAvailableValueWidth))
    }

    $border = "+" + ("-" * ($DetailWidth + 2)) + "+" + ("-" * ($ValueWidth + 2)) + "+"
    $header = "| " + 'Details'.PadRight($DetailWidth) + " | " + 'Values'.PadRight($ValueWidth) + " |"

    Write-Host $Title -ForegroundColor $Color
    Write-Host $border -ForegroundColor $Color
    Write-Host $header -ForegroundColor $Color
    Write-Host $border -ForegroundColor $Color

    foreach ($prop in $properties) {
        $valueText = if ([string]::IsNullOrWhiteSpace("$($prop.Value)")) { '' } else { "$($prop.Value)" }
        $valueLines = ConvertTo-WrappedConsoleLines -Text $valueText -Width $ValueWidth

        $isFirstLine = $true
        foreach ($line in $valueLines) {
            $detailsText = if ($isFirstLine) { "$($prop.Name)" } else { '' }
            $row = "| " + $detailsText.PadRight($DetailWidth) + " | " + $line.PadRight($ValueWidth) + " |"
            Write-Host $row -ForegroundColor $Color
            $isFirstLine = $false
        }
    }

    Write-Host $border -ForegroundColor $Color
}

function Get-EntityInfo {
    param (
        [string]$DeviceId,
        [string]$UserPrincipalName
    )
    $deviceData = $null
    $identityData = $null

    $identityQuery = "IdentityInfo
| where AccountUpn =~ '$UserPrincipalName'
| where Timestamp > ago(14d)
| summarize arg_max(Timestamp, *) by AccountUpn
| project AccountUpn, AccountDisplayName, AccountObjectId, AccountName, CompanyName, Department, JobTitle, Manager, SourceProvider, CreatedDateTime, RiskLevel, RiskStatus, RiskScoreUpdateTime, PrivilegedEntraRoles = tostring(PrivilegedEntraPimRoles), GroupMembership"

    $deviceQuery = "DeviceInfo
| where DeviceId == '$DeviceId'
| where Timestamp > ago(14d)
| summarize arg_max(Timestamp, *) by DeviceId
| extend Tags = set_union(todynamic(DeviceDynamicTags), todynamic(DeviceManualTags))
| join kind=leftouter (DeviceNetworkInfo | summarize arg_max(Timestamp, Timestamp, IPAddresses, DeviceId, DnsAddresses) by DeviceId ) on DeviceId
| project DeviceId, DeviceName, Tags, OSPlatform, CloudPlatforms, JoinType, AadDeviceId, MachineGroup, ExposureLevel, PublicIP, AssignedIPs = IPAddresses, DnsAddresses"

    $deviceFields = @('DeviceId', 'DeviceName', 'Tags', 'OSPlatform', 'CloudPlatforms', 'JoinType', 'AadDeviceId', 'MachineGroup', 'ExposureLevel', 'PublicIP', 'AssignedIPs', 'DnsAddresses')
    $identityFields = @('AccountUpn', 'AccountDisplayName', 'AccountObjectId', 'AccountName', 'CompanyName', 'Department', 'JobTitle', 'Manager', 'SourceProvider', 'CreatedDateTime', 'RiskLevel', 'RiskStatus', 'RiskScoreUpdateTime', 'PrivilegedEntraPimRoles', 'GroupMembership')

    if ($DeviceId) {
        try {
            $deviceResult = Start-MgSecurityHuntingQuery -BodyParameter @{ Query = $deviceQuery; Timespan = 'P180D' }
            $deviceRow = @($deviceResult.Results)[0]
            if ($deviceRow -and $deviceRow.AdditionalProperties) {
                $deviceData = [PSCustomObject]@{}
                foreach ($field in $deviceFields) {
                    $rawValue = $deviceRow.AdditionalProperties[$field]
                    if ($rawValue -is [System.Collections.IEnumerable] -and -not ($rawValue -is [string])) {
                        $value = ($rawValue | ForEach-Object { "$_" }) -join ', '
                    } else {
                        $value = if ($null -eq $rawValue) { '' } else { "$rawValue" }
                    }
                    $deviceData | Add-Member -NotePropertyName $field -NotePropertyValue $value -Force
                }
            }
        } catch {
            Write-Warning "Failed to retrieve device information: $_"
        }

        if ($deviceData) {
            Write-ConsoleDetailsTable -Title "Host information for $DeviceId" -Data $deviceData
        }
    }

    if ($UserPrincipalName) {
        try {
            $identityResult = Start-MgSecurityHuntingQuery -BodyParameter @{ Query = $identityQuery; Timespan = 'P180D' }
            $identityRow = @($identityResult.Results)[0]
            if ($identityRow -and $identityRow.AdditionalProperties) {
                $identityData = [PSCustomObject]@{}
                foreach ($field in $identityFields) {
                    $rawValue = $identityRow.AdditionalProperties[$field]
                    if ($rawValue -is [System.Collections.IEnumerable] -and -not ($rawValue -is [string])) {
                        $value = ($rawValue | ForEach-Object { "$_" }) -join ', '
                    } else {
                        $value = if ($null -eq $rawValue) { '' } else { "$rawValue" }
                    }
                    $identityData | Add-Member -NotePropertyName $field -NotePropertyValue $value -Force
                }
            }
        } catch {
            Write-Warning "Failed to retrieve identity information: $_"
        }

        # Retrieve authentication methods only when enabled by the selected tier.
        $authMethodsText = 'Not enough privileges to collect data'
        $authMethodsCountText = 'Not enough privileges to collect data'
        if (Test-AuthMethodsScopeEnabled) {
            try {
                $authUri = "https://graph.microsoft.com/v1.0/users/$([System.Uri]::EscapeDataString($UserPrincipalName))/authentication/methods"
                $authResponse = Invoke-MgGraphRequest -Method GET -Uri $authUri -ErrorAction Stop
                if ($authResponse -and $authResponse.value) {
                    $typeMap = @{
                        'microsoftAuthenticatorAuthenticationMethod'  = 'Microsoft Authenticator'
                        'passwordAuthenticationMethod'                = 'Password'
                        'phoneAuthenticationMethod'                   = 'Phone'
                        'fido2AuthenticationMethod'                   = 'FIDO2 Key'
                        'emailAuthenticationMethod'                   = 'Email OTP'
                        'softwareOathAuthenticationMethod'            = 'Software OATH (TOTP)'
                        'temporaryAccessPassAuthenticationMethod'     = 'Temporary Access Pass'
                        'windowsHelloForBusinessAuthenticationMethod' = 'Windows Hello for Business'
                        'hardwareOathAuthenticationMethod'            = 'Hardware OATH'
                    }

                    $methodDetails = @()
                    foreach ($method in @($authResponse.value)) {
                        $odataType = "$($method['@odata.type'])"
                        $shortType = if ($odataType) { $odataType -replace '#microsoft\.graph\.', '' } else { 'unknown' }
                        $friendlyType = if ($typeMap.ContainsKey($shortType)) { $typeMap[$shortType] } else { $shortType }

                        $displayName = if ($method['displayName']) {
                            "$($method['displayName'])"
                        } else {
                            'Unnamed method'
                        }

                        $createdRaw = if ($method['createdDateTime']) {
                            "$($method['createdDateTime'])"
                        } elseif ($method['creationDateTime']) {
                            "$($method['creationDateTime'])"
                        } else {
                            $null
                        }

                        $createdText = 'Unknown'
                        if (-not [string]::IsNullOrWhiteSpace($createdRaw)) {
                            try {
                                $createdText = (Get-Date -Date $createdRaw -ErrorAction Stop).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss UTC')
                            } catch {
                                $createdText = $createdRaw
                            }
                        }

                        $methodDetails += ("Type: {0} | Name: {1} | Created: {2}" -f $friendlyType, $displayName, $createdText)
                    }

                    $authMethodsCountText = $methodDetails.Count
                    $authMethodsText = if ($methodDetails.Count -gt 0) { $methodDetails -join '; ' } else { 'None registered' }
                } else {
                    $authMethodsCountText = '0'
                    $authMethodsText = 'None registered'
                }
            } catch {
                throw "Failed to retrieve authentication methods while tier '$($script:SelectedAuthTierConfig.Name)' requires UserAuthenticationMethod.Read.All. Error: $($_.Exception.Message)"
            }
        } else {
            $authMethodsText = 'Insufficient permissions to retrieve authentication methods'
            $authMethodsCountText = 'Insufficient permissions to retrieve authentication methods'
        }
        if ($null -eq $identityData) { $identityData = [PSCustomObject]@{} }
        $identityData | Add-Member -NotePropertyName 'AuthenticationMethodsCount' -NotePropertyValue $authMethodsCountText -Force
        $identityData | Add-Member -NotePropertyName 'AuthenticationMethods' -NotePropertyValue $authMethodsText -Force

        if ($identityData) {
            Write-ConsoleDetailsTable -Title "Identity information for $UserPrincipalName" -Data $identityData
        }
    }

    return @{
        DeviceInfo = $deviceData
        IdentityInfo = $identityData
    }
}   

function GetAlertsForEntity {
    param (
        [string]$DeviceId,
        [string]$UserPrincipalName
    )
    $deviceAlerts = @()
    $identityAlerts = @()

    if ($DeviceId) {
        $q = "AlertInfo
| where Timestamp > ago(30d)
| join kind=inner (AlertEvidence | where DeviceId =~ '$DeviceId') on AlertId
| summarize arg_max(Timestamp, *) by AlertId
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, AttackTechniques"
        try {
            $r = Start-MgSecurityHuntingQuery -BodyParameter @{ Query = $q; Timespan = "P30D" }
            foreach ($row in $r.Results) {
                $deviceAlerts += [PSCustomObject]@{
                    Timestamp        = $row.AdditionalProperties["Timestamp"]
                    AlertId          = $row.AdditionalProperties["AlertId"]
                    Title            = $row.AdditionalProperties["Title"]
                    Severity         = $row.AdditionalProperties["Severity"]
                    Category         = $row.AdditionalProperties["Category"]
                    ServiceSource    = $row.AdditionalProperties["ServiceSource"]
                    AttackTechniques = $row.AdditionalProperties["AttackTechniques"]
                    EntityType       = 'Device'
                }
            }
            Write-Host "Retrieved $($deviceAlerts.Count) device alert(s)." -ForegroundColor Cyan
        } catch {
            Write-Warning "Failed to retrieve device alerts: $_"
        }
    }

    if ($UserPrincipalName) {
        $q = "AlertInfo
| where Timestamp > ago(30d)
| join kind=inner (AlertEvidence | where AccountUpn =~ '$UserPrincipalName') on AlertId
| summarize arg_max(Timestamp, *) by AlertId
| project Timestamp, AlertId, Title, Severity, Category, ServiceSource, AttackTechniques"
        try {
            $r = Start-MgSecurityHuntingQuery -BodyParameter @{ Query = $q; Timespan = "P30D" }
            foreach ($row in $r.Results) {
                $identityAlerts += [PSCustomObject]@{
                    Timestamp        = $row.AdditionalProperties["Timestamp"]
                    AlertId          = $row.AdditionalProperties["AlertId"]
                    Title            = $row.AdditionalProperties["Title"]
                    Severity         = $row.AdditionalProperties["Severity"]
                    Category         = $row.AdditionalProperties["Category"]
                    ServiceSource    = $row.AdditionalProperties["ServiceSource"]
                    AttackTechniques = $row.AdditionalProperties["AttackTechniques"]
                    EntityType       = 'User'
                }
            }
            Write-Host "Retrieved $($identityAlerts.Count) identity alert(s)." -ForegroundColor Cyan
        } catch {
            Write-Warning "Failed to retrieve identity alerts: $_"
        }
    }

    return @{
        DeviceAlerts   = $deviceAlerts
        IdentityAlerts = $identityAlerts
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

function Get-LogoBase64 {
    $logoPath = Join-Path -Path $PSScriptRoot -ChildPath 'Images/Logo-NoBackground.png'
    if (Test-Path $logoPath) {
        return [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($logoPath))
    }
    return $null
}

function GetReportFooterHtml {
    return @"
    <div class='footer'>
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
"@
}

function GenerateQueryReport {
    param (
        [string]$FileName,
        [string]$QueryType,
        [bool]$IncludeSampleSet,
        [object[]]$QueryData
    )
    $logoBase64 = Get-LogoBase64
    $logoImgHtml = if ($logoBase64) { "<img class='header-logo' src='data:image/png;base64,$logoBase64' alt='KustoHawk' />" } else { "" }

    if ($null -ne $QueryData -and $QueryData.Count -gt 0) {
        $KQLQueries = $QueryData
    } else {
        $KQLQueries = Get-Content -Raw -Path ".\$FileName" | ConvertFrom-Json
    }

    switch ($QueryType) {
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

    $devicePageFile = if (-not [string]::IsNullOrWhiteSpace($DeviceId)) { "Device-ExecutedQueries-$DeviceId.html" } else { $null }
    $userPageFile = if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) { "Identity-ExecutedQueries-$UserPrincipalName.html" } else { $null }
    $mainPageFile = 'index.html'

    $mainNavClass = 'nav-link'
    $deviceNavClass = if ($QueryType -eq 'Device') { 'nav-link active' } else { 'nav-link' }
    $userNavClass = if ($QueryType -eq 'Identity') { 'nav-link active' } else { 'nav-link' }

    $mainNav = "<a class='$mainNavClass' href='$mainPageFile'>Main</a>"
    $deviceNav = if ($devicePageFile) { "<a class='$deviceNavClass' href='$devicePageFile'>Device</a>" } else { "<span class='nav-link disabled'>Device</span>" }
    $userNav = if ($userPageFile) { "<a class='$userNavClass' href='$userPageFile'>User</a>" } else { "<span class='nav-link disabled'>User</span>" }

    $pageLabel = if ($QueryType -eq 'Identity') { 'User' } else { $QueryType }

    $html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <script>(function(){var t=localStorage.getItem('kustohawk-theme');if(t)document.documentElement.setAttribute('data-theme',t);})();</script>
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
        .page-header {
            position: sticky;
            top: 0;
            z-index: 10;
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(8px);
            border-bottom: 1px solid var(--neutral-stroke-1);
        }
        .header-inner {
            max-width: 1200px;
            margin: 0 auto;
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
        }
        .header-title {
            font-weight: 700;
            color: var(--neutral-foreground-1);
        }
        .nav-links {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .nav-link {
            text-decoration: none;
            color: var(--brand-foreground-1);
            border: 1px solid var(--neutral-stroke-2);
            background: #fff;
            border-radius: 999px;
            padding: 6px 14px;
            font-weight: 600;
            font-size: 0.9rem;
        }
        .nav-link.active {
            color: #fff;
            background: var(--brand-bg-1);
            border-color: var(--brand-bg-1);
        }
        .nav-link.disabled {
            color: var(--neutral-foreground-2);
            background: var(--neutral-bg-3);
            border-color: var(--neutral-stroke-2);
            cursor: not-allowed;
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
        .report-table-wrap {
            width: 100%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            border: 1px solid var(--neutral-stroke-1);
            border-radius: 8px;
            background: var(--neutral-bg-1);
        }
        .report-table {
            width: 100%;
            min-width: 980px;
            border-collapse: separate;
            border-spacing: 0;
            background: var(--neutral-bg-1);
            table-layout: auto;
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
        .col-name { width: 20%; min-width: 180px; }
        .col-query { width: auto; min-width: 380px; }
        .col-hits { width: 110px; min-width: 110px; text-align: center; white-space: nowrap; }
        .col-source { width: 160px; min-width: 160px; }
        .sort-button {
            border: none;
            background: transparent;
            font: inherit;
            font-weight: 700;
            color: inherit;
            cursor: pointer;
            padding: 0;
        }
        .sort-indicator {
            display: inline-block;
            min-width: 10px;
            margin-left: 4px;
        }
        .cell-name {
            font-weight: 700;
            overflow-wrap: anywhere;
        }
        .cell-source {
            overflow-wrap: anywhere;
        }
        .query-cell {
            position: relative;
        }
        .query-card {
            position: relative;
        }
        .copy-query-button {
            position: absolute;
            top: 8px;
            right: 8px;
            z-index: 2;
            border: 1px solid #334155;
            background: rgba(17, 24, 39, 0.92);
            color: #e5e7eb;
            border-radius: 6px;
            padding: 3px 10px;
            font-size: 0.78rem;
            font-weight: 600;
            cursor: pointer;
            opacity: 0;
            transition: opacity 0.15s;
        }
        .query-card:hover .copy-query-button {
            opacity: 1;
        }
        .copy-query-button:hover {
            background: rgba(30, 41, 59, 0.98);
        }
        .copy-query-button.copied {
            background: #166534;
            border-color: #22c55e;
            color: #dcfce7;
            opacity: 1;
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
            word-break: break-word;
            max-height: 280px;
        }
        .cell-hits {
            text-align: center;
            white-space: nowrap;
        }
        .cell-source {
            white-space: nowrap;
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
            overflow: hidden;
        }
        .sample-details {
            margin-top: 2px;
            width: 100%;
            max-width: 100%;
        }
        .sample-details summary {
            cursor: pointer;
            color: var(--brand-foreground-1);
            font-weight: 600;
            padding: 4px 0;
        }
        .sample-table-wrap {
            display: block;
            width: 100%;
            margin-top: 8px;
            overflow-x: auto;
            overflow-y: hidden;
            max-width: 100%;
            border: 1px solid var(--neutral-stroke-2);
            border-radius: 6px;
            background: #fff;
        }
        .sample-table {
            width: max-content;
            min-width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        .sample-table th,
        .sample-table td {
            border: 1px solid var(--neutral-stroke-1);
            padding: 6px 8px;
            text-align: left;
            vertical-align: top;
            word-break: break-word;
        }
        .sample-table thead th {
            background: #f3f4f6;
            font-weight: 700;
            white-space: nowrap;
        }
        .sample-caption {
            margin-top: 8px;
            color: var(--neutral-foreground-2);
            font-size: 0.85rem;
        }
        .sample-empty {
            margin-top: 8px;
            color: var(--neutral-foreground-2);
            font-size: 0.92em;
        }
        @media (max-width: 900px) {
            .container { padding: 16px; }
            .query-pre { max-height: 220px; }
            .copy-query-button {
                top: 6px;
                right: 6px;
            }
        }
        .footer {
            text-align: center;
            color: #8d99ae;
            font-size: 1em;
            padding: 12px 16px;
            margin-top: 24px;
            background: #eaf0fa;
            border-top: 1px solid #d4dbe7;
            border-radius: 0 0 18px 18px;
            letter-spacing: 0.5px;
            font-family: 'Segoe UI', 'Arial', sans-serif;
        }
        .header-brand {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header-logo {
            height: 32px;
            width: auto;
        }
        a {
            color: #0077cc;
            text-decoration: none;
            font-weight: 500;
        }
        a:hover { text-decoration: underline; color: #005fa3; }
        /* Scrollbars */
        ::-webkit-scrollbar { width: 7px; height: 7px; }
        ::-webkit-scrollbar-track { background: var(--neutral-bg-3); border-radius: 4px; }
        ::-webkit-scrollbar-thumb { background: var(--brand-bg-1); border-radius: 4px; border: 2px solid var(--neutral-bg-3); }
        ::-webkit-scrollbar-thumb:hover { background: #0a5198; }
        * { scrollbar-width: thin; scrollbar-color: var(--brand-bg-1) var(--neutral-bg-3); }
        /* Theme toggle */
        .theme-toggle {
            background: var(--neutral-bg-2);
            border: 1px solid var(--neutral-stroke-2);
            color: var(--neutral-foreground-1);
            border-radius: 999px;
            padding: 6px 14px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            font-family: inherit;
            white-space: nowrap;
            transition: background 0.15s;
        }
        .theme-toggle:hover { background: var(--neutral-bg-3); }
        @media (prefers-color-scheme: dark) {
            html:not([data-theme='light']) {
                --neutral-bg-1: #1e2231;
                --neutral-bg-2: #252a3a;
                --neutral-bg-3: #2d3347;
                --neutral-stroke-1: #3a4055;
                --neutral-stroke-2: #454d66;
                --neutral-foreground-1: #e8eaf0;
                --neutral-foreground-2: #9ca3af;
                --brand-foreground-1: #4da3e8;
                --brand-bg-1: #0f6cbd;
                --brand-bg-2: #1a3556;
            }
            html:not([data-theme='light']) body { background: linear-gradient(180deg, #141824 0%, #1a2030 100%); }
            html:not([data-theme='light']) .page-header { background: rgba(20, 24, 36, 0.95); }
            html:not([data-theme='light']) .nav-link { background: var(--neutral-bg-2); }
            html:not([data-theme='light']) .sample-table-wrap { background: var(--neutral-bg-2); }
            html:not([data-theme='light']) .sample-table thead th { background: var(--neutral-bg-3); }
            html:not([data-theme='light']) .footer { background: #1a2030; border-top-color: #3a4055; color: #8d99ae; }
            html:not([data-theme='light']) a { color: #4da3e8; }
            html:not([data-theme='light']) a:hover { color: #76c0f5; }
        }
        /* Manual dark override (system is light, user chose dark) */
        html[data-theme='dark'] {
            --neutral-bg-1: #1e2231;
            --neutral-bg-2: #252a3a;
            --neutral-bg-3: #2d3347;
            --neutral-stroke-1: #3a4055;
            --neutral-stroke-2: #454d66;
            --neutral-foreground-1: #e8eaf0;
            --neutral-foreground-2: #9ca3af;
            --brand-foreground-1: #4da3e8;
            --brand-bg-1: #0f6cbd;
            --brand-bg-2: #1a3556;
        }
        html[data-theme='dark'] body { background: linear-gradient(180deg, #141824 0%, #1a2030 100%); }
        html[data-theme='dark'] .page-header { background: rgba(20, 24, 36, 0.95); }
        html[data-theme='dark'] .nav-link { background: var(--neutral-bg-2); }
        html[data-theme='dark'] .sample-table-wrap { background: var(--neutral-bg-2); }
        html[data-theme='dark'] .sample-table thead th { background: var(--neutral-bg-3); }
        html[data-theme='dark'] .footer { background: #1a2030; border-top-color: #3a4055; color: #8d99ae; }
        html[data-theme='dark'] a { color: #4da3e8; }
        html[data-theme='dark'] a:hover { color: #76c0f5; }
    </style>
</head>
<body>
    <header class='page-header'>
        <div class='header-inner'>
            <div class='header-brand'>$logoImgHtml<span class='header-title'>KustoHawk Report</span></div>
            <nav class='nav-links' aria-label='Report navigation'>
                $mainNav
                $deviceNav
                $userNav
            </nav>
            <button id='themeToggle' class='theme-toggle' type='button' aria-label='Toggle theme'>&#x1F319; Dark</button>
        </div>
    </header>
    <div class='container'>
        <h1>Executed Queries ($pageLabel - $Entity)</h1>
        <div class='report-table-wrap'>
        <table class='report-table' aria-label='Executed queries'>
            <thead>
                <tr>
                    <th class='col-name'>Name</th>
                    <th class='col-query'>Query</th>
                    <th class='col-hits'><button id='sortHitsButton' class='sort-button' type='button'>Hits <span id='sortIndicator' class='sort-indicator'>▼</span></button></th>
                    <th class='col-source'>Source</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($q in $KQLQueries) {
        $queryText = $q.Query -replace '\{DeviceId\}', $DeviceId -replace '\{TimeFrame\}', $TimeFrame -replace '\{UserPrincipalName\}', $UserPrincipalName
        $name = [System.Web.HttpUtility]::HtmlEncode($q.Name)
        $queryRendered = [System.Web.HttpUtility]::HtmlEncode($queryText)
        $queryForAttribute = [System.Web.HttpUtility]::HtmlAttributeEncode($queryText)
        $hits = if ($q.PSObject.Properties.Match('ResultCount')) { [int]$q.ResultCount } else { 0 }
        $source = $q.Source
        $sourceLink = if ($source -match '^https?://') {
            $sourceUrl = [System.Web.HttpUtility]::HtmlEncode($source)
            "<a href='$sourceUrl' target='_blank' rel='noopener noreferrer'>Query Link</a>"
        } else {
            [System.Web.HttpUtility]::HtmlEncode($source)
        }

        $hitsClass = if ($hits -eq 0) { 'hits-pill zero' } else { 'hits-pill' }
        $html += "<tr class='query-row' data-hits='$hits'><td class='cell-name'>$name</td><td><div class='query-cell'><div class='query-card'><button type='button' class='copy-query-button' data-query='$queryForAttribute'>Copy</button><pre class='query-pre'>$queryRendered</pre></div></div></td><td class='cell-hits'><span class='$hitsClass'>$hits</span></td><td class='cell-source'>$sourceLink</td></tr>`n"

        if ($IncludeSampleSet) {
            $sampleRows = @()
            if ($q.PSObject.Properties.Match('SampleResults')) {
                $sampleRows = @($q.SampleResults)
            }

            if ($sampleRows.Count -gt 0) {
                $sampleColumns = @()
                foreach ($sampleRow in $sampleRows) {
                    if ($null -eq $sampleRow -or $null -eq $sampleRow.PSObject) {
                        continue
                    }
                    foreach ($prop in $sampleRow.PSObject.Properties) {
                        if ($sampleColumns -notcontains $prop.Name) {
                            $sampleColumns += $prop.Name
                        }
                    }
                }

                if ($sampleColumns.Count -gt 0) {
                    $headerCells = ($sampleColumns | ForEach-Object {
                        "<th>$([System.Web.HttpUtility]::HtmlEncode($_))</th>"
                    }) -join ''

                    $sampleRowsHtml = ''
                    foreach ($sampleRow in $sampleRows) {
                        $rowCells = ''
                        foreach ($columnName in $sampleColumns) {
                            $rawValue = $sampleRow.PSObject.Properties[$columnName].Value
                            if ($null -eq $rawValue) {
                                $renderValue = ''
                            } elseif ($rawValue -is [System.Collections.IEnumerable] -and -not ($rawValue -is [string])) {
                                $renderValue = ($rawValue | ForEach-Object { "$_" }) -join ', '
                            } else {
                                $renderValue = "$rawValue"
                            }
                            $encodedValue = [System.Web.HttpUtility]::HtmlEncode($renderValue)
                            $rowCells += "<td>$encodedValue</td>"
                        }
                        $sampleRowsHtml += "<tr>$rowCells</tr>"
                    }

                    $sampleBody = "<div class='sample-table-wrap'><table class='sample-table'><thead><tr>$headerCells</tr></thead><tbody>$sampleRowsHtml</tbody></table></div><div class='sample-caption'>Showing up to 10 sample rows.</div>"
                } else {
                    $sampleBody = "<div class='sample-empty'>No sample rows available.</div>"
                }
            } else {
                $sampleBody = "<div class='sample-empty'>No sample rows available.</div>"
            }

            $summaryText = "View sample results ($($sampleRows.Count) rows)"
            $html += "<tr class='sample-row'><td colspan='4'><details class='sample-details'><summary>$summaryText</summary>$sampleBody</details></td></tr>`n"
        }
    }

    $footerHtml = GetReportFooterHtml

$html += @"
            </tbody>
        </table>
        </div>
    </div>
    <script>
        (function() {
            const tableBody = document.querySelector('.report-table tbody');
            const sortButton = document.getElementById('sortHitsButton');
            const sortIndicator = document.getElementById('sortIndicator');
            let descending = true;

            function sortRowsByHits() {
                const allRows = Array.from(tableBody.querySelectorAll('tr'));
                const pairs = [];

                for (let i = 0; i < allRows.length; i++) {
                    const row = allRows[i];
                    if (row.classList.contains('query-row')) {
                        const sampleRow = allRows[i + 1] && allRows[i + 1].classList.contains('sample-row') ? allRows[i + 1] : null;
                        const hits = Number(row.getAttribute('data-hits') || '0');
                        pairs.push({ queryRow: row, sampleRow: sampleRow, hits: hits });
                    }
                }

                pairs.sort((a, b) => descending ? (b.hits - a.hits) : (a.hits - b.hits));

                for (const pair of pairs) {
                    tableBody.appendChild(pair.queryRow);
                    if (pair.sampleRow) {
                        tableBody.appendChild(pair.sampleRow);
                    }
                }

                sortIndicator.textContent = descending ? '▼' : '▲';
                descending = !descending;
            }

            if (sortButton && tableBody) {
                sortButton.addEventListener('click', sortRowsByHits);
                sortRowsByHits();
            }

            const copyButtons = document.querySelectorAll('.copy-query-button');
            for (const button of copyButtons) {
                button.addEventListener('click', async function() {
                    const queryText = button.getAttribute('data-query') || '';
                    try {
                        await navigator.clipboard.writeText(queryText);
                        const originalText = button.textContent;
                        button.textContent = 'Copied';
                        button.classList.add('copied');
                        setTimeout(() => {
                            button.textContent = originalText;
                            button.classList.remove('copied');
                        }, 1200);
                    } catch (error) {
                        button.textContent = 'Failed';
                        setTimeout(() => { button.textContent = 'Copy'; }, 1200);
                    }
                });
            }
        })();

        // Theme toggle
        (function() {
            var html = document.documentElement;
            var btn = document.getElementById('themeToggle');
            function isDark() {
                var t = html.getAttribute('data-theme');
                return t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches);
            }
            function updateBtn() {
                if (btn) btn.textContent = isDark() ? '\u2600 Light' : '\uD83C\uDF19 Dark';
            }
            if (btn) {
                updateBtn();
                btn.addEventListener('click', function() {
                    var newTheme = isDark() ? 'light' : 'dark';
                    html.setAttribute('data-theme', newTheme);
                    localStorage.setItem('kustohawk-theme', newTheme);
                    updateBtn();
                });
            }
        })();
    </script>
$footerHtml
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

    return $outFile
}

function GenerateMainReportPage {
    param (
        [object[]]$DeviceQueryData,
        [object[]]$IdentityQueryData,
        [string]$DeviceEntity,
           [string]$UserEntity,
           [object[]]$DeviceAlerts,
           [object[]]$IdentityAlerts,
           [PSObject]$DeviceInfoData,
           [PSObject]$IdentityInfoData
    )

    $logoBase64 = Get-LogoBase64
    $logoImgHtml = if ($logoBase64) { "<img class='header-logo' src='data:image/png;base64,$logoBase64' alt='KustoHawk' />" } else { "" }

    $outputDir = Join-Path -Path (Get-Location) -ChildPath 'Reports'
    if (-not (Test-Path -Path $outputDir)) {
        New-Item -Path $outputDir -ItemType Directory | Out-Null
    }

    $devicePageFile = if (-not [string]::IsNullOrWhiteSpace($DeviceEntity)) { "Device-ExecutedQueries-$DeviceEntity.html" } else { $null }
    $userPageFile = if (-not [string]::IsNullOrWhiteSpace($UserEntity)) { "Identity-ExecutedQueries-$UserEntity.html" } else { $null }

    $deviceQueryCount = if ($DeviceQueryData) { $DeviceQueryData.Count } else { 0 }
    $deviceHitsTotal = if ($DeviceQueryData) { ($DeviceQueryData | Measure-Object -Property ResultCount -Sum).Sum } else { 0 }
    if ($null -eq $deviceHitsTotal) { $deviceHitsTotal = 0 }

    $deviceQueriesWithHits = @()
    if ($DeviceQueryData) {
        $deviceQueriesWithHits = @(
            $DeviceQueryData |
                Where-Object { [int]$_.ResultCount -gt 0 } |
                Sort-Object -Property @{ Expression = { [int]$_.ResultCount }; Descending = $true }, @{ Expression = { "$($_.Name)" }; Descending = $false }
        )
    }

    $userQueryCount = if ($IdentityQueryData) { $IdentityQueryData.Count } else { 0 }
    $userHitsTotal = if ($IdentityQueryData) { ($IdentityQueryData | Measure-Object -Property ResultCount -Sum).Sum } else { 0 }
    if ($null -eq $userHitsTotal) { $userHitsTotal = 0 }

    $userQueriesWithHits = @()
    if ($IdentityQueryData) {
        $userQueriesWithHits = @(
            $IdentityQueryData |
                Where-Object { [int]$_.ResultCount -gt 0 } |
                Sort-Object -Property @{ Expression = { [int]$_.ResultCount }; Descending = $true }, @{ Expression = { "$($_.Name)" }; Descending = $false }
        )
    }

    $allQueryData = @()
    if ($DeviceQueryData) { $allQueryData += $DeviceQueryData }
    if ($IdentityQueryData) { $allQueryData += $IdentityQueryData }

    $totalQueryCount = $allQueryData.Count
    $queriesWithHits = @($allQueryData | Where-Object { [int]$_.ResultCount -gt 0 }).Count
    $queriesWithoutHits = [Math]::Max(0, ($totalQueryCount - $queriesWithHits))

    $hitPercent = if ($totalQueryCount -gt 0) {
        [Math]::Round(($queriesWithHits / $totalQueryCount) * 100, 2)
    } else {
        0
    }

    $chartStyle = if ($totalQueryCount -gt 0) {
        "background: conic-gradient(#0f6cbd 0 $hitPercent%, #d1d5db $hitPercent% 100%);"
    } else {
        "background: conic-gradient(#d1d5db 0 100%);"
    }

    $deviceCardLink = if ($devicePageFile) {
        "<a class='card-link' href='$devicePageFile'>Open Device Report</a>"
    } else {
        "<span class='card-link disabled'>Device report not generated</span>"
    }

    $userCardLink = if ($userPageFile) {
        "<a class='card-link' href='$userPageFile'>Open User Report</a>"
    } else {
        "<span class='card-link disabled'>User report not generated</span>"
    }

    $buildQueryHitListHtml = {
        param(
            [object[]]$QueriesWithHits,
            [string]$NoneText
        )

        if (-not $QueriesWithHits -or $QueriesWithHits.Count -eq 0) {
            return "<p class='meta'>Queries with hits: 0</p><p class='meta-muted'>$([System.Web.HttpUtility]::HtmlEncode($NoneText))</p>"
        }

        $items = ''
        foreach ($q in $QueriesWithHits) {
            $name = [System.Web.HttpUtility]::HtmlEncode("$($q.Name)")
            $count = [int]$q.ResultCount
            $items += "<li><span class='query-hit-name'>$name</span> <span class='query-hit-count'>($count)</span></li>"
        }

        return "<p class='meta'>Queries with hits: $($QueriesWithHits.Count)</p><ul class='meta-list'>$items</ul>"
    }

    $deviceQueryHitListHtml = & $buildQueryHitListHtml -QueriesWithHits $deviceQueriesWithHits -NoneText 'No device queries returned hits.'
    $userQueryHitListHtml = & $buildQueryHitListHtml -QueriesWithHits $userQueriesWithHits -NoneText 'No user queries returned hits.'

    $deviceSummary = if ($devicePageFile) {
        "<p class='meta'>Entity: $([System.Web.HttpUtility]::HtmlEncode($DeviceEntity))</p><p class='meta'>Queries: $deviceQueryCount</p><p class='meta'>Total Hits: $deviceHitsTotal</p>$deviceQueryHitListHtml"
    } else {
        "<p class='meta'>No device input was provided in this run.</p>"
    }

    $userSummary = if ($userPageFile) {
        "<p class='meta'>Entity: $([System.Web.HttpUtility]::HtmlEncode($UserEntity))</p><p class='meta'>Queries: $userQueryCount</p><p class='meta'>Total Hits: $userHitsTotal</p>$userQueryHitListHtml"
    } else {
        "<p class='meta'>No user input was provided in this run.</p>"
    }

    $footerHtml = GetReportFooterHtml

    $deviceInfoHtml = ''
    if ($DeviceInfoData -and $DeviceInfoData.PSObject.Properties.Count -gt 0) {
        $rows = ''
        foreach ($prop in $DeviceInfoData.PSObject.Properties) {
            $field = [System.Web.HttpUtility]::HtmlEncode($prop.Name)
            $rawValue = if ($null -eq $prop.Value) { '' } else { "$($prop.Value)" }
            $value = [System.Web.HttpUtility]::HtmlEncode($rawValue)
            $rows += "<tr><td class='field-col'>$field</td><td>$value</td></tr>"
        }
        $deviceInfoHtml = "<article class='card entity-card'><h2>Device Info</h2><div class='entity-table-wrap'><table class='entity-table'><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>$rows</tbody></table></div></article>"
    }

    $identityInfoHtml = ''
    if ($IdentityInfoData -and $IdentityInfoData.PSObject.Properties.Count -gt 0) {
        $rows = ''
        foreach ($prop in $IdentityInfoData.PSObject.Properties) {
            $field = [System.Web.HttpUtility]::HtmlEncode($prop.Name)
            $rawValue = if ($null -eq $prop.Value) { '' } else { "$($prop.Value)" }
            if ($prop.Name -eq 'AuthenticationMethods' -and $rawValue -match ' \| ') {
                $methodEntries = $rawValue -split '; '
                $methodRowsHtml = ''
                foreach ($entry in $methodEntries) {
                    if ([string]::IsNullOrWhiteSpace($entry)) { continue }
                    $parts = @{}
                    foreach ($part in ($entry -split ' \| ')) {
                        if ($part -match '^(.+?):\s*(.*)$') {
                            $parts[$matches[1].Trim()] = $matches[2].Trim()
                        }
                    }
                    $typeVal    = [System.Web.HttpUtility]::HtmlEncode($parts['Type'])
                    $nameVal    = [System.Web.HttpUtility]::HtmlEncode($parts['Name'])
                    $createdVal = [System.Web.HttpUtility]::HtmlEncode($parts['Created'])
                    $methodRowsHtml += "<tr><td>$typeVal</td><td>$nameVal</td><td>$createdVal</td></tr>"
                }
                $value = "<table class='auth-methods-table'><thead><tr><th>Type</th><th>Name</th><th>Created (UTC)</th></tr></thead><tbody>$methodRowsHtml</tbody></table>"
                $rows += "<tr><td class='field-col'>$field</td><td>$value</td></tr>"
            } else {
                $value = [System.Web.HttpUtility]::HtmlEncode($rawValue)
                $rows += "<tr><td class='field-col'>$field</td><td>$value</td></tr>"
            }
        }
        $identityInfoHtml = "<article class='card entity-card'><h2>Identity Info</h2><div class='entity-table-wrap'><table class='entity-table'><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>$rows</tbody></table></div></article>"
    }

    $entityInfoSection = ''
    if ($deviceInfoHtml -or $identityInfoHtml) {
        $entityInfoSection = "<section class='entity-grid'>$deviceInfoHtml$identityInfoHtml</section>"
    }

    # Build combined alerts HTML
    $allAlerts = @()
    if ($DeviceAlerts)   { $allAlerts += $DeviceAlerts }
    if ($IdentityAlerts) { $allAlerts += $IdentityAlerts }

    $alertsById = @{}
    foreach ($a in $allAlerts) {
        $id = $a.AlertId
        if (-not $alertsById.ContainsKey($id)) {
            $alertsById[$id] = $a
        } else {
            $alertsById[$id].EntityType = 'Both'
        }
    }
    $severityRank = @{
        'high' = 0
        'medium' = 1
        'low' = 2
        'informational' = 3
    }

    $uniqueAlerts = @($alertsById.Values) | Sort-Object `
        @{ Expression = {
            $sev = if ($_.Severity) { $_.Severity.ToString().ToLower() } else { 'informational' }
            if ($severityRank.ContainsKey($sev)) { $severityRank[$sev] } else { 3 }
        } }, `
        @{ Expression = {
            $parsedTimestamp = [datetime]::MinValue
            [void][datetime]::TryParse("$($_.Timestamp)", [ref]$parsedTimestamp)
            $parsedTimestamp
        }; Descending = $true }

    if ($uniqueAlerts.Count -gt 0) {
        $alertRowsHtml = ''
        foreach ($alert in $uniqueAlerts) {
            $ts         = [System.Web.HttpUtility]::HtmlEncode($alert.Timestamp)
            $title      = [System.Web.HttpUtility]::HtmlEncode($alert.Title)
            $alertUrl   = "https://security.microsoft.com/alerts/$([System.Uri]::EscapeDataString($alert.AlertId))"
            $sevRaw     = if ($alert.Severity) { $alert.Severity.ToString().ToLower() } else { 'informational' }
            $sevClass   = switch ($sevRaw) { 'high' { 'sev-pill sev-high' } 'medium' { 'sev-pill sev-medium' } 'low' { 'sev-pill sev-low' } default { 'sev-pill sev-info' } }
            $sevLabel   = [System.Web.HttpUtility]::HtmlEncode($alert.Severity)
            $category   = [System.Web.HttpUtility]::HtmlEncode($alert.Category)
            $source     = [System.Web.HttpUtility]::HtmlEncode($alert.ServiceSource)
            $entityType = $alert.EntityType
            $badgeClass = switch ($entityType) { 'Device' { 'badge-device' } 'User' { 'badge-user' } default { 'badge-both' } }
            $entLabel   = [System.Web.HttpUtility]::HtmlEncode($entityType)
            $alertRowsHtml += "<tr><td>$ts</td><td><a href='$alertUrl' target='_blank' rel='noopener noreferrer'>$title</a></td><td><span class='$sevClass'>$sevLabel</span></td><td>$category</td><td>$source</td><td class='entity-cell'><span class='$badgeClass'>$entLabel</span></td></tr>"
        }
        $alertsHtml = "<article class='card alerts-card'><h2>Alerts <span style='font-size:0.9rem;font-weight:500;color:#6b7280;'>($($uniqueAlerts.Count) in last 30 days)</span></h2><div class='alerts-table-wrap'><table class='alerts-table'><thead><tr><th>Timestamp</th><th>Title</th><th>Severity</th><th>Category</th><th>Service Source</th><th>Entity</th></tr></thead><tbody>$alertRowsHtml</tbody></table></div></article>"
    } else {
        $alertsHtml = "<article class='card alerts-card'><h2>Alerts</h2><div class='no-alerts'>No alerts found for this entity in the last 30 days.</div></article>"
    }

    $mainHtml = @"
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <script>(function(){var t=localStorage.getItem('kustohawk-theme');if(t)document.documentElement.setAttribute('data-theme',t);})();</script>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>KustoHawk Reports</title>
    <style>
        :root {
            --bg: #f4f6fb;
            --surface: #ffffff;
            --text: #1f2937;
            --muted: #6b7280;
            --brand: #0f6cbd;
            --stroke: #dde3ec;
        }
        body {
            margin: 0;
            font-family: 'Segoe UI', 'Arial', sans-serif;
            background: linear-gradient(180deg, #f7f9fc 0%, #edf2f9 100%);
            color: var(--text);
        }
        .page-header {
            position: sticky;
            top: 0;
            z-index: 10;
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(8px);
            border-bottom: 1px solid var(--stroke);
        }
        .header-inner {
            max-width: 1100px;
            margin: 0 auto;
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
        }
        .header-title {
            font-weight: 700;
        }
        .nav-links {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }
        .nav-link {
            text-decoration: none;
            color: var(--brand);
            border: 1px solid var(--stroke);
            border-radius: 999px;
            background: #fff;
            padding: 6px 14px;
            font-weight: 600;
            font-size: 0.9rem;
        }
        .nav-link.active {
            background: var(--brand);
            border-color: var(--brand);
            color: #fff;
        }
        .nav-link.disabled {
            color: var(--muted);
            background: #f3f4f6;
            cursor: not-allowed;
        }
        .container {
            max-width: 1100px;
            margin: 34px auto;
            padding: 0 20px;
        }
        h1 {
            margin: 0 0 12px 0;
            font-size: 2rem;
        }
        .subtitle {
            margin: 0 0 24px 0;
            color: var(--muted);
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
            gap: 16px;
        }
        .entity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--stroke);
            border-radius: 12px;
            padding: 18px;
            box-shadow: 0 8px 24px rgba(10, 21, 40, 0.06);
        }
        .entity-card {
            overflow: hidden;
        }
        .card h2 {
            margin: 0 0 10px 0;
            font-size: 1.2rem;
        }
        .meta {
            margin: 4px 0;
            color: #374151;
        }
        .meta-muted {
            margin: 6px 0 0 0;
            color: var(--muted);
            font-size: 0.88rem;
        }
        .meta-list {
            margin: 8px 0 0 20px;
            padding: 0;
            color: #1f2937;
            font-size: 0.9rem;
            max-height: 170px;
            overflow-y: auto;
        }
        .meta-list li {
            margin: 3px 0;
        }
        .query-hit-name {
            font-weight: 600;
        }
        .query-hit-count {
            color: var(--muted);
            font-weight: 600;
        }
        .card-link {
            display: inline-block;
            margin-top: 14px;
            text-decoration: none;
            color: var(--brand);
            font-weight: 700;
        }
        .card-link.disabled {
            color: var(--muted);
            font-weight: 600;
        }
        .overview-grid {
            display: grid;
            grid-template-columns: minmax(260px, 340px) 1fr;
            gap: 16px;
            margin-bottom: 16px;
        }
        .pie-card {
            display: grid;
            justify-items: center;
            align-content: center;
            gap: 12px;
        }
        .pie-chart {
            width: 180px;
            height: 180px;
            border-radius: 50%;
            position: relative;
            box-shadow: inset 0 0 0 1px #d1d5db;
        }
        .pie-center {
            position: absolute;
            inset: 28%;
            border-radius: 50%;
            background: #fff;
            display: grid;
            place-items: center;
            text-align: center;
            font-weight: 700;
            color: #111827;
            font-size: 0.9rem;
            line-height: 1.2;
        }
        .legend {
            width: 100%;
            display: grid;
            gap: 6px;
            font-size: 0.9rem;
        }
        .legend-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }
        .legend-label {
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            display: inline-block;
        }
        .dot-hit { background: #0f6cbd; }
        .dot-nohit { background: #d1d5db; }
        .entity-table-wrap {
            overflow-x: auto;
            border: 1px solid var(--stroke);
            border-radius: 8px;
            background: var(--surface);
        }
        .entity-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            min-width: 520px;
        }
        .entity-table thead th {
            background: #f3f4f6;
            font-weight: 700;
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--stroke);
        }
        .entity-table tbody td {
            padding: 9px 12px;
            border-bottom: 1px solid var(--stroke);
            vertical-align: top;
            word-break: break-word;
        }
        .entity-table tbody tr:last-child td {
            border-bottom: none;
        }
        .field-col {
            width: 220px;
            font-weight: 700;
            white-space: nowrap;
        }
        .auth-methods-table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
        .auth-methods-table th,
        .auth-methods-table td { padding: 5px 8px; border: 1px solid var(--stroke); text-align: left; vertical-align: top; word-break: break-word; }
        .auth-methods-table thead th { background: #f3f4f6; font-weight: 700; }
        @media (max-width: 900px) {
            .overview-grid {
                grid-template-columns: 1fr;
            }
        }
            .alerts-card { margin-top: 16px; }
            .alerts-card h2 { font-size: 1.3rem; margin: 0 0 12px 0; }
            .alerts-table-wrap { overflow-x: auto; border: 1px solid var(--stroke); border-radius: 8px; background: var(--surface); }
            .alerts-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; min-width: 720px; }
            .alerts-table thead th { background: #f3f4f6; font-weight: 700; padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--stroke); white-space: nowrap; }
            .alerts-table tbody td { padding: 9px 12px; border-bottom: 1px solid var(--stroke); vertical-align: top; word-break: break-word; }
            .alerts-table tbody tr:last-child td { border-bottom: none; }
            .alerts-table tbody tr:hover { background: #f9fafb; }
            .alerts-table td.entity-cell { white-space: nowrap; word-break: normal; width: 1%; }
            .sev-pill { border-radius: 999px; padding: 2px 9px; font-weight: 700; font-size: 0.8rem; white-space: nowrap; display: inline-block; }
            .sev-high   { background: #dc2626; color: #fff; }
            .sev-medium { background: #ea580c; color: #fff; }
            .sev-low    { background: #fde68a; color: #1f2937; }
            .sev-info   { background: #2563eb; color: #fff; }
            .badge-device { background: #0f6cbd; color: #fff; border-radius: 999px; padding: 2px 8px; font-size: 0.8rem; font-weight: 600; display: inline-flex; align-items: center; white-space: nowrap; }
            .badge-user   { background: #7c3aed; color: #fff; border-radius: 999px; padding: 2px 8px; font-size: 0.8rem; font-weight: 600; display: inline-flex; align-items: center; white-space: nowrap; }
            .badge-both   { background: #0f766e; color: #fff; border-radius: 999px; padding: 2px 8px; font-size: 0.8rem; font-weight: 600; display: inline-flex; align-items: center; white-space: nowrap; }
            .no-alerts { color: var(--muted); font-size: 0.95rem; padding: 8px 0; }
        .header-brand {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header-logo {
            height: 32px;
            width: auto;
        }
        .footer {
            text-align: center;
            color: #8d99ae;
            font-size: 1em;
            padding: 12px 16px;
            margin-top: 24px;
            background: #eaf0fa;
            border-top: 1px solid #d4dbe7;
            letter-spacing: 0.5px;
            font-family: 'Segoe UI', 'Arial', sans-serif;
        }
        @media (prefers-color-scheme: dark) {
            html:not([data-theme='light']) {
                --bg: #141824;
                --surface: #1e2231;
                --text: #e8eaf0;
                --muted: #9ca3af;
                --brand: #4da3e8;
                --stroke: #3a4055;
            }
            html:not([data-theme='light']) body { background: linear-gradient(180deg, #141824 0%, #1a2030 100%); }
            html:not([data-theme='light']) .page-header { background: rgba(20, 24, 36, 0.95); }
            html:not([data-theme='light']) .nav-link { background: var(--surface); }
            html:not([data-theme='light']) .meta { color: #cbd5e1; }
            html:not([data-theme='light']) .meta-list { color: #e5e7eb; }
            html:not([data-theme='light']) .query-hit-name { color: #f3f4f6; }
            html:not([data-theme='light']) .query-hit-count { color: #93c5fd; }
            html:not([data-theme='light']) .pie-center { background: var(--surface); color: var(--text); }
            html:not([data-theme='light']) .pie-chart { box-shadow: inset 0 0 0 1px var(--stroke); }
            html:not([data-theme='light']) .alerts-table thead th { background: #252a3a; }
            html:not([data-theme='light']) .alerts-table tbody tr:hover { background: #252a3a; }
            html:not([data-theme='light']) .entity-table thead th { background: #252a3a; }
            html:not([data-theme='light']) .auth-methods-table thead th { background: #252a3a; }
            html:not([data-theme='light']) .footer { background: #1a2030; border-top-color: #3a4055; color: #8d99ae; }
        }
        /* Manual dark override */
        html[data-theme='dark'] {
            --bg: #141824;
            --surface: #1e2231;
            --text: #e8eaf0;
            --muted: #9ca3af;
            --brand: #4da3e8;
            --stroke: #3a4055;
        }
        html[data-theme='dark'] body { background: linear-gradient(180deg, #141824 0%, #1a2030 100%); }
        html[data-theme='dark'] .page-header { background: rgba(20, 24, 36, 0.95); }
        html[data-theme='dark'] .nav-link { background: var(--surface); }
        html[data-theme='dark'] .meta { color: #cbd5e1; }
        html[data-theme='dark'] .meta-list { color: #e5e7eb; }
        html[data-theme='dark'] .query-hit-name { color: #f3f4f6; }
        html[data-theme='dark'] .query-hit-count { color: #93c5fd; }
        html[data-theme='dark'] .pie-center { background: var(--surface); color: var(--text); }
        html[data-theme='dark'] .pie-chart { box-shadow: inset 0 0 0 1px var(--stroke); }
        html[data-theme='dark'] .alerts-table thead th { background: #252a3a; }
        html[data-theme='dark'] .alerts-table tbody tr:hover { background: #252a3a; }
        html[data-theme='dark'] .entity-table thead th { background: #252a3a; }
        html[data-theme='dark'] .auth-methods-table thead th { background: #252a3a; }
        html[data-theme='dark'] .footer { background: #1a2030; border-top-color: #3a4055; color: #8d99ae; }
        /* Scrollbars */
        ::-webkit-scrollbar { width: 7px; height: 7px; }
        ::-webkit-scrollbar-track { background: var(--surface); border-radius: 4px; }
        ::-webkit-scrollbar-thumb { background: var(--brand); border-radius: 4px; border: 2px solid var(--surface); }
        ::-webkit-scrollbar-thumb:hover { background: #0a5198; }
        * { scrollbar-width: thin; scrollbar-color: var(--brand) var(--surface); }
        /* Theme toggle */
        .theme-toggle {
            background: var(--surface);
            border: 1px solid var(--stroke);
            color: var(--text);
            border-radius: 999px;
            padding: 6px 14px;
            font-size: 0.9rem;
            font-weight: 600;
            cursor: pointer;
            font-family: inherit;
            white-space: nowrap;
            transition: background 0.15s;
        }
        .theme-toggle:hover { filter: brightness(0.9); }
        </style>
</head>
<body>
    <header class='page-header'>
        <div class='header-inner'>
            <div class='header-brand'>$logoImgHtml<span class='header-title'>KustoHawk Report</span></div>
            <nav class='nav-links' aria-label='Report navigation'>
                <a class='nav-link active' href='index.html'>Main</a>
                $(if ($devicePageFile) { "<a class='nav-link' href='$devicePageFile'>Device</a>" } else { "<span class='nav-link disabled'>Device</span>" })
                $(if ($userPageFile) { "<a class='nav-link' href='$userPageFile'>User</a>" } else { "<span class='nav-link disabled'>User</span>" })
            </nav>
            <button id='themeToggle' class='theme-toggle' type='button' aria-label='Toggle theme'>&#x1F319; Dark</button>
        </div>
    </header>
    <main class='container'>
        <h1>Investigation Reports</h1>
        <p class='subtitle'>Select a report page from the cards below or use the header navigation.</p>
        <section class='overview-grid'>
            <article class='card pie-card'>
                <h2>Query Hit Ratio</h2>
                <div class='pie-chart' style='$chartStyle'>
                    <div class='pie-center'>$queriesWithHits / $totalQueryCount<br/>with hits</div>
                </div>
                <div class='legend'>
                    <div class='legend-row'>
                        <span class='legend-label'><span class='legend-dot dot-hit'></span>Queries with hits</span>
                        <strong>$queriesWithHits</strong>
                    </div>
                    <div class='legend-row'>
                        <span class='legend-label'><span class='legend-dot dot-nohit'></span>Queries without hits</span>
                        <strong>$queriesWithoutHits</strong>
                    </div>
                    <div class='legend-row'>
                        <span>Total queries</span>
                        <strong>$totalQueryCount</strong>
                    </div>
                </div>
            </article>
            <article class='card'>
                <h2>Device Report</h2>
                $deviceSummary
                $deviceCardLink
                <hr style='border:none;border-top:1px solid #e5e7eb;margin:14px 0;'>
                <h2>User Report</h2>
                $userSummary
                $userCardLink
            </article>
        </section>
                $entityInfoSection
          $alertsHtml
     </main>
    <script>
        (function() {
            var html = document.documentElement;
            var btn = document.getElementById('themeToggle');
            function isDark() {
                var t = html.getAttribute('data-theme');
                return t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme: dark)').matches);
            }
            function updateBtn() {
                if (btn) btn.textContent = isDark() ? '\u2600 Light' : '\uD83C\uDF19 Dark';
            }
            if (btn) {
                updateBtn();
                btn.addEventListener('click', function() {
                    var newTheme = isDark() ? 'light' : 'dark';
                    html.setAttribute('data-theme', newTheme);
                    localStorage.setItem('kustohawk-theme', newTheme);
                    updateBtn();
                });
            }
        })();
    </script>
$footerHtml
</body>
</html>
"@

    $indexFile = Join-Path -Path $outputDir -ChildPath 'index.html'
    $mainHtml | Set-Content $indexFile
    Write-Host "Main report page saved to $indexFile"
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

$deviceQueryResults = $null
$identityQueryResults = $null

if (-not (Check-InstalledGraphModules)) {
    exit 1
}

try {
    $script:SelectedAuthTierConfig = Get-AuthenticationTierConfig -ConfigPath $AuthTierConfigPath -TierName $AuthenticationTier
    Write-Host "Authentication tier '$AuthenticationTier' loaded from '$AuthTierConfigPath'." -ForegroundColor Cyan
} catch {
    Write-Host "Failed to load authentication tier configuration: $_" -ForegroundColor Red
    exit 1
}

$info = ValidateInputParameters
Connect-GraphAPI

Write-Host "Verifying granted permissions against tier '$AuthenticationTier'..." -ForegroundColor Cyan
$effectiveTierConfig = Resolve-EffectiveTier -RequestedTier $AuthenticationTier
if (-not $effectiveTierConfig) {
    Write-Host "Script cannot start: the connected account or Service Principal does not have sufficient permissions to run KustoHawk." -ForegroundColor Red
    Write-Host "Ensure at minimum 'ThreatHunting.Read.All' is granted and re-run the script." -ForegroundColor Red
    exit 1
}
$script:SelectedAuthTierConfig = $effectiveTierConfig
if ($effectiveTierConfig.Name -ne $AuthenticationTier) {
    Write-Host "Running with effective tier '$($effectiveTierConfig.Name)' (downgraded from '$AuthenticationTier')." -ForegroundColor Yellow
}

$entityInfo = Get-EntityInfo $info.DeviceId $info.UserPrincipalName
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

$alertData = GetAlertsForEntity -DeviceId $info.DeviceId -UserPrincipalName $info.UserPrincipalName
GenerateMainReportPage -DeviceQueryData $deviceQueryResults -IdentityQueryData $identityQueryResults -DeviceEntity $info.DeviceId -UserEntity $info.UserPrincipalName -DeviceAlerts $alertData.DeviceAlerts -IdentityAlerts $alertData.IdentityAlerts -DeviceInfoData $entityInfo.DeviceInfo -IdentityInfoData $entityInfo.IdentityInfo