<#
.SYNOPSIS
    Synchronizes Active Directory users to Cisco Identity Intelligence.

.DESCRIPTION
    This script enumerates Active Directory users, processes their attributes and group memberships,
    applies classification rules, and sends user data to the Cisco CII service using bulk API calls.
    Supports preview modes for testing and validation before sending live data.

.PARAMETER KeyFilePath
    Path to the encryption key file used to decrypt the configuration file.

.PARAMETER ConfigFilePath
    Path to the encrypted configuration file containing SCIM endpoint and credentials.

.PARAMETER CustomizationFilePath
    (Optional) Path to a PowerShell data file containing customization rules and settings.
    If not specified, the script will use built-in defaults.

.PARAMETER BaseDN
    (Optional) Base DN to search for users. Defaults to the domain DN if not specified.

.PARAMETER Preview
    (Optional) Switch to enable preview mode. Outputs processed AD user data to a JSON file without sending to CII.

.PARAMETER PreviewFile
    (Optional) Output file path for preview mode. Default: "ad-preview-{timestamp}.jsonl"

.PARAMETER UserBatchSize
    (Optional) Number of users to retrieve from Active Directory at once. Default: 500.

.PARAMETER ScimPreview
    (Optional) Switch to enable SCIM preview mode. Outputs SCIM bulk request payloads to a JSON file without sending to CII.

.PARAMETER ScimPreviewFile
    (Optional) Output file path for SCIM preview mode. Default: "scim-preview-{timestamp}.jsonl"

.PARAMETER ScimBulkSize
    (Optional) Number of operations per SCIM bulk request. Default: 50.

.PARAMETER NoGroups
    (Optional) Switch to skip uploading user groups to CII.

.PARAMETER AttributeSizeWarningThreshold
    (Optional) Size threshold in bytes for warning about large attributes. Set to 0 to disable warnings. Default: 2048.

.EXAMPLE
    .\ADSync.ps1 -KeyFilePath .\cisco-cii-AD-encryption.key -ConfigFilePath .\cisco-cii-AD-encrypted-config.json

    Runs the AD sync operation using the specified key and config files.

.EXAMPLE
    .\ADSync.ps1 -KeyFilePath .\cisco-cii-AD-encryption.key -ConfigFilePath .\cisco-cii-AD-encrypted-config.json -CustomizationFilePath .\ADSync.config.psd1

    Runs the AD sync operation using the specified key, config, and a customer customization file.
    The customization file allows you to define classification rules, excluded attributes, group filtering, and more.

.EXAMPLE
    .\ADSync.ps1 -KeyFilePath cisco-cii-AD-encryption.key -ConfigFilePath cisco-cii-AD-encrypted-config.json -Preview

    Runs in preview mode, outputting processed user data to a JSON file without sending to CII.

.EXAMPLE
    .\ADSync.ps1 -KeyFilePath .\cisco-cii-AD-encryption.key -ConfigFilePath .\cisco-cii-AD-encrypted-config.json -LdapUsername "<bind_account>" -LdapPassword "<bind_password>"

    Runs the AD sync operation using explicit LDAP credentials for the connection.

.LINK
    https://docs.oort.io/integrations

.NOTES
    Version: 1.0

    SPDX-License-Identifier: Apache-2.0

    Copyright 2025 Cisco Systems, Inc. and its affiliates

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
#>

[CmdletBinding(DefaultParameterSetName = "Default")]
param(
    [Parameter(ParameterSetName = "Version")]
    [switch]$version,

    [Parameter(Mandatory=$true, ParameterSetName = "Default", HelpMessage="Path to the encryption key file")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$KeyFilePath,

    [Parameter(Mandatory=$true, ParameterSetName = "Default", HelpMessage="Path to the encrypted configuration file")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$ConfigFilePath,

    [Parameter(Mandatory=$false, ParameterSetName = "Default", HelpMessage="Path to the customer customization file")]
    [string]$CustomizationFilePath,

    [Parameter(Mandatory=$false, ParameterSetName = "Default", HelpMessage="Base DN to search for users (defaults to domain DN)")]
    [string]$BaseDN,

    [Parameter(ParameterSetName = "Default", HelpMessage="LDAP bind username (optional)")]
    [string]$LdapUsername,

    [Parameter(ParameterSetName = "Default", HelpMessage="LDAP bind password (optional)")]
    [string]$LdapPassword,

    [Parameter(ParameterSetName = "Default")]
    [switch]$Preview,

    [Parameter(ParameterSetName = "Default")]
    [string]$PreviewFile = "ad-preview-$(Get-Date -Format 'yyyyMMdd-HHmmss').jsonl",

    [Parameter(ParameterSetName = "Default")]
    [switch]$ScimPreview,

    [Parameter(ParameterSetName = "Default")]
    [string]$ScimPreviewFile = "scim-preview-$(Get-Date -Format 'yyyyMMdd-HHmmss').jsonl",

    [Parameter(ParameterSetName = "Default")]
    [int]$UserBatchSize = 500,

    [Parameter(ParameterSetName = "Default")]
    [int]$ScimBulkSize = 50,

    [Parameter(ParameterSetName = "Default", HelpMessage="Skip uploading user groups")]
    [switch]$NoGroups,

    [Parameter(ParameterSetName = "Default", HelpMessage="Size threshold in bytes for warning about large attributes")]
    [int]$AttributeSizeWarningThreshold = 2048
)

$ScriptVersion = "1.0"
$SCIM_OPERATION_SIZE_LIMIT = 1048576
$script:payloadTooLargeDetected = $false

# Handle version parameter set
if ($PSCmdlet.ParameterSetName -eq "Version") {
    Write-Host $ScriptVersion
    exit 0
}

#requires -Module ActiveDirectory

# Mandatory attributes that cannot be excluded (required for functionality)
$script:mandatoryAttributes = @(
    "objectGUID",
    "samAccountName",
    "distinguishedName",
    "displayName",
    "givenName",
    "sn",
    "mail",
    "userPrincipalName",
    "userAccountControl",
    "whenCreated",
    "whenChanged",
    "lastLogon",
    "pwdLastSet",
    "badPasswordTime"
)

# Logging functions
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $script:LogFile -Append
}

# Write status messages to console and log
function Write-Status {
    param(
        [string]$Message,
        [string]$ForegroundColor = "White"
    )
    Write-Host $Message -ForegroundColor $ForegroundColor
    Write-Log $Message
}

# Show progress bar with detailed metrics
function Show-Progress {
    param(
        $Activity,
        $Status,
        $Count,
        $Total,
        [datetime]$StartTime = (Get-Date),
        [int]$ProcessedCount = 0,
        [int]$SkippedCount = 0
    )
    $percentComplete = [math]::Round(($Count / $Total) * 100, 1)
    $elapsed = (Get-Date) - $StartTime
    $rate = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($Count / $elapsed.TotalSeconds, 1) } else { 0 }
    $remaining = $Total - $Count
    $eta = if ($rate -gt 0) {
        $etaSeconds = $remaining / $rate
        $etaTime = $StartTime.AddSeconds($elapsed.TotalSeconds + $etaSeconds)
        $etaTime.ToString("HH:mm:ss")
    } else {
        "Unknown"
    }
    $detailedStatus = "$Status ($Count/$Total) | Processed: $ProcessedCount, Skipped: $SkippedCount | ETA: $eta | Rate: $rate/sec"
    Write-Progress -Activity $Activity -Status $detailedStatus -PercentComplete $percentComplete
}

# Function to load customer customization settings
function Load-CustomerCustomization {
    param (
        [string]$CustomizationPath = $script:CustomizationFilePath
    )
    # First initialize all default settings
    Initialize-DefaultCustomization

    # If no path provided, use defaults without warning
    if ([string]::IsNullOrWhiteSpace($CustomizationPath)) {
        Write-Log "No customization file specified, using default settings"
        return
    }

    # Check if customization file exists
    if (-not (Test-Path -Path $CustomizationPath)) {
        Write-Error "Customization file not found: $CustomizationPath"
        Write-Log "ERROR: Customization file not found: $CustomizationPath"
        exit 1
    }

    try {
        # Load customer customization file to override default settings
        Write-Log "Loading customization file: $CustomizationPath"
        $config = Import-PowerShellDataFile -Path $CustomizationPath
        Apply-CustomConfiguration -ConfigData $config
        Write-Status "Loaded customization file: $CustomizationPath"
    } catch {
        Write-Error "Error loading customization file: $_"
        Write-Log "ERROR: Failed to load customization file: $_"
        exit 1
    }
}

function Apply-CustomConfiguration {
    param (
        [hashtable]$ConfigData
    )
    # Apply each section of configuration if present
    if ($ConfigData.classificationRules) {
        foreach ($key in $ConfigData.classificationRules.Keys) {
            if ($script:classificationRules.ContainsKey($key)) {
                foreach ($ruleType in $ConfigData.classificationRules[$key].Keys) {
                    $script:classificationRules[$key][$ruleType] = $ConfigData.classificationRules[$key][$ruleType]
                }
            }
        }
    }
    if ($ConfigData.customAttributeMapping) {
        $script:customAttributeMapping = $ConfigData.customAttributeMapping
    }
    if ($ConfigData.includeRules) {
        $script:includeRules = $ConfigData.includeRules
    }
    if ($ConfigData.excludeRules) {
        $script:excludeRules = $ConfigData.excludeRules
    }
    if ($ConfigData.excludedAttributes) {
        $script:excludedAttributes = $ConfigData.excludedAttributes
    }
    if ($ConfigData.specifiedGroups) {
        $script:specifiedGroups = $ConfigData.specifiedGroups
    } 
    if ($ConfigData.domainController) {
        $script:domainController = $ConfigData.domainController
    }
}

# Initialize default customization settings
function Initialize-DefaultCustomization {
    Write-Log "Initializing default customization settings"
    # Define user classification rules
    $script:classificationRules = @{
        # Define rules for service accounts
        isServiceAccount = @{
            Groups       = @()
            OUs          = @()
            NamePatterns = @()
            Usernames    = @()
        }
        # Define rules for administrators
        isAdmin = @{
            Groups       = @("Domain Admins", "Enterprise Admins", "Administrators")
            OUs          = @()
            NamePatterns = @()
            Usernames    = @("Administrator")
        }
        # Define rules for executives/special accounts
        isExecutive = @{
            Groups       = @()
            OUs          = @()
            NamePatterns = @()
            Usernames    = @()
        }
        # Define rules for external accounts
        isExternalAccount = @{
            Groups       = @()
            OUs          = @()
            NamePatterns = @()
            Usernames    = @("Guest")
        }
    }

    # Custom AD attribute classification and CII userType mapping
    $script:customAttributeMapping = @{
        # Specify the AD attribute name that contains classification values
        AttributeName = ""
        # Map AD attribute values to CII userType values
        ValueMappings = @{}
        # Default userType if attribute value doesn't match any mapping
        DefaultUserType = "employee"
    }

    # Include users in these OUs or with specific naming conventions
    $script:includeRules = @{
        OUs          = @()
        NamePatterns = @()
    }

    # Exclude users in these OUs or with specific naming conventions
    $script:excludeRules = @{
        OUs          = @()
        NamePatterns = @()
    }

    # Customize attributes to exclude
    $script:excludedAttributes = @(
        "ntSecurityDescriptor",
        "PropertyNames",
        "userCertificate",
        "thumbnailPhoto",
        "msPKIAccountCredentials",
        "msExchSafeSendersHash",
        "msExchSafeRecipientsHash",
        "msPKIDPAPIMasterKey",
        "msExchBlockedSendersHash",
        "msExchUMDtmfMap",
        "msExchUMSpokenName",
        "logonHours",
        "userParameters",
        "unicodePwd",
        "dBCSPwd",
        "lmPwdHistory",
        "ntPwdHistory",
        "supplementalCredentials",
        "msDS-KeyCredentialLink",
        "memberOf",
        "mS-DS-ConsistencyGuid",
        "msExchMailboxGuid",
        "msExchMailboxSecurityDescriptor",
        "msExchMasterAccountSid",
        "msMqDigests",
        "terminalServer",
        "protocolSettings",
        "unixUserPassword"
    )

    # If empty, all security groups are processed. Otherwise, only these group names are.
    $script:specifiedGroups = @()
}

# Convert Generalized time to ISO 8601 UTC
function Convert-GeneralizedTimeUtc {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        return ([DateTime]::Parse($Value)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    } catch { return $null }
}

# Convert FILETIME to ISO 8601 UTC
function Convert-FileTimeUtc {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    # Accept numeric or numeric string
    try {
        $fileTime = [int64]$Value
    } catch { return $null }
    if ($fileTime -le 0) { return $null }
    try {
        return [DateTime]::FromFileTimeUtc($fileTime).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    } catch { return $null }
}

# Get AD domain name
function Get-ADDomainName {
    try {
        return (Get-ADDomain).DNSRoot
    }
    catch {
        Write-Error "Failed to get AD domain: $_"
        exit 1
    }
}

# Get the total number of AD users
function Get-ADUserCount {
    param(
        [string]$SearchBase = $null
    )
    try {
        $params = @{
            Filter = '*'
            ResultSetSize = $null
        }
        if ($SearchBase) { $params['SearchBase'] = $SearchBase }
        $users = @(Get-ADUser @params)
        return $users.Count
    }
    catch {
        Write-Error "Failed to count AD users: $_"
        exit 1
    }
}

# Convert AD property values to friendly strings
function Get-PropertyString {
    param(
        [string]$PropertyName,
        [object[]]$PropertyValues
    )
    $convertedValues = foreach ($value in $PropertyValues) {
        if ($null -eq $value) {
            continue  # Skip null values
        }
        # Check attribute size and warn if needed
        Check-AttributeSize -PropertyName $PropertyName -Value $value
        switch ($value.GetType().Name) {
            "Byte[]" {
                switch ($PropertyName.ToLower()) {
                    "objectguid" {
                        try { [guid]::New($value).ToString() }
                        catch { [Convert]::ToBase64String($value) }
                    }
                    "objectsid" {
                        try { (New-Object System.Security.Principal.SecurityIdentifier($value, 0)).Value }
                        catch { [Convert]::ToBase64String($value) }
                    }
                    { $_ -in @("usercertificate", "thumbnailphoto") } {
                        [Convert]::ToBase64String($value)
                    }
                    default {
                        [BitConverter]::ToString($value) -replace "-", ""
                    }
                }
            }
            "DateTime" {
                $value.ToString("o")  # ISO 8601
            }
            default {
                $value.ToString()
            }
        }
    }
    # Return final formatted string
    if ($convertedValues -and $convertedValues.Count -gt 0) {
        if ($convertedValues.Count -eq 1) {
            return $convertedValues
        } else {
            return $convertedValues -join "; "  # Join multiple values
        }
    }
    return $null  # No valid values
}

# Convert a collection of properties to friendly strings, skipping excluded ones
function Get-ADAttributes {
    param(
        [System.DirectoryServices.ResultPropertyCollection]$Properties
    )
    $adAttributes = @{}
    # Skip properties on the exclusion list (unless they're mandatory), convert others to friendly strings
    foreach ($propertyName in $Properties.PropertyNames) {
        if ($script:excludedAttributes -contains $propertyName -and $script:mandatoryAttributes -notcontains $propertyName) {
            continue
        }
        # Convert property values to friendly strings
        $propertyValue = Get-PropertyString -PropertyName $propertyName -PropertyValues $Properties[$propertyName]
        if ($propertyValue -ne $null) {  # Keep non-empty properties
            $adAttributes[$propertyName] = $propertyValue
        }
    }
    return $adAttributes
}

# Resolve SID to friendly name, including well-known SIDs
function Resolve-SID {
    param ([System.Security.Principal.SecurityIdentifier]$sid)
    try {
        # Try to translate to NTAccount (DOMAIN\Group)
        return $sid.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
    } catch {
        # Try to match against well-known SID types
        foreach ($sidType in [System.Enum]::GetValues([System.Security.Principal.WellKnownSidType])) {
            try {
                $wellKnownSid = New-Object System.Security.Principal.SecurityIdentifier($sidType, $null)
                if ($sid -eq $wellKnownSid) {
                    return $sidType.ToString()
                }
            } catch {
                continue
            }
        }
        # Fallback: return raw SID string
        return $sid.Value
    }
}

# Function to initialize output files (log and preview files)
function Initialize-OutputFiles {
    $script:LogFile = ".\ADSync.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] AD Sync started" | Out-File -FilePath $script:LogFile -Force

    # Setup preview files if needed
    if ($Preview) {
        Write-Status "Preview mode enabled, output will be saved to: $PreviewFile"
        if (Test-Path $PreviewFile) {
            Remove-Item $PreviewFile -Force
        }
    }
    if ($ScimPreview) {
        Write-Status "SCIM Preview mode enabled, output will be saved to: $ScimPreviewFile"
        if (Test-Path $ScimPreviewFile) {
            Remove-Item $ScimPreviewFile -Force
        }
    }
    if ($NoGroups) {
        Write-Status "NoGroups parameter specified - user groups will be skipped"
    }
}

# Initialize attribute size warning tracking
function Initialize-AttributeSizeWarnings {
    $script:attributeSizeWarnings = @{}
}

# Function to pre-resolve group SIDs for classification rules
function Initialize-GroupSIDResolution {
    $script:resolvedGroupSIDs = @{}
    foreach ($category in $script:classificationRules.Keys) {
        $script:resolvedGroupSIDs[$category] = @{}
        foreach ($groupName in $script:classificationRules[$category].Groups) {
            try {
                $group = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction Stop
                if ($group) {
                    $script:resolvedGroupSIDs[$category][$groupName] = $group.SID.Value
                } else {
                    Write-Warning "Group '$groupName' in classification rules was not found"
                }
            }
            catch {
                Write-Warning "Failed to resolve group '$groupName': $_"
            }
        }
    }
}

# Function to initialize Active Directory connection and domain information
function Initialize-ActiveDirectory {
    # Determine current Active Directory domain
    $script:domainDNS = (Get-ADDomain).DNSRoot
    Write-Log "Detected AD domain: $script:domainDNS"

    # Determine search base DN
    if (-not $BaseDN) {
        $script:domainDN = (Get-ADDomain).DistinguishedName
        Write-Log "Using domain DN as search base: $script:domainDN"
    } else {
        $script:domainDN = $BaseDN
        Write-Log "Using specified search base: $script:domainDN"
    }
    if (-not $script:domainDN) {
        Write-Host "Failed to determine domain DN, exiting." -ForegroundColor Red
        exit 1
    }

    # Build LDAP connection string (optionally with specific domain controller)
    if ($script:domainController) {
        $ldapPath = "LDAP://$($script:domainController)/$script:domainDN"
        Write-Log "Using specified domain controller: $script:domainController"
    } else {
        $ldapPath = "LDAP://$script:domainDN"
    }

    # Create DirectoryEntry connection
    try {
        if ($LdapUsername -and $LdapPassword) {
            Write-Log "Using provided LDAP credentials for binding"
            $script:DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $LdapUsername, $LdapPassword)
        } else {
            $script:DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
        }
        $script:DirectoryEntry.RefreshCache()
        Write-Status "Connected to Active Directory: $script:domainDN" -ForegroundColor Green
    } catch {
        Write-Status "Failed to connect to Active Directory: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    # Show user count for the search base
    if ($BaseDN) {
        $script:TotalUsers = Get-ADUserCount -SearchBase $BaseDN
        Write-Status "There are $script:TotalUsers users in the specified search base: $BaseDN"
    } else {
        $script:TotalUsers = Get-ADUserCount
        Write-Status "There are $script:TotalUsers users in this domain"
    }
}

# Get UPN from Distinguished Name (DN) with caching
function Get-UPNFromDN {
    param (
        [string]$DistinguishedName,
        [hashtable]$DNtoUPNCache
    )
    # Return null silently if the DN is null or empty
    if ([string]::IsNullOrEmpty($DistinguishedName)) {
        return $null
    }
    # Check cache first
    if ($DNtoUPNCache.ContainsKey($DistinguishedName)) {
        return $DNtoUPNCache[$DistinguishedName]
    }
    try {
        $user = Get-ADUser -Identity $DistinguishedName -Properties UserPrincipalName
        if ($user -and $user.UserPrincipalName) {
            # Add to cache for future lookups
            $DNtoUPNCache[$DistinguishedName] = $user.UserPrincipalName
            return $user.UserPrincipalName
        }
        else {
            Write-Warning "Could not find UPN for: $DistinguishedName"
            return $null
        }
    }
    catch {
        Write-Warning "Error looking up UPN for DN: $_"
        return $null
    }
}

# Check if user is in specified groups by token
function Test-UserInGroupsByToken {
    param (
        [string[]]$UserTokenGroupSIDs,
        [string[]]$TargetGroupSIDs
    )
    # todo: it might be more efficient to check if any of the target group SIDs are in the user token group SIDs
    # why - because the user is likely to have many more groups than the target group SIDs
    foreach ($sid in $UserTokenGroupSIDs) {
        if ($TargetGroupSIDs -contains $sid) {
            return $true
        }
    }
    return $false
}

# Check if user should be included based on classification rules
function Test-UserShouldBeIncluded {
    param(
        [string]$dn,
        [string]$sam
    )
    # Exclude logic: if matches any exclude, skip
    foreach ($ou in $script:excludeRules.OUs) {
        if ($dn -like "*$ou") { return $false }
    }
    foreach ($pattern in $script:excludeRules.NamePatterns) {
        if ($sam -like $pattern) { return $false }
    }
    # Include logic: if include rules exist, must match at least one
    $includeMatch = $true
    if ($script:includeRules.OUs.Count -gt 0 -or $script:includeRules.NamePatterns.Count -gt 0) {
        $includeMatch = $false
        foreach ($ou in $script:includeRules.OUs) {
            if ($dn -like "*$ou") { $includeMatch = $true }
        }
        foreach ($pattern in $script:includeRules.NamePatterns) {
            if ($sam -like $pattern) { $includeMatch = $true }
        }
    }
    return $includeMatch
}

# Check attribute size and warn if needed (only once per attribute)
function Check-AttributeSize {
    param(
        [string]$PropertyName,
        [object]$Value
    )
    if (-not $AttributeSizeWarningThreshold -or $script:attributeSizeWarnings.ContainsKey($PropertyName)) {
        return
    }
    $valueSize = 0
    $valueType = $Value.GetType().Name
    if ($valueType -eq "Byte[]") {
        $valueSize = $Value.Length
    } else {
        $valueSize = [System.Text.Encoding]::UTF8.GetByteCount($Value.ToString())
    }
    if ($valueSize -gt $AttributeSizeWarningThreshold) {
        Write-Warning "Large attribute detected: '$PropertyName' is $([math]::Round($valueSize/1024, 2))KB"

        $script:attributeSizeWarnings[$PropertyName] = $valueSize
    }
}

# Show summary of large attributes found during processing
function Show-AttributeSizeSummary {
    if ($script:payloadTooLargeDetected) {
        Write-Host "`n=== Large User Warning ===" -ForegroundColor Yellow
        Write-Host "One or more users were not uploaded because their data was too large." -ForegroundColor Yellow
        Write-Host "Use Preview mode to identity the large attributes and adjust your excludedAttributes or specifiedGroups settings in your customization file." -ForegroundColor Yellow
    }
    if (-not $script:attributeSizeWarnings -or $script:attributeSizeWarnings.Count -eq 0) {
        return
    }
    Write-Host "`n=== Large Attribute Warning ===" -ForegroundColor Yellow
    Write-Host "The following attributes exceeded the size threshold ($([math]::Round($AttributeSizeWarningThreshold/1024, 2))KB):" -ForegroundColor Yellow

    foreach ($attr in $script:attributeSizeWarnings.Keys | Sort-Object) {
        $size = [math]::Round($script:attributeSizeWarnings[$attr]/1024, 2)
        Write-Host "  $attr : ${size}KB" -ForegroundColor Yellow
    }
    Write-Host "`nConsider adding large attributes to the excludedAttributes list if they are not needed for CII analysis." -ForegroundColor Yellow
    Write-Host "Large attributes can slow down processing and may exceed API payload limits." -ForegroundColor Yellow
}

# Send a SCIM request to the CII service
function Send-ScimBulkRequest {
    param(
        [array]$BulkOperations
    )
    $bulkRequest = @{
        schemas = @("urn:ietf:params:scim:api:messages:2.0:BulkRequest")
        Operations = $BulkOperations
    }
    $headers = @{
        "Authorization" = "Bearer $script:bearerToken"
        "Content-Type" = "application/scim+json; charset=utf-8"
    }
    try {
        # Serialize once (Compressed keeps Unicode characters intact; PowerShell does not escape them)
        $json = $bulkRequest | ConvertTo-Json -Depth 10 -Compress
        $response = Invoke-RestMethod -Uri $script:scimUrl -Method POST -Headers $headers -Body ([System.Text.Encoding]::UTF8.GetBytes($json))
        # Check if any operation failed
        if ($response.Operations) {
            $failedOps = $response.Operations | Where-Object { $_.status -ne "201" }
            if ($failedOps) {
                Write-Warning "Some SCIM operations failed: $($failedOps.Count) out of $($response.Operations.Count)"
                return $false
            }
        }
        return $true
    } catch {
        Write-Log "SCIM bulk request failed: $($_.Exception.Message)"
        return $false
    }
}

# Convert AD user object to CII SCIM user schema
function ConvertTo-ScimUser {
    param(
        [hashtable]$UserObject,
        [array]$groups = @()
    )
    $adAttributes = $UserObject.adAttributes
    $ciiAttributes = $UserObject.ciiAttributes

    # First attributes that relate to SCIM v2.0 user schema...

    # displayName (similar to Entra ID rules)
    $displayName = if ($adAttributes.displayname) {
        $adAttributes.displayname
    } elseif ($adAttributes.GivenName -or $adAttributes.sn) {
        @($adAttributes.GivenName, $adAttributes.sn) -join ' '
    } else {
        $adAttributes.samAccountName
    }

    # name
    $name = @{}
    if ($adAttributes.GivenName) { $name["givenName"] = $adAttributes.GivenName }
    if ($adAttributes.sn) { $name["familyName"] = $adAttributes.sn }
    if ($adAttributes.Initials) { $name["middleName"] = $adAttributes.Initials }
    if ($adAttributes.DisplayName) {
        $name["formatted"] = $adAttributes.DisplayName
    } elseif ($adAttributes.GivenName -or $adAttributes.sn) {
        $name["formatted"] = "$($adAttributes.GivenName) $($adAttributes.sn)".Trim()
    }

    # UserName
    $userName = if ($adAttributes.userPrincipalName) {
        $adAttributes.userPrincipalName
    } else {
        "$($adAttributes.samaccountname)@$script:domainDNS"
    }

    # Email
    $emails = @()
    if ($adAttributes.mail) {
        $emails += @{
            type    = "work"
            value   = $adAttributes.mail
            primary = $true
        }
    }

    # Phone numbers
    $phoneNumbers = @()
    if ($adAttributes.telephoneNumber) {
        $phoneNumbers += @{ type = "work"; value = $adAttributes.telephoneNumber }
    }
    if ($adAttributes.MobilePhone) {
        $phoneNumbers += @{ type = "mobile"; value = $adAttributes.MobilePhone }
    }
    if ($adAttributes.facsimileTelephoneNumber) {
        $phoneNumbers += @{ type = "fax"; value = $adAttributes.facsimileTelephoneNumber }
    }

    # Addresses
    $addresses = @()
    $address = @{}
    if ($adAttributes.streetAddress) { $address["streetAddress"] = $adAttributes.streetAddress }
    if ($adAttributes.l) { $address["locality"] = $adAttributes.l }
    if ($adAttributes.st) { $address["region"] = $adAttributes.st }
    if ($adAttributes.postalCode) { $address["postalCode"] = $adAttributes.postalCode }
    if ($adAttributes.co) { $address["country"] = $adAttributes.co }
    if ($address.Count -gt 0) {
        $address["type"] = "work"
        $addresses += $address
    }

    # Group objects
    $scimGroups = @()
    if (-not $NoGroups) {
        foreach ($group in $groups) {
            $scimGroups += @{
                value = $group.sid
                display = $group.name
            }
        }
    }

    # Active status
    $isDisabled = ($adAttributes.userAccountControl -band 0x2) -ne 0
    $isLockedOut = ($adAttributes.userAccountControl -band 0x10) -ne 0
    $active = -not $isDisabled -and -not $isLockedOut

    # Now Enterprise schema extension...

    $enterpriseProperties = @{}
    if ($adAttributes.employeeID) { $enterpriseProperties["employeeNumber"] = $adAttributes.employeeID }
    if ($adAttributes.department) { $enterpriseProperties["department"] = $adAttributes.department }
    if ($adAttributes.company) { $enterpriseProperties["company"] = $adAttributes.company }

    # AD gives us manager in DN format, which is unfriendly, convert to UPN
    $managerUPN = Get-UPNFromDN -DistinguishedName $adAttributes.manager -DNtoUPNCache $managerDNtoUPNCache
    if ($managerUPN) {
        $enterpriseProperties["manager"] = @{
            displayName = $adAttributes.manager -replace '^CN=([^,]+),.*$', '$1'
            value = $managerUPN
        }
    }

    # userType
    $userType = if ($ciiAttributes.isAdmin) {
        "admin"
    } elseif ($ciiAttributes.isServiceAccount) {
        "service"
    } elseif ($adAttributes.samAccountName -eq "Guest") {
        "guest"
    } elseif ($ciiAttributes.isExecutive) {
        "executive"
    } elseif ($ciiAttributes.isExternalAccount) {
        "external"
    } else {
        "employee"
    }

    # Now we can build the SCIM user object
    $scimUser = @{
        schemas = @(
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            "urn:ietf:params:scim:schemas:extension:cisco:cii:ad"
        )
        userName    = $userName
        # We set externalId to match Entra's immutableId, to promote user merging
        externalId  = [Convert]::ToBase64String([Guid]::Parse($adAttributes.objectGUID).ToByteArray())
        displayName = $displayName
        active      = $active
        userType    = $userType
        "urn:ietf:params:scim:schemas:extension:cisco:cii:ad" = @{
            adAttributes  = $adAttributes
            ciiAttributes = $ciiAttributes
        }
    }

    if ($name.Count -gt 0) { $scimUser["name"] = $name }
    if ($emails.Count -gt 0) { $scimUser["emails"] = $emails }
    if ($phoneNumbers.Count -gt 0) { $scimUser["phoneNumbers"] = $phoneNumbers }
    if ($addresses.Count -gt 0) { $scimUser["addresses"] = $addresses }
    if ($adAttributes.mailNickname) { $scimUser["nickName"] = $adAttributes.mailNickname }
    if ($adAttributes.wWWHomePage) { $scimUser["profileUrl"] = $adAttributes.wWWHomePage }
    if ($adAttributes.Title) { $scimUser["title"] = $adAttributes.Title }
    if ($scimGroups.Count -gt 0) { $scimUser["groups"] = $scimGroups }
    if ($enterpriseProperties.Count -gt 0) {
        $scimUser["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"] = $enterpriseProperties
    }

    return $scimUser
}

# Send a batch of users to the CII service
function Send-BatchOfUsers {
    param(
        [array]$UserBatch
    )
    if ($UserBatch.Count -eq 0) { return }
    if ($Preview) {
        $UserBatch | ConvertTo-Json -Depth 10 | Out-File -FilePath $PreviewFile -Append -Encoding UTF8
    } else {
        $bulkOperations = @()
        foreach ($userObject in $UserBatch) {
            $scimData = ConvertTo-ScimUser -UserObject $userObject -groups $userObject.groups
            $operation = @{
                method = "POST"
                path = "/Users"
                bulkId = $userObject.adAttributes.objectGUID
                data = $scimData
            }
            # Check operation size
            $opJson = $operation | ConvertTo-Json -Depth 10
            $opSize = [System.Text.Encoding]::UTF8.GetByteCount($opJson)
            if ($opSize -gt $SCIM_OPERATION_SIZE_LIMIT) {
                Write-Warning "Payload for user $($userObject.adAttributes.samAccountName) is too large and will be skipped."
                Write-Log "Payload for user $($userObject.adAttributes.samAccountName) too large ($opSize bytes) and will be skipped."
                $script:payloadTooLargeDetected = $true
                continue
            }
            $bulkOperations += $operation
        }
        if ($ScimPreview) {
            $bulkPayload = @{
                schemas = @("urn:ietf:params:scim:api:messages:2.0:BulkRequest")
                Operations = $bulkOperations
            }
            $bulkPayload | ConvertTo-Json -Depth 10 | Out-File -FilePath $ScimPreviewFile -Append -Encoding UTF8
        } else {
            $success = Send-ScimBulkRequest -BulkOperations $bulkOperations
            if (-not $success) {
                Write-Warning "Failed to send request to CII"
            }
        }
    }
}

# Get a user's group info (names and SIDs)
function Get-UserGroupInfo {
    param(
        [string]$DistinguishedName,
        [switch]$SkipGroupNames = $false
    )
    $groups = @()
    $userSIDs = @()
    $userWithGroups = Get-ADUser -Identity $DistinguishedName -Properties tokenGroups
    $tokenGroups = $userWithGroups.tokenGroups
    if ($tokenGroups) {
        foreach ($tg in $tokenGroups) {
            $userSIDs += $tg.Value
        }
        # Only resolve group names if not skipping
        if (-not $SkipGroupNames) {
            foreach ($sid in $tokenGroups) {
                $groupName = Resolve-SID -sid $sid
                # If specifiedGroups is set, only include matching groups, else include all
                if ($script:specifiedGroups.Count -eq 0 -or $script:specifiedGroups -contains $groupName) {
                    $groupEntry = @{
                        sid  = $sid.Value
                        name = $groupName
                    }
                    $groups += $groupEntry
                }
            }
        }
    }
    return @{
        Groups = $groups
        UserSIDs = $userSIDs
    }
}

# Get CII attributes (user classification and normalized timestamps)
function Get-CIIAttributes {
    param(
        [hashtable]$adAttributes,
        [string[]]$userSIDs = @()
    )

    # Classification logic (from Invoke-UserClassification)
    $classifications = @{
        isServiceAccount = $false
        isAdmin = $false
        isExecutive = $false
        isExternalAccount = $false
    }

    $sam = $adAttributes.samAccountName
    $dn = $adAttributes.distinguishedName

    # First check custom attribute mapping
    $customUserType = $null
    if ($script:customAttributeMapping.AttributeName -and $adAttributes.ContainsKey($script:customAttributeMapping.AttributeName)) {
        $attributeValue = $adAttributes[$script:customAttributeMapping.AttributeName]
        if ($script:customAttributeMapping.ValueMappings.ContainsKey($attributeValue)) {
            $customUserType = $script:customAttributeMapping.ValueMappings[$attributeValue]
            # Set classification flags based on custom userType mapping
            switch ($customUserType) {
                "admin" { $classifications.isAdmin = $true }
                "service" { $classifications.isServiceAccount = $true }
                "executive" { $classifications.isExecutive = $true }
                "external" { $classifications.isExternalAccount = $true }
                # "employee", "guest" and other types don't set any special flags
            }
        }
    }

    # If no custom attribute mapping matched, use the rule-based classification
    if (-not $customUserType) {
        foreach ($category in $script:classificationRules.Keys) {
            $rule = $script:classificationRules[$category]

            # Groups
            $targetGroupSIDs = $script:resolvedGroupSIDs[$category].Values
            $inGroup = $false
            if ($userSIDs.Count -gt 0 -and $targetGroupSIDs.Count -gt 0) {
                $inGroup = Test-UserInGroupsByToken -UserTokenGroupSIDs $userSIDs -TargetGroupSIDs $targetGroupSIDs
            }

            # OUs
            $inOU = $false
            if ($rule.OUs.Count -gt 0) {
                foreach ($ou in $rule.OUs) {
                    if ($dn -like "*$ou") {
                        $inOU = $true
                        break
                    }
                }
            }

            # Name patterns
            $matchesPattern = $false
            if ($rule.NamePatterns.Count -gt 0) {
                foreach ($pattern in $rule.NamePatterns) {
                    if ($sam -like $pattern) {
                        $matchesPattern = $true
                        break
                    }
                }
            }

            # Explicit usernames
            $inUserList = $rule.Usernames -contains $sam

            # Match if any criteria true
            if ($inGroup -or $inOU -or $matchesPattern -or $inUserList) {
                $classifications[$category] = $true
            }
        }
    }

    # Build CII attributes (from Get-CiiAttributes)
    $ciiAttributes = @{
        isServiceAccount = $classifications.isServiceAccount
        isAdmin         = $classifications.isAdmin
        isExecutive     = $classifications.isExecutive
        isExternalAccount = $classifications.isExternalAccount
    }

    if ($adAttributes.whenCreated -ne $null) {
        $val = Convert-GeneralizedTimeUtc $adAttributes.whenCreated
        if ($val) { $ciiAttributes["isoCreated"] = $val }
    }
    if ($adAttributes.whenChanged -ne $null) {
        $val = Convert-GeneralizedTimeUtc $adAttributes.whenChanged
        if ($val) { $ciiAttributes["isoLastModified"] = $val }
    }
    $val = Convert-FileTimeUtc $adAttributes.lastLogon
    if ($val) { $ciiAttributes["isoLastSuccessfulLogin"] = $val }

    $val = Convert-FileTimeUtc $adAttributes.pwdLastSet
    if ($val) { $ciiAttributes["isoLastPasswordChange"] = $val }

    $val = Convert-FileTimeUtc $adAttributes.badPasswordTime
    if ($val) { $ciiAttributes["isoBadPasswordTime"] = $val }

    $val = Convert-FileTimeUtc $adAttributes.lockoutTime
    if ($val) { $ciiAttributes["isoLockoutTime"] = $val }

    if ($adAttributes.accountExpires -ne $null) {
        $val = [int64]$adAttributes.accountExpires
        if ($val -gt 0 -and $val -ne 0x7FFFFFFFFFFFFFFF) {
            $ciiAttributes["isoAccountExpiry"] = Convert-FileTimeUtc $val
        }
    }
    return $ciiAttributes
}

# Function to read encryption key bytes from file
function Get-EncryptionKeyBytes {
    param([string]$KeyFilePath)
    if ([string]::IsNullOrWhiteSpace($KeyFilePath)) {
        Write-Error "KeyFilePath is empty."
        exit 1
    }
    if (-not [IO.Path]::IsPathRooted($KeyFilePath)) {
        $KeyFilePath = Join-Path $PSScriptRoot $KeyFilePath
    }
    if (-not (Test-Path -LiteralPath $KeyFilePath -PathType Leaf)) {
        Write-Error "Encryption key file not found: $KeyFilePath"
        exit 1
    }
    try {
        return [IO.File]::ReadAllBytes($KeyFilePath)
    } catch {
        Write-Error "Failed to read encryption key file: $KeyFilePath ($_)"
        exit 1
    }
}

# Function to decrypt encrypted config values using the key
function Decrypt-Value {
    param(
        [string]$encryptedString,
        [byte[]]$keyBytes
    )
    $secure = ConvertTo-SecureString $encryptedString -Key $keyBytes
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}

# Function to get OAuth bearer token
function Get-BearerToken {
    Write-Log "Retrieving OAuth bearer token"

    try {
        # Load the encrypted configuration
        $config = Get-Content $ConfigFilePath -Raw | ConvertFrom-Json

        # Get SCIM base URL from config (not encrypted)
        $scimBaseUrl = $config.ApiEndpoint
        if (-not $scimBaseUrl) {
            Write-Error "ApiEndpoint not found in config file"
            exit 1
        }

        # Create SCIM bulk endpoint URL and store in global scope
        $script:scimUrl = "$scimBaseUrl/Bulk"
        Write-Log "Using SCIM endpoint: $script:scimUrl"

        # Load the encryption key
        $keyBytes = Get-EncryptionKeyBytes -KeyFilePath $KeyFilePath

        # Extract token endpoint
        $tokenEndpoint = $config.TokenEndpoint

        # Decrypt client credentials
        $clientId = Decrypt-Value -encryptedString $config.ClientId.Value -keyBytes $keyBytes
        $clientSecret = Decrypt-Value -encryptedString $config.ClientSecret.Value -keyBytes $keyBytes

        Write-Log "Configuration decrypted successfully"

        # Define the request body
        $body = @{
            client_id     = $clientId
            client_secret = $clientSecret
            grant_type    = "client_credentials"
        }

        # Send the POST request to get the token
        Write-Log "Sending token request to $tokenEndpoint"
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"

        Write-Log "Bearer token obtained"
        return $response.access_token

    } catch {
        Write-Log "Failed to retrieve bearer token: $_"
        return $null
    }
}

# Main function to process users
function Process-Users {
    $startTime = Get-Date
    Write-Log "Starting user processing at $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"

    # Create dynamic activity title based on mode
    $baseActivity = "Cisco Identity Intelligence ADSync"
    $activityTitle = if ($Preview) {
        "$baseActivity (Preview mode)"
    } elseif ($ScimPreview) {
        "$baseActivity (SCIM Preview mode)"
    } else {
        $baseActivity
    }

    # Get users from AD
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($script:DirectoryEntry, "(&(objectClass=user)(objectCategory=person))", @('*'))
    $Searcher.PageSize = $UserBatchSize
    $Results = $Searcher.FindAll()

    if (-not $Results) {
        Write-Host "No users found to process." -ForegroundColor Yellow
        return
    }

    $UserBatch = @()
    $Count = 0
    $Processed = 0
    $Skipped = 0
    $lastProgressUpdate = Get-Date

    foreach ($Result in $Results) {
        $Count++
        $props = $Result.Properties
        $dn = $props["distinguishedName"][0]
        $sam = $props["samaccountname"][0]

        # Update progress on every 100 users or every 5 seconds
        $now = Get-Date
        if (($now - $lastProgressUpdate).TotalSeconds -ge 5 -or $Count % 100 -eq 0) {
            Show-Progress -Activity $activityTitle -Status "Evaluating" -Count $Count -Total $TotalUsers -StartTime $startTime -ProcessedCount $Processed -SkippedCount $Skipped
            $lastProgressUpdate = $now
        }

        # Skip if user does not match include/exclude rules
        if (-not (Test-UserShouldBeIncluded -dn $dn -sam $sam)) {
            $Skipped++
            continue
        }

        # Get each users's AD attributes, groups and classification
        $Processed++
        $adAttributes = Get-ADAttributes -Properties $props
        $userGroupInfo = Get-UserGroupInfo -DistinguishedName $adAttributes.DistinguishedName -SkipGroupNames:$NoGroups
        $ciiAttributes = Get-CIIAttributes -adAttributes $adAttributes -userSIDs $userGroupInfo.UserSIDs

        # Batch users until we have enough to send
        $UserBatch += @{ adAttributes = $adAttributes; ciiAttributes = $ciiAttributes; groups = $userGroupInfo.Groups }
        if ($UserBatch.Count -ge $ScimBulkSize) {
            Send-BatchOfUsers -UserBatch $UserBatch
            $UserBatch = @()
        }
    }

    # Process final batch if any users remain
    if ($UserBatch.Count -gt 0) {
        Send-BatchOfUsers -UserBatch $UserBatch
    }

    # Final progress update
    Show-Progress -Activity "User Processing Complete" -Status "Completed" -Count $Count -Total $TotalUsers -StartTime $startTime -ProcessedCount $Processed -SkippedCount $Skipped
    Write-Progress -Activity "User Processing Complete" -Completed
    $endTime = Get-Date
    $totalTime = $endTime - $startTime
    Write-Host "`n=== Processing Summary ==="
    Write-Host "Total Users Evaluated: $Count"
    Write-Host "Users Processed: $Processed"
    Write-Host "Users Skipped: $Skipped"
    Write-Host "Total Time: $($totalTime.ToString('hh\:mm\:ss'))"
    Write-Host "Average Rate: $([math]::Round($Count / $totalTime.TotalSeconds, 2)) users/sec"
    Write-Log "Processing completed. Total: $Count, Processed: $Processed, Skipped: $Skipped, Time: $($totalTime.ToString('hh\:mm\:ss'))"

    $Results.Dispose()
}

# -------------------------
# Main script entry point
# -------------------------

# Configure secure TLS protocols (older Server versions may not support TLS 1.2 or 1.3 by default)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

Initialize-OutputFiles          # Initialize log and preview files
Load-CustomerCustomization      # Load customer customization settings

# Get auth token using the provided key and config file (skip if preview mode)
if (-not $Preview) {
    $script:bearerToken = Get-BearerToken
    if (-not $script:bearerToken) {
        Write-Error "Failed to retrieve bearer token. Exiting."
        exit 1
    }
}

$managerDNtoUPNCache = @{}       # Create a cache for DN to UPN mapping
Initialize-AttributeSizeWarnings # Initialize attribute size warning tracking
Initialize-ActiveDirectory       # Connect to Active Directory and initialize domain information
Initialize-GroupSIDResolution    # Pre-resolve group SIDs (allows fast SID-based comparison)
Process-Users                    # Process users in AD, classify and send to CII

Write-Log "AD Sync completed"
Show-AttributeSizeSummary       # Show summary of large attributes if any were found
