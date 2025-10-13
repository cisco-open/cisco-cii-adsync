<#
.SYNOPSIS
    Provisions configuration files for the Cisco Identity Intelligence ADSync script.

.DESCRIPTION
    This script takes a plaintext configuration file and generates an encrypted version
    along with a secure key file for use with the ADSync tool.  Run this once on your
    configuration file to prepare it for use with the ADSync script.

.PARAMETER version
    Displays the script version and exits.

.PARAMETER InputConfigPath
    Path to the plaintext configuration file, typically downloaded from your AD Integration
    in Cisco Identity Intelligence.

.PARAMETER OutputConfigPath
    (Optional) Path where the encrypted configuration file will be saved.
    Usually not specified, defaults to "<your-integration>-encrypted-config.json".

.PARAMETER KeyFilePath
    (Optional) Path where the encryption key will be saved.
    Usually not specified, defaults to "<your-integration>-encryption.key".

.EXAMPLE
    .\Provision.ps1 -InputConfigPath .\cii-adsync-myintegation-config.json

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

    [Parameter(Mandatory=$true, ParameterSetName = "Default", HelpMessage="Path to the configuration file from Cisco Identity Intelligence AD Integration.")]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$InputConfigPath,

    [Parameter(ParameterSetName = "Default", HelpMessage="Path where the encrypted configuration file will be saved")]
    [string]$OutputConfigPath = $null,

    [Parameter(ParameterSetName = "Default", HelpMessage="Path where the encryption key will be saved")]
    [string]$KeyFilePath = $null
)

$ScriptVersion = "1.0"
$SleepTime = 500

# Handle version parameter set
if ($PSCmdlet.ParameterSetName -eq "Version") {
    Write-Host $ScriptVersion
    exit 0
}

# Logging functions
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $LogFile -Append
}

# Write status messages to console and log
function Write-Status {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
    Write-Log $Message
}

# Function to ensure we have a valid key file
function EnsureKeyFile($path) {
    if (-not (Test-Path $path)) {
        Write-Log "Creating new encryption key file at $path"
        # Generate a secure 32-byte key
        $keyBytes = New-Object Byte[] 32
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($keyBytes)
        $keyBytes | Set-Content -Path $path -Encoding Byte
    }

    # Return the key
    return Get-Content -Path $path -Encoding Byte
}

# Encrypt a value using the key
function EncryptValue($plainText, $keyBytes) {
    $secure = ConvertTo-SecureString $plainText -AsPlainText -Force
    return ConvertFrom-SecureString $secure -Key $keyBytes
}

# Decrypt a value using the key
function DecryptValue($encryptedString, $keyBytes) {
    $secure = ConvertTo-SecureString $encryptedString -Key $keyBytes
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}

# Validate the structure of the input config file
function ValidateConfig($config) {
    Write-Log "Validating config file structure"
    $requiredFields = @("clientId", "clientSecret", "tokenUrl", "scimBaseUrl")
    foreach ($field in $requiredFields) {
        if (-not $config.PSObject.Properties.Name -contains $field -or [string]::IsNullOrWhiteSpace($config.$field)) {
            Write-Log "Missing or empty required field: '$field' in input config"
            throw "Missing or empty required field: '$field' in input config"
        }
    }
    Write-Log "Config file validation successful"
}

# Get a bearer token from the token endpoint
function GetBearerToken($clientId, $clientSecret, $tokenEndpoint) {
    Write-Log "Attempting to acquire bearer token from $tokenEndpoint"
    try {
        $body = @{
            grant_type    = "client_credentials"
            client_id     = $clientId
            client_secret = $clientSecret
        }
        $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Log "Bearer token acquired successfully"
        return $response.access_token
    } catch {
        Write-Log "Failed to retrieve bearer token: $_"
        Write-Error "Failed to retrieve bearer token: $_"
        return $null
    }
}

# Validate the SCIM service by checking its schemas
function ValidateScimService($apiEndpoint, $token) {
    $scimUrl = "$apiEndpoint/Schemas"
    Write-Log "Validating SCIM service at $scimUrl"
    try {
        $headers = @{ Authorization = "Bearer $token" }
        $response = Invoke-RestMethod -Uri $scimUrl -Headers $headers -Method Get
        if ($response.schemas -contains "urn:ietf:params:scim:schemas:core:2.0") {
            Write-Log "SCIM service validated successfully"
            return $true
        } else {
            Write-Log "SCIM service did not include required schema"
            Write-Error "SCIM service did not include required schema."
            return $false
        }
    } catch {
        Write-Log "Failed to query SCIM service: $_"
        Write-Error "Failed to query SCIM service: $_"
        return $false
    }
}

# Configure secure TLS protocols (older Server versions may not support TLS 1.2 or 1.3 by default)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Log file setup
$LogFile = ".\Provision.log"
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"[$timestamp] Provisioning script started" | Out-File -FilePath $LogFile -Force

# Generate filenames derived from input filename
if ($InputConfigPath) {
    # Get the base name without extension
    $inputFileInfo = [System.IO.FileInfo]$InputConfigPath
    $baseName = $inputFileInfo.BaseName

    # If the basename ends with -config, remove it
    $baseName = $baseName -replace '-config$', ''
    Write-Log "Will use base name '$baseName' in file names"

    # Set the output paths in the CURRENT directory if not explicitly provided
    if (-not $OutputConfigPath) {
        $OutputConfigPath = ".\$baseName-encrypted-config.json"
    }
    if (-not $KeyFilePath) {
        $KeyFilePath = ".\$baseName-encryption.key"
    }
}

# Display confirmation message about the input file being checked
Write-Status "Checking your config file $InputConfigPath"
Write-Log "Will make encryption key file $KeyFilePath"
Write-Log "Will save encrypted config to $OutputConfigPath"

# Step 1: Load credentials
if ($InputConfigPath) {
    if (-not (Test-Path $InputConfigPath)) {
        Write-Error "Input config file not found at $InputConfigPath"
        Write-Log "Input config file not found at $InputConfigPath"
        exit 1
    }

    try {
        Write-Log "Loading config from $InputConfigPath"
        $inputJson = Get-Content $InputConfigPath -Raw
        $inputConfig = $inputJson | ConvertFrom-Json
        ValidateConfig $inputConfig

        $clientId = $inputConfig.clientId
        $clientSecret = $inputConfig.clientSecret
        $tokenEndpoint = $inputConfig.tokenUrl
        $apiEndpoint = $inputConfig.scimBaseUrl
        Write-Log "Config properties loaded successfully"
    } catch {
        Write-Log "Failed to load or validate input config: $_"
        Write-Error "Failed to load or validate input config: $_"
        exit 1
    }
} else {
    $clientId = Read-Host "Enter Client ID"
    $clientSecret = Read-Host "Enter Client Secret"
    $tokenEndpoint = Read-Host "Enter Token Endpoint"
    $apiEndpoint = Read-Host "Enter API Endpoint"
    Write-Log "Collected manual input from user (credentials not logged)"

    if ([string]::IsNullOrWhiteSpace($clientId) -or
        [string]::IsNullOrWhiteSpace($clientSecret) -or
        [string]::IsNullOrWhiteSpace($tokenEndpoint) -or
        [string]::IsNullOrWhiteSpace($apiEndpoint)) {
        Write-Error "All fields are required. Provisioning aborted."
        Write-Log "Provisioning aborted due to missing input fields"
        exit 1
    }
}

# Step 2: Try to get a bearer token
Write-Log "Validating credentials"
Write-Progress -Activity "Validating" -Status "Getting bearer token" -PercentComplete 0
Start-Sleep -Milliseconds $SleepTime

$token = GetBearerToken -clientId $clientId -clientSecret $clientSecret -tokenEndpoint $tokenEndpoint
if (-not $token) {
    Write-Error "Could not validate credentials. Config not saved."
    Write-Log "Failed to validate credentials. Config not saved."
    exit 1
}

Write-Log "Credentials validated"
Write-Progress -Activity "Validating" -Status "Checking SCIM service" -PercentComplete 25
Start-Sleep -Milliseconds $SleepTime

# Step 3: Validate SCIM service
if (-not (ValidateScimService -apiEndpoint $apiEndpoint -token $token)) {
    Write-Error "SCIM service validation failed. Config not saved."
    Write-Log "SCIM service validation failed. Config not saved."
    exit 1
}

Write-Progress -Activity "Validating" -Status "Creating new key and config files" -PercentComplete 50
Start-Sleep -Milliseconds $SleepTime

# Step 4: Ensure we have a key file and get the key
$keyBytes = EnsureKeyFile -path $KeyFilePath
Write-Log "Using encryption key file: $KeyFilePath"

# Step 5: Encrypt credentials using the key and save config
Write-Log "Encrypting credentials"
$encryptedClientId = @{
    Encrypted = $true
    Value = EncryptValue -plainText $clientId -keyBytes $keyBytes
    KeyFile = $KeyFilePath
}

$encryptedClientSecret = @{
    Encrypted = $true
    Value = EncryptValue -plainText $clientSecret -keyBytes $keyBytes
    KeyFile = $KeyFilePath
}

$config = [PSCustomObject]@{
    # Non-encrypted configuration properties
    TokenEndpoint = $tokenEndpoint
    ApiEndpoint = $apiEndpoint

    # Encryption key file reference
    EncryptionKeyFile = $KeyFilePath

    # Encrypted configuration properties
    ClientId = $encryptedClientId
    ClientSecret = $encryptedClientSecret
}

try {
    Write-Log "Saving encrypted config to $OutputConfigPath"
    $config | ConvertTo-Json -Depth 3 | Set-Content $OutputConfigPath -Force
} catch {
    Write-Log "Failed to write config file: $_"
    Write-Error "Failed to write config file: $_"
    exit 1
}

# Step 6: Verify we can load and decrypt the saved configuration
Write-Log "Testing the new configuration loads and decrypts"
Write-Progress -Activity "Validating" -Status "Validating new configuration" -PercentComplete 75
Start-Sleep -Milliseconds $SleepTime
try {
    # Load the config we just saved
    $loadedJson = Get-Content $OutputConfigPath -Raw
    $loadedConfig = $loadedJson | ConvertFrom-Json

    # Get the key file path and load the key
    $loadedKeyPath = $loadedConfig.EncryptionKeyFile
    if (-not (Test-Path $loadedKeyPath)) {
        Write-Log "Key file not found at: $loadedKeyPath"
        throw "Key file not found at: $loadedKeyPath"
    }
    $loadedKey = Get-Content -Path $loadedKeyPath -Encoding Byte

    # Decrypt the values
    $decryptedClientId = DecryptValue -encryptedString $loadedConfig.ClientId.Value -keyBytes $loadedKey
    $decryptedClientSecret = DecryptValue -encryptedString $loadedConfig.ClientSecret.Value -keyBytes $loadedKey

    # Verify the decrypted values match the originals
    $clientIdMatch = $decryptedClientId -eq $clientId
    $secretMatch = $decryptedClientSecret -eq $clientSecret

    if ($clientIdMatch -and $secretMatch) {
        Write-Status "Config verification successful" -Color Green
        # Show partial values for verification in log only
        $partialClientId = $decryptedClientId.Substring(0, [Math]::Min(4, $decryptedClientId.Length)) + "..."
        $partialSecret = $decryptedClientSecret.Substring(0, [Math]::Min(4, $decryptedClientSecret.Length)) + "..."
        Write-Log "Partial Client ID: $partialClientId"
        Write-Log "Partial Client Secret: $partialSecret"
    } else {
        Write-Log "Decryption verification failed! Client ID match: $($clientIdMatch), Secret match: $($secretMatch)"
        Write-Status "Decryption verification failed!" -Color Red
    }
} catch {
    Write-Log "Failed to test decryption: $_"
    Write-Status "Failed to verify config! See log for details." -Color Red
}

Write-Progress -Activity "Validating" -Status "Configuration looks good" -PercentComplete 100
Start-Sleep -Milliseconds $SleepTime
Write-Status "Created key file $KeyFilePath"
Write-Status "Created encrypted config file $OutputConfigPath"
Write-Host "You can now use these with the ADSync script (copied to clipboard)`ne.g."
Write-Host "`t.\ADSync.ps1 -KeyFilePath $KeyFilePath -ConfigFilePath $OutputConfigPath" -ForegroundColor Green
".\ADSync.ps1 -KeyFilePath $KeyFilePath -ConfigFilePath $OutputConfigPath" | Set-Clipboard

# Step 7: Offer to delete the original config file for security
if ($InputConfigPath -and (Test-Path $InputConfigPath) -and ($InputConfigPath -ne $OutputConfigPath)) {
    Write-Host "`nThe original config file can now be deleted"
    $deleteChoice = Read-Host "Delete the original config file? (Y/N)"
    Write-Log "User prompted to delete original config file"

    if ($deleteChoice.ToUpper() -eq "Y") {
        try {
            Remove-Item -Path $InputConfigPath -Force
            Write-Status "Original config file deleted" -Color Green
            Write-Log "Original config file deleted successfully"
        } catch {
            Write-Status "Failed to delete the config file: $_"
        }
    } else {
        Write-Log "User chose to keep the original config file"
    }
}

Write-Status "Provisioning script completed successfully" -Color Green
