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
    try {
        $fullPath = Join-Path $PSScriptRoot $path
        if (-not (Test-Path $path)) {
            Write-Log "Creating new encryption key file at $path"
            # Generate a secure 32-byte key
            $keyBytes = New-Object Byte[] 32
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
            [System.IO.File]::WriteAllBytes($fullPath, $keyBytes)
            Write-Log "Encryption key file created at $path"
        }
        # Return the key
        return [System.IO.File]::ReadAllBytes($fullPath)
    } catch {
        Write-Error "Failed to create or read key file: $_"
        Write-Log "Failed to create or read key file: $_"
        exit 1
    }
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

    # Get the key file path
    $loadedKeyPath = $loadedConfig.EncryptionKeyFile
    if (-not (Test-Path $loadedKeyPath)) {
        Write-Log "Key file not found at: $loadedKeyPath"
        throw "Key file not found at: $loadedKeyPath"
    }
    # Load the encryption key
    $loadedKey = Get-EncryptionKeyBytes -KeyFilePath $loadedKeyPath

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
    exit 1
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

# SIG # Begin signature block
# MIIpZQYJKoZIhvcNAQcCoIIpVjCCKVICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCABDPh3c48IGKt3
# JQf0Yb/mZJ1R46su3y/qUar0CP4RbqCCDhowggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggdiMIIFSqADAgECAhAOKNTaJjIAZ6j425z/NM/LMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwMTA3MDAwMDAwWhcNMjcwMjIw
# MjM1OTU5WjBqMQswCQYDVQQGEwJVUzERMA8GA1UECBMITWljaGlnYW4xEjAQBgNV
# BAcTCUFubiBBcmJvcjEZMBcGA1UEChMQRHVvIFNlY3VyaXR5IExMQzEZMBcGA1UE
# AxMQRHVvIFNlY3VyaXR5IExMQzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAJ5y5cbdQuifSsnFAQ3MkPwYQmHeZN0eVr4rypVuhFiBxN41KJb9phAw2lts
# Rzs5sVCKWKhNu10k6sExcNAbmLIR5WnE43kw1MAkRjNSKIiKtMeYtxQgPMEr24lK
# G5hwAa3Lx6TAQjVraRBw/ddJh34KsvwYGm8YC08FVdRnBX0zs52GLD/bW1+SkYg0
# PHirXT2PfoK/mIAVRUSwRWU/kcYAiQ9JHB0nA+8bs03x8I2Cna15KOzCWPRhtuDg
# yMkMX3i6HvCeV4bzguRyc8kLqhgODNRBjp8T6wbiR+lbALDJd/OrgE7xtF0ihbgE
# ejoaFFE/S+WktaZSeMPZ5+5JV3mCJjg2derM6+tXWmjn/ervv27MgtAs4Jk0en6G
# c04JRfPG47mjCC3/CJXHPOi+uakCqT/RIz4oebUIZ9QFdu2b4fU1HfwoytCNpnbp
# lQULygXHAJ6rvezX9W/CO48yN53Q2dZ2flpXBsSNQ/4/kwkPLCUH54R3AyiDPLRc
# kpRlhgFK0jRbVLj+GgLCkRIRsC6bCMY9/Lx/NOJu4giaflkEVE7IOpFFVIF3S/vq
# S9P+CPU2RTtlVrpdIZ118URMsJQyyZMk72Vrp9snry3NSl/6nh01KlqZexVrsC6G
# 5V/s4ZCtgWayXWNVWYF6cS65gIBt80c6Fb7i7oxcGqOGIiWLAgMBAAGjggIDMIIB
# /zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQUKzpQ
# x87KYiDMIZXuUEDMXLDpsOIwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggrBgEF
# BQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQEAwIH
# gDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmlu
# Z1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hB
# Mzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNB
# NDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQAD
# ggIBAAIiNo/ZUTZ375jyKBSpgeyGJ36cwgDulVTQ9Ux5KbVKXU/XAdh7tEsVOV31
# zaQDNauepMJzq+Kr8jtTQ23p4uMEeHSYnozs56OdQD26F40a+KL+6Ul+kxz5U5pT
# FuluZhpV9CrleEJTuoAforPgLu2r1X25qElZLUMlQ8jnlZWEww29d1In6VnW8Vll
# iXhVyAzkWUtobI7CuoCkf4ZHSaefWaGN18WMPtc4ciejQZ9YzrWkB0CCV1W9LvkA
# y0Dw99YV7GsRStFSmWtIcg7nJ/8uWEbKxvLNzc61XZWNO/YSVN0jNobPljQP0+Jl
# +FWoyoY0DG3oZSzj86MLiZ6QrGs7uZ55hcw+q6D40zKVV2D9IcUnDKpUYRJjKPK6
# /29QM1zph0NNoEr90J9LDYim/fH447MBetYlvuc2QKuQo8hHgM/fkp8cGikpOj9w
# 8O87PLpjp06adDYTQA7cUV7/uIhMekGU1cy50bXnvjtdtNeWED2ys8zObND4FXYh
# g3mMMGy3WMqLlZTk/zCkYPVN60itGZPQp5jmhe/SiNmEsy/OBVwQKIY8wdvZV4if
# vloIry2DKKmcpSRU/TrqXwxWEWizvSlUw7JRW4aS29x9pfew3w3Umj6DaReCFS3J
# kgdtA1T4ppg30H2TSq3E2vf6Mj7w6Oo1CnkPScHZrWElMHxwMYIaoTCCGp0CAQEw
# fTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNV
# BAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hB
# Mzg0IDIwMjEgQ0ExAhAOKNTaJjIAZ6j425z/NM/LMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIB8gQvVD
# ZFvh4au51ucc4WIvuI7xbUhohPqbHMd/WkCyMA0GCSqGSIb3DQEBAQUABIICABbn
# aAMrI2g3TtWGKCHHfolO8wvAm+aoRYIEnj/sCMdkvHOFjhsW/OXNErM/CMLUcQen
# qdmO+khUrPPMiFgqzNqhwIr1FProLZ/uyUa4BbvhoB1w75Oph0glITadAHq43wgl
# Y7ZjFltbq0l4bFfpDmLBlXnFpCLWOQYVE80nXcQZgEgRVnR351f+Mx5MCgXvPpXA
# bBANek8YgR5OwX+QBM+K6XFdKaz4uwX33IKCLmoe9qYmq5YdV9A1bMwEfM+3QyKK
# 9RZQgs/I33f4sQNLsq78VOXl40OcfLNUxEhGLxhT8g9t7cqWBuDdk23afLgwmHVI
# MKfYZobPEx0PSHZY80psWbSRcuCm3jmgl4eHRLTUYeTdf41mvLjhi5dolPS+hbeK
# nm01QSf8pWclAOvC2VbBwsPp2TkkppxodMUf3D1zuC3R2lmrT0mdb4KfWdwNWyVg
# 7TsNwTbqwsPbXJfruVaf9nT1/oi5OtWvXPrW4U2avtinHF409/0hrQEEuLGIzIJX
# J7j7DBIoF7Z3tS3/92wqkdzBu6rwJ1j0TJwBXBu0emJ/+ONuQPehNk0giHEE4D+f
# VVCGkq3jKNB4ljWpIscEK3f5qPfrrpMuYuyznGVivkvJggYhGH2/R9sboKmq/LKE
# rgWtV8/17mCd7aFGlgFiJpAkFaWvNgb3CA0bYAVwoYIXdzCCF3MGCisGAQQBgjcD
# AwExghdjMIIXXwYJKoZIhvcNAQcCoIIXUDCCF0wCAQMxDzANBglghkgBZQMEAgEF
# ADB4BgsqhkiG9w0BCRABBKBpBGcwZQIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUD
# BAIBBQAEIPvkqLXkL0n65dXGrmIsyK7AtFqITFBMDAmu5yXE7p9rAhEA+TiRVlE2
# mWucB+XiIHRIRhgPMjAyNjA3MzAyMzA1NDRaoIITOjCCBu0wggTVoAMCAQICEAqA
# 7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2
# MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQw
# OTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ
# 3xTWcfsLwOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqV
# Q+3bzWYesFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjo
# T1FpS54dNApZfKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R
# 0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6Un
# bksIcFJqLbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39
# iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0
# dVVZw7knh1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6ll
# N3QgshRta6Eq4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wg
# gn8O2klETsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmS
# F3voIgMFtNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwID
# AQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85Fx
# YxlQQ89hjOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0P
# AQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSB
# iDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsG
# AQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0f
# BFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1Ud
# IAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEA
# ZSqt8RwnBLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZ
# hY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/
# ciZmUnthfAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk
# 6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQ
# USntbjZ80FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdC
# G1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y5
# 8678IgmfORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V0
# 8X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1q
# mcwbdUfcSYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfY
# xJ7La54i71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhD
# Bf3Froguzzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcwgga0MIIEnKADAgECAhAN
# x6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAw
# MDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3Rh
# bXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMs
# VO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4
# kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8
# BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2
# Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwF
# t+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9o
# HRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq
# 6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+r
# x3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvU
# BDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl
# 9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwID
# AQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunk
# Bnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# DgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEB
# BGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsG
# AQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4H
# PRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qE
# JPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy
# 9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe
# 9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1U
# H410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6
# A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjs
# Yg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0
# vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/D
# Jbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHb
# xtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAP
# vIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv
# 21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcN
# MzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf
# 8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1
# mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe
# 7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecx
# y9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX
# 2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX
# 9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp49
# 3ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCq
# sWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFH
# dL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauG
# i0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYw
# DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# HwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGG
# MHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXn
# OF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23
# OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFI
# tJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7s
# pNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgi
# wbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cB
# qZ9Xql4o4rmUMYIDfDCCA3gCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGlt
# ZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAKgO8YS43xBYLRxHan
# lXRoMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAcBgkqhkiG9w0BCQUxDxcNMjYwNzMwMjMwNTQ0WjArBgsqhkiG9w0BCRACDDEc
# MBowGDAWBBTdYjCshgotMGvaOLFoeVIwB/tBfjAvBgkqhkiG9w0BCQQxIgQgktj1
# gAG00zJrCM3iOjqlXxaG8MtavXLufuTaNpzbyqcwNwYLKoZIhvcNAQkQAi8xKDAm
# MCQwIgQgSqA/oizXXITFXJOPgo5na5yuyrM/420mmqM08UYRCjMwDQYJKoZIhvcN
# AQEBBQAEggIAsjH4NurVBgwxzCQa+/3Yvq261nB42Gw9hlATDekLNT+kg8eksmRl
# sKfhqCVsY2gwQj6LPkfhyrYSkOIQw6s9RsZBdesHQ2wrWH6YqdvoGPIztAiijAiT
# X8+BRb14lMoa3eQxIxV7x5KnI9nWnKmUUB7jFGls/XI8zKLdex7EGXNew7SkuUMY
# F91YyZqg4rHnQ18qY8vjM+FCe/3wMuATHVZTEp3ccqwhALzEI3kMdHpl6r/bS07O
# pQ1Uwz1i1BXkIp1urBODqU2Kq9kK4ZcwdC1nMhdGGAntMg6vvfWWPyGAzqBg1p0E
# 4ieD/dsVt3kavpwXy3xsNcXJ0trIVm3U36MtmuZqxOyOShoLRHJWnzwwWU/rmnK4
# p9MTzbvFaeK5hAX3WzTrUWgtlvbn2Gt6Tg4GJyDwXaqUX6SzVqhsv9EuhHLpWr26
# G4pNY2WnnHK8U8FUf/YpgTo7hwWutlGulm/PUPcb4IQaS1N1PS4aq513Bek8EUNt
# WL+etpgXEzXwyRxbeYwHnMEPrRvdjFafdmu3DvFYNtzXrxfgKv0K/oEt7gMyX/mY
# wH+IqSAvn2o6297TE8yF77rCp9mQLu06/1JDfA20wFor6xsQU+jd1Ed46Oxu3lbT
# PjkwJmPGtuB2QTC52d2VhmSr+3hyti3yyQWzQSBT86+JYYhXLTCxG5A=
# SIG # End signature block
