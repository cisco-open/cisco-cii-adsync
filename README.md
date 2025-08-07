# Active Directory PowerShell Script for Cisco Identity Intelligence

This repository contains the open-source PowerShell script designed to integrate your on-premises Active Directory (AD) with Cisco Identity Intelligence (CII). This solution provides comprehensive visibility into your AD, enabling you to detect and address identity-based risks.

## Table of Contents
- [Project Description](#project-description)
- [Architecture Overview](#architecture-overview)
- [Key Features](#key-features)
- [Installation and Setup](#installation-and-setup)
- [Execution Instructions](#execution-instructions)
- [Customization and Configuration](#customization-and-configuration)
- [Protecting API Credentials](#protecting-api-credentials)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [License](#license)

## Project Description

Active Directory remains a critical component for over 80% of enterprises, yet it is a frequent target for identity-based attacks. The Active Directory PowerShell script for Cisco Identity Intelligence addresses the visibility gaps in identity environments by providing a unified view of your on-prem AD data within CII.

This lightweight, open-source PowerShell script securely collects user and group object data from your Active Directory, transferring it to Cisco Identity Intelligence via API. This integration allows for:
*   Full visibility into all AD accounts (human and service) merged with other identity data sources.
*   Actionable posture insights, including detection of inactive users, guest accounts, and password hygiene issues.


## Architecture Overview

The solution leverages PowerShell scripts to act as a data collector and a secure bridge between your Active Directory environment and Cisco Identity Intelligence. It consists of two scripts: a one-time setup script to configure credentials, and the main script for collecting and transferring data. 

1.  **Initial Setup (CII AD Provision)**: The provision script takes your downloaded CII API credentials (in plain text) and encrypts them into a machine-specific configuration file. This file is then used by the main sync script.
2.  **Data Collection (CII AD Sync)**: The main PowerShell script runs on a designated server within your network, querying Active Directory for user and group object data.
3.  **Secure Transfer**: The collected data is securely transferred to Cisco Identity Intelligence via an API, utilizing the SCIM (System for Cross-domain Identity Management) protocol (RFC 7642-4).
4.  **Data Ingestion and Processing**: Cisco Identity Intelligence ingests, processes and analyzes the AD data, merging it with other identity sources to provide comprehensive insights.

**Key Architectural Benefits:**
*   **Agentless**: No agent installation is required on your AD domain controllers or other servers.
*   **Standardized**: Utilizes the IETF SCIM standard, simplifying firewall configurations and security justifications.
*   **Scalable**: Designed for efficient data collection and transfer.

## Key Features

*   **Comprehensive AD Inventory**: Seamlessly merge all AD accounts (human and service) into your Cisco Identity Intelligence inventory.
*   **Posture Insights**: Detect inactive users, guest accounts, and password hygiene issues across your on-prem AD.
*   **Easy Onboarding**: Lightweight, open-source PowerShell scripts for secure data collection and setup.
*   **No Agent Required**: Simplifies deployment and reduces overhead.
*   **Secure Credential Handling**: The CII AD `Provision` script encrypts API client ID and secret for machine-wide use, locking down key files with ACLs and preventing portability to other machines.
*   **Nested Group Resolution**: Automatically resolves nested group memberships for accurate visibility.
*   **Preview Mode**: Test your script configuration and view collected data before sending it to CII.
*   **Attribute Filtering**: Tailor the script to fetch only specific attributes based on your organizational needs.
*   **User Classification**: Define rules to classify users as service accounts, administrators, executives, etc.
*   **User Filtering**: Include/exclude users based on OUs, naming patterns, or explicit lists.
*   **Progress Tracking**: Periodic progress report with ETA and processing rates.

## Installation and Setup

To get started with the Active Directory integration with Cisco Identity Intelligence, follow these steps:

1.  **Download the Scripts and Credentials**:
    *   In Cisco Identity Intelligence UI, go to "Integrations", click "Add Integration", choose "Active Directory".
    *   Follow the steps in the UI to generate the credentials and download them using the `Download json` button.
    *   Download the script package in this repository (a zip file containing CII AD `Provision.ps1` and `ADSync.ps1`).
    *   We recommend you create a dedicated directory on your chosen server for these files.

2.  **Choose a Host Machine**:
    *   The scripts can be run on *any member server* with connectivity to your Active Directory domain. It is not necessary to run them directly on a Domain Controller. 
    *   The machine should have network connectivity to Cisco Identity Intelligence API endpoints
    *   PowerShell 5.1 or later and the Active Directory PowerShell module (RSAT-AD-PowerShell) should be installed.

3.  **User Account Permissions**:
    *   The user account running the script (or under which the scheduled task will run) must have **read access** to Active Directory. This does not require a privileged domain administrator account; most standard user accounts have sufficient read permissions.

4.  **Run the Provision Script (One-Time Setup)**:
    *   Execute the CII AD `Provision.ps1` script once on the chosen host machine.
    *   This script will take your downloaded plain-text credentials file (e.g., `cii-ad-<integration_name>-config.json`), validate them by attempting to get a token from the CII API, check if the AD service is enabled in CII, and then make an encrypted configuration file and key file.
    *   This encrypted configuration file is designed to be used by any user account (with sufficient read access) on that specific machine but is not portable to other machines.

> Example:
> ```powershell
> .\Provision.ps1 -InputConfigPath .\cisco-cii-AD-config.json
> Checking your config file .\cisco-cii-AD-config.json
> Config verification successful
> Created key file .\cisco-cii-AD-encryption.key
> Created encrypted config file .\cisco-cii-AD-encrypted-config.json
> You can now use these with the ADSync script (copied to clipboard)
> e.g.
>         .\ADSync.ps1 -KeyFilePath .\cisco-cii-AD-encryption.key -ConfigFilePath .\cisco-cii-AD-encrypted-config.json
> 
> The original config file can now be deleted
> Delete the original config file? (Y/N): y
> Original config file deleted
> Provisioning script completed successfully
> ```

5.  **Delete File with Original Credentials (Recommended)**:
    *   After successful provisioning, the original plain-text credentials file is no longer needed. It is recommended to delete this file from your system for security reasons, as you can always download it again from the CII UI if required.  The Provision script will ask to delete this file for you once it has completed.

## Execution Instructions

Once installed and configured, you can run the CII `ADSync.ps1` script to collect and send AD data to Cisco Identity Intelligence.

1.  **Preview Mode (Recommended for Testing)**:
    Before performing a full data transfer, it is highly recommended to run the script in "preview mode." This mode allows you to see exactly what data would be sent to Cisco Identity Intelligence without actually sending it. The script will generate a local file (e.g., `ad-preview-YYYYMMDD-HHMMSS.jsonl`) containing the collected user data.

    To activate preview mode, include the `-Preview` parameter when executing the script.

> ```powershell
> .\ADSync.ps1 -KeyFilePath .\your-encryption.key -ConfigFilePath .\your-encrypted-config.json -Preview
> ```

2.  **Review Customizations**:
    Based on the preview output, you may want to customize what the script collects and classifies.  Refer to the _Customization and Configuration_ section below.

3.  **Run the Sync Script**:
    Once you have made any script customizations and are content with the data to be uploaded, execute the CII `ADSync.ps1` script. This will initiate the data collection from your Active Directory and its transfer to Cisco Identity Intelligence.

> ```powershell
> .\ADSync.ps1 -KeyFilePath .\your-encryption.key -ConfigFilePath .\your-encrypted-config.json
> ```

4.  **Scheduling**:
    For continuous visibility and up-to-date data, it is recommended to schedule the CII `ADSync.ps1` script to run periodically using Windows Task Scheduler or your preferred automation tool. The script is designed to be efficient and can be run alongside other scheduled scripts. We recommend running it once in 24 hours.

5.  **Output and Logging**:
    The script will provide output indicating its progress, including validation steps, data collection, and transfer status. For successful operations, you will receive a summary of how many users were uploaded. In case of errors, specific error messages will be displayed on-screen as well as in the log called `ADSync.log`.

> ```powershell
> .\ADSync.ps1 -KeyFilePath .\cisco-cii-AD-encryption.key -ConfigFilePath .\cisco-cii-AD-encrypted-config.json
> Connected to Active Directory: DC=acme,DC=com
> There are 10015 users in this domain
> 
> === Processing Summary ===
> Total Users Evaluated: 10015
> Users Processed: 15
> Users Skipped: 10000
> Total Time: 00:00:51
> Average Rate: 193.18 users/sec
> ADSync completed at: 2025-08-04 09:25:25
> ```

## Customization and Configuration

The CII `ADSync.ps1` script is highly customizable to fit your specific Active Directory environment and Cisco Identity Intelligence requirements. These configurations are made within the script file.

*   **Attribute Filtering**:
    You can configure which Active Directory attributes to exclude to control the data sent to CII. The script includes a list of excluded attributes where you can add any properties you do not wish to be collected.

> ```powershell
> $script:excludedAttributes = @(
>     "ntSecurityDescriptor",
>     "userCertificate",
>     "thumbnailPhoto",
>     "unicodePwd",
>     "ntPwdHistory"
>     # Add more attributes as needed
> )
> ```

*   **User Classification Rules**:
    You can define rules within the script to classify users *before* ingestion into Cisco Identity Intelligence. This allows you to categorize users as Service Accounts, Admins, or Special Accounts (Executives). You can configure these classifications using four methods:

    1.  **Active Directory Group Membership**: Classify users based on their membership in specific AD groups.
    2.  **Organizational Unit (OU) Membership**: Classify users based on the Organizational Unit they reside in. 
    3.  **Name Patterns**: Use patterns (e.g., prefixes like `svc_`) in usernames for classification.
    4.  **Explicit User Lists**: Provide a list of specific usernames for custom classification.

    You can leave these classification rules blank if you do not wish to use them for a specific category. The script has a few default rules for common built-in groups.

> ```powershell
> $script:classificationRules = @{
>     isServiceAccount = @{
>         Groups       = @("Service Accounts", "SQL Service Accounts")
>         OUs          = @("OU=Service Accounts,DC=acme,DC=com")
>         NamePatterns = @("svc_*", "sa_*")
>         Usernames    = @("svc_special", "krbtgt")
>     }
>     isAdmin = @{
>         Groups       = @("Domain Admins", "Enterprise Admins", "Administrators")
>         OUs          = @()
>         NamePatterns = @()
>         Usernames    = @("Administrator", "it_admin")
>     }
>     isExecutive = @{
>         Groups       = @("Executives", "Board Members")
>         OUs          = @("OU=Executive OU,DC=acme,DC=com")
>         NamePatterns = @()
>         Usernames    = @("ceo", "cfo")
>     }
> }
> ```

*   **User Population - Alternative Base**:
    By default, the script will attempt to sync all users in the detected primary domain. You can modify this behavior in two ways. By using the -BaseDN parameter you can limit the sync to users in a specific OU.

> ```powershell
> .\ADSync.ps1 -KeyFilePath .\encryption.key -ConfigFilePath .\config.json -BaseDN "OU=Users,DC=company,DC=com"
> ```

*   **User Population - Rule Based**:
    Alternatively, you can configure the `includeRules` and `excludeRules` in the script to either include or exclude users based on their OU membership or naming convention.
 
> ```powershell
> # Include only users matching these criteria (empty = include all)
> $script:includeRules = @{
>     OUs          = @()  # e.g., @("OU=Active Users,DC=acme,DC=com")
>     NamePatterns = @()  # e.g., @("emp_*", "contractor_*")
> }
> 
> # Exclude users matching these criteria
> $script:excludeRules = @{
>     OUs          = @("OU=Terminated,DC=acme,DC=com")
>     NamePatterns = @("testuser*", "temp*")
> }
> ```

## Protecting API Credentials

Security is paramount. The script implements robust measures to protect your Cisco Identity Intelligence API credentials:

*   **One-time Provisioning**: Credentials are set up once using the CII AD `Provision` script and then encrypted.
*   **Encryption**: Client ID and Secret are encrypted at rest within a machine-specific configuration file.
*   **ACL Lock Down**: The key file containing encrypted credentials is secured with Access Control Lists (ACLs) to restrict unauthorized access.
*   **Off-box Prevention**: The encrypted credentials cannot be used from a different machine, enhancing security by preventing simple file copying for compromise.

## Troubleshooting

*   **Eror about Not Digitally Signed**: Cisco is in the process of digitally signing these PowerShell scripts.  If you have an early release you may encounter this error if you AD domain blocks running scripts that are not signed.  As a temporary workaround you can use this command to allow the unsigned script to run in the PowerShell session:
```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
*   **Check Logs**: The scripts will generate logs detailing their operations, including any errors or warnings. Consult these logs first for any issues encountered during execution.

| Log filename | Created By | Notes |
|--------------|------------|-------|
| `Provision.log` | `Provision.ps1` | Provision script log file - check this for provisioning errors |
| `ADSync.log` | `ADSync.ps1` | ADSync script log file - check this for AD sync issues |

*   **Preview Mode**: Utilize the preview mode (as described in Execution Instructions) to diagnose issues related to data collection, attribute filtering, or user classification without affecting your live CII environment. This allows you to inspect the data before it's sent.
*   **Connectivity**: permit the server to contact the CII cloud service. 
*   **Permissions**: Ensure the user account running the script has sufficient read permissions within Active Directory to access the necessary user and group objects.

For more in-depth troubleshooting, refer to the official documentation or reach out to Cisco support.

## Data Processing and UI update

After data is successfully sent from the PowerShell script to Cisco Identity Intelligence, it undergoes several processing and analysis stages before becoming fully visible in the UI. This processing ensures the data is integrated and analyzed to provide comprehensive insights. For the initial data collection, it is recommended to allow up to 24 hours for the data to fully populate and be reflected in the Cisco Identity Intelligence UI.

## Documentation

*   [Cisco Identity Intelligence Official Documentation](https://www.cisco.com/go/cii-docs)
*   [SCIM (System for Cross-domain Identity Management) RFC 7642-4](https://datatracker.ietf.org/doc/html/rfc7642)

## License

Licensed under the Apache License, Version 2.0. See the script header for full license text.

---

For additional support and documentation, visit: https://docs.oort.io/integrations

