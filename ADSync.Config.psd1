@{
    # Example: Classification rules for user types
    # classificationRules = @{
    #     isServiceAccount = @{
    #         Groups       = @("Service Accounts")
    #         OUs          = @("OU=Service Accounts,DC=example,DC=com")
    #         NamePatterns = @("svc_*", "sa_*")
    #         Usernames    = @("svc_special")
    #     }
    #     isAdmin = @{
    #         Groups       = @("Domain Admins", "Enterprise Admins")
    #         OUs          = @("OU=Admins,DC=example,DC=com")
    #         NamePatterns = @("admin_*")
    #         Usernames    = @("Administrator")
    #     }
    #     isExecutive = @{
    #         Groups       = @("Executives")
    #         OUs          = @("OU=Executives,DC=example,DC=com")
    #         NamePatterns = @("exec_*")
    #         Usernames    = @("ceo", "cfo")
    #     }
    #     isExternalAccount = @{
    #         Groups       = @("External Users")
    #         OUs          = @("OU=External,DC=example,DC=com")
    #         NamePatterns = @("ext_*")
    #         Usernames    = @("contractor1")
    #     }
    # }

    # Example: Exclude specific attributes from sync (default full list)
    # excludedAttributes = @(
    #     "ntSecurityDescriptor",
    #     "PropertyNames",
    #     "userCertificate",
    #     "thumbnailPhoto",
    #     "msPKIAccountCredentials",
    #     "msExchSafeSendersHash",
    #     "msExchSafeRecipientsHash",
    #     "msPKIDPAPIMasterKey",
    #     "msExchBlockedSendersHash",
    #     "msExchUMDtmfMap",
    #     "msExchUMSpokenName",
    #     "logonHours",
    #     "userParameters",
    #     "unicodePwd",
    #     "dBCSPwd",
    #     "lmPwdHistory",
    #     "ntPwdHistory",
    #     "supplementalCredentials",
    #     "msDS-KeyCredentialLink",
    #     "memberOf",
    #     "mS-DS-ConsistencyGuid",
    #     "msExchMailboxGuid",
    #     "msExchMailboxSecurityDescriptor",
    #     "msExchMasterAccountSid",
    #     "msMqDigests",
    #     "terminalServer",
    #     "protocolSettings",
    #     "unixUserPassword"
    # )

    # Example: Only include these security groups in group membership uploads
    # specifiedGroups = @("Domain Admins", "HR", "Finance", "IT Support")

    # Example: Custom attribute mapping for userType
    # customAttributeMapping = @{
    #     AttributeName = "extensionAttribute1"
    #     ValueMappings = @{
    #         "contractor" = "external"
    #         "employee"   = "employee"
    #         "admin"      = "admin"
    #         "service"    = "service"
    #     }
    #     DefaultUserType = "employee"
    # }

    # Example: Include/exclude rules
    # includeRules = @{
    #     OUs          = @("OU=Active Users,DC=example,DC=com")
    #     NamePatterns = @("user_*")
    # }
    # excludeRules = @{
    #     OUs          = @("OU=Test Accounts,DC=example,DC=com")
    #     NamePatterns = @("test*", "temp*")
    # }
}