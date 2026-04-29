@{
    # Configuration settings for Active Directory synchronization
    #
    # Commented-out examples are provided for customization
    # Refer to the documentation for details on each setting
    # Customize any settings as needed for your environment
    # Uncomment the lines (remove the leading #) to enable them

    # Example: Specify a domain controller to connect to (optional)
    # domainController = "dc01.corp.example.com"

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
    #     isAgentic = @{
    #         Groups       = @("Agentic Accounts")
    #         OUs          = @("OU=Agentic,DC=example,DC=com")
    #         NamePatterns = @("agentic_*", "bot_*", "auto_*")
    #         Usernames    = @("agentic_bot")
    #     }
    # }

    # Example: Add more attributes to exclude (these are appended to the default internal list)
    # additionalExcludedAttributes = @(
    #     "jpegPhoto",
    #     "msDS-CloudExtensions"
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

    # Example: Specify the attribute that refers to the person responsible for an account
    # This is useful where NHI accounts are managed by someone else.
    # accountOwnerAttribute = "extensionAttribute2"

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