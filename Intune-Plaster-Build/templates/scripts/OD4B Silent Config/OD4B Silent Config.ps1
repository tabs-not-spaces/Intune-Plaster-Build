#region Config
$client = "<%=$PLASTER_PARAM_ClientName%>"
$appName = "OD4B_SilentConfig"
$scriptsPath = "$env:ProgramData\$client\Scripts"
$clientFQDN = "<%=$PLASTER_PARAM_ClientDomain%>"
$logPath = "`$env:ProgramData\`$client\logs"
#endregion
#region Env config
if (!(Test-Path $scriptsPath)) {
    New-Item -Path $scriptsPath -ItemType Directory -Force | Out-Null
}
#endregion
#region Main Process
$mainScript = @"
#region Config
`$AppName = "OneDriveConfig-EnableAutoConfig"
`$client = "$client"
`$clientFQDN = "$clientFQDN"
`$logPath = "$logPath"
`$logFile = "`$logPath\`$appName.log"
#endregion
#region Functions
function Set-RegistryValueForAllUsers {
    <#
    .SYNOPSIS
        This function uses Active Setup to create a "seeder" key which creates or modifies a user-based registry value
        for all users on a computer. If the key path doesn't exist to the value, it will automatically create the key and add the value.
    .EXAMPLE
        PS> Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = 'Setting'; 'Type' = 'String'; 'Value' = 'someval'; 'Path' = 'SOFTWARE\Microsoft\Windows\Something'}
        This example would modify the string registry value 'Type' in the path 'SOFTWARE\Microsoft\Windows\Something' to 'someval'
        for every user registry hive.
    .PARAMETER RegistryInstance
         A hash table containing key names of 'Name' designating the registry value name, 'Type' to designate the type
        of registry value which can be 'String,Binary,Dword,ExpandString or MultiString', 'Value' which is the value itself of the
        registry value and 'Path' designating the parent registry key the registry value is in.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = `$true)]
        [hashtable[]]`$RegistryInstance
    )
    try {
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        ## Change the registry values for the currently logged on user. Each logged on user SID is under HKEY_USERS
        `$LoggedOnSids = `$(Get-ChildItem HKU: | Where-Object { `$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+`$' } | foreach-object { `$_.Name })
        Write-Verbose "Found `$(`$LoggedOnSids.Count) logged on user SIDs"
        foreach (`$sid in `$LoggedOnSids) {
            Write-Verbose -Message "Loading the user registry hive for the logged on SID `$sid"
            foreach (`$instance in `$RegistryInstance) {
                ## Create the key path if it doesn't exist
                if (!(Test-Path "HKU:\`$sid\`$(`$instance.Path)")) {
                    New-Item -Path "HKU:\`$sid\`$(`$instance.Path | Split-Path -Parent)" -Name (`$instance.Path | Split-Path -Leaf) -Force | Out-Null
                }
                ## Create (or modify) the value specified in the param
                Set-ItemProperty -Path "HKU:\`$sid\`$(`$instance.Path)" -Name `$instance.Name -Value `$instance.Value -Type `$instance.Type -Force
            }
        }

        ## Create the Active Setup registry key so that the reg add cmd will get ran for each user
        ## logging into the machine.
        ## http://www.itninja.com/blog/view/an-active-setup-primer
        Write-Verbose "Setting Active Setup registry value to apply to all other users"
        foreach (`$instance in `$RegistryInstance) {
            ## Generate a unique value (usually a GUID) to use for Active Setup
            `$Guid = `$instance.Guid
            `$ActiveSetupRegParentPath = 'HKLM:\Software\Microsoft\Active Setup\Installed Components'
            ## Create the GUID registry key under the Active Setup key
            `$ActiveSetupRegPath = "HKLM:\Software\Microsoft\Active Setup\Installed Components\`$Guid"
            if (!(Test-Path -Path "`$ActiveSetupRegPath")) {
                New-Item -Path `$ActiveSetupRegParentPath -Name `$Guid -Force | Out-Null
            }
            Write-Verbose "Using registry path '`$ActiveSetupRegPath'"
            ## Convert the registry value type to one that reg.exe can understand.  This will be the
            ## type of value that's created for the value we want to set for all users
            switch (`$instance.Type) {
                'String' {
                    `$RegValueType = 'REG_SZ'
                }
                'Dword' {
                    `$RegValueType = 'REG_DWORD'
                }
                'Binary' {
                    `$RegValueType = 'REG_BINARY'
                }
                'ExpandString' {
                    `$RegValueType = 'REG_EXPAND_SZ'
                }
                'MultiString' {
                    `$RegValueType = 'REG_MULTI_SZ'
                }
                default {
                    throw "Registry type '`$(`$instance.Type)' not recognized"
                }
            }

            ## Build the registry value to use for Active Setup which is the command to create the registry value in all user hives
            `$ActiveSetupValue = 'reg add "{0}" /v {1} /t {2} /d {3} /f' -f "HKCU\`$(`$instance.Path)", `$instance.Name, `$RegValueType, `$instance.Value
            Write-Verbose -Message "Active setup value is '`$ActiveSetupValue'"
            ## Create the necessary Active Setup registry values
            Set-ItemProperty -Path `$ActiveSetupRegPath -Name '(Default)' -Value 'Active Setup Test' -Force
            Set-ItemProperty -Path `$ActiveSetupRegPath -Name 'Version' -Value '1' -Force
            Set-ItemProperty -Path `$ActiveSetupRegPath -Name 'StubPath' -Value `$ActiveSetupValue -Force
        }
    }
    catch {
        Throw -Message `$_.Exception.Message
    }
}
function Get-TenantIdFromDomain {
    param (
        [Parameter(Mandatory = `$true)]
        [string]`$FQDN
    )
    try {
        `$uri = "https://login.microsoftonline.com/`$(`$FQDN)/.well-known/openid-configuration"
        `$rest = Invoke-RestMethod -Method Get -UseBasicParsing -Uri `$uri
        if (`$rest.authorization_endpoint) {
            `$result = `$((`$rest.authorization_endpoint | Select-String '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}').Matches.Value)
            if (`$result -match '\w{8}-\w{4}-\w{4}-\w{4}-\w{12}') {
                return `$result
            }
            else {
                throw "Tenant ID not found."
            }
        }
        else {
            throw "Tenant ID not found."
        }
    }
    catch {
        throw `$_.Exception.Message
    }
}
#endregion
#region Logging
if (!(Test-Path -Path `$logPath)) {
    New-Item -Path `$logPath -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path `$logFile -ErrorAction SilentlyContinue -Force
#endregion
#region Main
try {
    #region Check for Office Installation
    if ((!(Get-Process -Name "OfficeClickToRun" -ErrorAction SilentlyContinue)) -or (Get-CimInstance Win32_Process -Filter "name = 'OfficeClickToRun.exe'" | Where-Object {`$_.CommandLine -ne '"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" /service'})) {
        #office setup is probably running, or office hasn't been installed yet.. let's drop out and try again in a few minutes..
        throw "Office 365 is installing or hasnt started installing - we will end this script and try again in a few minutes."
    }
    #endregion
    #region System Registry
    `$tenantId = Get-TenantIdFromDomain -FQDN `$clientFQDN
    `$regKeys = @(
        [PSCustomObject]@{
            Name  = "KFMBlockOptOut"
            Type  = "DWORD"
            Value = "1"
            Path  = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        }
        [PSCustomObject]@{
            Name  = "SilentAccountConfig"
            Type  = "DWORD"
            Value = "1"
            Path  = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        }
        [PSCustomObject]@{
            Name  = "FilesOnDemandEnabled"
            Type  = "DWORD"
            Value = "1"
            Path  = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        }
        [PSCustomObject]@{
            Name  = "KFMOptInWithWizard"
            Type  = "ExpandString"
            Value = `$tenantId
            Path  = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        }
        [PSCustomObject]@{
            Name  = "KFMSilentOptIn"
            Type  = "ExpandString"
            Value = `$tenantId
            Path  = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        }
        [PSCustomObject]@{
            Name  = "KFMSilentOptInWithNotification"
            Type  = "DWORD"
            Value = "0"
            Path  = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
        }
    )
    foreach (`$key in `$regKeys) {
        if (!(Test-Path `$key.Path)) {
            Write-Host "Registry path : `$(`$key.Path) not found. Creating now." -ForegroundColor Green
            New-Item -Path `$key.Path -Force | Out-Null
            Write-Host "Creating item property: `$(`$key.Name)" -ForegroundColor Green
            New-ItemProperty -Path `$key.Path -Name `$key.Name -Value `$key.Value -PropertyType `$key.Type -Force | Out-Null
        }
        else {
            Write-Host "Creating item property: `$(`$key.Name)" -ForegroundColor Green
            New-ItemProperty -Path `$key.Path -Name `$key.Name -Value `$key.Value -PropertyType `$key.Type -Force | Out-Null
        }
    }
    #endregion
    #region User Registry
    `$regKeys = @{
        Guid  = "{2F8FA12D-1C5E-483C-AA41-CEF357ADF6F6}"
        Name  = "EnableADAL"
        Type  = "DWORD"
        Value = "1"
        Path  = "SOFTWARE\Microsoft\OneDrive"
    }
    Write-Host "OneDrive - Enabling ADAL" -ForegroundColor Green
    Set-RegistryValueForAllUsers -RegistryInstance `$regKeys -Verbose
    #endregion
}
catch {
    `$errorMsg = `$_.Exception.Message
}
finally {
    if (`$errorMsg) {
        Write-Warning `$errorMsg
        Stop-Transcript
        Throw `$errorMsg
    }
    else {
        Write-Host "script completed successfully.."
        Unregister-ScheduledTask -TaskName "$appName" -Confirm:`$false
        Stop-Transcript
        Remove-Item `$MyInvocation.InvocationName -Force
    }
}
#endregion
"@
out-file -FilePath "$scriptsPath\$appName.ps1" -Encoding unicode -Force -InputObject $mainScript
#endregion
#region Scheduled Task Creation
$Time = New-ScheduledTaskTrigger `
    -Once `
    -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration (New-TimeSpan -Days (365 * 20))
$User = "SYSTEM"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ex bypass -file `"$scriptsPath\$appName.ps1`""
Register-ScheduledTask -TaskName "$appName" -Trigger $Time -User $User -Action $Action -Force
#endregion
