#region Config
$AppName = "Set-WallpaperStyle"
$client = "<%=$PLASTER_PARAM_ClientName%>"
$logPath = "$env:ProgramData\$client\logs"
$logFile = "$logPath\$appName.log"
#endregion
#region Functions
function Set-ComputerRegistryValues {
    param (
        [Parameter(Mandatory = $true)]
        [array]$RegistryInstance
    )
    try {
        foreach ($key in $RegistryInstance) {
            $keyPath = "HKLM:\$($key.Path)"
            if (!(Test-Path $keyPath)) {
                Write-Host "Registry path : $keyPath not found. Creating now." -ForegroundColor Green
                New-Item -Path $key.Path -Force | Out-Null
                Write-Host "Creating item property: $($key.Name)" -ForegroundColor Green
                New-ItemProperty -Path $keyPath -Name $key.Name -Value $key.Value -PropertyType $key.Type -Force
            }
            else {
                Write-Host "Creating item property: $($key.Name)" -ForegroundColor Green
                New-ItemProperty -Path $keyPath -Name $key.Name -Value $key.Value -PropertyType $key.Type -Force
            }
        }
    }
    catch {
        Throw $_.Exception.Message
    }
}
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
        [Parameter(Mandatory = $true)]
        [array]$RegistryInstance
    )
    try {
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

        ## Change the registry values for the currently logged on user. Each logged on user SID is under HKEY_USERS
        $LoggedOnSids = $(Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | foreach-object { $_.Name })
        Write-Verbose "Found $($LoggedOnSids.Count) logged on user SIDs"
        foreach ($sid in $LoggedOnSids) {
            Write-Host "Loading the user registry hive for the logged on SID $sid"  -ForegroundColor Green
            foreach ($instance in $RegistryInstance) {
                ## Create the key path if it doesn't exist
                if (!(Test-Path "HKU:\$sid\$($instance.Path)")) {
                    New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force
                }
                ## Create (or modify) the value specified in the param
                Set-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -Type $instance.Type -Force
            }
        }

        ## Create the Active Setup registry key so that the reg add cmd will get ran for each user
        ## logging into the machine.
        ## http://www.itninja.com/blog/view/an-active-setup-primer
        Write-Host "Setting Active Setup registry value to apply to all other users" -ForegroundColor Green
        foreach ($instance in $RegistryInstance) {
            ## Generate a unique value (usually a GUID) to use for Active Setup
            $Guid = $instance.Guid
            $ActiveSetupRegParentPath = 'HKLM:\Software\Microsoft\Active Setup\Installed Components'
            ## Create the GUID registry key under the Active Setup key
            $ActiveSetupRegPath = "HKLM:\Software\Microsoft\Active Setup\Installed Components\$Guid"
            if (!(Test-Path -Path "$ActiveSetupRegPath")) {
                New-Item -Path $ActiveSetupRegParentPath -Name $Guid -Force
            }
            Write-Verbose "Using registry path '$ActiveSetupRegPath'"
            ## Convert the registry value type to one that reg.exe can understand.  This will be the
            ## type of value that's created for the value we want to set for all users
            switch ($instance.Type) {
                'String' {
                    $RegValueType = 'REG_SZ'
                }
                'Dword' {
                    $RegValueType = 'REG_DWORD'
                }
                'Binary' {
                    $RegValueType = 'REG_BINARY'
                }
                'ExpandString' {
                    $RegValueType = 'REG_EXPAND_SZ'
                }
                'MultiString' {
                    $RegValueType = 'REG_MULTI_SZ'
                }
                default {
                    throw "Registry type '$($instance.Type)' not recognized"
                }
            }

            ## Build the registry value to use for Active Setup which is the command to create the registry value in all user hives
            $ActiveSetupValue = "reg add `"{0}`" /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value
            Write-Verbose -Message "Active setup value is '$ActiveSetupValue'"
            ## Create the necessary Active Setup registry values
            Set-ItemProperty -Path $ActiveSetupRegPath -Name '(Default)' -Value 'Active Setup Test' -Force
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'Version' -Value '1' -Force
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'StubPath' -Value $ActiveSetupValue -Force
        }
    }
    catch {
        Throw -Message $_.Exception.Message
    }
}
#endregion
#region Logging
if (!(Test-Path -Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}
$errorOccurred = $false
Start-Transcript -Path $logFile -ErrorAction SilentlyContinue -Force
#endregion
#region Keys
$hklmKeys = $null

$hkcuKeys = @(
    [PSCustomObject]@{
        Guid  = "{687af3cf-7032-424a-8e5a-7ab17ee08a38}" #set a random guid for each property
        Name  = "WallpaperStyle"
        Type  = "String" #String, ExpandString, Binary, DWord, MultiString, QWord, Unknown
        Value = "6"
        Path  = "Control Panel\Desktop"
    }
)
#endregion
#region Process
try {
    if ($hklmKeys) {
        Write-Host "Seting HKLM registry keys.." -ForegroundColor Green
        Set-ComputerRegistryValues -RegistryInstance $hklmKeys
        Write-Host "========"
    }
    if ($hkcuKeys) {
        Write-Host "Seting HKCU registry keys.." -ForegroundColor Green
        Set-RegistryValueForAllUsers -RegistryInstance $hkcuKeys
        Write-Host "========"
    }
}
catch {
    $errorOccurred = $true
    throw $_.Exception.Message
}
finally {
    if (!($errorOccurred)) {
        Write-Host "Configuration completed successfully."
    }
    Stop-Transcript -ErrorAction SilentlyContinue
}
if (!($errorOccurred)) {
    Write-Host "Configuration completed successfully."
}
#endregion
