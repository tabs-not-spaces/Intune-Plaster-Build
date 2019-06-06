[cmdletbinding()]
param (
    [string]$un,

    [string]$pw,

    [string]$tenantId,

    [string]$yamlPath
)
Write-Host "Grabbing required modules.."
Install-Module -Name Powershell-Yaml -Scope CurrentUser -Force
install-module -Name Plaster -Scope CurrentUser -Force
#region Config
$config = get-content $yamlPath -raw | ConvertFrom-Yaml
$deviceConfigurationPath = "$PSScriptRoot\EUC-$($config.client)\configuration"
$deviceCompliancePath = "$PSScriptRoot\EUC-$($config.client)\compliance"
$deviceScriptPath = "$PSScriptRoot\EUC-$($config.client)\scripts"
$plasterTemplatePath = "$PSScriptRoot\Intune-Plaster-Build"
$projectDestination = "$PSScriptRoot"
#endregion
#region Functions
function Get-UnattendedAuth {
    param (
        [Parameter(mandatory = $true)]
        [string]$un,

        [Parameter(mandatory = $true)]
        [string]$pw,

        [Parameter(mandatory = $true)]
        [string]$cid,

        [Parameter(mandatory = $true)]
        [string]$resourceURL,
        [Parameter(mandatory = $true)]
        [string]$tenantId,

        [Parameter(mandatory = $false)]
        [string]$refresh

    )
    if ($refresh) {
        $body = @{
            resource      = $resourceURL
            client_id     = $cid
            grant_type    = "refresh_token"
            username      = $un
            scope         = "openid"
            password      = $pw
            refresh_token = $refresh
        }
    }
    else {
        $body = @{
            resource   = $resourceURL
            client_id  = $cid
            grant_type = "password"
            username   = $un
            scope      = "openid"
            password   = $pw
        }
    }
    $response = Invoke-RestMethod -Method post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/token" -Body $body
    return $response
}
Function Add-DeviceManagementPolicy {
    
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory)]
        $authToken,

        [Parameter(Mandatory)]
        $json,
        
        [Parameter(Mandatory)]
        [ValidateSet('Configuration', 'Compliance', 'Script')]
        [string]$managementType

    )
    switch ($managementType) {
        "Configuration" {
            $graphEndpoint = "deviceManagement/deviceConfigurations"
            break
        }
        "Compliance" {
            $graphEndpoint = "deviceManagement/deviceCompliancePolicies"
            break
        }
        "Script" {
            $graphEndpoint = "deviceManagement/deviceManagementScripts"
            break
        }
    }
    $graphApiVersion = "Beta"
    Write-Verbose "Resource: $graphEndpoint"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($graphEndpoint)"
    try {
        Write-Host "Posting $managementType policy.."
        $res = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $json -ContentType "application/json"
        return $res
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-Host
        break
    }
}
#endregion
try {
    #region Unattended Authentication
    $script:authParams = @{
        un       = $un
        pw       = $pw
        tenantId = $tenantId
        resource = "https://graph.microsoft.com"
        cId      = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    }
    Write-Host "Authenticating to Graph.."
    $script:authToken = Get-UnattendedAuth @authParams
    $authHeader = @{ }
    $authHeader.Authorization = "$($authToken.token_type) $($authToken.access_token)"
    #endregion
    #region Build profile modules from templates
    $params = @{
        ClientName          = $config.client
        ClientDomain        = $config.tenantDomain
        ConfigPolicy        = $(if ($config.configPolicies) { $true } else { $false })
        confBitlocker       = $(if ($config.configPolicies -contains "bitlocker") { $true } else { $false })
        confCorpBranding    = $(if ($config.configPolicies.corporateBranding) { $true } else { $false })
        desktopImageUrl     = $(if ($config.configPolicies.corporateBranding) { $config.configPolicies.corporateBranding.desktopImageUrl })
        lockscreenImageUrl  = $(if ($config.configPolicies.corporateBranding) { $config.configPolicies.corporateBranding.lockscreenImageUrl })
        confDevRestrictions = $(if ($config.configPolicies.deviceRestrictions) { $true } else { $false })
        homepageUrl         = $(if ($config.configPolicies.deviceRestrictions) { $config.configPolicies.deviceRestrictions.homepageUrl } else { " " })
        confEndProtection   = $(if ($config.configPolicies.endpointProtection) { $true } else { $false })
        corporateMsgTitle   = $(if ($config.configPolicies.endpointProtection) { $config.configPolicies.endpointProtection.corporateMsgTitle } else { " " })
        corporateMsgText    = $(if ($config.configPolicies.endpointProtection) { $config.configPolicies.endpointProtection.corporateMsgText } else { " " })
        CompliancePolicy    = $(if ($config.compliancePolicies) { $true } else { $false })
        compBitlocker       = $(if ($config.compliancePolicies -contains "bitlocker") { $true } else { $false })
        scriptTimezone      = $(if ($config.scripts -contains "timezone") { $true } else { $false })
        scriptbitlocker     = $(if ($config.scripts -contains "bitlocker") { $true } else { $false })
        scriptonedrive      = $(if ($config.scripts -contains "onedrive") { $true } else { $false })
        scriptwallpaperFix  = $(if ($config.scripts -contains "wallpaperFix") { $true } else { $false })
    }
    invoke-plaster -TemplatePath $plasterTemplatePath -DestinationPath $projectDestination @params -Force
    #endregion
    #region Upload profile modules to tenant..
    Write-Host "Uploading Device configuration profiles to Intune.."
    foreach ($x in (Get-ChildItem $deviceConfigurationPath)) {
        $tmpJson = $null
        $tmpJson = Get-Content $x.FullName -raw
        $result = Add-DeviceManagementPolicy -authToken $authHeader -json $tmpJson -managementType Configuration
        $result | ConvertTo-Yaml | Out-File -FilePath "$ENV:Temp\Configuration_$($x.Name -replace '.json','').yaml" -Encoding ascii
        $confLog = "$ENV:Temp\Configuration_$($x.Name -replace '.json','').yaml"
        Write-Output "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Device Configuration Profile - $($x.Name -replace '.json','');]$confLog"
    }
    Write-Host "Uploading Device compliance policies to Intune.."
    foreach ($x in (Get-ChildItem $deviceCompliancePath)) {
        $tmpJson = $null
        $tmpJson = Get-Content $x.FullName -raw
        $result = Add-DeviceManagementPolicy -authToken $authHeader -json $tmpJson -managementType Compliance
        $result | ConvertTo-Yaml | Out-File -FilePath "$ENV:Temp\Compliance_$($x.Name -replace '.json','').yaml" -Encoding ascii -Force
        $compLog = "$ENV:Temp\Compliance_$($x.Name -replace '.json','').yaml"
        Write-Output "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Device Compliance Policy - $($x.Name -replace '.json','');]$compLog           "
    }
    Write-Host "Uploading scripts to Intune.."
    foreach ($x in (Get-ChildItem $deviceScriptPath)) {
        $tmpJson = $null
        $tmpScript = $null
        $tmpEncScript = $null
        $tmpJson = Get-Content "$($x.FullName)\$($x.Name).json" -raw | ConvertFrom-Json
        $tmpScript = Get-Content "$($x.FullName)\$($x.Name).ps1" -raw
        $tmpEncScript = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("$tmpScript"))
        $tmpJson | Add-Member -MemberType NoteProperty -Name "scriptContent" -Value $tmpEncScript
        $result = Add-DeviceManagementPolicy -authToken $authHeader -json ($tmpJson | ConvertTo-Json -Depth 100) -managementType Script
        $result | ConvertTo-Yaml | Out-File -FilePath "$ENV:Temp\Script_$($x.Name -replace '.json','').yaml" -Encoding ascii -Force
        $scriptLog = "$ENV:Temp\Script_$($x.Name -replace '.json','').yaml"
        $scriptLogName = $x.Name | Split-Path
        Write-Output "##vso[task.addattachment type=Distributedtask.Core.Summary;name=Scripts - $($x.Name -replace '.json','');]$scriptLog"
    }
    #endregion
}
catch {
    Write-Warning $_
}
