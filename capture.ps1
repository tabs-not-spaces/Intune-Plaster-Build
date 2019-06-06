[cmdletbinding()]
param (
    [string]$un,

    [string]$pw,

    [string]$tenantId
)
#region Config
$deviceConfigurationPath = "$PSScriptPath\Intune-Plaster-Build\templates\config-profiles"
$deviceCompliancePath = "$PSScriptPath\Intune-Plaster-Build\templates\compliance-policies"
$deviceScriptPath = "$PSScriptPath\Intune-Plaster-Build\templates\scripts"
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
        [string]$resourceURL
        ,
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
Function Get-DeviceManagementPolicy {
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        $authToken = $authheader,
        
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
        if ($managementType -eq "Script") {
            $response = @()
            $tmpRes = Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken -ContentType "application/json" | select-object value -ExpandProperty value
            foreach ($x in $tmpRes) {
                $response += Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/$graphApiVersion/$($graphEndpoint)/$($x.id)" -Headers $authToken -ContentType "application/json"
            }
            return $response
        }
        else {
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken -ContentType "application/json" | select-object value -ExpandProperty value
            if ($response) {
                Write-Host "Found $($response.count) objects"
                return $response
            }
            else {
                throw "Nothing returned.."
            }
        }
    }
    catch {
        $ex = $_.Exception
        Write-Warning $ex
        break
    }
}
#endregion
#region Unattended Authentication
$global:authParams = @{
    un       = $un
    pw       = $pw
    tenantId = $tenantId
    resource = "https://graph.microsoft.com"
    cId      = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
}
$global:authToken = Get-UnattendedAuth @authParams
$authHeader = @{ }
$authHeader.Authorization = "$($authToken.token_type) $($authToken.access_token)"
#endregion
$deviceConfiguration = Get-DeviceManagementPolicy -authToken $authHeader -managementType Configuration | Select-Object * -ExcludeProperty value
$deviceCompliance = Get-DeviceManagementPolicy -authToken $authHeader -managementType Compliance | Select-Object * -ExcludeProperty value
$scripts = Get-DeviceManagementPolicy -authToken $authHeader -managementType Script | Select-Object * -ExcludeProperty value

foreach ($d in $deviceConfiguration) {
    $d | Select-Object * -ExcludeProperty id, lastModifiedDateTime, roleScopeTagIds, supportsScopeTags, createdDateTime, version | ConvertTo-Json -Depth 100 | Out-File -FilePath "$configPath\$($d.displayName)`.json" -Encoding ascii -Force
}

foreach ($d in $deviceCompliance) {
    $d | Select-Object * -ExcludeProperty id, lastModifiedDateTime, roleScopeTagIds, supportsScopeTags, createdDateTime, version | ConvertTo-Json -Depth 100 | Out-File -FilePath "$compPath\$($d.displayName)`.json" -Encoding ascii -Force
}
foreach ($d in $scripts) {
        $tmpJson = $d | select-object '@odata.context', displayName, description, runAsAccount, enforceSignatureCheck, fileName, runAs32Bit;
        New-Item "$scriptPath\$($d.DisplayName)" -ItemType Directory -Force | Out-Null;
        $tmpJson | ConvertTo-Json -Depth 100 | Out-File -FilePath "$scriptPath\$($d.displayName)\$($d.displayName)`.json" -Encoding ascii -Force;
        [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String("$($d.scriptContent)")) | Out-File -FilePath "$scriptPath\$($d.displayName)\$($d.displayName)`.ps1" -Encoding ascii -Force;
}