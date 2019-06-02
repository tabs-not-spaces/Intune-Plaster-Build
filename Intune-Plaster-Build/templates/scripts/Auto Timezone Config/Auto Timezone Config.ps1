#region Config
$AppName = "Set_AutoDetect_Timezone"
$client = "<%=$PLASTER_PARAM_ClientName%>"
$logPath = "$env:ProgramData\$client\logs"
$logFile = "$logPath\$appName.log"
#endregion
#region Logging
if (!(Test-Path -Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path $logFile -Force
#endregion
#region Main Process
try {
    $regKeys = @(
        [PSCustomObject]@{
            Path  = "HKLM:\System\CurrentControlSet\Services\tzautoupdate"
            Name  = "Start"
            value = "3"
        }
        )
        foreach ($key in $regKeys) {
        Write-Host "Setting Timezone Auto Update in registry.." -ForegroundColor Green
        if (!(Test-Path $($key.Path))) {
            Write-Host "Registry path not found. Creating now." -ForegroundColor Green
            New-Item -Path $($key.Path) -Force | Out-Null
            Write-Host "Creating item property." -ForegroundColor Green
            New-ItemProperty -Path $($key.Path) -Name $($key.Name) -Value $($key.value) -PropertyType DWORD -Force | Out-Null
        }
        else {
            Write-Host "Registry path found." -ForegroundColor Green
            Write-Host "Creating item property." -ForegroundColor Green
            New-ItemProperty -Path $($key.Path) -Name $($key.Name) -Value $($key.value) -PropertyType DWORD -Force | Out-Null
        }
    }
}
catch {
    $errorMsg = $_.Exception.Message
}
finally {
    if ($errorMsg) {
        Write-Warning $errorMsg
        Stop-Transcript
        throw $errorMsg
    }
    else {
        Write-Host "Script completed successfully.."
        Stop-Transcript
    }
}
#endregion
