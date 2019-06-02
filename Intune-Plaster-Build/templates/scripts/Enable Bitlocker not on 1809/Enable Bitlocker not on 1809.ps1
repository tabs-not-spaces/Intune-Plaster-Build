[cmdletbinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OSDrive = $env:SystemDrive
)
#region Config
$targetVer = 17134
$osVer = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
$client = "<%=$PLASTER_PARAM_ClientName%>"
$logPath = "$ENV:ProgramData\$($client)\Logs"
$logFile = "$logPath\Bitlocker.log"
#endregion
#region Logging
if (!(Test-Path -Path $logPath)) {
    new-item -Path "$LogPath" -ItemType Directory -Force
}
Start-Transcript -Path "$logFile" -Force
#endregion
#region Main Process
Write-Host "Beginning Bitlocker configuration" -ForegroundColor Green
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    if ($osVer -gt $targetVer) {
        $skipRun = $true
        Throw "OS Version: $OSVer is higher than maximum target version: $targetVer`. We should be able to have bitlocker configured via Intune configuration policies, Skip set to: $skipRun"
    }
    $bdeProtect = Get-BitLockerVolume $OSDrive | Select-Object -Property VolumeStatus, ProtectionStatus
    if ($bdeProtect.VolumeStatus -eq "FullyDecrypted") {
        Write-Host "$OSDrive not currently encrypted. Will now attempt to encrypt" -ForegroundColor Green
        # Enable Bitlocker using TPM
        Enable-BitLocker -MountPoint $OSDrive  -TpmProtector -ErrorAction SilentlyContinue
        Enable-BitLocker -MountPoint $OSDrive  -RecoveryPasswordProtector

    }
    else {
        if (($bdeProtect.VolumeStatus -eq "FullyEncrypted") -and ($bdeProtect.ProtectionStatus -eq "Off")){
            Write-Host "$OSDrive is currently encrypted, however we may not have the key. So we will decrypt and start again." -ForegroundColor Yellow
            Disable-BitLocker -MountPoint $OSDrive
            while ($(Get-BitLockerVolume).EncryptionPercentage -ne 0) {
                Write-Host "Waiting for Bitlocker decryption to complete"
                Start-Sleep -Seconds 2
            }
            Write-Host "Bitlocker turned off. Now starting again."
            Enable-BitLocker -MountPoint $OSDrive  -TpmProtector -ErrorAction SilentlyContinue
            Enable-BitLocker -MountPoint $OSDrive  -RecoveryPasswordProtector
        }
    }    
    if ((Get-BitLockerVolume -MountPoint $OSDrive).KeyProtector) {
        Write-Host "Encryption key found. Will store in log folder." -ForegroundColor Green
        New-Item -ItemType Directory -Force -Path "$logPath" | out-null
        (Get-BitLockerVolume -MountPoint $OSDrive).KeyProtector   | Out-File "$logPath\$($env:computername)_BitlockerRecoveryPassword.txt"
    }
    else {
        Write-Host "No bitlocker key found. Will error out" -ForegroundColor Red
        throw 
    }
    Write-Host "Check if we can use BackupToAAD-BitLockerKeyProtector commandlet" -ForegroundColor Green
    $cmdName = "BackupToAAD-BitLockerKeyProtector"
    if (Get-Command $cmdName -ErrorAction SilentlyContinue) {
        Write-Host "BackupToAAD-BitLockerKeyProtector commandlet exists" -ForegroundColor Green
        $BLV = Get-BitLockerVolume -MountPoint $OSDrive | Select-Object *
        BackupToAAD-BitLockerKeyProtector -MountPoint $OSDrive -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
    }
    else { 

        Write-Host "BackupToAAD-BitLockerKeyProtector commandlet not available, using other mechanism" -ForegroundColor Green
        Write-Host "Get the AAD Machine Certificate" -ForegroundColor Green
        $cert = Get-ChildItem Cert:\LocalMachine\My\ | Where-Object { $_.Issuer -match "CN=MS-Organization-Access" }

        Write-Host "Obtain the AAD Device ID from the certificate" -ForegroundColor Green
        $id = $cert.Subject.Replace("CN=", "")

        Write-Host "Get the tenant name from the registry" -ForegroundColor Green
        $tenant = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\$($id)).UserEmail.Split('@')[1]

        Write-Host "Generate the body to send to AAD containing the recovery information" -ForegroundColor Green
        Write-Host "Get the BitLocker key information from WMI" -ForegroundColor Green
        (Get-BitLockerVolume -MountPoint $OSDrive).KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'} | ForEach-Object {
            $key = $_
            write-verbose "kid : $($key.KeyProtectorId) key: $($key.RecoveryPassword)"
            $body = "{""key"":""$($key.RecoveryPassword)"",""kid"":""$($key.KeyProtectorId.replace('{','').Replace('}',''))"",""vol"":""OSV""}"
				
            Write-Host "Create the URL to post the data to based on the tenant and device information" -ForegroundColor Green
            $url = "https://enterpriseregistration.windows.net/manage/$tenant/device/$($id)?api-version=1.0"
				
            Write-Host "Post the data to the URL and sign it with the AAD Machine Certificate" -ForegroundColor Green
            $req = Invoke-WebRequest -Uri $url -Body $body -UseBasicParsing -Method Post -UseDefaultCredentials -Certificate $cert
            $req.RawContent
        }
    }
    #>
    
}
catch {
    if ($skipRun = $true) {
        Write-Host "OS Version is higher than 1803 and should be able to have bitlocker configured via Intune configuration policies, thus we will skip this script."
    }
    else {
        $errorMsg = "Error while setting up AAD Bitlocker, make sure that you are AAD joined and are running the cmdlet as an admin: $_"
    }
}
finally {
    if ($erroMsg) {
        Write-Warning $errorMsg
        Stop-Transcript
        Throw $errorMsg
    }
    else {
        Write-Host "Script completed successfully"
        Stop-Transcript
    }
}
#endregion

