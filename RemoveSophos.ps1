$ErrorActionPreference = 'SilentlyContinue'

# Stop Sophos services
# Write-Host "1. Stop all Sophos services"
Get-Service -DisplayName Sophos* | Set-Service -StartupType Disabled
Get-Service -DisplayName Sophos* | Stop-Service -Force

# Stop Sophos processes
# Write-Host "2. Stop all Sophos processes"
"ALMon", "ManagementAgentNT", "RouterNT", "swc_service", "SavService", "SAVAdminService", "Sophos Endpoint Defense Service", "SEDService",
"swi_service", "swi_filter", "SCFManager", "SophosNtpService", "SSPService" | ForEach-Object { Stop-Process -ProcessName $_ -Force }

# Remove Sophos executables
# Write-Host "3. Remove all Sophos executables"
Start-Process -FilePath ".\AVRemove.exe" -Verb RunAs
Start-Process -FilePath ".\SEDuninstall.exe" -Verb runAs

# Wait of Remove Sophos executables
# Write-Host "Start-Sleep -Seconds 10"
Start-Sleep -Seconds 10

# Uninstall Sophos products (not Nessesary if you Use AVRemove.exe and SEDuninstall.exe)
# Write-Host "4. Uninstall all Sophos products"
Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "Sophos*"} | ForEach-Object {
    $UninstallGUID = $_.IdentifyingNumber
    Start-Process -FilePath msiexec -ArgumentList @("/uninstall $UninstallGUID", "/quiet", "/norestart") -Wait
}

# Remove Sophos directories
# Write-Host "5. Remove all Sophos directories"
$foldersToDelete = @(
    "$env:ProgramFiles (x86)\Sophos",
    "$env:ProgramFiles (x86)\Common Files\Sophos",
    "$env:ProgramFiles\Sophos",
    "$env:ProgramFiles\Common Files\Sophos",
    "$env:ProgramData\Sophos",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos"
)

foreach ($folder in $foldersToDelete) {
    if (Test-Path -Path $folder -PathType Container) {
        Remove-Item -Path $folder -Recurse -Force
    }
}

# Delete Sophos services
# Write-Host "6. Delete all Sophos services"
Get-Service -DisplayName Sophos* | ForEach-Object { & "sc.exe" "delete" $_.Name }

# Remove Sophos registry entries (Critical)
# Write-Host "7. Remove all Sophos registry entries"
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Sophos" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Sophos" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Sophos" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SntpService" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Agent" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos AutoUpdate Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Client Firewall" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Client Firewall Manager" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos ELAM" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Message Router" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos System Protection Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Web Control Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SophosBootDriver" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swi_filter" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\swi_service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVService" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVAdminService" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Products\338C3CA1394DC06418F62DF6037FD93C" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Products\9009F1B458DC0C34CBDB4D1909D8A525" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Products\9B1ACBFAC6946EA489EAE31AFC6FC545" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Products\A2BF508A448AABC40888AC4680D7951E" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Products\D5001DEF8CBC5D542A88FF7CBB031412" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Features\338C3CA1394DC06418F62DF6037FD93C" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Features\9009F1B458DC0C34CBDB4D1909D8A525" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Features\9B1ACBFAC6946EA489EAE31AFC6FC545" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Features\A2BF508A448AABC40888AC4680D7951E" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\Features\D5001DEF8CBC5D542A88FF7CBB031412" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\UpgradeCodes\0D6888B32A8929940ACA98A3DEBB94B4" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\UpgradeCodes\82D9ADE749FF8CF439F889EBE1D3F767" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\UpgradeCodes\A2ECF5789F971654CBB5476964870E94" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\UpgradeCodes\D396FC6A171C5FD4EA9422B3666FA5A1" -Recurse -Force
Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\Installer\UpgradeCodes\E932B7952303A1943A2218777329E5A8" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\338C3CA1394DC06418F62DF6037FD93C" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\9009F1B458DC0C34CBDB4D1909D8A525" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\9B1ACBFAC6946EA489EAE31AFC6FC545" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\A2BF508A448AABC40888AC4680D7951E" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\D5001DEF8CBC5D542A88FF7CBB031412" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\338C3CA1394DC06418F62DF6037FD93C" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\9009F1B458DC0C34CBDB4D1909D8A525" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\9B1ACBFAC6946EA489EAE31AFC6FC545" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\A2BF508A448AABC40888AC4680D7951E" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\D5001DEF8CBC5D542A88FF7CBB031412" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\0D6888B32A8929940ACA98A3DEBB94B4" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\82D9ADE749FF8CF439F889EBE1D3F767" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\A2ECF5789F971654CBB5476964870E94" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\D396FC6A171C5FD4EA9422B3666FA5A1" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\E932B7952303A1943A2218777329E5A8" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\0D6888B32A8929940ACA98A3DEBB94B4" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\82D9ADE749FF8CF439F889EBE1D3F767" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\A2ECF5789F971654CBB5476964870E94" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\D396FC6A171C5FD4EA9422B3666FA5A1" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\E932B7952303A1943A2218777329E5A8" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\338C3CA1394DC06418F62DF6037FD93C" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\9009F1B458DC0C34CBDB4D1909D8A525" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\9B1ACBFAC6946EA489EAE31AFC6FC545" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\A2BF508A448AABC40888AC4680D7951E" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\D5001DEF8CBC5D542A88FF7CBB031412" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{4B1F9009-CD85-43C0-BCBD-D491908D5A52}" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sophos Endpoint Defense" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\Application\Sophos Anti-Virus" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\Application\Sophos Client Firewall" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\Application\Sophos Client Firewall Manager" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\Application\Sophos Message Router" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\Application\Sophos System Protection" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\Application\SophosAntiVirus" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\System\SAVOnAccess" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\System\SAVOnAccessControl" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\System\SAVOnAccessFilter" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SAVAdminService" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SAVOnAccess" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SAVService" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Agent" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos AutoUpdate Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Client Firewall" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Client Firewall Manager" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos ELAM" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Endpoint Defense" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Endpoint Defense Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Message Router" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos System Protection Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Web Control Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sophos Anti-Virus" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sophos Client Firewall" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sophos Client Firewall Manager" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sophos Message Router" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sophos System Protection" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\SophosAntiVirus" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\SAVOnAccess" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\SAVOnAccessControl" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\SAVOnAccessFilter" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVOnAccess" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVOnAccessControl" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVOnAccessFilter" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos-NetworkThreatProtection-Driver" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SophosBootDriver" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Agent" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos AutoUpdate Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Client Firewall" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Client Firewall Manager" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos ELAM" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Message Router" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos System Protection Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Web Control Service" -Recurse -Force
Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SophosBootDriver" -Recurse -Force

# Optional (Critical)
Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls" -Name "C:\Program Files\Sophos\Sophos Network Threat Protection\BPAIF.dll"
Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls" -Name "C:\Program Files\Sophos\Sophos Network Threat Protection\navl.dll"
Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls" -Name "C:\Windows\system32\msvcp120.dll"
Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls" -Name "C:\Windows\system32\msvcr120.dll"
Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls" -Name "C:\Windows\system32\vccorlib120.dll"

# Remove Sophos drivers
# Write-Host "8. Remove all Sophos drivers"
pnputil.exe -e | select-string "Sophos" | foreach-object { pnputil.exe -f -d $_.ToString().Split(":")[1].Trim() }
 
# Remove Sophos components from Windows Installer Cache (Critical)
# Write-Host "9. Remove all Sophos components from Windows Installer Cache"
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Sophos*" } | ForEach-Object { $_.Uninstall() }

# Deleting Sophos Accounts and Sophos Groups
# Write-Host "10. Deleting Sophos Accounts and Sophos Groups"
$userAccounts = Get-LocalUser | Where-Object { $_.Name -like "SophosSAUDESKTOP*" }
$userAccounts | ForEach-Object {
    if (Get-LocalUser -Name $_.Name -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $_.Name
    }
}

$groups = "SophosAdministrator", "SophosOnAccess", "SophosPowerUser", "SophosUser"
$groups | ForEach-Object {
    if (Get-LocalGroup -Name $_ -ErrorAction SilentlyContinue) {
        Remove-LocalGroup -Name $_
    }
}

# Optional: Remove Sophos residue (Visibility due to the termination of the Fileexplorer service) (Critical)
# Write-Host "11. Remove all Sophos residue"
# Get-Process | Where-Object {$_.Modules.FileName -eq "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\SavShellExtX64.dll"} | Stop-Process -Force
# Remove-Item "C:\Program Files (x86)\Sophos" -Recurse -Force
