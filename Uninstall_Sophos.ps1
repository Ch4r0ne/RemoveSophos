$ErrorActionPreference = 'SilentlyContinue'

# Stop Sophos services
# Write-Host "#Stepp1 Stop Sophos services"
Get-Service -DisplayName Sophos* | Set-Service -StartupType Disabled
Get-Service -DisplayName Sophos* | Stop-Service -Force

# Stop Sophos processes
# Write-Host "Stop Sophos processes"
"ALMon", "ManagementAgentNT", "RouterNT", "swc_service", "SavService", "SAVAdminService", "Sophos Endpoint Defense Service", "SEDService",
"swi_service", "swi_filter", "SCFManager", "SophosNtpService", "SSPService" | ForEach-Object { Stop-Process -ProcessName $_ -Force }

# Remove Sophos executables
# Write-Host "Remove Sophos executables"
Start-Process -FilePath ".\AVRemove.exe" -Verb RunAs
Start-Process -FilePath ".\SEDuninstall.exe" -Verb runAs

# Wait of Remove Sophos executables
# Write-Host "Start-Sleep -Seconds 10"
Start-Sleep -Seconds 10

# Uninstall Sophos products (not Nessesary if you Use AVRemove.exe and SEDuninstall.exe)
# Write-Host "Uninstall Sophos products"
# Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "Sophos*"} | ForEach-Object {
#     $UninstallGUID = $_.IdentifyingNumber
#     Start-Process -FilePath msiexec -ArgumentList @("/uninstall $UninstallGUID", "/quiet", "/norestart") -Wait
# }

# Remove Sophos directories
# Write-Host "Remove Sophos directories"
$foldersToDelete = @(
    "$env:ProgramFiles (x86)\Sophos",
    "$env:ProgramFiles (x86)\Common Files\Sophos",
    "$env:ProgramFiles\Sophos",
    "$env:ProgramFiles\Common Files\Sophos",
    "$env:ProgramData\Sophos",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos"
)

C:\\Windows\\Installer\\{15C418EB-7675-42be-B2B3-281952DA014D}
C:\\Windows\\Installer\\{FED1005D-CBC8-45D5-A288-FFC7BB304121}
C:\\Windows\\Installer\\{9ACB414D-9347-40B6-A453-5EFB2DB59DFA}

foreach ($folder in $foldersToDelete) {
    if (Test-Path -Path $folder -PathType Container) {
        Remove-Item -Path $folder -Recurse -Force
    }
}

# Delete Sophos services
# Write-Host "Delete Sophos services"
Get-Service -DisplayName Sophos* | ForEach-Object { & "sc.exe" "delete" $_.Name }

# Remove Sophos registry entries (Critical)
# Write-Host "Remove Sophos registry entries"
Remove-Item -Path "HKLM:\SOFTWARE\Sophos" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SntpService" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Agent" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos AutoUpdate Service" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Client Firewall" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Client Firewall Manager" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos ELAM" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense Service" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Message Router" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos System Protection Service" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sophos Web Control Service" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SophosBootDriver" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\swi_filter" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\swi_service" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SAVService" -Recurse -Force
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SAVAdminService" -Recurse -Force

# Test
Remove-Item -Path "HKLM:\SOFTWARE\Sophos" -Recurse -Force
Remove-Item -Path "HKCU:\Software\Sophos" -Recurse -Force

HKEY_CURRENT_USER\Software\Sophos
HKEY_LOCAL_MACHINE\Software\Sophos

Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Products\338C3CA1394DC06418F62DF6037FD93C" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Products\9009F1B458DC0C34CBDB4D1909D8A525" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Products\9B1ACBFAC6946EA489EAE31AFC6FC545" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Products\A2BF508A448AABC40888AC4680D7951E" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Products\D5001DEF8CBC5D542A88FF7CBB031412" -Recurse -Force

Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Features\338C3CA1394DC06418F62DF6037FD93C" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Features\9009F1B458DC0C34CBDB4D1909D8A525" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Features\9B1ACBFAC6946EA489EAE31AFC6FC545" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Features\A2BF508A448AABC40888AC4680D7951E" -Recurse -Force
Remove-Item -Path "HKEY_CLASSES_ROOT\Installer\Features\D5001DEF8CBC5D542A88FF7CBB031412" -Recurse -Force

HKEY_CLASSES_ROOT\Installer\UpgradeCodes\0D6888B32A8929940ACA98A3DEBB94B4
HKEY_CLASSES_ROOT\Installer\UpgradeCodes\82D9ADE749FF8CF439F889EBE1D3F767
HKEY_CLASSES_ROOT\Installer\UpgradeCodes\A2ECF5789F971654CBB5476964870E94
HKEY_CLASSES_ROOT\Installer\UpgradeCodes\D396FC6A171C5FD4EA9422B3666FA5A1
HKEY_CLASSES_ROOT\Installer\UpgradeCodes\E932B7952303A1943A2218777329E5A8

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\338C3CA1394DC06418F62DF6037FD93C
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\9009F1B458DC0C34CBDB4D1909D8A525
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\9B1ACBFAC6946EA489EAE31AFC6FC545
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\A2BF508A448AABC40888AC4680D7951E
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\D5001DEF8CBC5D542A88FF7CBB031412

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\338C3CA1394DC06418F62DF6037FD93C
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\9009F1B458DC0C34CBDB4D1909D8A525
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\9B1ACBFAC6946EA489EAE31AFC6FC545
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\A2BF508A448AABC40888AC4680D7951E
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\D5001DEF8CBC5D542A88FF7CBB031412

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\0D6888B32A8929940ACA98A3DEBB94B4
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\82D9ADE749FF8CF439F889EBE1D3F767
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\A2ECF5789F971654CBB5476964870E94
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\D396FC6A171C5FD4EA9422B3666FA5A1
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\UpgradeCodes\E932B7952303A1943A2218777329E5A8

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\0D6888B32A8929940ACA98A3DEBB94B4
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\82D9ADE749FF8CF439F889EBE1D3F767
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\A2ECF5789F971654CBB5476964870E94
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\D396FC6A171C5FD4EA9422B3666FA5A1
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\E932B7952303A1943A2218777329E5A8

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\338C3CA1394DC06418F62DF6037FD93C
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\9009F1B458DC0C34CBDB4D1909D8A525
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\9B1ACBFAC6946EA489EAE31AFC6FC545
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\A2BF508A448AABC40888AC4680D7951E
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\D5001DEF8CBC5D542A88FF7CBB031412


HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{09C6BF52-6DBA-4A97-9939-B6C24E4738BF}
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{15C418EB-7675-42be-B2B3-281952DA014D}
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{C12953C2-4F15-4A6C-91BC-511B96AE2775}
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FF11005D-CBC8-45D5-A288-25C7BB304121}
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SAVADMINSERVICE
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SAVONACCESS_CONTROL
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SAVONACCESS_FILTER
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SAVSERVICE
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SOPHOS_AGENT
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SOPHOS_AUTOUPDATE_AGENT
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SOPHOS_AUTOUPDATE_SERVICE
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Enum\Root\LEGACY_SOPHOS_MESSAGE_ROUTER
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\Application\SophosAntiVirus
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\System\SAVOnAccess Control
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Eventlog\System\SAVOnAccess Filter
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SAVAdminService
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SAVOnAccess Control
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SAVOnAccess Filter
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SAVService
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Agent
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos AutoUpdate Agent
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos AutoUpdate Service
HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Sophos Message Router
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SAVADMINSERVICE
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SAVONACCESS_CONTROL
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SAVONACCESS_FILTER
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SOPHOS_AGENT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SAVSERVICE
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SOPHOS_AUTOUPDATE_AGENT
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SOPHOS_AUTOUPDATE_SERVICE
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\Root\LEGACY_SOPHOS_MESSAGE_ROUTER
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application\SophosAntiVirus
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\SAVOnAccess Control
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System\SAVOnAccess Filter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVAdminService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVOnAccess Control
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVOnAccess Filter
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SAVService
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Agent
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos AutoUpdate Agent
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos AutoUpdate Service
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Message Router
+HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls
+HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Remove Sophos drivers
# Write-Host "Remove Sophos drivers"
pnputil.exe -e | select-string "Sophos" | foreach-object { pnputil.exe -f -d $_.ToString().Split(":")[1].Trim() }
 
# Remove Sophos components from Windows Installer Cache (Critical)
# Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Sophos*" } | ForEach-Object { $_.Uninstall() }

# Deleting Sophos Accounts and Sophos Groups
Write-Host "Deleting Sophos Accounts and Sophos Groups"
$userAccounts = Get-LocalUser | Where-Object { $_.Name -like "SophosSAUDESKTOP*" }
foreach ($user in $userAccounts) {
    try {
        Remove-LocalUser -Name $user.Name -ErrorAction Stop > $null
    }
    catch {
        if ($_.Exception.Message -notmatch "The user account does not exist") {
            throw $_
        }
    }
}

$groups = "SophosAdministrator", "SophosOnAccess", "SophosPowerUser", "SophosUser"
foreach ($group in $groups) {
    try {
        Remove-LocalGroup -Name $group -ErrorAction Stop > $null
    }
    catch {
        if ($_.Exception.Message -notmatch "The group name could not be found") {
            throw $_
        }
    }
}

# Remove Sophos residue (Visibility due to the termination of the Fileexplorer service)
Get-Process | Where-Object {$_.Modules.FileName -eq "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\SavShellExtX64.dll"} | Stop-Process -Force
Remove-Item "C:\Program Files (x86)\Sophos" -Recurse -Force
