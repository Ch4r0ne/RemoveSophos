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
