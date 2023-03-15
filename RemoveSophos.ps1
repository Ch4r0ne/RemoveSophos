Write-Host "Removal and cleanup of Sophos Endpoint Sophos Endpoint Security and Control version 10.8"

$ErrorActionPreference = 'SilentlyContinue'

# Stop Sophos services
Write-Host "1. Stop all Sophos services"
Get-Service -DisplayName Sophos* | Set-Service -StartupType Disabled
Get-Service -DisplayName Sophos* | Stop-Service -Force

# Stop Sophos processes
Write-Host "2. Stop all Sophos processes"
"ALMon", "ManagementAgentNT", "RouterNT", "swc_service", "SavService", "SAVAdminService", "Sophos Endpoint Defense Service", "SEDService",
"swi_service", "swi_filter", "SCFManager", "SophosNtpService", "SSPService" | ForEach-Object { Stop-Process -ProcessName $_ -Force }

# Uninstall Sophos products
Write-Host "3. Uninstall all Sophos products"
$programs = @(
    "Sophos Network Threat Protection",
    "Sophos System Protection",
    "Sophos Client Firewall",
    "Sophos Anti-Virus",
    "Sophos Remote Management System",
    "Sophos AutoUpdate",
    "Sophos Endpoint Defense"
)

foreach ($program in $programs) {
    $programVersion = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall |
        Get-ItemProperty |
        Where-Object {$_.DisplayName -match $program } |
        Select-Object -Property DisplayName, UninstallString

    foreach ($version in $programVersion) {
        if ($version.UninstallString) {
            $uninstallString = $version.UninstallString
            Start-Process cmd "/c $uninstallString /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow -Wait
        }
    }
}

# Remove Sophos directories
Write-Host "4. Remove all Sophos directories"
$foldersToDelete = @(
    "$env:ProgramFiles (x86)\Sophos",
    "$env:ProgramFiles (x86)\Common Files\Sophos",
    "$env:ProgramFiles\Sophos",
    "$env:ProgramFiles\Common Files\Sophos",
    "$env:ProgramData\Sophos",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos",
    "$env:SystemRoot\System32\SophosAV",
    "$env:SystemRoot\SysWOW64\SophosAV"
)

foreach ($folder in $foldersToDelete) {
    if (Test-Path -Path $folder -PathType Container) {
        Remove-Item -Path $folder -Recurse -Force
    }
}

# Remove Sophos registry entries (Critical)
Write-Host "5. Remove all Sophos registry entries"
Remove-Item -Path "HKLM:\SOFTWARE\Sophos" -Recurse -Force
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Sophos" -Recurse -Force

# Delete Sophos services
Write-Host "6. Delete all Sophos services"
Get-Service -DisplayName Sophos* | ForEach-Object { & "sc.exe" "delete" $_.Name }

# Deleting Sophos Accounts and Sophos Groups
Write-Host "7. Deleting Sophos Accounts and Sophos Groups"
$userAccounts = Get-LocalUser | Where-Object { $_.Name -like "SophosSAU*" }
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

# Notify the user to restart
Write-Host "8. Sophos is now uninstalled and removed"
Write-Host "Please reboot to complete the uninstallation completely"
