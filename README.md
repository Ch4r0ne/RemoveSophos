# Removing Sophos Endpoint Security from Windows
Uninstall Sophos Endpoint Sophos Endpoint Security and Control Version 10.8

- Sophos AutoUpdate Service
- Sophos Agent
- Sophos Message Router
- Sophos Web Control Service
- Sophos Anti-Virus
- Sophos Anti-Virus Statusreporter
- Sophos Web Intelligence Service
- Sophos Web Filter
- Sophos Client Firewall Manager
- Sophos Client Firewall
- Sophos Network Threat Protection
- Sophos System Protection Service

## Requirements
To uninstall the Sophos Endpoint Defense Service, you need SEDuninstall.exe. This can be found in the Install_Sophos.exe file. Extract the installation file using a zip program and locate SEDuninstall.exe. Optionally, you can also find 'AVRemove.exe' and add it to the path where 'Uninstall_Sophos.ps1' is located.

## Usage

This script is dynamic and can therefore probably also uninstall all versions, only for the "Sophos Endpoint Defense Service" the requirements must be met.

    1. Download the script to the computer you want to remove Sophos Endpoint Security from.
    2. Note: SEDuninstall.exe and AVRemove.exe should be in the same path as the script.
    3. Open PowerShell as an administrator.
    4. Navigate to the directory where the script is located.
    5. Run the script by typing the name of the script and pressing Enter.
    6. Wait for the script to finish. This may take several minutes.
    7. Reboot the system
        
## This PowerShell script is designed to remove Sophos Endpoint Security from a Windows computer. It performs the following actions:

1. Stops all Sophos services
2. Stops all Sophos processes
3. Removes all Sophos executables
4. Uninstalls all Sophos products
5. Deletes all Sophos directories
6. Deletes all Sophos services
7. Deletes all Sophos registry entries
8. Remove all Sophos drivers
9. Remove all Sophos components from Windows Installer Cache
10. Deleting all Sophos Accounts and Sophos Groups
11. Optional: Remove Sophos residue

## Disclaimer
This script is provided "as is" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. The author and publisher of this script are not responsible for any damages resulting from its use or misuse. Use at your own risk.

## Known residues
- "C:\Program Files (x86)\Sophos\Sophos Anti-Virus\SavShellExtX64.dll" (File still there and also still locked)

