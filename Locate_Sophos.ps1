Get-WmiObject Win32_Service | Where-Object {$_.DisplayName -like "Sophos*"} | ForEach-Object {
    $Process = Get-WmiObject Win32_Process -Filter "ProcessId = $($_.ProcessId) AND CommandLine LIKE '%Sophos%'" | Select-Object -First 1
    if ($Process) {
        New-Object PSObject -Property @{
            "Service Name" = $_.DisplayName
            "Process Name" = $Process.Name
            "Status" = $_.Status
            "Start Mode" = $_.StartMode
            "Description" = $_.Description
        }
    }
} | Format-Table -AutoSize


$services = Get-Service -DisplayName Sophos*
$processes = Get-WmiObject Win32_Process | Where-Object {$_.CommandLine -like "*Sophos*"}

$keys = @()
foreach ($service in $services) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
    $keys += Get-Item -Path $key
}
$keys
