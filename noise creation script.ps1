C:\windows\system32\wevtutil.exe epl Microsoft-Windows-Sysmon/Operational 'C:\Users\IEUser\Documents\noise_data.evtx'

$sysmon_log_path = 'C:\Users\IEUser\Documents\noise_data.evtx'

$logs = Analyse-Log -MaxEvents $([int32]::MaxValue) -path $sysmon_log_path -QueryID $(1..26+255) -raw
$column_names = $logs | %{$_.psobject.properties.name} | select -Unique
$column_names += "Injected"
$result = $logs | select $column_names -ErrorAction SilentlyContinue

$result | %{$_.injected = 'FALSE'}

$result | export-csv C:\Users\IEUser\Documents\noise.csv -NoTypeInformation