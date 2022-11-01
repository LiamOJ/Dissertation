#####################
# Select Experiment #
#####################

$experiment_selection = Read-Host "[?] Which experiment would you like to run?"

#$target_pid = Read-Host "[?] Enter PID of the target process"


###############
# Prepare Lab #
###############

# Create subfolder in results folder for storage

# remove known FP
Get-process ruby -erroraction SilentlyContinue | stop-process -force

$datetime = get-date -format 'Ddd_MM_yyyyTHH_mm_ss'

$foldername = "Experiment$($experiment_selection)_" + $datetime

$destination_folder = New-Item -Path C:\users\IEUser\Documents\Results\$($foldername) -ItemType Directory

# Clear Sysmon log
C:\windows\system32\wevtutil.exe cl Microsoft-Windows-Sysmon/Operational

# Clear Application log
C:\windows\system32\wevtutil.exe cl Application

Write-Host "[*] Preparing for run"


Write-Host "[*] Changing Sysmon config to trace"

# C:\windows\Sysmon.exe -c C:\temp\sysmonconfig-trace-noisy.xml

Write-Host "[*] Confirming Sysmon config"

$sysmon_config_file = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty configfile

$sysmon_config_file_hash = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty confighash

Write-Host "[*] Sysmon config: $sysmon_config_file`n[*] Sysmon config hash: $sysmon_config_file_hash"


Write-Host "[*] Confirming Service Status"

$sysmon_status = get-service sysmon | select -ExpandProperty status

$Auror_status = get-service aurora-agent | select -ExpandProperty status

if ($sysmon_status -eq "Running" -and $Auror_status -eq "Running") { 
    
    Write-Host "[*] Required services are running" 
    
    } else {
        
        Write-Host "[!] Required services not running. Aborting." -ForegroundColor Red
        return
    }

##################
# Deploy exploit #
##################

# might need to be cmdline - possibly a good idea to just comment them out as I go 
# If launching calc as part of exploit make sure to close them all at this point
# if a given process or PID is used save it to ensure accurate detection

# kill processes likely to be getting used for injection
get-process Calculator -ErrorAction SilentlyContinue | stop-process -force -ErrorAction SilentlyContinue
get-process notepad -ErrorAction SilentlyContinue | stop-process -force -ErrorAction SilentlyContinue

# sysmon change 
C:\windows\Sysmon.exe -c C:\temp\sysmonconfig-trace-noisy.xml 2> $null

# Experiment 1 - DLL Injection 
if ($experiment_selection -eq 1) {

    Write-Host "[*] Performing DLL Injection" -ForegroundColor Cyan

    C:\windows\syswow64\notepad.exe

    $target_pid = get-process notepad | select -ExpandProperty ID
    
    C:\Users\IEUser\Documents\Unmonitored\DLLInjection\RemoteDLLInjector32.exe $target_pid  C:\Users\IEUser\Documents\Unmonitored\DLLInjection\dll_spawns_calc_32.dll 

    $target_process_name = "notepad.exe"

}

# Experiment 2 - PE Injection
if ($experiment_selection -eq 2) {

    Write-Host "[*] Performing PE Injection" -ForegroundColor Cyan
    
    C:\windows\system32\notepad.exe

    $target_pid = get-process notepad | select -ExpandProperty ID

    cmd.exe /c C:\Users\IEUser\Documents\Unmonitored\PEInjection\runshc32.exe C:\Users\IEUser\Documents\Unmonitored\PEInjection\launches_calc_shellcode_32bit.txt $target_pid

    $target_process_name = "notepad.exe"
}

# Experiment 3 - Process Hollowing
if ($experiment_selection -eq 3) {
    
    Write-Host "[*] Performing Process Hollowing" -ForegroundColor Cyan

    # done as a job to prevent it hanging from spawnign a cmd.exe instance that holds. 
    Start-Job {C:\users\IEUser\Documents\Unmonitored\ProcessHollowing\ProcessHollowing.exe}

    Start-Sleep -Seconds 2

    $target_pid = get-injectedthread | select -ExpandProperty processId

    $target_process_name = "svchost.exe"
}

# Experiment 4 - Thread Execution Hijacking
if ($experiment_selection -eq 4) {
    
    Write-Host "[*] Performing Thread Hijacking" -ForegroundColor Cyan

    C:\windows\syswow64\notepad.exe

    $target_pid = get-process notepad | select -ExpandProperty ID

    # works best using a rev shell for a persistent process - remove the 1 to fix this btw
    start-job {C:\Users\IEUser\Documents\Unmonitored\ThreadHijacking\Thread-Hijacking1.exe $using:target_pid}

    $target_process_name = "notepad.exe"
}

#Experiment 5 - Hook Injection via SetWindowsHookEx
if ($experiment_selection -eq 5) {
    
    Write-Host "[*] Performing Hook Injection Via SetWindowsHookEx" -ForegroundColor Cyan

    # Prepare space
    #C:\windows\system32\notepad.exe

    #$target_pid = get-process notepad | select -ExpandProperty ID

    # Run Exploit
    explorer C:\Users\IEUser\Documents\Unmonitored\SetWindowsHookEx\SetWindowsHookExInjector.exe

    Start-Sleep -Seconds 2
    $target_pid = get-process conhost | select -ExpandProperty ID

    # Trigger the hook
    Start-Sleep -Seconds 3 # give the COM objects time to work
    $wsh = New-Object -ComObject wscript.shell
    $wsh.AppActivate('SetWindowsHookExInjector.exe')
    Start-Sleep -Seconds 1 # give the COM objects time to work
    $wsh.SendKeys('Exploit')
    $target_pid = get-process conhost | select -ExpandProperty ID

    $target_process_name = "conhost.exe"
    

}

#Experiment 6 - ProcessHerpaderping (replacing registry modification) 
if ($experiment_selection -eq 6) {
    
    Write-Host "[*] Performing ProcessHerpaderping" -ForegroundColor Cyan

    # Won't launch from ISE
    start-job {C:\Users\IEUser\Documents\Unmonitored\ProcessHerpaderping\ProcessHerpaderping.exe C:\Users\IEUser\Documents\Unmonitored\ProcessHerpaderping\shell-x64_stageless_9998.exe C:\Users\IEUser\Documents\Unmonitored\ProcessHerpaderping\notepad.exe C:\windows\system32\calc.exe}

    $target_pid = ""
    $limit = 1000

    Write-Host "[*] Ensure the Herpaderped process will hang or the scans won't work" -ForegroundColor Yellow
    do{
        $target_pid = get-process notepad -ErrorAction SilentlyContinue | select -ExpandProperty id # must match whatever the second argument is 
        $limit--
    } until ($target_pid -is [int] -or $limit -lt 0)

    $target_process_name = "notepad.exe"
}

# Sysmon Change back
C:\windows\Sysmon.exe -c C:\temp\sysmonconfig-export.xml 2>$null


#############################
# Conduct Detection Methods #
#############################

# run Get-InjectedThread.ps1
$Get_injectedthread_results = Get-InjectedThread

# run PE-Sieve against process
C:\Users\IEUser\Documents\Unmonitored\pe-sieve.exe.lnk /dir $destination_folder /pid $target_pid /data 5 /shellc /minidmp /threads /iat 3

# OSQuery - Gather some reasonable tables.
$process_table = cmd.exe /c osqueryi.exe "select * from processes where pid = $($target_pid);"

$parent_processes = cmd.exe /c osqueryi.exe "WITH target_procs AS (   SELECT * FROM processes WHERE pid = $($target_pid)  )  SELECT *  FROM (   WITH recursive parent_proc AS (   SELECT * FROM target_procs   UNION ALL   SELECT p.* FROM processes p JOIN parent_proc pp ON p.pid = pp.parent   WHERE pp.pid != pp.parent   ORDER BY pid    )   SELECT pid, parent, uid, name, path   FROM parent_proc  );"

$child_processes = cmd.exe /c osqueryi.exe "WITH target_procs AS (   SELECT * FROM processes WHERE pid = $($target_pid)  )  SELECT *   FROM (   WITH recursive child_proc AS (  	SELECT * from target_procs  	union ALL  	select p.* from processes p join child_proc pp on p.parent = pp.pid  	order by pid   )   SELECT pid, parent, uid, name, path   from child_proc  );"

$process_memory_map_table = cmd.exe /c osqueryi.exe "select * from process_memory_map where pid = $($target_pid);"


###################
# Collect Results #
###################

# export logs to a results folder with a time and date and exploit ran with config 

C:\windows\system32\wevtutil.exe epl Application "C:\users\IEUser\Documents\Results\$($foldername)\application.evtx"

C:\windows\system32\wevtutil.exe epl Microsoft-Windows-Sysmon/Operational "C:\users\IEUser\Documents\Results\$($foldername)\sysmon.evtx"

$Get_injectedthread_results > (join-path -path $destination_folder -ChildPath GIT.txt)

# No longer applicable, binary itself used to direct output
#$pesieve_results > (join-path -path $destination_folder -ChildPath PE-Sieve.txt)

$process_table > (Join-Path -Path $destination_folder -ChildPath process_table.txt)

$process_memory_map_table > (Join-Path -Path $destination_folder -ChildPath process_memory_map_table.txt)

$child_processes > (Join-Path -Path $destination_folder -ChildPath child_process_tree.txt)

$parent_processes > (Join-Path -Path $destination_folder -ChildPath parent_process_tree.txt)

############################
# Revert to previous state #
############################

# sysmon config on noise reduced state
# C:\windows\Sysmon.exe -c C:\temp\sysmonconfig-export.xml

Write-Host "[*] Confirming Sysmon config"

$sysmon_config_file = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty configfile

$sysmon_config_file_hash = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty confighash

Write-Host "[*] Sysmon config: $sysmon_config_file`n[*] Sysmon config hash: $sysmon_config_file_hash"

#######
# end #
#######

# Kill all remaining processes that were targetted 
foreach ($process_id in $target_pid) {
    Get-Process -Id $process_id | Stop-Process -force
    }

# Parse out Sysmon log into CSV for possible ML input
$sysmon_log_path = join-path -Path $destination_folder.fullname -ChildPath "sysmon.evtx"
$export_csv_path = Join-Path -Path $destination_folder.FullName -ChildPath "sysmon.csv"

$logs = Analyse-Log -MaxEvents $([int32]::MaxValue) -path $sysmon_log_path -QueryID $(1..26+255) -raw
$column_names = $logs | %{$_.psobject.properties.name} | select -Unique
$column_names += "Injected"
$result = $logs | select $column_names | sort time 
# automated attempt to mark the data as relating to the injected process or not - will require manual review
$result = $result | %{if ($_ -like $target_pid -or $_ -like $target_process_name){$_.injected = 1} else {$_.injected = 0}}

# Export CSV
$result | export-csv $export_csv_path -NoTypeInformation
