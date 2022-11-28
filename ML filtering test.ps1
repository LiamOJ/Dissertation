$all_results_sysmon_csvs = Get-ChildItem C:\Users\IEUser\Documents\Results | %{Join-Path -Path $_.fullName -childpath "sysmon.csv"}

$all_results_sysmon_csvs | %{
    
    # get base folder name
    $base_path = $_ -replace "\\sysmon.csv",""
    $csv = Import-csv $_
    #get and add in noise from activity not involving injection
    $noise = import-csv C:\Users\IEUser\Documents\noise.csv
    # add data sets together
    $csv += $noise
    # filter down to EVID 10s
    $csv = $csv | ?{$_.eventid -eq 10}

    # get col names in variable
    $column_names = $csv | %{$_.psobject.properties.name} | select -Unique
    # list additional ones you want added
    $column_names += "unknown_count","calltrace_count","unique_call_steps","decimal_grantedaccess"
    #get a csv with all those in it 
    $csv = $csv | select $column_names -ErrorAction SilentlyContinue

    $csv | ?{$_.eventid -eq 10} | %{

        # add in calltrace count
        $_.calltrace_count = ($_.calltrace.tochararray() -eq "|").count +1

        # add in unknown check
        $_.unknown_count = ($_.calltrace | select-string "unknown\(" -AllMatches).Matches.count

        # number of unique DLLs/exes in calltrace
        $_.unique_call_steps = ($_.calltrace -replace "\|","`n" -replace "\+.*","" -replace "\(.*","") -split "`n" | select -Unique | measure | select -ExpandProperty count

        # gets grantedaccess in decimal
        $_.decimal_grantedaccess = [uint32]$_.grantedaccess

    }

    $csv | select grantedaccess,"decimal_grantedaccess","unknown_count","calltrace_count","unique_call_steps",injected -ErrorAction SilentlyContinue| Export-csv $(join-path -path $base_path -ChildPath 'filtered_evid10.csv') -NoTypeInformation

}

$all_results_sysmon_csvs = Get-ChildItem C:\Users\IEUser\Documents\Results | %{Join-Path -Path $_.fullName -childpath "filtered_EVID10.csv"}

$all_results_sysmon_csvs | %{

    $csv = import-csv $_;

    $csv | %{
        
        if ($_.injected -eq '1') {$_.injected = 'TRUE'} else {$_.injected = 'FALSE'}

    }

    $csv | Export-Csv $_ -NoTypeInformation
}