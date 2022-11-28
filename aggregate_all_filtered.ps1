$all_results_sysmon_csvs = Get-ChildItem C:\Users\IEUser\Documents\Results | %{Join-Path -Path $_.fullName -childpath "sysmon.csv"}

$csv = $null

$all_results_sysmon_csvs | %{

    # consider pulling out which type of process injection was used and putting it as a column
    
    # get base folder name
    #$base_path = $_ -replace "\\sysmon.csv",""
    $csv_single = Import-csv $_

    $csv += $csv_single
}

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

$csv | %{

    # add in calltrace count
    $_.calltrace_count = ($_.calltrace.tochararray() -eq "|").count +1

    # add in unknown check
    $_.unknown_count = ($_.calltrace | select-string "unknown\(" -AllMatches).Matches.count

    # number of unique DLLs/exes in calltrace
    $_.unique_call_steps = ($_.calltrace -replace "\|","`n" -replace "\+.*","" -replace "\(.*","") -split "`n" | select -Unique | measure | select -ExpandProperty count

    # gets grantedaccess in decimal
    $_.decimal_grantedaccess = [uint32]$_.grantedaccess

    # Fix issues with 0s and 1s
    if ($_.injected -eq '1') {$_.injected = 'TRUE'} else {$_.injected = 'FALSE'}

}

$csv | select grantedaccess,"decimal_grantedaccess","unknown_count","calltrace_count","unique_call_steps",injected -ErrorAction SilentlyContinue| Export-csv $(join-path -path 'C:\Users\IEUser\Documents\Results' -ChildPath 'all_filtered_evid10_aggregated.csv') -NoTypeInformation

 