# Goes into the results folders and pulls out all the sysmon logs and aggregates them into one sheet

$all_results_sysmon_csvs = Get-ChildItem C:\Users\IEUser\Documents\Results -Directory | %{Join-Path -Path $_.fullName -childpath "sysmon.csv"}

$csv = $null

$all_results_sysmon_csvs | %{

    # consider pulling out which type of process injection was used and putting it as a colum
    $injection_type = $($_ -replace ".*\\Run-","" -replace "_.*","")

    # get base folder name
    #$base_path = $_ -replace "\\sysmon.csv",""
    $csv_single = Import-csv $_ 

    $column_names = $csv_single[0] | %{$_.psobject.properties.name} | select -Unique
    $column_names += "Injection_Type"

    # add in column called injection_type - get it from the filename
    $csv_single = $csv_single | select $column_names -ErrorAction SilentlyContinue
    $csv_single | %{$_.injection_type = $injection_type}

    # add in injection type to the rolling CSV data
    $csv += $csv_single

}

#get and add in noise from activity not involving injection
$noise = import-csv C:\Users\IEUser\Documents\noise.csv

# Add none to injection type for noise
$column_names = $noise[0] | %{$_.psobject.properties.name} | select -Unique
$column_names += "Injection_Type"

# add in column called injection_type - get it from the filename
$noise = $noise | select $column_names -ErrorAction SilentlyContinue
$noise | %{$_.injection_type = "none"}


# add data sets together
#$csv += $noise
# filter down to EVID 10s
#$csv = $csv | ?{$_.eventid -eq 10}

# get col names in variable
$column_names = $csv | %{$_.psobject.properties.name} | select -Unique
# list additional ones you want added
#$column_names += "unknown_count","calltrace_count","unique_call_steps","decimal_grantedaccess"
#get a csv with all those in it 
$csv = $csv | select $column_names -ErrorAction SilentlyContinue | Export-csv $(join-path -path 'C:\Users\IEUser\Documents\Results' -ChildPath 'all_aggregated_sysmon.csv') -NoTypeInformation
