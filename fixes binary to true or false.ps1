$all_results_sysmon_csvs = Get-ChildItem C:\Users\IEUser\Documents\Results | %{Join-Path -Path $_.fullName -childpath "filtered_EVID10.csv"}

$all_results_sysmon_csvs | %{

    $csv = import-csv $_;

    $csv | %{
        
        if ($_.injected -eq '1') {$_.injected = 'TRUE'} else {$_.injected = 'FALSE'}

    }

    $csv | Export-Csv $_ -NoTypeInformation
}