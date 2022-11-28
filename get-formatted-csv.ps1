$csv = import-csv .\filtered_evid10.csv | 
    select grantedaccess,
    @{Name="decimal_grantedaccess";Expression={[Int]$_.decimal_grantedaccess}},
    @{Name="unknown_count";Expression={[Int]$_.unknown_count}},
    @{name='calltrace_count';expression={[Int]$_.calltrace_count}},
    @{name='unique_call_steps';expression={[Int]$_.unique_call_steps}},
    injected