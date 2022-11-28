function Analyse-Log {

    <#
        .SYNOPSIS
            Analyse the specified log. Originally intended to aid customisation of Sysmon configuration. 
        .DESCRIPTION
            Essentially a syntactically simple wrapper for Wevtutil.
            Queries a local or remote event log, parsing the event data into searchable fields. 
            It provides the some of the functionality of Xpaths but without the complex syntax. 


        .PARAMETER TimePeriod
            Measured in hours. This has a default is 1 hour. 
            E.g. Analyse-Log -TimePeriod 12 -LogName Security

        .PARAMETER ComputerName
            The name of the computers you wish to query. The default is the current system. 
            E.g Analyse-Log -ComputerName AB12345 -Summary

        .PARAMETER QueryID
            The Event ID number you wish to query 
            E.g. Analyse-Log -QueryID 1

        .PARAMETER Summary
            Provides a brief summary of totals.
            E.g. Analyse-Log -TimePeriod 24 -Summary

        .PARAMETER SummaryDepth
            The log results are provided top first, by the number specified by this variable. Default is 10.
            E.g. Analyse-Log -QueryID 15 -SummaryDepth 5

        .PARAMETER LogName
            The log you wish to query. The default is Microsoft-Windows-Sysmon/Operational.
            E.g. Anaylse-Log -Logname Security -Summary

        .PARAMETER Field
            The name of the log line you wish to query.
            E.g. Analyse-Log -TimePeriod 24 -QueryId 1 -Field ParentImage

        .PARAMETER Value
            The specified value of the field you wish to search for. Must be used after Field
            E.g. Analyse-Log -TimePeriod 12 -QueryID 1 -Field Image -Value C:\Windows\System32\cmd.exe

        .PARAMETER FieldList
            Gives a list of all available fields for the Event ID specified by -QueryID
            E.g. -QueryID 1 -FieldList

        .PARAMETER Display
            This switch must be set if you wish to print out the full log. The default depth of 3 is used if it is not set.
            E.g. Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -Display

        .PARAMETER SubField
            For when you have selected logs matching a Field and Value pair but you do not want the full output
            E.g Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -SubField ParentImage,CommandLine -SummaryDepth 4 
               
        .PARAMETER Path
            Takes the log from the specified path rather than the local or a remote system.
            E.g. Analyse-Log -Path C:\Temp\logs.evtx -TimePeriod 12 -QueryID 1 -Field Image -Value C:\Windows\System32\cmd.exe 

        .PARAMETER Raw
            Outputs a PsCustomObject table containing all the data gathered, providing easy interface with other cmdlets. 
            E.g. Analyse-Log -TimePeriod 24 -QueryID $(1..25) -Raw

        .PARAMETER DisplayDepth
            Limits the printed out logs to the specified number. The Default is 3. 
            E.g. Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -Display -DisplayDepth 4
        

        .INPUTS
            None
        .OUTPUTS
            Tables of summarised data via Format-Table, or pased log output. 

                                      
        .EXAMPLE
        This will get a summary of the default logs (Sysmon) for the last 5 hours from the default computer (current machine) and output. 

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -Summary
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        [*] Number of events in the last 5 hours is: 970
        [*] IDs of events seen in last 5 hours

        Get Counts
        Id Message                                                                                                                            
        -- -------                                                                                                                            
         1 Process Create:...                                                                                                                 
         3 Network connection detected:...                                                                                                    
         4 Sysmon service state changed:...                                                                                                   
         5 Process terminated:...                                                                                                             
         6 Driver loaded:...                                                                                                                  
        11 File created:...                                                                                                                   
        12 Registry object added or deleted:...                                                                                               
        13 Registry value set:...                                                                                                             
        15 File stream created:...                                                                                                            


        Name Count Percent
        ---- ----- -------
        1      446 45.98% 
        11     356 36.70% 
        13     129 13.30% 
        3       11 1.13%  
        6       11 1.13%  
        5        7 0.72%  
        12       5 0.52%  
        15       4 0.41%  
        4        1 0.10%  
        
        .EXAMPLE
        You can list the Field names for any event that is within the captured logs

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -FieldList
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        The state of the current PowerShell instance is not valid for this operation.
        At line:0 char:0

        Field Names for Event ID 1
        Time
        ParentCommandLine
        Description
        CommandLine
        CurrentDirectory
        User
        Hashes
        Image
        UtcTime
        ProcessGuid
        Company
        IntegrityLevel
        EventID
        FileVersion
        Process Create
        RuleName
        Product
        LogonId
        ProcessId
        LogonGuid
        TerminalSessionId
        ParentProcessGuid
        ParentProcessId
        ParentImage

        .EXAMPLE
        From this point you may wish to drill down, here we can see a specific event ID selected, with the output limited to the top 5 results and showing only the Image field. 

        Multiple Field parameters may be specified  (or none at all for a full output)

        PS C:\WINDOWS\system32> Analyse-Log -TimePeriod 1 -QueryID 1 -SummaryDepth 5 -Field Image
        Image
        Summary for 
         Event ID:1 
         Field: Image

        Count Name                                                                                               
        ----- ----                                                                                               
            5 C:\Windows\System32\cmd.exe                                                                        
            4 C:\Windows\System32\sc.exe                                                                         
            3 C:\Windows\System32\icacls.exe                                                                     
            3 C:\Windows\System32\wbem\WmiPrvSE.exe                                                              
            2 C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe   

        .EXAMPLE
        You may then drill down further by looking for summaries of all other fields matching a specified Event ID and Field. In this case only 1 Field parameter should be specified. 

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*svchost.exe"
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
         Event ID:1 
         Field: Time

        Count Name               
        ----- ----               
            1 01/03/2021 12:29:00
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:32
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33
            1 01/03/2021 08:20:33


        Summary for 
         Event ID:1 
         Field: ParentCommandLine

        Count Name                            
        ----- ----                            
          111 C:\WINDOWS\system32\services.exe


        Summary for 
         Event ID:1 
         Field: Description

        Count Name                             
        ----- ----                             
          111 Host Process for Windows Services

          (output truncated ... )

        .EXAMPLE
        Here we can specify which SubFields we want displayed and to what depth (decided by the First N entries). 

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -SubField ParentImage,CommandLine -SummaryDepth 3
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
            Event ID:1 
            Field: ParentImage

        Count Name                                        
        ----- ----                                        
            17 C:\Program Files\Mozilla Firefox\firefox.exe
            2 C:\Program Files\Mozilla Firefox\updater.exe
            1 C:\Windows\explorer.exe                     


        Summary for 
            Event ID:1 
            Field: CommandLine

        Count Name                                                                                                                                            
        ----- ----                                                                                                                                            
            6 "C:\Program Files\Mozilla Firefox\firefox.exe"                                                                                                  
            1 "C:\Program Files\Mozilla Firefox\firefox.exe" 3184 tab                                                                                         
            1 "C:\Program Files\Mozilla Firefox\firefox.exe" 6372 tab  


        .EXAMPLE
        If you wish to display the full log/s matching a specific query you can do so in the following way

        PS C:\Users\User\Documents> Analyse-Log -TimePeriod 5 -QueryID 1 -Field Image -Value "*firefox.exe" -Display -DisplayDepth 4
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
         Event ID:1 
         Field: Time

        Name                           Value                                                                            
        ----                           -----                                                                            
        Time                           01/03/2021 13:25:52                                                              
        ParentCommandLine              "C:\Program Files\Mozilla Firefox\firefox.exe"                                   
        Description                    Firefox                                                                          
        CommandLine                    "C:\Program Files\Mozilla Firefox\firefox.exe" -contentproc --channel="16876.9...
        CurrentDirectory               C:\Program Files\Mozilla Firefox\                                                
        User                           user1                                                                 
        Hashes                         MD5=21754E43574EA7411AED6B3EA639F22D,SHA256=FDA4D66274A0D99C33B19A3FE565EB9225...
        Image                          C:\Program Files\Mozilla Firefox\firefox.exe                                     
        UtcTime                        2021-03-01 13:25:52.600                                                          
        ProcessGuid                    {bb437cb3-eb60-603c-0000-001019c81b0a}                                           
        Company                        Mozilla Corporation                                                              
        IntegrityLevel                 Low                                                                              
        EventID                        1                                                                                
        FileVersion                    86.0                                                                             
        Process Create                                                                                                  
        RuleName                                                                                                        
        Product                        Firefox                                                                          
        LogonId                        0x2EE27E                                                                         
        ProcessId                      17392                                                                            
        LogonGuid                      {bb437cb3-a410-603c-0000-00207ee22e00}                                           
        TerminalSessionId              1                                                                                
        ParentProcessGuid              {bb437cb3-a508-603c-0000-0010819fd100}                                           
        ParentProcessId                16876                                                                            
        ParentImage                    C:\Program Files\Mozilla Firefox\firefox.exe                                     
        -----------------------------------------
        Time                           01/03/2021 12:33:17                                                              
        ParentCommandLine              "C:\Program Files\Mozilla Firefox\firefox.exe"                                   
        Description                    Firefox                                                                          

        output truncated...

        .EXAMPLE
        To increase speed it is suggested you save remote logs using the -Save switch. This is demonstrated here. 

        PS C:\WINDOWS\system32> Analyse-Log -TimePeriod 4 -ComputerName LT12345 -Save
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        [!] There's no error handling here - beware dragons
        This will save to C:\Temp. Please specify a filename: Someones_logs
        [*] Phew, that seemed to work. :D

        .EXAMPLE
        To load a JSON file, such as that saved by the Save switch, you may do the following. This is the suggested way when working with remote logs. 
        
        PS C:\WINDOWS\system32> Analyse-Log -TimePeriod 12 -Load C:\temp\sysmon_logs.json -QueryID 1 -Field Image
        [*] Fetching logs ...
        [*] Logs fetched. Now analysing...
        Summary for 
         Event ID:1 
         Field: Image

        Count Name                                        
        ----- ----                                        
          108 C:\Windows\System32\svchost.exe             
          107 C:\Windows\System32\wevtutil.exe            
           28 C:\Windows\System32\PING.EXE                
           27 C:\Program Files\Mozilla Firefox\firefox.exe
           19 C:\Windows\System32\taskhostw.exe           
           10 C:\Windows\SysWOW64\cmd.exe                 
           10 C:\Windows\System32\dsregcmd.exe            
           10 C:\Windows\System32\cmd.exe                 
            8 C:\Windows\System32\msiexec.exe             
            7 C:\Windows\System32\gpupdate.exe 
            
            
        .EXAMPLE
        To search all logs (meaning every Event ID) for a specific field/value match:

        PS C:\WINDOWS\system32> Analyse-Log -TimePeriod 1 -QueryID $(1..26) -field image -value "*powershell.exe*"
        [*] Fetching logs ...
        [*] Logs fetched ...
        [*] Parsing logs...
        [*] Logs parsed. Now analysing...
        Summary for 
         Event ID:1 
         Field: IntegrityLevel

        Count Name  
        ----- ----  
            1 High  
            1 Medium


        Summary for 
         Event ID:1 
         Field: ParentCommandLine

        Count Name                   
        ----- ----                   
            2 C:\WINDOWS\Explorer.EXE

        .EXAMPLE
        To get a PSCustomObject as output, for ease of interfacing with other cmdlets. 

        PS C:\WINDOWS\system32> $alldata = Analyse-Log -TimePeriod 24 -QueryID $(1..25) -Raw
        [*] Fetching logs ...
        [*] Logs fetched ...
        [*] Parsing logs...
        [*] Repairing damaged XML...
        [*] Parsing logs...
        [*] Logs parsed. Now analysing...
        [*] Releasing raw output


#>

       [CmdletBinding()]
    Param (

        [Parameter(Mandatory = $false, Position = 0)]
        [Float] $TimePeriod, # needs an error message here

        [Parameter(Mandatory = $false, Position = 0)]
        [Int32] $MaxEvents,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $ComputerName = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, Position = 0)]
        [Array] $QueryID,# = $null, # testing this for the analysis function entry conditions

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $Summary,

        [Parameter(Mandatory = $false, Position = 0)]
        [Int32] $SummaryDepth = 10,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $Logname = "microsoft-windows-sysmon/operational",

        [Parameter(Mandatory = $false, Position = 0)]
        [Array] $Field,

        [Parameter(Mandatory = $false, Position = 0)]
        [String] $Value,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $FieldList,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $ShowBlanks,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $Display,

        [Parameter(Mandatory = $false, Position = 0)]
        [Array] $SubField,

        [Parameter(Mandatory = $false, Position = 0)]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $false, Position = 0)]
        [Switch] $Raw,

        [Parameter(Mandatory = $false, Position = 0)]
        [Int32] $DisplayDepth = 3

        )
    
    # Because this cmdlet tends to get run over and over in the same session we need to clear the variables or there will be blood
    $all_events = $null
    $Array_List = $null
    $broken_data = $null
    $final_data = $null
    $keys = $null

    # Local Variable, not intended for changing
    # Used to calculate time for XPath - takes 24 hours in milliseconds and breaks down into hours. Bit faffy but there you do
    [Int32]$Xpath_Time = (86400000/24)*$TimePeriod
    $XPath = "*[System[TimeCreated[timediff(@SystemTime) <= $Xpath_Time]]]"
    [System.Collections.ArrayList]$Array_List = @()
    [System.Collections.ArrayList]$broken_data = @();
    $Hashmah = @{} #yes I misspelled hashmap, no I didn't change it, yes it's a bad variable name either way 
    [System.Collections.ArrayList]$accumulated_raw_event_data = @()

    # Function to convert hashtable to powershell custom object
    function ConvertTo-Object($hashtable) 
    {
       $object = New-Object PSObject
       $hashtable.GetEnumerator() | 
          ForEach-Object { Add-Member -inputObject $object `
	  	    -memberType NoteProperty -name $_.Name -value $_.Value }
       $object
    }

    # Title: Log Collector
    # Purpose: Does the actual job of pulling the logs from the local or remote system
    # Method: Currently employs Get-WinEvent with time handled via XPaths. 
    # Issues: Will also need to test if requested time is larger than current time
    Write-Host "[*] Fetching logs ..."
    try {
        # This builds the command line for wevtutil. Each parameter must be done separately. Dunno why
        # This provides an example for building a command for another binary.
        $New_Path = $Path.FullName # manipulating the path object in situ wasn't working, did it here instead
        $all_events = C:\windows\system32\wevtutil.exe `
        qe `
        /r:$ComputerName `
        /rd:true `
        $(if ($Path) {"$New_Path"} else {"$Logname"}) `
        $(if ($Path) {"/lf:true"}) `
        $(if ($Xpath -and -not $Path) {"/q:$($Xpath)"}) `
        $(if ($MaxEvents) {"/c:$($MaxEvents)"}) 
        # could theoretically expand the efficiency by doing /q:"*[System[(EventID=$QueryID[0] or EventID=$QueryID[1])]]" etc here
    } catch {
        Write-Host "No matching logs found"
        Return
    }
    Write-Host "[*] Logs fetched ..."

    # Title: Log parser
    # Purpose: Parses all event objects into something searchable. 
    # Method: Breaks up each log entry into key:values pairs in a hashmap and stores them all in an arraylist
    function Parse-Log ($all_events_in_function) {
        Write-Host "[*] Parsing logs..."
            foreach ($event in $all_events_in_function) { 
           
            # =================
            # Convert Wevtutil XML string to Powershell XML object and error handling thereof
            try {
                # Convert event into XML event
                $xml_event = [XML]$event
            } catch {
                # new approach to fixing broken data. Gather broken stuff into a broken variable
                $broken_data.add($event) > $null
                continue # not doing anything with the broken data, just gathering it for now
            }

            # Declare new hashtable to be used - it has to be done in the loop
            $hash_table_of_individual_event = @{}

            # =================
            # System Section
            # The System bit is a little nested and not everything is useful, so we'll pull out specifics
            $system_data_holder = $xml_event.Event.System

            $hash_table_of_individual_event.add('EventID',$system_data_holder.EventID)
            $hash_table_of_individual_event.add('ThreadID',$system_data_holder.Execution.ThreadID)
            $hash_table_of_individual_event.add('UserID',$system_data_holder.Security.UserID)
            $hash_table_of_individual_event.add('Level',$system_data_holder.Level)
            $hash_table_of_individual_event.add('Computer',$system_data_holder.Computer)
            $hash_table_of_individual_event.add('Time',$system_data_holder.TimeCreated.SystemTime)
            $hash_table_of_individual_event.add('EventRecordID',$system_data_holder.EventRecordID)
           

            # ==================
            # Event Data Section
            # The event data is, arguably, all useful and not nested. 
            $eventdata = $xml_event.Event.EventData.Data

            foreach ($event_data_row in $Eventdata) {
                try{
                    $hash_table_of_individual_event.add($event_data_row.Name, $event_data_row.'#text')
                } catch {
                    #$event_data_row
                    # We'll sometimes come here if the eventdata can't be neatly segmented down into key value pairs by way of name:#text
                    # Handling this would probably be dealt with on a case by case basis and would take a lot of work
                    # The security log and sysmon don't ever come here, just windows powershell so far. 
                    # likewise Powershell/Operational is tricky as it contains scriptblocks.
                    Write-Host "I cannae do this, cap'n" -ForegroundColor DarkCyan
                    Return
                }
            }

            # =================
            # Add finished hashtable to array list
            
            $Array_List.Add($hash_table_of_individual_event) > $null 
              
        }
    }
    Parse-Log($all_events)

    # Title: XML Fixer
    # Purpose: wevtutil returns broken xml objects because ... who knows why, but here we are.
    # Method: iterate over broken xml fixing known issues
    function fix-xml ($broken_data) {
        Write-Host "[*] Repairing damaged XML..."
         # fix or remove things we know break XML -beware, if these things appear in the logs themselves they are also being replaced. 
         $broken_data = $broken_data -replace '<\?xml version="1\.0" encoding="UTF-16"\?>',""
         $broken_data = $broken_data -replace "&gt;",">"
         $broken_data = $broken_data -replace "&lt;","<" 

         # removed rogue data, now needs to be concatenated together right
         [System.Collections.ArrayList]$final_data = @()
         $object = ""

         foreach ($chunk in $broken_data) {
            if ($chunk -like "*</Event>*") { #if it's the end of the event we do something different
                $object += $chunk #cumulatively add last line of broken data to the object we'll input into the final result
                $final_data.Add($object) # input that final bit of data
                $object = "" # clear that object because we've reached the end of the event as per the </event> tag
            } else {
                $object += $chunk #comes here if it's not the end of the event, so just continue building the object
            }
         }

         return $final_data # this whole thing should return a string of XML structured data that can be converted now
    }

    # if there's noticably broken XML returned from wevtutil do this
    if ($broken_data){
        $final_data = fix-xml($broken_data)
        Parse-Log($final_data) # this function adds onto the arraylist without destroying it first, so it's safe to do this. 
    }


    # Title: Summary Generator
    # Purpose: To generate a brief summary of the log, getting all occuring event IDs and totals
    # Method: 
    function Generate_Summary {
        if ( $Summary -and -not $QueryID  ) {
            Write-Host "[*] Processing Summary"
           # Total logs
            Write-Host "[*] Number of events in the last $($TimePeriod) hours is:" $Array_List.Count

            # List unique values
            Write-Host "[*] IDs of events seen in last $($TimePeriod) hours"
            $print_event_IDs = $Array_List.EventID | Group-Object | Select -Property Count,Name,@{Name = 'Percent'; Expression = {($_.Count/$Array_List.Count).tostring("P") }} | Sort -Property count -Descending

            # Merge data with event IDs with the task. Pretty slow way of doing this. Refactor at some point. 
            $collection = @()
            
            # Way of getting event names - won't work if the manifest isn't present on this computer. Maybe better to
            # split this off into its own function and make it a little more complete e.g. will try local first and if not present will
            # try remote 
            try {
                $manifest_event_hash_table = @{}

                # remove channel from logname
                $Logname = $Logname -replace "\/.*",""

                $raw_publisher_data = get-winevent -listprovider $Logname -ErrorAction SilentlyContinue -ComputerName $ComputerName

                # if $foo.Events has no data, you need the publisher info from the log and repeat the above query with that
                if ($raw_publisher_data.Events) {
                    foreach ($event in ($raw_publisher_data.Events)) {
                        $manifest_event_id =  $event.id
                        $manifest_event_name = (($event.description -split "`n")[0] -split ":")[0] 
        
                        # skip key if already present - manifests contain multiple entries for the same ID

                        if ($manifest_event_hash_table.keys -contains $manifest_event_id) { continue }

                        # Add to dict
                        $manifest_event_hash_table.add($manifest_event_id,$manifest_event_name)
                    }
                } else { 
                    # Write-Host "CANT FETCH EVENT NAME"
                }
            } catch {
                $manifest_event_hash_table = @{}

            }
            # Build custom PS Object
            foreach ($line in $print_event_IDs) {
                if ($manifest_event_hash_table[[Int64]$line.Name]) {
                    $eventname = $manifest_event_hash_table[[Int64]$line.Name]
                } else {
                    $eventname = "..."
                }
                $collection += [pscustomobject] @{
                        EventID   = $line.Name
                        EventName = $eventname
                        EventCount = $line.Count
                        EventPercent = $line.Percent
                    }
            }

            $collection | Format-Table -AutoSize
        }
    }
    Generate_Summary
    
    # Title: Key parser
    # Purpose: To stop needing to repeatedly pull keys out we'll do it once and store 
    # Method: use pipeline to pull unique IDs. Iterate over, pulling keys from first match and adding to hashmap based on event ID. 
    $hashmap_of_event_keys_by_event_id = @{}
    $all_event_ids = $Array_List.EventID | Sort -Unique

    if ( $load ) {
        foreach ( $each_unique_id in $all_event_ids ){
           $keys_to_be_added = foreach ($property in ($Array_List | where {$_.EventID -eq $each_unique_id} | select -first 1 | Get-Member)) { if ($property.MemberType -eq "NoteProperty") { $property.Name } }
           $hashmap_of_event_keys_by_event_id.add([int32]$each_unique_id, $keys_to_be_added)
        }
    } else {
        foreach ( $each_unique_id in $all_event_ids ){
           $keys_to_be_added = ($Array_List | where {$_.EventID -eq $each_unique_id} | select -first 1).keys 
           $hashmap_of_event_keys_by_event_id.add([int32]$each_unique_id, $keys_to_be_added)
        }
    }

    # Title: List all field names
    # Purpose: Provides the user with a list of fields for a given event
    # Method: selects 1 matching event and loops over the hashmap keys. Cannot generate fields if event did not occur in time frame.
    function Generate_FieldList { 
        if ( $QueryID -and $FieldList ) {
            foreach ($ID_Queried in $QueryID) {
                Write-Host "`nField Names for Event ID $($ID_Queried)"
                $hashmap_of_event_keys_by_event_id[$ID_Queried]
            }
        }
    }
    Generate_FieldList

    # Title: Query Based Analysis - By Key (Field)
    # Purpose: Does the actual breakdow
    # Method: iterates over QueryID array, getting field names (or  using supplied ones) and displays the data based on that by iterating over the array list for matching keys.  
    if ( ($field -or $QueryID) -and -not $FieldList) {
        Write-Host "[*] Logs parsed. Now analysing..."
        foreach ($ID_Queried in $QueryID) {

            # Here we specify which keys (log fields) we want to display/show in the table

            # Do this if we're looking for a specific value in a field and only want a limited display
            if ( $Field -and $Value -and $SubField ) { $keys = $SubField }
            # Do this if we're looking for a specific field with any value
            if ( $Field -and -not $Value) { $keys = $Field }
            # come here if they've got a field and a value and just want all keys
            if ( $Field -and $Value -and -not $SubField) { $keys = $hashmap_of_event_keys_by_event_id[$ID_Queried] }
            # Come here if they just want all data for that queryID
            if (-not $Field) { $keys = $hashmap_of_event_keys_by_event_id[$ID_Queried] }
             # Come here if they're asking for a field and subfield with no values, is wrong. 
            if ( $Field -and $SubField -and -not $Value ) {Write-Host "Please also specify a Value. What you're asking for doesn't make sense" -ForegroundColor Cyan; Return }

            
            # I moved this out of the for loop below as it's not needed there
            if ($Value) {
                $specified_events = $Array_List | ? {$_.EventID -eq $ID_Queried} | ? $($field) -like $value
            } else {
                $specified_events = $Array_List | ? {$_.EventID -eq $ID_Queried}
            }
            

            # Now that we know what they're looking for, iterate over that and extract data from the hashtable
            foreach ($key in $keys) {
                   
                # This does the printing, and also handles subfield printing. 
                if ( $Display ) {
                    $events_to_display = $specified_events | Select-Object -first $DisplayDepth

                    foreach ($display_item in $events_to_display ) {
                        if ( $SubField ) {
                            foreach ( $subfield_to_print in $SubField ) {
                                $display_item.$subfield_to_print
                                Write-Host "-----------------------------------------"
                            }
                        } else {
                            $display_item
                            Write-Host "-----------------------------------------"
                        }
                    }
                        
                } else {
                    # This is so that we won't see empty fields, can make debugging painful so you may wish to remove it at those times. 
                    if (-not $specified_events -and -not $ShowBlanks) { continue }

                    if ($Raw) { continue } # trying to get a way to access the underlying object from outside the cmdlet

                    if (-not ($specified_events).$key) { Write-Host "Event ID:$ID_Queried has Field $Field and Value $Value, but has no $key field" -ForegroundColor DarkYellow; continue }

                    Write-Host "Summary for `n Event ID:$ID_Queried `n Field: $key"
                                                                                  
                    $output_table = ($specified_events).$key | Group-Object 
                    
                    # Do a Format switch here, which changes what comes out. 
                    # However, binding it 
                    $output_table | Sort-Object -Property Count -Descending | Select count,name -First $SummaryDepth | Format-table -wrap
                } 
                # You're in a loop here, if we don't return we'll display the logs repeatedly
                if ( $display ) { Return }

            } #END  foreach ($key in $keys)

            if ($Raw) {
                $accumulated_raw_event_data += $specified_events
            }

        } #END foreach ($ID_Queried in $QueryID) {

    } #END if ( ($field -or $QueryID -ne "") -and -not $FieldList
        
    if ($Raw) {
        Write-Host "[*] Releasing raw output"
        $hashtable_convert_to_pscustomobject = @() ;foreach($table in $accumulated_raw_event_data) { $hashtable_convert_to_pscustomobject += ConvertTo-Object($table) }
        return $hashtable_convert_to_pscustomobject
    }
} #END of script