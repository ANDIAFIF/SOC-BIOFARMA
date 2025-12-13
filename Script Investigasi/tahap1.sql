union isfuzzy=true
(
    DeviceProcessEvents
    | where TimeGenerated between (startofday(now()) .. now())
    | where DeviceName has_any ("sbcs-laptop16","sbcs-pc38","sbcs-laptop10","sbcs-laptop04",
                                "sbcs-laptop19","sbcs-pc34","sbcs-laptop01","sbcs-laptop20","sbcs-laptop05")
    | where ProcessCommandLine has_any ("oserver3_x64.exe", "OReportServer3_x64.exe", "OMailRpt.exe", "msiexec.exe /V")
    | project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
),
(
    DeviceImageLoadEvents
    | where TimeGenerated between (startofday(now()) .. now())
    | where DeviceName has_any ("sbcs-laptop16","sbcs-pc38","sbcs-laptop10","sbcs-laptop04",
                                "sbcs-laptop19","sbcs-pc34","sbcs-laptop01","sbcs-laptop20","sbcs-laptop05")
    | where InitiatingProcessCommandLine has_any ("oserver3_x64.exe", "OReportServer3_x64.exe", "OMailRpt.exe", "msiexec.exe /V")
    | project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath
),
(
    DeviceNetworkEvents
    | where TimeGenerated between (startofday(now()) .. now())
    | where DeviceName has_any ("sbcs-laptop16","sbcs-pc38","sbcs-laptop10","sbcs-laptop04",
                                "sbcs-laptop19","sbcs-pc34","sbcs-laptop01","sbcs-laptop20","sbcs-laptop05")
    | where InitiatingProcessCommandLine has_any ("oserver3_x64.exe", "OReportServer3_x64.exe", "OMailRpt.exe", "msiexec.exe /V")
    | project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Protocol, Action
)
| order by TimeGenerated desc
