// Hunting: msiexec executed from SystemTemp or chrome_Unpacker, or matching specific hash
let targetDevice = "sbcs-pc23";
let targetSha1 = "80d5095d-9f3c-e2ee-b680-7891f3ba39f3";
DeviceProcessEvents
| where FileName =~ "msiexec.exe" or ProcessCommandLine has "msiexec"
| where DeviceName == targetDevice or ProcessCommandLine has "chrome_Unpacker" or ProcessCommandLine has "SystemTemp"
| where Timestamp >= ago(30d)
| extend
    ProcessPath = FolderPath,
    Cmd = ProcessCommandLine,
    RunBy = InitiatingProcessAccountName == "" ? AccountName : InitiatingProcessAccountName,
    IsSystem = tolower(RunBy) has "system",
    SilentFlags = iff(Cmd has "/qn" or Cmd has "/quiet" or Cmd has "/qn", true, false),
    FromTemp = cmd =~ ".*SystemTemp.*" or Cmd has "chrome_Unpacker"
| extend
    What = "msiexec installer execution",
    When = Timestamp,
    Where = DeviceName,
    Who = RunBy,
    Why = case(IsSystem, "Executed as SYSTEM - needs verification", SilentFlags, "Silent install flags present", FromTemp, "Installer executed from temp/unpack path", "Needs investigation"),
    How = strcat("CommandLine: ", Cmd)
| project Timestamp, DeviceName, FileName, ProcessId, InitiatingProcessFileName, RunBy, IsSystem, SilentFlags, FromTemp, Cmd, SHA1, What, When, Where, Who, Why, How
| order by Timestamp desc
