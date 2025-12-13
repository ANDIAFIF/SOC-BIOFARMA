DeviceImageLoadEvents
| where SHA256 in~ (
    "106b9f9e5067882c63c3dd5965c27abec64a2cda3f6250b35ba26fdcb30e997b",
    "ba6530f06df6592a2f8d4d306391b1968a07734c27a420a7cdd971ffea5c58e1",
    "21c431e5995644a756e0593755cf919b79243c9a",
    "a453ab17539f876003ee45583244f5cbaef63bf0"
)
| summarize by DeviceName, InitiatingProcessFileName, FileName, FolderPath




-- Pencarian data berdasarkan hash SHA256 dari file DLL yang mencurigakan

// 1A - Cari image/module load berdasarkan SHA1 atau nama file (recommended)
let suspiciousFiles = dynamic(["98d28c316d35c8a8711e81e293ee456b037bd1ff", "a453ab17539f876003ee45583244f5cbaef63bf0", "701b4a5f0b28f2c24878d9d0e78af7becbf82a84", "21c431e5995644a756e0593755cf919b79243c9a"]);
let suspiciousNames = dynamic(["winncap364.dll","dtsframe64.dll","TIjtDrvd64.dll","TMailHook64.dll"]);
DeviceImageLoadEvents
| where SHA1 in (suspiciousFiles) or FileName in (suspiciousNames)
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessAccountDomain, InitiatingProcessId
| sort by Timestamp desc

