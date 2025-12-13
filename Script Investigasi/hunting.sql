DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("winncap364.dll", "TIjtDrvd64.dll", "dtsframe64.dll", "TMailHook64.dll")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA1, SHA256
| sort by Timestamp desc



2. Cek apakah DLL muncul di registry atau startup

Gunakan tabel DeviceRegistryEvents untuk mencari persistence:

DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryValueData has_any ("winncap364.dll", "TIjtDrvd64.dll", "dtsframe64.dll", "TMailHook64.dll")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| sort by Timestamp desc




Cek apakah file tersebut muncul di file system

Gunakan DeviceFileEvents untuk melihat apakah file tersebut pernah dibuat, diakses, atau dimodifikasi:


DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("winncap364.dll", "TIjtDrvd64.dll", "dtsframe64.dll", "TMailHook64.dll")
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256, MD5
| sort by Timestamp desc



-- hunting URL Host, Path, Query
where("url_host" OR "url_path" OR "url_query")

