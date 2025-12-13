DeviceFileEvents
| where DeviceName in ("sbcs-laptop05", "sbcs-pc34")
| where FileName in ("winncap364.dll","winhafnt64.dll","winhadnt64.dll","TIjtDrvd64.dll","dtsframe64.dll","dtframe64.dll","TMailHook64.dll")
| where TimeGenerated between (startofday(now()) .. now())
| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, FilePath, SHA256
| order by TimeGenerated desc



-- Tahap 2: Mencari aktivitas terkait file berbahaya pada device tertentu
DeviceNetworkEvents
| where DeviceName in ("sbcs-laptop05", "sbcs-pc34")
| where InitiatingProcessFileName == "msiexec.exe"
| where TimeGenerated between (startofday(now()) .. now())
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, Action
| order by TimeGenerated desc




-- Tahap 3: Mencari proses yang mencurigakan pada device tertentu

DeviceRegistryEvents
| where DeviceName in ("sbcs-laptop05", "sbcs-pc34")
| where RegistryKey contains "Services"
| where RegistryValueData has_any ("oserver3_x64.exe", "OReportServer3_x64.exe", "OMailRpt.exe", "msiexec.exe /V", "winncap364.dll", "winhafnt64.dll")
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated desc



🧰 Rekomendasi Mitigasi

🔥 Isolasi host sbcs-laptop05 dan sbcs-pc34 segera (via Defender atau network block).

🧹 Hapus file mencurigakan dari C:\Windows\System32\ (pastikan hash diverifikasi dulu).

🧩 Cek registry untuk service mencurigakan yang refer ke file itu.

🔐 Reset kredensial SYSTEM service atau admin jika ditemukan eskalasi hak akses.

📑 Simpan artefak: hash DLL, command line, timestamp — untuk IR evidence.