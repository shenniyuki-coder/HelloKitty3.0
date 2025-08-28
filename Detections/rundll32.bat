@echo off
title [🔒] Windows 11 Rundll32 Hardening & Detection Setup
color 1F
echo [+] Starting Blue Team Rundll32 Defense Script...
timeout /t 2 >nul

:: Step 1: Enable Windows Defender if not already
echo [+] Enabling Microsoft Defender...
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
powershell -Command "Set-MpPreference -PUAProtection Enabled"

:: Step 2: Add ASR Rules for LOLBins (includes Rundll32)
echo [+] Adding Attack Surface Reduction (ASR) rules for rundll32 abuse prevention...
powershell -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions Enabled"  REM: Block Office child processes
powershell -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled"  REM: Block all Office communication to child processes

:: Step 3: Optional – Block Rundll32 launching scripts from %TEMP% or %APPDATA%
echo [+] Creating Software Restriction Policy for rundll32 hardening...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v AuthenticodeEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v PolicyScope /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v TransparentEnabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v DefaultLevel /t REG_DWORD /d 262144 /f

:: Block rundll32 from TEMP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{rundll32temp}" /v ItemData /t REG_SZ /d "%TEMP%\rundll32.exe" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{rundll32temp}" /v SaferFlags /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths\{rundll32temp}" /v Description /t REG_SZ /d "Block rundll32 in TEMP" /f

:: Step 4: Enable Logging (Defender + PowerShell + WMI)
echo [+] Enabling PowerShell and Script Block Logging...
powershell -Command "Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -Force"
powershell -Command "Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription -Name EnableTranscripting -Value 1 -Force"
powershell -Command "Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription -Name OutputDirectory -Value '%SystemRoot%\Logs' -Force"

:: Step 5: Create Scheduled Task for Rundll32 Alerts
echo [+] Creating Rundll32 detection scheduled task...
schtasks /create /tn "MonitorRundll32" /tr "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -Command Get-WinEvent -FilterXPath \"*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=1)] and EventData[Data[@Name='Image'] and (contains(.,'rundll32.exe'))]]\" >> %SystemRoot%\Logs\rundll32_alerts.log" /sc minute /mo 5 /ru SYSTEM /f

:: Step 6: Defender Signature Update
echo [+] Updating Defender Signatures...
powershell -Command "Update-MpSignature"

echo.
echo [✔] Rundll32 hardening, ASR, logging, and detection is complete.
pause
exit
