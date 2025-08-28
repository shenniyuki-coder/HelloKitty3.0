@echo off
title [🔍] Real-World LOLBins Threat Hunter - Windows 11
color 1E
echo [+] Starting LOLBin Threat Detection Script...
mkdir %SystemRoot%\Logs\LOLBin_Hunter 2>nul

:: ----------- STEP 1: Enable Defender, Logging, and Updates
echo [+] Enabling Defender & Logging...
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $false"
powershell -c "Set-MpPreference -PUAProtection Enabled"
powershell -c "Update-MpSignature"

echo [+] Enabling Script Block Logging...
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription /v OutputDirectory /t REG_SZ /d "%SystemRoot%\Logs\LOLBin_Hunter" /f

:: ----------- STEP 2: Monitor and Detect Key LOLBins
echo [+] Scanning for LOLBin activity... (Rundll32, MSHTA, Certutil, Regsvr32, Wmic, PowerShell, InstallUtil)

echo [*] Checking for rundll32 abuse...
tasklist | findstr /i rundll32 >> %SystemRoot%\Logs\LOLBin_Hunter\rundll32_detect.log

echo [*] Checking for mshta abuse...
tasklist | findstr /i mshta >> %SystemRoot%\Logs\LOLBin_Hunter\mshta_detect.log

echo [*] Checking for certutil usage...
wevtutil qe Security "/q:*[System[(EventID=4688)]] and *[EventData[Data[@Name='NewProcessName'] and (contains(.,'certutil.exe'))]]" /f:text >> %SystemRoot%\Logs\LOLBin_Hunter\certutil_detect.log

echo [*] Checking for regsvr32...
tasklist | findstr /i regsvr32 >> %SystemRoot%\Logs\LOLBin_Hunter\regsvr32_detect.log

echo [*] Checking for wmic...
tasklist | findstr /i wmic >> %SystemRoot%\Logs\LOLBin_Hunter\wmic_detect.log

echo [*] Checking for installutil abuse...
tasklist | findstr /i installutil >> %SystemRoot%\Logs\LOLBin_Hunter\installutil_detect.log

echo [*] Checking for suspicious PowerShell execution...
powershell -c "Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; ID=4104} -MaxEvents 25" >> %SystemRoot%\Logs\LOLBin_Hunter\powershell_detect.log

:: ----------- STEP 3: Return Summary Report
echo [+] Creating LOLBin Summary Threat Report...

(
    echo ================================
    echo Rundll32 Executions:
    echo ================================
    type %SystemRoot%\Logs\LOLBin_Hunter\rundll32_detect.log
    echo.

    echo ================================
    echo MSHTA Executions:
    echo ================================
    type %SystemRoot%\Logs\LOLBin_Hunter\mshta_detect.log
    echo.

    echo ================================
    echo CERTUTIL Executions:
    echo ================================
    type %SystemRoot%\Logs\LOLBin_Hunter\certutil_detect.log
    echo.

    echo ================================
    echo REGSVR32 Executions:
    echo ================================
    type %SystemRoot%\Logs\LOLBin_Hunter\regsvr32_detect.log
    echo.

    echo ================================
    echo WMIC Executions:
    echo ================================
    type %SystemRoot%\Logs\LOLBin_Hunter\wmic_detect.log
    echo.

    echo ================================
    echo INSTALLUTIL Executions:
    echo ================================
    type %SystemRoot%\Logs\LOLBin_Hunter\installutil_detect.log
    echo.

    echo ================================
    echo PowerShell Suspicious Script Logs:
    echo ================================
    type %SystemRoot%\Logs\LOLBin_Hunter\powershell_detect.log
) > %SystemRoot%\Logs\LOLBin_Hunter\LOLBin_Summary_Report.txt

start notepad %SystemRoot%\Logs\LOLBin_Hunter\LOLBin_Summary_Report.txt

echo [✔] Done. Full report saved to:
echo     %SystemRoot%\Logs\LOLBin_Hunter\LOLBin_Summary_Report.txt
pause
exit
