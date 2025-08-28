@echo off
:: ================================
:: Purple Team + LOLBins Monitor
:: ================================
:: Purpose: Windows 11 hardening + basic LOLBin execution detection
:: Version: 1.0
:: Tested: Windows 11 Pro (22H2+)
:: Author: Red-Blue Team Hybrid Tool
:: ================================

setlocal EnableDelayedExpansion

:: SECTION 1: Define LOLBins list
set "LOLBINS=bitsadmin certutil mshta wmic powershell regsvr32 rundll32 schtasks iexpress cmstp installutil"

:: SECTION 2: Set up log file
set "LOGFILE=%~dp0lolbins_monitor.log"

:: SECTION 3: Define basic host context
set "HOSTNAME=%COMPUTERNAME%"
set "USERNAME=%USERNAME%"
set "DATESTAMP=%date%"
set "TIMESTAMP=%time%"
set "SESSION_ID=%SESSIONNAME%"

:: Write header once
if not exist "%LOGFILE%" (
    echo ========================================== >> "%LOGFILE%"
    echo === LOLBin Monitoring Log Initialized === >> "%LOGFILE%"
    echo Host: %HOSTNAME% | User: %USERNAME% | Session: %SESSION_ID% >> "%LOGFILE%"
    echo Date: %DATESTAMP% | Time: %TIMESTAMP% >> "%LOGFILE%"
    echo ========================================== >> "%LOGFILE%"
)

:: SECTION 4: Function to log LOLBin execution
:log_attempt
set "EXECUTABLE=%~1"
set "TS=%date% %time%"
echo [%TS%] ALERT: Suspicious execution detected! %EXECUTABLE% run by %USERNAME% on %HOSTNAME% >> "%LOGFILE%"
exit /b

:: SECTION 5: Check running processes for known LOLBins
for %%B in (%LOLBINS%) do (
    tasklist /FI "IMAGENAME eq %%B.exe" | find /I "%%B.exe" >nul
    if !errorlevel! equ 0 (
        call :log_attempt %%B.exe
    )
)

:: SECTION 6: Run PowerShell-based Hardening and Detection Configuration
echo Running PowerShell Purple Team Toolkit setup...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"Write-Host '==[ PowerShell Purple Team Hardening Start ]==' -ForegroundColor Cyan; ^
Set-ExecutionPolicy Bypass -Scope Process -Force; ^

# ASR Rules (Aggressive Profile)
\$rules = @(
  'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',  # Block executable content from email/webmail
  '3B576869-A4EC-4529-8536-B80A7769E899',  # Use advanced ransomware protection
  '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',  # Block credential stealing
  '26190899-1602-49E8-8B27-EB1D0A1CE869',  # Block Office child processes
  'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'   # Block WScript, MSHTA, etc.
); ^
foreach (\$rule in \$rules) { Add-MpPreference -AttackSurfaceReductionRules_Ids \$rule -AttackSurfaceReductionRules_Actions Enabled }; ^

# Enable ScriptBlock Logging
New-Item -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Force | Out-Null; ^
Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1; ^
Set-ItemProperty -Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -Name 'EnableScriptBlockInvocationLogging' -Value 1; ^

# Download and Install Sysmon
Invoke-WebRequest -Uri 'https://live.sysinternals.com/Sysmon64.exe' -OutFile '\$env:TEMP\\Sysmon64.exe'; ^
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml' -OutFile '\$env:TEMP\\sysmon.xml'; ^
& '\$env:TEMP\\Sysmon64.exe' -accepteula -i '\$env:TEMP\\sysmon.xml'; ^

# Enable Event Logs
wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true; ^
wevtutil sl Security /e:true; ^

# Disable insecure services/features
Set-Service -Name 'RemoteRegistry' -StartupType Disabled; ^
Set-Service -Name 'wuauserv' -StartupType Manual; ^
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart; ^

# Defender Preferences
Set-MpPreference -PUAProtection Enabled; ^
Set-MpPreference -SubmitSamplesConsent 2; ^
Set-MpPreference -MAPSReporting Advanced; ^

Write-Host '==[ Purple Team Hardening Complete ]==' -ForegroundColor Green"

:: SECTION 7: Final status
echo [%date% %time%] INFO: LOLBin scan + hardening complete >> "%LOGFILE%"
echo Deployment Complete. Review %LOGFILE% for suspicious activity.
endlocal
pause
