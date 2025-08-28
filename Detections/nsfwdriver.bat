@echo off
:: nsfwdriver.bat - Import Microsoft's Vulnerable Driver Blocklist into WDAC
:: Applies system-wide driver block rules for known vulnerable kernel drivers.

echo [*] Checking for Admin rights...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run this script as Administrator.
    pause
    exit /b
)

echo [*] Creating working directory...
set "WDIR=%~dp0WDAC"
mkdir "%WDIR%" >nul 2>&1

echo [*] Downloading Microsoft Vulnerable Driver Blocklist...
powershell -Command "Invoke-WebRequest -Uri 'https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/vulnerable-driver-blocklist.xml' -OutFile '%WDIR%\vulndriver.xml'"

if not exist "%WDIR%\vulndriver.xml" (
    echo [!] Failed to download vulnerable driver blocklist.
    pause
    exit /b
)

echo [*] Converting XML to binary WDAC policy...
powershell -Command "ConvertFrom-CIPolicy -XmlFilePath '%WDIR%\vulndriver.xml' -BinaryFilePath '%WDIR%\DriverBlockPolicy.cip'"

echo [*] Copying policy to WDAC folder...
copy "%WDIR%\DriverBlockPolicy.cip" "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b" /Y

echo [*] Enabling driver block policy on next boot...
bcdedit /set flightsigning on
bcdedit /set nointegritychecks off

echo [*] Done! Reboot your system for policy to apply.
pause
exit /b
