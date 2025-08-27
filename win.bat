@echo off
setlocal

:: --- CONFIG ---
set "REPO_DIR=%~dp0"
set "BUILD_DIR=%REPO_DIR%build"
set "BACKUP_DIR=%REPO_DIR%backup"
set "PACKAGE_NAME=repo_package.zip"

:: --- timestamp ---
for /f "tokens=1-4 delims=/: " %%a in ("%date% %time%") do set TIMESTAMP=%%a-%%b-%%c_%%d
set "PACKAGE=%REPO_DIR%%PACKAGE_NAME%"

echo === Starting safe build process ===
echo Repo: %REPO_DIR%
echo Build: %BUILD_DIR%
echo Backup: %BACKUP_DIR%

:: --- make backup (safe) ---
if exist "%BACKUP_DIR%" rd /s /q "%BACKUP_DIR%"
mkdir "%BACKUP_DIR%"
powershell -NoProfile -Command "Compress-Archive -Path '%REPO_DIR%*' -DestinationPath '%BACKUP_DIR%\repo_backup_%TIMESTAMP%.zip' -Force"
if errorlevel 1 (
  echo Backup failed.
  goto :cleanup
)
echo Backup created.

:: --- prepare build dir (exclude binaries) ---
if exist "%BUILD_DIR%" rd /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
:: Copy source files but exclude common binary patterns
robocopy "%REPO_DIR%" "%BUILD_DIR%" /MIR /XD .git .gitignore backup build /XF *.exe *.dll *.bin *.so *.dat *.lock *.key
if errorlevel 8 (
  echo Robocopy reported a fatal error.
  goto :cleanup
)
echo Files copied to build directory.

:: --- optional: run tests if provided ---
if exist "%REPO_DIR%run_tests.bat" (
  echo Running repository tests...
  call "%REPO_DIR%run_tests.bat"
) else (
  echo No run_tests.bat found. Skipping tests.
)

:: --- create distribution package ---
if exist "%PACKAGE%" del /f /q "%PACKAGE%"
powershell -NoProfile -Command "Compress-Archive -Path '%BUILD_DIR%\*' -DestinationPath '%PACKAGE%' -Force"
if errorlevel 1 (
  echo Packaging failed.
  goto :cleanup
)
echo Package created: %PACKAGE%

:cleanup
echo === Done ===
endlocal
exit /b 0
