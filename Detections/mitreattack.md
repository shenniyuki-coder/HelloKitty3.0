# Ryuk MITRE ATT&CK Techniques and Commands

## T1134 - Access Token Manipulation
- **Technique**: Access Token Manipulation
- **Command**: Adjust token privileges to include `SeDebugPrivilege`

## T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **Command**: `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SomeValue /t REG_SZ /d "PathToExecutable"`

## T1059.003 - Command and Scripting Interpreter: Windows Command Shell
- **Command**: `cmd.exe /c reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v SomeValue /t REG_SZ /d "PathToExecutable"`

## T1486 - Data Encrypted for Impact
- **Command**: Files encrypted using AES and RSA; file extension changed to `.RYK`; ransom note `RyukReadMe.txt` written to directories.

## T1083 - File and Directory Discovery
- **Command**: Enumerates files and folders on mounted drives (e.g., `dir /s /b`)

## T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification
- **Command**: `icacls "C:\\Path" /grant Everyone:F /T /C /Q`

## T1562.001 - Impair Defenses: Disable or Modify Tools
- **Command**: Stops services related to anti-virus (e.g., `net stop AVServiceName`)

## T1490 - Inhibit System Recovery
- **Command**: 
  - `vssadmin Delete Shadows /all /quiet`
  - `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB`

## T1036 - Masquerading
- **Command**: Create `.dll` file containing RTF format document

## T1036.005 - Masquerading: Match Legitimate Resource Name or Location
- **Command**: Use `GetWindowsDirectoryW` and insert null byte in path (e.g., `C:\\Users\\Public`)

## T1106 - Native API
- **Command**: Uses APIs like `ShellExecuteW`, `GetWindowsDirectoryW`, `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`

## T1027 - Obfuscated Files or Information
- **Command**: Uses anti-disassembly and code transformation techniques

## T1057 - Process Discovery
- **Command**: `CreateToolhelp32Snapshot` to enumerate running processes

## T1055 - Process Injection
- **Command**: Inject via `VirtualAlloc`, `WriteProcessMemory`, and `CreateRemoteThread`

## T1021.002 - Remote Services: SMB/Windows Admin Shares
- **Command**: Use of `C$` network share for lateral movement

## T1053.005 - Scheduled Task/Job: Scheduled Task
- **Command**: `schtasks /create /tn "TaskName" /tr "PathToExecutable" /sc onstart /ru SYSTEM`

## T1489 - Service Stop
- **Command**: `kill.bat` used to stop and disable services and kill processes

## T1082 - System Information Discovery
- **Command**: Uses `GetLogicalDrives` and `GetDriveTypeW`

## T1614.001 - System Location Discovery: System Language Discovery
- **Command**: Reads `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language\\InstallLanguage` and stops if value is `0x419`, `0x422`, or `0x423`

## T1016 - System Network Configuration Discovery
- **Command**: Calls `GetIpNetTable` to identify ARP entries

## T1205 - Traffic Signaling
- **Command**: Uses Wake-on-LAN to power on systems

## T1078.002 - Valid Accounts: Domain Accounts
- **Command**: Uses stolen domain admin credentials for lateral movement

## T0828 - Loss of Productivity and Revenue (ICS)
- **Impact**: ERP manufacturing server lost, production reverted to manual processes
