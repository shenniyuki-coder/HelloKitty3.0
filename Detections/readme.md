
### 📁 **NSFW-Ransomware Sigma Ruleset**

**YAML Format | Compatible with: Splunk, ELK, Sentinel, etc.**

---

#### 1️⃣ **Download Payload via `certutil`**

**Technique:** T1105 - Ingress Tool Transfer

```yaml
title: Certutil Payload Download
id: 07fc5d3e-e6bb-492b-bdf4-4c06bcff9f91
description: Detects certutil used to download remote payloads from GitHub or external sources.
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\certutil.exe'
    CommandLine|contains|all:
      - '-urlcache'
      - '-split'
  condition: selection
level: high
tags:
  - attack.command_and_control
  - attack.t1105
  - nsfw.simulation
```

---

#### 2️⃣ **Execution of `.ps1` Payload via PowerShell**

**Technique:** T1059.001 - PowerShell

```yaml
title: Suspicious PowerShell Script Execution
id: f199f674-36d4-4d1a-8cb6-54b0cf67d16b
description: Detects hidden PowerShell script execution of nsfw_inject.ps1
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'ExecutionPolicy'
      - 'Bypass'
      - '.ps1'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - nsfw.simulation
```

---

#### 3️⃣ **DLL Execution via Rundll32**

**Technique:** T1218.011 - Rundll32

```yaml
title: Rundll32 DLL Execution
id: c48c8201-4e3f-4f4c-9c11-9479cf83a05b
description: Detects use of rundll32 to execute reflectively injected DLL (e.g., nsfw.dll)
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: 'nsfw.dll'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.011
  - nsfw.simulation
```

---

#### 4️⃣ **UAC Bypass via `fodhelper` and Registry Hijack**

**Technique:** T1548.002 - Bypass User Access Control

```yaml
title: UAC Bypass via Fodhelper Registry Hijack
id: 98d6a1d5-f3f1-42f2-9a99-b9dd24c2e928
description: Detects registry hijack technique using fodhelper.exe to bypass UAC
logsource:
  category: registry_event
  product: windows
detection:
  reg_set:
    EventType: 'SetValue'
    TargetObject|contains: 'Software\Classes\ms-settings\Shell\Open\command'
  process_run:
    Image|endswith: '\fodhelper.exe'
  condition: reg_set and process_run
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.002
  - nsfw.simulation
```

---

#### 5️⃣ **Persistence via `Run` Key**

**Technique:** T1547.001 - Registry Run Keys

```yaml
title: Persistence via Registry Run Key
id: d7e7cb26-430f-4a92-b201-7a9d1894be4e
description: Detects script-based persistence using Run key
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    EventType: 'SetValue'
    TargetObject|contains: 'CurrentVersion\Run'
    Details|contains: 'powershell'
  condition: selection
level: medium
tags:
  - attack.persistence
  - attack.t1547.001
  - nsfw.simulation
```

---

#### 6️⃣ **Log Wiping via `wevtutil`**

**Technique:** T1070.001 - Clear Windows Event Logs

```yaml
title: Windows Event Log Clearing via Wevtutil
id: d2357cbe-bf21-4962-8913-2cfc083bd251
description: Detects use of wevtutil to clear logs — indicative of covering tracks
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\wevtutil.exe'
    CommandLine|contains: 'cl'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
  - nsfw.simulation
```

---

### 🔄 How to Use These

1. **Convert to `.yml`** files and import into:

   * [Elastic SIEM (Elastic Stack)](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
   * [Splunk with Sigma plugin](https://github.com/SigmaHQ/sigma)
   * \[Azure Sentinel / Microsoft Defender XDR]
2. Use a tool like `sigmac`:

   ```bash
   sigmac -t splunk -c splunk-windows.yml nsfw_rundll32_inject.yml
   ```


