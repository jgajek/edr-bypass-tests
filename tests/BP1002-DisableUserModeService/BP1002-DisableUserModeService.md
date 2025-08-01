## [cite\_start]BP-1002: Disable EDR User-Mode Service [cite: 1]

### Technique Description

[cite\_start]EDR and AV products are typically composed of multiple components, with some running in kernel mode and others in user mode[cite: 3]. [cite\_start]The user-mode components are most often implemented as Windows services[cite: 4]. [cite\_start]This technique focuses on disabling these user-mode services to stop them from starting[cite: 4]. [cite\_start]Attackers can use various methods to accomplish this, such as exploiting vulnerabilities or using legitimate system tools[cite: 5]. [cite\_start]They may have to bypass protection mechanisms like registry tamper protection (via kernel callbacks) or Process Protection Levels (PPL)[cite: 6].

-----

### Sub-Techniques

#### BP-1002.1: Disable service using services.msc

[cite\_start]The Services control panel (`services.msc`) can be used to stop and disable Windows services that are not otherwise protected[cite: 11]. [cite\_start]When a service is created, it can specify if it can be stopped via the `SERVICE_ACCEPT_STOP` flag[cite: 12, 13]. [cite\_start]If this flag is not set, the option to stop the service is greyed out in the control panel[cite: 13, 14].

[cite\_start]A service can also be disabled by setting its **Startup Type** to **Disabled** in its properties window[cite: 58, 59]. [cite\_start]This prevents the service from starting on the next reboot or when it transitions to a stopped state[cite: 86].

[cite\_start]Service permissions, which control who can stop or configure a service, are managed by a security descriptor[cite: 87]. [cite\_start]These permissions can be viewed using the Sysinternals `accesschk` tool[cite: 88].

```
C:\Windows\System32>accesschk -cv AgentManager
[cite_start][cite: 89]
[cite_start]Accesschk v6.15 - Reports effective permissions for securable objects [cite: 91]
[cite_start]Copyright (C) 2006-2022 Mark Russinovich [cite: 92]
[cite_start]Sysinternals - www.sysinternals.com [cite: 93]

[cite_start]AgentManager [cite: 95]
  [cite_start]Medium Mandatory Level (Default) [No-Write-Up] [cite: 96]
  [cite_start]RW NT AUTHORITY\SYSTEM [cite: 99]
        [cite_start]SERVICE_ALL_ACCESS [cite: 105]
  [cite_start]RW BUILTIN\Administrators [cite: 106]
        [cite_start]SERVICE_ALL_ACCESS [cite: 107]
  [cite_start]R  NT AUTHORITY\INTERACTIVE [cite: 108]
        [cite_start]SERVICE_QUERY_STATUS [cite: 109]
        [cite_start]SERVICE_QUERY_CONFIG [cite: 111]
        [cite_start]SERVICE_INTERROGATE [cite: 113]
        [cite_start]SERVICE_ENUMERATE_DEPENDENTS [cite: 115]
        [cite_start]SERVICE_USER_DEFINED_CONTROL [cite: 117]
        [cite_start]READ_CONTROL [cite: 119]
  [cite_start]R  NT AUTHORITY\SERVICE [cite: 121]
        [cite_start]SERVICE_QUERY_STATUS [cite: 123]
        [cite_start]SERVICE_QUERY_CONFIG [cite: 125]
        [cite_start]SERVICE_INTERROGATE [cite: 127]
        [cite_start]SERVICE_ENUMERATE_DEPENDENTS [cite: 129]
        [cite_start]SERVICE_USER_DEFINED_CONTROL [cite: 132]
        [cite_start]READ_CONTROL [cite: 133]
```

[cite\_start]**Note:** PPL (Process Protection Level) services cannot be disabled through the `services.msc` control panel[cite: 134]. [cite\_start]This is enforced by the Service Control Manager (`services.exe`), and any attempt will be denied[cite: 135, 139].

#### BP-1002.2: Disable service using msconfig.exe

[cite\_start]The System Configuration utility (`msconfig.exe`) can be used to disable Windows services[cite: 166]. [cite\_start]After a service is disabled this way, it will not start when the system reboots[cite: 167]. [cite\_start]However, because `msconfig.exe` sends its requests through the Service Control Manager, it cannot be used to disable PPL services[cite: 218, 219].

#### BP-1002.3: Disable service using sc.exe

[cite\_start]The `sc.exe` command-line tool can stop and disable Windows services[cite: 221].

  * [cite\_start]**To stop a service:** `sc stop AgentManager` [cite: 223]
  * [cite\_start]**To disable a service:** `sc config AgentManager start=disabled` [cite: 225, 226]

[cite\_start]Similar to the other tools, `sc.exe` also routes requests through the Service Control Manager, so it cannot stop or disable PPL services[cite: 227, 228].

#### BP-1002.4: Disable service using PowerShell cmdlet

[cite\_start]PowerShell cmdlets can also be used to manage Windows services[cite: 229].

  * [cite\_start]**To stop a service:** `Stop-Service -Name AgentManager -Force` [cite: 229]
  * [cite\_start]**To disable a service:** `Set-Service -Name AgentManager -StartupType Disabled` [cite: 229]

[cite\_start]Because PowerShell also interacts with the Service Control Manager, it cannot be used to stop or disable PPL services[cite: 229].

#### BP-1002.5: Disable service using reg.exe

[cite\_start]An attacker can bypass the security checks performed by the Service Control Manager by directly editing the registry[cite: 229]. [cite\_start]This allows them to change a service's configuration, with the changes taking effect after the next reboot[cite: 229].

  * **To disable a service via command line:**

    ```
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AgentManager" /v Start /t REG_DWORD /d 4 /f
    ```

    [cite\_start][cite: 229]
    The `Start` values are interpreted as:

      * `0`: Boot
      * `1`: System
      * `2`: Automatic
      * `3`: Manual
      * `4`: Disabled
        [cite\_start][cite: 229]

  * [cite\_start]**To disable a service via a `.reg` file:** An attacker can create a file to avoid exposing the manipulation on the command line[cite: 229].

    ```reg
    Windows Registry Editor Version 5.00

    [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AgentManager]
    "Start"=dword:00000004
    ```

    [cite\_start][cite: 229]
    [cite\_start]This file can then be imported with the command: `reg import agent_manager.reg`[cite: 229]. [cite\_start]If the registry key for a PPL service is not otherwise protected, it can be disabled using this method[cite: 229].

#### BP-1002.6: Disable service using registry save/restore

[cite\_start]To avoid detection from registry notification callbacks, an attacker can use registry save and restore operations[cite: 230]. [cite\_start]A registry key can be saved to a binary hive file, modified offline, and then restored[cite: 230].

[cite\_start]This sequence overwrites the `Start` value for the `AgentManager` service, disabling it on the next reboot[cite: 230]:

```
reg save HKLM\SYSTEM\ControlSet001\Services\AgentManager C:\Windows\Temp\Backup.hiv
reg load HKLM\Backup C:\Windows\Temp\Backup.hiv
reg add HKLM\Backup /v Start /t REG_DWORD /d 0x04 /f
reg unload HKLM\Backup
reg restore HKLM\SYSTEM\ControlSet001\Services\AgentManager C:\Windows\Temp\Backup.hiv
```

[cite\_start][cite: 230]

[cite\_start]Attackers may use variations of this, such as saving the entire parent key to avoid directly referencing the target service's key, or restoring a hive file prepared beforehand[cite: 230].

-----

### Detection Opportunities

1.  **Service Identification**:
      * [cite\_start]Identify the specific services associated with the target EDR solution[cite: 233]. [cite\_start]This can be done by analyzing running processes, looking at service configurations, or checking documentation[cite: 234].