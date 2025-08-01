## BP-1002: Disable EDR User-Mode Service 

### Technique Description

EDR and AV products are typically composed of multiple components, with some running in kernel mode and others in user mode. The user-mode components are most often implemented as Windows services. This technique focuses on disabling these user-mode services to stop them from starting. Attackers can use various methods to accomplish this, such as exploiting vulnerabilities or using legitimate system tools. They may have to bypass protection mechanisms like registry tamper protection (via kernel callbacks) or Process Protection Levels (PPL).

-----

### Sub-Techniques

#### BP-1002.1: Disable service using services.msc

The Services control panel (`services.msc`) can be used to stop and disable Windows services that are not otherwise protected. When a service is created, it can specify if it can be stopped via the `SERVICE_ACCEPT_STOP` flag. If this flag is not set, the option to stop the service is greyed out in the control panel.

A service can also be disabled by setting its **Startup Type** to **Disabled** in its properties window. This prevents the service from starting on the next reboot or when it transitions to a stopped state.

Service permissions, which control who can stop or configure a service, are managed by a security descriptor. These permissions can be viewed using the Sysinternals `accesschk` tool.

```
C:\Windows\System32>accesschk -cv AgentManager

Accesschk v6.15 - Reports effective permissions for securable objects 
Copyright (C) 2006-2022 Mark Russinovich 
Sysinternals - www.sysinternals.com 

AgentManager 
  Medium Mandatory Level (Default) [No-Write-Up] 
  RW NT AUTHORITY\SYSTEM 
        SERVICE_ALL_ACCESS 
  RW BUILTIN\Administrators 
        SERVICE_ALL_ACCESS 
  R  NT AUTHORITY\INTERACTIVE 
        SERVICE_QUERY_STATUS 
        SERVICE_QUERY_CONFIG 
        SERVICE_INTERROGATE 
        SERVICE_ENUMERATE_DEPENDENTS 
        SERVICE_USER_DEFINED_CONTROL 
        READ_CONTROL 
  R  NT AUTHORITY\SERVICE 
        SERVICE_QUERY_STATUS 
        SERVICE_QUERY_CONFIG 
        SERVICE_INTERROGATE 
        SERVICE_ENUMERATE_DEPENDENTS 
        SERVICE_USER_DEFINED_CONTROL 
        READ_CONTROL 
```

**Note:** PPL (Process Protection Level) services cannot be disabled through the `services.msc` control panel. This is enforced by the Service Control Manager (`services.exe`), and any attempt will be denied.

#### BP-1002.2: Disable service using msconfig.exe

The System Configuration utility (`msconfig.exe`) can be used to disable Windows services. After a service is disabled this way, it will not start when the system reboots. However, because `msconfig.exe` sends its requests through the Service Control Manager, it cannot be used to disable PPL services.

#### BP-1002.3: Disable service using sc.exe

The `sc.exe` command-line tool can stop and disable Windows services.

  * **To stop a service:** `sc stop AgentManager` 
  * **To disable a service:** `sc config AgentManager start=disabled` 

Similar to the other tools, `sc.exe` also routes requests through the Service Control Manager, so it cannot stop or disable PPL services.

#### BP-1002.4: Disable service using PowerShell cmdlet

PowerShell cmdlets can also be used to manage Windows services.

  * **To stop a service:** `Stop-Service -Name AgentManager -Force` 
  * **To disable a service:** `Set-Service -Name AgentManager -StartupType Disabled` 

Because PowerShell also interacts with the Service Control Manager, it cannot be used to stop or disable PPL services.

#### BP-1002.5: Disable service using reg.exe

An attacker can bypass the security checks performed by the Service Control Manager by directly editing the registry. This allows them to change a service's configuration, with the changes taking effect after the next reboot.

  * **To disable a service via command line:**

    ```
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AgentManager" /v Start /t REG_DWORD /d 4 /f
    ```

    
    The `Start` values are interpreted as:

      * `0`: Boot
      * `1`: System
      * `2`: Automatic
      * `3`: Manual
      * `4`: Disabled
        

  * **To disable a service via a `.reg` file:** An attacker can create a file to avoid exposing the manipulation on the command line.

    ```reg
    Windows Registry Editor Version 5.00

    [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AgentManager]
    "Start"=dword:00000004
    ```

    
    This file can then be imported with the command: `reg import agent_manager.reg`. If the registry key for a PPL service is not otherwise protected, it can be disabled using this method.

#### BP-1002.6: Disable service using registry save/restore

To avoid detection from registry notification callbacks, an attacker can use registry save and restore operations. A registry key can be saved to a binary hive file, modified offline, and then restored.

This sequence overwrites the `Start` value for the `AgentManager` service, disabling it on the next reboot:

```
reg save HKLM\SYSTEM\ControlSet001\Services\AgentManager C:\Windows\Temp\Backup.hiv
reg load HKLM\Backup C:\Windows\Temp\Backup.hiv
reg add HKLM\Backup /v Start /t REG_DWORD /d 0x04 /f
reg unload HKLM\Backup
reg restore HKLM\SYSTEM\ControlSet001\Services\AgentManager C:\Windows\Temp\Backup.hiv
```



Attackers may use variations of this, such as saving the entire parent key to avoid directly referencing the target service's key, or restoring a hive file prepared beforehand.

-----

### Detection Opportunities

1.  **Service Identification**:
      * Identify the specific services associated with the target EDR solution. This can be done by analyzing running processes, looking at service configurations, or checking documentation.