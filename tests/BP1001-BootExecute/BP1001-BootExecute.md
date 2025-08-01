# BP1001: BootExecute EDR Bypass

## Overview

**MITRE ATT&CK Techniques**: 
- T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)
- T1562.001 (Impair Defenses: Disable or Modify Tools)

**Objective**: Leverage Windows Boot Execute mechanism to run native applications before EDR/AV initialization, allowing pre-emptive security software disruption.

## Description

The Boot Execute mechanism allows native applications (executables with NtProcessStartup entry point and dependencies solely on ntdll.dll) to run prior to complete Windows OS initialization. This occurs even before Windows services launch, providing an opportunity to disrupt security mechanisms before they become operational.

### Technical Background

**Boot Sequence Position**:
1. Windows Kernel loads
2. **Boot Execute applications run** ← *Our insertion point*
3. Windows subsystems initialize (win32k, etc.)
4. Windows services start
5. EDR/AV agents load

**Execution Context**:
- **Privileges**: SYSTEM (highest Windows privilege level)
- **Dependencies**: Only ntdll.dll available
- **Timing**: Pre-service initialization
- **Protection**: Minimal security mechanisms active

### Attack Vector

Because native applications execute before security mechanisms are fully operational, attackers can:
- Delete critical EDR/AV application files
- Modify security software registry configurations
- Disable security services before they start
- Establish persistence with minimal detection risk

## Requirements

### Prerequisites
- **Administrative Privileges**: Required for registry modification and file placement
- **Native Executable**: Compiled binary with NtProcessStartup entry point
- **System Access**: Ability to write to `%SystemRoot%\System32` directory

### Binary Specifications
- **Entry Point**: `NtProcessStartup` (not standard `main` or `WinMain`)
- **Dependencies**: Only ntdll.dll (no kernel32.dll, user32.dll, etc.)
- **Architecture**: Must match system architecture (x64 for x64 systems)
- **File Location**: Must be placed in `C:\Windows\System32\`

## Implementation Methods

### Registry Keys for Boot Execute

Windows provides several registry values for boot-time execution:

#### Primary Boot Execute Keys

```registry
# Standard Boot Execute (most common)
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
Value: BootExecute
Type: REG_MULTI_SZ
Data: autocheck autochk *\0<executable_name>

# Boot Execute without PnP synchronization  
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
Value: BootExecuteNoPnpSync
Type: REG_MULTI_SZ
Data: <executable_name>

# Setup Execute (runs during setup/upgrade)
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
Value: SetupExecute  
Type: REG_MULTI_SZ
Data: <executable_name>

# Platform Execute (platform-specific initialization)
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
Value: PlatformExecute
Type: REG_MULTI_SZ
Data: <executable_name>
```

### Available Variants

| Variant ID | Method | Stealth Level | Persistence | Complexity |
|------------|---------|---------------|-------------|------------|
| **BP1001.1** | Registry manipulation | High | Boot-persistent | ⭐⭐⭐⭐ |

## Execution Flow

### Phase 1: Preparation
1. Validate administrative privileges
2. Verify target binary exists (`bootexecute.exe`)
3. Backup current registry state

### Phase 2: Binary Deployment  
1. Copy binary to `C:\Windows\System32\bootexecute.exe`
2. Set appropriate file permissions
3. Verify binary placement

### Phase 3: Registry Configuration
1. Modify selected Boot Execute registry key
2. Add binary to execution list
3. Verify registry modification

### Phase 4: Verification
1. Confirm binary is in System32
2. Verify registry key contains binary entry
3. Test registry key accessibility

### Phase 5: Reversion (Testing)
1. Remove binary from System32
2. Restore original registry values
3. Verify complete cleanup

## Detection Considerations

### Detection Vectors
- **Registry Monitoring**: Boot Execute keys frequently monitored
- **File System Events**: System32 file additions tracked
- **Boot Process Analysis**: Unusual boot-time execution patterns
- **Binary Analysis**: Non-standard entry points and dependencies

### Evasion Techniques
- **Legitimate Names**: Use system-like binary names
- **Minimal Footprint**: Small, efficient native binaries
- **Timing**: Execute quickly and exit cleanly
- **Cleanup**: Remove traces after primary objective

## Security Implications

### Attack Capabilities
- **Pre-AV Execution**: Run before antivirus initialization
- **Pre-EDR Execution**: Execute before EDR agent startup
- **System-Level Access**: Full SYSTEM privileges available
- **Persistence**: Survives reboots and system updates

### Defensive Measures
- **Boot Process Monitoring**: Track unusual boot execute entries
- **System32 Integrity**: Monitor System32 directory changes
- **Registry Protection**: Protect critical boot registry keys
- **Native Binary Analysis**: Scan for suspicious native executables

## References

### Microsoft Documentation
- [Boot Configuration Data (BCD)](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcd-boot-options-reference)
- [Session Manager Registry Entries](https://docs.microsoft.com/en-us/windows/win32/sysinfo/session-manager-registry-entries)

### Security Research
- [BootExecuteEDR Repository](https://github.com/rad9800/BootExecuteEDR) - Original implementation reference
- [Native API Programming](https://undocumented.ntinternals.net/) - Native Windows API documentation

### MITRE ATT&CK Framework
- [T1547.001: Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/001/)
- [T1562.001: Impair Defenses](https://attack.mitre.org/techniques/T1562/001/)

---

**Note**: This technique represents an advanced persistence and defense evasion method requiring deep Windows internals knowledge and careful implementation to avoid system instability.