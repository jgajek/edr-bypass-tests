# BP1001.1 - BootExecute EDR Bypass via Registry Manipulation

## Overview

This variant implements the BootExecute EDR bypass technique using PowerShell registry manipulation to configure Windows Boot Execute mechanisms. The technique leverages native Windows boot-time execution capabilities to run payloads before EDR/AV systems initialize.

## Technique Details

### Execution Method
- **Tool**: PowerShell registry cmdlets
- **Target**: Windows Session Manager registry keys
- **Payload**: Native Windows executable (`bootexecute.exe`)
- **Timing**: Pre-service initialization (boot-time)

### Boot Execute Mechanism

Windows provides several registry values for boot-time native application execution:

#### Registry Methods Available

1. **BootExecuteNoPnpSync** (Default)
   - **Key**: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
   - **Type**: `REG_MULTI_SZ`
   - **Description**: Executes without Plug-and-Play synchronization
   - **Format**: Simple executable name

2. **BootExecute**
   - **Key**: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
   - **Type**: `REG_MULTI_SZ`
   - **Description**: Standard boot execute with autocheck integration
   - **Format**: Appended to existing autocheck entries

3. **SetupExecute**
   - **Key**: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
   - **Type**: `REG_MULTI_SZ`
   - **Description**: Executes during system setup/upgrade
   - **Format**: Simple executable name

4. **PlatformExecute**
   - **Key**: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
   - **Type**: `REG_MULTI_SZ`
   - **Description**: Platform-specific initialization
   - **Format**: Simple executable name

## Usage

### Basic Execution

```powershell
# Run with default settings (BootExecuteNoPnpSync method)
.\run.ps1

# Specify different registry method
.\run.ps1 -RegistryMethod "BootExecute"

# Use custom binary name
.\run.ps1 -BinaryName "myapp.exe"

# Skip reversion for persistence testing
.\run.ps1 -SkipReversion
```

### Advanced Configuration

```powershell
# Full parameter example
.\run.ps1 -LogPath "D:\TestLogs" `
          -RegistryMethod "SetupExecute" `
          -BinaryName "bootexecute.exe" `
          -Verbose
```

## Parameters

### Standard Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `LogPath` | String | `C:\EDRBypassTests\Logs` | Directory for logs and results |
| `SkipReversion` | Switch | `$false` | Skip state restoration |
| `Verbose` | Switch | `$false` | Enable verbose debug output |

### Technique-Specific Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `BinaryName` | String | `bootexecute.exe` | Name of the native executable |
| `RegistryMethod` | String | `BootExecuteNoPnpSync` | Registry method to use |

#### Valid Registry Methods

- `BootExecute`: Standard boot execute with autocheck integration
- `BootExecuteNoPnpSync`: Boot execute without PnP synchronization (recommended)
- `SetupExecute`: Setup/upgrade execution
- `PlatformExecute`: Platform-specific execution

## Binary Requirements

### Native Executable Specifications

The target binary must be a **native Windows executable** with specific characteristics:

#### Technical Requirements
- **Entry Point**: `NtProcessStartup` (not standard `main` or `WinMain`)
- **Dependencies**: Only `ntdll.dll` (no kernel32.dll, user32.dll, etc.)
- **Architecture**: Must match system architecture (x64 for x64 systems)
- **File Format**: Standard Windows PE executable
- **Size**: Typically small (< 100KB for efficiency)

#### Binary Placement
- **Source Location**: Current directory (`.\bootexecute.exe`)
- **Target Location**: `C:\Windows\System32\bootexecute.exe`
- **Permissions**: Must be accessible to SYSTEM account

### Example Binary (Expected)

The script expects a compiled binary based on the [BootExecuteEDR project](https://github.com/rad9800/BootExecuteEDR) with the following characteristics:

```c
// Native application entry point
void NtProcessStartup(PPEB Peb) {
    // Minimal native code execution
    // Typically used to:
    // - Delete EDR/AV files
    // - Modify security configurations
    // - Establish persistence
    
    NtTerminateProcess(NtCurrentProcess(), 0);
}
```

## Execution Flow

### Phase 1: Pre-Execution Validation
1. **Privilege Check**: Verify administrator privileges
2. **Binary Validation**: Confirm source binary exists and is accessible
3. **System Check**: Validate System32 directory access

### Phase 2: State Backup
1. **Registry Backup**: Save current Boot Execute registry values
2. **Binary Check**: Verify target location is available
3. **State Recording**: Document current system configuration

### Phase 3: Bypass Implementation
1. **Binary Deployment**: Copy executable to `C:\Windows\System32\`
2. **Registry Configuration**: Add binary to selected Boot Execute key
3. **Permissions**: Ensure appropriate file and registry permissions

### Phase 4: Verification
1. **Binary Verification**: Confirm binary exists in System32
2. **Registry Verification**: Validate registry entry contains binary
3. **Accessibility Check**: Ensure configuration is properly formatted

### Phase 5: State Reversion (Default)
1. **Binary Removal**: Delete binary from System32
2. **Registry Restoration**: Restore original registry values
3. **Verification**: Confirm complete cleanup

## Success Criteria

### Bypass Success Indicators
- ✅ Binary successfully deployed to System32
- ✅ Registry key properly configured with binary entry
- ✅ No errors during configuration process

### Verification Checks
- **Binary Location**: `C:\Windows\System32\bootexecute.exe` exists
- **Registry Content**: Selected Boot Execute key contains binary name
- **Format Validation**: Registry value properly formatted as `REG_MULTI_SZ`

## Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Technique executed and reverted successfully |
| 1 | General Failure | Unspecified error occurred |
| 2 | Insufficient Privileges | Administrator rights required |
| 3 | Bypass Failure | Failed to implement bypass technique |
| 4 | Verification Failure | Bypass applied but verification failed |
| 5 | Reversion Failure | Bypass successful but cleanup failed |
| 6 | Binary Not Found | Source binary not available |

## Security Implications

### Attack Potential
- **Pre-Boot Execution**: Runs before security software initialization
- **SYSTEM Privileges**: Full administrator access during execution
- **Persistence**: Survives reboots and system updates
- **Stealth**: Minimal detection signatures during configuration

### Detection Vectors
- **Registry Monitoring**: Boot Execute keys frequently monitored by EDR
- **File System Events**: System32 file additions tracked
- **Boot Process Analysis**: Unusual boot-time execution patterns
- **Binary Analysis**: Non-standard executables in System32

### Evasion Considerations
- **Legitimate Names**: Use system-like executable names
- **Minimal Footprint**: Keep binary small and efficient
- **Clean Exit**: Ensure binary exits cleanly after execution
- **Timing**: Quick execution to minimize detection window

## Troubleshooting

### Common Issues

#### 1. Binary Not Found
```
ERROR: Source binary not available
Expected: .\bootexecute.exe
```
**Solution**: Ensure the native executable is present in the current directory.

#### 2. Access Denied
```
ERROR: Failed to deploy binary: Access to the path 'C:\Windows\System32\bootexecute.exe' is denied
```
**Solution**: Run PowerShell as Administrator.

#### 3. Registry Access Failure
```
ERROR: Failed to set Boot Execute registry: Access denied
```
**Solution**: Verify administrator privileges and ensure registry permissions.

#### 4. Binary Format Issues
```
WARNING: Source file is not an .exe file
```
**Solution**: Ensure the binary is a properly compiled native Windows executable.

### Debug Mode

Enable comprehensive debugging for troubleshooting:

```powershell
.\run.ps1 -Verbose -LogPath "C:\Temp\Debug" -SkipReversion
```

### Manual Verification

Check the configuration manually:

```powershell
# Check binary deployment
Test-Path "C:\Windows\System32\bootexecute.exe"

# Check registry configuration
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecuteNoPnpSync"
```

## Integration Examples

### Batch Testing
```powershell
# Test different registry methods
$methods = @("BootExecuteNoPnpSync", "SetupExecute", "PlatformExecute")
foreach ($method in $methods) {
    Write-Host "Testing method: $method"
    .\run.ps1 -RegistryMethod $method -LogPath "C:\Results\$method"
}
```

### Orchestrator Integration
```powershell
# Example automation script
$result = .\run.ps1 -LogPath "C:\TestResults" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "BootExecute bypass successful"
} else {
    Write-Host "BootExecute bypass failed with code $LASTEXITCODE"
}
```

## References

### Technical Documentation
- [Session Manager Registry Entries](https://docs.microsoft.com/en-us/windows/win32/sysinfo/session-manager-registry-entries)
- [Native API Programming](https://undocumented.ntinternals.net/)
- [Boot Configuration Data](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcd-boot-options-reference)

### Security Research
- [BootExecuteEDR Repository](https://github.com/rad9800/BootExecuteEDR) - Original implementation
- [Windows Boot Process Security](https://www.microsoft.com/en-us/research/publication/windows-boot-process-security/)

### Framework Integration
- [EDR Bypass Testing Framework](../../../README.md) - Main framework documentation
- [BP1001 Technique Overview](../BP1001-BootExecute.md) - Complete technique documentation

---

**Note**: This technique requires careful implementation and should only be used in authorized testing environments. The BootExecute mechanism can affect system stability if not properly implemented.