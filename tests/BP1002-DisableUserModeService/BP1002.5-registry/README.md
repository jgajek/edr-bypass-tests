# BP1002.5 - Disable EDR User-Mode Service via PowerShell Registry Manipulation

## Overview

This variant implements the **BP-1002.5** EDR bypass technique, which disables EDR user-mode services by directly modifying their registry configuration. The technique uses PowerShell registry cmdlets to bypass Service Control Manager protections and can potentially affect PPL-protected services if their registry keys are not additionally protected.

## Technique Details

**Technique ID:** BP1002.5  
**Technique Name:** Disable EDR User-Mode Service via PowerShell Registry Manipulation  
**Category:** EDR Service Disruption  
**Platform:** Windows Vista and later  

### How It Works

1. **Registry Direct Access**: Bypasses Service Control Manager by directly modifying service registry keys
2. **Start Value Modification**: Changes the `Start` value in `HKLM\SYSTEM\CurrentControlSet\Services\[ServiceName]`
3. **PPL Bypass Potential**: Can potentially affect PPL-protected services if registry keys aren't protected
4. **Reboot-Effective**: Changes take effect after system restart
5. **State Restoration**: Restores original registry values after testing

### Registry Path Structure

```
HKLM\SYSTEM\CurrentControlSet\Services\[ServiceName]\Start
```

### Service Start Values

The `Start` registry value controls service startup behavior:

| Value | Startup Type | Description |
|-------|-------------|-------------|
| 0 | Boot | Loaded by kernel loader |
| 1 | System | Loaded by I/O subsystem |
| 2 | Automatic | Started by Service Control Manager at boot |
| 3 | Manual | Started on demand |
| **4** | **Disabled** | **Service cannot start** |

### PowerShell Registry Operations

```powershell
# Read current Start value
$currentStart = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SENSE" -Name "Start").Start

# Disable service (set Start=4)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SENSE" -Name "Start" -Value 4 -Type DWord

# Restore original value
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SENSE" -Name "Start" -Value $originalStart -Type DWord
```

### Service Control Manager Bypass

This technique bypasses SCM protections by:
- **Direct Registry Access**: No API calls to Service Control Manager
- **Kernel-Level Enforcement**: Changes enforced at boot time by kernel
- **PPL Independence**: Registry access doesn't require service-level permissions
- **Boot-Time Processing**: Start value read during system initialization

## Script Features

### Core Functionality

- **Registry-Native**: Uses PowerShell registry cmdlets for direct access
- **PPL Compatibility**: Can potentially affect PPL-protected services
- **Comprehensive Backup**: Complete service registry configuration preservation
- **Verification System**: Confirms registry changes were applied correctly
- **Error Classification**: Specific handling for access denied and security exceptions
- **Automatic Reversion**: Restores original registry state after testing

### Validation & Verification

- **Privilege Checking**: Verifies administrative privileges before execution
- **Service Existence**: Confirms target service exists on the system
- **Registry Access**: Validates access to service registry keys
- **Configuration Verification**: Confirms Start value was modified correctly
- **Reversion Validation**: Ensures original registry state is restored

### Logging & Monitoring

- **Centralized Logging**: All activities logged to `C:\EDRBypassTests\Logs\` by default
- **Multiple Log Levels**: INFO, WARN, ERROR, DEBUG for different verbosity needs
- **JSON Result Output**: Machine-readable test results for orchestrator consumption
- **Console Output**: Real-time progress indication with color coding
- **Registry Details**: Logs registry paths, values, and modification results

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
# Custom target service and log directory
.\run.ps1 -TargetService "CylanceSvc" -LogPath "D:\CustomLogs"

# Skip state reversion (for debugging)
.\run.ps1 -SkipReversion

# Verbose output
.\run.ps1 -Verbose

# Combined options
.\run.ps1 -TargetService "SentinelAgent" -LogPath "D:\TestLogs" -Verbose
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `TargetService` | String | `"SENSE"` | Name of the EDR service to target |
| `LogPath` | String | `C:\EDRBypassTests\Logs` | Directory for log and result files |
| `SkipReversion` | Switch | `$false` | Skip state reversion for debugging |
| `Verbose` | Switch | `$false` | Enable verbose debug output |

## Requirements

### System Requirements

- **Operating System**: Windows Vista or later
- **Privileges**: Administrator privileges required
- **Registry Access**: Access to `HKLM\SYSTEM\CurrentControlSet\Services`
- **PowerShell**: PowerShell 3.0 or later (registry cmdlets)

### Permissions

The script requires administrator privileges to:
- Modify registry keys under `HKLM\SYSTEM\CurrentControlSet\Services`
- Read service registry configuration
- Write to system log directories

### Registry Access Patterns

| Service Type | Registry Protection | Access Result |
|-------------|-------------------|---------------|
| **Standard Services** | Basic ACLs | ✅ Full Access |
| **Protected Services** | Enhanced ACLs | ⚠️ May require additional permissions |
| **PPL Services** | Service-level protection | ✅ Registry may be accessible |
| **System Critical** | Registry protection | ❌ May be denied |

## PPL Service Compatibility

### Key Advantage over Other Variants

Unlike BP1002.1-1002.4, this technique can potentially affect PPL-protected services because:

- **Registry vs. Service Level**: PPL protection is at the service/process level, not necessarily registry
- **Boot-Time Enforcement**: Start value is read during system initialization, before PPL activation
- **Kernel Processing**: Service startup decisions made by kernel before user-mode protections
- **Access Path**: Direct registry modification bypasses service control APIs

### PPL Protection Scenarios

| Scenario | Registry Access | Service Control | BP1002.5 Effectiveness |
|----------|----------------|-----------------|-------------------------|
| **Standard Service** | ✅ Allowed | ✅ Allowed | ✅ Full effectiveness |
| **PPL + Registry Protected** | ❌ Denied | ❌ Denied | ❌ Cannot modify |
| **PPL + Registry Accessible** | ✅ Allowed | ❌ Denied | ✅ **Bypass possible** |
| **Critical System Service** | ❌ Denied | ❌ Denied | ❌ Cannot modify |

## Output & Results

### Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Registry modified and reverted successfully |
| 1 | General Failure | Unspecified error occurred |
| 2 | Insufficient Privileges | Administrator rights required |
| 3 | Registry Modification Failed | Could not modify registry |
| 4 | Registry Verification Failed | Modification not confirmed |
| 5 | Registry Reversion Failed | Could not restore original state |
| 6 | Target Service Not Found | Service does not exist on system |
| 7 | Service Registry Key Not Accessible | Cannot access registry key |

### Result Status Values

- **BYPASSED**: Technique executed successfully
- **FAILED**: Technique failed to execute
- **DETECTED**: Technique was blocked/detected
- **ERROR**: System error occurred

### Log Files

The script generates two types of output files:

1. **Log File**: `BP1002.5-registry_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - Registry paths and value modifications
   - All activities, errors, and debug information
   - Human-readable format

2. **Result File**: `BP1002.5-registry_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1002.5",
  "TechniqueName": "Disable EDR User-Mode Service via PowerShell Registry Manipulation",
  "Status": "BYPASSED",
  "Message": "BP1002.5 registry bypass technique executed successfully (service disabled via registry, effective after reboot)",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "TargetService": "SENSE",
    "OriginalConfiguration": {
      "ServiceName": "SENSE",
      "RegistryPath": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SENSE",
      "StartValue": 2,
      "DisplayName": "Windows Defender Advanced Threat Protection Service",
      "ImagePath": "\"C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe\"",
      "ServiceStatus": "Running",
      "StartDescription": "Automatic",
      "Exists": true
    },
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true,
    "RegistryPath": "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SENSE",
    "BypassMethod": "Registry Start Value Modification",
    "RebootRequired": true
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

```
TECHNIQUE_RESULT:BYPASSED|BP1002.5 registry bypass technique executed successfully (service disabled via registry, effective after reboot)
```

### File Locations

- **Script**: `tests/BP1002-DisableUserModeService/BP1002.5-registry/run.ps1`
- **Logs**: `C:\EDRBypassTests\Logs\` (configurable)
- **Results**: JSON files in same directory as logs

## Security Considerations

### Legitimate Use Cases

This technique is designed for:
- **Authorized Security Testing**: Evaluating EDR service resilience in controlled environments
- **Red Team Exercises**: Simulating registry-based service disruption attacks
- **PPL Bypass Research**: Understanding service protection limitations

### Risk Mitigation

- **Automatic Reversion**: Script automatically restores original registry configuration
- **Reboot Requirement**: Changes only effective after restart (limits immediate impact)
- **Privilege Requirements**: Requires administrator access (limits casual abuse)
- **Logging**: Complete audit trail of all registry modifications
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- Registry modifications to `HKLM\SYSTEM\CurrentControlSet\Services\*\Start`
- PowerShell registry cmdlet execution patterns
- Process access to service registry keys
- Registry value changes for security-related services
- Direct registry modification without corresponding SCM activity

## Troubleshooting

### Common Issues

1. **Access Denied to Registry Key**
   - **Error**: `SecurityException` or `UnauthorizedAccessException`
   - **Solution**: Verify administrator privileges and registry permissions
   - **Check**: Use `Get-Acl` to examine registry key permissions

2. **Service Registry Key Not Found**
   - **Error**: "Service registry key does not exist"
   - **Solution**: Verify service name spelling and installation
   - **Check**: Use `Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services"` to list services

3. **Registry Value Type Mismatch**
   - **Issue**: Start value not properly set
   - **Solution**: Ensure `-Type DWord` parameter is used
   - **Verification**: Check value type with `Get-ItemProperty`

4. **PPL Registry Protection**
   - **Error**: Access denied despite administrator privileges
   - **Cause**: Some PPL services have registry-level protection
   - **Alternative**: This indicates robust protection implementation

5. **System Critical Service**
   - **Warning**: Disabling may affect system stability
   - **Caution**: Only test on isolated systems
   - **Recovery**: Ensure automatic reversion is enabled

### Debug Mode

Enable comprehensive debugging:

```powershell
.\run.ps1 -TargetService "SENSE" -Verbose -LogPath "C:\Temp"
```

### Manual Registry Inspection

Verify registry operations manually:

```powershell
# Check service registry key
$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\SENSE"
Get-ItemProperty -Path $servicePath | Format-List

# Check Start value specifically
(Get-ItemProperty -Path $servicePath -Name "Start").Start

# List all service registry keys
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object {$_.Name -match "Sense|Defender"}
```

## Performance Considerations

### Execution Time

- **Normal Execution**: 3-10 seconds
- **Registry Modification**: < 1 second
- **Verification**: 1-2 seconds
- **Reversion**: < 1 second

### Resource Usage

- **Memory**: Low (< 20MB during execution)
- **CPU**: Low (minimal registry operations)
- **Disk**: Minimal (log files only)
- **Network**: None (local operations only)

### Registry Performance

Registry operations are very fast because:
- **In-Memory Access**: Registry is memory-mapped
- **Single Value Changes**: Only modifying one DWORD value
- **No External Processes**: Direct PowerShell cmdlet execution

## Comparison with Other BP1002 Variants

| Variant | Method | PPL Support | Immediate Effect | Stealth Level | Reboot Required |
|---------|--------|-------------|------------------|---------------|-----------------|
| BP1002.1 | services.msc | No | Yes | Low | No |
| BP1002.2 | msconfig.exe | No | No | Low | Yes |
| BP1002.3 | sc.exe | No | Yes | Medium | No |
| BP1002.4 | PowerShell cmdlets | No | Yes | Medium | No |
| **BP1002.5** | **Registry manipulation** | **Partial** | **No** | **High** | **Yes** |
| BP1002.6 | Registry save/restore | Yes | No | High | Yes |

### When to Use BP1002.5

**Advantages:**
- Potential PPL service compatibility
- High stealth (no SCM interaction)
- Direct registry control
- No external tool dependencies
- Fast execution

**Disadvantages:**
- Requires system reboot for effect
- May trigger registry monitoring
- Administrator privileges required
- Some services may have registry protection

## Advanced Techniques

### Bulk Service Targeting

```powershell
# Target multiple EDR services
$edrServices = @("SENSE", "WinDefend", "MsMpSvc")
foreach ($service in $edrServices) {
    try {
        .\run.ps1 -TargetService $service -SkipReversion
        Write-Host "Successfully processed $service" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to process $service`: $_"
    }
}
```

### Registry Permission Analysis

```powershell
# Analyze service registry permissions
$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\SENSE"
$acl = Get-Acl -Path $servicePath
$acl.Access | Format-Table IdentityReference, AccessControlType, RegistryRights
```

### Service Discovery via Registry

```powershell
# Find EDR services via registry
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
    $service = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
    if ($service.DisplayName -match "Defender|Security|Antivirus|EDR|Endpoint") {
        [PSCustomObject]@{
            Name = $_.PSChildName
            DisplayName = $service.DisplayName
            Start = $service.Start
            ImagePath = $service.ImagePath
        }
    }
}
```

## Related Techniques

- **BP1002.1**: Disable service using services.msc (GUI-based)
- **BP1002.2**: Disable service using msconfig.exe (GUI-based)
- **BP1002.3**: Disable service using sc.exe (command-line)
- **BP1002.4**: Disable service using PowerShell cmdlets
- **BP1002.6**: Disable service using registry save/restore (advanced PPL bypass)

## References

- [Windows Service Registry Structure](https://docs.microsoft.com/en-us/windows/win32/services/service-configuration)
- [PowerShell Registry Provider](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_registry)
- [Windows Registry Security](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-security-and-access-rights)
- [Process Protection Level (PPL)](https://docs.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [Service Control Manager Architecture](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)