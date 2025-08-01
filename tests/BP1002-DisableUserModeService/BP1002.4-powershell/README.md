# BP1002.4 - Disable EDR User-Mode Service via PowerShell Cmdlets

## Overview

This variant implements the **BP-1002.4** EDR bypass technique, which disables EDR user-mode services to stop them from protecting the system. The technique uses PowerShell service management cmdlets to stop and disable Windows services associated with EDR solutions, providing a native PowerShell approach to service manipulation.

## Technique Details

**Technique ID:** BP1002.4  
**Technique Name:** Disable EDR User-Mode Service via PowerShell Cmdlets  
**Category:** EDR Service Disruption  
**Platform:** Windows PowerShell 3.0+ / PowerShell Core  

### How It Works

1. **Service Identification**: Targets specific EDR services (default: Windows Defender ATP "SENSE" service)
2. **Service Termination**: Uses `Stop-Service -Name [service] -Force` to terminate the running service
3. **Service Disabling**: Uses `Set-Service -Name [service] -StartupType Disabled` to prevent service restart
4. **EDR Bypass**: Disabling EDR services removes real-time protection capabilities (immediately if stopped, after reboot if only disabled)
5. **State Restoration**: Re-enables and restarts the service after testing

### Partial Success Handling

The script handles scenarios where the service cannot be stopped immediately but can be disabled:

- **Full Success**: Service stopped AND disabled (immediate bypass)
- **Partial Success**: Service disabled but still running (bypass effective after reboot)
- **Failure**: Service cannot be disabled (no bypass achieved)

This approach recognizes that disabling a service achieves the bypass objective even if the current instance continues running, as the EDR protection will be absent after system restart.

### PowerShell Cmdlet Sequence

```powershell
# Stop the service
Stop-Service -Name SENSE -Force

# Disable the service (prevent restart)
Set-Service -Name SENSE -StartupType Disabled

# Verify service status
Get-Service -Name SENSE

# Restore service (revert)
Set-Service -Name SENSE -StartupType Automatic
Start-Service -Name SENSE
```

### Service Control Manager Integration

PowerShell service cmdlets route all requests through the Windows Service Control Manager (`services.exe`), which means:
- **Standard Services**: Can be stopped and disabled normally
- **PPL Protected Services**: Cannot be managed (access denied or invalid operation exceptions)
- **System Critical Services**: May have additional protection mechanisms

### Advantages over sc.exe

| Feature | PowerShell Cmdlets | sc.exe |
|---------|-------------------|--------|
| **Object-Oriented** | Returns .NET objects | Returns text output |
| **Error Handling** | Structured exceptions | Exit codes and text |
| **Type Safety** | Strongly-typed parameters | String-based commands |
| **Integration** | Native PowerShell | External process |
| **Timeout Management** | Built-in cmdlet timeouts | Manual process monitoring |

## Script Features

### Core Functionality

- **PowerShell Native**: Uses built-in service cmdlets without external dependencies
- **Enhanced Error Handling**: Structured exception handling for different failure scenarios
- **Object-Based Configuration**: Works with .NET ServiceController objects
- **Comprehensive Service Details**: Leverages both Get-Service and WMI for complete information
- **State Verification**: Uses PowerShell objects for precise state validation
- **Automatic Reversion**: Restores original service state after testing

### Validation & Verification

- **Privilege Checking**: Verifies administrative privileges before execution
- **Cmdlet Availability**: Confirms required PowerShell service cmdlets are loaded
- **Service Existence**: Validates target service exists using Get-Service
- **PPL Protection Detection**: Uses service properties and exception patterns to identify protected services
- **Configuration Verification**: Confirms service stop and disable operations using PowerShell objects
- **Reversion Validation**: Ensures service state is properly restored

### Logging & Monitoring

- **Centralized Logging**: All activities logged to `C:\EDRBypassTests\Logs\` by default
- **Multiple Log Levels**: INFO, WARN, ERROR, DEBUG for different verbosity needs
- **JSON Result Output**: Machine-readable test results for orchestrator consumption
- **Console Output**: Real-time progress indication with color coding
- **PowerShell Details**: Logs PowerShell version and cmdlet availability
- **Exception Details**: Structured exception type and message logging

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

# Extended service timeout (default: 30 seconds)
.\run.ps1 -ServiceTimeoutSeconds 60

# Skip state reversion (for debugging)
.\run.ps1 -SkipReversion

# Verbose output
.\run.ps1 -Verbose

# Combined options
.\run.ps1 -TargetService "SentinelAgent" -LogPath "D:\TestLogs" -ServiceTimeoutSeconds 45 -Verbose
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `TargetService` | String | `"SENSE"` | Name of the EDR service to target |
| `LogPath` | String | `C:\EDRBypassTests\Logs` | Directory for log and result files |
| `SkipReversion` | Switch | `$false` | Skip state reversion for debugging |
| `Verbose` | Switch | `$false` | Enable verbose debug output |
| `ServiceTimeoutSeconds` | Int | `30` | Timeout for service stop operations |

## Requirements

### System Requirements

- **PowerShell Version**: PowerShell 3.0 or later (service cmdlets)
- **Operating System**: Windows Vista or later
- **Privileges**: Administrator privileges required
- **Target Service**: Must exist and not be PPL protected

### PowerShell Cmdlet Dependencies

| Cmdlet | Purpose | Availability |
|--------|---------|--------------|
| `Get-Service` | Query service information | PowerShell 1.0+ |
| `Stop-Service` | Stop running services | PowerShell 1.0+ |
| `Start-Service` | Start stopped services | PowerShell 1.0+ |
| `Set-Service` | Modify service configuration | PowerShell 3.0+ |

### Permissions

The script requires administrator privileges to:
- Stop and disable Windows services via PowerShell cmdlets
- Modify service configuration through Service Control Manager
- Write to system log directories

## PowerShell Service Object Properties

### ServiceController Properties

```powershell
# Key properties available from Get-Service
$service = Get-Service -Name SENSE
$service.Status         # Running, Stopped, etc.
$service.StartType      # Automatic, Manual, Disabled
$service.CanStop        # Boolean - indicates if service can be stopped
$service.CanShutdown    # Boolean - responds to system shutdown
$service.ServiceType    # Win32OwnProcess, Win32ShareProcess, etc.
```

### WMI Service Properties

```powershell
# Additional details from WMI
$wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='SENSE'"
$wmiService.ProcessId   # Process ID of service
$wmiService.PathName    # Executable path
$wmiService.StartName   # Service account
```

## Exception Handling

### Common PowerShell Service Exceptions

| Exception Type | Typical Cause | Handling |
|----------------|---------------|----------|
| `TimeoutException` | Service stop timeout | Retry or force termination |
| `InvalidOperationException` | PPL protection or service state | Identify protection level |
| `Win32Exception` | Access denied or system error | Check privileges and protection |
| `ServiceNotRunning` | Service already stopped | Continue with disable operation |

### PPL Detection via Exceptions

```powershell
try {
    Stop-Service -Name $ServiceName -Force
}
catch [System.InvalidOperationException] {
    # Likely PPL protected
}
catch [System.ComponentModel.Win32Exception] {
    # Access denied - may indicate PPL
}
```

## Output & Results

### Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Service disabled and reverted successfully |
| 1 | General Failure | Unspecified error occurred |
| 2 | Insufficient Privileges | Administrator rights required |
| 3 | Service Stop Failed | Could not stop the target service |
| 4 | Service Disable Failed | Could not disable the target service |
| 5 | Service Verification Failed | Bypass not confirmed |
| 6 | Service Reversion Failed | Could not restore original state |
| 7 | Target Service Not Found | Service does not exist on system |
| 8 | Service is PPL Protected | Cannot manage PPL-protected service |

### Result Status Values

- **BYPASSED**: Technique executed successfully
- **FAILED**: Technique failed to execute
- **DETECTED**: Technique was blocked/detected
- **ERROR**: System error occurred

### Log Files

The script generates two types of output files:

1. **Log File**: `BP1002.4-powershell_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - PowerShell cmdlet execution details
   - Service object properties and state changes
   - Exception types and structured error messages
   - Human-readable format

2. **Result File**: `BP1002.4-powershell_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1002.4",
  "TechniqueName": "Disable EDR User-Mode Service via PowerShell Cmdlets",
  "Status": "BYPASSED",
  "Message": "BP1002.4 PowerShell service bypass technique executed and verified successfully",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "TargetService": "SENSE",
    "OriginalConfiguration": {
      "ServiceName": "SENSE",
      "DisplayName": "Windows Defender Advanced Threat Protection Service",
      "Status": "Running",
      "StartType": "Automatic",
      "CanStop": true,
      "CanShutdown": false,
      "ServiceType": "Win32OwnProcess",
      "ProcessId": 1234,
      "Exists": true
    },
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true,
    "ServiceTimeoutSeconds": 30,
    "PPLProtected": false,
    "PowerShellVersion": "5.1.19041.4412",
    "PartialSuccess": false,
    "ServiceStopped": true,
    "RebootRequired": false
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

**Full Success:**
```
TECHNIQUE_RESULT:BYPASSED|BP1002.4 PowerShell service bypass technique executed and verified successfully
```

**Partial Success (Reboot Required):**
```
TECHNIQUE_RESULT:BYPASSED|BP1002.4 PowerShell service bypass technique executed successfully (service disabled, effective after reboot)
```

### File Locations

- **Script**: `tests/BP1002-DisableUserModeService/BP1002.4-powershell/run.ps1`
- **Logs**: `C:\EDRBypassTests\Logs\` (configurable)
- **Results**: JSON files in same directory as logs

## Security Considerations

### Legitimate Use Cases

This technique is designed for:
- **Authorized Security Testing**: Evaluating EDR service resilience in controlled environments
- **Red Team Exercises**: Simulating PowerShell-based service disruption attacks
- **Security Research**: Understanding PowerShell service management capabilities

### Risk Mitigation

- **Automatic Reversion**: Script automatically restores original service configuration
- **PowerShell Execution Policy**: May be restricted by execution policies
- **Privilege Requirements**: Requires administrator access (limits casual abuse)
- **Logging**: Complete audit trail of all service modifications
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- PowerShell service cmdlet execution (`Stop-Service`, `Set-Service`)
- PowerShell script execution with service management parameters
- Service Control Manager API calls from PowerShell processes
- Service state changes (running → stopped, auto → disabled)
- PowerShell module loading patterns for service management
- Process termination of EDR service processes via PowerShell

## Troubleshooting

### Common Issues

1. **PowerShell Execution Policy**
   - **Error**: Script execution blocked by execution policy
   - **Solution**: Set execution policy with `Set-ExecutionPolicy RemoteSigned`
   - **Alternative**: Use `-ExecutionPolicy Bypass` parameter

2. **Access Denied Errors**
   - **Error**: `Win32Exception` or `InvalidOperationException`
   - **Solution**: Run PowerShell as Administrator
   - **Check**: Verify service is not PPL protected

3. **Cmdlet Not Found**
   - **Error**: "The term 'Set-Service' is not recognized"
   - **Solution**: Upgrade to PowerShell 3.0 or later
   - **Check**: Run `Get-Command *Service` to verify availability

4. **Service Cannot Be Stopped**
   - **Error**: `InvalidOperationException` when calling Stop-Service
   - **Causes**: PPL protection, service dependencies, critical system service
   - **Solution**: Check `$service.CanStop` property and dependencies

5. **Service Timeout During Stop**
   - **Issue**: Service takes longer than timeout to stop
   - **Solution**: Increase `-ServiceTimeoutSeconds` parameter
   - **Alternative**: Check for hung processes or dependencies

6. **Partial Success Scenarios**
   - **Scenario**: Service disabled but still running
   - **Result**: Script reports success with "reboot required" message
   - **Action**: EDR bypass will be effective after system restart
   - **Verification**: Check `PartialSuccess` and `RebootRequired` fields in result JSON

### Debug Mode

Enable comprehensive debugging:

```powershell
.\run.ps1 -TargetService "SENSE" -Verbose -ServiceTimeoutSeconds 60 -LogPath "C:\Temp"
```

### Manual PowerShell Service Inspection

Verify service operations manually:

```powershell
# Check service details
Get-Service -Name SENSE | Format-List *

# Check WMI service information
Get-WmiObject -Class Win32_Service -Filter "Name='SENSE'" | Format-List *

# List all services with specific patterns
Get-Service | Where-Object {$_.Name -match "Sense|Defender|Security"}

# Check service dependencies
(Get-Service -Name SENSE).DependentServices
(Get-Service -Name SENSE).ServicesDependedOn
```

## Performance Considerations

### Execution Time

- **Normal Execution**: 5-20 seconds
- **Service Stop**: 1-10 seconds (depends on service)
- **Service Disable**: < 1 second
- **Verification**: 1-3 seconds

### Resource Usage

- **Memory**: Low (< 30MB during execution)
- **CPU**: Low (brief spikes during cmdlet execution)
- **Disk**: Minimal (log files only)
- **Network**: None (local operations only)

### PowerShell Cmdlet Performance

PowerShell service cmdlets offer several performance advantages:
- **No External Process**: Direct .NET API calls instead of spawning sc.exe
- **Object-Based**: No text parsing overhead
- **Built-in Timeouts**: Automatic timeout handling
- **Exception Handling**: Structured error information

## Comparison with Other BP1002 Variants

| Variant | Method | Interface | PPL Support | Object-Oriented | Error Handling |
|---------|--------|-----------|-------------|-----------------|----------------|
| BP1002.1 | services.msc | GUI | No | No | Basic |
| BP1002.2 | msconfig.exe | GUI | No | No | Basic |
| BP1002.3 | sc.exe | CLI | No | No | Exit codes |
| **BP1002.4** | **PowerShell cmdlets** | **PowerShell** | **No** | **Yes** | **Structured** |
| BP1002.5 | reg.exe | CLI | Partial | No | Exit codes |
| BP1002.6 | Registry save/restore | CLI | Yes | No | Exit codes |

### When to Use BP1002.4

**Advantages:**
- Native PowerShell integration
- Object-oriented approach
- Superior error handling
- No external process dependencies
- Built-in timeout management
- Strongly-typed parameters

**Disadvantages:**
- PowerShell execution policy restrictions
- Cannot affect PPL services
- May be more closely monitored in PowerShell logs
- Requires PowerShell 3.0+ for full functionality

## Advanced Techniques

### Bulk Service Management

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

### Service Dependency Analysis

```powershell
# Analyze service dependencies
$service = Get-Service -Name SENSE
Write-Host "Services that depend on $($service.Name):"
$service.DependentServices | Format-Table Name, Status

Write-Host "Services that $($service.Name) depends on:"
$service.ServicesDependedOn | Format-Table Name, Status
```

### Custom Service Discovery

```powershell
# Find EDR-related services using advanced filtering
Get-Service | Where-Object {
    $_.DisplayName -match "Defender|Security|Antivirus|EDR|Endpoint" -or
    $_.Name -match "Sense|Defender|Security|Av|Edr"
} | Select-Object Name, DisplayName, Status, StartType
```

## Related Techniques

- **BP1002.1**: Disable service using services.msc (GUI-based)
- **BP1002.2**: Disable service using msconfig.exe (GUI-based)
- **BP1002.3**: Disable service using sc.exe (command-line)
- **BP1002.5**: Disable service using reg.exe (registry editing)
- **BP1002.6**: Disable service using registry save/restore (PPL bypass)

## References

- [PowerShell Service Cmdlets Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/#service-cmdlets)
- [Windows Service Control Manager](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)
- [PowerShell Execution Policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
- [Process Protection Level (PPL)](https://docs.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [Windows Service Security](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)