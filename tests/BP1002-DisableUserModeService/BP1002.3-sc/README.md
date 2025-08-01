# BP1002.3 - Disable EDR User-Mode Service via sc.exe

## Overview

This variant implements the **BP-1002.3** EDR bypass technique, which disables EDR user-mode services to stop them from protecting the system. The technique uses the `sc.exe` command-line tool to stop and disable Windows services associated with EDR solutions, routing requests through the Service Control Manager.

## Technique Details

**Technique ID:** BP1002.3  
**Technique Name:** Disable EDR User-Mode Service via sc.exe  
**Category:** EDR Service Disruption  
**Platform:** Windows Vista and later  

### How It Works

1. **Service Identification**: Targets specific EDR services (default: Windows Defender ATP "SENSE" service)
2. **Service Termination**: Uses `sc stop [service]` to terminate the running service
3. **Service Disabling**: Uses `sc config [service] start=disabled` to prevent service restart
4. **EDR Bypass**: Disabling EDR services removes real-time protection capabilities
5. **State Restoration**: Re-enables and restarts the service after testing

### Command Sequence

```cmd
# Stop the service
sc stop SENSE

# Disable the service (prevent restart)
sc config SENSE start=disabled

# Verify service status
sc query SENSE

# Restore service (revert)
sc config SENSE start=auto
sc start SENSE
```

### Service Control Manager Integration

The `sc.exe` tool routes all requests through the Windows Service Control Manager (`services.exe`), which means:
- **Standard Services**: Can be stopped and disabled normally
- **PPL Protected Services**: Cannot be managed (access denied errors)
- **System Critical Services**: May have additional protection mechanisms

## Script Features

### Core Functionality

- **Configurable Target Service**: Default SENSE service with parameter override capability
- **Service State Management**: Complete backup and restoration of original service configuration
- **Comprehensive Error Handling**: Specific handling for PPL protection and access denied scenarios
- **Timeout Management**: Configurable timeouts for service stop operations
- **State Verification**: Confirms both service stop and disable operations succeeded
- **Automatic Reversion**: Restores original service state after testing

### Validation & Verification

- **Privilege Checking**: Verifies administrative privileges before execution
- **Tool Availability**: Confirms `sc.exe` is available and accessible
- **Service Existence**: Validates target service exists on the system
- **PPL Protection Detection**: Attempts to identify PPL-protected services
- **Configuration Verification**: Confirms service stop and disable operations
- **Reversion Validation**: Ensures service state is properly restored

### Logging & Monitoring

- **Centralized Logging**: All activities logged to `C:\EDRBypassTests\Logs\` by default
- **Multiple Log Levels**: INFO, WARN, ERROR, DEBUG for different verbosity needs
- **JSON Result Output**: Machine-readable test results for orchestrator consumption
- **Console Output**: Real-time progress indication with color coding
- **Service Details**: Logs service configuration, state changes, and process information

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

- **Operating System**: Windows Vista or later
- **Privileges**: Administrator privileges required
- **Tools**: `sc.exe` (included with Windows)
- **Target Service**: Must exist and not be PPL protected

### Permissions

The script requires administrator privileges to:
- Stop and disable Windows services
- Modify service configuration via Service Control Manager
- Write to system log directories

### Service Protection Levels

| Protection Level | sc.exe Support | Notes |
|------------------|----------------|--------|
| **Standard Services** | ✅ Full Support | Can stop, disable, and reconfigure |
| **Protected Services** | ⚠️ Limited | May have restricted operations |
| **PPL Services** | ❌ No Support | Access denied by Service Control Manager |
| **System Critical** | ⚠️ Limited | May prevent system operation if disabled |

## Common EDR Services

### Windows Defender ATP
- **Service Name**: `SENSE`
- **Display Name**: Windows Defender Advanced Threat Protection Service
- **Typical Protection**: Standard (can be disabled)

### Windows Defender Antivirus
- **Service Name**: `WinDefend`
- **Display Name**: Windows Defender Antivirus Service
- **Typical Protection**: Standard to Protected

### Microsoft Defender Antimalware
- **Service Name**: `MsMpSvc`
- **Display Name**: Microsoft Defender Antimalware Service
- **Typical Protection**: Standard to Protected

### Third-Party EDR Examples
- **CrowdStrike**: `CSFalconService`
- **SentinelOne**: `SentinelAgent`, `SentinelHelperService`
- **Cylance**: `CylanceSvc`
- **Carbon Black**: `CbDefense`

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

1. **Log File**: `BP1002.3-sc_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - Service configuration details and state changes
   - All activities, errors, and debug information
   - Human-readable format

2. **Result File**: `BP1002.3-sc_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1002.3",
  "TechniqueName": "Disable EDR User-Mode Service via sc.exe",
  "Status": "BYPASSED",
  "Message": "BP1002.3 service bypass technique executed and verified successfully",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "TargetService": "SENSE",
    "OriginalConfiguration": {
      "ServiceName": "SENSE",
      "DisplayName": "Windows Defender Advanced Threat Protection Service",
      "StartType": "auto",
      "State": "RUNNING",
      "AcceptStop": true,
      "ProcessId": 1234,
      "Exists": true
    },
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true,
    "ServiceTimeoutSeconds": 30,
    "PPLProtected": false
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

```
TECHNIQUE_RESULT:BYPASSED|BP1002.3 service bypass technique executed and verified successfully
```

### File Locations

- **Script**: `tests/BP1002-DisableUserModeService/BP1002.3-sc/run.ps1`
- **Logs**: `C:\EDRBypassTests\Logs\` (configurable)
- **Results**: JSON files in same directory as logs

## Security Considerations

### Legitimate Use Cases

This technique is designed for:
- **Authorized Security Testing**: Evaluating EDR service resilience in controlled environments
- **Red Team Exercises**: Simulating service disruption attacks
- **Security Research**: Understanding service protection mechanisms

### Risk Mitigation

- **Automatic Reversion**: Script automatically restores original service configuration
- **Privilege Requirements**: Requires administrator access (limits casual abuse)
- **Logging**: Complete audit trail of all service modifications
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- `sc.exe` process execution with service management parameters
- Service Control Manager API calls for stop/disable operations
- Service state changes (running → stopped, auto → disabled)
- Process termination of EDR service processes
- Registry modifications to service configuration keys

## Troubleshooting

### Common Issues

1. **Access Denied Errors**
   - **Error**: sc.exe returns error code 5
   - **Solution**: Run PowerShell as Administrator
   - **Alternative**: Check if service is PPL protected

2. **Target Service Not Found**
   - **Error**: "Target service 'ServiceName' not found on this system"
   - **Solution**: Verify service name spelling and existence
   - **Check**: Use `sc query` or `Get-Service` to list services

3. **PPL Protected Service**
   - **Error**: "Service appears to be PPL protected"
   - **Solution**: Use different bypass technique (registry manipulation)
   - **Alternative**: Target different EDR service component

4. **Service Cannot Be Stopped**
   - **Error**: Service stop operation fails
   - **Causes**: Service dependencies, critical system service
   - **Solution**: Check service dependencies with `sc qc ServiceName`

5. **Service Restart Fails During Reversion**
   - **Issue**: Service configuration restored but won't restart
   - **Solution**: Manual restart or system reboot may be required
   - **Check**: Verify service dependencies and system state

### Debug Mode

Enable comprehensive debugging:

```powershell
.\run.ps1 -TargetService "SENSE" -Verbose -ServiceTimeoutSeconds 60 -LogPath "C:\Temp"
```

### Manual Service Inspection

Verify service operations manually:

```cmd
# Check service configuration
sc qc SENSE

# Check service status
sc query SENSE

# List all services
sc query type=service state=all

# Check service dependencies
sc enumdepend SENSE
```

## Performance Considerations

### Execution Time

- **Normal Execution**: 10-30 seconds
- **Service Stop**: 1-10 seconds (depends on service)
- **Service Disable**: 1-3 seconds
- **Verification**: 2-5 seconds

### Resource Usage

- **Memory**: Low (< 20MB during execution)
- **CPU**: Low (brief spikes during service operations)
- **Disk**: Minimal (log files only)
- **Network**: None (local operations only)

### Service Stop Considerations

Different services have varying stop characteristics:
- **Lightweight Services**: Stop in 1-3 seconds
- **Complex Services**: May take 10-30 seconds
- **Services with Dependencies**: May require dependency stops first
- **Hung Services**: May require force termination

## Comparison with Other BP1002 Variants

| Variant | Method | Tool | PPL Support | GUI Required | Stealth Level |
|---------|--------|------|-------------|--------------|---------------|
| BP1002.1 | services.msc | GUI | No | Yes | Low |
| BP1002.2 | msconfig.exe | GUI | No | Yes | Low |
| **BP1002.3** | **sc.exe** | **CLI** | **No** | **No** | **Medium** |
| BP1002.4 | PowerShell | Cmdlets | No | No | Medium |
| BP1002.5 | reg.exe | CLI | Partial | No | High |
| BP1002.6 | Registry save/restore | CLI | Yes | No | High |

### When to Use BP1002.3

**Advantages:**
- Command-line interface (scriptable)
- No GUI dependency
- Standard Windows tool
- Clear error reporting
- Fast execution

**Disadvantages:**
- Cannot affect PPL services
- Requires Service Control Manager
- May be monitored/logged
- Administrator privileges required

## Advanced Techniques

### Multiple Service Targeting

```powershell
# Target multiple services in sequence
$services = @("SENSE", "WinDefend", "MsMpSvc")
foreach ($service in $services) {
    .\run.ps1 -TargetService $service -SkipReversion
}
```

### Service Dependency Analysis

```cmd
# Check what depends on a service
sc enumdepend SENSE

# Check what a service depends on
sc qc SENSE | findstr DEPENDENCIES
```

### Custom Service Discovery

```powershell
# Find EDR-related services
Get-Service | Where-Object {$_.DisplayName -match "Defender|Security|Antivirus|EDR"}

# Check service executable paths
sc qc SENSE | findstr BINARY_PATH_NAME
```

## Related Techniques

- **BP1002.1**: Disable service using services.msc (GUI-based)
- **BP1002.2**: Disable service using msconfig.exe (GUI-based)
- **BP1002.4**: Disable service using PowerShell cmdlets
- **BP1002.5**: Disable service using reg.exe (registry editing)
- **BP1002.6**: Disable service using registry save/restore (PPL bypass)

## References

- [Microsoft sc.exe Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc)
- [Windows Service Control Manager](https://docs.microsoft.com/en-us/windows/win32/services/service-control-manager)
- [Process Protection Level (PPL)](https://docs.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [Windows Service Security](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)