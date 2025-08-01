# BP1000.1 - Safe Mode Boot Bypass via bcdedit.exe

## Overview

This variant implements the **BP-1000.1** EDR bypass technique, which leverages Windows Safe Mode to disable or neutralize EDR agents. The technique uses the `bcdedit.exe` command-line tool to configure the system to boot into Safe Mode with Network on the next restart.

## Technique Details

**Technique ID:** BP1000.1  
**Technique Name:** Safe Mode Boot via bcdedit  
**Category:** EDR Driver Unload  
**Platform:** Windows Vista and later  

### How It Works

1. **Boot Configuration Modification**: Uses `bcdedit /set {current} safeboot network` to configure the system to boot into Safe Mode with Network
2. **EDR Bypass**: Most EDR agents and security software do not load in Safe Mode, effectively bypassing their protection
3. **Network Access**: Safe Mode with Network maintains network connectivity, allowing continued remote access
4. **State Restoration**: Uses `bcdedit /deletevalue {current} safeboot` to restore normal boot mode

### Command Sequence

```powershell
# Apply bypass
bcdedit /set {current} safeboot network

# Verify configuration
bcdedit /enum {current}

# Revert to normal boot
bcdedit /deletevalue {current} safeboot
```

## Script Features

### Core Functionality

- **Automated Execution**: Complete bypass workflow with verification and reversion
- **State Management**: Backs up original boot configuration and restores it after testing
- **Comprehensive Logging**: Detailed logging to centralized location for audit trail
- **Error Handling**: Robust error checking and graceful failure handling
- **Result Communication**: Standardized output format for test orchestrator integration

### Validation & Verification

- **Privilege Checking**: Verifies administrative privileges before execution
- **Tool Availability**: Confirms `bcdedit.exe` is available and accessible
- **Configuration Verification**: Validates that bypass was applied correctly
- **Reversion Validation**: Ensures system state is properly restored

### Logging & Monitoring

- **Centralized Logging**: All activities logged to `C:\EDRBypassTests\Logs\` by default
- **Multiple Log Levels**: INFO, WARN, ERROR, DEBUG for different verbosity needs
- **JSON Result Output**: Machine-readable test results for orchestrator consumption
- **Console Output**: Real-time progress indication with color coding

## Usage

### Standard Execution

```powershell
# Run the test with default settings
.\run.ps1
```

### Advanced Options

```powershell
# Custom log directory
.\run.ps1 -LogPath "D:\CustomLogs"

# Skip state reversion (for debugging)
.\run.ps1 -SkipReversion

# Verbose output
.\run.ps1 -Verbose

# Combined options
.\run.ps1 -LogPath "D:\TestLogs" -Verbose
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `LogPath` | String | `C:\EDRBypassTests\Logs` | Directory for log and result files |
| `SkipReversion` | Switch | `$false` | Skip state reversion for debugging |
| `Verbose` | Switch | `$false` | Enable verbose debug output |

## Requirements

### System Requirements

- **Operating System**: Windows Vista or later
- **Privileges**: Administrator privileges required
- **Tools**: `bcdedit.exe` (included with Windows)

### Permissions

The script requires administrator privileges to:
- Modify Boot Configuration Data (BCD)
- Execute `bcdedit.exe` commands
- Write to system log directories

## Output & Results

### Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Bypass applied and reverted successfully |
| 1 | General Failure | Unspecified error occurred |
| 2 | Insufficient Privileges | Administrator rights required |
| 3 | Bypass Application Failed | Could not apply the bypass |
| 4 | Bypass Verification Failed | Bypass not confirmed in BCD |
| 5 | Reversion Failed | Could not restore original state |

### Result Status Values

- **BYPASSED**: Technique executed successfully
- **FAILED**: Technique failed to execute
- **DETECTED**: Technique was blocked/detected
- **ERROR**: System error occurred

### Log Files

The script generates two types of output files:

1. **Log File**: `BP1000.1-bcdedit_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - All activities, errors, and debug information
   - Human-readable format

2. **Result File**: `BP1000.1-bcdedit_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1000.1",
  "TechniqueName": "Safe Mode Boot via bcdedit",
  "Status": "BYPASSED",
  "Message": "BP1000.1 bypass technique executed and verified successfully",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "OriginalSafebootValue": null,
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

```
TECHNIQUE_RESULT:BYPASSED|BP1000.1 bypass technique executed and verified successfully
```

### File Locations

- **Script**: `tests/BP1000-SafeModeBoot/BP1000.1-bcdedit/run.ps1`
- **Logs**: `C:\EDRBypassTests\Logs\` (configurable)
- **Results**: JSON files in same directory as logs

## Security Considerations

### Legitimate Use Cases

This technique is designed for:
- **Authorized Security Testing**: Evaluating EDR effectiveness in controlled environments
- **Red Team Exercises**: Simulating advanced persistent threat techniques
- **Security Research**: Understanding bypass methodologies for defensive improvements

### Risk Mitigation

- **Automatic Reversion**: Script automatically restores original boot configuration
- **Logging**: Complete audit trail of all activities
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- Registry modifications to BCD objects
- `bcdedit.exe` process execution with safeboot parameters
- Boot configuration changes
- Unusual Safe Mode boot patterns

## Troubleshooting

### Common Issues

1. **Access Denied Errors**
   - Solution: Run PowerShell as Administrator
   - Verification: Script checks privileges automatically

2. **bcdedit Command Not Found**
   - Solution: Ensure Windows system directories are in PATH
   - Verification: Script tests tool availability

3. **BCD Modification Failed**
   - Solution: Check system integrity with `sfc /scannow`
   - Alternative: Use different bypass variant (BP1000.2-1000.5)

4. **Logging Permission Errors**
   - Solution: Use `-LogPath` parameter to specify writable directory
   - Alternative: Run from directory with write permissions

### Debug Mode

Enable verbose logging for troubleshooting:

```powershell
.\run.ps1 -Verbose -LogPath "C:\Temp"
```

## Related Techniques

- **BP1000.2**: Safe Mode via msconfig.exe (GUI-based)
- **BP1000.3**: Safe Mode via PowerShell cmdlets (Windows 11 21H2+)
- **BP1000.4**: Safe Mode via registry editing
- **BP1000.5**: Safe Mode via BCD file overwrite

## References

- [Microsoft bcdedit Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit)
- [Boot Configuration Data Reference](https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm)
- [Windows Safe Mode Technical Details](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/safe-mode-boot-options)