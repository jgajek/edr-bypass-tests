# BP1000.2 - Safe Mode Boot Bypass via msconfig.exe (GUI)

## Overview

This variant implements the **BP-1000.2** EDR bypass technique, which leverages Windows Safe Mode to disable or neutralize EDR agents. The technique uses the System Configuration utility (`msconfig.exe`) with GUI automation to configure the system to boot into Safe Mode with Network on the next restart.

## Technique Details

**Technique ID:** BP1000.2  
**Technique Name:** Safe Mode Boot via msconfig (GUI)  
**Category:** EDR Driver Unload  
**Platform:** Windows Vista and later  

### How It Works

1. **GUI Automation**: Uses AutoIt script to manipulate the `msconfig.exe` interface automatically
2. **Boot Configuration**: Navigates to the Boot tab and enables "Safe boot" with "Network" option
3. **EDR Bypass**: Most EDR agents and security software do not load in Safe Mode, effectively bypassing their protection
4. **Network Access**: Safe Mode with Network maintains network connectivity, allowing continued remote access
5. **State Restoration**: Uses `bcdedit` command to restore normal boot mode after testing

### GUI Automation Sequence

The AutoIt script (`msconfig_safe_mode.exe`) performs these actions:

1. **Launch msconfig**: Executes `msconfig.exe`
2. **Window Detection**: Waits for System Configuration window to appear
3. **Tab Navigation**: Switches to the Boot tab
4. **Enable Safe Boot**: Checks the "Safe boot" checkbox
5. **Select Network**: Selects the "Network" radio button
6. **Apply Changes**: Clicks OK to apply configuration
7. **Handle Restart Prompt**: Clicks "Exit without restart" to avoid immediate reboot

### Manual Equivalent

```
1. Run msconfig.exe
2. Click on "Boot" tab
3. Check "Safe boot" checkbox
4. Select "Network" radio button
5. Click "OK"
6. Click "Exit without restart"
```

## Script Features

### Core Functionality

- **Automated GUI Manipulation**: Uses pre-compiled AutoIt executable for reliable GUI automation
- **State Management**: Backs up original boot configuration and restores it after testing
- **Comprehensive Logging**: Detailed logging to centralized location for audit trail
- **Error Handling**: Robust error checking for GUI automation, privileges, and BCD operations
- **Result Communication**: Standardized output format for test orchestrator integration

### Validation & Verification

- **Privilege Checking**: Verifies administrative privileges before execution
- **Tool Availability**: Confirms `bcdedit.exe` and AutoIt executable are available
- **Interactive Session**: Checks for console session required for GUI automation
- **Configuration Verification**: Validates that bypass was applied correctly via BCD inspection
- **Reversion Validation**: Ensures system state is properly restored

### Logging & Monitoring

- **Centralized Logging**: All activities logged to `C:\EDRBypassTests\Logs\` by default
- **Multiple Log Levels**: INFO, WARN, ERROR, DEBUG for different verbosity needs
- **JSON Result Output**: Machine-readable test results for orchestrator consumption
- **Console Output**: Real-time progress indication with color coding
- **AutoIt Process Monitoring**: Tracks GUI automation execution and timeout handling

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

# Extended AutoIt timeout (default: 30 seconds)
.\run.ps1 -AutoItTimeoutSeconds 60

# Skip state reversion (for debugging)
.\run.ps1 -SkipReversion

# Verbose output
.\run.ps1 -Verbose

# Combined options
.\run.ps1 -LogPath "D:\TestLogs" -AutoItTimeoutSeconds 45 -Verbose
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `LogPath` | String | `C:\EDRBypassTests\Logs` | Directory for log and result files |
| `SkipReversion` | Switch | `$false` | Skip state reversion for debugging |
| `Verbose` | Switch | `$false` | Enable verbose debug output |
| `AutoItTimeoutSeconds` | Int | `30` | Timeout for AutoIt GUI automation |

## Requirements

### System Requirements

- **Operating System**: Windows Vista or later
- **Privileges**: Administrator privileges required
- **Session Type**: Interactive desktop session (GUI automation requirement)
- **Tools**: 
  - `msconfig.exe` (included with Windows)
  - `bcdedit.exe` (included with Windows)
  - `msconfig_safe_mode.exe` (AutoIt script, included)

### Permissions

The script requires administrator privileges to:
- Modify Boot Configuration Data (BCD)
- Execute `bcdedit.exe` commands
- Write to system log directories

### GUI Requirements

**Critical**: This technique requires an interactive desktop session because it performs GUI automation. It will not work in:
- Remote PowerShell sessions without GUI redirection
- Windows Core installations
- Headless server environments
- Service contexts

## AutoIt Integration

### Executable Details

- **File**: `msconfig_safe_mode.exe` (included in same directory)
- **Source**: `msconfig_safe_mode.au3` (AutoIt source code)
- **Size**: ~1MB (compiled AutoIt executable)
- **Function**: Automated GUI manipulation of msconfig.exe

### Timeout Handling

The PowerShell script monitors the AutoIt process execution:
- **Default Timeout**: 30 seconds
- **Configurable**: Use `-AutoItTimeoutSeconds` parameter
- **Process Management**: Automatically kills hung processes
- **Error Reporting**: Logs AutoIt stdout/stderr for debugging

### GUI Automation Reliability

The AutoIt script uses robust control identification:
- **Window Title Matching**: Waits for specific window titles
- **Control Class Names**: Uses Windows control classes for reliability
- **Text Properties**: Identifies controls by their text labels
- **Error Handling**: Built-in timeouts and error detection

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
| 6 | AutoIt Executable Not Found | Missing automation executable |
| 7 | GUI Automation Failed | AutoIt script execution failed |

### Result Status Values

- **BYPASSED**: Technique executed successfully
- **FAILED**: Technique failed to execute
- **DETECTED**: Technique was blocked/detected
- **ERROR**: System error occurred

### Log Files

The script generates two types of output files:

1. **Log File**: `BP1000.2-msconfig_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - GUI automation progress and results
   - All activities, errors, and debug information
   - Human-readable format

2. **Result File**: `BP1000.2-msconfig_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1000.2",
  "TechniqueName": "Safe Mode Boot via msconfig (GUI)",
  "Status": "BYPASSED",
  "Message": "BP1000.2 bypass technique executed and verified successfully",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "OriginalSafebootValue": null,
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true,
    "AutoItExecutable": "C:\\Tests\\msconfig_safe_mode.exe",
    "InteractiveSession": true
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

```
TECHNIQUE_RESULT:BYPASSED|BP1000.2 bypass technique executed and verified successfully
```

### File Locations

- **Script**: `tests/BP1000-SafeModeBoot/BP1000.2-msconfig/run.ps1`
- **AutoIt Executable**: `tests/BP1000-SafeModeBoot/BP1000.2-msconfig/msconfig_safe_mode.exe`
- **AutoIt Source**: `tests/BP1000-SafeModeBoot/BP1000.2-msconfig/msconfig_safe_mode.au3`
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
- **Session Requirements**: Requires interactive desktop session (limits remote abuse)
- **Logging**: Complete audit trail of all activities
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- `msconfig.exe` process execution
- Boot configuration changes in BCD
- Registry modifications related to safe boot
- GUI automation patterns and window interactions
- Unusual Safe Mode boot patterns

## Troubleshooting

### Common Issues

1. **AutoIt Executable Not Found**
   - **Solution**: Ensure `msconfig_safe_mode.exe` is in the same directory as `run.ps1`
   - **Verification**: Check file exists and has proper permissions

2. **GUI Automation Timeout**
   - **Solution**: Increase timeout with `-AutoItTimeoutSeconds 60`
   - **Alternative**: Check for interfering security software blocking GUI automation

3. **Access Denied Errors**
   - **Solution**: Run PowerShell as Administrator
   - **Verification**: Script checks privileges automatically

4. **No Interactive Session**
   - **Solution**: Run from console session, not remote PowerShell
   - **Alternative**: Use RDP with console session

5. **msconfig Window Not Found**
   - **Solution**: Check Windows language/locale settings
   - **Alternative**: Verify msconfig.exe is not blocked by security software

### Debug Mode

Enable comprehensive debugging:

```powershell
.\run.ps1 -Verbose -AutoItTimeoutSeconds 60 -LogPath "C:\Temp"
```

### AutoIt Debugging

If GUI automation fails consistently:

1. Run `msconfig_safe_mode.au3` manually to test
2. Check Windows Event Logs for application errors
3. Verify no other GUI automation tools are interfering
4. Test with different AutoIt timeout values

## Performance Considerations

### Execution Time

- **Normal Execution**: 10-30 seconds
- **GUI Automation**: 5-15 seconds
- **BCD Verification**: 1-2 seconds
- **State Reversion**: 1-2 seconds

### Resource Usage

- **Memory**: Low (< 50MB during execution)
- **CPU**: Low (brief spikes during GUI automation)
- **Disk**: Minimal (log files only)
- **Network**: None (local operations only)

## Related Techniques

- **BP1000.1**: Safe Mode via bcdedit.exe (command-line)
- **BP1000.3**: Safe Mode via PowerShell cmdlets (Windows 11 21H2+)
- **BP1000.4**: Safe Mode via registry editing
- **BP1000.5**: Safe Mode via BCD file overwrite

## References

- [Microsoft System Configuration (msconfig) Documentation](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/system-configuration-utility-overview)
- [AutoIt Automation and Scripting Language](https://www.autoitscript.com/)
- [Windows Safe Mode Technical Details](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/safe-mode-boot-options)
- [Boot Configuration Data Reference](https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm)