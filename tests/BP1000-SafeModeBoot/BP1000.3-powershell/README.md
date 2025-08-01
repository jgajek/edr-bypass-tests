# BP1000.3 - Safe Mode Boot Bypass via PowerShell BCD Cmdlets

## Overview

This variant implements the **BP-1000.3** EDR bypass technique, which leverages Windows Safe Mode to disable or neutralize EDR agents. The technique uses PowerShell BCD cmdlets introduced in Windows 11 21H2 to configure the system to boot into Safe Mode with Network on the next restart.

## Technique Details

**Technique ID:** BP1000.3  
**Technique Name:** Safe Mode Boot via PowerShell BCD Cmdlets  
**Category:** EDR Driver Unload  
**Platform:** Windows 11 21H2 or later (build 22000+)  

### How It Works

1. **Version Validation**: Checks for Windows 11 21H2+ (build 22000) or later
2. **Cmdlet Availability**: Verifies PowerShell BCD cmdlets are available
3. **Boot Configuration**: Uses `Set-BcdElement safeboot -Type Integer Value 1` to enable Safe Mode with Network
4. **EDR Bypass**: Most EDR agents and security software do not load in Safe Mode, effectively bypassing their protection
5. **Network Access**: Safe Mode with Network maintains network connectivity, allowing continued remote access
6. **State Restoration**: Uses `Remove-BcdElement safeboot -Force` to restore normal boot mode

### PowerShell Cmdlet Sequence

```powershell
# Apply bypass (Safe Mode with Network = value 1)
Set-BcdElement safeboot -Type Integer Value 1

# Verify configuration
Get-BcdElement safeboot

# Revert to normal boot
Remove-BcdElement safeboot -Force
```

### BCD Element Values

| Value | Mode | Description |
|-------|------|-------------|
| 0 | Minimal | Safe Mode (minimal drivers) |
| 1 | Network | Safe Mode with Network |
| 2 | DsRepair | Directory Services Repair Mode |
| (none) | Normal | Standard boot mode |

## Script Features

### Core Functionality

- **Windows Version Checking**: Validates Windows 11 21H2+ requirement before execution
- **PowerShell Cmdlet Integration**: Uses native BCD cmdlets instead of external tools
- **State Management**: Backs up original boot configuration and restores it after testing
- **Comprehensive Logging**: Detailed logging to centralized location for audit trail
- **Error Handling**: Robust error checking for version compatibility, cmdlets, and BCD operations
- **Result Communication**: Standardized output format for test orchestrator integration

### Validation & Verification

- **OS Compatibility**: Verifies Windows build number (≥22000 for Windows 11 21H2)
- **Privilege Checking**: Verifies administrative privileges before execution
- **Cmdlet Availability**: Confirms PowerShell BCD cmdlets are loaded and accessible
- **Configuration Verification**: Validates that bypass was applied correctly via BCD inspection
- **Reversion Validation**: Ensures system state is properly restored

### Logging & Monitoring

- **Centralized Logging**: All activities logged to `C:\EDRBypassTests\Logs\` by default
- **Multiple Log Levels**: INFO, WARN, ERROR, DEBUG for different verbosity needs
- **JSON Result Output**: Machine-readable test results for orchestrator consumption
- **Console Output**: Real-time progress indication with color coding
- **System Information**: Logs OS version, build number, and PowerShell version

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

- **Operating System**: Windows 11 21H2 or later (build 22000+)
- **PowerShell**: PowerShell 5.1 or later with BCD module
- **Privileges**: Administrator privileges required
- **Cmdlets**: `Set-BcdElement`, `Get-BcdElement`, `Remove-BcdElement`

### Windows Version Compatibility

| Windows Version | Build Number | Supported | Notes |
|-----------------|--------------|-----------|-------|
| Windows 10 | < 22000 | ❌ | BCD cmdlets not available |
| Windows 11 21H1 | < 22000 | ❌ | BCD cmdlets not available |
| Windows 11 21H2 | ≥ 22000 | ✅ | First version with BCD cmdlets |
| Windows 11 22H2+ | ≥ 22621 | ✅ | Full compatibility |

### Permissions

The script requires administrator privileges to:
- Execute PowerShell BCD cmdlets
- Modify Boot Configuration Data (BCD)
- Write to system log directories

## PowerShell BCD Cmdlets

### Cmdlet Overview

The BCD cmdlets were introduced in Windows 11 21H2 as part of PowerShell's enhanced system management capabilities:

- **Set-BcdElement**: Creates or modifies BCD elements
- **Get-BcdElement**: Retrieves current BCD element values
- **Remove-BcdElement**: Removes BCD elements

### Advantages over bcdedit

1. **Native PowerShell**: No external process execution required
2. **Object-Oriented**: Returns structured objects instead of text parsing
3. **Error Handling**: Better exception handling and error reporting
4. **Type Safety**: Strongly-typed parameters and return values
5. **Integration**: Seamless integration with PowerShell workflows

### Example Usage

```powershell
# Check current safeboot configuration
$current = Get-BcdElement -Element safeboot
if ($current) {
    Write-Host "Current safeboot mode: $($current.Integer)"
}

# Set Safe Mode with Network
Set-BcdElement -Element safeboot -Type Integer -Value 1

# Remove safeboot configuration
Remove-BcdElement -Element safeboot -Force
```

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
| 6 | Unsupported Windows Version | Requires Windows 11 21H2+ |
| 7 | BCD Cmdlets Not Available | PowerShell BCD module missing |

### Result Status Values

- **BYPASSED**: Technique executed successfully
- **FAILED**: Technique failed to execute
- **DETECTED**: Technique was blocked/detected
- **ERROR**: System error occurred

### Log Files

The script generates two types of output files:

1. **Log File**: `BP1000.3-powershell_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - Windows version and PowerShell information
   - All activities, errors, and debug information
   - Human-readable format

2. **Result File**: `BP1000.3-powershell_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1000.3",
  "TechniqueName": "Safe Mode Boot via PowerShell BCD Cmdlets",
  "Status": "BYPASSED",
  "Message": "BP1000.3 PowerShell BCD bypass technique executed and verified successfully",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "OriginalSafebootElement": null,
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true,
    "SystemInfo": {
      "Caption": "Microsoft Windows 11 Pro",
      "Version": "10.0.22631",
      "BuildNumber": 22631,
      "IsSupported": true
    },
    "PowerShellVersion": "5.1.22631.4460",
    "BcdEditAvailable": true
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

```
TECHNIQUE_RESULT:BYPASSED|BP1000.3 PowerShell BCD bypass technique executed and verified successfully
```

### File Locations

- **Script**: `tests/BP1000-SafeModeBoot/BP1000.3-powershell/run.ps1`
- **Logs**: `C:\EDRBypassTests\Logs\` (configurable)
- **Results**: JSON files in same directory as logs

## Security Considerations

### Legitimate Use Cases

This technique is designed for:
- **Authorized Security Testing**: Evaluating EDR effectiveness in controlled environments
- **Red Team Exercises**: Simulating advanced persistent threat techniques
- **Security Research**: Understanding bypass methodologies for defensive improvements

### Risk Mitigation

- **Version Restrictions**: Only works on Windows 11 21H2+ (limits attack surface)
- **Automatic Reversion**: Script automatically restores original boot configuration
- **Logging**: Complete audit trail of all activities
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- PowerShell execution with BCD-related cmdlets
- `Set-BcdElement` and `Remove-BcdElement` cmdlet usage
- Boot configuration changes in BCD
- PowerShell module loading patterns
- Unusual Safe Mode boot patterns

## Troubleshooting

### Common Issues

1. **Unsupported Windows Version**
   - **Error**: "Unsupported Windows version - requires Windows 11 21H2 or later"
   - **Solution**: Upgrade to Windows 11 21H2+ (build 22000+)
   - **Alternative**: Use BP1000.1 (bcdedit) or BP1000.2 (msconfig) variants

2. **BCD Cmdlets Not Available**
   - **Error**: "PowerShell BCD cmdlets are not available"
   - **Solution**: Verify Windows 11 21H2+ and PowerShell module integrity
   - **Check**: Run `Get-Command *BcdElement*` to verify cmdlets

3. **Access Denied Errors**
   - **Solution**: Run PowerShell as Administrator
   - **Verification**: Script checks privileges automatically

4. **Cmdlet Execution Errors**
   - **Solution**: Check system integrity with `sfc /scannow`
   - **Alternative**: Use different bypass variant (BP1000.1-1000.2)

### Debug Mode

Enable comprehensive debugging:

```powershell
.\run.ps1 -Verbose -LogPath "C:\Temp"
```

### Version Verification

Check your Windows version compatibility:

```powershell
# Check Windows build
[System.Environment]::OSVersion.Version

# Check BCD cmdlets
Get-Command Set-BcdElement, Get-BcdElement, Remove-BcdElement

# Manual test
Get-BcdElement -Element safeboot
```

## Performance Considerations

### Execution Time

- **Normal Execution**: 5-15 seconds
- **Version Checking**: 1-2 seconds
- **BCD Operations**: 1-3 seconds
- **Verification**: 1-2 seconds

### Resource Usage

- **Memory**: Low (< 30MB during execution)
- **CPU**: Low (brief spikes during cmdlet execution)
- **Disk**: Minimal (log files only)
- **Network**: None (local operations only)

### Cmdlet Performance

PowerShell BCD cmdlets are generally faster than `bcdedit.exe` because:
- No external process creation overhead
- Direct API calls to BCD functions
- Object-based returns (no text parsing)

## Comparison with Other Variants

| Variant | Method | Windows Support | Privileges | GUI Required |
|---------|--------|-----------------|------------|--------------|
| BP1000.1 | bcdedit.exe | Vista+ | Admin | No |
| BP1000.2 | msconfig.exe | Vista+ | Admin | Yes |
| **BP1000.3** | **PowerShell cmdlets** | **Win11 21H2+** | **Admin** | **No** |
| BP1000.4 | Registry editing | Vista+ | Admin | No |
| BP1000.5 | BCD file overwrite | Vista+ | Admin | No |

### When to Use BP1000.3

**Advantages:**
- Native PowerShell integration
- Better error handling and logging
- No external tool dependencies
- Object-oriented approach

**Disadvantages:**
- Limited to Windows 11 21H2+
- Newer technique (less tested in wild)
- May be more closely monitored

## Related Techniques

- **BP1000.1**: Safe Mode via bcdedit.exe (command-line, broader compatibility)
- **BP1000.2**: Safe Mode via msconfig.exe (GUI-based)
- **BP1000.4**: Safe Mode via registry editing
- **BP1000.5**: Safe Mode via BCD file overwrite

## References

- [Microsoft PowerShell BCD Cmdlets Documentation](https://docs.microsoft.com/en-us/powershell/module/bcdbootdevice/)
- [Windows 11 21H2 Feature Updates](https://docs.microsoft.com/en-us/windows/whats-new/windows-11-version-21h2)
- [Boot Configuration Data Reference](https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm)
- [Windows Safe Mode Technical Details](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/safe-mode-boot-options)