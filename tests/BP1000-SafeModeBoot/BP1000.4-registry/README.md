# BP1000.4 - Safe Mode Boot Bypass via PowerShell Registry Manipulation

## Overview

This variant implements the **BP-1000.4** EDR bypass technique, which leverages Windows Safe Mode to disable or neutralize EDR agents. The technique uses PowerShell registry cmdlets to directly manipulate the BCD (Boot Configuration Data) registry hive, bypassing standard BCD tools like `bcdedit.exe` and `msconfig.exe`.

## Technique Details

**Technique ID:** BP1000.4  
**Technique Name:** Safe Mode Boot via PowerShell Registry Manipulation  
**Category:** EDR Driver Unload  
**Platform:** Windows Vista and later  

### How It Works

1. **BCD Registry Access**: Accesses the BCD hive mounted at `HKLM\BCD00000000`
2. **GUID Resolution**: Locates the default boot object GUID via the bootmgr BCD object
3. **Direct Registry Modification**: Modifies the safeboot element (`25000080`) directly in the registry
4. **EDR Bypass**: Most EDR agents and security software do not load in Safe Mode, effectively bypassing their protection
5. **Network Access**: Safe Mode with Network maintains network connectivity, allowing continued remote access
6. **State Restoration**: Restores original registry values or removes safeboot element

### Registry Path Structure

```
HKLM\BCD00000000\Objects\{bootmgr-guid}\Elements\23000003     # Contains default boot object GUID
HKLM\BCD00000000\Objects\{boot-object-guid}\Elements\25000080 # Safeboot configuration element
```

### Key Registry Elements

| Element | Path Component | Purpose |
|---------|----------------|---------|
| `{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}` | Bootmgr GUID | Known bootmgr object identifier |
| `23000003` | Element ID | Contains reference to default boot object |
| `25000080` | Element ID | Controls safeboot mode configuration |

### Safeboot Values

The safeboot element (`25000080`) uses an 8-byte `REG_BINARY` value representing a 64-bit little-endian integer:

| Value | Binary (Hex) | Mode | Description |
|-------|--------------|------|-------------|
| (not present) | - | Normal | Standard boot mode |
| 0 | `00 00 00 00 00 00 00 00` | Minimal | Safe Mode (minimal drivers) |
| 1 | `01 00 00 00 00 00 00 00` | Network | Safe Mode with Network |
| 2 | `02 00 00 00 00 00 00 00` | DsRepair | Directory Services Repair Mode |

## Script Features

### Core Functionality

- **GUID Resolution**: Automatically locates the default boot object GUID via bootmgr lookup
- **Direct Registry Access**: Uses PowerShell registry cmdlets instead of external tools
- **Permission Management**: Handles BCD registry permissions (SYSTEM account restrictions)
- **Binary Value Handling**: Properly formats 8-byte little-endian binary values
- **State Management**: Backs up original registry values and restores them after testing
- **Comprehensive Logging**: Detailed logging to centralized location for audit trail
- **Error Handling**: Robust error checking for registry access, permissions, and GUID resolution
- **Result Communication**: Standardized output format for test orchestrator integration

### Validation & Verification

- **Privilege Checking**: Verifies administrative privileges before execution
- **Registry Access**: Confirms BCD hive accessibility at `HKLM\BCD00000000`
- **GUID Resolution**: Validates successful lookup of default boot object GUID
- **Configuration Verification**: Confirms bypass was applied correctly via registry inspection
- **Reversion Validation**: Ensures system state is properly restored

### Logging & Monitoring

- **Centralized Logging**: All activities logged to `C:\EDRBypassTests\Logs\` by default
- **Multiple Log Levels**: INFO, WARN, ERROR, DEBUG for different verbosity needs
- **JSON Result Output**: Machine-readable test results for orchestrator consumption
- **Console Output**: Real-time progress indication with color coding
- **Registry Details**: Logs GUIDs, binary values, and registry paths

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
- **Registry Access**: BCD hive must be mounted at `HKLM\BCD00000000`
- **PowerShell**: PowerShell 3.0 or later (registry cmdlets)

### Permissions

The script requires administrator privileges to:
- Access and modify BCD registry keys
- Set registry permissions on protected keys
- Write to system log directories

### BCD Registry Hive

The BCD registry hive is typically mounted during boot at `HKLM\BCD00000000`. Key characteristics:
- **Default Access**: SYSTEM account has full control
- **Administrator Access**: Local administrators can grant themselves permissions
- **Protection**: Keys are protected against casual modification
- **Persistence**: Changes persist across reboots

## PowerShell Registry Operations

### Key Cmdlets Used

- **`Get-ItemProperty`**: Reads registry values
- **`Set-ItemProperty`**: Writes registry values
- **`Test-Path`**: Checks registry key existence
- **`New-Item`**: Creates registry keys
- **`Remove-Item`**: Deletes registry keys
- **`Get-Acl`/`Set-Acl`**: Manages registry permissions

### Binary Value Handling

```powershell
# Create 8-byte little-endian binary for network safe mode (value 1)
$networkValue = [byte[]]@(1, 0, 0, 0, 0, 0, 0, 0)

# Set the registry value
Set-ItemProperty -Path $registryPath -Name "Element" -Value $networkValue -Type Binary

# Read and convert binary value
$binaryValue = (Get-ItemProperty -Path $registryPath -Name "Element").Element
$intValue = [System.BitConverter]::ToUInt64($binaryValue, 0)
```

### GUID Conversion

```powershell
# Convert binary GUID from registry to string format
$guidBytes = $elementValue.Element
$guid = [System.Guid]::new($guidBytes)
$guidString = "{$($guid.ToString().ToUpper())}"
```

## Output & Results

### Exit Codes

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Bypass applied and reverted successfully |
| 1 | General Failure | Unspecified error occurred |
| 2 | Insufficient Privileges | Administrator rights required |
| 3 | Bypass Application Failed | Could not apply the bypass |
| 4 | Bypass Verification Failed | Bypass not confirmed in registry |
| 5 | Reversion Failed | Could not restore original state |
| 6 | BCD Registry Hive Not Accessible | Cannot access `HKLM\BCD00000000` |
| 7 | Default Boot Object GUID Not Found | Cannot resolve boot object GUID |

### Result Status Values

- **BYPASSED**: Technique executed successfully
- **FAILED**: Technique failed to execute
- **DETECTED**: Technique was blocked/detected
- **ERROR**: System error occurred

### Log Files

The script generates two types of output files:

1. **Log File**: `BP1000.4-registry_YYYYMMDD_HHMMSS.log`
   - Detailed execution log with timestamps
   - Registry paths, GUIDs, and binary values
   - All activities, errors, and debug information
   - Human-readable format

2. **Result File**: `BP1000.4-registry_YYYYMMDD_HHMMSS_result.json`
   - Machine-readable test results
   - Status, message, and metadata
   - Used by test orchestrator

### Sample Result JSON

```json
{
  "TechniqueId": "BP1000.4",
  "TechniqueName": "Safe Mode Boot via PowerShell Registry Manipulation",
  "Status": "BYPASSED",
  "Message": "BP1000.4 registry bypass technique executed and verified successfully",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "BootObjectGuid": "{12345678-1234-5678-9ABC-123456789ABC}",
    "OriginalSafebootValue": {
      "BinaryValue": null,
      "IntegerValue": null,
      "Description": null,
      "Exists": false
    },
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true,
    "BcdHivePath": "HKLM:\\BCD00000000",
    "BootmgrGuid": "{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}"
  },
  "ScriptVersion": "1.0.0"
}
```

## Integration with Test Framework

### Orchestrator Communication

The script outputs standardized results that can be consumed by the test orchestrator:

```
TECHNIQUE_RESULT:BYPASSED|BP1000.4 registry bypass technique executed and verified successfully
```

### File Locations

- **Script**: `tests/BP1000-SafeModeBoot/BP1000.4-registry/run.ps1`
- **Logs**: `C:\EDRBypassTests\Logs\` (configurable)
- **Results**: JSON files in same directory as logs

## Security Considerations

### Legitimate Use Cases

This technique is designed for:
- **Authorized Security Testing**: Evaluating EDR effectiveness in controlled environments
- **Red Team Exercises**: Simulating advanced persistent threat techniques
- **Security Research**: Understanding bypass methodologies for defensive improvements

### Risk Mitigation

- **Automatic Reversion**: Script automatically restores original registry configuration
- **Permission Handling**: Manages registry permissions appropriately
- **Logging**: Complete audit trail of all registry modifications
- **Controlled Environment**: Intended for isolated test environments only

### Detection Opportunities

EDR products can detect this technique by monitoring:
- Registry access to BCD hive (`HKLM\BCD00000000`)
- Modifications to BCD elements (`25000080`)
- PowerShell registry cmdlet usage patterns
- Binary value changes in boot configuration
- Registry permission modifications
- Unusual Safe Mode boot patterns

## Troubleshooting

### Common Issues

1. **BCD Registry Hive Not Accessible**
   - **Error**: "BCD registry hive is not accessible at HKLM:\BCD00000000"
   - **Solution**: Verify system is properly booted and BCD hive is mounted
   - **Check**: Run `Test-Path "HKLM:\BCD00000000"` manually

2. **Access Denied Errors**
   - **Solution**: Run PowerShell as Administrator
   - **Alternative**: Check if registry permissions were modified by other software

3. **Default Boot Object GUID Not Found**
   - **Error**: "Failed to locate default boot object GUID"
   - **Solution**: Verify BCD structure integrity with `bcdedit /enum`
   - **Alternative**: Use different bypass variant if BCD is corrupted

4. **Registry Permission Errors**
   - **Solution**: Script attempts automatic permission modification
   - **Manual Fix**: Use `regedit.exe` to grant permissions to administrators

5. **Binary Value Format Errors**
   - **Check**: Ensure 8-byte little-endian format is maintained
   - **Debug**: Enable verbose logging to see binary value hexdumps

### Debug Mode

Enable comprehensive debugging:

```powershell
.\run.ps1 -Verbose -LogPath "C:\Temp"
```

### Manual Registry Inspection

Verify registry operations manually:

```powershell
# Check BCD hive access
Test-Path "HKLM:\BCD00000000"

# Look up bootmgr object
$bootmgrPath = "HKLM:\BCD00000000\Objects\{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}\Elements\23000003"
Get-ItemProperty -Path $bootmgrPath -Name "Element" | Format-Hex

# Check safeboot element (replace GUID)
$safebootPath = "HKLM:\BCD00000000\Objects\{YOUR-BOOT-GUID}\Elements\25000080"
Get-ItemProperty -Path $safebootPath -Name "Element" -ErrorAction SilentlyContinue
```

## Performance Considerations

### Execution Time

- **Normal Execution**: 5-15 seconds
- **GUID Resolution**: 1-2 seconds
- **Registry Operations**: 1-3 seconds
- **Permission Handling**: 1-2 seconds

### Resource Usage

- **Memory**: Low (< 30MB during execution)
- **CPU**: Low (brief spikes during registry operations)
- **Disk**: Minimal (log files only)
- **Network**: None (local operations only)

### Registry Performance

Registry operations are generally fast because:
- Direct in-memory access to mounted hive
- No external process overhead
- Efficient binary value handling

## Comparison with Other Variants

| Variant | Method | Tool Dependency | Registry Access | Stealth Level |
|---------|--------|-----------------|-----------------|---------------|
| BP1000.1 | bcdedit.exe | External tool | Indirect | Medium |
| BP1000.2 | msconfig.exe | External tool + GUI | Indirect | Low |
| BP1000.3 | PowerShell cmdlets | None | Indirect | Medium |
| **BP1000.4** | **Registry manipulation** | **None** | **Direct** | **High** |
| BP1000.5 | BCD file overwrite | External tools | File system | High |

### When to Use BP1000.4

**Advantages:**
- Direct registry access (no tool dependencies)
- Bypasses BCD tool restrictions
- High stealth (no external process execution)
- Granular control over binary values
- Works when BCD tools are blocked

**Disadvantages:**
- More complex implementation
- Requires deep BCD knowledge
- Permission challenges
- Platform-specific registry structure

## Advanced Techniques

### Alternative Registry Paths

The script can be adapted for scenarios where the BCD hive is mounted elsewhere:

```powershell
# If BCD hive is mounted at different location
$alternativePath = "HKLM:\CustomBCD12345"
```

### Permission Escalation

For environments with restricted registry access:

```powershell
# Grant full control to current user
$acl = Get-Acl -Path $registryPath
$accessRule = New-Object System.Security.AccessControl.RegistryAccessRule(
    $currentUser, "FullControl", "Allow"
)
$acl.SetAccessRule($accessRule)
Set-Acl -Path $registryPath -AclObject $acl
```

## Related Techniques

- **BP1000.1**: Safe Mode via bcdedit.exe (command-line, broader compatibility)
- **BP1000.2**: Safe Mode via msconfig.exe (GUI-based)
- **BP1000.3**: Safe Mode via PowerShell cmdlets (Windows 11 21H2+)
- **BP1000.5**: Safe Mode via BCD file overwrite (file system access)

## References

- [Boot Configuration Data Reference](https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm)
- [Windows Registry Architecture](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [PowerShell Registry Provider](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_registry)
- [Windows Safe Mode Technical Details](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/safe-mode-boot-options)
- [BCD Registry Hive Structure](https://www.geoffchappell.com/notes/windows/boot/bcd/objects.htm)