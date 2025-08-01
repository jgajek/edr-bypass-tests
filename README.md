# EDR Bypass Testing Automation Framework

**Version:** 2.0.0  
**Last Updated:** January 27, 2025

## Overview

This repository contains a comprehensive, production-ready automation framework for testing EDR (Endpoint Detection and Response) bypass techniques in controlled laboratory environments. The framework provides standardized PowerShell implementations of various bypass methods with consistent logging, error handling, state management, and result reporting.

**Current Implementation Status:**
- **9 Total Variants** across 3 major technique categories
- **3 Technique Series**: Safe Mode Boot (BP1000), Pre-Boot Execute (BP1001), Service Disruption (BP1002)
- **Progressive Complexity**: From basic tool usage to expert-level native execution
- **Complete Framework**: Standardized interfaces, comprehensive documentation, and orchestrator integration

## Architecture

The framework consists of three main components:

1. **Standardized Test Runners**: PowerShell scripts implementing specific bypass techniques with consistent interfaces
2. **Technique Documentation**: Comprehensive documentation for each bypass method and variant
3. **Result Communication**: Structured output format for integration with test orchestration systems

### Design Principles

- **Modular Architecture**: Each technique and variant is self-contained
- **Consistent Interface**: All test runners follow identical patterns and standards
- **State Management**: Automatic backup and restoration of system configuration
- **Comprehensive Logging**: Detailed audit trails for all operations
- **Error Recovery**: Robust error handling with graceful cleanup
- **Orchestrator Integration**: Standardized result communication for automation

## Repository Structure

```
tests/
├── BP1000-SafeModeBoot/                    # Safe Mode Boot Bypass Techniques
│   ├── BP1000.1-bcdedit/                   # bcdedit.exe implementation
│   │   ├── run.ps1                         # Standardized entry point
│   │   └── README.md                       # Technique documentation
│   ├── BP1000.2-msconfig/                  # msconfig.exe with GUI automation
│   │   ├── run.ps1
│   │   ├── README.md
│   │   ├── msconfig_safe_mode.exe          # Compiled AutoIt automation
│   │   └── msconfig_safe_mode.au3          # AutoIt source code
│   ├── BP1000.3-powershell/                # PowerShell BCD cmdlets
│   │   ├── run.ps1
│   │   └── README.md
│   ├── BP1000.4-registry/                  # PowerShell registry manipulation
│   │   ├── run.ps1
│   │   └── README.md
│   └── BP1000-SafeModeBoot.md              # Technique overview
│
├── BP1001-BootExecute/                     # Pre-Boot EDR Bypass Techniques
│   ├── BP1001.1-registry/                  # Registry manipulation implementation
│   │   ├── run.ps1
│   │   └── README.md
│   └── BP1001-BootExecute.md               # Technique overview
│
└── BP1002-DisableUserModeService/          # Service Disruption Techniques
    ├── BP1002.3-sc/                        # sc.exe implementation
    │   ├── run.ps1
    │   └── README.md
    ├── BP1002.4-powershell/                # PowerShell service cmdlets
    │   ├── run.ps1
    │   └── README.md
    ├── BP1002.5-registry/                  # Direct registry manipulation
    │   ├── run.ps1
    │   └── README.md
    ├── BP1002.6-registry-save-restore/     # Registry save/restore (advanced)
    │   ├── run.ps1
    │   └── README.md
    └── BP-1002_Disable_User_Mode_Service.md # Technique overview
```

## Implemented Techniques

### BP1000: Safe Mode Boot Bypass

**Objective**: Configure system to boot into Safe Mode where EDR agents typically don't load.

| Variant | Method | Platform | Stealth | Complexity |
|---------|--------|----------|---------|------------|
| **BP1000.1** | bcdedit.exe | Windows Vista+ | Medium | ⭐⭐ |
| **BP1000.2** | msconfig.exe (GUI) | Windows Vista+ | Low | ⭐⭐⭐ |
| **BP1000.3** | PowerShell BCD cmdlets | Windows 11 21H2+ | Medium | ⭐⭐⭐ |
| **BP1000.4** | Registry manipulation | Windows Vista+ | High | ⭐⭐⭐⭐ |

### BP1001: Pre-Boot EDR Bypass

**Objective**: Execute native payloads before EDR/AV initialization using Windows Boot Execute mechanism.

| Variant | Method | Platform | Stealth | Complexity |
|---------|--------|----------|---------|------------|
| **BP1001.1** | Registry manipulation | Windows Vista+ | Very High | ⭐⭐⭐⭐⭐ |

### BP1002: EDR Service Disruption

**Objective**: Stop and disable EDR user-mode services to remove protection.

| Variant | Method | PPL Support | Callback Bypass | Complexity |
|---------|--------|-------------|-----------------|------------|
| **BP1002.3** | sc.exe | No | No | ⭐⭐ |
| **BP1002.4** | PowerShell cmdlets | No | No | ⭐⭐⭐ |
| **BP1002.5** | Registry manipulation | Partial | No | ⭐⭐⭐⭐ |
| **BP1002.6** | Registry save/restore | Yes | Yes | ⭐⭐⭐⭐⭐ |

## Quick Start

### Basic Usage

```powershell
# Run a specific bypass technique
cd tests\BP1000-SafeModeBoot\BP1000.1-bcdedit\
.\run.ps1

# Run with custom parameters
.\run.ps1 -LogPath "D:\TestLogs" -Verbose

# Target specific service (for BP1002 series)
cd tests\BP1002-DisableUserModeService\BP1002.4-powershell\
.\run.ps1 -TargetService "SENSE" -ServiceTimeoutSeconds 60

# Execute pre-boot bypass (requires native binary)
cd tests\BP1001-BootExecute\BP1001.1-registry\
.\run.ps1 -RegistryMethod "BootExecuteNoPnpSync" -BinaryName "bootexecute.exe"
```

### Standard Parameters

All test runners support these common parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `LogPath` | String | `C:\EDRBypassTests\Logs` | Directory for logs and results |
| `SkipReversion` | Switch | `$false` | Skip state restoration (debug mode) |
| `Verbose` | Switch | `$false` | Enable verbose debug output |

### Technique-Specific Parameters

**BP1000.2 (msconfig GUI automation):**
- `AutoItTimeoutSeconds`: Timeout for GUI automation (default: 30)

**BP1001.1 (BootExecute pre-boot bypass):**
- `BinaryName`: Name of native executable (default: "bootexecute.exe")
- `RegistryMethod`: Boot Execute method (default: "BootExecuteNoPnpSync")
  - Valid options: `BootExecute`, `BootExecuteNoPnpSync`, `SetupExecute`, `PlatformExecute`

**BP1002 Service Disruption variants:**
- `TargetService`: EDR service name to target (default: "SENSE")
- `ServiceTimeoutSeconds`: Service operation timeout (default: 30)

**BP1002.6 (Registry save/restore):**
- `TempPath`: Directory for temporary hive files (default: `$env:TEMP\EDRBypass`)

## Framework Standards

### Standardized Entry Point

Every technique variant includes a `run.ps1` script that serves as the standardized entry point:

```powershell
# Common execution pattern
.\run.ps1 [parameters]
```

### Consistent Logging

All scripts implement identical logging patterns:

```powershell
# Centralized log files
C:\EDRBypassTests\Logs\[TechniqueID]-[method]_YYYYMMDD_HHMMSS.log
C:\EDRBypassTests\Logs\[TechniqueID]-[method]_YYYYMMDD_HHMMSS_result.json
```

### State Management

All implementations follow the same state management pattern:

1. **Pre-execution checks** (privileges, tool availability, compatibility)
2. **State backup** (current system configuration)
3. **Bypass execution** (implement the technique)
4. **Verification** (confirm bypass was applied)
5. **State restoration** (revert to original configuration)
6. **Result reporting** (structured output for orchestrators)

### Exit Codes

Standardized exit codes across all implementations:

| Code | Status | Description |
|------|--------|-------------|
| 0 | Success | Technique executed and reverted successfully |
| 1 | General Failure | Unspecified error occurred |
| 2 | Insufficient Privileges | Administrator rights required |
| 3-5 | Technique-Specific | Bypass/verification/reversion failures |
| 6+ | Variant-Specific | Tool/compatibility/configuration errors |

### Result Communication

All scripts output standardized results for orchestrator integration:

```
TECHNIQUE_RESULT:STATUS|MESSAGE
```

**Status Values:**
- `BYPASSED`: Technique executed successfully
- `FAILED`: Technique failed to execute
- `DETECTED`: Technique was blocked/detected  
- `ERROR`: System error occurred

### JSON Result Format

Detailed results are saved in JSON format:

```json
{
  "TechniqueId": "BP1000.1",
  "TechniqueName": "Safe Mode Boot via bcdedit",
  "Status": "BYPASSED",
  "Message": "Technique executed successfully",
  "Timestamp": "2025-01-27 14:30:45",
  "Details": {
    "BypassApplied": true,
    "BypassVerified": true,
    "StateReverted": true
  },
  "ScriptVersion": "1.0.0"
}
```

## Advanced Features

### Progressive Sophistication

Techniques are organized by increasing sophistication levels:

**Level 1 (Basic)**: Standard tools and methods
- BP1000.1 (bcdedit), BP1002.3 (sc.exe)

**Level 2 (Intermediate)**: PowerShell-native approaches  
- BP1000.3 (PS cmdlets), BP1002.4 (PS cmdlets)

**Level 3 (Advanced)**: Direct system manipulation
- BP1000.4 (registry), BP1002.5 (registry)

**Level 4 (Expert)**: Sophisticated evasion techniques
- BP1001.1 (pre-boot execution with native payloads)
- BP1002.6 (registry save/restore with callback bypass)

### Error Recovery

All scripts implement comprehensive error recovery:

```powershell
# Automatic cleanup on failure
try {
    # Bypass implementation
}
catch {
    # Error logging
    # State restoration attempt
    # Cleanup operations
}
finally {
    # Guaranteed cleanup
}
```

### Partial Success Handling

Advanced variants support partial success scenarios:

```powershell
# BP1002.4 example: Service disabled but not stopped
if ($isDisabled -and -not $isStopped) {
    Write-Log "Partial success - effective after reboot" -Level "WARN"
    return $true  # Still consider success
}
```

## Integration Examples

### Batch Execution

```powershell
# Test multiple Safe Mode variants
$variants = @(
    "BP1000.1-bcdedit",
    "BP1000.3-powershell",
    "BP1000.4-registry"
)

foreach ($variant in $variants) {
    Write-Host "Testing $variant..." -ForegroundColor Cyan
    cd "tests\BP1000-SafeModeBoot\$variant"
    .\run.ps1 -LogPath "D:\TestResults\$variant"
}

# Test advanced pre-boot bypass
Write-Host "Testing BP1001.1-registry (BootExecute)..." -ForegroundColor Magenta
cd "tests\BP1001-BootExecute\BP1001.1-registry"
.\run.ps1 -LogPath "D:\TestResults\BP1001.1" -RegistryMethod "BootExecuteNoPnpSync"
```

### Orchestrator Integration

```powershell
# Example orchestrator pattern
function Invoke-BypassTest {
    param($TechniquePath, $Parameters = @{})
    
    $result = & "$TechniquePath\run.ps1" @Parameters
    
    # Parse standardized output
    if ($result -match "TECHNIQUE_RESULT:(.+)\|(.+)") {
        return @{
            Status = $matches[1]
            Message = $matches[2]
            JsonPath = (Get-ChildItem "$LogPath\*_result.json" | Sort LastWriteTime | Select -Last 1).FullName
        }
    }
}
```

## Extending the Framework

### Adding New Techniques

1. **Create Technique Directory Structure**:
```
tests/BP[ID]-[TechniqueName]/
├── BP[ID]-[TechniqueName].md          # Technique overview
├── BP[ID].[Variant]-[method]/         # Variant implementation
│   ├── run.ps1                        # Entry point
│   └── README.md                       # Variant documentation
└── [additional variants...]
```

2. **Implement Standard Template**:

```powershell
#==============================================================================
# BP[ID].[Variant] - [Technique Name] via [Method]
# EDR Bypass Testing Automation Framework
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\EDRBypassTests\Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReversion = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose = $false
)

# Constants
$TECHNIQUE_ID = "BP[ID].[Variant]"
$TECHNIQUE_NAME = "[Technique Name] via [Method]"
$SCRIPT_VERSION = "1.0.0"

# Result constants
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_ERROR = "ERROR"

# Implement standard functions:
# - Initialize-Logging
# - Write-Log  
# - Test-AdminPrivileges
# - Write-TestResult
# - Backup-OriginalState
# - Invoke-BypassTechnique
# - Test-BypassSuccess
# - Invoke-StateReversion
# - Test-ReversionSuccess
# - main

# Execute main function
main
```

3. **Follow Framework Patterns**:
- Use identical logging and error handling
- Implement state backup/restoration
- Support standard parameters
- Provide comprehensive documentation
- Include technique-specific exit codes

### Best Practices for New Implementations

**Code Standards**:
- Use strict mode: `Set-StrictMode -Version Latest`
- Consistent error handling: `$ErrorActionPreference = "Stop"`
- Comprehensive logging at all stages
- Graceful cleanup in finally blocks

**Documentation Standards**:
- Technique overview with MITRE ATT&CK mapping
- Platform compatibility matrix
- Usage examples and parameter documentation
- Troubleshooting guide with common issues
- Integration examples

**Testing Standards**:
- Test on multiple Windows versions
- Verify state restoration in all scenarios
- Test privilege escalation requirements
- Validate orchestrator integration
- Document performance characteristics

## Security Considerations

### Legitimate Use Cases

This framework is designed exclusively for:
- **Authorized Security Testing**: Evaluating EDR effectiveness in controlled environments
- **Red Team Exercises**: Simulating advanced persistent threat techniques  
- **Security Research**: Understanding bypass methodologies for defensive improvements
- **Purple Team Activities**: Improving detection and response capabilities

### Operational Security

- **Controlled Environments**: Only use in isolated test environments
- **Administrative Privileges**: All techniques require administrator access
- **Audit Trails**: Comprehensive logging provides complete activity records
- **State Restoration**: Automatic reversion minimizes persistent changes
- **Documentation**: Clear usage patterns prevent accidental deployment

### Legal Compliance

**⚠️ IMPORTANT**: Use of these techniques against systems without explicit authorization is illegal. Users are responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Using techniques only in controlled environments
- Maintaining appropriate documentation and audit trails

## Performance Characteristics

### Execution Times

| Technique Category | Typical Duration | Complexity Factor |
|------------------|------------------|-------------------|
| **Safe Mode (BP1000)** | 5-30 seconds | Boot configuration changes |
| **Pre-Boot Execute (BP1001)** | 10-30 seconds | Binary deployment + registry config |
| **Service Disruption (BP1002)** | 3-45 seconds | Service complexity dependent |
| **Registry Operations** | 1-10 seconds | Fast registry modifications |
| **GUI Automation** | 10-60 seconds | User interface dependent |
| **Save/Restore** | 15-45 seconds | Hive file operations |

### Resource Requirements

- **Memory**: 20-100 MB during execution
- **Disk**: Minimal (logs + temporary files for BP1002.6 + binary deployment for BP1001)
- **CPU**: Low (brief spikes during operations)
- **Network**: None (all operations are local)

## Troubleshooting

### Common Issues

1. **Insufficient Privileges**
   - **Solution**: Run PowerShell as Administrator
   - **Verification**: All scripts check privileges automatically

2. **Execution Policy Restrictions**
   - **Solution**: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`
   - **Alternative**: Use `-ExecutionPolicy Bypass` parameter

3. **Path Not Found Errors**
   - **Solution**: Verify working directory is correct variant folder
   - **Check**: Use absolute paths for log directories

4. **Tool Availability Issues**
   - **Solution**: Verify required tools (bcdedit, sc.exe, etc.) are available
   - **Alternative**: Use different technique variant

5. **Native Binary Missing (BP1001)**
   - **Solution**: Ensure `bootexecute.exe` (or specified binary) exists in technique directory
   - **Requirement**: Must be native Windows executable with NtProcessStartup entry point
   - **Alternative**: Compile from [BootExecuteEDR source](https://github.com/rad9800/BootExecuteEDR)

### Debug Mode

Enable comprehensive debugging across all techniques:

```powershell
.\run.ps1 -Verbose -LogPath "C:\Temp\Debug" -SkipReversion
```

### Log Analysis

Monitor execution through standardized log patterns:

```powershell
# Real-time log monitoring
Get-Content "C:\EDRBypassTests\Logs\*.log" -Wait -Tail 10

# Result parsing
Get-ChildItem "C:\EDRBypassTests\Logs\*_result.json" | 
    ForEach-Object { Get-Content $_ | ConvertFrom-Json } |
    Format-Table TechniqueId, Status, Message
```

## Contributing

### Framework Enhancement

When contributing new techniques or improvements:

1. **Follow Established Patterns**: Use existing implementations as templates
2. **Maintain Consistency**: Adhere to logging, error handling, and documentation standards  
3. **Test Thoroughly**: Verify functionality across supported Windows versions
4. **Document Comprehensively**: Provide complete usage and troubleshooting documentation
5. **Consider Edge Cases**: Handle partial success, cleanup failures, and error recovery

### Code Review Standards

- **Functionality**: Technique works as documented
- **Standards Compliance**: Follows framework patterns
- **Error Handling**: Comprehensive error recovery
- **Documentation**: Complete and accurate
- **Security**: Appropriate for controlled environments only

## Version History

### Version 2.0.0 (January 2025)
- Complete framework redesign with standardized patterns
- Implemented BP1000 series (Safe Mode Boot bypass) - 4 variants
- Implemented BP1001 series (Pre-Boot EDR Bypass) - 1 variant
- Implemented BP1002 series (Service Disruption) - 4 variants  
- Advanced features: partial success handling, registry save/restore, pre-boot execution
- Comprehensive documentation and troubleshooting guides

### Version 1.0.0 (Legacy)
- Initial framework concept
- Basic technique implementations
- Limited standardization

## License

This project is intended for authorized security research and testing purposes only. See individual technique documentation for specific usage guidelines and legal considerations.

---

**Disclaimer**: The techniques and tools within this repository are for authorized security research and testing in controlled laboratory environments only. Unauthorized use against systems without prior explicit consent is illegal and unethical. Users assume full responsibility for compliance with all applicable laws and regulations.