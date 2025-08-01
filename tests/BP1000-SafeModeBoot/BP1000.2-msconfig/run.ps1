#==============================================================================
# BP1000.2 - Safe Mode Boot Bypass via msconfig.exe (GUI)
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by configuring system to boot into Safe Mode with Network
#   using msconfig.exe GUI manipulation via AutoIt automation, then reverts the 
#   configuration after verification.
#
# DESCRIPTION
#   This script implements BP-1000.2 technique which uses the System Configuration
#   utility (msconfig.exe) to set the system to boot into Safe Mode with Network
#   on next restart. Most EDR agents do not load in Safe Mode, effectively 
#   bypassing their protection.
#   
#   Test Flow:
#   1. Backup current boot configuration
#   2. Execute AutoIt script to manipulate msconfig.exe GUI
#   3. Verify bypass was applied successfully (check BCD)
#   4. Revert configuration using bcdedit
#   5. Verify reversion was successful
#   6. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for BCD operations)
#   - Windows Vista or later (msconfig availability)
#   - AutoIt executable (msconfig_safe_mode.exe) in script directory
#   - Interactive desktop session (GUI automation)
#
# EXIT CODES
#   0 = Success (bypass applied and reverted successfully)
#   1 = General failure
#   2 = Insufficient privileges
#   3 = Bypass application failed
#   4 = Bypass verification failed
#   5 = Reversion failed
#   6 = AutoIt executable not found
#   7 = GUI automation failed
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\EDRBypassTests\Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReversion = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$AutoItTimeoutSeconds = 30
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Constants and Configuration
$TECHNIQUE_ID = "BP1000.2"
$TECHNIQUE_NAME = "Safe Mode Boot via msconfig (GUI)"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1000.2-msconfig"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# BCD constants
$BCD_SAFEBOOT_NETWORK = "network"
$BCD_CURRENT_ENTRY = "{current}"

# AutoIt executable
$AUTOIT_EXECUTABLE = "msconfig_safe_mode.exe"
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

function Test-AutoItExecutable {
    try {
        $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
        $autoItPath = Join-Path $scriptDir $AUTOIT_EXECUTABLE
        
        Write-Log "Checking for AutoIt executable: $autoItPath" -Level "DEBUG"
        
        if (Test-Path $autoItPath) {
            Write-Log "AutoIt executable found: $autoItPath" -Level "DEBUG"
            return $autoItPath
        }
        else {
            Write-Log "AutoIt executable not found: $autoItPath" -Level "ERROR"
            return $null
        }
    }
    catch {
        Write-Log "Failed to check AutoIt executable: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Test-InteractiveSession {
    try {
        $sessionInfo = query session 2>&1
        $currentSession = $sessionInfo | Where-Object { $_ -match "console.*Active" }
        
        if ($currentSession) {
            Write-Log "Interactive console session detected" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "No interactive console session found - GUI automation may fail" -Level "WARN"
            return $false
        }
    }
    catch {
        Write-Log "Failed to check interactive session: $($_.Exception.Message)" -Level "WARN"
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

function Invoke-AutoItBypass {
    param([string]$AutoItPath)
    
    try {
        Write-Log "Executing AutoIt GUI automation for msconfig..." -Level "INFO"
        Write-Log "AutoIt executable: $AutoItPath" -Level "DEBUG"
        Write-Log "Timeout: $AutoItTimeoutSeconds seconds" -Level "DEBUG"
        
        # Start the AutoIt process
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $AutoItPath
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $false
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        Write-Log "Starting AutoIt process..." -Level "DEBUG"
        $started = $process.Start()
        
        if (-not $started) {
            throw "Failed to start AutoIt process"
        }
        
        Write-Log "AutoIt process started (PID: $($process.Id))" -Level "DEBUG"
        
        # Wait for the process to complete with timeout
        $completed = $process.WaitForExit($AutoItTimeoutSeconds * 1000)
        
        if (-not $completed) {
            Write-Log "AutoIt process timed out after $AutoItTimeoutSeconds seconds" -Level "ERROR"
            try {
                $process.Kill()
                Write-Log "AutoIt process killed due to timeout" -Level "WARN"
            }
            catch {
                Write-Log "Failed to kill timed-out AutoIt process: $($_.Exception.Message)" -Level "ERROR"
            }
            return $false
        }
        
        $exitCode = $process.ExitCode
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        
        Write-Log "AutoIt process completed with exit code: $exitCode" -Level "DEBUG"
        
        if ($stdout) {
            Write-Log "AutoIt STDOUT: $stdout" -Level "DEBUG"
        }
        
        if ($stderr) {
            Write-Log "AutoIt STDERR: $stderr" -Level "DEBUG"
        }
        
        if ($exitCode -eq 0) {
            Write-Log "AutoIt GUI automation completed successfully" -Level "INFO"
            return $true
        }
        else {
            Write-Log "AutoIt GUI automation failed with exit code: $exitCode" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to execute AutoIt bypass: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    finally {
        if ($process -and -not $process.HasExited) {
            try {
                $process.Kill()
            }
            catch {
                Write-Log "Failed to cleanup AutoIt process: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }
}

function Test-BypassSuccess {
    try {
        Write-Log "Verifying bypass was applied successfully..." -Level "INFO"
        
        # Small delay to ensure BCD changes are persisted
        Start-Sleep -Seconds 2
        
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
        Write-Log "Reverting system to original state using bcdedit..." -Level "INFO"
        
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
            $errorMsg = "Administrative privileges required for BCD operations"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 2
        }
        Write-Log "Administrative privileges confirmed" -Level "INFO"
        
        # Check bcdedit availability (needed for verification and reversion)
        if (-not (Test-BcdToolAvailability)) {
            $errorMsg = "bcdedit tool is not available or accessible"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        Write-Log "bcdedit tool availability confirmed" -Level "INFO"
        
        # Check AutoIt executable
        $autoItPath = Test-AutoItExecutable
        if (-not $autoItPath) {
            $errorMsg = "AutoIt executable ($AUTOIT_EXECUTABLE) not found in script directory"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 6
        }
        Write-Log "AutoIt executable confirmed: $autoItPath" -Level "INFO"
        
        # Check interactive session
        $hasInteractiveSession = Test-InteractiveSession
        if (-not $hasInteractiveSession) {
            Write-Log "Warning: No interactive console session detected - GUI automation may fail" -Level "WARN"
        }
        
        Write-Log "=== EXECUTING BYPASS TECHNIQUE ===" -Level "INFO"
        
        # Backup original state
        if (-not (Backup-OriginalState)) {
            $errorMsg = "Failed to backup original system state"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        
        # Execute bypass technique using AutoIt
        if (-not (Invoke-AutoItBypass -AutoItPath $autoItPath)) {
            $errorMsg = "Failed to execute AutoIt GUI automation"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 7
        }
        
        # Verify bypass was applied
        if (-not (Test-BypassSuccess)) {
            $errorMsg = "Bypass technique failed verification - BCD not modified as expected"
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
        $successMsg = "BP1000.2 bypass technique executed and verified successfully"
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            OriginalSafebootValue = $global:OriginalState.SafebootValue
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            AutoItExecutable = $autoItPath
            InteractiveSession = $hasInteractiveSession
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