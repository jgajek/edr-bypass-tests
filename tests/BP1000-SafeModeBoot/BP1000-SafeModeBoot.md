# BP-1000: Bypass EDR via Safe Mode Boot

## Technique Description

Attackers can bypass EDR solutions by leveraging Windows Safe Mode to disable or neutralize EDR agents. This technique exploits the limited set of services and drivers loaded in Safe Mode, which often excludes security software such as EDR agents. Attackers with administrative privileges can configure the system to boot into Safe Mode using tools like bcdedit or msconfig. By modifying the Boot Configuration Data (BCD), the attacker sets the boot mode to Safe Mode with Network, where most EDR processes are not initialized. Remote attackers need to ensure that a remote access method remains available to them after booting into Safe Mode with Network. Some RMM tools have this capability and are commonly installed by threat actors prior to carrying out this attack.

## Sub-Techniques 

### BP-1000.1 - Enable Safe Mode using bcdedit.exe 

Using the command:

```
bcdedit /set {current} safeboot network 
```

This sets the system to boot into Safe Mode with Network on the next restart.

To reset the system to boot normally:

```
bcdedit /deletevalue {current} safeboot 
```

### BP-1000.2- Enable Safe Mode using msconfig.exe 

This method uses the System Configuration utility (`msconfig.exe`). In the 'Boot' tab, an attacker can select the "Safe boot" checkbox and choose the "Network" option.

### BP-1000.3 Enable Safe Mode using PowerShell cmdlet 

Starting in Windows 11 21H2, PowerShell provides cmdlets to manipulate the BCD datastore.

To set the safeboot value:

```powershell
Set-BcdElement safeboot -Type Integer Value 1 
```

To delete it:

```powershell
Remove-BcdElement safeboot -Force 
```

### BP-1000.4 - Enable Safe Mode using regedit.exe 

Alternatively, the attacker can directly edit the registry key:
`HKLM\BCD00000000\Objects\{object-guid}\Elements\25000080` 

The `{object-guid}` is for the BCD object representing the default boot entry. This GUID can be found by looking up the value of element `23000003` of the bootmgr BCD object, whose GUID is `{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}`.

Once the default bootmgr object's GUID is found, the element `25000080` controls safeboot mode as follows:

  * **does not exist**: Normal boot 
  * **0**: Minimal 
  * **1**: Network 
  * **2**: DsRepair 

If the `Element` value exists, it is an 8-byte `REG_BINARY` value that corresponds to a 64-bit unsigned little-endian integer.

During the boot sequence, Windows mounts the BCD hive at `HKEY_LOCAL_MACHINE\BCD00000000`, but it can be manually unmounted and mounted under a different key. The BCD editing tools (`bcdedit` and `msconfig`) will only recognize it when it's mounted at `HKEY_LOCAL_MACHINE` under a key that starts with "BCD" (case insensitive). Manual registry editing is necessary when the hive is mounted elsewhere, as the tools will fail. By default, only the SYSTEM account can modify these keys, but local administrators can grant themselves permission.

### BP-1000.5 - Enable Safe Mode via BCD file overwrite 

The BCD registry hive is typically stored in the EFI System Partition, which usually does not have an assigned drive letter. To access the partition's contents, a drive letter can be assigned using the `diskpart` tool.

```
C:\Windows\System32>diskpart 
Microsoft DiskPart version 10.0.26100.1150 

Copyright (C) Microsoft Corporation. 

On computer: EDR-W11-ATLAS 

DISKPART> list disk 

  Disk ###  Status      Size     Free     Dyn  Gpt 
  --------  ----------  -------  -------  ---  --- 
  Disk 0    Online       64 GB  1024 KB        * 

DISKPART> select disk 0 

Disk 0 is now the selected disk. 

DISKPART> list part 

  Partition ###  Type          Size     Offset 
  -------------  ------------  -------  -------- 
  Partition 1    System         100 MB  1024 KB 
  Partition 2    Reserved        16 MB   101 MB 
  Partition 3    Primary         63 GB   117 MB 
  Partition 4    Recovery       644 MB    63 GB 

DISKPART> select part 1 

Partition 1 is now the selected partition. 

DISKPART> assign letter=V 
```

Once the partition's contents are accessible, the BCD hive is located at `\EFI\Microsoft\Boot\BCD`. It can be overwritten with a BCD file prepared on another machine. To do this, the BCD hive must first be unmounted from the registry. This allows the BCD file to be replaced with the attacker's version.

```
copy /Y C:\AttackStaging\BCD V:\EFI\Microsoft\Boot 
```

## Detection Opportunities 

  * **[Evaded by BP-1000.5]** Modifying the `safeboot` value in the registry. Look for the registry path pattern `HKLM\BCD*\Objects\{????????-????-????-????-????????????}\Elements\25000080` (case-insensitive). Flag operations such as `RegCreateKey`, `RegCreateKeyEx`, `RegRenameKey`, and `RegSetValue` (Element). Modifications made without standard tools (`bcdedit.exe` or `msconfig.exe`) are especially suspicious, as are modifications preceded by the installation of an RMM tool to start in Safe Mode.
  * **[Potential attempt to evade BP-1000 mitigations]** Loading the BCD hive to a key other than `HKLM\BCD00000000`. This is not a normal operation but is a necessary step for some attack variants. Look for the `RegLoadKey` operation with a target path other than `HKLM\BCD00000000` and a hive path of `\EFI\Microsoft\Boot\BCD`.
  * **[Potential attempt to evade BP-1000 mitigations]** Unloading the BCD hive from `HKLM\BCD00000000`. This is not a normal operation but is required for certain attack variants. Look for the `RegUnloadKey` operation with the target path `HKLM\BCD00000000`.
  * **[Potential attempt to evade BP-1000 mitigations]** Directly writing to the `\EFI\Microsoft\Boot\BCD` file with a non-standard tool. This is done to flag threat actors trying to manipulate the BCD registry hive directly on disk, either by copying a prepared BCD hive file or by modifying its binary content. Only the kernel and a few known system processes should be writing to this file.
  * **[Potential BP-1000 attack precursor]** Adding new services that start in Safe Mode. Monitor for new keys being created in the registry paths `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network` and `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal` (`containerworker.exe` is a potential false positive).

## Prevention Opportunities 

  * To block Safe Mode entirely, block `RegCreateKey`, `RegCreateKeyEx`, and `RegRenameKey` operations that target the registry path `HKLM\BCD*\Objects\{????????-????-????-????-????????????}\Elements\25000080`.
  * To block only Safe Mode with Network, block `RegSetValue` operations that target the `Element` value `1` for the same registry path mentioned above.

## References 

  * [https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm](https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm) 