# [cite\_start]BP-1000: Bypass EDR via Safe Mode Boot [cite: 1]

## [cite\_start]Technique Description [cite: 2]

[cite\_start]Attackers can bypass EDR solutions by leveraging Windows Safe Mode to disable or neutralize EDR agents[cite: 3]. [cite\_start]This technique exploits the limited set of services and drivers loaded in Safe Mode, which often excludes security software such as EDR agents[cite: 4]. [cite\_start]Attackers with administrative privileges can configure the system to boot into Safe Mode using tools like bcdedit or msconfig[cite: 5]. [cite\_start]By modifying the Boot Configuration Data (BCD), the attacker sets the boot mode to Safe Mode with Network, where most EDR processes are not initialized[cite: 6]. [cite\_start]Remote attackers need to ensure that a remote access method remains available to them after booting into Safe Mode with Network[cite: 7]. [cite\_start]Some RMM tools have this capability and are commonly installed by threat actors prior to carrying out this attack[cite: 8].

## [cite\_start]Sub-Techniques [cite: 9]

### [cite\_start]BP-1000.1 - Enable Safe Mode using bcdedit.exe [cite: 10, 12, 14]

[cite\_start]Using the command[cite: 11]:

```
[cite_start]bcdedit /set {current} safeboot network [cite: 13]
```

[cite\_start]This sets the system to boot into Safe Mode with Network on the next restart[cite: 15].

[cite\_start]To reset the system to boot normally[cite: 17]:

```
[cite_start]bcdedit /deletevalue {current} safeboot [cite: 16]
```

### [cite\_start]BP-1000.2- Enable Safe Mode using msconfig.exe [cite: 18, 19, 21, 24]

[cite\_start]This method uses the System Configuration utility (`msconfig.exe`)[cite: 24]. [cite\_start]In the 'Boot' tab, an attacker can select the "Safe boot" checkbox and choose the "Network" option[cite: 30, 42].

### [cite\_start]BP-1000.3 Enable Safe Mode using PowerShell cmdlet [cite: 47]

[cite\_start]Starting in Windows 11 21H2, PowerShell provides cmdlets to manipulate the BCD datastore[cite: 48].

[cite\_start]To set the safeboot value[cite: 49]:

```powershell
[cite_start]Set-BcdElement safeboot -Type Integer Value 1 [cite: 50]
```

[cite\_start]To delete it[cite: 51]:

```powershell
[cite_start]Remove-BcdElement safeboot -Force [cite: 52]
```

### [cite\_start]BP-1000.4 - Enable Safe Mode using regedit.exe [cite: 53, 54, 55]

[cite\_start]Alternatively, the attacker can directly edit the registry key[cite: 53]:
[cite\_start]`HKLM\BCD00000000\Objects\{object-guid}\Elements\25000080` [cite: 56, 57]

[cite\_start]The `{object-guid}` is for the BCD object representing the default boot entry[cite: 58]. [cite\_start]This GUID can be found by looking up the value of element `23000003` of the bootmgr BCD object, whose GUID is `{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}`[cite: 58, 59].

[cite\_start]Once the default bootmgr object's GUID is found, the element `25000080` controls safeboot mode as follows[cite: 60]:

  * [cite\_start]**does not exist**: Normal boot [cite: 61]
  * [cite\_start]**0**: Minimal [cite: 62]
  * [cite\_start]**1**: Network [cite: 63]
  * [cite\_start]**2**: DsRepair [cite: 64]

[cite\_start]If the `Element` value exists, it is an 8-byte `REG_BINARY` value that corresponds to a 64-bit unsigned little-endian integer[cite: 65].

[cite\_start]During the boot sequence, Windows mounts the BCD hive at `HKEY_LOCAL_MACHINE\BCD00000000`, but it can be manually unmounted and mounted under a different key[cite: 67]. [cite\_start]The BCD editing tools (`bcdedit` and `msconfig`) will only recognize it when it's mounted at `HKEY_LOCAL_MACHINE` under a key that starts with "BCD" (case insensitive)[cite: 67]. [cite\_start]Manual registry editing is necessary when the hive is mounted elsewhere, as the tools will fail[cite: 67]. [cite\_start]By default, only the SYSTEM account can modify these keys, but local administrators can grant themselves permission[cite: 67].

### [cite\_start]BP-1000.5 - Enable Safe Mode via BCD file overwrite [cite: 67]

[cite\_start]The BCD registry hive is typically stored in the EFI System Partition, which usually does not have an assigned drive letter[cite: 67]. [cite\_start]To access the partition's contents, a drive letter can be assigned using the `diskpart` tool[cite: 67].

```
[cite_start]C:\Windows\System32>diskpart [cite: 67]
[cite_start]Microsoft DiskPart version 10.0.26100.1150 [cite: 67]

[cite_start]Copyright (C) Microsoft Corporation. [cite: 67]

[cite_start]On computer: EDR-W11-ATLAS [cite: 67]

[cite_start]DISKPART> list disk [cite: 67]

  [cite_start]Disk ###  Status      Size     Free     Dyn  Gpt [cite: 67]
  [cite_start]--------  ----------  -------  -------  ---  --- [cite: 67]
  [cite_start]Disk 0    Online       64 GB  1024 KB        * [cite: 67]

[cite_start]DISKPART> select disk 0 [cite: 67]

[cite_start]Disk 0 is now the selected disk. [cite: 67]

[cite_start]DISKPART> list part [cite: 67]

  [cite_start]Partition ###  Type          Size     Offset [cite: 69]
  [cite_start]-------------  ------------  -------  -------- [cite: 67]
  [cite_start]Partition 1    System         100 MB  1024 KB [cite: 74, 75, 76, 77]
  [cite_start]Partition 2    Reserved        16 MB   101 MB [cite: 79, 80, 81, 82]
  [cite_start]Partition 3    Primary         63 GB   117 MB [cite: 84, 85, 86, 87]
  [cite_start]Partition 4    Recovery       644 MB    63 GB [cite: 89, 90, 91, 92]

[cite_start]DISKPART> select part 1 [cite: 94]

[cite_start]Partition 1 is now the selected partition. [cite: 96]

[cite_start]DISKPART> assign letter=V [cite: 98]
```

[cite\_start]Once the partition's contents are accessible, the BCD hive is located at `\EFI\Microsoft\Boot\BCD`[cite: 99]. [cite\_start]It can be overwritten with a BCD file prepared on another machine[cite: 99]. [cite\_start]To do this, the BCD hive must first be unmounted from the registry[cite: 100]. [cite\_start]This allows the BCD file to be replaced with the attacker's version[cite: 101].

```
[cite_start]copy /Y C:\AttackStaging\BCD V:\EFI\Microsoft\Boot [cite: 102]
```

## [cite\_start]Detection Opportunities [cite: 103]

  * [cite\_start]**[Evaded by BP-1000.5]** Modifying the `safeboot` value in the registry[cite: 104]. [cite\_start]Look for the registry path pattern `HKLM\BCD*\Objects\{????????-????-????-????-????????????}\Elements\25000080` (case-insensitive)[cite: 104, 105]. [cite\_start]Flag operations such as `RegCreateKey`, `RegCreateKeyEx`, `RegRenameKey`, and `RegSetValue` (Element)[cite: 105]. [cite\_start]Modifications made without standard tools (`bcdedit.exe` or `msconfig.exe`) are especially suspicious, as are modifications preceded by the installation of an RMM tool to start in Safe Mode[cite: 106, 107].
  * [cite\_start]**[Potential attempt to evade BP-1000 mitigations]** Loading the BCD hive to a key other than `HKLM\BCD00000000`[cite: 108]. [cite\_start]This is not a normal operation but is a necessary step for some attack variants[cite: 109]. [cite\_start]Look for the `RegLoadKey` operation with a target path other than `HKLM\BCD00000000` and a hive path of `\EFI\Microsoft\Boot\BCD`[cite: 110].
  * [cite\_start]**[Potential attempt to evade BP-1000 mitigations]** Unloading the BCD hive from `HKLM\BCD00000000`[cite: 111]. [cite\_start]This is not a normal operation but is required for certain attack variants[cite: 112]. [cite\_start]Look for the `RegUnloadKey` operation with the target path `HKLM\BCD00000000`[cite: 113].
  * [cite\_start]**[Potential attempt to evade BP-1000 mitigations]** Directly writing to the `\EFI\Microsoft\Boot\BCD` file with a non-standard tool[cite: 114, 115]. [cite\_start]This is done to flag threat actors trying to manipulate the BCD registry hive directly on disk, either by copying a prepared BCD hive file or by modifying its binary content[cite: 115]. [cite\_start]Only the kernel and a few known system processes should be writing to this file[cite: 116].
  * [cite\_start]**[Potential BP-1000 attack precursor]** Adding new services that start in Safe Mode[cite: 117]. [cite\_start]Monitor for new keys being created in the registry paths `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network` and `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal` (`containerworker.exe` is a potential false positive)[cite: 118, 119, 120, 121, 122].

## [cite\_start]Prevention Opportunities [cite: 123]

  * [cite\_start]To block Safe Mode entirely, block `RegCreateKey`, `RegCreateKeyEx`, and `RegRenameKey` operations that target the registry path `HKLM\BCD*\Objects\{????????-????-????-????-????????????}\Elements\25000080`[cite: 124, 125].
  * [cite\_start]To block only Safe Mode with Network, block `RegSetValue` operations that target the `Element` value `1` for the same registry path mentioned above[cite: 126].

## [cite\_start]References [cite: 127]

  * [cite\_start][https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm](https://www.geoffchappell.com/notes/windows/boot/bcd/index.htm) [cite: 128]