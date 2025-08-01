; Script to enable Safe Mode with Networking via msconfig.exe

; Run msconfig
Run("msconfig.exe")

; Wait for the System Configuration window to be active
Local $hWnd = WinWaitActive("System Configuration", "", 10)

; If the window does not appear after 10 seconds, exit the script.
If $hWnd = 0 Then
    MsgBox(48, "Error", "System Configuration window did not appear.")
    Exit
EndIf

; Send a direct command to the tab control to switch one tab to the right.
ControlCommand($hWnd, "", "[CLASS:SysTabControl32; INSTANCE:1]", "TabRight", "")

; Check the "Safe boot" checkbox using its text property.
ControlCommand($hWnd, "", "[CLASS:Button; TEXT:Sa&fe boot]", "Check", "")

; Select the "Network" radio button using its text property.
ControlCommand($hWnd, "", "[CLASS:Button; TEXT:Net&work]", "Check", "")

; Click the "OK" button using its text property.
ControlClick($hWnd, "", "[CLASS:Button; TEXT:OK]")

; Wait for the restart prompt dialog to appear
WinWaitActive("System Configuration", "You may need to restart", 10)

; Click the "Exit without restart" button using its text property.
ControlClick("System Configuration", "", "[CLASS:Button; TEXT:E&xit without restart]")