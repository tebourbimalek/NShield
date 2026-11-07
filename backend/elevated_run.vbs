' NShield - hidden elevated runner (no console window of its own).
' Opened with "runas" by open_netguard.vbs. Runs the batch fully hidden,
' which avoids the white console flash Windows can show when a .bat is
' elevated directly.
Option Explicit

Dim shell, fso, root
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(fso.GetParentFolderName(WScript.ScriptFullName))

Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = root

' fully hidden batch start
shell.Run """" & root & "\run.bat"" go", 0, False
