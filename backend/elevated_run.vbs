' NShield - hidden elevated runner (no console window of its own).
' Opened with "runas" by open_nshield.vbs. Runs the batch fully hidden,
' which avoids the white console flash Windows can show when a .bat is
' elevated directly.
Option Explicit

Dim shell, root
root = "C:\Users\GIGABYTE\Desktop\nshield"

Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = root

' fully hidden batch start
shell.Run """" & root & "\run.bat"" go", 0, False
