' NShield - the desktop double-click entry.
' 1) shows the splash window right away (no console flash anywhere)
' 2) then quietly elevates run.bat (Windows asks "Yes" once) to start the app
Option Explicit

Dim shell, shellX, fso, root
Set fso = CreateObject("Scripting.FileSystemObject")
' This file lives in backend\, so its grandparent is the repo root.
root = fso.GetParentFolderName(fso.GetParentFolderName(WScript.ScriptFullName))

Set shell  = CreateObject("WScript.Shell")
Set shellX = CreateObject("Shell.Application")

' splash shows first so something is on screen during the elevation prompt
shell.Run "powershell -NoProfile -ExecutionPolicy Bypass -File """ & root & "\backend\splash.ps1""", 0, False

' elevated + fully hidden start of the app (via a windowless runner so no
' console - and no white console flash - is ever created)
shellX.ShellExecute "wscript.exe", """" & root & "\backend\elevated_run.vbs""", root, "runas", 0
