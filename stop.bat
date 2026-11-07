@echo off
:: NShield stopper.
:: Double-click and answer "Yes" when Windows asks for permission.
:: This quietly ends the app in the background.
:: TIP: if any device is currently cut off, press "Restore everyone" in the
:: web page first so it comes back online immediately - this stopper can also
:: be used alone, and everything heals by itself shortly after.
setlocal
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WindowStyle Hidden"
    exit /b
)
taskkill /F /IM pythonw.exe >nul 2>&1
exit /b
