@echo off
:: NetGuard starter (run directly, or elevated with "go" by the hidden launcher).
:: Ordinary double-click: a dark splash shows until the page opens.
:: Console windows are fully hidden along this path.
setlocal
cd /d "%~dp0"

:: --- elevated with "go": setup (only if missing) then start the app -------- -
if /i "%~1"=="go" goto elevated

:: --- entry point -------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% equ 0 goto elevated

:: not admin yet
if not exist "backend\venv\Scripts\pythonw.exe" goto elevate-visible
if not exist "frontend\dist\index.html" goto elevate-visible

:: everything ready: splash + quiet elevation through the windowless runner
start "" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0backend\splash.ps1"
powershell -NoProfile -Command "Start-Process wscript -ArgumentList '\"%~dp0backend\\elevated_run.vbs\"' -Verb RunAs"
exit /b

:elevate-visible
:: first-time setup needs a visible console to show progress
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b

:: --------------------------------------------------------------------------- -
:elevated
:: ----------------------------------------------- first-run setup (once) --- -
if not exist "backend\config.yaml" if exist "backend\config.example.yaml" copy "backend\config.example.yaml" "backend\config.yaml" >nul
if not exist "backend\venv\Scripts\pythonw.exe" (
    echo [NetGuard] First run: installing everything that is needed. Once only.
    python -m venv "backend\venv" 2>nul || py -3 -m venv "backend\venv"
    if not exist "backend\venv\Scripts\python.exe" (
        echo [NetGuard] ERROR: Python 3.11+ was not found. Install it from python.org and try again.
        pause & exit /b 1
    )
    "backend\venv\Scripts\python.exe" -m pip install -r "backend\requirements.txt"
)
if not exist "frontend\dist\index.html" (
    echo [NetGuard] First run: building the web page. Once only.
    pushd frontend
    call npm install
    call npm run build
    popd
    if not exist "frontend\dist\index.html" (
        echo [NetGuard] ERROR: the web page could not be built - see the messages above.
        pause & exit /b 1
    )
)

:: create a desktop shortcut on first run (one icon for everything)
if not exist "%USERPROFILE%\Desktop\NetGuard.lnk" (
    powershell -NoProfile -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\NetGuard.lnk'); $s.TargetPath = '%~f0'; $s.WorkingDirectory = '%~dp0'; $s.IconLocation = '%~dp0backend\assets\app.ico'; $s.Description = 'NetGuard - manage your home network'; $s.Save()"
)

:: --- already running? toggle: stop it instead of starting ------------------
powershell -NoProfile -Command "try { $null = Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:8000/api/self -TimeoutSec 2; exit 0 } catch { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    powershell -NoProfile -Command "try { Invoke-WebRequest -UseBasicParsing -Method POST -Uri http://127.0.0.1:8000/api/shutdown -TimeoutSec 5 | Out-Null } catch {}" >nul 2>&1
    for /l %%i in (1,1,20) do (
        powershell -NoProfile -Command "try { $null = Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:8000/api/self -TimeoutSec 1; exit 0 } catch { exit 1 }" >nul 2>&1
        if errorlevel 1 goto :stopped
        timeout /t 1 /nobreak >nul
    )
    :stopped
    exit /b 0
)

start "" "backend\venv\Scripts\pythonw.exe" "backend\main.py"
exit /b
