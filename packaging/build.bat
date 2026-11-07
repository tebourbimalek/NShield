@echo off
:: Build a standalone Windows bundle of NetGuard.
:: Requires: Python 3.11+, Node 18+, and (for the installer) Inno Setup 6.
setlocal
cd /d "%~dp0.."

echo [1/4] Building the web page...
pushd frontend
call npm install
if errorlevel 1 ( echo npm install failed & popd & exit /b 1 )
call npm run build
if errorlevel 1 ( echo npm build failed & popd & exit /b 1 )
popd

echo [2/4] Installing PyInstaller...
backend\venv\Scripts\python.exe -m pip install pyinstaller
if errorlevel 1 ( echo pip install failed & exit /b 1 )

echo [3/4] Bundling with PyInstaller...
backend\venv\Scripts\pyinstaller.exe packaging\netguard.spec --noconfirm
if errorlevel 1 ( echo pyinstaller failed & exit /b 1 )

echo [4/4] Done. Bundle is in dist\NetGuard\
echo        To make an installer, open packaging\installer.iss in Inno Setup.
pause
