@ECHO off
ECHO Checking for Mariana Updates
cd %~dp0

echo MsgBox "Starting Mariana's Qubit!",64,"Please wait" > %temp%\msg.vbs
start "" wscript "%temp%\msg.vbs"


taskkill /F /IM python.exe
taskkill /F /IM pythow.exe

start /B "" pythonw "%~dp0wintray.py"
git config --global --add safe.directory %~dp0
git pull
python -m pip install --upgrade pip
python -m pip install cryptography psutil requests flask flask-cors
