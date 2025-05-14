@ECHO off
ECHO Checking for Mariana Updates
cd %~dp0
git config --global --add safe.directory %~dp0
git pull
python -m pip install --upgrade pip
python -m pip install cryptography psutil requests flask flask-cors
start /B "" pythonw "%~dp0proxyserver.py"
