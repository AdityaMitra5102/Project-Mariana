@ECHO off
ECHO Checking for Mariana Updates
cd %~dp0
git config --global --add safe.directory %~dp0
git pull
start /B "" pythonw "%~dp0proxyserver.py"
