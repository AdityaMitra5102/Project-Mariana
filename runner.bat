@ECHO off
ECHO Checking for Mariana Updates
cd %~dp0

echo MsgBox "Starting Mariana's Qubit!",64,"Please wait" > %temp%\msg.vbs
start "" wscript "%temp%\msg.vbs"
git config --global --add safe.directory %~dp0
git stash
git pull

pythonw wintray.py
