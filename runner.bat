@ECHO off
ECHO Checking for Mariana Updates
cd %~dp0
git pull
start "" pythonw proxyserver.py
exit