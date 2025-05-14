@echo off
taskkill /F /IM pythonw.exe
taskkill /F /IM python.exe
start /B "" cmd /C "%UserProfile%\AppData\Local\Programs\Project-Mariana\runner.bat"
exit
