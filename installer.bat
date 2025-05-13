@echo off
cd %UserProfile%\AppData\Local\Programs
del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python.exe
del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python3.exe
for /f "usebackq" %%F in (`where python`) do del "%%F"
for /f "usebackq" %%F in (`where pythonw`) do del "%%F"
for /f "usebackq" %%F in (`where py`) do del "%%F"
curl -L https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe -o python-3.12.1-amd64.exe
curl -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://github.com/git-for-windows/git/releases/download/v2.49.0.windows.1/Git-2.49.0-64-bit.exe -o Git-2.49.0-64-bit.exe
START /wait python-3.12.1-amd64.exe /passive PrependPath=1 Include_pip=1 InstallAllUsers=1
START /wait Git-2.49.0-64-bit.exe /SILENT
%userprofile%\AppData\Local\Microsoft\WindowsApps\winget.exe install Git.Git -e --source winget --accept-source-agreements
python -m pip install --upgrade pip
taskkill /F /IM python.exe
taskkill /F /IM pythonw.exe
rmdir /S /Q "Project-Mariana"
git clone https://github.com/AdityaMitra5102/Project-Mariana
cd Project-Mariana
start /wait ChromeSetup.exe /install
python -m pip install cryptography psutil requests flask
copy "startup.bat" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
copy "mariana.bat" "%UserProfile%/Desktop"
copy "mariana.bat" "%OneDrive%/Desktop"
taskkill /F /IM chrome.exe
start "" "runner.bat"
echo "Installation complete"
exit
