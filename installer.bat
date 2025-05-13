@Echo off
cd %UserProfile%\AppData\Local\Programs
del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python.exe
del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python3.exe
for /f "usebackq" %%F in (`where python`) do del %%F
for /f "usebackq" %%F in (`where pythonw`) do del %%F
for /f "usebackq" %%F in (`where py`) do del %%F
curl https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe -o python-3.12.1-amd64.exe
winget install Git.Git -e --source winget --accept-source-agreements
START /wait python-3.12.1-amd64.exe /passive PrependPath=1 Include_pip=1 InstallAllUsers=1
start /wait chrome_installer.exe /silent /install
python -m pip install --upgrade pip
git clone https://github.com/AdityaMitra5102/Project-Mariana
cd Project-Mariana
start /wait ChromeSetup.exe /silent /install
python -m pip install -r requirements.txt
schtasks /create /tn "Mariana" /tr "%~dp0runner.bat" /sc onstart /ru "" /f
schtasks /run /tn "Mariana"
set "currentDir=%~dp0"
set "batchFile=%currentDir%chrome.bat"
set "iconFile=%currentDir%icon.ico"
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Mariana.lnk'); $Shortcut.TargetPath = '%batchFile%'; $Shortcut.IconLocation = '%iconFile%'; $Shortcut.Save()"
powershell -Command "$WshShell = New-Object -ComObject WScript.Shell; $StartMenuPath = [Environment]::GetFolderPath('StartMenu') + '\Programs'; if(!(Test-Path \"$StartMenuPath\Mariana.lnk\")) { $Shortcut = $WshShell.CreateShortcut(\"$StartMenuPath\Mariana.lnk\"); $Shortcut.TargetPath = '%batchFile%'; $Shortcut.IconLocation = '%iconFile%'; $Shortcut.Save() }"
start "" "chrome.bat"