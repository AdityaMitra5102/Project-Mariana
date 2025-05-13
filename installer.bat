cd %UserProfile%\AppData\Local\Programs
del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python.exe
del %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\python3.exe
for /f "usebackq" %%F in (`where python`) do del "%%F"
for /f "usebackq" %%F in (`where pythonw`) do del "%%F"
for /f "usebackq" %%F in (`where py`) do del "%%F"
curl https://www.python.org/ftp/python/3.12.1/python-3.12.1-amd64.exe -o python-3.12.1-amd64.exe
winget install Git.Git -e --source winget --accept-source-agreements
START /wait python-3.12.1-amd64.exe /passive PrependPath=1 Include_pip=1 InstallAllUsers=1
python -m pip install --upgrade pip
git clone https://github.com/AdityaMitra5102/Project-Mariana
cd Project-Mariana
start /wait ChromeSetup.exe /silent /install
python -m pip install cryptography psutil requests flask
sc create Mariana binPath= "cmd /c start /B \"\" \"%UserProfile%\AppData\Local\Programs\Project-Mariana\runner.bat\"" start=auto obj=LocalSystem type=own error=normal
sc start Mariana
mklink chrome.bat %UserProfile%/Desktop
start "" "chrome.bat"
