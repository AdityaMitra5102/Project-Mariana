cd "%AppData%"
taskkill /F /IM msiexec.exe
taskkill /F /IM python.exe
taskkill /F /IM pythonw.exe
curl -L https://www.python.org/ftp/python/3.13.3/python-3.13.3-amd64.exe -o python-inst.exe
curl -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://github.com/git-for-windows/git/releases/download/v2.49.0.windows.1/Git-2.49.0-64-bit.exe -o Git-2.49.0-64-bit.exe
curl -L -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" https://github.com/AdityaMitra5102/mariana-browser/releases/download/v1/mariana-browser.1.0.0.msi -o mariana-browser.msi
START /wait python-inst.exe /uninstall /passive
START /wait python-inst.exe /passive PrependPath=1 InstallAllUsers=1 Include_exe=1
START /wait Git-2.49.0-64-bit.exe /SILENT
setlocal EnableDelayedExpansion
for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH') do set "SYS_PATH=%%b"
for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set "USER_PATH=%%b"
set "NEW_PATH=%SYS_PATH%;%USER_PATH%"
set "PATH=%NEW_PATH%;%PATH%"
where python
python -m pip install --upgrade pip
taskkill /F /IM python.exe
taskkill /F /IM pythonw.exe
rmdir /S /Q "Project-Mariana"
git clone https://github.com/AdityaMitra5102/Project-Mariana
cd Project-Mariana
python -m pip install cryptography psutil requests flask flask-cors
copy "startup.bat" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
start /B "" "runner.bat"
ping localhost -n 10
explorer "http://localhost:8000"
cd ..
msiexec /i mariana-browser.msi
ping localhost -n 10
del python-inst.exe
del Git-2.49.0-64-bit.exe
del mariana-browser.msi
taskkill /F /IM cmd.exe
taskkill /F /IM conhost.exe
