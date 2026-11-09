@echo off
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PY=python
where py >nul 2>nul
if %errorlevel%==0 set PY=py -3
%PY% restore_backup.py
echo.
set /p CHOICE=Nhap latest de khoi phuc ban on dinh gan nhat, hoac ten tep sao luu (Enter de thoat): 
if not "%CHOICE%"=="" %PY% restore_backup.py %CHOICE%
pause
