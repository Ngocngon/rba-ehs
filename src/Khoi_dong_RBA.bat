@echo off
REM RBA 8.0.1 EHS Audit Automation - Khoi dong (Windows) - (c) NGUYEN NGOC NGON
chcp 65001 >nul
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
if "%PORT%"=="" set PORT=8801
set PY=
REM Chay thu that su: Windows co san loi tat python gia mo Microsoft Store
py -3 -c "" >nul 2>nul
if not errorlevel 1 set PY=py -3
if not defined PY (
  python -c "" >nul 2>nul
  if not errorlevel 1 set PY=python
)
if not defined PY goto nopython
echo ==============================================
echo   RBA 8.0.1 EHS AUDIT AUTOMATION - OFFLINE
echo   Ban quyen: NGUYEN NGOC NGON
echo   Dia chi: http://127.0.0.1:%PORT%
echo   Giu cua so nay mo trong khi su dung.
echo   Dong cua so de tat he thong.
echo ==============================================
start "" cmd /c "timeout /t 3 /nobreak >nul & start "" http://127.0.0.1:%PORT%"
%PY% start_server.py
pause
exit /b 0
:nopython
echo Chua cai Python 3. Hay tai tai https://www.python.org/downloads/
echo Khi cai dat nho tick o "Add Python to PATH", sau do chay lai tep nay.
start "" https://www.python.org/downloads/
pause
exit /b 1
