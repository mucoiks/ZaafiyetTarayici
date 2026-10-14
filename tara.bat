@echo off
setlocal
cd /d "%~dp0"
title Otomatik Zafiyet Tarayici

echo ============================================================
echo           OTOMATIK ZAFIYET TARAYICI - WEB CRAWLER
echo ============================================================
echo.

:: 1. venv klasorunde python.exe var mi?
if exist "%~dp0venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0venv\Scripts\python.exe"
    goto PYTHON_HAZIR
)

:: 2. venv yoksa sistemde python var mi?
echo [*] 'venv' sanal ortami bulunamadi. Sistemdeki Python kontrol ediliyor...
where python >nul 2>&1
if not errorlevel 1 goto SISTEM_PYTHON_ILE_KUR

:: 3. py launcher var mi?
where py >nul 2>&1
if not errorlevel 1 goto PY_LAUNCHER_ILE_KUR

:: 4. Hicbir Python bulunamadi
echo.
echo ============================================================
echo [HATA] Bu bilgisayarda Python bulunamadi!
echo ============================================================
echo Lutfen https://www.python.org adresinden Python kurun.
echo Kurulum sirasinda "Add Python to PATH" secenegini isaretleyin.
echo.
pause
exit /b 1

:SISTEM_PYTHON_ILE_KUR
echo [*] Python bulundu. Otomatik olarak 'venv' sanal ortami olusturuluyor...
python -m venv "%~dp0venv"
if not exist "%~dp0venv\Scripts\pip.exe" (
    echo [!] venv olusturulamadi. Dogrudan sistem Python'u kullanilacak.
    set "PY_CMD=python"
    goto PYTHON_HAZIR
)
echo [*] Gerekli paketler yukleniyor: requests, beautifulsoup4, jinja2...
"%~dp0venv\Scripts\pip.exe" install -r "%~dp0requirements.txt"
set "PY_CMD=%~dp0venv\Scripts\python.exe"
goto PYTHON_HAZIR

:PY_LAUNCHER_ILE_KUR
echo [*] Python Launcher bulundu. Otomatik olarak 'venv' olusturuluyor...
py -m venv "%~dp0venv"
if not exist "%~dp0venv\Scripts\pip.exe" (
    set "PY_CMD=py"
    goto PYTHON_HAZIR
)
echo [*] Gerekli paketler yukleniyor: requests, beautifulsoup4, jinja2...
"%~dp0venv\Scripts\pip.exe" install -r "%~dp0requirements.txt"
set "PY_CMD=%~dp0venv\Scripts\python.exe"
goto PYTHON_HAZIR

:PYTHON_HAZIR
echo.
set "target_url="
set /p "target_url=Taranacak site adresi (Varsayilan: http://localhost:8080): "

if not defined target_url set "target_url=http://localhost:8080"
if "%target_url%"=="" set "target_url=http://localhost:8080"

echo.
echo Tarama Turu:
echo   [1] Standart Tarama (Oturum / Giris yok)
echo   [2] DVWA Test Ortami (Otomatik Girisli)
echo   [3] Ozel Cookie ile Tara
echo.

set "secim="
set /p "secim=Seciminiz (1, 2 veya 3 - Varsayilan: 2): "

if not defined secim set "secim=2"
if "%secim%"=="" set "secim=2"

echo.
echo [*] Hedef: %target_url%
echo ------------------------------------------------------------

if "%secim%"=="1" (
    "%PY_CMD%" "%~dp0main.py" --target "%target_url%"
    goto SON
)

if "%secim%"=="3" (
    set "cookie_val="
    set /p "cookie_val=Cookie degeri (Orn: PHPSESSID=xyz): "
    "%PY_CMD%" "%~dp0main.py" --target "%target_url%" --cookie "%cookie_val%"
    goto SON
)

:: Varsayilan secenek: 2 (DVWA)
"%PY_CMD%" "%~dp0main.py" --target "%target_url%" --dvwa-login

:SON
echo.
echo ------------------------------------------------------------
echo [+] Islem tamamlandi! Sonuclar 'logs' klasorune kaydedildi.
echo ------------------------------------------------------------
echo.
pause
