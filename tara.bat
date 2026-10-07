@echo off
setlocal
cd /d "%~dp0"
title Otomatik Zafiyet Tarayici

echo ============================================================
echo           OTOMATIK ZAFIYET TARAYICI - WEB CRAWLER
echo ============================================================
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
    "%~dp0venv\Scripts\python.exe" "%~dp0main.py" --target "%target_url%"
    goto SON
)

if "%secim%"=="3" (
    set "cookie_val="
    set /p "cookie_val=Cookie degeri (Orn: PHPSESSID=xyz): "
    "%~dp0venv\Scripts\python.exe" "%~dp0main.py" --target "%target_url%" --cookie "%cookie_val%"
    goto SON
)

:: Varsayilan secenek: 2 (DVWA)
"%~dp0venv\Scripts\python.exe" "%~dp0main.py" --target "%target_url%" --dvwa-login

:SON
echo.
echo ------------------------------------------------------------
echo [+] Islem tamamlandi! Sonuclar 'logs' klasorune kaydedildi.
echo ------------------------------------------------------------
echo.
pause
