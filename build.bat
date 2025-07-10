@echo off
setlocal

:: -----------------------------------------------------------------------------
::  Go Mobile Upload ȫƽ̨�����ű� (Windows)
:: -----------------------------------------------------------------------------
::  ����:
::  1. һ������������ Windows, Linux, macOS (Intel & Apple Silicon) �ĳ���
::  2. ���������ɵ��ļ�ͳһ����� 'builds' Ŀ¼��
::  3. �Ż����п�ִ���ļ��Ĵ�С��
::  4. �ṩ�����ĳɹ���ʧ����ʾ��
:: -----------------------------------------------------------------------------

:: �л������ű����ڵ�Ŀ¼
cd /d "%~dp0"

:: --- ���� ---
set "BASE_NAME=gofileup"
set "BUILD_DIR=builds"
set "LDFLAGS=-s -w"

:: --- ׼������ ---
echo.
echo ����׼����������...

:: �����������Ŀ¼��ȷ��һ���ɾ��Ĺ�������
if exist "%BUILD_DIR%" (
    echo ����ɵĹ���Ŀ¼: %BUILD_DIR%
    rmdir /s /q "%BUILD_DIR%"
)
mkdir "%BUILD_DIR%"
echo.

:: --- ��ʼ��ƽ̨���� ---

:: 1. Windows (amd64)
echo --- [1/5] ���ڹ���: Windows (x86_64) ---
set GOOS=windows
set GOARCH=amd64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%.exe" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 2. Linux (amd64)
echo --- [2/5] ���ڹ���: Linux (x86_64) ---
set GOOS=linux
set GOARCH=amd64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 3. macOS (amd64 - Intel)
echo --- [3/5] ���ڹ���: macOS (Intel x86_64) ---
set GOOS=darwin
set GOARCH=amd64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 4. macOS (arm64 - Apple Silicon)
echo --- [4/5] ���ڹ���: macOS (Apple Silicon arm64) ---
set GOOS=darwin
set GOARCH=arm64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 5. Linux (arm64 - for Raspberry Pi, etc.)
echo --- [5/5] ���ڹ���: Linux (arm64) ---
set GOOS=linux
set GOARCH=arm64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.


:: --- �ɹ����� ---
echo =======================================================
echo.
echo  [*] ����ƽ̨���ѳɹ�����!
echo.
echo =======================================================
echo �����ļ��ѱ��浽 "%BUILD_DIR%" Ŀ¼�С�
echo.
tree /f "%BUILD_DIR%"
echo.
goto end


:: --- ʧ�ܴ��� ---
:error_exit
echo.
echo =======================================================
echo.
echo  [!] �ڹ��� %GOOS%/%GOARCH% ʱ��������!
echo.
echo =======================================================
echo ������������ֹ����������Ĵ�����Ϣ��
echo.


:: --- �ű����� ---
:end
pause
endlocal