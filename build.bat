@echo off
setlocal

:: -----------------------------------------------------------------------------
::  Go Mobile Upload 全平台构建脚本 (Windows)
:: -----------------------------------------------------------------------------
::  功能:
::  1. 一键编译适用于 Windows, Linux, macOS (Intel & Apple Silicon) 的程序。
::  2. 将所有生成的文件统一输出到 'builds' 目录。
::  3. 优化所有可执行文件的大小。
::  4. 提供清晰的成功或失败提示。
:: -----------------------------------------------------------------------------

:: 切换到本脚本所在的目录
cd /d "%~dp0"

:: --- 配置 ---
set "BASE_NAME=gofileup"
set "BUILD_DIR=builds"
set "LDFLAGS=-s -w"

:: --- 准备工作 ---
echo.
echo 正在准备构建环境...

:: 清理并创建输出目录，确保一个干净的构建环境
if exist "%BUILD_DIR%" (
    echo 清理旧的构建目录: %BUILD_DIR%
    rmdir /s /q "%BUILD_DIR%"
)
mkdir "%BUILD_DIR%"
echo.

:: --- 开始跨平台编译 ---

:: 1. Windows (amd64)
echo --- [1/5] 正在构建: Windows (x86_64) ---
set GOOS=windows
set GOARCH=amd64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%.exe" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 2. Linux (amd64)
echo --- [2/5] 正在构建: Linux (x86_64) ---
set GOOS=linux
set GOARCH=amd64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 3. macOS (amd64 - Intel)
echo --- [3/5] 正在构建: macOS (Intel x86_64) ---
set GOOS=darwin
set GOARCH=amd64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 4. macOS (arm64 - Apple Silicon)
echo --- [4/5] 正在构建: macOS (Apple Silicon arm64) ---
set GOOS=darwin
set GOARCH=arm64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.

:: 5. Linux (arm64 - for Raspberry Pi, etc.)
echo --- [5/5] 正在构建: Linux (arm64) ---
set GOOS=linux
set GOARCH=arm64
go build -o "%BUILD_DIR%\%BASE_NAME%-%GOOS%-%GOARCH%" -ldflags="%LDFLAGS%" .
if %errorlevel% neq 0 goto error_exit
echo.


:: --- 成功流程 ---
echo =======================================================
echo.
echo  [*] 所有平台均已成功构建!
echo.
echo =======================================================
echo 所有文件已保存到 "%BUILD_DIR%" 目录中。
echo.
tree /f "%BUILD_DIR%"
echo.
goto end


:: --- 失败处理 ---
:error_exit
echo.
echo =======================================================
echo.
echo  [!] 在构建 %GOOS%/%GOARCH% 时发生错误!
echo.
echo =======================================================
echo 构建过程已中止。请检查上面的错误信息。
echo.


:: --- 脚本结束 ---
:end
pause
endlocal